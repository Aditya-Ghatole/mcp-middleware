"""FastAPI application that reads traces but never forwards MCP traffic."""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from fastapi import FastAPI, Query, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mcp_phalanx.observability.traces import TraceEvent, TraceStore


class TraceResponse(BaseModel):
    """Safe trace fields exposed by the read-only dashboard API."""

    event_id: str
    created_at: str
    session_id: str
    direction: str
    method: str | None
    request_id: str | None
    disposition: str
    summary: str
    byte_count: int
    latency_ms: float | None

    @classmethod
    def from_event(cls, event: TraceEvent) -> TraceResponse:
        """Convert an internal trace event to an API response."""

        return cls(
            event_id=event.event_id,
            created_at=event.created_at.isoformat(),
            session_id=event.session_id,
            direction=event.direction.value,
            method=event.method,
            request_id=event.request_id,
            disposition=event.disposition,
            summary=event.summary,
            byte_count=event.byte_count,
            latency_ms=event.latency_ms,
        )


class HealthResponse(BaseModel):
    """Control-plane health response."""

    status: str
    trace_database_ready: bool


def create_app(database_path: Path) -> FastAPI:
    """Create a control-plane application bound to one trace database."""

    store = TraceStore(database_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
        await store.initialize()
        yield

    application = FastAPI(title="MCP-Phalanx Control Plane", lifespan=lifespan)

    @application.get("/api/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok", trace_database_ready=await store.health())

    @application.get("/api/traces", response_model=list[TraceResponse])
    async def traces(
        after: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[TraceResponse]:
        events = await store.list_events(after=after, limit=limit)
        return [TraceResponse.from_event(event) for event in events]

    @application.get("/api/traces/stream")
    async def trace_stream(request: Request, after: str | None = None) -> StreamingResponse:
        return StreamingResponse(
            _stream_events(request, store, after),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    static_directory = Path(__file__).with_name("static")
    application.mount("/", StaticFiles(directory=static_directory, html=True), name="dashboard")
    return application


async def _stream_events(
    request: Request, store: TraceStore, after: str | None
) -> AsyncIterator[str]:
    cursor = after
    while not await request.is_disconnected():
        events = await store.list_events(after=cursor, limit=100)
        if not events:
            yield ": ping\n\n"
            await anyio.sleep(0.75)
            continue

        for event in events:
            response = TraceResponse.from_event(event)
            cursor = response.event_id
            payload = response.model_dump_json()
            yield f"event: trace\ndata: {payload}\n\n"
        await anyio.sleep(0.75)
