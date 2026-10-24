"""Tests for the read-only dashboard API."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, cast

from fastapi.testclient import TestClient

from mcp_phalanx.api.app import create_app
from mcp_phalanx.observability.traces import TraceEvent, TraceStore
from mcp_phalanx.protocol.messages import Direction, MessageDetails


def test_control_plane_lists_persisted_traces(tmp_path: Path) -> None:
    """The HTTP API reads trace data without an MCP tool execution endpoint."""

    database_path = tmp_path / "traces.db"

    async def seed() -> None:
        store = TraceStore(database_path)
        await store.initialize()
        await store.append(
            TraceEvent.from_message(
                session_id="session-a",
                direction=Direction.CLIENT_TO_UPSTREAM,
                details=MessageDetails("tools/list", "1", "MCP tools/list request", 100),
                disposition="forward",
                latency_ms=None,
            )
        )

    asyncio.run(seed())
    with TestClient(create_app(database_path)) as client:
        typed_client: Any = cast(Any, client)
        response: Any = typed_client.get("/api/traces")
        assert response.status_code == 200
        body = cast(list[dict[str, Any]], response.json())
        assert len(body) == 1
        assert body[0]["method"] == "tools/list"
        openapi_resp: Any = typed_client.get("/openapi.json")
        openapi_paths = cast(dict[str, Any], openapi_resp.json())["paths"]
        assert "/api/execute" not in openapi_paths
