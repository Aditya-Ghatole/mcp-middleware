"""Tests for redacted trace persistence."""

from __future__ import annotations

import asyncio
from pathlib import Path

from mcp_phalanx.observability.traces import TraceEvent, TraceStore
from mcp_phalanx.protocol.messages import Direction, MessageDetails


def test_trace_store_persists_and_cursors_events(tmp_path: Path) -> None:
    """The dashboard can safely read events after an SSE cursor."""

    async def scenario() -> None:
        store = TraceStore(tmp_path / "traces.db")
        await store.initialize()
        first = TraceEvent.from_message(
            session_id="session-a",
            direction=Direction.CLIENT_TO_UPSTREAM,
            details=MessageDetails("tools/list", "1", "MCP tools/list request", 100),
            disposition="forward",
            latency_ms=None,
        )
        second = TraceEvent.from_message(
            session_id="session-a",
            direction=Direction.UPSTREAM_TO_CLIENT,
            details=MessageDetails("tools/list", "1", "MCP response", 120),
            disposition="forward",
            latency_ms=2.5,
        )
        await store.append(first)
        await store.append(second)
        after_first = await store.list_events(after=first.event_id, limit=10)
        assert [event.event_id for event in after_first] == [second.event_id]

    asyncio.run(scenario())
