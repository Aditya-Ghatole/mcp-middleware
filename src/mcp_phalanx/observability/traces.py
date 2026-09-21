"""SQLite-backed, redacted protocol trace storage."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from anyio.to_thread import run_sync

from mcp_phalanx.protocol.messages import Direction, MessageDetails


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One observed MCP message, stored without its raw payload."""

    event_id: str
    created_at: datetime
    session_id: str
    direction: Direction
    method: str | None
    request_id: str | None
    disposition: str
    summary: str
    byte_count: int
    latency_ms: float | None

    @classmethod
    def from_message(
        cls,
        *,
        session_id: str,
        direction: Direction,
        details: MessageDetails,
        disposition: str,
        latency_ms: float | None,
    ) -> TraceEvent:
        """Create a trace event with a UTC timestamp and random identifier."""

        return cls(
            event_id=str(uuid4()),
            created_at=datetime.now(UTC),
            session_id=session_id,
            direction=direction,
            method=details.method,
            request_id=details.request_id,
            disposition=disposition,
            summary=details.summary,
            byte_count=details.byte_count,
            latency_ms=latency_ms,
        )


class TraceStore:
    """A small SQLite repository shared by the proxy and read-only API."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path
        self._local = threading.local()

    async def initialize(self) -> None:
        """Create the trace table and enable safe concurrent read access."""

        await run_sync(self._initialize_sync)

    async def append(self, event: TraceEvent) -> None:
        """Persist an observed message event."""

        await run_sync(self._append_sync, event)

    async def list_events(self, *, after: str | None, limit: int) -> list[TraceEvent]:
        """Return trace events in creation order for the dashboard."""

        return await run_sync(self._list_events_sync, after, limit)

    async def health(self) -> bool:
        """Return whether the database can be read."""

        return await run_sync(self._health_sync)

    def _initialize_sync(self) -> None:
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS trace_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    method TEXT,
                    request_id TEXT,
                    disposition TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    byte_count INTEGER NOT NULL,
                    latency_ms REAL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_trace_events_event_id "
                "ON trace_events(event_id)"
            )

    def _append_sync(self, event: TraceEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO trace_events (
                    event_id, created_at, session_id, direction, method, request_id,
                    disposition, summary, byte_count, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.created_at.isoformat(),
                    event.session_id,
                    event.direction,
                    event.method,
                    event.request_id,
                    event.disposition,
                    event.summary,
                    event.byte_count,
                    event.latency_ms,
                ),
            )

    def _list_events_sync(self, after: str | None, limit: int) -> list[TraceEvent]:
        if after is None:
            query = """
                SELECT event_id, created_at, session_id, direction, method, request_id,
                       disposition, summary, byte_count, latency_ms
                FROM trace_events
                ORDER BY sequence DESC
                LIMIT ?
            """
            parameters: tuple[object, ...] = (limit,)
        else:
            query = """
                SELECT event_id, created_at, session_id, direction, method, request_id,
                       disposition, summary, byte_count, latency_ms
                FROM trace_events
                WHERE sequence > COALESCE(
                    (SELECT sequence FROM trace_events WHERE event_id = ?), 0
                )
                ORDER BY sequence ASC
                LIMIT ?
            """
            parameters = (after, limit)

        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._event_from_row(row) for row in rows]

    def _health_sync(self) -> bool:
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True

    def _connect(self) -> sqlite3.Connection:
        if not hasattr(self._local, "connection"):
            self._local.connection = sqlite3.connect(
                self._database_path, timeout=5.0
            )
        return self._local.connection

    @staticmethod
    def _event_from_row(row: tuple[object, ...]) -> TraceEvent:
        (
            event_id, created_at, session_id, direction, method, 
            request_id, disposition, summary, byte_count, latency_ms
        ) = row
        return TraceEvent(
            event_id=str(event_id),
            created_at=datetime.fromisoformat(str(created_at)),
            session_id=str(session_id),
            direction=Direction(str(direction)),
            method=None if method is None else str(method),
            request_id=None if request_id is None else str(request_id),
            disposition=str(disposition),
            summary=str(summary),
            byte_count=int(str(byte_count)),
            latency_ms=None if latency_ms is None else float(str(latency_ms)),
        )
