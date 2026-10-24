"""Redacted, batched trace persistence isolated from the MCP data plane."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import anyio
from anyio import EndOfStream, WouldBlock
from anyio.to_thread import run_sync

from mcp_phalanx.interceptors.chain import ControlLayer, DecisionEvidence
from mcp_phalanx.protocol.messages import Direction, MessageDetails

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One redacted observed message or proxy-health event."""

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
    processing_ms: float | None
    layer: str | None
    reason_code: str | None
    rule_id: str | None

    @classmethod
    def from_message(
        cls,
        *,
        session_id: str,
        direction: Direction,
        details: MessageDetails,
        disposition: str,
        latency_ms: float | None,
        processing_ms: float = 0.0,
        evidence: DecisionEvidence | None = None,
    ) -> TraceEvent:
        """Create an event without retaining raw protocol payloads."""

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
            processing_ms=processing_ms,
            layer=None if evidence is None else evidence.layer.value,
            reason_code=None if evidence is None else evidence.reason_code,
            rule_id=None if evidence is None else evidence.rule_id,
        )

    @classmethod
    def dropped_summary(cls, session_id: str, count: int) -> TraceEvent:
        """Record an honest summary when trace buffering overflowed."""

        return cls(
            event_id=str(uuid4()),
            created_at=datetime.now(UTC),
            session_id=session_id,
            direction=Direction.SYSTEM,
            method=None,
            request_id=None,
            disposition="dropped",
            summary=f"Trace buffer dropped {count} event(s)",
            byte_count=0,
            latency_ms=None,
            processing_ms=None,
            layer=ControlLayer.TRANSPORT.value,
            reason_code="TRACE_QUEUE_FULL",
            rule_id=None,
        )


class TraceStore:
    """SQLite repository shared by the proxy writer and read-only API."""

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path

    async def initialize(self) -> None:
        await run_sync(self._initialize_sync)

    async def append(self, event: TraceEvent) -> None:
        await self.append_many((event,))

    async def append_many(self, events: tuple[TraceEvent, ...]) -> None:
        if events:
            await run_sync(self._append_many_sync, events)

    async def list_events(self, *, after: str | None, limit: int) -> list[TraceEvent]:
        return await run_sync(self._list_events_sync, after, limit)

    async def health(self) -> bool:
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
                    latency_ms REAL,
                    processing_ms REAL,
                    layer TEXT,
                    reason_code TEXT,
                    rule_id TEXT
                )
                """
            )
            existing = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(trace_events)")
            }
            for name, sqlite_type in (
                ("processing_ms", "REAL"),
                ("layer", "TEXT"),
                ("reason_code", "TEXT"),
                ("rule_id", "TEXT"),
            ):
                if name not in existing:
                    connection.execute(f"ALTER TABLE trace_events ADD COLUMN {name} {sqlite_type}")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_trace_events_event_id ON trace_events(event_id)"
            )

    def _append_many_sync(self, events: tuple[TraceEvent, ...]) -> None:
        rows = tuple(
            (
                event.event_id,
                event.created_at.isoformat(),
                event.session_id,
                event.direction.value,
                event.method,
                event.request_id,
                event.disposition,
                event.summary,
                event.byte_count,
                event.latency_ms,
                event.processing_ms,
                event.layer,
                event.reason_code,
                event.rule_id,
            )
            for event in events
        )
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO trace_events (
                    event_id, created_at, session_id, direction, method, request_id,
                    disposition, summary, byte_count, latency_ms, processing_ms,
                    layer, reason_code, rule_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def _list_events_sync(self, after: str | None, limit: int) -> list[TraceEvent]:
        if after is None:
            query = """
                SELECT event_id, created_at, session_id, direction, method, request_id,
                       disposition, summary, byte_count, latency_ms, processing_ms,
                       layer, reason_code, rule_id
                FROM trace_events ORDER BY sequence DESC LIMIT ?
            """
            parameters: tuple[object, ...] = (limit,)
        else:
            query = """
                SELECT event_id, created_at, session_id, direction, method, request_id,
                       disposition, summary, byte_count, latency_ms, processing_ms,
                       layer, reason_code, rule_id
                FROM trace_events
                WHERE sequence > COALESCE(
                    (SELECT sequence FROM trace_events WHERE event_id = ?), 0
                )
                ORDER BY sequence ASC LIMIT ?
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

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _event_from_row(row: tuple[object, ...]) -> TraceEvent:
        return TraceEvent(
            event_id=str(row[0]),
            created_at=datetime.fromisoformat(str(row[1])),
            session_id=str(row[2]),
            direction=Direction(str(row[3])),
            method=None if row[4] is None else str(row[4]),
            request_id=None if row[5] is None else str(row[5]),
            disposition=str(row[6]),
            summary=str(row[7]),
            byte_count=_to_int(row[8]),
            latency_ms=_to_float_or_none(row[9]),
            processing_ms=_to_float_or_none(row[10]),
            layer=None if row[11] is None else str(row[11]),
            reason_code=None if row[12] is None else str(row[12]),
            rule_id=None if row[13] is None else str(row[13]),
        )


def _to_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise ValueError("Trace database contains a non-integer byte count")


def _to_float_or_none(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        return float(value)
    raise ValueError("Trace database contains a non-numeric timing")


class TraceSink:
    """Buffers trace writes so slow SQLite storage never blocks forwarding."""

    def __init__(self, store: TraceStore, session_id: str, capacity: int = 1_000) -> None:
        self._store = store
        self._session_id = session_id
        self._send, self._receive = anyio.create_memory_object_stream[TraceEvent](capacity)
        self._dropped = 0

    def record(self, event: TraceEvent) -> None:
        """Queue a trace without awaiting disk I/O on the proxy hot path."""

        try:
            self._send.send_nowait(event)
        except WouldBlock:
            self._dropped += 1

    async def close(self) -> None:
        """Finish writes and persist a truthful overflow summary if necessary."""

        await self._send.aclose()

    async def run(self) -> None:
        """Write short batches until the producer closes the stream."""

        async with self._receive:
            while True:
                try:
                    first = await self._receive.receive()
                except EndOfStream:
                    break
                batch = [first]
                with anyio.move_on_after(0.1):
                    while len(batch) < 100:
                        try:
                            batch.append(await self._receive.receive())
                        except EndOfStream:
                            break
                try:
                    await self._store.append_many(tuple(batch))
                except (OSError, sqlite3.Error):
                    logger.exception("Unable to persist an MCP trace batch")
        if self._dropped:
            try:
                await self._store.append(
                    TraceEvent.dropped_summary(self._session_id, self._dropped)
                )
            except (OSError, sqlite3.Error):
                logger.exception("Unable to persist dropped-trace summary")
