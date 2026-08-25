"""Bidirectional, persistent stdio MCP proxy runtime."""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field, replace
from uuid import uuid4

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage

from mcpshield.config.settings import ProxyConfiguration
from mcpshield.interceptors.chain import InterceptionAction, InterceptorChain
from mcpshield.interceptors.containment import InboundContainment
from mcpshield.interceptors.limits import MessageSizeLimit
from mcpshield.observability.traces import TraceEvent, TraceStore
from mcpshield.protocol.messages import (
    Direction,
    MessageDetails,
    blocked_error,
    inspect_message,
    is_request,
    response_request_id,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ProxyRuntime:
    """Owns one host connection and one persistent upstream MCP subprocess."""

    configuration: ProxyConfiguration
    trace_store: TraceStore
    _interceptors: InterceptorChain = field(init=False)
    _request_started_at: dict[str, float] = field(init=False)
    _request_methods: dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        self._request_started_at = {}
        self._request_methods = {}
        interceptors: list[MessageSizeLimit | InboundContainment] = [
            MessageSizeLimit(self.configuration.max_message_bytes),
        ]
        if self.configuration.containment.enabled:
            interceptors.append(InboundContainment(self.configuration.containment))
        self._interceptors = InterceptorChain(
            interceptors=tuple(interceptors)
        )

    async def run(self) -> None:
        """Run until the host disconnects or the upstream process exits."""

        await self.trace_store.initialize()
        upstream = StdioServerParameters(
            command=self.configuration.upstream.command,
            args=list(self.configuration.upstream.arguments),
            cwd=self.configuration.upstream.working_directory,
            env=self.configuration.upstream.environment,
        )
        session_id = str(uuid4())

        async with stdio_server() as (host_read, host_write):
            async with stdio_client(upstream) as (upstream_read, upstream_write):
                await self._run_pumps(
                    session_id=session_id,
                    host_read=host_read,
                    host_write=host_write,
                    upstream_read=upstream_read,
                    upstream_write=upstream_write,
                )

    async def _run_pumps(
        self,
        *,
        session_id: str,
        host_read: MemoryObjectReceiveStream[SessionMessage | Exception],
        host_write: MemoryObjectSendStream[SessionMessage],
        upstream_read: MemoryObjectReceiveStream[SessionMessage | Exception],
        upstream_write: MemoryObjectSendStream[SessionMessage],
    ) -> None:
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(
                self._pump,
                session_id,
                Direction.CLIENT_TO_UPSTREAM,
                host_read,
                upstream_write,
                host_write,
                task_group.cancel_scope,
            )
            task_group.start_soon(
                self._pump,
                session_id,
                Direction.UPSTREAM_TO_CLIENT,
                upstream_read,
                host_write,
                host_write,
                task_group.cancel_scope,
            )

    async def _pump(
        self,
        session_id: str,
        direction: Direction,
        source: MemoryObjectReceiveStream[SessionMessage | Exception],
        destination: MemoryObjectSendStream[SessionMessage],
        block_destination: MemoryObjectSendStream[SessionMessage],
        cancel_scope: anyio.CancelScope,
    ) -> None:
        try:
            async for incoming in source:
                if isinstance(incoming, Exception):
                    raise incoming

                details = inspect_message(incoming)
                self._track_request(direction, incoming, details.method)
                details = self._attach_correlated_method(direction, incoming, details)
                decision = await self._interceptors.inspect(direction, incoming, details)
                latency_ms = self._elapsed_ms(direction, incoming)

                if decision.action is InterceptionAction.BLOCK:
                    await self._handle_block(
                        session_id, direction, decision.message, details,
                        decision.reason, block_destination, latency_ms,
                    )
                    continue

                await destination.send(decision.message)
                await self._record(
                    TraceEvent.from_message(
                        session_id=session_id,
                        direction=direction,
                        details=details,
                        disposition=decision.action.value,
                        latency_ms=latency_ms,
                    )
                )
        finally:
            cancel_scope.cancel()

    async def _handle_block(
        self,
        session_id: str,
        direction: Direction,
        message: SessionMessage,
        details: MessageDetails,
        reason: str | None,
        destination: MemoryObjectSendStream[SessionMessage],
        latency_ms: float | None,
    ) -> None:
        if not is_request(message) and response_request_id(message) is None:
            message_text = "MCPShield cannot block a notification without a response id"
            raise RuntimeError(message_text)
        await destination.send(blocked_error(message, reason or "Policy denied this message"))
        await self._record(
            TraceEvent.from_message(
                session_id=session_id,
                direction=direction,
                details=details,
                disposition=InterceptionAction.BLOCK.value,
                latency_ms=latency_ms,
            )
        )

    def _track_request(
        self, direction: Direction, message: SessionMessage, method: str | None,
    ) -> None:
        if direction is not Direction.CLIENT_TO_UPSTREAM or not is_request(message):
            return
        request_id = inspect_message(message).request_id
        if request_id is None:
            return

        # Bound the dictionary to prevent memory leaks if upstream drops requests
        if len(self._request_started_at) > 10000:
            oldest = next(iter(self._request_started_at))
            self._request_started_at.pop(oldest, None)
            self._request_methods.pop(oldest, None)

        self._request_started_at[request_id] = time.perf_counter()
        if method is not None:
            self._request_methods[request_id] = method

    def _elapsed_ms(self, direction: Direction, message: SessionMessage) -> float | None:
        if direction is not Direction.UPSTREAM_TO_CLIENT:
            return None
        request_id = response_request_id(message)
        if request_id is None:
            return None
        started_at = self._request_started_at.pop(request_id, None)
        self._request_methods.pop(request_id, None)
        if started_at is None:
            return None
        return round((time.perf_counter() - started_at) * 1_000, 3)

    def _attach_correlated_method(
        self, direction: Direction, message: SessionMessage, details: MessageDetails
    ) -> MessageDetails:
        if direction is not Direction.UPSTREAM_TO_CLIENT or details.method is not None:
            return details
        request_id = response_request_id(message)
        if request_id is None:
            return details
        method = self._request_methods.get(request_id)
        return details if method is None else replace(details, method=method)

    async def _record(self, event: TraceEvent) -> None:
        try:
            await self.trace_store.append(event)
        except (OSError, sqlite3.Error):
            logger.exception("Unable to persist MCP trace event")
