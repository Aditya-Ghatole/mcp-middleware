"""Bidirectional, persistent stdio MCP proxy runtime."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, replace
from uuid import uuid4

import anyio
import mcp.types as types
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage

from mcp_phalanx.config.settings import ProxyConfiguration
from mcp_phalanx.interceptors.chain import (
    DecisionEvidence,
    InterceptionAction,
    InterceptorChain,
    MessageInterceptor,
)
from mcp_phalanx.interceptors.containment import InboundContainment
from mcp_phalanx.interceptors.limits import MessageSizeLimit
from mcp_phalanx.interceptors.metadata import MetadataScanner
from mcp_phalanx.interceptors.policy import PolicyGate
from mcp_phalanx.interceptors.validation import InvocationValidator
from mcp_phalanx.observability.traces import TraceEvent, TraceSink, TraceStore
from mcp_phalanx.protocol.messages import (
    Direction,
    MessageDetails,
    blocked_error,
    cancellation_request_id,
    inspect_message,
    is_request,
    response_request_id,
)
from mcp_phalanx.security.state import RequestLedger, ToolRegistry

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ProxyRuntime:
    """Owns one host connection and one persistent upstream MCP subprocess."""

    configuration: ProxyConfiguration
    trace_store: TraceStore
    _interceptors: InterceptorChain = field(init=False)
    _ledger: RequestLedger = field(init=False)

    def __post_init__(self) -> None:
        self._ledger = RequestLedger()
        registry = ToolRegistry()
        interceptors: list[MessageInterceptor] = [
            MessageSizeLimit(self.configuration.max_message_bytes)
        ]
        policy = self.configuration.security.policy
        interceptors.append(
            MetadataScanner(
                registry,
                filter_unsafe=self.configuration.security.l0_enabled,
            )
        )
        if self.configuration.security.l1_enabled and policy is not None:
            interceptors.append(InvocationValidator(registry, policy))
        if self.configuration.security.l2_enabled and policy is not None:
            interceptors.append(PolicyGate(policy))
        if self.configuration.containment.enabled:
            interceptors.append(
                InboundContainment(self.configuration.containment, registry)
            )
        self._interceptors = InterceptorChain(interceptors=tuple(interceptors))

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
        trace_sink = TraceSink(self.trace_store, session_id)
        async with anyio.create_task_group() as trace_group:
            trace_group.start_soon(trace_sink.run)
            try:
                async with stdio_server() as (host_read, host_write):
                    async with stdio_client(upstream) as (upstream_read, upstream_write):
                        await self._run_pumps(
                            session_id=session_id,
                            host_read=host_read,
                            host_write=host_write,
                            upstream_read=upstream_read,
                            upstream_write=upstream_write,
                            trace_sink=trace_sink,
                        )
            finally:
                await trace_sink.close()

    async def _run_pumps(
        self,
        *,
        session_id: str,
        host_read: MemoryObjectReceiveStream[SessionMessage | Exception],
        host_write: MemoryObjectSendStream[SessionMessage],
        upstream_read: MemoryObjectReceiveStream[SessionMessage | Exception],
        upstream_write: MemoryObjectSendStream[SessionMessage],
        trace_sink: TraceSink,
    ) -> None:
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(
                self._pump,
                session_id,
                Direction.CLIENT_TO_UPSTREAM,
                host_read,
                upstream_write,
                host_write,
                trace_sink,
                task_group.cancel_scope,
            )
            task_group.start_soon(
                self._pump,
                session_id,
                Direction.UPSTREAM_TO_CLIENT,
                upstream_read,
                host_write,
                host_write,
                trace_sink,
                task_group.cancel_scope,
            )

    async def _pump(
        self,
        session_id: str,
        direction: Direction,
        source: MemoryObjectReceiveStream[SessionMessage | Exception],
        destination: MemoryObjectSendStream[SessionMessage],
        block_destination: MemoryObjectSendStream[SessionMessage],
        trace_sink: TraceSink,
        cancel_scope: anyio.CancelScope,
    ) -> None:
        try:
            async for incoming in source:
                if isinstance(incoming, Exception):
                    raise incoming
                details = inspect_message(incoming)
                self._track_request(direction, incoming, details.method)
                details = self._attach_correlated_method(direction, incoming, details)
                started_at = time.perf_counter()
                decision = await self._interceptors.inspect(direction, incoming, details)
                processing_ms = round((time.perf_counter() - started_at) * 1_000, 3)
                latency_ms = self._elapsed_ms(direction, incoming)
                if decision.action is InterceptionAction.BLOCK:
                    await self._handle_block(
                        session_id=session_id,
                        direction=direction,
                        message=decision.message,
                        details=details,
                        reason=decision.reason,
                        destination=block_destination,
                        latency_ms=latency_ms,
                        processing_ms=processing_ms,
                        action=decision.action,
                        evidence=decision.evidence,
                        trace_sink=trace_sink,
                    )
                    continue
                await destination.send(decision.message)
                trace_sink.record(
                    TraceEvent.from_message(
                        session_id=session_id,
                        direction=direction,
                        details=details,
                        disposition=decision.action.value,
                        latency_ms=latency_ms,
                        processing_ms=processing_ms,
                        evidence=decision.evidence,
                    )
                )
        finally:
            cancel_scope.cancel()

    async def _handle_block(
        self,
        *,
        session_id: str,
        direction: Direction,
        message: SessionMessage,
        details: MessageDetails,
        reason: str | None,
        destination: MemoryObjectSendStream[SessionMessage],
        latency_ms: float | None,
        processing_ms: float,
        action: InterceptionAction,
        evidence: DecisionEvidence | None,
        trace_sink: TraceSink,
    ) -> None:
        if not is_request(message) and response_request_id(message) is None:
            raise RuntimeError("MCP-Phalanx cannot block a notification without a response id")
        if direction is Direction.CLIENT_TO_UPSTREAM and details.request_id is not None:
            request = self._ledger.finish(details.request_id)
            if request is not None:
                latency_ms = round((time.perf_counter() - request.started_at) * 1_000, 3)
        has_response_id = is_request(message) or response_request_id(message) is not None
        if has_response_id:
            await destination.send(blocked_error(message, reason or "Policy denied this message"))
        trace_sink.record(
            TraceEvent.from_message(
                session_id=session_id,
                direction=direction,
                details=details,
                disposition=action.value,
                latency_ms=latency_ms,
                processing_ms=processing_ms,
                evidence=evidence,
            )
        )

    def _track_request(
        self, direction: Direction, message: SessionMessage, method: str | None
    ) -> None:
        if direction is not Direction.CLIENT_TO_UPSTREAM:
            return
        root = message.message.root
        if isinstance(root, types.JSONRPCNotification):
            request_id = cancellation_request_id(message)
            if request_id is not None:
                self._ledger.finish(request_id)
            return
        if not is_request(message):
            return
        request_id = inspect_message(message).request_id
        if request_id is not None and method is not None:
            self._ledger.start(request_id, method)

    def _elapsed_ms(self, direction: Direction, message: SessionMessage) -> float | None:
        if direction is not Direction.UPSTREAM_TO_CLIENT:
            return None
        request_id = response_request_id(message)
        if request_id is None:
            return None
        record = self._ledger.finish(request_id)
        if record is None:
            return None
        return round((time.perf_counter() - record.started_at) * 1_000, 3)

    def _attach_correlated_method(
        self, direction: Direction, message: SessionMessage, details: MessageDetails
    ) -> MessageDetails:
        if direction is not Direction.UPSTREAM_TO_CLIENT or details.method is not None:
            return details
        request_id = response_request_id(message)
        if request_id is None:
            return details
        record = self._ledger.get(request_id)
        return details if record is None else replace(details, method=record.method)
