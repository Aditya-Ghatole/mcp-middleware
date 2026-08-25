"""Composable interception pipeline used by the transparent proxy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from mcp.shared.message import SessionMessage

from mcpshield.protocol.messages import Direction


class InterceptionAction(StrEnum):
    """The action an interceptor can request."""

    FORWARD = "forward"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class InterceptionDecision:
    """A message and the disposition selected by an interceptor."""

    action: InterceptionAction
    message: SessionMessage
    reason: str | None = None

    @classmethod
    def forward(cls, message: SessionMessage) -> InterceptionDecision:
        """Forward a message unchanged."""

        return cls(action=InterceptionAction.FORWARD, message=message)


class MessageInterceptor(Protocol):
    """A protocol-aware control that can inspect one message direction."""

    async def inspect(
        self, direction: Direction, message: SessionMessage
    ) -> InterceptionDecision: ...


@dataclass(frozen=True, slots=True)
class InterceptorChain:
    """Runs controls in order and stops immediately on a block decision."""

    interceptors: tuple[MessageInterceptor, ...]

    async def inspect(
        self, direction: Direction, message: SessionMessage
    ) -> InterceptionDecision:
        """Apply the configured controls to a message."""

        decision = InterceptionDecision.forward(message)
        for interceptor in self.interceptors:
            decision = await interceptor.inspect(direction, decision.message)
            if decision.action is InterceptionAction.BLOCK:
                return decision
        return decision
