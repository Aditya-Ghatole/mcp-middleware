"""Composable interception pipeline used by the transparent proxy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from mcp.shared.message import SessionMessage

from mcp_phalanx.protocol.messages import Direction, MessageDetails


class InterceptionAction(StrEnum):
    """The action an interceptor can request."""

    FORWARD = "forward"
    BLOCK = "block"
    FILTER = "filter"
    TAINT = "taint"


class ControlLayer(StrEnum):
    """Named controls that may make a security decision."""

    TRANSPORT = "transport"
    L0 = "l0_metadata"
    L1 = "l1_validation"
    L2 = "l2_policy"
    L3 = "l3_containment"


@dataclass(frozen=True, slots=True)
class DecisionEvidence:
    """Redacted evidence explaining a control decision."""

    layer: ControlLayer
    reason_code: str
    rule_id: str | None = None


@dataclass(frozen=True, slots=True)
class InterceptionDecision:
    """A message and the disposition selected by an interceptor."""

    action: InterceptionAction
    message: SessionMessage
    reason: str | None = None
    evidence: DecisionEvidence | None = None

    @classmethod
    def forward(
        cls,
        message: SessionMessage,
        *,
        action: InterceptionAction = InterceptionAction.FORWARD,
        evidence: DecisionEvidence | None = None,
    ) -> InterceptionDecision:
        """Forward a message unchanged."""

        return cls(action=action, message=message, evidence=evidence)


class MessageInterceptor(Protocol):
    """A protocol-aware control that can inspect one message direction."""

    async def inspect(
        self, direction: Direction, message: SessionMessage, details: MessageDetails
    ) -> InterceptionDecision: ...


@dataclass(frozen=True, slots=True)
class InterceptorChain:
    """Runs controls in order and stops immediately on a block decision."""

    interceptors: tuple[MessageInterceptor, ...]

    async def inspect(
        self, direction: Direction, message: SessionMessage, details: MessageDetails
    ) -> InterceptionDecision:
        """Apply the configured controls to a message."""

        current_message = message
        action = InterceptionAction.FORWARD
        evidence: DecisionEvidence | None = None
        for interceptor in self.interceptors:
            decision = await interceptor.inspect(direction, current_message, details)
            current_message = decision.message
            if decision.action is InterceptionAction.BLOCK:
                return decision
            if decision.action is not InterceptionAction.FORWARD:
                action = decision.action
                evidence = decision.evidence
        return InterceptionDecision(action=action, message=current_message, evidence=evidence)
