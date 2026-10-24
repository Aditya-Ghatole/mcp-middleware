"""Layer 2: authorize validated MCP tool invocations."""

from __future__ import annotations

from dataclasses import dataclass

import mcp.types as types
from mcp.shared.message import SessionMessage

from mcp_phalanx.interceptors.chain import (
    ControlLayer,
    DecisionEvidence,
    InterceptionAction,
    InterceptionDecision,
)
from mcp_phalanx.protocol.messages import Direction, MessageDetails
from mcp_phalanx.security.policy import CompiledPolicy


@dataclass(frozen=True, slots=True)
class PolicyGate:
    """Enforces the compiled default-deny authorization decision."""

    policy: CompiledPolicy

    async def inspect(
        self, direction: Direction, message: SessionMessage, details: MessageDetails
    ) -> InterceptionDecision:
        """Authorize only well-formed tool invocation requests."""

        del details
        if direction is not Direction.CLIENT_TO_UPSTREAM:
            return InterceptionDecision.forward(message)
        root = message.message.root
        if not isinstance(root, types.JSONRPCRequest) or root.method != "tools/call":
            return InterceptionDecision.forward(message)
        if not isinstance(root.params, dict) or not isinstance(root.params.get("name"), str):
            return InterceptionDecision.forward(message)
        decision = self.policy.authorize(root.params["name"])
        if decision.allowed:
            return InterceptionDecision.forward(message)
        return InterceptionDecision(
            action=InterceptionAction.BLOCK,
            message=message,
            reason="Tool invocation is not allowed by policy",
            evidence=DecisionEvidence(
                layer=ControlLayer.L2,
                reason_code="L2_DEFAULT_DENY",
                rule_id=decision.rule_id,
            ),
        )
