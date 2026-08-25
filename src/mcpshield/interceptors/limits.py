"""Protocol-level guardrails that are active before research layers are added."""

from __future__ import annotations

from dataclasses import dataclass

from mcp.shared.message import SessionMessage

from mcpshield.interceptors.chain import InterceptionAction, InterceptionDecision
from mcpshield.protocol.messages import Direction, inspect_message


@dataclass(frozen=True, slots=True)
class MessageSizeLimit:
    """Reject JSON-RPC messages larger than a configured, transport-safe maximum."""

    maximum_bytes: int

    async def inspect(
        self, direction: Direction, message: SessionMessage
    ) -> InterceptionDecision:
        """Inspect serialized message size without retaining its payload."""

        del direction
        details = inspect_message(message)
        if details.byte_count > self.maximum_bytes:
            reason = f"Message exceeds the {self.maximum_bytes}-byte configured limit"
            return InterceptionDecision(
                action=InterceptionAction.BLOCK, message=message, reason=reason
            )
        return InterceptionDecision.forward(message)
