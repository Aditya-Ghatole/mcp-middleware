"""Layer 1: validate discovered tool calls before forwarding them upstream."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import mcp.types as types
from jsonschema import Draft202012Validator
from mcp.shared.message import SessionMessage

from mcp_phalanx.interceptors.chain import (
    ControlLayer,
    DecisionEvidence,
    InterceptionAction,
    InterceptionDecision,
)
from mcp_phalanx.protocol.messages import Direction, MessageDetails
from mcp_phalanx.security.policy import CompiledPolicy, is_read_only_sql, is_safe_relative_path
from mcp_phalanx.security.state import ToolRegistry


@dataclass(frozen=True, slots=True)
class InvocationValidator:
    """Validates arguments against discovered schemas and policy constraints."""

    registry: ToolRegistry
    policy: CompiledPolicy

    async def inspect(
        self, direction: Direction, message: SessionMessage, details: MessageDetails
    ) -> InterceptionDecision:
        """Validate client-to-upstream tools/call requests only."""

        if direction is not Direction.CLIENT_TO_UPSTREAM or not _is_tool_call(message):
            return InterceptionDecision.forward(message)
        tool_name = _tool_name(message)
        if tool_name is None:
            return _block(message, "L1_INVALID_TOOL_CALL", None)
        definition = self.registry.get(tool_name)
        if definition is None:
            return _block(message, "L1_TOOL_NOT_DISCOVERED", None)
        arguments = _arguments(message)
        if arguments is None:
            return _block(message, "L1_INVALID_ARGUMENTS", None)
        schema: Any = definition.input_schema
        instance: Any = arguments
        validator: Any = Draft202012Validator(schema)
        if next(validator.iter_errors(instance), None) is not None:
            return _block(message, "L1_SCHEMA_INVALID", f"schema:{tool_name}")
        rule = self.policy.rule_for(tool_name)
        if rule is None:
            return InterceptionDecision.forward(message)
        for name in rule.path_parameters:
            value = arguments.get(name)
            if not isinstance(value, str) or not is_safe_relative_path(
                value, rule.allowed_path_roots
            ):
                return _block(message, "L1_PATH_OUTSIDE_ALLOWED_ROOT", f"policy:{tool_name}")
        for name in rule.sql_parameters:
            value = arguments.get(name)
            if not isinstance(value, str) or not is_read_only_sql(value):
                return _block(message, "L1_SQL_NOT_READ_ONLY", f"policy:{tool_name}")
        return InterceptionDecision.forward(message)


def _is_tool_call(message: SessionMessage) -> bool:
    root = message.message.root
    return isinstance(root, types.JSONRPCRequest) and root.method == "tools/call"


def _tool_name(message: SessionMessage) -> str | None:
    root = message.message.root
    if not isinstance(root, types.JSONRPCRequest) or not isinstance(root.params, dict):
        return None
    name = root.params.get("name")
    return name if isinstance(name, str) else None


def _arguments(message: SessionMessage) -> dict[str, object] | None:
    root = message.message.root
    if not isinstance(root, types.JSONRPCRequest) or not isinstance(root.params, dict):
        return None
    value = root.params.get("arguments", {})
    if not isinstance(value, dict):
        return None
    return cast(dict[str, object], value)


def _block(message: SessionMessage, reason_code: str, rule_id: str | None) -> InterceptionDecision:
    return InterceptionDecision(
        action=InterceptionAction.BLOCK,
        message=message,
        reason="Tool invocation failed validation",
        evidence=DecisionEvidence(
            layer=ControlLayer.L1,
            reason_code=reason_code,
            rule_id=rule_id,
        ),
    )
