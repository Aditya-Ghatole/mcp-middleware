"""Layer 0: validate and filter untrusted MCP tool metadata."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, cast

import mcp.types as types
from jsonschema import Draft202012Validator, SchemaError
from mcp.shared.message import SessionMessage

from mcp_phalanx.interceptors.chain import (
    ControlLayer,
    DecisionEvidence,
    InterceptionAction,
    InterceptionDecision,
)
from mcp_phalanx.interceptors.patterns import matching_instruction_pattern
from mcp_phalanx.protocol.messages import Direction, MessageDetails
from mcp_phalanx.security.state import ToolDefinition, ToolRegistry

_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_MAX_DESCRIPTION_CHARS = 4_096
_MAX_SCHEMA_BYTES = 65_536
_MAX_SCHEMA_NODES = 2_000
_MAX_SCHEMA_DEPTH = 32
_SAFE_SCHEMA_KEYS = frozenset(
    {
        "$schema",
        "additionalProperties",
        "const",
        "default",
        "description",
        "enum",
        "examples",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "items",
        "maximum",
        "maxItems",
        "maxLength",
        "minimum",
        "minItems",
        "minLength",
        "multipleOf",
        "properties",
        "required",
        "title",
        "type",
    }
)


@dataclass(frozen=True, slots=True)
class MetadataScanner:
    """Filters unsafe tool definitions before they reach the MCP client."""

    registry: ToolRegistry
    filter_unsafe: bool = True

    async def inspect(
        self, direction: Direction, message: SessionMessage, details: MessageDetails
    ) -> InterceptionDecision:
        """Inspect only the response to a tools/list request."""

        root = message.message.root
        if direction is Direction.CLIENT_TO_UPSTREAM and isinstance(root, types.JSONRPCRequest):
            if root.method == "tools/list":
                cursor = root.params.get("cursor") if isinstance(root.params, dict) else None
                self.registry.begin_discovery(cursor)
            return InterceptionDecision.forward(message)
        if direction is Direction.UPSTREAM_TO_CLIENT and isinstance(
            root, types.JSONRPCNotification
        ):
            if root.method == "notifications/tools/list_changed":
                self.registry.clear()
            return InterceptionDecision.forward(message)
        if direction is not Direction.UPSTREAM_TO_CLIENT or details.method != "tools/list":
            return InterceptionDecision.forward(message)
        if not isinstance(root, types.JSONRPCResponse):
            return InterceptionDecision.forward(message)
        result = _object(root.result)
        if result is None:
            return (
                _block(message, "L0_INVALID_TOOLS_RESPONSE")
                if self.filter_unsafe
                else InterceptionDecision.forward(message)
            )
        tools = result.get("tools")
        if not isinstance(tools, list):
            return (
                _block(message, "L0_INVALID_TOOLS_RESPONSE")
                if self.filter_unsafe
                else InterceptionDecision.forward(message)
            )

        approved: list[dict[str, Any]] = []
        definitions: list[ToolDefinition] = []
        filtered = False
        for raw_tool in cast(list[object], tools):
            tool = _object(raw_tool)
            definition, safe = _tool_definition(tool)
            if definition is None:
                filtered = True
                continue
            if safe or not self.filter_unsafe:
                definitions.append(definition)
            if safe:
                approved.append(cast(dict[str, Any], tool))
            else:
                filtered = True

        self.registry.replace_page(tuple(definitions))
        if not self.filter_unsafe or not filtered:
            return InterceptionDecision.forward(message)
        rewritten = dict(root.result)
        rewritten["tools"] = approved
        response = types.JSONRPCResponse(jsonrpc=root.jsonrpc, id=root.id, result=rewritten)
        rewritten_message = SessionMessage(message=types.JSONRPCMessage(root=response))
        return InterceptionDecision.forward(
            rewritten_message,
            action=InterceptionAction.FILTER,
            evidence=DecisionEvidence(
                layer=ControlLayer.L0,
                reason_code="L0_TOOL_FILTERED",
                rule_id="metadata:tool_definition",
            ),
        )


def _tool_definition(
    tool: dict[str, object] | None,
) -> tuple[ToolDefinition | None, bool]:
    if tool is None:
        return None, False
    name = tool.get("name")
    description = tool.get("description", "")
    schema = tool.get("inputSchema")
    output_schema = tool.get("outputSchema")
    if not isinstance(name, str) or _TOOL_NAME.fullmatch(name) is None:
        return None, False
    if not isinstance(description, str) or len(description) > _MAX_DESCRIPTION_CHARS:
        return None, False
    if not isinstance(schema, dict):
        return None, False
    typed_schema = cast(dict[str, object], schema)
    try:
        if not _valid_schema(typed_schema):
            return None, False
        typed_output_schema: dict[str, object] | None = None
        if output_schema is not None:
            output_object = _object(output_schema)
            if output_object is None or not _valid_schema(output_object):
                return None, False
            typed_output_schema = output_object
    except (RecursionError, SchemaError, TypeError, ValueError):
        return None, False
    definition = ToolDefinition(
        name=name,
        input_schema=typed_schema,
        output_schema=typed_output_schema,
    )
    return definition, _metadata_text_is_safe(tool) and _metadata_text_is_safe(typed_schema)


def _valid_schema(schema: dict[str, object]) -> bool:
    encoded_size = len(json.dumps(schema, separators=(",", ":")).encode("utf-8"))
    if encoded_size > _MAX_SCHEMA_BYTES or not _safe_schema(schema):
        return False
    Draft202012Validator.check_schema(cast(dict[str, Any], schema))
    return True


def _safe_schema(schema: dict[str, object]) -> bool:
    """Limit validation to bounded, local-reference-free JSON Schema keywords."""

    remaining_nodes = [_MAX_SCHEMA_NODES]

    def visit(value: object, depth: int) -> bool:
        remaining_nodes[0] -= 1
        if remaining_nodes[0] < 0 or depth > _MAX_SCHEMA_DEPTH:
            return False
        if isinstance(value, dict):
            entries = cast(dict[object, object], value)
            if not all(isinstance(key, str) and key in _SAFE_SCHEMA_KEYS for key in entries):
                return False
            for key, item in entries.items():
                if key == "$schema" and item != "https://json-schema.org/draft/2020-12/schema":
                    return False
                if key == "properties":
                    if not isinstance(item, dict):
                        return False
                    children = cast(dict[object, object], item).values()
                    if not all(visit(child, depth + 1) for child in children):
                        return False
                elif key == "items" or key == "additionalProperties":
                    if isinstance(item, dict) and not visit(
                        cast(dict[str, object], item), depth + 1
                    ):
                        return False
                elif key not in {"required", "type", "$schema"} and not visit(item, depth + 1):
                    return False
            return True
        if isinstance(value, list):
            return all(visit(item, depth + 1) for item in cast(list[object], value))
        return True

    return visit(schema, 0)


def _metadata_text_is_safe(value: object) -> bool:
    if isinstance(value, str):
        return len(value) <= _MAX_DESCRIPTION_CHARS and matching_instruction_pattern(value) is None
    if isinstance(value, list):
        return all(_metadata_text_is_safe(item) for item in cast(list[object], value))
    if isinstance(value, dict):
        return all(
            _metadata_text_is_safe(key) and _metadata_text_is_safe(item)
            for key, item in cast(dict[object, object], value).items()
        )
    return True


def _object(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return cast(dict[str, object], value)


def _block(message: SessionMessage, reason_code: str) -> InterceptionDecision:
    return InterceptionDecision(
        action=InterceptionAction.BLOCK,
        message=message,
        reason="Upstream returned invalid tool discovery metadata",
        evidence=DecisionEvidence(layer=ControlLayer.L0, reason_code=reason_code),
    )
