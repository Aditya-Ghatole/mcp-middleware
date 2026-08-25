"""Small, typed helpers for inspecting MCP JSON-RPC traffic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import mcp.types as types
from mcp.shared.message import SessionMessage


class Direction(StrEnum):
    """The two traffic directions the proxy observes."""

    CLIENT_TO_UPSTREAM = "client_to_upstream"
    UPSTREAM_TO_CLIENT = "upstream_to_client"


@dataclass(frozen=True, slots=True)
class MessageDetails:
    """Safe metadata derived from a JSON-RPC message without retaining its payload."""

    method: str | None
    request_id: str | None
    summary: str
    byte_count: int


def inspect_message(session_message: SessionMessage) -> MessageDetails:
    """Return metadata suitable for trace storage without storing raw content."""

    message = session_message.message.root
    serialized = session_message.message.model_dump_json(by_alias=True, exclude_none=True)
    byte_count = len(serialized.encode("utf-8"))

    if isinstance(message, types.JSONRPCRequest | types.JSONRPCNotification):
        request_id = _request_id(message) if isinstance(message, types.JSONRPCRequest) else None
        summary = _request_summary(message.method, message.params)
        
        # Enrich method name with tool name for finer-grained interceptor logic
        enriched_method = message.method
        if message.method == "tools/call" and isinstance(message.params, dict):
            tool_name = message.params.get("name")
            if isinstance(tool_name, str):
                enriched_method = f"tools/call:{tool_name}"
                
        return MessageDetails(enriched_method, request_id, summary, byte_count)

    if isinstance(message, types.JSONRPCResponse):
        return MessageDetails(None, str(message.id), _response_summary(message.result), byte_count)

    return MessageDetails(None, str(message.id), f"JSON-RPC error {message.error.code}", byte_count)


def is_request(session_message: SessionMessage) -> bool:
    """Return whether a message expects a JSON-RPC response."""

    return isinstance(session_message.message.root, types.JSONRPCRequest)


def response_request_id(session_message: SessionMessage) -> str | None:
    """Return the id for a JSON-RPC response or error."""

    message = session_message.message.root
    if isinstance(message, types.JSONRPCResponse | types.JSONRPCError):
        return str(message.id)
    return None


def blocked_error(session_message: SessionMessage, reason: str) -> SessionMessage:
    """Construct a protocol-correct error for a blocked request or response."""

    message = session_message.message.root
    if isinstance(message, types.JSONRPCRequest):
        request_id: str | int = message.id
    elif isinstance(message, types.JSONRPCResponse | types.JSONRPCError):
        request_id = message.id
    else:
        raise ValueError("Cannot generate a JSON-RPC error for a notification")

    error = types.JSONRPCError(
        jsonrpc="2.0",
        id=request_id,
        error=types.ErrorData(code=-32050, message="Blocked by MCPShield", data={"reason": reason}),
    )
    return SessionMessage(message=types.JSONRPCMessage(root=error))


def _request_id(message: types.JSONRPCRequest) -> str:
    return str(message.id)


def _request_summary(method: str, params: dict[str, object] | None) -> str:
    if method != "tools/call" or params is None:
        return f"MCP {method} request"
    tool_name = params.get("name")
    arguments = params.get("arguments")
    if isinstance(tool_name, str) and isinstance(arguments, dict):
        args_dict = cast(dict[str, object], arguments)
        argument_names = ", ".join(sorted(str(name) for name in args_dict.keys()))
        return f"Tool call '{tool_name}' with argument keys: {argument_names or 'none'}"
    if isinstance(tool_name, str):
        return f"Tool call '{tool_name}'"
    return "Tool call"


def _response_summary(result: dict[str, object]) -> str:
    keys = ", ".join(sorted(result))
    return f"MCP response with result fields: {keys or 'none'}"
