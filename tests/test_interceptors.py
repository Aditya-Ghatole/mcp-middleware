"""Tests for transport-level proxy guardrails."""

from __future__ import annotations

import asyncio

import mcp.types as types
from mcp.shared.message import SessionMessage

from mcpshield.interceptors.chain import InterceptionAction
from mcpshield.interceptors.limits import MessageSizeLimit
from mcpshield.protocol.messages import Direction, inspect_message


def test_message_limit_blocks_an_oversized_request() -> None:
    """The proxy rejects excessive traffic before it is forwarded upstream."""

    message = SessionMessage(
        message=types.JSONRPCMessage(
            root=types.JSONRPCRequest(
                jsonrpc="2.0",
                id=1,
                method="tools/call",
                params={"name": "write_file", "arguments": {"content": "x" * 500}},
            )
        )
    )
    details = inspect_message(message)
    decision = asyncio.run(
        MessageSizeLimit(maximum_bytes=100).inspect(Direction.CLIENT_TO_UPSTREAM, message, details)
    )
    assert decision.action is InterceptionAction.BLOCK
