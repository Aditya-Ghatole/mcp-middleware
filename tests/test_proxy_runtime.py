"""Runtime lifecycle tests for the stdio proxy."""

from __future__ import annotations

import mcp.types as types
from mcp.shared.message import SessionMessage

from mcp_phalanx.protocol.messages import cancellation_request_id
from mcp_phalanx.security.state import RequestLedger


def test_cancelled_notification_clears_request_correlation() -> None:
    ledger = RequestLedger()
    ledger.start("71", "tools/call:read_file")
    cancellation = SessionMessage(
        message=types.JSONRPCMessage(
            root=types.JSONRPCNotification(
                jsonrpc="2.0",
                method="notifications/cancelled",
                params={"requestId": 71},
            )
        )
    )

    request_id = cancellation_request_id(cancellation)
    assert request_id == "71"
    ledger.finish(request_id)
    assert ledger.get("71") is None


def test_malformed_cancellation_has_no_request_id() -> None:
    message = SessionMessage(
        message=types.JSONRPCMessage(
            root=types.JSONRPCNotification(
                jsonrpc="2.0",
                method="notifications/cancelled",
                params={"requestId": True},
            )
        )
    )
    assert cancellation_request_id(message) is None
