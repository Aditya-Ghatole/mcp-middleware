"""Per-session state used to correlate MCP discovery, calls, and responses."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Validated discovery metadata retained only for the current session."""

    name: str
    input_schema: dict[str, object]
    output_schema: dict[str, object] | None = None


class ToolRegistry:
    """Stores observed, schema-validated tool definitions for one host session."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def replace_page(self, tools: tuple[ToolDefinition, ...]) -> None:
        """Merge one validated tools/list page into the session registry."""

        self._tools.update({tool.name: tool for tool in tools})

    def begin_discovery(self, cursor: object = None) -> None:
        """Start a fresh listing or preserve the cache for a continuation page."""

        if cursor is None:
            self._tools.clear()

    def clear(self) -> None:
        """Invalidate discovered metadata after a tools/list_changed notification."""

        self._tools.clear()

    def get(self, name: str) -> ToolDefinition | None:
        """Return a discovered definition, if the host exposed it."""

        return self._tools.get(name)


@dataclass(frozen=True, slots=True)
class RequestRecord:
    """Minimal state needed to correlate an upstream response."""

    method: str
    started_at: float


class RequestLedger:
    """Bounds request correlation state for one proxy session."""

    def __init__(self, maximum_entries: int = 10_000) -> None:
        self._maximum_entries = maximum_entries
        self._records: dict[str, RequestRecord] = {}

    def start(self, request_id: str, method: str) -> None:
        """Record an outbound request, evicting the oldest entry if necessary."""

        if len(self._records) >= self._maximum_entries:
            self._records.pop(next(iter(self._records)))
        self._records[request_id] = RequestRecord(method=method, started_at=time.perf_counter())

    def finish(self, request_id: str) -> RequestRecord | None:
        """Return and remove the correlation record for one completed request."""

        return self._records.pop(request_id, None)

    def get(self, request_id: str) -> RequestRecord | None:
        """Return correlation metadata without completing the request."""

        return self._records.get(request_id)
