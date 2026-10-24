"""Shared deterministic patterns for untrusted MCP text."""

from __future__ import annotations

import re

from mcp_phalanx.interceptors.normalize import normalize

INSTRUCTION_OVERRIDE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", re.I),
    re.compile(r"(disregard|forget)\s+(all\s+)?(previous|prior|above|everything)", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.I),
    re.compile(r"new\s+(instructions|rules|prompt)\s*:", re.I),
    re.compile(r"system\s*:\s*you\s+are", re.I),
    re.compile(r"\[system\]", re.I),
    re.compile(r"<\s*/?system\s*>", re.I),
    re.compile(r"act\s+as\s+(a|an|if)\s+", re.I),
    re.compile(r"override\s+(previous|all|system)\s+", re.I),
    re.compile(r"do\s+not\s+follow\s+(any\s+)?(previous|prior|original)\s+", re.I),
    re.compile(r"reveal\s+(your|the)\s+(system\s+)?(prompt|instructions)", re.I),
)


def matching_instruction_pattern(text: str) -> str | None:
    """Return a stable pattern identifier when normalized text is suspicious."""

    normalized = normalize(text)
    for index, pattern in enumerate(INSTRUCTION_OVERRIDE_PATTERNS, start=1):
        if pattern.search(normalized) is not None:
            return f"instruction_override_{index}"
    return None
