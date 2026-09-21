"""Layer 0: Metadata Scanning — validate tool schemas and detect injections.

This interceptor inspects **upstream → client** ``tools/list`` responses
before they reach the host LLM.  It performs two classes of checks on each
tool definition in the response:

    1. **Schema validation** — ``inputSchema`` must be a dict whose
       top-level ``type`` is ``"object"`` and whose ``properties`` (if
       present) contain well-formed property descriptors.  References
       (``$ref``, ``$dynamicRef``) and remote ``$id`` URIs are blocked
       as an L0 security policy to prevent schema-hijacking attacks;
       this is *not* a claim that they are invalid JSON Schema.
    2. **Description injection detection** — tool ``name`` and
       ``description`` fields are normalised and checked against
       deterministic regex patterns for embedded instructions and
       prompt-injection content.

L0 is *inspection-only*: when a ``tools/list`` response passes all checks
the original ``SessionMessage`` is forwarded unchanged.  When any tool
fails, a protocol-correct JSON-RPC error is returned to the client.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import mcp.types as types
from mcp.shared.message import SessionMessage

from mcp_phalanx.interceptors.chain import (
    InterceptionAction,
    InterceptionDecision,
)
from mcp_phalanx.interceptors.normalize import normalize
from mcp_phalanx.protocol.messages import Direction, MessageDetails

if TYPE_CHECKING:
    from mcp_phalanx.config.settings import MetadataScanConfiguration

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Description injection patterns (deterministic, no ML)
# ---------------------------------------------------------------------------

_DESCRIPTION_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Classic prompt-injection preambles
    re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", re.I,
    ),
    re.compile(r"(disregard|forget)\s+(all\s+)?(previous|prior|above|everything)", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.I),
    re.compile(r"new\s+(instructions|rules|prompt)\s*:", re.I),
    re.compile(r"system\s*:\s*you\s+are", re.I),
    re.compile(r"\[system\]", re.I),
    re.compile(r"<\s*/?system\s*>", re.I),
    re.compile(r"act\s+as\s+(a|an|if)\s+", re.I),
    re.compile(r"override\s+(previous|all|system)\s+", re.I),
    re.compile(r"do\s+not\s+follow\s+(any\s+)?(previous|prior|original)\s+", re.I),
    re.compile(r"from\s+now\s+on\s*,?\s+(you|ignore|forget)", re.I),
    re.compile(r"reveal\s+(your|the)\s+(system\s+)?(prompt|instructions)", re.I),
    re.compile(
        r"(output|print|show|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions)", re.I,
    ),
    # L0-specific: directives that instruct the LLM to call tools
    re.compile(r"(execute|run|call|invoke)\s+(this|the|that)\s+tool", re.I),
    re.compile(r"(always|must|should)\s+(call|execute|run|use)\s+\w+\s+first", re.I),
    # Hidden markdown links (exfiltration via tool descriptions)
    re.compile(r"\[.*?\]\(https?://", re.I),
)

# Tool-name validation: names should be simple ASCII identifiers
_INVALID_TOOL_NAME = re.compile(r"[^\w\-.]")  # allow alphanumeric, underscore, hyphen, dot

# Schema keys that L0 blocks as a security policy (potential hijacking)
_BLOCKED_SCHEMA_KEYS: frozenset[str] = frozenset({"$ref", "$dynamicRef"})


# ---------------------------------------------------------------------------
# Diagnostic dataclass for per-tool findings
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _ToolFinding:
    """One diagnostic issue found in a tool definition."""

    tool_name: str
    category: str  # "schema" or "description"
    detail: str


# ---------------------------------------------------------------------------
# Core interceptor
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class MetadataScan:
    """L0 interceptor: validates tool metadata in ``tools/list`` responses.

    Implements the ``MessageInterceptor`` protocol so it can be added to
    the ``InterceptorChain`` alongside other controls.  It is strictly
    *inspection-only*: the original message is forwarded unchanged on
    allow.
    """

    _config: MetadataScanConfiguration
    _max_description_length: int = field(init=False)

    def __init__(self, config: MetadataScanConfiguration) -> None:
        self._config = config
        self._max_description_length = config.max_description_length

    # -- MessageInterceptor protocol ---------------------------------------

    async def inspect(
        self, direction: Direction, message: SessionMessage, details: MessageDetails,
    ) -> InterceptionDecision:
        """Inspect upstream→client ``tools/list`` responses."""

        # Gate 1: only inspect upstream → client traffic
        if direction is not Direction.UPSTREAM_TO_CLIENT:
            return InterceptionDecision.forward(message)

        # Gate 2: only inspect tools/list responses (method attached by
        # ProxyRuntime._attach_correlated_method before interceptors run)
        if details.method != "tools/list":
            return InterceptionDecision.forward(message)

        # Gate 3: must be a successful JSON-RPC response
        root = message.message.root
        if not isinstance(root, types.JSONRPCResponse):
            return InterceptionDecision.forward(message)

        result = root.result
        if not isinstance(result, dict):
            return InterceptionDecision.forward(message)

        tools = result.get("tools")
        if not isinstance(tools, list):
            return InterceptionDecision.forward(message)

        # Run checks on every tool definition
        findings = self._validate_tools(tools)

        if not findings:
            # All tools passed — forward the ORIGINAL message unchanged
            return InterceptionDecision.forward(message)

        # Separate findings by category to respect per-category config
        schema_findings = [f for f in findings if f.category == "schema"]
        description_findings = [f for f in findings if f.category == "description"]

        blocking_reasons: list[str] = []

        if schema_findings and self._config.block_on_schema_violation:
            for finding in schema_findings:
                blocking_reasons.append(f"[{finding.tool_name}] {finding.detail}")
        elif schema_findings:
            for finding in schema_findings:
                logger.warning(
                    "L0 schema warning (forwarding): tool=%s detail=%s",
                    finding.tool_name, finding.detail,
                )

        if description_findings and self._config.block_on_suspicious_description:
            for finding in description_findings:
                blocking_reasons.append(f"[{finding.tool_name}] {finding.detail}")
        elif description_findings:
            for finding in description_findings:
                logger.warning(
                    "L0 description warning (forwarding): tool=%s detail=%s",
                    finding.tool_name, finding.detail,
                )

        if not blocking_reasons:
            # Findings exist but config says forward with warnings
            return InterceptionDecision.forward(message)

        reason = (
            "L0 Metadata Scan blocked tools/list response: "
            + "; ".join(blocking_reasons)
        )
        logger.warning("L0 BLOCK: %s", reason)
        return InterceptionDecision(
            action=InterceptionAction.BLOCK, message=message, reason=reason,
        )

    # -- Internal validation -----------------------------------------------

    def _validate_tools(self, tools: list[object]) -> list[_ToolFinding]:
        """Check every tool object and return all findings."""

        findings: list[_ToolFinding] = []
        for tool in tools:
            if not isinstance(tool, dict):
                findings.append(_ToolFinding("(non-dict)", "schema", "tool entry is not a dict"))
                continue

            name = tool.get("name", "(unnamed)")
            if not isinstance(name, str):
                name = str(name)

            findings.extend(self._check_name(name))
            findings.extend(self._check_schema(name, tool))
            findings.extend(self._check_description(name, tool))

        return findings

    def _check_name(self, name: str) -> list[_ToolFinding]:
        """Validate tool name characters."""

        findings: list[_ToolFinding] = []
        if _INVALID_TOOL_NAME.search(name):
            findings.append(_ToolFinding(
                name, "description",
                f"tool name contains invalid characters: {name!r}",
            ))
        return findings

    def _check_schema(self, name: str, tool: dict[str, object]) -> list[_ToolFinding]:
        """Validate the inputSchema of a single tool definition."""

        findings: list[_ToolFinding] = []

        input_schema = tool.get("inputSchema")
        if input_schema is None:
            findings.append(_ToolFinding(name, "schema", "missing inputSchema"))
            return findings

        if not isinstance(input_schema, dict):
            findings.append(_ToolFinding(
                name, "schema",
                f"inputSchema must be an object, got {type(input_schema).__name__}",
            ))
            return findings

        # Top-level type must be "object"
        schema_type = input_schema.get("type")
        if schema_type != "object":
            findings.append(_ToolFinding(
                name, "schema",
                f"inputSchema.type must be 'object', got {schema_type!r}",
            ))

        # Security policy: block $ref, $dynamicRef
        findings.extend(self._check_blocked_keys(name, input_schema, "inputSchema"))

        # Validate properties if present
        properties = input_schema.get("properties")
        if properties is not None:
            if not isinstance(properties, dict):
                findings.append(_ToolFinding(
                    name, "schema",
                    "inputSchema.properties must be an object",
                ))
            else:
                for prop_name, prop_def in properties.items():
                    if not isinstance(prop_def, dict):
                        findings.append(_ToolFinding(
                            name, "schema",
                            f"property '{prop_name}' must be an object",
                        ))
                    elif "type" not in prop_def:
                        findings.append(_ToolFinding(
                            name, "schema",
                            f"property '{prop_name}' is missing a 'type' field",
                        ))
                    else:
                        # Check nested blocked keys in property definitions
                        findings.extend(self._check_blocked_keys(
                            name, prop_def, f"property '{prop_name}'",
                        ))

        return findings

    def _check_blocked_keys(
        self, name: str, schema: dict[str, object], location: str,
    ) -> list[_ToolFinding]:
        """Security policy: block $ref, $dynamicRef and remote $id."""

        findings: list[_ToolFinding] = []
        for key in _BLOCKED_SCHEMA_KEYS:
            if key in schema:
                findings.append(_ToolFinding(
                    name, "schema",
                    f"{location} contains {key} (blocked by L0 security policy)",
                ))

        # Remote $id — only flag if it looks like a URL
        schema_id = schema.get("$id")
        if isinstance(schema_id, str) and schema_id.startswith(("http://", "https://")):
            findings.append(_ToolFinding(
                name, "schema",
                f"{location} contains remote $id '{schema_id}' (blocked by L0 security policy)",
            ))

        return findings

    def _check_description(
        self, name: str, tool: dict[str, object],
    ) -> list[_ToolFinding]:
        """Check tool description for injection patterns and length."""

        findings: list[_ToolFinding] = []
        description = tool.get("description", "")
        if not isinstance(description, str):
            return findings

        # Length check
        if len(description) > self._max_description_length:
            findings.append(_ToolFinding(
                name, "description",
                f"description exceeds {self._max_description_length}-char limit "
                f"({len(description)} chars)",
            ))

        # Normalise to defeat encoding bypasses, then check patterns
        normalised = normalize(description)
        for pattern in _DESCRIPTION_INJECTION_PATTERNS:
            if pattern.search(normalised):
                findings.append(_ToolFinding(
                    name, "description",
                    f"description matches injection pattern: {pattern.pattern}",
                ))
                break  # one match is enough to flag

        return findings
