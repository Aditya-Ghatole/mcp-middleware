"""Typed TOML configuration for the MCP-Phalanx proxy."""

from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from mcp_phalanx.interceptors.containment import ContainmentMode
from mcp_phalanx.security.policy import CompiledPolicy, load_policy


class ConfigurationError(ValueError):
    """Raised when a proxy configuration cannot be used safely."""


@dataclass(frozen=True, slots=True)
class UpstreamConfiguration:
    """How one proxy session starts its persistent upstream MCP server."""

    command: str
    arguments: tuple[str, ...]
    working_directory: Path | None
    environment: dict[str, str] | None


@dataclass(frozen=True, slots=True)
class SecurityConfiguration:
    """Feature flags and compiled policy for the deterministic controls."""

    l0_enabled: bool
    l1_enabled: bool
    l2_enabled: bool
    policy: CompiledPolicy | None


@dataclass(frozen=True, slots=True)
class ContainmentConfiguration:
    """Settings for Layer 3 inbound containment."""

    enabled: bool
    mode: ContainmentMode
    model_name: str
    confidence_threshold_block: float
    high_risk_tools: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProxyConfiguration:
    """All settings affecting one proxy process."""

    upstream: UpstreamConfiguration
    trace_database: Path
    max_message_bytes: int
    security: SecurityConfiguration
    containment: ContainmentConfiguration


def load_proxy_configuration(path: Path) -> ProxyConfiguration:
    """Load a checked configuration and compile its policy before startup."""

    if not path.is_file():
        raise ConfigurationError(f"Configuration file does not exist: {path}")
    with path.open("rb") as config_file:
        document = _table(tomllib.load(config_file), "configuration")

    upstream_table = _table(document.get("upstream"), "upstream")
    runtime_table = _table_or_empty(document.get("runtime"), "runtime")
    security_table = _table_or_empty(document.get("security"), "security")
    containment_table = _table_or_empty(document.get("containment"), "containment")

    l0_enabled = _boolean(security_table.get("l0_enabled", False), "security.l0_enabled")
    l1_enabled = _boolean(security_table.get("l1_enabled", False), "security.l1_enabled")
    l2_enabled = _boolean(security_table.get("l2_enabled", False), "security.l2_enabled")
    policy_value = security_table.get("policy_file")
    if (l1_enabled or l2_enabled) and policy_value is None:
        raise ConfigurationError("security.policy_file is required when L1 or L2 is enabled")
    policy = (
        None
        if policy_value is None
        else load_policy(_path(policy_value, "security.policy_file", path.parent))
    )

    try:
        mode = ContainmentMode(
            _string(containment_table.get("mode", "deterministic"), "containment.mode")
        )
    except ValueError as error:
        raise ConfigurationError(
            "containment.mode must be 'deterministic' or 'classifier'"
        ) from error

    return ProxyConfiguration(
        upstream=UpstreamConfiguration(
            command=_resolve_command(_string(upstream_table.get("command"), "upstream.command")),
            arguments=_string_tuple(upstream_table.get("arguments", []), "upstream.arguments"),
            working_directory=_optional_path(
                upstream_table.get("working_directory"), "upstream.working_directory", path.parent
            ),
            environment=_optional_environment(upstream_table.get("environment")),
        ),
        trace_database=_path(
            runtime_table.get("trace_database", "../data/traces.db"),
            "runtime.trace_database",
            path.parent,
        ),
        max_message_bytes=_positive_int(
            runtime_table.get("max_message_bytes", 1_000_000), "runtime.max_message_bytes"
        ),
        security=SecurityConfiguration(
            l0_enabled=l0_enabled,
            l1_enabled=l1_enabled,
            l2_enabled=l2_enabled,
            policy=policy,
        ),
        containment=ContainmentConfiguration(
            enabled=_boolean(containment_table.get("enabled", False), "containment.enabled"),
            mode=mode,
            model_name=_string(
                containment_table.get(
                    "model_name", "protectai/deberta-v3-base-prompt-injection-v2"
                ),
                "containment.model_name",
            ),
            confidence_threshold_block=_float_between(
                containment_table.get("confidence_threshold_block", 0.85),
                "containment.confidence_threshold_block",
                0.0,
                1.0,
            ),
            high_risk_tools=_string_tuple(
                containment_table.get("high_risk_tools", []), "containment.high_risk_tools"
            ),
        ),
    )


def _table(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"'{name}' must be a TOML table")
    return cast(dict[str, object], value)


def _table_or_empty(value: object, name: str) -> dict[str, object]:
    return {} if value is None else _table(value, name)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"'{name}' must be a non-empty string")
    return value


def _string_tuple(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigurationError(f"'{name}' must be an array of non-empty strings")
    items = cast(list[object], value)
    if not all(isinstance(item, str) and item for item in items):
        raise ConfigurationError(f"'{name}' must be an array of non-empty strings")
    return tuple(item for item in items if isinstance(item, str))


def _optional_path(value: object, name: str, base_directory: Path) -> Path | None:
    return None if value is None else _path(value, name, base_directory)


def _path(value: object, name: str, base_directory: Path) -> Path:
    candidate = Path(_string(value, name))
    if candidate.is_absolute():
        return candidate.resolve()
    return (base_directory / candidate).resolve()


def _optional_environment(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    table = _table(value, "upstream.environment")
    if not all(isinstance(item, str) for item in table.values()):
        raise ConfigurationError("'upstream.environment' values must all be strings")
    return {key: item for key, item in table.items() if isinstance(item, str)}


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"'{name}' must be boolean")
    return value


def _positive_int(value: object, name: str) -> int:
    if not isinstance(value, bool) and isinstance(value, int) and value > 0:
        return value
    raise ConfigurationError(f"'{name}' must be a positive integer")


def _float_between(value: object, name: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigurationError(f"'{name}' must be a number between {low} and {high}")
    result = float(value)
    if not low <= result <= high:
        raise ConfigurationError(f"'{name}' must be between {low} and {high}")
    return result


def _resolve_command(command: str) -> str:
    return sys.executable if command == "${python}" else command
