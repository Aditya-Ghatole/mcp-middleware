"""Configuration loading for the proxy runtime."""

from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast


class ConfigurationError(ValueError):
    """Raised when a proxy configuration file is invalid."""


@dataclass(frozen=True, slots=True)
class UpstreamConfiguration:
    """How the proxy starts its one upstream stdio MCP server."""

    command: str
    arguments: tuple[str, ...]
    working_directory: Path | None
    environment: dict[str, str] | None


@dataclass(frozen=True, slots=True)
class MetadataScanConfiguration:
    """Settings for the L0 Metadata Scanning interceptor."""

    enabled: bool
    block_on_schema_violation: bool
    block_on_suspicious_description: bool
    max_description_length: int


@dataclass(frozen=True, slots=True)
class ContainmentConfiguration:
    """Settings for the L3 Inbound Containment interceptor."""

    enabled: bool
    model_name: str
    confidence_threshold_block: float
    confidence_threshold_warn: float
    high_risk_tools: tuple[str, ...]
    use_onnx: bool


@dataclass(frozen=True, slots=True)
class ProxyConfiguration:
    """Settings that affect the transparent data plane."""

    upstream: UpstreamConfiguration
    trace_database: Path
    max_message_bytes: int
    metadata_scan: MetadataScanConfiguration
    containment: ContainmentConfiguration


def load_proxy_configuration(path: Path) -> ProxyConfiguration:
    """Load a checked proxy configuration from a TOML file."""

    if not path.is_file():
        message = f"Configuration file does not exist: {path}"
        raise ConfigurationError(message)

    with path.open("rb") as config_file:
        document = cast(dict[str, object], tomllib.load(config_file))

    upstream_table = _require_table(document, "upstream")
    command = _resolve_command(_require_string(upstream_table, "command"))
    arguments = _string_tuple(upstream_table.get("arguments", []), "upstream.arguments")
    working_directory = _optional_path(upstream_table.get("working_directory"), path.parent)
    environment = _optional_environment(upstream_table.get("environment"))

    runtime_table = _optional_table(document, "runtime")
    database_value = runtime_table.get("trace_database", "../data/traces.db")
    trace_database = _require_path(database_value, "runtime.trace_database", path.parent)
    max_message_bytes = _positive_int(runtime_table.get("max_message_bytes", 1_000_000),
        "runtime.max_message_bytes")

    metadata_scan_table = _optional_table(document, "metadata_scan")
    metadata_scan = MetadataScanConfiguration(
        enabled=_boolean(metadata_scan_table.get("enabled", True), "metadata_scan.enabled"),
        block_on_schema_violation=_boolean(
            metadata_scan_table.get("block_on_schema_violation", True),
            "metadata_scan.block_on_schema_violation",
        ),
        block_on_suspicious_description=_boolean(
            metadata_scan_table.get("block_on_suspicious_description", True),
            "metadata_scan.block_on_suspicious_description",
        ),
        max_description_length=_positive_int(
            metadata_scan_table.get("max_description_length", 4096),
            "metadata_scan.max_description_length",
        ),
    )

    containment_table = _optional_table(document, "containment")
    containment = ContainmentConfiguration(
        enabled=_boolean(containment_table.get("enabled", False), "containment.enabled"),
        model_name=str(containment_table.get(
            "model_name", "protectai/deberta-v3-base-prompt-injection-v2",
        )),
        confidence_threshold_block=_float_between(
            containment_table.get("confidence_threshold_block", 0.85),
            "containment.confidence_threshold_block", 0.0, 1.0,
        ),
        confidence_threshold_warn=_float_between(
            containment_table.get("confidence_threshold_warn", 0.50),
            "containment.confidence_threshold_warn", 0.0, 1.0,
        ),
        high_risk_tools=_string_tuple(
            containment_table.get("high_risk_tools", ["read_file"]),
            "containment.high_risk_tools",
        ),
        use_onnx=_boolean(containment_table.get("use_onnx", False), "containment.use_onnx"),
    )

    return ProxyConfiguration(
        upstream=UpstreamConfiguration(
            command=command,
            arguments=arguments,
            working_directory=working_directory,
            environment=environment,
        ),
        trace_database=trace_database,
        max_message_bytes=max_message_bytes,
        metadata_scan=metadata_scan,
        containment=containment,
    )


def _require_table(document: dict[str, object], name: str) -> dict[str, object]:
    value = document.get(name)
    if not isinstance(value, dict):
        raise ConfigurationError(f"'{name}' must be a TOML table")
    return cast(dict[str, object], value)


def _optional_table(document: dict[str, object], name: str) -> dict[str, object]:
    value = document.get(name, {})
    if not isinstance(value, dict):
        raise ConfigurationError(f"'{name}' must be a TOML table")
    return cast(dict[str, object], value)


def _require_string(document: dict[str, object], name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"'{name}' must be a non-empty string")
    return value


def _string_tuple(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"'{name}' must be an array of strings")
    return tuple(value)


def _optional_path(value: object, base_directory: Path) -> Path | None:
    if value is None:
        return None
    return _require_path(value, "upstream.working_directory", base_directory)


def _require_path(value: object, name: str, base_directory: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"'{name}' must be a non-empty path string")
    candidate = Path(value)
    return candidate if candidate.is_absolute() else (base_directory / candidate).resolve()


def _optional_environment(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ConfigurationError("'upstream.environment' must be a table of strings")
    environment = cast(dict[str, object], value)
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in environment.items()):
        raise ConfigurationError("'upstream.environment' values must all be strings")
    return cast(dict[str, str], environment)


def _positive_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigurationError(f"'{name}' must be a positive integer")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"'{name}' must be a boolean")
    return value


def _float_between(value: object, name: str, low: float, high: float) -> float:
    if isinstance(value, bool):
        raise ConfigurationError(f"'{name}' must be a number between {low} and {high}")
    if not isinstance(value, int | float):
        raise ConfigurationError(f"'{name}' must be a number between {low} and {high}")
    result = float(value)
    if not (low <= result <= high):
        raise ConfigurationError(f"'{name}' must be between {low} and {high}, got {result}")
    return result


def _resolve_command(command: str) -> str:
    """Resolve the portable interpreter token used by bundled reference configs."""

    return sys.executable if command == "${python}" else command
