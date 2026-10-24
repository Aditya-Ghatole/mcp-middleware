"""Run the local, real-process L0-L3 ablation suite and export raw evidence."""

from __future__ import annotations

import argparse
import asyncio
import csv
import itertools
import json
import platform
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

from mcp_phalanx.observability.traces import TraceEvent, TraceStore

PROJECT_ROOT = Path(__file__).parents[3]


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    """One local fixture case with a known defensive layer."""

    case_id: str
    target: str
    operation: str
    tool: str | None
    arguments: dict[str, object]
    guard_layer: str


@dataclass(frozen=True, slots=True)
class EvaluationRow:
    """One actual proxy run, safe to export as a research record."""

    profile: str
    case_id: str
    target: str
    l0_enabled: bool
    l1_enabled: bool
    l2_enabled: bool
    l3_enabled: bool
    expected_disposition: str
    observed_disposition: str
    reason_code: str | None
    elapsed_ms: float
    event_latency_ms: float | None
    git_revision: str
    python_version: str
    platform: str


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run MCP-Phalanx's local L0-L3 ablation suite")
    parser.add_argument(
        "--suite",
        type=Path,
        default=PROJECT_ROOT / "fixtures" / "evaluation" / "manifest.toml",
        help="Path to the local TOML fixture manifest",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "output" / "evaluation",
        help="Directory for timestamped CSV and JSON evidence",
    )
    return parser.parse_args()


def main() -> None:
    """Execute every L0-L3 profile using local reference MCP processes."""

    arguments = _arguments()
    cases = _load_cases(arguments.suite.resolve())
    rows = asyncio.run(_run_suite(cases))
    _write_results(arguments.output.resolve(), rows)
    print(f"Wrote {len(rows)} real evaluation rows to {arguments.output.resolve()}")


async def _run_suite(cases: tuple[EvaluationCase, ...]) -> list[EvaluationRow]:
    rows: list[EvaluationRow] = []
    for bits in itertools.product((False, True), repeat=4):
        flags = (bits[0], bits[1], bits[2], bits[3])
        profile = "-".join(
            f"l{index}={'on' if enabled else 'off'}" for index, enabled in enumerate(flags)
        )
        for case in cases:
            rows.append(await _run_case(profile, flags, case))
    return rows


async def _run_case(
    profile: str, flags: tuple[bool, bool, bool, bool], case: EvaluationCase
) -> EvaluationRow:
    l0_enabled, l1_enabled, l2_enabled, l3_enabled = flags
    started_at = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="mcp-phalanx-evaluation-") as directory_name:
        directory = Path(directory_name)
        trace_database = directory / "traces.db"
        config_path = directory / "proxy.toml"
        _write_profile_config(config_path, trace_database, case.target, flags, directory)
        await _exercise_proxy(config_path, case)
        events = await TraceStore(trace_database).list_events(after=None, limit=100)
    observed, reason_code, latency = _observe(case, events)
    return EvaluationRow(
        profile=profile,
        case_id=case.case_id,
        target=case.target,
        l0_enabled=l0_enabled,
        l1_enabled=l1_enabled,
        l2_enabled=l2_enabled,
        l3_enabled=l3_enabled,
        expected_disposition=_expected(case.guard_layer, flags),
        observed_disposition=observed,
        reason_code=reason_code,
        elapsed_ms=round((time.perf_counter() - started_at) * 1_000, 3),
        event_latency_ms=latency,
        git_revision=_git_revision(),
        python_version=sys.version.split()[0],
        platform=platform.platform(),
    )


async def _exercise_proxy(config_path: Path, case: EvaluationCase) -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_phalanx.cli.proxy", "--config", str(config_path)],
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            if case.operation == "list_tools":
                await session.list_tools()
                return
            await session.list_tools()
            if case.tool is None:
                raise ValueError(f"Case '{case.case_id}' has no tool")
            try:
                await session.call_tool(case.tool, arguments=case.arguments)
            except McpError:
                # The policy decision is observed from the proxy trace below.
                pass


def _write_profile_config(
    path: Path,
    trace_database: Path,
    target: str,
    flags: tuple[bool, bool, bool, bool],
    temporary_directory: Path,
) -> None:
    l0_enabled, l1_enabled, l2_enabled, l3_enabled = flags
    module, policy_name, high_risk = _target_settings(target)
    policy_path = PROJECT_ROOT / "configs" / "policies" / policy_name
    environment = ""
    if target == "sqlite":
        database_file = (temporary_directory / "reference.sqlite3").as_posix()
        environment = (
            "\n[upstream.environment]\n"
            f'MCP_PHALANX_SQLITE_DATABASE = "{database_file}"\n'
        )
    path.write_text(
        "\n".join(
            (
                "[upstream]",
                'command = "${python}"',
                f'arguments = ["-m", "{module}"]',
                f'working_directory = "{PROJECT_ROOT.as_posix()}"',
                "",
                "[runtime]",
                f'trace_database = "{trace_database.as_posix()}"',
                "max_message_bytes = 1000000",
                "",
                "[security]",
                f"l0_enabled = {str(l0_enabled).lower()}",
                f"l1_enabled = {str(l1_enabled).lower()}",
                f"l2_enabled = {str(l2_enabled).lower()}",
                f'policy_file = "{policy_path.as_posix()}"',
                "",
                "[containment]",
                f"enabled = {str(l3_enabled).lower()}",
                'mode = "deterministic"',
                f"high_risk_tools = {json.dumps(high_risk)}",
            )
        )
        + environment,
        encoding="utf-8",
    )


def _target_settings(target: str) -> tuple[str, str, list[str]]:
    if target == "filesystem":
        return (
            "mcp_phalanx.reference_servers.filesystem",
            "filesystem_demo.toml",
            ["read_file", "write_file", "list_directory", "create_directory"],
        )
    if target == "sqlite":
        return (
            "mcp_phalanx.reference_servers.sqlite",
            "sqlite_demo.toml",
            ["query_sql", "execute_sql"],
        )
    if target == "metadata":
        return (
            "mcp_phalanx.reference_servers.metadata",
            "filesystem_demo.toml",
            ["safe_lookup", "poisoned_lookup"],
        )
    raise ValueError(f"Unknown local evaluation target: {target}")


def _observe(
    case: EvaluationCase, events: list[TraceEvent]
) -> tuple[str, str | None, float | None]:
    relevant = [event for event in events if event.method is not None]
    if case.operation == "list_tools":
        relevant = [event for event in relevant if event.method == "tools/list"]
    elif case.tool is not None:
        relevant = [event for event in relevant if event.method == f"tools/call:{case.tool}"]
    if not relevant:
        return "no_trace", None, None
    event = relevant[0]
    return event.disposition, event.reason_code, event.latency_ms


def _expected(guard_layer: str, flags: tuple[bool, bool, bool, bool]) -> str:
    layer_index = {"l0": 0, "l1": 1, "l2": 2, "l3": 3}.get(guard_layer)
    if layer_index is None:
        return "forward"
    if not flags[layer_index]:
        return "forward"
    return "filter" if guard_layer == "l0" else "taint" if guard_layer == "l3" else "block"


def _load_cases(path: Path) -> tuple[EvaluationCase, ...]:
    with path.open("rb") as suite_file:
        document = cast(dict[str, object], tomllib.load(suite_file))
    raw_cases = document.get("case")
    if not isinstance(raw_cases, list):
        raise ValueError("Evaluation manifest must contain [[case]] entries")
    parsed: list[EvaluationCase] = []
    for raw_case in cast(list[object], raw_cases):
        if not isinstance(raw_case, dict):
            raise ValueError("Every evaluation case must be a TOML table")
        item = cast(dict[str, object], raw_case)
        arguments = item.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ValueError("case.arguments must be a TOML table")
        raw_arguments = cast(dict[object, object], arguments)
        if not all(isinstance(key, str) for key in raw_arguments):
            raise ValueError("case.arguments keys must be strings")
        typed_arguments = {
            key: value for key, value in raw_arguments.items() if isinstance(key, str)
        }
        parsed.append(
            EvaluationCase(
                case_id=_required_string(item, "id"),
                target=_required_string(item, "target"),
                operation=_required_string(item, "operation"),
                tool=_optional_string(item.get("tool")),
                arguments=typed_arguments,
                guard_layer=_required_string(item, "guard_layer"),
            )
        )
    return tuple(parsed)


def _required_string(document: dict[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Evaluation case field '{key}' must be a non-empty string")
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("Evaluation case field 'tool' must be a non-empty string")
    return value


def _write_results(output_directory: Path, rows: list[EvaluationRow]) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    records = [asdict(row) for row in rows]
    json_path = output_directory / f"ablation-{stamp}.json"
    csv_path = output_directory / f"ablation-{stamp}.csv"
    json_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)


def _git_revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unavailable"
