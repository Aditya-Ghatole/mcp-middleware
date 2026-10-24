"""Run repeatable local benign and poisoned-response demonstrations."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT_ROOT = Path(__file__).parents[3]


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a local MCP-Phalanx presentation scenario")
    parser.add_argument(
        "scenario",
        choices=("benign", "attack"),
        help="Run safe filesystem/SQLite calls or inspect the poisoned fixture response",
    )
    return parser.parse_args()


def main() -> None:
    """Run the selected scenario against the local demo proxy configurations."""

    asyncio.run(_run(_arguments().scenario))


async def _run(scenario: str) -> None:
    if scenario == "benign":
        print("Scenario: benign local filesystem and read-only SQLite calls")
        filesystem_result = await _call(
            PROJECT_ROOT / "configs" / "filesystem.toml",
            "read_file",
            {"path": "docs/report_2026.txt"},
        )
        print("Filesystem result:")
        print(filesystem_result)
        sqlite_result = await _call(
            PROJECT_ROOT / "configs" / "sqlite.toml",
            "query_sql",
            {"query": "SELECT username, role FROM users ORDER BY id"},
        )
        print("SQLite result:")
        print(sqlite_result)
        return

    print("Scenario: suspicious instructions in an intentionally poisoned local fixture")
    result = await _call(
        PROJECT_ROOT / "configs" / "filesystem.toml",
        "read_file",
        {"path": "docs/poisoned_report.txt"},
    )
    print("The proxy should preserve the fixture text and mark it as untrusted:")
    print(result)


async def _call(config_path: Path, tool_name: str, arguments: dict[str, object]) -> str:
    """Call a tool through its real configured MCP-Phalanx subprocess proxy."""

    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "mcp_phalanx.cli.proxy",
            "--config",
            str(config_path),
        ],
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()
            result = await session.call_tool(tool_name, arguments=arguments)
            return result.model_dump_json(indent=2, by_alias=True)
