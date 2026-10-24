"""End-to-end tests using the actual stdio proxy and local MCP fixtures."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from mcp.types import TextContent

from mcp_phalanx.observability.traces import TraceStore

PROJECT_ROOT = Path(__file__).parents[1]


def test_filesystem_server_is_reached_through_proxy(tmp_path: Path) -> None:
    """A real MCP client can list and call tools through one proxy process."""

    config_path = _write_config(tmp_path, "mcp_phalanx.reference_servers.filesystem")

    async def scenario() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_phalanx.cli.proxy", "--config", str(config_path)],
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert "read_file" in {tool.name for tool in tools.tools}
                result = await session.call_tool(
                    "read_file", arguments={"path": "docs/report_2026.txt"}
                )
                assert isinstance(result.content[0], TextContent)
                assert "Revenue up 14%" in result.content[0].text
                poisoned = await session.call_tool(
                    "read_file", arguments={"path": "docs/poisoned_report.txt"}
                )
                assert isinstance(poisoned.content[0], TextContent)
                assert "<untrusted_external_data>" in poisoned.content[0].text
                try:
                    await session.call_tool(
                        "read_file", arguments={"path": "../outside_sandbox/sentinel.txt"}
                    )
                except McpError:
                    pass
                else:
                    raise AssertionError("path traversal should receive a JSON-RPC error")
                try:
                    await session.call_tool(
                        "write_file",
                        arguments={"path": "docs/should_not_exist.txt", "content": "x"},
                    )
                except McpError:
                    pass
                else:
                    raise AssertionError("write_file should be denied by the demo policy")

    asyncio.run(scenario())
    events = asyncio.run(TraceStore(tmp_path / "traces.db").list_events(after=None, limit=20))
    assert any(event.method == "tools/call:read_file" for event in events)
    assert any(event.latency_ms is not None for event in events)
    assert any(event.disposition == "taint" for event in events)
    assert any(event.reason_code == "L1_PATH_OUTSIDE_ALLOWED_ROOT" for event in events)
    assert any(event.reason_code == "L2_DEFAULT_DENY" for event in events)
    trace_summaries = "\n".join(event.summary for event in events)
    assert "Revenue up 14%" not in trace_summaries
    assert "Ignore all previous instructions" not in trace_summaries
    assert "docs/report_2026.txt" not in trace_summaries


def test_sqlite_server_is_reached_through_proxy(tmp_path: Path) -> None:
    """The local SQLite MCP server is a usable second reference target."""

    database_path = tmp_path / "reference.sqlite3"
    config_path = _write_config(
        tmp_path,
        "mcp_phalanx.reference_servers.sqlite",
        extra_environment={"MCP_PHALANX_SQLITE_DATABASE": database_path.as_posix()},
    )

    async def scenario() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_phalanx.cli.proxy", "--config", str(config_path)],
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert "query_sql" in {tool.name for tool in tools.tools}
                result = await session.call_tool(
                    "query_sql", arguments={"query": "SELECT username FROM users ORDER BY id"}
                )
                assert result.isError is False
                assert result.structuredContent is not None
                try:
                    await session.call_tool(
                        "query_sql",
                        arguments={"query": "SELECT username FROM users; DELETE FROM users"},
                    )
                except McpError:
                    pass
                else:
                    raise AssertionError("multi-statement SQL should be denied")
                try:
                    await session.call_tool(
                        "execute_sql", arguments={"script": "DROP TABLE users"}
                    )
                except McpError:
                    pass
                else:
                    raise AssertionError("execute_sql should be denied by the demo policy")

    asyncio.run(scenario())


def test_l0_filters_poisoned_tool_description_in_real_mcp_session(tmp_path: Path) -> None:
    """A host sees only the safe tool definition after a real proxied tools/list."""

    config_path = _write_config(tmp_path, "mcp_phalanx.reference_servers.metadata")

    async def scenario() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_phalanx.cli.proxy", "--config", str(config_path)],
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = {tool.name for tool in tools.tools}
                assert "safe_lookup" in names
                assert "poisoned_lookup" not in names

    asyncio.run(scenario())
    events = asyncio.run(TraceStore(tmp_path / "traces.db").list_events(after=None, limit=20))
    assert any(event.disposition == "filter" for event in events)
    assert any(event.reason_code == "L0_TOOL_FILTERED" for event in events)


def _write_config(
    directory: Path, module: str, extra_environment: dict[str, str] | None = None
) -> Path:
    environment_lines = ""
    if extra_environment is not None:
        environment_lines = "\n[upstream.environment]\n" + "\n".join(
            f'{key} = "{value}"' for key, value in extra_environment.items()
        )
    policy_name = "sqlite_demo.toml" if module.endswith("sqlite") else "filesystem_demo.toml"
    policy_path = (PROJECT_ROOT / "configs" / "policies" / policy_name).as_posix()
    config_path = directory / "proxy.toml"
    config_path.write_text(
        "\n".join(
            [
                "[upstream]",
                'command = "${python}"',
                f'arguments = ["-m", "{module}"]',
                f'working_directory = "{PROJECT_ROOT.as_posix()}"',
                "",
                "[runtime]",
                'trace_database = "traces.db"',
                "max_message_bytes = 1000000",
                "",
                "[security]",
                "l0_enabled = true",
                "l1_enabled = true",
                "l2_enabled = true",
                f'policy_file = "{policy_path}"',
                "",
                "[containment]",
                "enabled = true",
                'mode = "deterministic"',
                'high_risk_tools = ["read_file", "query_sql", "execute_sql"]',
            ]
        )
        + environment_lines
        + "\n",
        encoding="utf-8",
    )
    return config_path
