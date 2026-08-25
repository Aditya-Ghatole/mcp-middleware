"""End-to-end tests using the actual stdio proxy and local MCP fixtures."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

from mcpshield.observability.traces import TraceStore

PROJECT_ROOT = Path(__file__).parents[1]


def test_filesystem_server_is_reached_through_proxy(tmp_path: Path) -> None:
    """A real MCP client can list and call tools through one proxy process."""

    config_path = _write_config(tmp_path, "mcpshield.reference_servers.filesystem")

    async def scenario() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcpshield.cli.proxy", "--config", str(config_path)],
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

    asyncio.run(scenario())
    events = asyncio.run(TraceStore(tmp_path / "traces.db").list_events(after=None, limit=20))
    assert any(event.method == "tools/call" for event in events)
    assert any(event.latency_ms is not None for event in events)


def test_sqlite_server_is_reached_through_proxy(tmp_path: Path) -> None:
    """The local SQLite MCP server is a usable second reference target."""

    database_path = tmp_path / "reference.sqlite3"
    config_path = _write_config(
        tmp_path,
        "mcpshield.reference_servers.sqlite",
        extra_environment={"MCPSHIELD_SQLITE_DATABASE": database_path.as_posix()},
    )

    async def scenario() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcpshield.cli.proxy", "--config", str(config_path)],
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

    asyncio.run(scenario())


def _write_config(
    directory: Path, module: str, extra_environment: dict[str, str] | None = None
) -> Path:
    environment_lines = ""
    if extra_environment is not None:
        environment_lines = "\n[upstream.environment]\n" + "\n".join(
            f'{key} = "{value}"' for key, value in extra_environment.items()
        )
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
            ]
        )
        + environment_lines
        + "\n",
        encoding="utf-8",
    )
    return config_path
