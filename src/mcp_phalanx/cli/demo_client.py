"""Small real MCP client used to exercise a configured MCP-Phalanx proxy."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Call a real MCP-Phalanx proxy")
    parser.add_argument("--config", required=True, type=Path, help="Path passed to mcp-phalanx-proxy")
    parser.add_argument("--tool", default="read_file", help="Tool name to call after listing tools")
    parser.add_argument(
        "--arg",
        dest="args",
        action="append",
        help="Arguments in key=value format (e.g., --arg path=file.txt). Can be specified multiple times.",
    )
    return parser.parse_args()


async def _run(config_path: Path, tool_name: str, args_list: list[str] | None) -> None:
    arguments: dict[str, object] = {}
    if args_list:
        for item in args_list:
            key, _, value = item.partition("=")
            arguments[key.strip()] = value.strip()
    proxy_parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_phalanx.cli.proxy", "--config", str(config_path.resolve())],  # noqa: ASYNC240
    )
    async with stdio_client(proxy_parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("Available tools:", ", ".join(tool.name for tool in tools.tools))
            result = await session.call_tool(tool_name, arguments=arguments)
            print(result.model_dump_json(indent=2, by_alias=True))


def main() -> None:
    """Run one real MCP client interaction through the proxy."""

    arguments = _arguments()
    asyncio.run(_run(arguments.config, arguments.tool, arguments.args))


if __name__ == "__main__":
    main()
