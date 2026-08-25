"""Small real MCP client used to exercise a configured MCPShield proxy."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import cast

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Call a real MCPShield proxy")
    parser.add_argument("--config", required=True, type=Path, help="Path passed to mcpshield-proxy")
    parser.add_argument("--tool", default="read_file", help="Tool name to call after listing tools")
    parser.add_argument(
        "--arguments",
        default='{"path": "docs/report_2026.txt"}',
        help="JSON object supplied to the selected tool",
    )
    return parser.parse_args()


async def _run(config_path: Path, tool_name: str, raw_arguments: str) -> None:
    parsed_arguments = json.loads(raw_arguments)
    if not isinstance(parsed_arguments, dict):
        raise ValueError("--arguments must decode to a JSON object")
    arguments = cast(dict[str, object], parsed_arguments)
    proxy_parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcpshield.cli.proxy", "--config", str(config_path.resolve())],  # noqa: ASYNC240
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
    asyncio.run(_run(arguments.config, arguments.tool, arguments.arguments))


if __name__ == "__main__":
    main()
