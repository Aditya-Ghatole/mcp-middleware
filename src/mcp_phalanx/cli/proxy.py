"""CLI entry point for the MCP data-plane proxy."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import anyio

from mcp_phalanx.config.settings import load_proxy_configuration
from mcp_phalanx.observability.traces import TraceStore
from mcp_phalanx.proxy.runtime import ProxyRuntime


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the MCP-Phalanx stdio proxy")
    parser.add_argument("--config", required=True, type=Path, help="Path to a proxy TOML file")
    parser.add_argument("--log-level", default="INFO", help="Python log level")
    return parser.parse_args()


async def _run(config_path: Path) -> None:
    configuration = load_proxy_configuration(config_path.resolve())  # noqa: ASYNC240
    runtime = ProxyRuntime(configuration, TraceStore(configuration.trace_database))
    await runtime.run()


def main() -> None:
    """Run the proxy until its host disconnects."""

    arguments = _arguments()
    logging.basicConfig(
        level=arguments.log_level.upper(), 
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    anyio.run(_run, arguments.config)


if __name__ == "__main__":
    main()
