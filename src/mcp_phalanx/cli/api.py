"""CLI entry point for MCP-Phalanx's read-only control plane."""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from mcp_phalanx.api.app import create_app


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the MCP-Phalanx control-plane API")
    parser.add_argument("--database", type=Path, default=Path("data/traces.db"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    return parser.parse_args()


def main() -> None:
    """Run the read-only dashboard API."""

    arguments = _arguments()
    uvicorn.run(create_app(arguments.database.resolve()), host=arguments.host, port=arguments.port)


if __name__ == "__main__":
    main()
