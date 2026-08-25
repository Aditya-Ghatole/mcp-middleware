"""Intentionally vulnerable filesystem MCP server used only as a test fixture."""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("MCPShield Vulnerable Filesystem Reference")


def _sandbox_root() -> Path:
    configured = os.environ.get("MCPSHIELD_FILESYSTEM_ROOT")
    root = Path(configured) if configured is not None else Path("fixtures/filesystem/sandbox")
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def _unsafe_resolve(path: str) -> Path:
    """Join paths without canonicalisation to preserve the traversal baseline."""

    return _sandbox_root() / path


@mcp.tool()
def read_file(path: str) -> str:
    """Read a UTF-8 file relative to the vulnerable fixture sandbox."""

    return _unsafe_resolve(path).read_text(encoding="utf-8")


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write a UTF-8 file relative to the vulnerable fixture sandbox."""

    target = _unsafe_resolve(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return "OK"


@mcp.tool()
def list_directory(path: str) -> list[str]:
    """List one directory relative to the vulnerable fixture sandbox."""

    return sorted(entry.name for entry in _unsafe_resolve(path).iterdir())


@mcp.tool()
def create_directory(path: str) -> str:
    """Create a directory relative to the vulnerable fixture sandbox."""

    _unsafe_resolve(path).mkdir(parents=True, exist_ok=True)
    return "OK"


def main() -> None:
    """Run the local fixture over stdio."""

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
