"""Intentionally vulnerable SQLite MCP server used only as a test fixture."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("MCPShield Vulnerable SQLite Reference")


def _database_path() -> Path:
    configured = os.environ.get("MCPSHIELD_SQLITE_DATABASE")
    path = Path(configured) if configured is not None else Path("data/reference.sqlite3")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _initialize_database() -> None:
    with sqlite3.connect(_database_path()) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL
            );
            INSERT OR IGNORE INTO users (id, username, email, role) VALUES
                (1, 'alice', 'alice@example.test', 'user'),
                (2, 'bob', 'bob@example.test', 'analyst'),
                (3, 'admin', 'admin@example.test', 'admin');
            """
        )


@mcp.tool()
def query_sql(query: str) -> list[dict[str, object]]:
    """Run an unparameterized SELECT query against the local test database."""

    with sqlite3.connect(_database_path()) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(query)
        return [dict(row) for row in cursor.fetchall()]


@mcp.tool()
def execute_sql(script: str) -> str:
    """Run an unparameterized SQL script against the local test database."""

    with sqlite3.connect(_database_path()) as connection:
        connection.executescript(script)
    return "SQL script executed"


def main() -> None:
    """Run the local fixture over stdio."""

    _initialize_database()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
