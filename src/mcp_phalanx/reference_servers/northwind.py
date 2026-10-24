"""Read-only Northwind MCP server backed by a synthetic research fixture."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import cast

from mcp.server.fastmcp import FastMCP

MAX_ROWS = 50
MAX_OUTPUT_BYTES = 24_000
QUERY_TIMEOUT_SECONDS = 5.0


class NorthwindDatabase:
    """Prepared, bounded queries over a read-only SQLite snapshot."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"Build the Northwind fixture first: {self.path}")
        self._local = threading.local()

    def _connection(self) -> sqlite3.Connection:
        existing = getattr(self._local, "connection", None)
        if isinstance(existing, sqlite3.Connection):
            return existing
        connection = sqlite3.connect(f"{self.path.as_uri()}?mode=ro", uri=True, timeout=1.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        self._local.connection = connection
        return connection

    def _query(self, statement: str, parameters: tuple[object, ...]) -> list[dict[str, object]]:
        connection = self._connection()
        deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
        connection.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 1_000)
        try:
            cursor = connection.execute(statement, parameters)
            rows = [dict(row) for row in cursor.fetchmany(MAX_ROWS + 1)]
        finally:
            connection.set_progress_handler(None, 0)
        if len(rows) > MAX_ROWS:
            raise ValueError("Result exceeded the server row limit")
        return cast(list[dict[str, object]], rows)

    @staticmethod
    def _json(rows: list[dict[str, object]]) -> str:
        text = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
        if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("Result exceeded the server byte limit")
        return text

    def search_products(self, text: str, *, cursor: int = 0, limit: int = 20) -> str:
        if not 1 <= len(text.strip()) <= 80 or not 1 <= limit <= MAX_ROWS or cursor < 0:
            raise ValueError("Invalid search parameters")
        escaped = text.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return self._json(
            self._query(
                "SELECT p.id, p.name, c.name AS category, p.price_cents "
                "FROM products p JOIN categories c ON c.id = p.category_id "
                "WHERE p.id > ? AND p.name LIKE ? ESCAPE '\\' "
                "ORDER BY p.id LIMIT ?",
                (cursor, f"%{escaped}%", limit),
            )
        )

    def get_product(self, product_id: int) -> str:
        if product_id < 1:
            raise ValueError("product_id must be positive")
        return self._json(
            self._query(
                "SELECT p.id, p.name, c.name AS category, p.price_cents "
                "FROM products p JOIN categories c ON c.id = p.category_id WHERE p.id = ?",
                (product_id,),
            )
        )

    def get_order(self, order_id: int) -> str:
        if order_id < 1:
            raise ValueError("order_id must be positive")
        return self._json(
            self._query(
                "SELECT o.id AS order_id, o.order_date, o.ship_country, "
                "i.product_id, p.name AS product_name, i.quantity, i.net_cents "
                "FROM orders o JOIN order_items i ON i.order_id = o.id "
                "JOIN products p ON p.id = i.product_id "
                "WHERE o.id = ? ORDER BY i.id",
                (order_id,),
            )
        )

    def sales_summary(self, product_id: int) -> str:
        if product_id < 1:
            raise ValueError("product_id must be positive")
        return self._json(
            self._query(
                "SELECT p.id AS product_id, p.name, COUNT(i.id) AS line_count, "
                "COALESCE(SUM(i.quantity), 0) AS units_sold, "
                "COALESCE(SUM(i.net_cents), 0) AS sales_cents "
                "FROM products p LEFT JOIN order_items i ON i.product_id = p.id "
                "WHERE p.id = ? GROUP BY p.id",
                (product_id,),
            )
        )

    def get_product_note(self, product_id: int) -> str:
        if product_id < 1:
            raise ValueError("product_id must be positive")
        rows = self._query(
            "SELECT p.id, p.name, n.note FROM products p "
            "JOIN product_notes n ON n.product_id = p.id WHERE p.id = ?",
            (product_id,),
        )
        if not rows:
            return "No note found."
        note = str(rows[0]["note"])
        if len(note.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("Note exceeded the server byte limit")
        return f"Product {product_id} ({rows[0]['name']}) catalog note:\n{note}"


def create_server(database: NorthwindDatabase) -> FastMCP:
    """Expose only named read-only operations; no SQL execution tool exists."""

    server = FastMCP("MCP-Phalanx Northwind Read-only Fixture")

    @server.tool()
    def search_products(text: str, cursor: int = 0, limit: int = 20) -> str:
        """Search catalog product names. Use cursor for the next page."""

        return database.search_products(text, cursor=cursor, limit=limit)

    @server.tool()
    def get_product(product_id: int) -> str:
        """Look up a product's ID, name, category, and price in cents."""

        return database.get_product(product_id)

    @server.tool()
    def get_order(order_id: int) -> str:
        """Look up one order and its five line items; amounts are integer cents."""

        return database.get_order(order_id)

    @server.tool()
    def sales_summary(product_id: int) -> str:
        """Calculate units and net sales for one product across all orders."""

        return database.sales_summary(product_id)

    @server.tool()
    def get_product_note(product_id: int) -> str:
        """Read an untrusted external catalog note about a product."""

        return database.get_product_note(product_id)

    return server


def main() -> None:
    """Run the read-only fixture over stdio."""

    configured = os.environ.get("MCP_PHALANX_NORTHWIND_DATABASE")
    if not configured:
        raise RuntimeError("MCP_PHALANX_NORTHWIND_DATABASE must point to a built fixture")
    create_server(NorthwindDatabase(Path(configured))).run(transport="stdio")


if __name__ == "__main__":
    main()
