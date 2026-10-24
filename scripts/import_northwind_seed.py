"""Extract a privacy-minimized seed from the pinned upstream Northwind SQL."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

UPSTREAM_REVISION = "4f56e7f5906dfd23b25244c5bfe8fb5da6402efd"
CREATE_SHA256 = "5854b536dea3fe8c586223bf7b47a793727dd44c34fc32537a68a97fec8e2f4b"
UPDATE_SHA256 = "78863933b20cb78f0a24d4ae421781c3e3d961c29c8ee884f2e55a5e2a12c18a"


def _verified_text(path: Path, expected: str) -> str:
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ValueError(f"Unexpected SHA-256 for {path}: {actual}")
    return raw.decode("utf-8")


def extract(source: Path, destination: Path) -> None:
    """Import upstream SQL once, then export only non-personal benchmark fields."""

    create = _verified_text(source / "src" / "create.sql", CREATE_SHA256)
    update = _verified_text(source / "src" / "update.sql", UPDATE_SHA256)
    with sqlite3.connect(":memory:") as connection:
        connection.executescript(create)
        connection.executescript(update)
        tables = {
            "categories": connection.execute(
                "SELECT CategoryID, CategoryName FROM Categories ORDER BY CategoryID"
            ).fetchall(),
            "products": connection.execute(
                "SELECT ProductID, ProductName, CategoryID, UnitPrice "
                "FROM Products ORDER BY ProductID"
            ).fetchall(),
            "orders": connection.execute(
                "SELECT OrderID, OrderDate, ShipCountry FROM Orders ORDER BY OrderID"
            ).fetchall(),
            "order_details": connection.execute(
                'SELECT OrderID, ProductID, UnitPrice, Quantity, Discount '
                'FROM "Order Details" ORDER BY OrderID, ProductID'
            ).fetchall(),
        }
    payload = {
        "source": "https://github.com/jpwhite3/northwind-SQLite3",
        "revision": UPSTREAM_REVISION,
        "license": "MIT; see LICENSE.northwind",
        "create_sha256": CREATE_SHA256,
        "update_sha256": UPDATE_SHA256,
        "data": tables,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Checkout of the pinned upstream revision")
    parser.add_argument("destination", type=Path, help="Output seed JSON")
    args = parser.parse_args()
    extract(args.source, args.destination)


if __name__ == "__main__":
    main()
