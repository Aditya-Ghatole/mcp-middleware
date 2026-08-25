# MCPShield

MCPShield is a transparent, stdio-based Model Context Protocol (MCP) proxy for
security research. An MCP host connects to MCPShield; MCPShield maintains one
persistent connection to the configured upstream MCP server and records the
real protocol traffic it forwards.

This repository currently provides the **foundation** for later defensive
layers. It does not claim to detect prompt injection yet. In particular, Layer
3 is intentionally deferred until a real classifier and containment policy are
implemented.

## Components

- `mcpshield-proxy`: the MCP data-plane proxy. It is the only component that
  forwards MCP messages.
- `mcpshield-api`: a read-only FastAPI control plane. It serves health and
  trace data; it never invokes MCP tools.
- `mcpshield-filesystem-server`: an intentionally vulnerable filesystem
  reference server, isolated to `fixtures/filesystem`.
- `mcpshield-sqlite-server`: an intentionally vulnerable SQLite reference
  server, isolated to a local database file.

## Development setup

Install [uv](https://docs.astral.sh/uv/) and run:

```powershell
uv sync --all-groups
```

Run a filesystem proxy:

```powershell
uv run mcpshield-proxy --config configs/filesystem.toml
```

In another terminal, start the dashboard API:

```powershell
uv run mcpshield-api --database data/traces.db
```

Open `http://127.0.0.1:8000`. The dashboard shows only persisted trace events;
it does not execute MCP tools.

The bundled reference configurations use `"${python}"`, which means the same
interpreter running the proxy. For an external upstream server, set `command`
and `arguments` to that server's real launch command instead.

Run checks:

```powershell
uv run ruff check .
uv run pyright
uv run pytest
```

## Safety note

The reference servers are deliberately unsafe test fixtures. They must be used
only with their included local fixtures and never with production data or
credentials.
