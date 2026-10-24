# MCP-Phalanx

MCP-Phalanx is a local research prototype that places a Python stdio proxy between an MCP host and one upstream MCP server. The proxy inspects real JSON-RPC messages, applies optional security controls, and writes redacted trace events to SQLite. A separate, read-only FastAPI dashboard displays those events.

```text
MCP host  <->  MCP-Phalanx stdio proxy  <->  one persistent MCP server process
                         |
                         +--> bounded trace queue --> SQLite --> read-only dashboard
```

This is a cybersecurity capstone prototype, not a production-proven security product. The research contribution is a reproducible comparison of established defensive controls. MCP-Phalanx does not claim a novel detection algorithm or that prompt injection can be solved.

## Controls

- **L0 — tool discovery:** checks tool names and bounded JSON Schema metadata; removes tools with malformed schemas or instruction-override text from discovery results.
- **L1 — invocation validation:** validates call arguments against schemas discovered in the current session. Policy can constrain filesystem paths and SQL to one read-only statement.
- **L2 — authorization:** applies a separately configured TOML policy. Unknown tools are denied by default.
- **L3 — inbound containment:** normalizes selected text obfuscations, detects known instruction-override patterns, and taint-marks suspicious text. Suspicious strings in structured output are blocked when they cannot be wrapped safely.

These controls have known limits. Pattern matching can miss attacks or flag benign text; taint markers do not guarantee that an LLM will ignore content. Policy enforcement evaluates each call independently and does not detect multi-call semantic chaining.

## Install and check

Requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync --all-groups
uv run ruff check src tests
uv run pyright
uv run pytest
```

The default configuration uses deterministic, local controls and does not load or download a model.

## Presentation demo

Start the dashboard in one terminal:

```powershell
uv run mcp-phalanx-api --database data/traces.db
```

Open `http://127.0.0.1:8000`. In another terminal, run the two local scenarios:

```powershell
uv run mcp-phalanx-demo benign
uv run mcp-phalanx-demo attack
```

The benign scenario reads the fixture report and queries the local SQLite fixture using a read-only query. The attack scenario reads a deliberately poisoned fixture file; L3 should preserve its content while wrapping it as untrusted. The dashboard displays only real events emitted by those proxy runs.

The demonstration configurations and policies are in `configs/` and `configs/policies/`. Each proxy process starts one upstream server for its lifetime. The API process cannot execute tools.

## Northwind research fixture

The read-only Northwind MCP server uses a deterministic, synthetic expansion of the bundled MIT-licensed seed. Generated SQLite databases are local artifacts and are not committed to Git. From the project root, build the clean and poisoned variants before using `configs/northwind_clean.toml` or `configs/northwind_poisoned.toml`:

```powershell
uv run mcp-phalanx-build-db
```

The builder writes both databases and a manifest with the source revision, seed, row counts, and checksums under `data/northwind/`. The expanded transactions are synthetic, not real company records. The server offers only named, read-only lookup and summary tools; the poisoned variant changes designated product-note text for research tests.

## Local evaluation

Run the complete 2⁴ layer ablation against real local MCP subprocesses:

```powershell
uv run mcp-phalanx-evaluate
```

The runner executes every L0–L3 on/off profile for the cases in `fixtures/evaluation/manifest.toml`. It writes timestamped raw JSON and CSV records to `output/evaluation/`; those files include observed decisions, reason codes, timings, platform, Python version, and Git revision. The runner does not calculate or invent attack-success or utility metrics. Add cases to the manifest and document their expected outcomes before interpreting the records.

## Optional classifier

The classifier is an explicit, optional experiment mode. Install its dependencies with `uv sync --extra classifier`, set `mode = "classifier"` in the containment configuration, and ensure the selected model is already available locally for offline use. The default deterministic mode does not import the classifier package or access a model registry.

## Safety and research limits

The filesystem and SQLite MCP servers are intentionally vulnerable fixtures. Use them only with files under `fixtures/filesystem/` and disposable local databases. Do not connect them to real user data, credentials, or production systems.

The current scope is stdio tool traffic in a single local process chain. Streamable HTTP, authentication, multi-tenant operation, container escape, direct access to the upstream server, adaptive attackers, stateful cross-call analysis, and end-to-end evaluation with an LLM agent are outside this implementation. Treat all effectiveness and performance claims as unproven until documented experiments support them.
