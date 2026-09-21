# MCP-Phalanx — Project Context for AI Contributors

Read this document before changing MCP-Phalanx. It explains the project’s purpose, current state, and non-negotiable engineering and academic rules.

## 1. Project in plain language

MCP-Phalanx is a local security proxy for **Model Context Protocol (MCP)** tool traffic. It sits between an MCP host (for example, an AI application) and an MCP tool server:

```text
MCP host / client  <->  MCP-Phalanx proxy  <->  upstream MCP server
                              |
                              +-> redacted trace store -> read-only dashboard
```

The proxy is the security enforcement point. It receives real JSON-RPC messages from the client, forwards them to one persistent upstream MCP server, and inspects both directions of traffic before forwarding.

This is a final-year cybersecurity capstone. The research contribution is a reproducible, combined evaluation of known defense patterns. It is **not** a claim to have invented a new defense algorithm or solved prompt injection.

## 2. Academic boundaries

Always preserve these claims and limits:

- Say the **evaluation scope and empirical comparison** are the contribution; do not call the middleware itself novel.
- Do not claim prompt injection is solved, or that Layer 3 guarantees safety.
- Do not report ASR, utility, false-positive, classifier accuracy, or latency figures unless they were produced by a documented, repeatable experiment.
- Do not put illustrative or invented metrics in the dashboard.
- Adaptive attackers, cloud/multi-tenant deployment, and a new trained model remain out of scope unless the project owner explicitly expands the scope.
- The two local reference servers are deliberately vulnerable fixtures. Never point them at real files, credentials, or production databases.

## 3. Current architecture and status

### Implemented foundation

- `src/mcp_phalanx/proxy/`: a bidirectional stdio MCP proxy. It starts one upstream process for the proxy lifetime; it does **not** start a subprocess per HTTP request.
- `src/mcp_phalanx/protocol/`: JSON-RPC inspection, response correlation, and protocol-correct blocked-message construction.
- `src/mcp_phalanx/observability/`: SQLite-backed, redacted trace events. Raw tool payloads are not stored in the dashboard trace database.
- `src/mcp_phalanx/api/`: a read-only FastAPI control plane and an honest, framework-free dashboard. It must never forward or execute MCP tool calls.
- `src/mcp_phalanx/reference_servers/`: local filesystem and SQLite MCP fixtures used for controlled experiments.
- `tests/`: unit, API, normalization, containment, and end-to-end proxy tests.

### Layer 3 status: inbound prompt-injection containment

Layer 3 lives in `src/mcp_phalanx/interceptors/containment.py`. It currently:

1. observes inbound MCP tool responses;
2. normalizes text to expose selected zero-width, homoglyph, and Base64 obfuscation attempts;
3. checks known imperative prompt-injection patterns;
4. optionally loads a configured Hugging Face classifier; and
5. taint-marks flagged text with explicit `untrusted_external_data` boundaries before forwarding it to the MCP client.

This is a containment mechanism, not proof that an LLM will ignore malicious content. If the optional ML model cannot load, the implementation must report and test its heuristic-only behavior honestly; it must not invent a score or a successful classification.

### Not yet complete

- Layer 0 metadata scanning, Layer 1 tool-parameter validation, and Layer 2 policy enforcement still need rigorous implementations and tests.
- Benchmark ingestion, experiment orchestration, ablation reporting, and CSV result exports are not yet a completed research pipeline.
- The dashboard is an operational trace viewer, not an experiment-results dashboard until real result data exists.
- The system is a local research prototype. Do not describe it as a deployed or production-proven security product.

## 4. Repository map

```text
src/mcp_phalanx/
  api/                 Read-only FastAPI API and static dashboard
  cli/                 `mcp-phalanx-*` command-line entry points
  config/              Typed TOML configuration
  interceptors/        Security-control extension points and Layer 3
  observability/       Redacted SQLite trace storage
  protocol/            JSON-RPC message helpers
  proxy/               Persistent bidirectional stdio runtime
  reference_servers/   Vulnerable filesystem and SQLite fixtures
configs/               Example upstream/proxy configurations
fixtures/              Local benign and malicious test data only
tests/                 Automated verification
docs/                  Architecture and research materials
```

`pyproject.toml` is the single dependency and tooling definition. Do not add a second dependency manifest or a second frontend copy.

## 5. Development workflow

Use Python 3.12+ and `uv`:

```powershell
uv sync --all-groups
uv run ruff check src tests
uv run pyright
uv run pytest
```

For a local filesystem demonstration:

```powershell
uv run mcp-phalanx-proxy --config configs/filesystem.toml
uv run mcp-phalanx-api --database data/traces.db
```

The proxy is normally launched by an MCP host over stdio. The API can be run separately because it only reads persisted traces.

## 6. Engineering rules for future agents

- Keep the proxy data plane independent of FastAPI and the dashboard.
- Preserve bidirectional forwarding, JSON-RPC request IDs, notifications, response types, cancellation, and upstream-process cleanup.
- Prefer typed dataclasses/Pydantic models and strict Pyright-compatible code. Avoid public `dict`/`Any` interfaces when a model can express the contract.
- Do not suppress warnings globally, swallow broad exceptions, or add fake fallback behavior. Failures must be logged and represented accurately.
- Do not log raw untrusted payloads or real secrets by default. Add explicit, documented opt-in research recording only if it is truly required.
- Keep security decisions in Python interceptors, never in browser JavaScript.
- Treat tool descriptions and all tool responses as untrusted input.
- Keep reference-server vulnerabilities isolated to `fixtures/` and clearly labelled. Never make the default configuration target user data.
- Update tests, README, and this context document when an architectural change materially changes the project’s behavior or research claims.

## 7. Useful companion documents

- `README.md`: installation and local run commands.
- `docs/MCP-Phalanx_Architectural_Briefing.md`: deeper architecture and stakeholder explanation. Treat performance and effectiveness statements in it as claims requiring validation, not as established experiment results.
- The project owner’s original capstone brief: authoritative source for the research scope, literature framing, and prohibited novelty claims.

When requirements conflict, follow the project owner’s latest instruction and preserve the academic boundaries above.
