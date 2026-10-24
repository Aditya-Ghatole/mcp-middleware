# MCP-Phalanx — Project Context for AI Contributors

Read this file before changing the repository. It records the project purpose, current implementation, and academic boundaries.

## Purpose

MCP-Phalanx is a local Python stdio proxy for Model Context Protocol (MCP) traffic:

```text
MCP host/client <-> MCP-Phalanx proxy <-> one persistent upstream MCP server
                            |
                            +-> redacted SQLite traces -> read-only FastAPI dashboard
```

It is a final-year cybersecurity capstone prototype. The research contribution is a reproducible empirical comparison of established controls across a local MCP tool invocation lifecycle. Do not claim the controls or middleware are novel, or that they solve prompt injection.

## Current implementation

- `src/mcp_phalanx/proxy/`: bidirectional stdio forwarding, request correlation, and one upstream subprocess per proxy lifetime.
- `src/mcp_phalanx/interceptors/metadata.py`: L0 tool metadata/schema checks and filtering. Accepted schemas use a bounded, local-reference-free JSON Schema subset.
- `src/mcp_phalanx/interceptors/validation.py`: L1 validation of arguments against schemas discovered in the current MCP session, including path-root and read-only SQL constraints from policy.
- `src/mcp_phalanx/interceptors/policy.py`: L2 default-deny tool authorization.
- `src/mcp_phalanx/interceptors/containment.py`: L3 deterministic text scanning, normalization, taint wrapping, and blocking of suspicious structured output.
- `src/mcp_phalanx/security/`: typed TOML policy and per-session tool registry/request ledger.
- `src/mcp_phalanx/observability/`: bounded asynchronous trace queue and batched SQLite writes; raw tool payloads are not persisted.
- `src/mcp_phalanx/api/`: read-only FastAPI trace and health API with a simple dashboard. It never executes MCP calls.
- `src/mcp_phalanx/reference_servers/`: intentionally vulnerable local filesystem and SQLite fixtures, plus a poisoned metadata fixture for L0 experiments.
- `src/mcp_phalanx/cli/demo.py`: repeatable benign and poisoned-response scenarios.
- `src/mcp_phalanx/cli/evaluate.py`: local 16-profile L0–L3 ablation runner with raw CSV/JSON evidence output.

The demonstration profiles in `configs/` enable deterministic L0–L3 controls. The optional classifier mode is off by default and requires its extra dependencies and a locally available model for offline use.

## Academic and safety boundaries

- The evaluation scope and evidence are the contribution; the controls are established defensive patterns.
- A regex or classifier result is not a guarantee that the LLM will ignore malicious content.
- Never report attack-success, utility, false-positive, accuracy, or performance measurements as facts unless reproducible runs produced them.
- Keep the dashboard limited to real stored events. Do not invent traffic or metrics.
- Reference servers are deliberately unsafe. Use only fixture files and disposable databases.
- Current scope is local stdio tool traffic. Streamable HTTP, production deployment, authentication, cloud/multi-tenant operation, container escape, adaptive attackers, stateful semantic chaining, and LLM-agent outcome evaluation are not implemented claims.

## Development

Use Python 3.12+ and `uv`:

```powershell
uv sync --all-groups
uv run ruff check src tests
uv run pyright
uv run pytest
uv run mcp-phalanx-demo benign
uv run mcp-phalanx-demo attack
uv run mcp-phalanx-evaluate
```

The API and proxy run as separate processes. The proxy is launched over stdio by an MCP host; the API reads the shared SQLite trace file. All security decisions belong in Python interceptors, never in browser JavaScript.

## Engineering rules

- Preserve JSON-RPC IDs, request/response correlation, notifications, cancellation, pagination, error responses, and upstream process cleanup.
- Keep the proxy independent from FastAPI and the dashboard.
- Keep policy compiled once at startup and session tool schemas scoped to that host session.
- Keep trace records redacted; never log or store untrusted payloads by default.
- Fail clearly on invalid configuration, policy, or explicit classifier setup. Do not silently degrade classifier mode.
- Use typed models at system boundaries and keep `uv run ruff check src tests`, strict Pyright, and the test suite passing.
- Update tests, README, this file, and the action plan when behavior or research claims change.
