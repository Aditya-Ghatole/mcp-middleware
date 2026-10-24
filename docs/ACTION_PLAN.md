# MCP-Phalanx Completion and Research Action Plan

## Current implementation

- A persistent, bidirectional stdio proxy with separate read-only FastAPI dashboard.
- Deterministic L0 metadata screening, L1 invocation validation, L2 default-deny policy, and L3 inbound containment.
- Local filesystem and SQLite fixtures with demonstration TOML policies.
- Bounded, batched, redacted SQLite tracing.
- Benign and poisoned-response demo scenarios.
- A local runner for all 16 L0–L3 on/off profiles, exporting raw JSON and CSV records.

The current code is a research prototype. Passing tests shows the implementation behaves as tested; it does not establish attack prevention or production readiness.

## Work required before reporting research results

1. Review the local fixture manifest with the project supervisor and document why each benign/malicious case represents its intended category.
2. Run the full ablation suite from a clean environment. Preserve the generated raw CSV/JSON, Git revision, dependency lock, OS, and Python version with the analysis.
3. Add enough benign and malicious cases to estimate false rejection and detection rates meaningfully. The initial manifest is a smoke-test corpus, not a statistically adequate benchmark.
4. If studying LLM task utility or attack success, add a documented host/model/task harness. The current evaluator exercises MCP traffic and proxy dispositions only; it does not measure what an LLM obeys.
5. Review and cite the related-work sources in the capstone write-up. Do not state novelty for the controls themselves.

## Known technical limits

- The proxy currently supports stdio only; Streamable HTTP needs a separate transport adapter and its own protocol/security tests.
- L0 uses deterministic pattern checks and a bounded JSON Schema subset. It can miss semantic attacks and can remove benign metadata.
- L1 SQL checks use a conservative local lexer and policy constraints. They do not replace a database read-only connection or a full SQL parser.
- L3 pattern-based containment can miss attacks or flag benign content. Taint tags do not guarantee model compliance.
- Authorization is per tool call. Cross-call semantic chains and human approval flows are not implemented.
- Trace writes are asynchronous and bounded; on overload, events may be dropped and a summary event is recorded when persistence recovers.
- The dashboard has no authentication and is intended for localhost research use only.

## Research framing

Describe MCP-Phalanx as an engineering platform for a reproducible comparison of established defense patterns at MCP tool discovery, invocation, authorization, and response handling. Do not describe the project as a solved injection defense, a new algorithm, a production deployment, or an empirical result before the data has been collected and analyzed.
