# MCP-Phalanx Architecture and Research Briefing

## Project in plain language

An MCP host uses MCP servers to read files, query databases, and call other tools. MCP-Phalanx sits between that host and one MCP server. It checks tool discovery, validates tool calls, applies an allow/deny policy, and inspects returned text before the host receives it.

```text
MCP host/client
    |
    | stdio JSON-RPC
    v
MCP-Phalanx proxy -----> one persistent upstream MCP server
    |
    +---- redacted event queue ----> SQLite trace store ----> read-only dashboard
```

The proxy is the only component that forwards MCP traffic. FastAPI provides health and trace-reading endpoints; it cannot invoke tools. Local filesystem and SQLite servers provide repeatable fixtures and are intentionally vulnerable.

## Security control flow

| Stage | Direction | Control | Example decision |
|---|---|---|---|
| Discovery | Server to host | L0 checks tool metadata, names, and schemas; suspicious or malformed tools are filtered | Filter a tool whose description contains an instruction override |
| Invocation | Host to server | L1 validates arguments against a schema observed in the session | Reject an invalid argument or a path outside its configured fixture root |
| Authorization | Host to server | L2 checks a compiled TOML policy with default-deny behavior | Allow a read tool; deny unlisted or write tools |
| Response | Server to host | L3 scans text and marks suspicious content as untrusted | Preserve the text inside untrusted-data tags |

If suspicious content appears in structured output that cannot be tagged without changing its structure, L3 blocks that response. JSON-RPC request IDs and normal response correlation are preserved so the client receives a protocol-level result.

## Trace handling

The proxy records message direction, method, redacted summary, byte count, measured response latency, interceptor processing time, disposition, and optional layer/rule/reason codes. It does not store the raw tool payload. A bounded asynchronous queue batches SQLite inserts away from the message-forwarding path; when full, the queue drops trace events and attempts to record a dropped-event summary.

The dashboard renders persisted trace fields as text. It does not create sample events, latency scores, or security claims. The API should bind to localhost for this research setup.

## Demo and evaluation

`mcp-phalanx-demo benign` calls the local filesystem and read-only SQLite fixture through the proxy. `mcp-phalanx-demo attack` reads the poisoned report fixture; the expected L3 behavior is to preserve and taint-mark its text. Start `mcp-phalanx-api` separately to display the real trace events.

`mcp-phalanx-evaluate` runs the current fixture manifest for all 16 L0–L3 enabled/disabled combinations using local MCP subprocesses. It exports raw JSON and CSV records with observed dispositions, reason codes, timings, runtime environment, and Git revision. The initial corpus is only a functional smoke-test set; it is not sufficient to claim benchmark-level detection, attack-success, or false-positive rates.

## Research framing and limitations

The capstone contribution is a reproducible systems comparison of established controls across the MCP tool invocation lifecycle. It is not a new injection-detection algorithm and does not prove that prompt injection is solved or that an LLM will obey taint boundaries.

Current scope is one local stdio connection chain. The implementation does not evaluate an LLM’s final behavior, multi-call semantic chaining, adaptive attackers, direct access to the upstream server, transport/container escape, Streamable HTTP, authentication, or multi-tenant deployment. All effectiveness and performance claims require documented experiments before publication.

## Presentation sequence

1. Start `uv run mcp-phalanx-api --database data/traces.db` and open `http://127.0.0.1:8000`.
2. Run `uv run mcp-phalanx-demo benign`; show the real read-only filesystem and SQLite calls in the dashboard.
3. Run `uv run mcp-phalanx-demo attack`; show the returned poisoned text wrapped with `<untrusted_external_data>` and the associated L3 event.
4. Explain that containment reduces risk but cannot guarantee model behavior. Point to the ablation command as the reproducible next step for measured comparisons.

## Safe use

The reference servers exist only for local experiments. Keep filesystem paths within `fixtures/filesystem/`, use disposable database files, and never configure them with production data or credentials. This prototype is not hardened for deployment on a network or as a multi-user service.
