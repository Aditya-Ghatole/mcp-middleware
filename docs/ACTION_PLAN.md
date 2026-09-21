# MCP Middleware Improvement Action Plan

This document outlines the step-by-step action plan to address the academic, structural, and security concerns raised during our architectural review. The plan is organized by difficulty, allowing us to tackle the "quick wins" first before moving into deep engineering work.

---

## Phase 1: Quick Wins & Hygiene (Easy)
*These tasks resolve immediate academic red flags and branding collisions with minimal code impact.*

- [ ] **Step 1.1: Project Renaming & Branding Update**
  - **Why:** The name "MCP-Phalanx" collides exactly with a 2026 Zhou et al. arXiv preprint. Keeping it will cause citation confusion and reviewer pushback.
  - **Action:** Select a new name (e.g., `MCP-Gate`, `LayerGuard-MCP`, or `Aegis-MCP`). 
  - **Codebase impact:** Perform a global find-and-replace in `PROJECT_CONTEXT.md`, `README.md`, `pyproject.toml`, the CLI entry points, and Python package structure (`src/mcp_phalanx` -> `src/new_name`).

- [ ] **Step 1.2: Literature Review Correction**
  - **Why:** Rows 6 and 9 (Siameh et al.) in the literature spreadsheet are the preprint and conference versions of the same paper, reporting identical metrics.
  - **Action:** Merge these into a single citation cluster in any related work drafts or review scripts (e.g., `build_review_paper.py`). Ensure the total paper count reaches the target >30 cleanly using the 13 new papers vetted in our previous conversation.

---

## Phase 2: Academic Framing & Scope Definition (Medium)
*These tasks involve updating the project's documentation to establish an "ironclad" novelty defense and protect against "incremental novelty" rejections.*

- [ ] **Step 2.1: Define the "Tool Invocation Lifecycle" Scope**
  - **Why:** Reviewers will attack the phrase "end-to-end pipeline" by pointing out network MITM attacks or base-model jailbreaks.
  - **Action:** Update `docs/MCP-Phalanx_Architectural_Briefing.md` and your paper draft to explicitly state the pipeline secures the *Tool Invocation Lifecycle* (Discovery -> Intent -> Authorization -> Integration), explicitly placing transport-layer and container-escape vulnerabilities out of scope.

- [ ] **Step 2.2: Document the "Semantic Chaining" Limitation**
  - **Why:** The pipeline currently appears stateless, meaning an attacker could exfiltrate data by splitting steps across multiple benign-looking tool calls.
  - **Action:** Add a "Threat Model Limitations" section explicitly stating that the proxy evaluates tool calls in isolation. Acknowledge that defending against stateful "semantic chaining" remains future work.

- [ ] **Step 2.3: Position as a "Systems-Engineering Solution"**
  - **Why:** If the paper claims to invent RBAC or parameter validation, it will be rejected.
  - **Action:** In the introduction, clarify that the novelty lies in integrating established primitives (WAF, RBAC, heuristics) into a holistic, deterministic, transparent stdio proxy for MCP, proven via a 2⁴ factorial ablation.

---

## Phase 3: Engineering Depth for L0, L1, & L2 (Medium-Hard)
*The codebase already has a great foundation (a true bidirectional stdio proxy, not just an API wrapper), and L3 uses deterministic heuristics/tainting. We need to build out the missing layers with enough engineering depth to impress systems reviewers.*

- [ ] **Step 3.1: Implement L0 (Metadata Scanning)**
  - **Action:** Build static analysis for the `tools/list` response. Don't just check for "bad words"—validate schema ASTs and ensure tool descriptions don't contain embedded system-prompt overrides.

- [ ] **Step 3.2: Implement L1 (Parameter Validation)**
  - **Action:** Build deep payload inspection for `tools/call` parameters. Go beyond basic JSON type-checking (e.g., detecting path traversal `../` in file paths or SQL injection payloads in string arguments).

- [ ] **Step 3.3: Implement L2 (Policy Enforcement)**
  - **Action:** Build the high-performance YAML gate. This needs to be fast—compile the YAML policies into a quick-lookup structure in Python to minimize latency overhead during tool calls.

---

## Phase 4: Performance & Evaluation Rigor (Hard)
*A 2⁴ factorial ablation is useless if the system is too slow or blocks legitimate user requests.*

- [ ] **Step 4.1: Implement Latency Benchmarking**
  - **Why:** Systems papers die if performance overhead isn't tracked.
  - **Action:** Instrument the proxy (`src/mcp_phalanx/proxy/`) to track exactly how many milliseconds L0, L1, L2, and L3 add to the request/response cycle. Store these timings in the `observability` trace database.

- [ ] **Step 4.2: Measure False Positive Rates (Utility Drop)**
  - **Why:** A proxy that blocks all attacks but also blocks legitimate work is useless.
  - **Action:** Update the ablation orchestration script to track False Rejection Rate (FRR) by running known-benign agent workflows (e.g., from AgentDojo) and measuring how often L1 or L3 incorrectly triggers.

- [ ] **Step 4.3: Execute the 2⁴ Factorial Ablation**
  - **Why:** This is the core research contribution.
  - **Action:** Finalize the benchmark ingestion and orchestration to run the 16 combinations (L0..L3 on/off). Use a deterministic local setup or temperature=0 API calls to ensure reproducibility and keep costs down.
