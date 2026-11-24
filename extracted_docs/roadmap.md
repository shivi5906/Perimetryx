# Roadmap

```text
Basic subdomain scanner
        ↓
Asset discovery tool
        ↓
Attack surface mapper
        ↓
Security intelligence platform
        ↓
AI-assisted recon analyst
        ↓
Agentic security research platform
```

Each phase below lists scope, difficulty, dependencies, and an honest note on what's easy to underestimate.

---

## Phase 0 — Research & Architecture
**Difficulty:** Low effort, high importance. **Dependencies:** none.

- Write the threat model: what can go wrong if this tool is misused or misconfigured (scanning out-of-scope targets, leaking scan data, AI hallucinating a false positive that gets acted on).
- Finalize scope-control mechanism (`scope.yaml` format) before writing any scanning code.
- Lock the MVP data model (even a rough ER diagram) — changing core entities later is expensive.

## Phase 1 — Basic Recon Engine
**Difficulty:** Medium. **Dependencies:** Phase 0 data model + scope guard.

- Domain input + normalization + Scope Guard enforcement
- Passive subdomain discovery (CT logs at minimum)
- DNS resolution (A/AAAA/CNAME/MX/NS/TXT)
- Basic HTTP probing (status, title, headers)
- SQLite storage
- **Underestimated part:** rate limiting and timeout handling for hundreds of concurrent HTTP/DNS calls — build this correctly now, it's painful to retrofit.

## Phase 2 — Asset Intelligence
**Difficulty:** Medium. **Dependencies:** Phase 1 complete.

- Technology fingerprinting (headers/cert/body signatures)
- Certificate intelligence (issuer, SAN list, expiry — SANs are a great secondary source of subdomains)
- Richer HTTP metadata (redirect chains, response timing/size)
- DNS analysis (CNAME chains, MX/NS anomalies)
- Environment classification heuristics (prod/staging/dev from hostname + headers)

## Phase 3 — Security Analysis
**Difficulty:** Medium-High. **Dependencies:** Phase 2 (needs technology + DNS data as input to rules).

- Security header checks (CSP, HSTS, X-Frame-Options, etc.)
- TLS configuration indicators (protocol version, cert validity — not active cipher-suite probing in MVP)
- Dev/staging exposure detection
- Dangling CNAME / potential subdomain takeover *indicators* (flag only — confirming takeover requires active verification, which needs its own explicit consent flag in scope config)
- Deterministic risk scoring engine
- **Underestimated part:** getting the `Observed vs Potential Risk vs Needs Manual Verification` labeling consistently right across ~30 rules. Write this as a decision table, not ad hoc per-rule judgment calls.

## Phase 4 — AI Intelligence
**Difficulty:** High (not because the API calls are hard — because grounding them well is hard). **Dependencies:** Phase 3's structured Findings/RiskScore data — the AI layer has nothing useful to reason over without it.

- `AIProvider` interface + first provider implementation
- Tool functions the AI can call (`get_assets`, `get_findings`, `get_dns_records`, etc. — see ai-engine.md)
- AI asset prioritization with evidence citations
- AI recon copilot (natural-language Q&A over the scan)
- Finding clustering/deduplication
- **Underestimated part:** preventing the AI from asserting things not backed by a tool-call result. Budget real time for prompt iteration and output validation (schema-checking AI JSON output before it's trusted anywhere downstream).

## Phase 5 — Attack Surface Graph
**Difficulty:** Medium. **Dependencies:** Phase 2-4 relationship data.

- Relationship graph queries over the correlation join table
- Graph data API (nodes/edges) for the dashboard
- Technology relationship mapping (shared stacks across assets)

## Phase 6 — Historical Intelligence
**Difficulty:** Medium. **Dependencies:** Phase 1 storage model must support multiple scans per domain (should already, if `Scan` was modeled correctly from Phase 0).

- Scan-to-scan diffing (new/removed/changed assets)
- Configuration change detection (e.g., a header that disappeared, a new technology detected)
- AI-generated change summaries (grounded in the diff, not free-form)

## Phase 7 — Professional Platform
**Difficulty:** High (mostly product/engineering breadth, not novel difficulty). **Dependencies:** everything above; this phase is "productionize."

- Web dashboard (Next.js)
- FastAPI REST API
- Authentication + team workspaces
- Report generation (Markdown → PDF)
- Celery + Redis background/scheduled scans
- Plugin architecture for discovery sources
- Multiple AI providers configurable per user/workspace

---

## Sequencing Notes

- **Do not skip to Phase 4 for a demo.** An AI layer with nothing but shallow data behind it is exactly the "gimmick" this project is trying to avoid. Phases 1-3 are what make Phase 4 credible.
- **Phase 5 (graph) and Phase 6 (history) can be reordered** relative to each other depending on what you want to demo first — history is arguably more impressive for a portfolio ("look, it caught a new exposed staging server automatically") and is lower engineering risk than a graph UI.
- **Active verification features (confirming subdomain takeover, deeper port scanning) are deliberately never scheduled as a numbered phase.** If you want them later, treat them as a separate, explicitly-consented "active mode" with its own scope flag and rate-limit profile — don't fold them into the passive pipeline's default behavior.
