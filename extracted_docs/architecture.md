# Architecture

## 1. System Overview

```text
User
 ↓
CLI  ──────────────┐
 ↓                  │  (v2: Web Dashboard talks to the same API)
Recon Orchestrator ←┘
 ↓
Scope Guard  (validates every target against scope.yaml before anything runs)
 ↓
Asset Discovery Engine  (passive sources → candidate subdomains)
 ↓
DNS Resolution Engine
 ↓
HTTP Enrichment Engine
 ↓
Technology Fingerprinting
 ↓
Security Posture Analysis
 ↓
Asset Correlation / Graph Builder
 ↓
Deterministic Risk Engine
 ↓
AI Analysis Layer  (reasons over the above — never replaces it)
 ↓
Storage (Postgres/SQLite)
 ↓
Findings / CLI Output / Reports / Dashboard
```

Two changes from the original sketch, and why:
- **Scope Guard is inserted immediately after the CLI**, not implied. Every single downstream component receives already-validated, in-scope targets only — it's a gate, not a check performed somewhere in the middle.
- **AI Analysis Layer sits *after* the Risk Engine, reading from storage**, not inline in the pipeline. This makes AI analysis re-runnable independently of a scan (you can re-prioritize with a new prompt/model without re-scanning), and keeps a scan reproducible without any AI dependency at all.

## 2. Component Breakdown

### Scope Guard
- **Purpose:** Enforce that only explicitly authorized domains/subdomains are ever touched.
- **Input:** `scope.yaml`, requested target.
- **Output:** Allow/deny decision + normalized target list.
- **Tech:** Plain Python, `tldextract` for domain parsing, fnmatch/regex for wildcard scope rules.
- **MVP:** Yes — non-negotiable, ships in v0.1.

### Recon Orchestrator
- **Purpose:** Coordinates pipeline stages, manages concurrency, retries, and scan lifecycle (a "Scan" record).
- **Input:** Validated target(s), scan config (which sources/stages to run).
- **Output:** Scan ID, stage completion events, final asset set.
- **Tech:** `asyncio` task graph for MVP; Celery + Redis once background/scheduled scans matter (Phase 7).
- **Communicates via:** in-process function calls in MVP; message queue in production version.
- **MVP:** Yes.

### Asset Discovery Engine
- **Purpose:** Generate candidate subdomains/assets from passive sources only.
- **Input:** Root domain.
- **Output:** List of candidate hostnames + source attribution (which source found each one — needed for evidence citations later).
- **Sources (each implemented as a plugin):**
  - Certificate Transparency (crt.sh, or a CT log aggregator API) — **MVP**
  - Passive DNS aggregators (e.g. a provider API) — **MVP if a free/authorized-use API is available, else v2**
  - Search-engine-derived OSINT (e.g. indexed subdomain leaks) — **v2 plugin**
  - Public bug-bounty-friendly recon APIs — **v2 plugin, optional/pluggable**
- **Tech:** `httpx` (async client) for API calls, a `SourcePlugin` base class so new sources are drop-in.
- **MVP:** Core CT-log source yes; others as optional plugins.

### DNS Resolution Engine
- **Purpose:** Resolve each candidate to A/AAAA/CNAME/MX/NS/TXT records. No zone transfers, no brute-force enumeration, no DNS attacks.
- **Input:** Candidate hostnames.
- **Output:** `DNSRecord` rows per hostname/type.
- **Tech:** `dnspython`, async resolution pool with a hard concurrency cap (respect the rate-limit config).
- **MVP:** Yes.

### HTTP Enrichment Engine
- **Purpose:** For hosts with a live web service, collect passive/safe HTTP metadata.
- **Input:** Resolved hostnames + ports 80/443 (only ports explicitly in scope config — no arbitrary port sweep in MVP).
- **Output:** `HTTPObservation` rows: status, redirect chain, title, headers, TLS cert info, response size/timing.
- **Tech:** `httpx` async client with strict timeouts, custom identifying User-Agent (see security.md), TLS info via `ssl`/`cryptography`.
- **MVP:** Yes.

### Technology Fingerprinting
- **Purpose:** Identify web server, framework, CMS, JS framework, CDN, cloud provider, reverse proxy from headers/body/cert signals.
- **Input:** `HTTPObservation` data.
- **Output:** `Technology` rows linked to the asset.
- **Tech:** A Wappalyzer-style signature ruleset (there are open datasets/libraries for this — e.g. `python-Wappalyzer` or a maintained fork; verify license before shipping) plus custom header/cert heuristics.
- **MVP:** Basic header/cert-based fingerprinting yes; full signature-database matching can start minimal and grow.

### Security Posture Analysis
- **Purpose:** Deterministic checks against collected evidence — missing security headers, weak TLS indicators, staging/dev hostname patterns, dangling CNAME indicators, publicly-reachable admin-looking paths (based on hostname/title only, never active probing of hidden paths).
- **Input:** All prior stage outputs.
- **Output:** `Finding` rows, each tagged `Observed / Potential Risk / Needs Manual Verification` (never `Confirmed Vulnerability` from this stage — that requires a matched CVE database entry or human review).
- **Tech:** Rule engine — a plain Python rules module is enough for MVP; consider a declarative YAML rule format once rules exceed ~30 (easier to audit and contribute to).
- **MVP:** Yes, this is the core value of the tool pre-AI.

### Asset Correlation / Graph Builder
- **Purpose:** Build the relationship graph: `Subdomain → IP → ASN → Cloud Provider → HTTP Service → Technology → Finding`.
- **Input:** All entity tables for a scan.
- **Output:** An in-memory/DB-backed graph structure (adjacency table or a graph library object) used by both the AI layer and the dashboard graph view.
- **Tech:** For MVP, a simple `AssetRelationship` join table in the relational DB is sufficient — don't reach for Neo4j until the dashboard graph view (Phase 5) actually needs graph-native queries.
- **MVP:** Data model yes (join table); dedicated graph visualization is v2.

### Deterministic Risk Engine
- **Purpose:** Compute a transparent, explainable score per asset from weighted signal categories.
- **Input:** Findings, technology, environment classification (prod/staging/dev heuristics), correlation data.
- **Output:** `RiskScore` row per asset with a breakdown by category (not just a final number — see database.md).
- **Tech:** Pure Python, unit-testable scoring function. See `docs/ai-engine.md` for the exact formula and category weights.
- **MVP:** Yes.

### AI Analysis Layer
- **Purpose:** Prioritize, cluster, explain, and answer natural-language questions — always reading from the structured evidence already in storage, never as the source of a risk number.
- **Input:** Structured query results (via defined "tool" functions — see ai-engine.md), never a raw dump of the whole scan.
- **Output:** Prioritized lists with evidence citations, natural-language answers, cluster/anomaly labels, report prose.
- **Tech:** Provider-agnostic `AIProvider` interface (OpenAI / Gemini / Ollama implementations), structured-output mode (JSON schema) for anything that feeds back into the UI.
- **MVP:** One well-built feature (asset prioritization with citations) — see ai-engine.md for the full staged rollout.

### Storage
- **Purpose:** Durable, queryable record of every scan, asset, and finding.
- **MVP:** SQLite (zero-ops, fine for single-user CLI tool).
- **Production:** PostgreSQL (concurrent access, JSON columns for flexible evidence blobs, better suited to a multi-user dashboard/API).
- **Redis:** Introduced only when background jobs (Celery) or rate-limit token buckets need shared state across processes — not needed for MVP.

### Findings / Output Layer
- **Purpose:** Render CLI tables, JSON/CSV export, and (v2) Markdown/PDF reports and the web dashboard.
- **MVP:** CLI + JSON/CSV.
- **v2:** Report generation (Markdown → PDF), web dashboard, REST API.

## 3. Data Relationships

**Ownership hierarchy** (who belongs to whom):
```text
Domain (example.com)
 ├── Subdomain (api.example.com)
 ├── Subdomain (admin.example.com)
 ├── Subdomain (dev.example.com)
 ├── Subdomain (staging.example.com)
 └── Subdomain (assets.example.com)
```
Modeled as a self-referential/foreign-key relationship: every `Subdomain` row has a `domain_id` FK to its parent `Domain`.

**Evidence chain** (why an asset scored the way it did):
```text
Subdomain
 → IPAddress (from DNS resolution)
 → ASN / Cloud Provider (from IP → WHOIS/ASN lookup, passive)
 → HTTPObservation (from HTTP enrichment)
 → Technology (from fingerprinting, FK to HTTPObservation)
 → Finding (from security analysis, FK to the observation/technology that triggered it)
 → RiskScore (aggregates Findings + signals for that asset)
```
This chain is what lets both the CLI report and the AI layer answer "why" — every `Finding` and every AI claim carries a foreign key back to the specific `HTTPObservation`/`DNSRecord`/`Technology` row that justifies it. This traceability is the single most important design constraint in the whole system; it's what separates "AI-powered" from "AI-decorated."

## 4. Technology Stack

**Backend:** Python 3.12+, FastAPI (API, from Phase 7 onward — CLI calls the same service layer directly in MVP without HTTP overhead), `asyncio` for concurrency, `httpx` for HTTP, `dnspython` for DNS, `Pydantic` for all data validation/schemas, `SQLAlchemy` (async) as the ORM.

**Database:** SQLite for MVP → PostgreSQL for production/dashboard. Redis added only alongside Celery in Phase 7 (job queue + rate-limit state).

**Frontend (v2+):** Next.js + React + Tailwind + shadcn/ui — standard, well-supported combination for a data-dense dashboard; shadcn's table/graph-adjacent components fit an attack-surface dashboard well.

**AI:** Provider-agnostic interface:
```text
AIProvider (abstract)
 ├── OpenAIProvider
 ├── GeminiProvider
 └── OllamaProvider   ← important for privacy-sensitive users who don't want target data leaving their machine
```
Structured outputs (JSON schema / function-calling mode) used for anything programmatic; free-text only for the conversational copilot answers.

**Background jobs:** MVP uses plain `asyncio` (single-user, single-scan-at-a-time is fine). Celery + Redis introduced in Phase 7 for scheduled/recurring scans and multi-user concurrency.

## 5. Folder Structure

```text
perimetryx/
├── cli/              # Click/Typer command definitions, output formatting
├── core/             # Scan orchestration, Scan lifecycle, config loading
├── scope/            # Scope Guard: scope.yaml parsing + enforcement
├── discovery/         # Passive source plugins (CT logs, passive DNS, ...)
├── dns/               # DNS resolution engine
├── http/              # HTTP enrichment engine
├── fingerprinting/    # Technology detection signatures + matcher
├── analysis/          # Deterministic security posture rules
├── scoring/           # Risk engine (weights, formula, category breakdown)
├── ai/                # AIProvider interface + implementations, tool functions, prompts
├── storage/            # SQLAlchemy models, migrations (Alembic), repositories
├── models/             # Pydantic schemas shared across layers
├── workers/            # Celery tasks (v2+)
├── reporting/          # Markdown/PDF/JSON/CSV report generation
├── api/                 # FastAPI app (v2+)
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
└── docs/
```

This differs slightly from the original sketch by adding `scope/` as its own top-level module rather than burying it inside `core/` — given that scope enforcement is the tool's primary legal/ethical safety mechanism, it deserves to be independently testable and auditable as its own module.
