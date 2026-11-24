# Perimetryx

**AI-assisted attack surface intelligence for domains you own or are authorized to assess.**

> Recon Engine + Attack Surface Mapper + AI Security Analyst — not another `subfinder` wrapper.

---

## 1. Naming

Five candidates considered, with the reasoning for the pick:

| Name | Take |
|---|---|
| **Perimetryx** ✅ | "Perimeter" (attack surface) + "-etryx" (telemetry/metrics). Sounds like a real product, no trademark collisions with known recon tools, works as a CLI binary name (`perimetryx`) and a company name. |
| Surfacely | Reads too much like a consumer SaaS, not a security tool. |
| ReconAegis | Aegis is overused in security-tool branding; feels generic. |
| Vantage Recon | Decent, but "Vantage" collides with several existing commercial products (Vantage, VantagePoint). |
| AttackScope AI | Puts "AI" in the name, which cheapens it — the AI is a layer, not the identity. |

**Chosen name: Perimetryx** — CLI binary: `perimetryx`, short alias `ptx`.

---

## 2. Product Definition

**One-line description:** Perimetryx turns a single authorized root domain into a continuously-refreshable, evidence-backed map of its external attack surface, with deterministic risk scoring and an AI layer that explains *why* something matters and answers questions about the data — never a black-box verdict.

**Problem statement:** Traditional recon tools (subfinder, amass, httpx, nuclei) each solve one narrow slice — enumeration, resolution, or probing — and leave correlation, prioritization, and explanation entirely to the human operator. As attack surfaces grow (subdomains, cloud assets, forgotten staging environments), the bottleneck isn't *finding* assets, it's *understanding which ones matter and why*, quickly and defensibly. Bolting an LLM onto raw scan output ("summarize these 300 lines") produces plausible-sounding but unverifiable prose. Perimetryx instead builds a structured evidence graph first, and constrains the AI to reason *over* that graph.

**Target users:**
- Independent bug bounty hunters managing recon for many programs
- AppSec/security engineers monitoring their own org's external surface
- Security students/researchers building a portfolio-grade project
- Small red teams doing authorized external assessments

**Main use cases:**
1. Initial recon sweep of a newly in-scope bug bounty target
2. Continuous/periodic re-scan of an org's own domain to catch new/forgotten assets (shadow IT, orphaned staging hosts)
3. Fast triage: "of these 200 subdomains, which 10 deserve my next hour?"
4. Change detection between scans ("what's new since last week?")
5. Generating a defensible, evidence-cited report for a client or internal stakeholder

**What makes it different from existing recon tools:**
- Structured, queryable data model (not scrollback text) — every finding is traceable to raw evidence
- Deterministic risk scoring *first*; AI explains and prioritizes on top of it, never invents a score
- AI answers natural-language questions against the actual dataset, not a prompt-stuffed transcript
- Explicit `Observed / Potential Risk / Needs Manual Verification / Confirmed Vulnerability` labeling — the tool refuses to overclaim
- Built-in scope enforcement, rate limiting, and audit logging as first-class architecture, not an afterthought
- Historical diffing across scans as a native feature, not a script you bolt on later

**MVP (what "done" looks like for v0.1):**
- CLI-only, single-target scans
- Passive subdomain discovery (CT logs + 1-2 passive DNS sources) + DNS resolution + HTTP probing
- SQLite storage, deterministic risk scoring, JSON/CSV/report output
- One AI feature done *well*: evidence-grounded asset prioritization with citations back to raw findings

**Version 2:**
- Web dashboard, attack surface graph, historical diffing, AI recon copilot (Q&A), multi-provider AI, Postgres, background job queue

**Long-term vision:**
- Agentic pipeline (discovery → analysis → prioritization → reporting agents) operating over a constrained toolset (no shell access), team workspaces, plugin architecture for passive sources, continuous monitoring mode with alerting.

---

## 3. Documentation Map

This repo's docs live in `docs/`:

| File | Purpose |
|---|---|
| `docs/architecture.md` | Full system architecture, component breakdown, data-flow, folder structure, tech stack |
| `docs/roadmap.md` | Phase-by-phase build roadmap with difficulty/dependencies |
| `docs/learning-roadmap.md` | What to *learn* before building each phase — DNS/HTTP/TLS through LLM agents |
| `docs/ai-engine.md` | AI feature catalog, prompt/tool design, hybrid scoring rationale |
| `docs/database.md` | ER model and schema for all core entities |
| `docs/security.md` | Scope enforcement, rate limiting, ethics, audit logging, secrets handling |

Additional docs referenced by the full blueprint (recon pipeline detail, CLI reference, dashboard spec, testing strategy, API reference) follow the same structure and can be generated the same way once you're ready to flesh out that phase — start with the six above; they're the ones that actually gate implementation decisions.

---

## 4. Critical Notes / Where the Original Idea Needed Pushback

Being direct about the parts of a "kitchen sink" recon+AI project that are weak by default, and how this design avoids them:

- **"Send everything to the LLM and summarize" is explicitly rejected.** It's unverifiable and doesn't scale past a handful of assets. Every AI output here must cite the structured evidence it drew from.
- **Unusual ports/service scanning is scoped out of MVP entirely**, not just "later." Active port scanning changes the tool's risk/legal profile (it's no longer purely passive) and needs its own consent/rate-limit story — don't build it until Phase 3+ and only against explicitly authorized targets with active-scan consent flagged in scope config.
- **A generic "AI risk score" is a red flag, not a feature.** Score is deterministic and rule-based; AI never outputs a number that becomes *the* score — it only explains, clusters, and prioritizes among assets that already have a score.
- **A slick dashboard before the data model is right is wasted effort.** Roadmap deliberately keeps the dashboard in Phase 7, after the graph/data model and CLI have proven the pipeline works.
- **"Confirmed Vulnerability" as an AI-assigned label is disallowed by design** — that classification requires either a deterministic rule with a citable CVE/misconfig reference or explicit human sign-off. The AI can only ever say "Potential Risk" or "Needs Manual Verification."