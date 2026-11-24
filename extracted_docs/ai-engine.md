# AI Engine

## 1. Core Principle

The AI layer never invents facts and never assigns a final risk score. It reasons over structured evidence retrieved through defined tool functions, and every output that claims something about an asset must carry a reference back to the specific database rows that justify the claim. If the AI can't cite evidence for a claim, that claim doesn't ship.

## 2. Hybrid Scoring Architecture

```text
Deterministic Security Rules
             +
        Statistical Signals
             +
         AI Reasoning
             ↓
       Final Prioritization
```

**Risk Score formula (deterministic, computed without any AI involvement):**
```text
Risk Score =
    Asset Criticality        (is it prod, admin-looking, auth-related?)
  + Exposure                 (publicly reachable, unusual port, no auth wall detected)
  + Technology Signals       (known-risky stack, outdated version if detectable, exposed admin panel patterns)
  + Configuration Signals    (missing security headers, weak TLS indicators)
  + Environment Signals      (staging/dev hostname pattern reachable externally)
  + Correlation Signals      (shares infra with already-flagged assets, unusual DNS chain)
```
Each category is a small set of independently unit-tested rules with fixed point weights, tunable via config — not magic numbers buried in code. Total score maps to Low/Medium/High/Critical bands.

**Why not let the LLM be the sole scoring authority:**
- **Reproducibility:** the same scan re-run must produce the same score. LLM output varies run to run even at low temperature.
- **Auditability:** a bug bounty report or an internal security review needs a defensible "why" — "the model said Critical" is not defensible; "missing HSTS + publicly reachable staging admin panel + shares infra with a known-risky asset" is.
- **Cost and latency:** running every asset through an LLM call for a numeric score doesn't scale to hundreds of assets and adds nondeterminism to a number that should be a pure function of the evidence.
- **Attack surface for prompt injection:** if a score were AI-derived directly from scanned content (page titles, headers), a target could manipulate its own score by embedding adversarial text. Keeping scoring deterministic removes this entirely as an attack vector on the scoring number itself; the AI's *prose* layer above it still needs the input-sanitization discipline described below regardless.

The AI's job starts *after* the score exists: prioritize among same-tier assets, explain the score in plain language with citations, cluster related findings, flag statistical anomalies (e.g., "this asset's tech stack doesn't match any other asset on this domain — worth a look"), and answer questions.

## 3. AI Tool Interface (what the model is allowed to call)

```text
AI Agent
   |
   +── get_assets(filter)
   +── get_dns_records(asset_id)
   +── get_http_observation(asset_id)
   +── get_technologies(asset_id)
   +── get_findings(asset_id | severity | category)
   +── get_risk_score(asset_id)          # read-only — AI never writes this
   +── compare_scans(scan_id_a, scan_id_b)
   +── search_findings(query)
```
The model operates over this fixed toolset — never arbitrary SQL, never shell access, never a raw dump of the entire dataset stuffed into one prompt. This keeps context small, keeps answers traceable to specific calls, and keeps the blast radius of a bad model output limited to "wrong answer to a query," never "arbitrary code execution."

**Handling untrusted scanned content in prompts:** HTTP titles, header values, and any other scanned text that gets passed into a prompt (e.g., for technology explanation) is treated as untrusted input — wrapped clearly as data, never concatenated into instruction text, and the model is explicitly told in the system prompt that content sourced from scanned targets is data to analyze, not instructions to follow.

## 4. Feature Catalog

| # | Feature | Input | Approach | Output | Why AI helps | Phase |
|---|---|---|---|---|---|---|
| 1 | Asset prioritization | RiskScore + Findings per asset | LLM w/ tool calls, structured JSON output | Ranked list w/ 1-2 sentence evidence-cited reason each | Turns a flat score list into a legible narrative a human can act on fast | MVP |
| 2 | Recon summarization | All findings for a scan | LLM, structured prompt | 3-5 sentence posture summary | Saves reading dozens of raw findings for a first-pass overview | v2 |
| 3 | Attack-surface clustering | Technology + infra correlation data | Simple statistical clustering (e.g. group by shared tech/ASN) + LLM to label clusters | Named clusters ("Legacy PHP stack", "Modern Node/Cloud stack") | Clustering itself is deterministic; AI just names/describes clusters in useful language | v2 |
| 4 | Environment classification | Hostname + header + cert patterns | Rule-based first pass, LLM as tie-breaker for ambiguous cases only | prod/staging/dev/unknown label | Most cases are rule-solvable; AI only adds value on the genuinely ambiguous ~10% | Phase 2-3 |
| 5 | Technology relationship mapping | Technology table across all assets | Deterministic aggregation + AI narrative | "14 assets share nginx + Node; 3 outliers run legacy Apache" | Aggregation is deterministic; AI turns it into a readable insight | v2 |
| 6 | Anomaly detection | Statistical baseline across assets on the domain | Simple statistical outlier detection (z-score on response time/size/tech rarity) + AI explanation | Flagged anomalous asset + plain-language reason | Detection stays statistical/reliable; AI's value is explaining *why* it's unusual in context | v2 |
| 7 | DNS configuration explanation | DNSRecord set for an asset | LLM w/ tool call, grounded in the actual records | Plain-language explanation of a CNAME chain, MX setup, etc. | Translates technical DNS structure into something a non-DNS-expert stakeholder can read | MVP-adjacent (cheap to add once tool interface exists) |
| 8 | Security-header explanation | HTTPObservation headers | LLM, grounded in actual observed headers only | "Missing CSP means X; HSTS present but max-age is low, meaning Y" | Same translation value as #7 — technical finding to plain-language impact | MVP-adjacent |
| 9 | Finding deduplication | Raw Finding rows across many assets | Embedding similarity + LLM confirmation | Merged/grouped findings ("same missing-header issue across 40 subdomains") | Prevents alert fatigue from repetitive rule hits — high practical value | v2 |
| 10 | Natural-language recon queries | User question + full tool interface | LLM agent loop over tool functions | Direct answer, grounded, with citations | This is the actual "copilot" experience — lets a user explore data without learning a query syntax | Phase 4 |
| 11 | Evidence-based finding generation | Correlated signals not caught by a single rule | LLM proposes a candidate finding from combined evidence, always labeled "Needs Manual Verification" | New finding candidate, never auto-promoted to a rule-confirmed finding | Catches multi-signal patterns a single deterministic rule wouldn't — but must be human-reviewed before trust | v2, careful rollout |
| 12 | Recon report generation | Full scan dataset | LLM assembles narrative from structured sections, each section backed by an explicit data pull | Markdown/PDF report | Turns structured data into a client-ready document without a human writing prose from scratch | Phase 7 |
| 13 | Asset-change detection | Scan diff (deterministic) | Deterministic diff first; AI only summarizes | "17 new assets, 3 removed, 2 with new tech detected" + narrative | Diff logic must be deterministic and testable; AI's role is purely narrative | Phase 6 |
| 14 | Historical attack-surface comparison | Multiple scans over time | Deterministic trend computation + AI narrative | Trend summary ("your admin-exposed asset count has doubled since Q1") | Same pattern — compute don't guess, then narrate | Phase 6 |
| 15 | Investigation recommendations | Findings + prioritization | LLM, grounded, tool-calling | "Next steps: verify header X manually via curl; check if staging requires auth" | Turns a finding into an actionable next step — genuinely saves analyst time | v2 |

**Feature explicitly rejected:** a single "chat with your entire scan" free-form mode with no tool constraints. It's the exact "scan → dump everything into GPT" anti-pattern the project is trying to avoid, and it reintroduces every grounding/injection risk the tool-call interface exists to prevent.

## 5. Output Validation

Every structured AI output (prioritization lists, clustering, environment classification) is schema-validated (Pydantic) before it's persisted or shown. If validation fails, the system falls back to the deterministic result with no AI annotation, rather than showing malformed or unconstrained model output.
