# Perimetryx

**Attack Surface Intelligence and Evidence-Grounded Threat Analysis for Authorized Security Assessments**

Perimetryx maps the externally visible attack surface of a domain, scores each asset with a deterministic risk model mapped to MITRE ATT&CK and CWE, and lets you query the collected evidence through an AI analyst that is restricted to facts stored in the scan database.

It is a **reconnaissance and triage** tool. It observes what is already publicly visible. It does not exploit, brute-force, fuzz or guess hidden paths.

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Framework](https://img.shields.io/badge/API-FastAPI-009688)
![Storage](https://img.shields.io/badge/storage-SQLite-lightgrey)
![Tests](https://img.shields.io/badge/tests-pytest-success)

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Quick Start](#quick-start)
7. [CLI Reference](#cli-reference)
8. [Scope Files](#scope-files)
9. [Using Perimetryx for Bug Bounty Recon](#using-perimetryx-for-bug-bounty-recon)
10. [Web Dashboard and REST API](#web-dashboard-and-rest-api)
11. [Reports](#reports)
12. [AI Analyst](#ai-analyst)
13. [Testing](#testing)
14. [Project Structure](#project-structure)
15. [Troubleshooting](#troubleshooting)
16. [Legal and Ethical Use](#legal-and-ethical-use)

---

## Features

| Area | Capability |
|---|---|
| **Passive discovery** | Certificate Transparency log harvesting (crt.sh) and TLS SAN expansion |
| **DNS analysis** | A, AAAA, CNAME, MX, TXT, NS and SOA resolution |
| **DNS hygiene** | SPF and DMARC evaluation (permissive `+all`, `?all`, `p=none`), AXFR zone-transfer check |
| **Subdomain takeover** | Dangling-CNAME detection using signatures for 20+ cloud and SaaS providers (MITRE ATT&CK T1584) |
| **TLS inspection** | X.509 parsing, expiry and validity checks, SAN extraction |
| **Web fingerprinting** | 50+ technology signatures; exposed Swagger/OpenAPI, GraphQL, Prometheus, Actuator and Grafana surfaces |
| **Header audit** | HSTS, CSP (`unsafe-inline`, `unsafe-eval`), X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **Risk scoring** | Deterministic 0-100 score per asset, severity bands, CVSS v3.1 and CWE references |
| **Historical diffing** | New assets, removed assets, new and resolved findings, posture trend between two scans |
| **Visualization** | Terminal topology tree and JSON graph export |
| **AI analyst** | Evidence-grounded Q&A, CISO briefing, remediation playbook (offline mode available) |
| **Reporting** | Standalone dark-themed HTML and Markdown audit reports |
| **Safety controls** | Scope guard, rate limiting, port allow-list, identifying User-Agent, no exploitation |

---

## Architecture

```
            +-----------------+
 CLI / API  |  scope.yaml or  |
 ---------> |  target domain  |
            +--------+--------+
                     |
              +------v------+
              | Scope Guard |  every hostname checked before any request
              +------+------+
                     |
   +-----------------+------------------+
   |                 |                  |
+--v---+        +----v----+        +----v----+
|  CT  |        |   DNS   |        | HTTP/TLS|
| logs |        | engine  |        | probes  |
+--+---+        +----+----+        +----+----+
   |                 |                  |
   +-----------------v------------------+
                     |
          +----------v-----------+
          | Analysis + Scoring   |  takeover, headers, tech, MITRE/CWE
          +----------+-----------+
                     |
          +----------v-----------+
          |  SQLite (WAL mode)   |
          +----------+-----------+
                     |
     +-------+-------+--------+---------+
     |       |       |        |         |
  Inspect  Graph    Diff   Copilot   Reports
```

Detailed design notes live in [`extracted_docs/`](extracted_docs/) (architecture, database, AI engine, security, roadmap).

---

## Requirements

- Python **3.12 or 3.13**
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`
- Internet access (crt.sh, DNS resolvers, target HTTP/HTTPS)
- Windows, Linux or macOS

Docker is **not required**. `docker-compose.yml` provisions Postgres and Redis for planned scaling work. The current version stores data in SQLite.

---

## Installation

### Option A: uv (recommended)

```bash
git clone <your-repository-url> perimetryx
cd perimetryx
uv sync
```

`uv sync` creates `.venv` and installs everything from `pyproject.toml`, including the dev group (pytest, ruff).

### Option B: pip

```bash
git clone <your-repository-url> perimetryx
cd perimetryx
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

pip install "fastapi>=0.115" "httpx>=0.27" "PyYAML>=6.0" "python-dotenv>=1.0" \
            "uvicorn[standard]>=0.30" "rich>=15.0.0" "dnspython>=2.9.2" \
            "cryptography>=50.0.2" pytest ruff
```

With pip, replace `uv run python -m app ...` in this document with `python -m app ...`.

### Verify the installation

```bash
uv run python -m app          # prints the banner and command list
uv run pytest                 # runs the test suite
```

---

## Configuration

Copy the example environment file and edit it:

```bash
cp .env.example .env          # Windows: copy .env.example .env
```

| Variable | Default | Purpose |
|---|---|---|
| `PERIMETRYX_DB_PATH` | `data/perimetryx.db` | SQLite database location |
| `PERIMETRYX_ALLOWED_ORIGINS` | `http://localhost:8000` | CORS origins for the web dashboard |
| `PERIMETRYX_AI_PROVIDER` | `deterministic` | `deterministic`, `groq`, `openai` or `ollama` |
| `GROQ_API_KEY` / `GROQ_MODEL` | empty / `llama-3.3-70b-versatile` | Groq settings |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | empty / `gpt-4o-mini` | OpenAI settings |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | `http://localhost:11434/v1` / `llama3.2` | Local Ollama settings |

If a provider is selected but its API key is missing, Perimetryx falls back to the offline deterministic analyst automatically.

> **Never commit `.env`.** It is already in `.gitignore`. Do not share archives of the project folder with a populated `.env` inside.

---

## Quick Start

```bash
# 1. Preview without sending anything to the target
uv run python -m app scan example.com --dry-run

# 2. Live scan
uv run python -m app quick-scan example.com

# 3. Review results (use the Scan ID printed in step 2)
uv run python -m app inspect --scan 1
uv run python -m app graph --scan 1

# 4. Ask the analyst
uv run python -m app copilot --scan 1 --query "What are the top 3 assets to review first and why?"

# 5. Export a report
uv run python -m app report --scan 1 --format html --output audit.html
```

A live scan also writes `perimetryx-<domain>-report.html` to the working directory automatically.

> `quick-scan` is designed for assets you own or have been told you may assess. It marks the target as `owned_asset` and allows `domain` and `*.domain`. For third-party programs with exclusions, use a scope file instead (see below).

---

## CLI Reference

All commands are run as `uv run python -m app <command>`.

| Command | Description |
|---|---|
| `init-scope --domain D --authorization A [--output F] [--force]` | Create a scope YAML. `A` is `owned_asset`, `bug_bounty_program` or `signed_engagement_letter` |
| `scan <domain> [--dry-run]` | Scan a domain directly |
| `scan --scope scope.yaml --dry-run` | Validate a scope file without external probing |
| `scan --scope scope.yaml --confirm-authorization` | Live scan driven by a scope file |
| `quick-scan <domain> [--dry-run]` | Fast scan intended for demos and owned assets |
| `inspect --scan N [--host H]` | Per-asset telemetry, technologies and findings |
| `graph --scan N [--json]` | Topology tree, or raw nodes and edges as JSON |
| `diff --scan-a A --scan-b B` | Compare two scans of the same domain |
| `copilot --scan N --query "..."` | Ask the AI analyst about a scan |
| `report --scan N --format html\|markdown --output F` | Generate an audit report |
| `status --scan N` | Scan status and statistics (JSON) |
| `prioritize --scan N` | Evidence-backed manual review priorities |
| `roadmap --scan N` | Responsible research roadmap for the scan |
| `export --scan N --output F` | Export review priorities as Markdown |

---

## Scope Files

A scope file declares exactly what may be touched. Every discovered hostname is checked against it before any request is made.

```yaml
scope:
  domain: example.com
  authorization_basis: bug_bounty_program     # owned_asset | bug_bounty_program | signed_engagement_letter
  allowed_domains:
    - example.com
    - "*.example.com"
  excluded:
    - payments.example.com
    - "*.internal.example.com"
  active_verification: false
  max_requests_per_second: 2
  max_concurrent_connections: 5
  allowed_ports: [80, 443]
  user_agent: "Perimetryx/2.0 (+you@example.com; authorized-recon)"
```

| Field | Meaning |
|---|---|
| `allowed_domains` | Patterns that may be scanned. `*.` matches subdomains; a bare domain does not imply them |
| `excluded` | Patterns that are never scanned. Exclusions win over allowed patterns |
| `max_requests_per_second` | Hard ceiling enforced by a central rate limiter |
| `max_concurrent_connections` | Hard ceiling on parallel connections |
| `allowed_ports` | Only these ports are contacted |
| `user_agent` | Sent with every request. Put a real contact address in it |

Generate a starting file with `init-scope`, then edit it to match the program's published scope.

---

## Using Perimetryx for Bug Bounty Recon

Perimetryx suits the **first phase** of a bug bounty engagement: building an inventory of in-scope assets and deciding where to spend manual testing time. It is deliberately passive and low-impact, which fits the rules of most programs.

### 1. Choose a program and read its policy

Use programs listed on platforms such as HackerOne, Bugcrowd, Intigriti or YesWeHack. For learning, favor programs that have a broad, clearly written scope and permit automated reconnaissance. Many companies also publish a `security.txt` at `https://<domain>/.well-known/security.txt` and a vulnerability disclosure policy.

Before running anything, write down:

- The exact in-scope domains and wildcards
- Everything listed as **out of scope** (these become your `excluded` entries)
- Rules on automated scanning and rate limits
- Prohibited activity (typically DoS, social engineering, data access beyond proof of concept)

If the policy does not mention a domain, treat it as out of scope.

### 2. Create a scope file that mirrors the policy

```bash
uv run python -m app init-scope --domain target.com --authorization bug_bounty_program --output target-scope.yaml
```

Edit `target-scope.yaml`:

- List only the in-scope assets under `allowed_domains`
- Copy every out-of-scope asset into `excluded`
- Keep `max_requests_per_second` at 2 or lower unless the program states otherwise
- Add a contact address to `user_agent`, and if the program requires a custom header or username, follow its instructions

### 3. Dry run, then live scan

```bash
uv run python -m app scan --scope target-scope.yaml --dry-run
uv run python -m app scan --scope target-scope.yaml --confirm-authorization
```

Prefer `--scope` over `quick-scan` for third-party programs, because `quick-scan` does not read your exclusions.

### 4. Triage

```bash
uv run python -m app inspect --scan <ID>        # all assets with findings
uv run python -m app prioritize --scan <ID>     # where to look first
uv run python -m app graph --scan <ID>          # structure of the surface
uv run python -m app copilot --scan <ID> --query "Which assets look like staging, admin, or forgotten infrastructure?"
```

Useful signals to follow up manually:

| Finding | Why it matters |
|---|---|
| Dangling CNAME to a cloud provider | Possible subdomain takeover; verify by hand and report if the provider allows claiming it |
| Exposed Swagger, OpenAPI or GraphQL | Large API surface; read the documented endpoints and test authorization logic |
| Exposed metrics, Actuator, Grafana | Information disclosure |
| Staging, dev or test hostnames | Often weaker controls than production |
| Permissive SPF or `p=none` DMARC | Spoofing risk (check whether the program accepts email findings) |
| Missing HSTS or CSP weaknesses | Usually low severity; many programs do not reward them |
| Open AXFR | Full DNS zone disclosure |

### 5. Track change over time

New assets are where fresh bugs tend to appear. Re-scan on a schedule and diff:

```bash
uv run python -m app scan --scope target-scope.yaml --confirm-authorization
uv run python -m app diff --scan-a 1 --scan-b 2
```

### 6. Verify manually and report responsibly

Perimetryx stops at "this needs verification". For any finding you want to submit:

1. Confirm it manually with the **minimum** interaction needed to prove it.
2. Stay inside the program's rules. No data exfiltration, no persistence, no service disruption.
3. Write a clear report: asset, steps to reproduce, impact, and a suggested fix. Use `report --format markdown` as supporting evidence.
4. Check for duplicates and previously disclosed reports before submitting.

### Good practice

- Keep a log of what you scanned and when. The Perimetryx database already does this.
- Do not scan assets belonging to a program's third-party vendors unless the policy includes them.
- If you accidentally see sensitive data, stop and report it without accessing more.
- Treat scan results as confidential. They describe someone else's infrastructure.

### Practice targets that are explicitly open for testing

Use these to learn the output before moving to real programs:

- `scanme.nmap.org` (provided by the Nmap project for scanning)
- Your own domain or lab
- Intentionally vulnerable training environments you host yourself

---

## Web Dashboard and REST API

Start the server:

```bash
uv run uvicorn app.main:app --reload
```

- Dashboard: <http://localhost:8000>
- Interactive API docs: <http://localhost:8000/docs>

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/domains` | Register a domain with its scope |
| GET | `/api/domains` | List domains |
| POST | `/api/domains/{id}/scans` | Start a scan |
| POST | `/api/quick-scan` | Register and scan in one call |
| GET | `/api/scans/{id}` | Scan status |
| GET | `/api/scans/{id}/overview` | Assets, findings and scores |
| GET | `/api/scans/{id}/graph` | Topology nodes and edges |
| GET | `/api/scans/{id}/diff/{scan_b_id}` | Comparison between scans |
| POST | `/api/scans/{id}/copilot` | Query the AI analyst |
| GET | `/api/scans/{id}/report` | Report output |

The server binds to localhost by default. Do not expose it publicly without authentication in front of it.

---

## Reports

```bash
uv run python -m app report --scan 1 --format html --output audit.html
uv run python -m app report --scan 1 --format markdown --output audit.md
```

The HTML report is a single self-contained file with severity distribution cards, per-asset findings, and MITRE ATT&CK and CWE references. It can be opened offline or attached to a submission.

---

## AI Analyst

The analyst only reasons over data already stored for the scan, and its answers cite the assets they refer to.

| Provider | How to enable |
|---|---|
| `deterministic` (default) | Works offline, no key needed |
| `groq` | Set `PERIMETRYX_AI_PROVIDER=groq` and `GROQ_API_KEY` |
| `openai` | Set `PERIMETRYX_AI_PROVIDER=openai` and `OPENAI_API_KEY` |
| `ollama` | Set `PERIMETRYX_AI_PROVIDER=ollama`, run Ollama locally |

Example prompts:

```
What are the top 3 critical assets to review and why?
Generate an executive CISO briefing for this attack surface.
Which hosts look like staging or development environments?
Summarize the DNS and email security posture.
```

Scan data sent to a hosted provider leaves your machine. For sensitive engagements use `deterministic` or `ollama`.

---

## Testing

```bash
uv run pytest             # full suite
uv run ruff check .       # lint
```

Tests cover DNS analysis, TLS parsing, takeover signatures, technology fingerprinting, graph construction, scan diffing, and AI analyst reasoning.

---

## Project Structure

```
Perimetryx/
├── app/
│   ├── cli.py                  # command-line interface
│   ├── main.py                 # FastAPI app and scan orchestration
│   ├── pipeline.py             # CT discovery, HTTP observation, rate limiter
│   ├── scope_guard.py          # scope enforcement
│   ├── dns_engine.py           # DNS records, SPF/DMARC, AXFR check
│   ├── tls_engine.py           # certificate parsing
│   ├── fingerprint.py          # technology and sensitive-surface detection
│   ├── takeover_signatures.py  # dangling-DNS provider signatures
│   ├── analysis.py             # finding generation
│   ├── scoring.py              # deterministic risk model
│   ├── graph.py                # topology builder
│   ├── diff.py                 # scan comparison
│   ├── ai.py                   # analyst providers
│   ├── reporting.py            # HTML and Markdown reports
│   ├── guidance.py             # prioritization and roadmap
│   ├── schemas.py              # Pydantic models
│   └── store.py                # SQLite layer
├── web/                        # dashboard (HTML, CSS, JS)
├── tests/                      # pytest suite
├── extracted_docs/             # design documentation
├── scope.example.yaml          # scope template
├── .env.example                # environment template
└── pyproject.toml
```

---

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `Live reconnaissance requires explicit authorization confirmation` | Add `--confirm-authorization`, or use `--dry-run` |
| `Failed to load scope configuration` | YAML syntax error or missing field; compare with `scope.example.yaml` |
| Scan finishes with very few assets | crt.sh was slow or rate limited; wait and re-run, or check the target actually has certificates in CT logs |
| Hosts show `Unreachable` | Host does not resolve, blocks the request, or only serves non-standard ports (only 80 and 443 are contacted) |
| Copilot output looks generic | No API key set, so the offline analyst is in use |
| `Scan N not found` | Use the Scan ID printed after the scan, or check `PERIMETRYX_DB_PATH` |
| `ModuleNotFoundError` | Run through `uv run`, or activate `.venv` first |

---

## Legal and Ethical Use

Use Perimetryx **only** on systems you own or are explicitly authorized to assess, such as assets in a bug bounty program's published scope, or targets covered by a written engagement letter or instructor permission.

- Unauthorized scanning may violate computer misuse laws in your jurisdiction.
- Always follow the program's rules, rate limits and exclusions.
- Authorization to scan is not authorization to exploit.
- The authors accept no liability for misuse.

Design principles that back this up: explicit scope declaration, central rate limiting, port allow-list, identifying User-Agent, audit-friendly scan history, no credential attacks, and no exploitation. See [`extracted_docs/security.md`](extracted_docs/security.md).

---

## License

still -- tbh