# Perimetryx 🛡️

**Enterprise Attack Surface Intelligence & Evidence-Grounded Threat Engine**

> Built for AppSec engineers, Red Teams, Bug Bounty researchers, and academic cybersecurity excellence. Maps external perimeters, performs deterministic risk scoring mapped to MITRE ATT&CK & CWE, detects Subdomain Takeovers & Email Spoofing, and reasons over factual evidence using an AI Security Analyst.

---

```text
██████╗ ███████╗██████╗ ██╗███╗   ███╗███████╗████████╗██████╗ ██╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔══██╗██║████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝╚██╗██╔╝
██████╔╝█████╗  ██████╔╝██║██╔████╔██║█████╗     ██║   ██████╔╝ ╚████╔╝  ╚███╔╝ 
██╔═══╝ ██╔══╝  ██╔══██╗██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗  ╚██╔╝   ██╔██╗ 
██║     ███████╗██║  ██║██║██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██╔╝ ██╗
```

---

## ⚡ Key Highlights (Grade A+ Features)

1. **Rich Interactive Cyber Terminal Console**:
   - Modern ASCII banner, live progress spinners, colorized severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
   - Terminal Attack Surface Topology Tree (`rich.tree.Tree`) rendering hierarchical dependencies.
   - Comparative scan deltas and security regression tables.

2. **Multi-Vector Passive Reconnaissance**:
   - Passive Certificate Transparency log harvesting (crt.sh, CertSpotter).
   - Deep DNS Resolution: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`.
   - TLS X.509 Certificate parsing with Subject Alternative Names (SAN) passive asset expansion.

3. **Subdomain Takeover & Dangling DNS Engine**:
   - Signature-based detection across 20+ cloud providers (AWS S3, GitHub Pages, Heroku, Azure App Services & Traffic Manager, Shopify, Surge, Fastly, Netlify, Fly.io, Zendesk, Readme, etc.).
   - Mapped to **MITRE ATT&CK T1584** (Compromise Infrastructure).

4. **DNS Security & Email Spoofing Hygiene**:
   - Evaluates SPF policies for permissive `+all` (critical spoofing vulnerability) and neutral `?all`.
   - Evaluates DMARC records for `p=none` (monitoring only) vs `p=quarantine`/`p=reject`.
   - Probes nameservers for unrestricted AXFR DNS Zone Transfers (**MITRE ATT&CK T1590.002**).

5. **Web Technology & Sensitive Surface Fingerprinting**:
   - 50+ technology signatures across servers, backend frameworks, CMS, and client-side UI libraries.
   - Detects exposed API documentation (Swagger UI, OpenAPI specs, GraphQL endpoints).
   - Detects exposed metrics and telemetry (Prometheus, Actuator, Grafana).
   - Flags public administrative surfaces without credential bruteforcing.

6. **Defense-in-Depth Security Header Audit**:
   - Comprehensive audit of HSTS (including `max-age` duration and subdomains), CSP (flagging `unsafe-inline` and `unsafe-eval`), X-Frame-Options (Clickjacking / CWE-1021), X-Content-Type-Options, and Referrer-Policy.

7. **Historical Intelligence & Continuous Diffing**:
   - Calculates exact deltas between Scan $N$ and Scan $N-1$: newly introduced shadow IT, decommissioned hosts, resolved findings, and posture score trajectory.

8. **Evidence-Grounded AI Security Analyst & Copilot**:
   - Natural language Q&A strictly grounded in the database evidence graph.
   - Generates CISO executive briefings and DevSecOps remediation playbooks.
   - Operates offline via a high-accuracy deterministic analyst or connects to Groq (`llama-3.3-70b-versatile`), OpenAI (`gpt-4o-mini`), or local Ollama.

9. **Enterprise Audit Reporting**:
   - Generates client-ready **Markdown** reports and **Standalone Dark-Themed HTML** audit reports with severity distribution cards and MITRE ATT&CK references.

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Runtime & Language** | Python 3.12+ (Typed Async, Dataclasses, Pydantic v2) |
| **CLI & Terminal UI** | `rich` (Tables, Panels, Trees, Progress Bars, ANSI Badges), `argparse` |
| **Network & Recon** | `httpx` (Async HTTP), `dnspython` (Async DNS resolver & AXFR probe) |
| **Cryptography** | `cryptography` (X.509 cert decoding, SAN extraction, validity checks), Python `ssl` |
| **Persistence** | SQLite with WAL mode, foreign keys, and relational normalization |
| **Threat Frameworks** | MITRE ATT&CK for Enterprise, Common Weakness Enumeration (CWE), CVSS v3.1 |
| **AI Analyst Layer** | Multi-provider (`deterministic-v2`, `groq`, `openai`, `ollama`) |
| **Web REST API** | FastAPI, Starlette, Uvicorn |

---

## 🚀 Quickstart & CLI Commands

### 1. Initialize an Authorized Scope
Perimetryx requires an explicit scope definition before any scanning can occur:
```powershell
uv run python -m app init-scope --domain example.com --authorization owned_asset --output scope.yaml
```

### 2. Run a Reconnaissance Scan
```powershell
# Simulation / Dry Run (Validates scope rules without external probes):
uv run python -m app scan --scope scope.yaml --dry-run

# Live Authorized Assessment:
uv run python -m app scan --scope scope.yaml --confirm-authorization
```

### 3. Inspect Asset Telemetry & Findings
```powershell
# Inspect all assets from a scan
uv run python -m app inspect --scan 1

# Inspect a specific target host
uv run python -m app inspect --scan 1 --host admin.example.com
```

### 4. Render Attack Surface Topology Tree
```powershell
# Terminal tree visualization:
uv run python -m app graph --scan 1

# Export raw topology nodes & edges as JSON:
uv run python -m app graph --scan 1 --json
```

### 5. Historical Diffing & Security Regressions
Compare baseline scan #1 against subsequent scan #2 to catch shadow IT and regressions:
```powershell
uv run python -m app diff --scan-a 1 --scan-b 2
```

### 6. AI Security Analyst Copilot
Query the factual evidence using natural language:
```powershell
uv run python -m app copilot --scan 1 --query "What are the top 3 critical assets to review and why?"
uv run python -m app copilot --scan 1 --query "Generate an executive CISO briefing for this attack surface."
```

### 7. Generate Audit Reports (HTML & Markdown)
```powershell
# Export dark-themed executive HTML audit report:
uv run python -m app report --scan 1 --format html --output audit-report.html

# Export Markdown security report:
uv run python -m app report --scan 1 --format markdown --output audit-report.md
```

---

## 🧪 Automated Test Suite

Run the full pytest suite:
```powershell
uv run pytest
```
*Current test coverage: 16 passing unit and integration tests across DNS, TLS, Takeover Signatures, Tech Fingerprinting, Graph Topology, Historical Diffing, and AI Analyst Reasoning.*
