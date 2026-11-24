# Perimetryx CLI Reference Manual

The Command-Line Interface (`perimetryx` / `python -m app`) provides an operator-grade terminal environment built on **Rich**.

---

## 1. Global Usage

```powershell
uv run python -m app [COMMAND] [OPTIONS]
```

---

## 2. Command Details

### `init-scope`
Creates an authorized, reviewable YAML configuration file for a target domain.

```powershell
uv run python -m app init-scope --domain <DOMAIN> --authorization <BASIS> [--output <PATH>] [--force]
```
- `--domain`: Root domain (e.g. `example.com`).
- `--authorization`: Legal authorization basis (`owned_asset`, `bug_bounty_program`, `signed_engagement_letter`).
- `--output`: Output path (default: `scope.yaml`).
- `--force`: Overwrite existing scope file.

### `scan`
Executes an attack surface reconnaissance sweep.

```powershell
uv run python -m app scan --scope <PATH> [--dry-run] [--confirm-authorization]
```
- `--scope`: Path to `scope.yaml`.
- `--dry-run`: Simulates the scan without making any external requests to the target.
- `--confirm-authorization`: Required flag to confirm live authorization before network probes commence.

### `inspect`
Retrieves detailed telemetry, DNS records, TLS certificates, technologies, and findings for a scan or specific host.

```powershell
uv run python -m app inspect --scan <SCAN_ID> [--host <HOSTNAME>]
```
- `--scan`: Numerical scan ID.
- `--host`: Optional specific hostname filter (e.g. `admin.example.com`).

### `graph`
Visualizes the attack surface topology as an ASCII tree in the terminal or exports raw graph data.

```powershell
uv run python -m app graph --scan <SCAN_ID> [--json]
```
- `--scan`: Numerical scan ID.
- `--json`: Outputs raw nodes and edges in JSON format.

### `diff`
Computes the comparative delta between two scans to track shadow IT additions, decommissioned hosts, and security regressions.

```powershell
uv run python -m app diff --scan-a <SCAN_ID_A> --scan-b <SCAN_ID_B>
```
- `--scan-a`: Baseline earlier scan ID.
- `--scan-b`: Subsequent later scan ID.

### `copilot`
Submits natural-language security questions to the AI Security Analyst grounded in the scan evidence.

```powershell
uv run python -m app copilot --scan <SCAN_ID> --query "<QUESTION>"
```
- `--scan`: Numerical scan ID.
- `--query`: Natural language question (e.g. `"What are the top 3 critical assets to review?"`).

### `report`
Generates client-ready executive security audit reports in HTML or Markdown.

```powershell
uv run python -m app report --scan <SCAN_ID> --format <html|markdown> --output <PATH>
```
- `--scan`: Numerical scan ID.
- `--format`: Report format (`html` or `markdown`).
- `--output`: File destination (e.g. `audit-report.html`).

### `prioritize`
Outputs manual review priority plan sorted by deterministic risk scores with verification checks.

```powershell
uv run python -m app prioritize --scan <SCAN_ID>
```

### `roadmap`
Outputs responsible research roadmap detailing the 4-phase testing workflow.

```powershell
uv run python -m app roadmap --scan <SCAN_ID>
```
