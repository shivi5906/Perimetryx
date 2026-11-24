# Perimetryx

Perimetryx is an authorized attack-surface intelligence platform. It makes evidence-backed reconnaissance understandable without presenting potential findings as confirmed vulnerabilities.

## Version 2 delivery

- Web dashboard for asset priority, graph relations, history, and grounded copilot answers
- FastAPI REST API with strict scope enforcement and audit events
- Scan lifecycle, asset evidence, deterministic risk scoring, and historical diffs
- Pluggable copilot providers: deterministic baseline, OpenAI, or local Ollama
- Scope-gated collection: public CT records, DNS, and one root-page observation per in-scope host
- SQLite development store with Postgres/Redis container services ready for the production migration

## Run locally

```powershell
winget install --id=astral-sh.uv -e
# Restart PowerShell once installation completes.
uv sync --all-groups
./scripts/dev.ps1
```

Open `http://localhost:8000`. Start with **Dry run** to verify the domain and scope configuration. A live scan requires explicit authorization confirmation and is limited to public CT records, DNS, and a single root-page request to each in-scope host.

## Development with uv

`pyproject.toml` is the only dependency source. `uv sync` creates the isolated `.venv` and `uv.lock`; commit the lock file after the first sync for reproducible installs.

```powershell
# Add a runtime or development dependency
uv add dnspython
uv add --group dev pytest-cov

# Run the main tasks without manually activating .venv
./scripts/dev.ps1
./scripts/check.ps1
```

## CLI workflow

The CLI is the primary operator workflow. It writes a reviewable scope file first and refuses a live scan without explicit confirmation.

```powershell
# Create scope, then edit targets/exclusions against the current program brief.
uv run python -m app init-scope --domain your-test-store.myshopify.com --authorization bug_bounty_program

# No network requests; validates scope and creates a scan record.
uv run python -m app scan --scope scope.yaml --dry-run

# Only after explicit program authorization.
uv run python -m app scan --scope scope.yaml --confirm-authorization

# Turn evidence into manual-review priorities and a responsible reporting roadmap.
uv run python -m app prioritize --scan 1
uv run python -m app roadmap --scan 1
uv run python -m app export --scan 1 --output report.md
```

The roadmap identifies safe next checks and evidence requirements. It does not perform exploitation, credential attacks, account enumeration, path fuzzing, or submit reports automatically.

## Safety model

Every target is validated against an explicit scope before it can enter a scan. This implementation does not include exploitation, brute force, arbitrary port scanning, or vulnerability confirmation. Findings are limited to `Observed`, `Potential Risk`, and `Needs Manual Verification`.

Use [scope.example.yaml](scope.example.yaml) as the required authorization and rate-limit template for any future collection adapter.

## API surface

- `POST /api/domains` - create an authorized domain and immutable scope configuration
- `POST /api/domains/{id}/scans` - create a scan lifecycle
- `POST /api/scans/{id}/assets` - ingest an in-scope observed asset
- `POST /api/scans/{id}/assets/{asset}/findings` - record citable deterministic findings
- `GET /api/scans/{id}/overview`, `/graph`, `/diff` - power the v2 dashboard
- `POST /api/scans/{id}/copilot` - evidence-grounded priority answer

## Architecture

The current delivery deliberately separates collection adapters from analysis. The dashboard is useful today with validated imported observations; any passive-source connector must pass the same scope guard, rate limits, and audit log before storing an asset. AI output does not calculate or override a risk score.

Set `PERIMETRYX_AI_PROVIDER` to `groq`, `openai`, or `ollama` only after configuring its environment variables. Groq uses the OpenAI-compatible endpoint and defaults to `llama-3.3-70b-versatile`. Provider output is returned with the same asset citations used in the prompt.
