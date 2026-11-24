# Perimetryx

Perimetryx is an authorized attack-surface intelligence platform. It makes evidence-backed reconnaissance understandable without presenting potential findings as confirmed vulnerabilities.

## Version 2 delivery

- Web dashboard for asset priority, graph relations, history, and grounded copilot answers
- FastAPI REST API with strict scope enforcement and audit events
- Scan lifecycle, asset evidence, deterministic risk scoring, and historical diffs
- SQLite development store with Postgres/Redis container services ready for the production migration

## Run locally

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open `http://localhost:8000`, then select **Load safe demo**. It only writes local demo data; it sends no network requests.

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
