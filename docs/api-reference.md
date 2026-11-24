# Perimetryx REST API Reference Manual

The REST API is implemented with **FastAPI** and runs on **Uvicorn**.

---

## 1. Service Management

Start the REST API server locally:
```powershell
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

---

## 2. API Endpoints

### 2.1 Health Check
- **Endpoint:** `GET /api/health`
- **Response:** `200 OK`
  ```json
  {
    "status": "ok",
    "version": "2.0.0"
  }
  ```

### 2.2 Domains & Scope Management
- **Endpoint:** `POST /api/domains`
  - **Request Body (`DomainCreate`):**
    ```json
    {
      "root_domain": "example.com",
      "scope": {
        "domain": "example.com",
        "authorization_basis": "owned_asset",
        "allowed_domains": ["example.com", "*.example.com"],
        "excluded": ["payments.example.com"],
        "active_verification": false,
        "max_requests_per_second": 2.0,
        "max_concurrent_connections": 5,
        "allowed_ports": [80, 443],
        "user_agent": "Perimetryx/2.0 (+https://example.com; security-assessment)"
      }
    }
    ```
  - **Response:** `201 Created`

- **Endpoint:** `GET /api/domains`
  - **Response:** `200 OK` (List of registered domains)

- **Endpoint:** `GET /api/domains/{domain_id}`
  - **Response:** `200 OK` (Specific domain and serialized scope policy)

### 2.3 Scans Lifecycle
- **Endpoint:** `POST /api/domains/{domain_id}/scans`
  - **Request Body (`ScanCreate`):**
    ```json
    {
      "dry_run": true,
      "confirmed_authorization": false
    }
    ```
  - **Response:** `201 Created` (`id`, `status: queued`)

- **Endpoint:** `GET /api/scans/{scan_id}`
  - **Response:** `200 OK` (Status, timestamps, asset counts, findings counts)

- **Endpoint:** `GET /api/scans/{scan_id}/overview`
  - **Response:** `200 OK` (Full scan overview: assets, observations, findings, risk scores)

### 2.4 Attack Surface Topology Graph
- **Endpoint:** `GET /api/scans/{scan_id}/graph`
  - **Response:** `200 OK`
    ```json
    {
      "scan_id": 1,
      "root_domain": "example.com",
      "summary": { "total_nodes": 14, "total_edges": 18, "assets": 3 },
      "nodes": [
        { "id": "domain:example.com", "label": "example.com", "type": "domain" },
        { "id": "host:admin.example.com", "label": "admin.example.com", "type": "subdomain" }
      ],
      "edges": [
        { "source": "domain:example.com", "target": "host:admin.example.com", "relationship": "has_subdomain" }
      ]
    }
    ```

### 2.5 Historical Comparative Diff
- **Endpoint:** `GET /api/scans/{scan_id}/diff/{scan_b_id}`
  - **Response:** `200 OK`
    ```json
    {
      "from_scan_id": 1,
      "to_scan_id": 2,
      "new_assets": [],
      "removed_assets": [],
      "persisted_assets_count": 3,
      "new_findings": [],
      "resolved_findings": [],
      "score_delta": -5.2,
      "posture_trend": "Improved (-5.2 risk reduction)"
    }
    ```

### 2.6 AI Security Analyst Copilot
- **Endpoint:** `POST /api/scans/{scan_id}/copilot`
  - **Request Body (`CopilotQuestion`):**
    ```json
    {
      "question": "What are the primary attack surface exposure risks detected?"
    }
    ```
  - **Response:** `200 OK`
    ```json
    {
      "answer": "### Priority Attack Surface Review...",
      "citations": [
        { "asset_id": 1, "hostname": "staging.example.com", "score": 85 }
      ],
      "grounded": true,
      "model": "deterministic-analyst-v2"
    }
    ```

### 2.7 Audit Reports
- **Endpoint:** `GET /api/scans/{scan_id}/report?format=html`
  - **Response:** `200 OK` (`text/html`, Standalone Dark-Theme HTML Report)
- **Endpoint:** `GET /api/scans/{scan_id}/report?format=markdown`
  - **Response:** `200 OK` (`text/plain`, Markdown Report)
