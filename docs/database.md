# Database & Persistence Specification

Perimetryx utilizes a normalized SQLite database with Foreign Keys enabled (`PRAGMA foreign_keys = ON;`) and WAL (Write-Ahead Logging) mode for concurrent reader/writer isolation.

---

## 1. Relational Schema Definitions

```sql
PRAGMA foreign_keys = ON;

-- Organizational Root Domains
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY,
    root_domain TEXT UNIQUE NOT NULL,
    scope_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Scan Lifecycles
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    status TEXT NOT NULL,
    dry_run INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    stats_json TEXT NOT NULL DEFAULT '{}'
);

-- Discovered Assets / Subdomains
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    hostname TEXT NOT NULL,
    source TEXT NOT NULL,
    environment TEXT NOT NULL,
    first_seen_scan_id INTEGER REFERENCES scans(id),
    last_seen_scan_id INTEGER REFERENCES scans(id),
    UNIQUE(domain_id, hostname)
);

-- Join table: Assets per Scan
CREATE TABLE IF NOT EXISTS scan_assets (
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    status TEXT NOT NULL,
    PRIMARY KEY(scan_id, asset_id)
);

-- Raw HTTP Observations
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    status_code INTEGER,
    title TEXT,
    headers_json TEXT NOT NULL,
    cname TEXT,
    response_time_ms REAL DEFAULT 0.0,
    body_preview TEXT DEFAULT ''
);

-- Granular DNS Records
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER
);

-- Fingerprinted Technologies
CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    version TEXT,
    confidence INTEGER
);

-- Cryptographic TLS Certificates
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    issuer TEXT,
    subject TEXT,
    sans_json TEXT NOT NULL DEFAULT '[]',
    not_before TEXT,
    not_after TEXT,
    days_left INTEGER,
    expired INTEGER DEFAULT 0,
    self_signed INTEGER DEFAULT 0
);

-- Deterministic Security Findings
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    rule_id TEXT,
    category TEXT,
    classification TEXT,
    description TEXT,
    evidence_json TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    mitre_technique TEXT DEFAULT '',
    cwe_id TEXT DEFAULT '',
    cvss_score REAL DEFAULT 0.0
);

-- Deterministic Risk Scores
CREATE TABLE IF NOT EXISTS risk_scores (
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    total INTEGER,
    band TEXT,
    breakdown_json TEXT NOT NULL,
    PRIMARY KEY(scan_id, asset_id)
);

-- Immutable Security Audit Trail
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    at TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL
);
```

---

## 2. Query Patterns & Indices

### 2.1 Asset Inventory Retrieval
```sql
SELECT a.id, a.hostname, a.environment,
       r.total AS score, r.band,
       o.status_code, o.cname, o.response_time_ms
FROM scan_assets sa
JOIN assets a ON a.id = sa.asset_id
LEFT JOIN risk_scores r ON r.asset_id = a.id AND r.scan_id = sa.scan_id
LEFT JOIN observations o ON o.asset_id = a.id AND o.scan_id = sa.scan_id
WHERE sa.scan_id = ?
ORDER BY r.total DESC;
```

### 2.2 Attack Surface Topology Graph Queries
```sql
-- Retrieve all subdomains, IP resolutions, technologies, and vulnerabilities for a given scan
SELECT a.hostname, d.record_type, d.value AS dns_val, t.name AS tech_name, f.rule_id, f.severity
FROM scan_assets sa
JOIN assets a ON a.id = sa.asset_id
LEFT JOIN dns_records d ON d.asset_id = a.id AND d.scan_id = sa.scan_id
LEFT JOIN technologies t ON t.asset_id = a.id AND t.scan_id = sa.scan_id
LEFT JOIN findings f ON f.asset_id = a.id AND f.scan_id = sa.scan_id
WHERE sa.scan_id = ?;
```

### 2.3 Historical Scan Comparative Queries
```sql
-- Identify newly introduced assets between Scan A and Scan B
SELECT a.hostname, r.total, r.band
FROM scan_assets sa
JOIN assets a ON a.id = sa.asset_id
LEFT JOIN risk_scores r ON r.asset_id = a.id AND r.scan_id = sa.scan_id
WHERE sa.scan_id = :scan_b
  AND a.hostname NOT IN (
      SELECT a2.hostname
      FROM scan_assets sa2
      JOIN assets a2 ON a2.id = sa2.asset_id
      WHERE sa2.scan_id = :scan_a
  );
```
