# Database Design

## 1. Conceptual ER Model

```text
Domain 1───* Scan
Scan 1───* Subdomain (assets discovered in that scan)
Subdomain *───* Scan   (via ScanAsset join — an asset can reappear across scans)
Subdomain 1───* DNSRecord
Subdomain 1───* IPAddress            (via DNSRecord A/AAAA resolution)
IPAddress *───1 ASNInfo               (cloud/provider/ASN lookup, cached & shared)
Subdomain 1───* Certificate
Subdomain 1───* HTTPObservation
HTTPObservation 1───* Technology
Subdomain 1───* Finding
Finding *───1 HTTPObservation | DNSRecord | Technology   (evidence FK — polymorphic or nullable FKs)
Subdomain 1───1 RiskScore   (per scan — really Subdomain+Scan → RiskScore)
Subdomain 1───* AIInsight
Scan 1───* ScanHistoryDiff  (comparison artifacts vs a prior scan)
```

## 2. Core Tables

### `domain`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| root_domain | text, unique | e.g. `example.com` |
| owner_user_id | UUID FK → user | who authorized this domain |
| scope_config | JSONB | serialized scope.yaml at time of creation |
| created_at | timestamp | |

### `scan`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| domain_id | UUID FK → domain | |
| status | enum | pending / running / completed / failed |
| started_at / completed_at | timestamp | |
| config | JSONB | which sources/stages were enabled |
| stats | JSONB | asset counts, duration, etc. — cached for fast dashboard reads |

### `subdomain`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| domain_id | UUID FK → domain | |
| hostname | text | |
| first_seen_scan_id | UUID FK → scan | |
| last_seen_scan_id | UUID FK → scan | |
| environment_guess | enum | prod / staging / dev / unknown |
| discovery_source | text | which passive source found it (evidence attribution) |

### `scan_asset` (join table — which assets appeared in which scan)
| Column | Type | Notes |
|---|---|---|
| scan_id | UUID FK | |
| subdomain_id | UUID FK | |
| status | enum | new / persisted / removed (relative to prior scan) |

### `dns_record`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| subdomain_id | UUID FK | |
| scan_id | UUID FK | |
| record_type | enum | A / AAAA / CNAME / MX / NS / TXT |
| value | text | |
| ttl | int | |

### `ip_address`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| address | inet, unique | |
| asn | int, nullable | cached, shared across subdomains that resolve to the same IP |
| asn_org | text, nullable | |
| cloud_provider | text, nullable | derived from ASN/reverse-DNS heuristics |

### `certificate`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| subdomain_id | UUID FK | |
| issuer | text | |
| subject_alt_names | text[] | secondary subdomain discovery source |
| not_before / not_after | timestamp | |
| observed_at_scan_id | UUID FK | |

### `http_observation`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| subdomain_id | UUID FK | |
| scan_id | UUID FK | |
| status_code | int | |
| redirect_chain | JSONB | ordered list of URLs |
| title | text | |
| headers | JSONB | full raw header set — this is the evidence blob findings cite |
| response_size | int | |
| response_time_ms | int | |
| tls_summary | JSONB | protocol version, cert chain summary |

### `technology`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| http_observation_id | UUID FK | |
| category | enum | web_server / framework / cms / js_framework / cdn / cloud / reverse_proxy |
| name | text | |
| confidence | float | 0-1, from fingerprint matcher |

### `finding`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| subdomain_id | UUID FK | |
| scan_id | UUID FK | |
| rule_id | text | which deterministic rule (or `ai-proposed`) generated this |
| category | text | e.g. `missing_security_header`, `staging_exposed`, `dangling_cname_indicator` |
| classification | enum | Observed / Potential Risk / Needs Manual Verification / Confirmed Vulnerability |
| evidence_ref | JSONB | FK-like pointers to the http_observation/dns_record/technology row(s) that justify this |
| description | text | |

### `risk_score`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| subdomain_id | UUID FK | |
| scan_id | UUID FK | |
| total_score | int | |
| breakdown | JSONB | `{criticality: N, exposure: N, technology: N, configuration: N, environment: N, correlation: N}` — never just the total, always the breakdown |
| band | enum | low / medium / high / critical |

### `ai_insight`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| subdomain_id | UUID FK, nullable | null for scan-level insights (e.g. summaries) |
| scan_id | UUID FK | |
| insight_type | text | prioritization / explanation / cluster_label / anomaly / qa_answer |
| content | text | |
| citations | JSONB | list of evidence row references the AI drew on |
| model_used | text | |
| generated_at | timestamp | |

### `scan_history_diff`
| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| scan_id_from / scan_id_to | UUID FK | |
| new_assets | UUID[] | |
| removed_assets | UUID[] | |
| changed_assets | JSONB | per-asset list of what changed (new tech, new finding, score delta) |
| ai_summary | text, nullable | grounded narrative, generated from the deterministic diff above |

## 3. Why Historical Scan Data Matters

A single scan is a snapshot; attack surfaces are not static. The value compounds over repeated scans:

```text
Scan 1 → 120 assets
Scan 2 → 137 assets
AI: "17 new assets appeared since the previous scan."
```

This is the difference between a one-off report and a monitoring capability — the same data model that supports "what does this domain look like today" also supports "what changed, and does the change matter" without any additional scanning logic, just diffing already-structured rows. It's also what makes the `scan_asset.status` (new/persisted/removed) and `scan_history_diff` tables worth building even though they add no value to a single-scan MVP demo — they're what turns the tool from a scanner into a monitoring platform later without a schema migration.

## 4. Storage Choice

**MVP: SQLite.** Zero operational overhead, trivially portable (`.db` file you can hand someone), and completely sufficient for a single-user CLI tool running one scan at a time. JSONB columns above degrade gracefully to SQLite's JSON1 extension.

**Production/dashboard: PostgreSQL.** Needed once there's concurrent multi-user access (Phase 7 web dashboard + API), real JSONB indexing for querying evidence blobs efficiently, and row-level concurrency for background scan workers.

**Redis:** introduced only alongside Celery (Phase 7) — as a broker/result backend and for rate-limit token-bucket state shared across worker processes. Not needed before then.
