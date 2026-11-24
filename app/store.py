from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("PERIMETRYX_DB_PATH", "data/perimetryx.db"))

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY,
    root_domain TEXT UNIQUE NOT NULL,
    scope_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    status TEXT NOT NULL,
    dry_run INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    stats_json TEXT NOT NULL DEFAULT '{}'
);
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
CREATE TABLE IF NOT EXISTS scan_assets (
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    status TEXT NOT NULL,
    PRIMARY KEY(scan_id, asset_id)
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    status_code INTEGER,
    title TEXT,
    headers_json TEXT NOT NULL,
    cname TEXT,
    response_time_ms REAL,
    body_preview TEXT
);
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER
);
CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    version TEXT,
    confidence INTEGER
);
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
CREATE TABLE IF NOT EXISTS risk_scores (
    scan_id INTEGER REFERENCES scans(id),
    asset_id INTEGER REFERENCES assets(id),
    total INTEGER,
    band TEXT,
    breakdown_json TEXT NOT NULL,
    PRIMARY KEY(scan_id, asset_id)
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    at TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with db() as conn:
        conn.executescript(SCHEMA)
        # Migrate existing database columns gracefully
        obs_cols = [r["name"] for r in rows(conn.execute("PRAGMA table_info(observations)"))]
        if "response_time_ms" not in obs_cols:
            conn.execute("ALTER TABLE observations ADD COLUMN response_time_ms REAL DEFAULT 0.0")
        if "body_preview" not in obs_cols:
            conn.execute("ALTER TABLE observations ADD COLUMN body_preview TEXT DEFAULT ''")

        finding_cols = [r["name"] for r in rows(conn.execute("PRAGMA table_info(findings)"))]
        if "severity" not in finding_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN severity TEXT DEFAULT 'medium'")
        if "mitre_technique" not in finding_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN mitre_technique TEXT DEFAULT ''")
        if "cwe_id" not in finding_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN cwe_id TEXT DEFAULT ''")
        if "cvss_score" not in finding_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN cvss_score REAL DEFAULT 0.0")


def rows(cursor):
    return [dict(row) for row in cursor.fetchall()]


def dump(value):
    return json.dumps(value, separators=(",", ":"))


def load(value):
    return json.loads(value) if value else {}
