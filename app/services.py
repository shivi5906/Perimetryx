"""Storage operations shared by API endpoints and background scan jobs."""

from __future__ import annotations

from .pipeline import Observation
from .scoring import score
from .store import db, dump, now, rows


def audit(scan_id: int, action: str, target: str, result: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_events(scan_id, at, action, target, result) VALUES (?, ?, ?, ?, ?)",
            (scan_id, now(), action, target, result),
        )


def ingest_observation(scan_id: int, domain_id: int, observation: Observation) -> int:
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM assets WHERE domain_id = ? AND hostname = ?",
            (domain_id, observation.hostname),
        ).fetchone()
        if existing:
            asset_id = existing["id"]
            change = "persisted"
        else:
            asset_id = conn.execute(
                """INSERT INTO assets(
                    domain_id, hostname, source, environment, first_seen_scan_id, last_seen_scan_id
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    domain_id,
                    observation.hostname,
                    observation.source,
                    observation.environment,
                    scan_id,
                    scan_id,
                ),
            ).lastrowid
            change = "new"
        conn.execute(
            "UPDATE assets SET last_seen_scan_id = ?, environment = ? WHERE id = ?",
            (scan_id, observation.environment, asset_id),
        )
        conn.execute(
            "INSERT OR REPLACE INTO scan_assets(scan_id, asset_id, status) VALUES (?, ?, ?)",
            (scan_id, asset_id, change),
        )
        conn.execute(
            """INSERT INTO observations(
                scan_id, asset_id, status_code, title, headers_json, cname
            ) VALUES (?, ?, ?, ?, ?, NULL)""",
            (
                scan_id,
                asset_id,
                observation.status_code,
                observation.title,
                dump(observation.headers),
            ),
        )
    return asset_id


def add_finding(scan_id: int, asset_id: int, finding: dict) -> int:
    with db() as conn:
        finding_id = conn.execute(
            """INSERT INTO findings(
                scan_id, asset_id, rule_id, category, classification, description, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                asset_id,
                finding["rule_id"],
                finding["category"],
                finding["classification"],
                finding["description"],
                dump(finding["evidence"]),
            ),
        ).lastrowid
    recompute_score(scan_id, asset_id)
    return finding_id


def recompute_score(scan_id: int, asset_id: int) -> None:
    with db() as conn:
        asset = conn.execute("SELECT environment FROM assets WHERE id = ?", (asset_id,)).fetchone()
        findings = rows(
            conn.execute(
                "SELECT category FROM findings WHERE scan_id = ? AND asset_id = ?",
                (scan_id, asset_id),
            )
        )
        total, band, breakdown = score(findings, asset["environment"])
        conn.execute(
            """INSERT OR REPLACE INTO risk_scores(
                scan_id, asset_id, total, band, breakdown_json
            ) VALUES (?, ?, ?, ?, ?)""",
            (scan_id, asset_id, total, band, dump(breakdown)),
        )


def finish_scan(scan_id: int, status: str, error: str | None = None) -> dict:
    with db() as conn:
        asset_ids = rows(conn.execute("SELECT asset_id FROM scan_assets WHERE scan_id = ?", (scan_id,)))
    for record in asset_ids:
        recompute_score(scan_id, record["asset_id"])
    with db() as conn:
        stats = {
            "assets": len(asset_ids),
            "findings": conn.execute("SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)).fetchone()[0],
        }
        if error:
            stats["error"] = error
        conn.execute(
            "UPDATE scans SET status = ?, completed_at = ?, stats_json = ? WHERE id = ?",
            (status, now(), dump(stats), scan_id),
        )
    return stats
