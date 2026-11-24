"""Storage operations shared by API endpoints, CLI, and scan jobs."""

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
                scan_id, asset_id, status_code, title, headers_json, cname, response_time_ms, body_preview
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                asset_id,
                observation.status_code,
                observation.title,
                dump(observation.headers),
                observation.cname,
                getattr(observation, "response_time_ms", 0.0),
                getattr(observation, "body_preview", "")[:500],
            ),
        )

        # Ingest Technologies
        for tech in getattr(observation, "technologies", []):
            conn.execute(
                """INSERT INTO technologies(
                    scan_id, asset_id, name, category, version, confidence
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    asset_id,
                    tech["name"],
                    tech["category"],
                    tech.get("version"),
                    tech.get("confidence", 100),
                ),
            )

        # Ingest DNS records
        dns_prof = getattr(observation, "dns_profile", None)
        if dns_prof:
            for ip in dns_prof.a_records:
                conn.execute(
                    "INSERT INTO dns_records(scan_id, asset_id, record_type, value) VALUES (?, ?, 'A', ?)",
                    (scan_id, asset_id, ip),
                )
            for ip6 in dns_prof.aaaa_records:
                conn.execute(
                    "INSERT INTO dns_records(scan_id, asset_id, record_type, value) VALUES (?, ?, 'AAAA', ?)",
                    (scan_id, asset_id, ip6),
                )
            for cname in dns_prof.cname_records:
                conn.execute(
                    "INSERT INTO dns_records(scan_id, asset_id, record_type, value) VALUES (?, ?, 'CNAME', ?)",
                    (scan_id, asset_id, cname),
                )
            for mx in dns_prof.mx_records:
                conn.execute(
                    "INSERT INTO dns_records(scan_id, asset_id, record_type, value) VALUES (?, ?, 'MX', ?)",
                    (scan_id, asset_id, f"{mx['preference']} {mx['exchange']}"),
                )
            for txt in dns_prof.txt_records:
                conn.execute(
                    "INSERT INTO dns_records(scan_id, asset_id, record_type, value) VALUES (?, ?, 'TXT', ?)",
                    (scan_id, asset_id, txt[:255]),
                )
            for ns in dns_prof.ns_records:
                conn.execute(
                    "INSERT INTO dns_records(scan_id, asset_id, record_type, value) VALUES (?, ?, 'NS', ?)",
                    (scan_id, asset_id, ns),
                )
            if dns_prof.soa_record:
                conn.execute(
                    "INSERT INTO dns_records(scan_id, asset_id, record_type, value) VALUES (?, ?, 'SOA', ?)",
                    (scan_id, asset_id, dns_prof.soa_record),
                )

        # Ingest TLS certificate
        tls_prof = getattr(observation, "tls_profile", None)
        if tls_prof and tls_prof.not_after:
            conn.execute(
                """INSERT INTO certificates(
                    scan_id, asset_id, issuer, subject, sans_json, not_before, not_after, days_left, expired, self_signed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    asset_id,
                    tls_prof.issuer,
                    tls_prof.subject,
                    dump(tls_prof.sans),
                    tls_prof.not_before.isoformat() if tls_prof.not_before else None,
                    tls_prof.not_after.isoformat() if tls_prof.not_after else None,
                    tls_prof.days_left,
                    1 if tls_prof.expired else 0,
                    1 if tls_prof.self_signed else 0,
                ),
            )

    return asset_id


def add_finding(scan_id: int, asset_id: int, finding: dict) -> int:
    with db() as conn:
        finding_id = conn.execute(
            """INSERT INTO findings(
                scan_id, asset_id, rule_id, category, classification, description, evidence_json,
                severity, mitre_technique, cwe_id, cvss_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                asset_id,
                finding["rule_id"],
                finding["category"],
                finding["classification"],
                finding["description"],
                dump(finding["evidence"]),
                finding.get("severity", "medium"),
                finding.get("mitre_technique", ""),
                finding.get("cwe_id", ""),
                float(finding.get("cvss_score", 0.0)),
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
