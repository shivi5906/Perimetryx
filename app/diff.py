"""Historical scan diffing and security regression analysis engine."""

from __future__ import annotations

from typing import Any
from .store import db, rows


def calculate_scan_diff(scan_id_a: int, scan_id_b: int) -> dict[str, Any]:
    """Calculate comparative delta between an earlier scan A and later scan B."""
    with db() as conn:
        def get_scan_assets(sid: int) -> dict[str, dict]:
            res = rows(conn.execute(
                """SELECT a.id, a.hostname, a.environment, r.total as score, r.band
                   FROM scan_assets sa
                   JOIN assets a ON a.id = sa.asset_id
                   LEFT JOIN risk_scores r ON r.asset_id = a.id AND r.scan_id = sa.scan_id
                   WHERE sa.scan_id = ?""",
                (sid,),
            ))
            return {item["hostname"]: item for item in res}

        def get_scan_findings(sid: int) -> set[tuple[str, str]]:
            res = rows(conn.execute(
                """SELECT a.hostname, f.rule_id
                   FROM findings f
                   JOIN assets a ON a.id = f.asset_id
                   WHERE f.scan_id = ?""",
                (sid,),
            ))
            return {(item["hostname"], item["rule_id"]) for item in res}

        assets_a = get_scan_assets(scan_id_a)
        assets_b = get_scan_assets(scan_id_b)

        names_a = set(assets_a.keys())
        names_b = set(assets_b.keys())

        new_hostnames = sorted(names_b - names_a)
        removed_hostnames = sorted(names_a - names_b)
        persistent_hostnames = sorted(names_a & names_b)

        findings_a = get_scan_findings(scan_id_a)
        findings_b = get_scan_findings(scan_id_b)

        new_findings = [
            {"hostname": host, "rule_id": rule}
            for host, rule in sorted(findings_b - findings_a)
        ]
        resolved_findings = [
            {"hostname": host, "rule_id": rule}
            for host, rule in sorted(findings_a - findings_b)
        ]

        avg_score_a = (
            sum(a["score"] or 0 for a in assets_a.values()) / max(len(assets_a), 1)
        )
        avg_score_b = (
            sum(b["score"] or 0 for b in assets_b.values()) / max(len(assets_b), 1)
        )

        score_delta = round(avg_score_b - avg_score_a, 2)
        if score_delta > 0:
            posture_trend = f"Degraded (+{score_delta} risk increase)"
        elif score_delta < 0:
            posture_trend = f"Improved ({score_delta} risk reduction)"
        else:
            posture_trend = "Neutral (No significant risk delta)"

        return {
            "from_scan_id": scan_id_a,
            "to_scan_id": scan_id_b,
            "new_assets": [assets_b[h] for h in new_hostnames],
            "removed_assets": [assets_a[h] for h in removed_hostnames],
            "persisted_assets_count": len(persistent_hostnames),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "score_delta": score_delta,
            "posture_trend": posture_trend,
        }
