"""Transparent, deterministic asset scoring. AI never writes this score."""

from __future__ import annotations

WEIGHTS = {
    "missing_security_header": ("configuration", 12),
    "staging_exposed": ("environment", 25),
    "dev_exposed": ("environment", 20),
    "dangling_cname_indicator": ("exposure", 30),
    "admin_surface": ("criticality", 15),
}


def score(findings: list[dict], environment: str) -> tuple[int, str, dict[str, int]]:
    breakdown = {
        key: 0 for key in ("criticality", "exposure", "technology", "configuration", "environment", "correlation")
    }
    for finding in findings:
        category, points = WEIGHTS.get(finding["category"], ("configuration", 5))
        breakdown[category] += points
    if environment == "staging":
        breakdown["environment"] += 10
    if environment == "dev":
        breakdown["environment"] += 8
    total = min(100, sum(breakdown.values()))
    band = "critical" if total >= 75 else "high" if total >= 45 else "medium" if total >= 20 else "low"
    return total, band, breakdown
