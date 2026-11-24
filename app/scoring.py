"""Transparent, deterministic asset risk scoring. AI never writes this score."""

from __future__ import annotations

WEIGHTS: dict[str, tuple[str, int]] = {
    # Legacy & core weights
    "missing_security_header": ("configuration", 12),
    "staging_exposed": ("environment", 25),
    "dev_exposed": ("environment", 20),
    "dangling_cname_indicator": ("exposure", 30),
    "admin_surface": ("criticality", 15),

    # Advanced security signals
    "dns_zone_transfer": ("exposure", 35),
    "permissive_spf_all": ("configuration", 20),
    "neutral_spf_all": ("configuration", 8),
    "missing_spf_record": ("configuration", 10),
    "missing_dmarc_policy": ("configuration", 10),
    "dmarc_policy_none": ("configuration", 6),
    "expired_tls_certificate": ("configuration", 25),
    "tls_certificate_near_expiry": ("configuration", 10),
    "self_signed_certificate": ("configuration", 15),
    "deprecated_tls_version": ("configuration", 20),
    "exposed_metrics_endpoint": ("criticality", 25),
    "exposed_api_documentation": ("criticality", 15),
    "exposed_graphql_endpoint": ("criticality", 12),
    "exposed_monitoring_dashboard": ("criticality", 18),
    "weak_csp_policy": ("configuration", 10),
    "weak_hsts_policy": ("configuration", 6),
    "server_version_disclosure": ("configuration", 5),
    "unencrypted_http_transport": ("exposure", 15),
}


def score(findings: list[dict], environment: str) -> tuple[int, str, dict[str, int]]:
    """Calculate deterministic risk score, severity band, and category breakdown."""
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
