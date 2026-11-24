"""Deterministic rules that only assess evidence gathered by the scan."""

from __future__ import annotations

from typing import Any

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
}


def classify_environment(hostname: str) -> str:
    labels = hostname.lower().split(".")
    if any(label in {"staging", "stage", "uat", "test"} for label in labels):
        return "staging"
    if any(label in {"dev", "development", "sandbox", "demo"} for label in labels):
        return "dev"
    return "prod"


def findings_for_observation(
    hostname: str,
    scheme: str | None,
    status_code: int | None,
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    normalized_headers = {name.lower(): value for name, value in headers.items()}
    environment = classify_environment(hostname)

    if status_code is not None and environment in {"staging", "dev"}:
        findings.append(
            {
                "rule_id": "ENV-001",
                "category": f"{environment}_exposed",
                "classification": "Potential Risk",
                "description": f"A {environment}-named hostname responded over {scheme or 'HTTP'}.",
                "evidence": {"hostname": hostname, "status_code": status_code, "scheme": scheme},
            }
        )

    if status_code is not None:
        for header_key, header_name in SECURITY_HEADERS.items():
            if header_key not in normalized_headers:
                findings.append(
                    {
                        "rule_id": f"HDR-{header_key.upper()}",
                        "category": "missing_security_header",
                        "classification": "Observed",
                        "description": f"Response did not include {header_name}.",
                        "evidence": {"hostname": hostname, "status_code": status_code, "missing_header": header_name},
                    }
                )

    if any(label in {"admin", "administrator", "manage"} for label in hostname.lower().split(".")):
        findings.append(
            {
                "rule_id": "SURFACE-001",
                "category": "admin_surface",
                "classification": "Needs Manual Verification",
                "description": "Hostname suggests an administrative surface; no authentication or path probing was performed.",
                "evidence": {"hostname": hostname},
            }
        )
    return findings
