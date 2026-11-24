"""Enterprise security posture analysis engine.

Evaluates evidence against defense-in-depth rules mapped to MITRE ATT&CK and CWE standards.
"""

from __future__ import annotations

import re
from typing import Any

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def classify_environment(hostname: str) -> str:
    """Classify asset into prod, staging, dev, or test environment."""
    labels = hostname.lower().split(".")
    if any(label in {"staging", "stage", "uat", "test", "qa", "preprod"} for label in labels):
        return "staging"
    if any(label in {"dev", "development", "sandbox", "demo", "lab", "local"} for label in labels):
        return "dev"
    return "prod"


def findings_for_observation(
    hostname: str,
    scheme: str | None,
    status_code: int | None,
    headers: dict[str, str],
    body_preview: str | None = None,
) -> list[dict[str, Any]]:
    """Generate deterministic security findings from HTTP headers and environment indicators."""
    findings: list[dict[str, Any]] = []
    normalized_headers = {name.lower(): str(value) for name, value in headers.items()}
    environment = classify_environment(hostname)

    # 1. Environment Exposure Findings
    if status_code is not None and environment in {"staging", "dev"}:
        findings.append({
            "rule_id": "ENV-001",
            "category": f"{environment}_exposed",
            "classification": "Potential Risk",
            "severity": "high",
            "mitre_technique": "T1592",
            "cwe_id": "CWE-200",
            "cvss_score": 6.8,
            "description": f"A non-production ({environment}) hostname responded with HTTP {status_code} over {scheme or 'HTTP'}. May expose unhardened endpoints or test data.",
            "evidence": {"hostname": hostname, "status_code": status_code, "scheme": scheme},
        })

    # 2. Insecure Plain HTTP (No TLS)
    if scheme == "http" and status_code is not None:
        # Check if it didn't redirect to HTTPS
        location = normalized_headers.get("location", "")
        if not location.startswith("https://"):
            findings.append({
                "rule_id": "NET-HTTP-INSECURE",
                "category": "unencrypted_http_transport",
                "classification": "Potential Risk",
                "severity": "medium",
                "mitre_technique": "T1557",
                "cwe_id": "CWE-319",
                "cvss_score": 5.9,
                "description": f"Host {hostname} serves traffic over unencrypted HTTP (port 80) without automatic redirection to HTTPS.",
                "evidence": {"hostname": hostname, "status_code": status_code, "location": location},
            })

    # 3. Security Header Analysis
    if status_code is not None:
        # HSTS (Strict-Transport-Security)
        hsts = normalized_headers.get("strict-transport-security")
        if not hsts:
            findings.append({
                "rule_id": "HDR-STRICT-TRANSPORT-SECURITY",
                "category": "missing_security_header",
                "classification": "Observed",
                "severity": "medium",
                "mitre_technique": "T1557",
                "cwe_id": "CWE-319",
                "cvss_score": 4.8,
                "description": f"Response on {hostname} lacks Strict-Transport-Security (HSTS), leaving clients vulnerable to SSL-stripping man-in-the-middle attacks.",
                "evidence": {"hostname": hostname, "missing_header": "Strict-Transport-Security"},
            })
        else:
            # Check max-age duration
            match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    findings.append({
                        "rule_id": "HDR-HSTS-WEAK",
                        "category": "weak_hsts_policy",
                        "classification": "Observed",
                        "severity": "low",
                        "mitre_technique": "T1557",
                        "cwe_id": "CWE-319",
                        "cvss_score": 3.1,
                        "description": f"HSTS max-age is set to {max_age} seconds (< 1 year recommended duration).",
                        "evidence": {"hostname": hostname, "hsts_value": hsts},
                    })

        # Content-Security-Policy (CSP)
        csp = normalized_headers.get("content-security-policy")
        if not csp:
            findings.append({
                "rule_id": "HDR-CONTENT-SECURITY-POLICY",
                "category": "missing_security_header",
                "classification": "Observed",
                "severity": "medium",
                "mitre_technique": "T1189",
                "cwe_id": "CWE-693",
                "cvss_score": 5.0,
                "description": f"Response on {hostname} lacks a Content-Security-Policy (CSP) header, increasing susceptibility to Cross-Site Scripting (XSS) and data injection.",
                "evidence": {"hostname": hostname, "missing_header": "Content-Security-Policy"},
            })
        else:
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                findings.append({
                    "rule_id": "HDR-CSP-UNSAFE-DIRECTIVES",
                    "category": "weak_csp_policy",
                    "classification": "Potential Risk",
                    "severity": "medium",
                    "mitre_technique": "T1189",
                    "cwe_id": "CWE-693",
                    "cvss_score": 5.4,
                    "description": f"Content-Security-Policy uses 'unsafe-inline' or 'unsafe-eval', undermining script execution isolation guarantees.",
                    "evidence": {"hostname": hostname, "csp_snippet": csp[:120]},
                })

        # X-Frame-Options
        if "x-frame-options" not in normalized_headers and (not csp or "frame-ancestors" not in csp):
            findings.append({
                "rule_id": "HDR-X-FRAME-OPTIONS",
                "category": "missing_security_header",
                "classification": "Observed",
                "severity": "low",
                "mitre_technique": "T1189",
                "cwe_id": "CWE-1021",
                "cvss_score": 3.7,
                "description": f"Response lacks X-Frame-Options and CSP frame-ancestors, permitting framing in malicious <iframes> (Clickjacking).",
                "evidence": {"hostname": hostname, "missing_header": "X-Frame-Options"},
            })

        # X-Content-Type-Options
        if "x-content-type-options" not in normalized_headers:
            findings.append({
                "rule_id": "HDR-X-CONTENT-TYPE-OPTIONS",
                "category": "missing_security_header",
                "classification": "Observed",
                "severity": "low",
                "mitre_technique": "T1592",
                "cwe_id": "CWE-16",
                "cvss_score": 3.1,
                "description": f"Response lacks 'X-Content-Type-Options: nosniff', allowing browsers to MIME-sniff responses into executable script formats.",
                "evidence": {"hostname": hostname, "missing_header": "X-Content-Type-Options"},
            })

        # Referrer-Policy
        if "referrer-policy" not in normalized_headers:
            findings.append({
                "rule_id": "HDR-REFERRER-POLICY",
                "category": "missing_security_header",
                "classification": "Observed",
                "severity": "low",
                "mitre_technique": "T1592",
                "cwe_id": "CWE-200",
                "cvss_score": 2.5,
                "description": f"Response lacks Referrer-Policy header; URLs containing private tokens or session parameters may leak in Referer headers.",
                "evidence": {"hostname": hostname, "missing_header": "Referrer-Policy"},
            })

        # 4. Server Banner Version Disclosure
        server = normalized_headers.get("server", "")
        x_powered = normalized_headers.get("x-powered-by", "")
        for header_val, header_title in ((server, "Server"), (x_powered, "X-Powered-By")):
            if re.search(r"[\d]+\.[\d]+", header_val):
                findings.append({
                    "rule_id": "DISC-BANNER-VERSION",
                    "category": "server_version_disclosure",
                    "classification": "Observed",
                    "severity": "low",
                    "mitre_technique": "T1592.002",
                    "cwe_id": "CWE-200",
                    "cvss_score": 3.3,
                    "description": f"Header '{header_title}: {header_val}' leaks precise software version details, simplifying targeted exploit selection.",
                    "evidence": {"hostname": hostname, "header": header_title, "value": header_val},
                })

    # 5. Admin Surface Keyword Indicator
    if any(label in {"admin", "administrator", "manage"} for label in hostname.lower().split(".")):
        findings.append({
            "rule_id": "SURFACE-001",
            "category": "admin_surface",
            "classification": "Needs Manual Verification",
            "severity": "medium",
            "mitre_technique": "T1078",
            "cwe_id": "CWE-200",
            "cvss_score": 4.8,
            "description": "Hostname suggests an administrative surface; no authentication or path probing was performed.",
            "evidence": {"hostname": hostname},
        })

    return findings
