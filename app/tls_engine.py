"""TLS/SSL Cryptographic Posture, Certificate Hierarchy, and SAN Recon Engine."""

from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class TLSProfile:
    hostname: str
    port: int = 443
    issuer: str | None = None
    subject: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: datetime.datetime | None = None
    not_after: datetime.datetime | None = None
    days_left: int | None = None
    expired: bool = False
    near_expiry: bool = False
    self_signed: bool = False
    tls_version: str | None = None
    cipher_suite: str | None = None
    error: str | None = None


async def inspect_tls(hostname: str, port: int = 443, timeout: float = 4.0) -> TLSProfile:
    """Connect via TLS and parse the X.509 certificate and cipher parameters."""
    profile = TLSProfile(hostname=hostname, port=port)

    def _sync_tls_handshake():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We want to examine untrusted/self-signed certs too

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                version = ssock.version()
                cipher = ssock.cipher()
                return der_cert, version, cipher

    try:
        loop = asyncio.get_running_loop()
        der_cert, version, cipher = await loop.run_in_executor(None, _sync_tls_handshake)
        if not der_cert:
            profile.error = "No certificate presented"
            return profile

        profile.tls_version = version
        profile.cipher_suite = cipher[0] if cipher else None

        cert = x509.load_der_x509_certificate(der_cert)

        # Subject & Issuer
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        profile.subject = subject_cn[0].value if subject_cn else str(cert.subject)

        issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if issuer_org:
            profile.issuer = issuer_org[0].value
        elif issuer_cn:
            profile.issuer = issuer_cn[0].value
        else:
            profile.issuer = str(cert.issuer)

        # Self-signed test
        if cert.issuer == cert.subject:
            profile.self_signed = True

        # Validity Dates
        profile.not_before = cert.not_valid_before_utc
        profile.not_after = cert.not_valid_after_utc

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        delta = profile.not_after - now_utc
        profile.days_left = delta.days

        if profile.days_left < 0:
            profile.expired = True
        elif profile.days_left <= 14:
            profile.near_expiry = True

        # Subject Alternative Names (SANs) - High recon value!
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            profile.sans = [name.lower() for name in san_ext.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            profile.sans = []

    except (ssl.SSLError, socket.error, OSError, TimeoutError) as e:
        profile.error = str(e)
    except Exception as e:
        profile.error = f"Certificate parse error: {e}"

    return profile


def evaluate_tls_hygiene(profile: TLSProfile) -> list[dict]:
    """Generate findings for certificate expiry, self-signed status, and cipher hygiene."""
    findings = []
    if profile.error or not profile.not_after:
        return findings

    if profile.expired:
        findings.append({
            "rule_id": "TLS-CERT-EXPIRED",
            "category": "expired_tls_certificate",
            "classification": "Confirmed Vulnerability",
            "severity": "high",
            "mitre_technique": "T1592.004",
            "cwe_id": "CWE-295",
            "cvss_score": 6.5,
            "description": f"TLS certificate for {profile.hostname} expired {abs(profile.days_left or 0)} days ago ({profile.not_after.strftime('%Y-%m-%d')}).",
            "evidence": {
                "hostname": profile.hostname,
                "issuer": profile.issuer,
                "days_expired": abs(profile.days_left or 0),
                "not_after": profile.not_after.isoformat(),
            },
        })
    elif profile.near_expiry:
        findings.append({
            "rule_id": "TLS-CERT-NEAR-EXPIRY",
            "category": "tls_certificate_near_expiry",
            "classification": "Potential Risk",
            "severity": "medium",
            "mitre_technique": "T1592.004",
            "cwe_id": "CWE-298",
            "cvss_score": 4.0,
            "description": f"TLS certificate for {profile.hostname} expires in {profile.days_left} days. Service disruption risk if not renewed.",
            "evidence": {
                "hostname": profile.hostname,
                "issuer": profile.issuer,
                "days_left": profile.days_left,
                "not_after": profile.not_after.isoformat(),
            },
        })

    if profile.self_signed:
        findings.append({
            "rule_id": "TLS-CERT-SELFSIGNED",
            "category": "self_signed_certificate",
            "classification": "Potential Risk",
            "severity": "medium",
            "mitre_technique": "T1592.004",
            "cwe_id": "CWE-295",
            "cvss_score": 5.9,
            "description": f"Host {profile.hostname} presents a self-signed certificate untrusted by public root stores.",
            "evidence": {"hostname": profile.hostname, "issuer": profile.issuer},
        })

    if profile.tls_version in ("TLSv1", "TLSv1.1"):
        findings.append({
            "rule_id": "TLS-PROTO-DEPRECATED",
            "category": "deprecated_tls_version",
            "classification": "Confirmed Vulnerability",
            "severity": "high",
            "mitre_technique": "T1592.004",
            "cwe_id": "CWE-326",
            "cvss_score": 7.4,
            "description": f"Host {profile.hostname} supports deprecated {profile.tls_version}, vulnerable to POODLE and BEAST cryptographic attacks.",
            "evidence": {"hostname": profile.hostname, "tls_version": profile.tls_version},
        })

    return findings
