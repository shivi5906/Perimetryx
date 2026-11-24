"""Deep DNS intelligence, record resolution, and email spoofing posture analyzer."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone


@dataclass
class HostDNSProfile:
    hostname: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    mx_records: list[dict] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    soa_record: str | None = None
    spf_record: str | None = None
    dmarc_record: str | None = None
    is_nxdomain: bool = False
    zone_transfer_vulnerable: bool = False
    vulnerable_nameservers: list[str] = field(default_factory=list)


async def resolve_dns_profile(hostname: str, timeout: float = 3.0) -> HostDNSProfile:
    """Resolve standard records and perform security hygiene inspection."""
    profile = HostDNSProfile(hostname=hostname)
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    # 1. A Records (IPv4)
    try:
        answers = await resolver.resolve(hostname, "A")
        profile.a_records = [str(rdata) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        profile.is_nxdomain = True
        return profile
    except (dns.resolver.NoAnswer, dns.exception.DNSException, OSError):
        pass

    # 2. AAAA Records (IPv6)
    try:
        answers = await resolver.resolve(hostname, "AAAA")
        profile.aaaa_records = [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.exception.DNSException, OSError):
        pass

    # 3. CNAME Records
    try:
        answers = await resolver.resolve(hostname, "CNAME")
        profile.cname_records = [str(rdata.target).rstrip(".") for rdata in answers]
    except (dns.resolver.NoAnswer, dns.exception.DNSException, OSError):
        pass

    # 4. MX Records
    try:
        answers = await resolver.resolve(hostname, "MX")
        profile.mx_records = [
            {"preference": rdata.preference, "exchange": str(rdata.exchange).rstrip(".")}
            for rdata in answers
        ]
    except (dns.resolver.NoAnswer, dns.exception.DNSException, OSError):
        pass

    # 5. TXT Records & SPF Detection
    try:
        answers = await resolver.resolve(hostname, "TXT")
        for rdata in answers:
            txt_val = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            profile.txt_records.append(txt_val)
            if txt_val.startswith("v=spf1"):
                profile.spf_record = txt_val
    except (dns.resolver.NoAnswer, dns.exception.DNSException, OSError):
        pass

    # 6. DMARC Record on _dmarc.<hostname>
    try:
        dmarc_answers = await resolver.resolve(f"_dmarc.{hostname}", "TXT")
        for rdata in dmarc_answers:
            txt_val = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            if txt_val.startswith("v=DMARC1"):
                profile.dmarc_record = txt_val
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException, OSError):
        pass

    # 7. NS Records
    try:
        answers = await resolver.resolve(hostname, "NS")
        profile.ns_records = [str(rdata.target).rstrip(".") for rdata in answers]
    except (dns.resolver.NoAnswer, dns.exception.DNSException, OSError):
        pass

    # 8. SOA Record
    try:
        answers = await resolver.resolve(hostname, "SOA")
        if answers:
            profile.soa_record = str(answers[0].mname).rstrip(".")
    except (dns.resolver.NoAnswer, dns.exception.DNSException, OSError):
        pass

    # 9. Safe AXFR (Zone Transfer) check on primary NS servers (if NS found)
    if profile.ns_records:
        for ns in profile.ns_records[:2]:  # Check up to 2 nameservers
            try:
                # Query IP of nameserver
                ns_ips = await resolver.resolve(ns, "A")
                for ns_ip in ns_ips:
                    try:
                        # Attempt safe AXFR test with 2 second timeout
                        xfr = dns.query.xfr(str(ns_ip), hostname, timeout=2.0, lifetime=2.0)
                        # Reading one message confirms whether AXFR was permitted
                        first_msg = next(xfr, None)
                        if first_msg and len(first_msg.answer) > 1:
                            profile.zone_transfer_vulnerable = True
                            profile.vulnerable_nameservers.append(ns)
                            break
                    except Exception:
                        pass
            except Exception:
                pass

    return profile


def evaluate_dns_hygiene(profile: HostDNSProfile, is_root_domain: bool = False) -> list[dict]:
    """Audit DNS hygiene, email spoofing posture, and zone transfer vulnerabilities."""
    findings = []

    # AXFR Zone Transfer check
    if profile.zone_transfer_vulnerable:
        findings.append({
            "rule_id": "DNS-AXFR-001",
            "category": "dns_zone_transfer",
            "classification": "Confirmed Vulnerability",
            "severity": "critical",
            "mitre_technique": "T1590.002",
            "cwe_id": "CWE-200",
            "cvss_score": 7.5,
            "description": f"Nameserver ({', '.join(profile.vulnerable_nameservers)}) allows unrestricted DNS Zone Transfer (AXFR), exposing internal DNS architecture.",
            "evidence": {
                "hostname": profile.hostname,
                "nameservers": profile.vulnerable_nameservers,
            },
        })

    # Email Posture (Only evaluated on root domain or hosts with MX records)
    if is_root_domain or profile.mx_records:
        # SPF Checks
        if not profile.spf_record:
            findings.append({
                "rule_id": "DNS-SPF-MISSING",
                "category": "missing_spf_record",
                "classification": "Potential Risk",
                "severity": "medium",
                "mitre_technique": "T1566",
                "cwe_id": "CWE-345",
                "cvss_score": 5.3,
                "description": f"Domain {profile.hostname} lacks an SPF record, allowing unauthorized actors to spoof emails from this domain.",
                "evidence": {"hostname": profile.hostname},
            })
        else:
            spf = profile.spf_record.lower()
            if "+all" in spf:
                findings.append({
                    "rule_id": "DNS-SPF-PERMISSIVE",
                    "category": "permissive_spf_all",
                    "classification": "Potential Risk",
                    "severity": "high",
                    "mitre_technique": "T1566",
                    "cwe_id": "CWE-290",
                    "cvss_score": 7.5,
                    "description": f"SPF record contains '+all', explicitly authorizing any server on the internet to send mail on behalf of {profile.hostname}.",
                    "evidence": {"hostname": profile.hostname, "spf": profile.spf_record},
                })
            elif "?all" in spf:
                findings.append({
                    "rule_id": "DNS-SPF-NEUTRAL",
                    "category": "neutral_spf_all",
                    "classification": "Observed",
                    "severity": "low",
                    "mitre_technique": "T1566",
                    "cwe_id": "CWE-345",
                    "cvss_score": 3.7,
                    "description": f"SPF record uses '?all' (neutral policy), which does not instruct receiving MTAs to reject spoofed mail.",
                    "evidence": {"hostname": profile.hostname, "spf": profile.spf_record},
                })

        # DMARC Checks
        if not profile.dmarc_record:
            findings.append({
                "rule_id": "DNS-DMARC-MISSING",
                "category": "missing_dmarc_policy",
                "classification": "Potential Risk",
                "severity": "medium",
                "mitre_technique": "T1566",
                "cwe_id": "CWE-345",
                "cvss_score": 5.3,
                "description": f"Domain {profile.hostname} lacks a DMARC policy record (_dmarc.{profile.hostname}), failing email spoofing prevention best practices.",
                "evidence": {"hostname": profile.hostname},
            })
        else:
            dmarc = profile.dmarc_record.lower()
            if "p=none" in dmarc:
                findings.append({
                    "rule_id": "DNS-DMARC-NONE",
                    "category": "dmarc_policy_none",
                    "classification": "Observed",
                    "severity": "low",
                    "mitre_technique": "T1566",
                    "cwe_id": "CWE-345",
                    "cvss_score": 3.7,
                    "description": "DMARC policy is set to 'p=none' (monitoring only). Receiving servers will not reject or quarantine unauthenticated emails.",
                    "evidence": {"hostname": profile.hostname, "dmarc": profile.dmarc_record},
                })

    return findings
