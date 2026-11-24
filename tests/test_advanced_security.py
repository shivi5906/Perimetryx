"""Comprehensive test suite for Perimetryx's Advanced Security & Threat Engine."""

import pytest

from app.ai import DeterministicProvider
from app.analysis import findings_for_observation
from app.diff import calculate_scan_diff
from app.dns_engine import HostDNSProfile, evaluate_dns_hygiene
from app.fingerprint import detect_sensitive_surfaces, detect_technologies
from app.graph import build_attack_surface_graph
from app.reporting import generate_html_report, generate_markdown_report
from app.store import db, init
from app.takeover_signatures import check_takeover_risk
from app.tls_engine import TLSProfile, evaluate_tls_hygiene
import datetime


def test_subdomain_takeover_detection_s3():
    # Test AWS S3 bucket missing response
    result = check_takeover_risk("bucket.s3.amazonaws.com", "The specified bucket does not exist", False)
    assert result is not None
    assert result["service"] == "AWS S3"
    assert result["severity"] == "critical"
    assert result["confidence"] == "high"


def test_subdomain_takeover_detection_github_pages_nxdomain():
    # Test GitHub Pages CNAME with NXDOMAIN
    result = check_takeover_risk("myorg.github.io", None, is_nxdomain=True)
    assert result is not None
    assert result["service"] == "GitHub Pages"
    assert result["severity"] == "critical"


def test_dns_spf_and_dmarc_evaluation():
    # Permissive SPF (+all)
    profile = HostDNSProfile(
        hostname="example.com",
        spf_record="v=spf1 +all",
        dmarc_record="v=DMARC1; p=none;",
    )
    findings = evaluate_dns_hygiene(profile, is_root_domain=True)
    categories = {f["category"] for f in findings}

    assert "permissive_spf_all" in categories
    assert "dmarc_policy_none" in categories

    spf_finding = next(f for f in findings if f["category"] == "permissive_spf_all")
    assert spf_finding["severity"] == "high"
    assert spf_finding["mitre_technique"] == "T1566"


def test_dns_axfr_zone_transfer():
    profile = HostDNSProfile(
        hostname="example.com",
        zone_transfer_vulnerable=True,
        vulnerable_nameservers=["ns1.example.com"],
    )
    findings = evaluate_dns_hygiene(profile, is_root_domain=True)
    axfr = next(f for f in findings if f["category"] == "dns_zone_transfer")
    assert axfr["severity"] == "critical"
    assert axfr["classification"] == "Confirmed Vulnerability"


def test_technology_fingerprinting():
    headers = {
        "server": "nginx/1.24.0",
        "x-powered-by": "Next.js",
        "set-cookie": "csrftoken=xyz123; Path=/",
    }
    body = "<html><head><script src='/_next/static/chunks/main.js'></script></head><body><div data-reactroot=''>App</div></body></html>"

    techs = detect_technologies(headers, body)
    names = {t["name"] for t in techs}

    assert "Nginx" in names
    assert "Next.js" in names
    assert "React" in names
    assert "Django" in names  # Detected from csrftoken cookie


def test_sensitive_surfaces_swagger_and_prometheus():
    techs = [{"name": "Swagger / OpenAPI", "category": "API Documentation"}, {"name": "Prometheus", "category": "Metrics"}]
    findings = detect_sensitive_surfaces("api.example.com", "API Documentation", techs, 200)
    categories = {f["category"] for f in findings}

    assert "exposed_api_documentation" in categories
    assert "exposed_metrics_endpoint" in categories


def test_tls_certificate_evaluation():
    # Expired cert
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_profile = TLSProfile(
        hostname="secure.example.com",
        not_after=now - datetime.timedelta(days=5),
        days_left=-5,
        expired=True,
        issuer="Let's Encrypt",
    )
    findings = evaluate_tls_hygiene(expired_profile)
    assert any(f["category"] == "expired_tls_certificate" for f in findings)


def test_deterministic_ai_analyst_prioritization():
    import asyncio
    provider = DeterministicProvider()
    evidence = [
        {"id": 1, "hostname": "staging.example.com", "score": 85, "band": "critical", "environment": "staging"},
        {"id": 2, "hostname": "api.example.com", "score": 30, "band": "medium", "environment": "prod"},
    ]
    answer = asyncio.run(provider.answer("What are my top priorities?", evidence))
    assert "staging.example.com" in answer
    assert "85/100" in answer
    assert "CRITICAL" in answer


def test_graph_and_diff_modules(tmp_path, monkeypatch):
    from app import store
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "test_graph.db")
    init()

    with db() as conn:
        did = conn.execute("INSERT INTO domains(root_domain, scope_json, created_at) VALUES ('target.com', '{}', 'now')").lastrowid
        s1 = conn.execute("INSERT INTO scans(domain_id, status, dry_run, started_at) VALUES (?, 'completed', 0, 'now')", (did,)).lastrowid
        s2 = conn.execute("INSERT INTO scans(domain_id, status, dry_run, started_at) VALUES (?, 'completed', 0, 'now')", (did,)).lastrowid

        # Asset 1 in scan 1 and 2
        a1 = conn.execute("INSERT INTO assets(domain_id, hostname, source, environment) VALUES (?, 'admin.target.com', 'ct', 'prod')", (did,)).lastrowid
        conn.execute("INSERT INTO scan_assets(scan_id, asset_id, status) VALUES (?, ?, 'new')", (s1, a1))
        conn.execute("INSERT INTO scan_assets(scan_id, asset_id, status) VALUES (?, ?, 'persisted')", (s2, a1))
        conn.execute("INSERT INTO risk_scores(scan_id, asset_id, total, band, breakdown_json) VALUES (?, ?, 75, 'critical', '{}')", (s1, a1))
        conn.execute("INSERT INTO risk_scores(scan_id, asset_id, total, band, breakdown_json) VALUES (?, ?, 75, 'critical', '{}')", (s2, a1))

        # Asset 2 new in scan 2
        a2 = conn.execute("INSERT INTO assets(domain_id, hostname, source, environment) VALUES (?, 'dev.target.com', 'ct', 'dev')", (did,)).lastrowid
        conn.execute("INSERT INTO scan_assets(scan_id, asset_id, status) VALUES (?, ?, 'new')", (s2, a2))
        conn.execute("INSERT INTO risk_scores(scan_id, asset_id, total, band, breakdown_json) VALUES (?, ?, 50, 'high', '{}')", (s2, a2))

    # Test Graph Builder
    graph = build_attack_surface_graph(s1)
    assert graph["root_domain"] == "target.com"
    assert len(graph["nodes"]) >= 2
    assert any(n["label"] == "admin.target.com" for n in graph["nodes"])

    # Test Comparative Diff
    diff = calculate_scan_diff(s1, s2)
    assert len(diff["new_assets"]) == 1
    assert diff["new_assets"][0]["hostname"] == "dev.target.com"
    assert diff["persisted_assets_count"] == 1

    # Test Report Generation
    md_report = generate_markdown_report(s2)
    assert "# Attack Surface Security Assessment Report: target.com" in md_report
    assert "admin.target.com" in md_report
    assert "dev.target.com" in md_report

    html_report = generate_html_report(s2)
    assert "<!DOCTYPE html>" in html_report
    assert "target.com" in html_report
