import argparse

from fastapi.testclient import TestClient

from app import store
from app.analysis import classify_environment, findings_for_observation
from app.cli import create_scope
from app.guidance import priority_plan
from app.main import app
from app.schemas import ScopeConfig
from app.scope_guard import allowed
from app.scoring import score


def scope():
    return ScopeConfig(
        domain="example.com",
        authorization_basis="owned_asset",
        allowed_domains=["example.com", "*.example.com"],
        excluded=["payments.example.com"],
        user_agent="Perimetryx/2.0 test",
    )


def test_subdomains_require_an_explicit_wildcard():
    assert allowed("api.example.com", scope())[0]
    assert not allowed("other-example.com", scope())[0]


def test_exclusions_win_over_allowed_patterns():
    assert allowed("payments.example.com", scope()) == (False, "explicitly excluded by scope")


def test_score_is_explainable_and_capped():
    total, band, breakdown = score([{"category": "dangling_cname_indicator"}] * 5, "staging")
    assert total == 100 and band == "critical" and breakdown["exposure"] == 150


def test_observed_headers_and_environment_produce_deterministic_findings():
    findings = findings_for_observation("staging.example.com", "https", 200, {})
    categories = {finding["category"] for finding in findings}
    assert classify_environment("staging.example.com") == "staging"
    assert "staging_exposed" in categories
    assert "missing_security_header" in categories


def test_dry_run_completes_without_external_collection(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "perimetryx.db")
    body = {
        "root_domain": "demo.example.com",
        "scope": {
            "domain": "demo.example.com",
            "authorization_basis": "owned_asset",
            "allowed_domains": ["demo.example.com", "*.demo.example.com"],
            "excluded": [],
            "active_verification": False,
            "max_requests_per_second": 2,
            "max_concurrent_connections": 5,
            "allowed_ports": [80, 443],
            "user_agent": "Perimetryx/2.0 integration",
        },
    }
    with TestClient(app) as client:
        domain = client.post("/api/domains", json=body).json()
        scan = client.post(
            f"/api/domains/{domain['id']}/scans",
            json={"dry_run": True, "confirmed_authorization": False},
        ).json()
        result = client.get(f"/api/scans/{scan['id']}").json()
    assert result["status"] == "completed"


def test_cli_scope_defaults_to_exact_domain_only(tmp_path):
    output = tmp_path / "scope.yaml"
    result = create_scope(
        argparse.Namespace(
            domain="demo.example.com",
            authorization="owned_asset",
            output=str(output),
            force=False,
        )
    )
    assert result == 0
    assert "*.demo.example.com" not in output.read_text(encoding="utf-8")


def test_priority_plan_provides_safe_checks():
    plan = priority_plan(
        [{"id": 1, "hostname": "staging.example.com", "total": 35}],
        [
            {
                "asset_id": 1,
                "category": "staging_exposed",
                "classification": "Potential Risk",
                "description": "Staging host responded.",
                "evidence": {"status": 200},
            }
        ],
    )
    assert plan[0]["priority"] == "High"
    assert "brute force" not in " ".join(plan[0]["safe_checks"]).lower()
