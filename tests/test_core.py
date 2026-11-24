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
