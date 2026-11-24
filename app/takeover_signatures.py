"""Signatures for Subdomain Takeover and Dangling CNAME detection.

Covers major cloud providers, SaaS platforms, and hosting services.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class TakeoverSignature:
    service: str
    cname_patterns: tuple[str, ...]
    fingerprints: tuple[str, ...]
    nxdomain_vulnerable: bool
    severity: str = "critical"


TAKEOVER_SIGNATURES: list[TakeoverSignature] = [
    TakeoverSignature(
        service="AWS S3",
        cname_patterns=("s3.amazonaws.com", "s3-website", "s3.dualstack"),
        fingerprints=(
            "The specified bucket does not exist",
            "NoSuchBucket",
            "Website-Access-Denied",
        ),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="GitHub Pages",
        cname_patterns=("github.io", "github.map.fastly.net"),
        fingerprints=(
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="Heroku",
        cname_patterns=("herokuapp.com", "herokussl.com", "herokudns.com"),
        fingerprints=(
            "Heroku | No such app",
            "no-such-app.html",
            "<title>No such app</title>",
        ),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="Azure App Service / Traffic Manager",
        cname_patterns=("azurewebsites.net", "trafficmanager.net", "cloudapp.net", "azureedge.net"),
        fingerprints=(
            "404 Web Site not found",
            "You've arrived at this page because there is no application",
        ),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="Shopify",
        cname_patterns=("myshopify.com",),
        fingerprints=(
            "Sorry, this shop is currently unavailable",
            "Only one step left to start selling",
        ),
        nxdomain_vulnerable=False,
    ),
    TakeoverSignature(
        service="Surge.sh",
        cname_patterns=("surge.sh",),
        fingerprints=("project not found",),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="WordPress.com",
        cname_patterns=("wordpress.com",),
        fingerprints=("Do you want to register",),
        nxdomain_vulnerable=False,
    ),
    TakeoverSignature(
        service="Zendesk",
        cname_patterns=("zendesk.com",),
        fingerprints=("Help Center Closed",),
        nxdomain_vulnerable=False,
    ),
    TakeoverSignature(
        service="Fastly",
        cname_patterns=("fastly.net",),
        fingerprints=("Fastly error: unknown domain",),
        nxdomain_vulnerable=False,
    ),
    TakeoverSignature(
        service="Fly.io",
        cname_patterns=("fly.dev",),
        fingerprints=("404 Not Found", "Could not find app"),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="Netlify",
        cname_patterns=("netlify.app", "netlify.com"),
        fingerprints=("Not Found - Request ID",),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="Bitbucket",
        cname_patterns=("bitbucket.io",),
        fingerprints=("Repository not found",),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="Ghost",
        cname_patterns=("ghost.io",),
        fingerprints=("The thing you were looking for is no longer here",),
        nxdomain_vulnerable=False,
    ),
    TakeoverSignature(
        service="Readme.io",
        cname_patterns=("readme.io",),
        fingerprints=("Project doesnt exist",),
        nxdomain_vulnerable=True,
    ),
    TakeoverSignature(
        service="Tumblr",
        cname_patterns=("domains.tumblr.com",),
        fingerprints=("Whatever you were looking for doesn't seem to exist",),
        nxdomain_vulnerable=False,
    ),
]


def check_takeover_risk(
    cname: str | None,
    http_body: str | None = None,
    is_nxdomain: bool = False,
) -> dict | None:
    """Analyze CNAME target and HTTP response for subdomain takeover vulnerability."""
    if not cname:
        return None

    cname_lower = cname.lower()
    for sig in TAKEOVER_SIGNATURES:
        pattern_match = any(pattern in cname_lower for pattern in sig.cname_patterns)
        if not pattern_match:
            continue

        # If CNAME points to service and domain returns NXDOMAIN
        if is_nxdomain and sig.nxdomain_vulnerable:
            return {
                "service": sig.service,
                "cname": cname,
                "confidence": "high",
                "severity": "critical",
                "reason": f"Dangling CNAME points to {sig.service} ({cname}) with unresolvable DNS (NXDOMAIN). Host can be registered by an attacker.",
            }

        # If HTTP body matches known orphaned asset fingerprint
        if http_body:
            body_match = any(fp.lower() in http_body.lower() for fp in sig.fingerprints)
            if body_match:
                return {
                    "service": sig.service,
                    "cname": cname,
                    "confidence": "high",
                    "severity": "critical",
                    "reason": f"Active HTTP response on {cname} matches orphaned {sig.service} signature. Immediate verification advised.",
                }

        # Matched CNAME pattern without confirmed body signature (Potential Risk)
        return {
            "service": sig.service,
            "cname": cname,
            "confidence": "medium",
            "severity": "high",
            "reason": f"CNAME aliases known SaaS provider {sig.service} ({cname}). Review whether tenant configuration is active.",
        }

    return None
