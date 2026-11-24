"""Web technology signature engine and exposed sensitive surface detector."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TechSignature:
    name: str
    category: str
    header_patterns: dict[str, str] = None
    cookie_patterns: tuple[str, ...] = ()
    body_patterns: tuple[str, ...] = ()
    confidence: int = 100


TECH_DATABASE: list[TechSignature] = [
    # Web Servers
    TechSignature("Nginx", "Web Server", header_patterns={"server": r"nginx(?:/([\d.]+))?"}),
    TechSignature("Apache HTTP Server", "Web Server", header_patterns={"server": r"apache(?:/([\d.]+))?"}),
    TechSignature("Microsoft-IIS", "Web Server", header_patterns={"server": r"microsoft-iis(?:/([\d.]+))?"}),
    TechSignature("Caddy", "Web Server", header_patterns={"server": r"caddy"}),
    TechSignature("Cloudflare", "CDN / Reverse Proxy", header_patterns={"server": r"cloudflare", "cf-ray": r"."}),
    TechSignature("Envoy", "Proxy", header_patterns={"server": r"envoy"}),
    TechSignature("LiteSpeed", "Web Server", header_patterns={"server": r"litespeed"}),
    TechSignature("Uvicorn / FastAPI", "ASGI Server", header_patterns={"server": r"uvicorn"}),
    TechSignature("Gunicorn", "WSGI Server", header_patterns={"server": r"gunicorn"}),

    # Backend Frameworks
    TechSignature("PHP", "Programming Language", header_patterns={"x-powered-by": r"php(?:/([\d.]+))?"}, cookie_patterns=("phpsessid",)),
    TechSignature("ASP.NET", "Web Framework", header_patterns={"x-powered-by": r"asp\.net", "x-aspnet-version": r"."}, cookie_patterns=("aspsessionid", "asp.net_sessionid")),
    TechSignature("Express.js", "Web Framework", header_patterns={"x-powered-by": r"express"}),
    TechSignature("Next.js", "Fullstack Framework", header_patterns={"x-powered-by": r"next\.js"}, body_patterns=(r"__NEXT_DATA__", r"/_next/static/")),
    TechSignature("Nuxt.js", "Fullstack Framework", body_patterns=(r"__NUXT__", r"/_nuxt/")),
    TechSignature("Django", "Web Framework", cookie_patterns=("csrftoken", "django_language"), body_patterns=(r"csrfmiddlewaretoken",)),
    TechSignature("Laravel", "Web Framework", cookie_patterns=("laravel_session", "XSRF-TOKEN")),
    TechSignature("Ruby on Rails", "Web Framework", header_patterns={"x-powered-by": r"phusion_passenger"}, cookie_patterns=("_session_id",)),
    TechSignature("Spring Boot / Java", "Enterprise Framework", cookie_patterns=("jsessionid",), body_patterns=(r"Whitelabel Error Page", r"/actuator/")),

    # Frontend Libraries
    TechSignature("React", "JavaScript Library", body_patterns=(r"data-reactroot", r"_reactListening", r"react\.production\.min\.js")),
    TechSignature("Vue.js", "JavaScript Framework", body_patterns=(r"data-v-[a-f0-9]+", r"vue\.global\.js", r"vue\.runtime")),
    TechSignature("Angular", "JavaScript Framework", body_patterns=(r"ng-version=", r"ng-app=")),
    TechSignature("jQuery", "JavaScript Library", body_patterns=(r"jquery(?:-([\d.]+))?\.min\.js", r"\$\(document\)\.ready")),
    TechSignature("Tailwind CSS", "CSS Framework", body_patterns=(r"text-gray-", r"bg-slate-", r"flex flex-col")),
    TechSignature("Bootstrap", "CSS Framework", body_patterns=(r"class=[\"'][^\"']*btn-(?:primary|danger|success)", r"bootstrap(?:\.bundle)?\.min\.js")),

    # CMS & Platforms
    TechSignature("WordPress", "CMS", header_patterns={"x-powered-by": r"wordpress"}, body_patterns=(r"/wp-content/", r"/wp-includes/", r"name=[\"']generator[\"'] content=[\"']WordPress")),
    TechSignature("Drupal", "CMS", header_patterns={"x-generator": r"drupal", "x-drupal-cache": r"."}),
    TechSignature("Joomla", "CMS", header_patterns={"x-content-encoded-by": r"joomla"}),
    TechSignature("Shopify", "E-Commerce", header_patterns={"x-shopify-stage": r"."}, body_patterns=(r"cdn\.shopify\.com",)),
    TechSignature("Ghost", "Publishing", header_patterns={"x-ghost-cache-status": r"."}),

    # Cloud & CDN
    TechSignature("AWS CloudFront", "CDN", header_patterns={"via": r"cloudfront", "x-amz-cf-id": r"."}),
    TechSignature("Fastly", "CDN", header_patterns={"x-fastly-request-id": r"."}),
    TechSignature("Vercel", "Hosting Platform", header_patterns={"x-vercel-id": r"."}),
    TechSignature("Netlify", "Hosting Platform", header_patterns={"server": r"netlify"}),

    # Developer & Internal Portals
    TechSignature("Swagger / OpenAPI", "API Documentation", body_patterns=(r"swagger-ui", r"/swagger-resources", r"Swagger UI", r"openapi\.json")),
    TechSignature("GraphQL", "API Engine", body_patterns=(r"GraphQL Playground", r"\"__schema\"", r"/graphql")),
    TechSignature("Grafana", "Monitoring Dashboard", body_patterns=(r"Grafana", r"window\.grafanaBootData")),
    TechSignature("Prometheus", "Metrics", body_patterns=(r"# HELP", r"# TYPE", r"process_cpu_seconds_total")),
]


def detect_technologies(
    headers: dict[str, str],
    body: str = "",
    cookies: list[str] = None,
) -> list[dict]:
    """Inspect headers, body snippets, and cookies to identify technologies."""
    detected = []
    norm_headers = {k.lower(): str(v) for k, v in headers.items()}
    norm_body = body or ""
    all_cookie_names = [c.lower() for c in (cookies or [])]

    # Also parse cookies from Set-Cookie header if present
    set_cookie = norm_headers.get("set-cookie", "")
    if set_cookie:
        for part in set_cookie.split(";"):
            if "=" in part:
                cookie_name = part.split("=")[0].strip().lower()
                all_cookie_names.append(cookie_name)

    for sig in TECH_DATABASE:
        matched = False
        version = None

        # Check headers
        if sig.header_patterns:
            for header_name, pattern in sig.header_patterns.items():
                if header_name in norm_headers:
                    val = norm_headers[header_name]
                    match = re.search(pattern, val, re.IGNORECASE)
                    if match:
                        matched = True
                        if match.groups() and match.group(1):
                            version = match.group(1)
                        break

        # Check cookies
        if not matched and sig.cookie_patterns:
            for cookie_target in sig.cookie_patterns:
                if any(cookie_target in c for c in all_cookie_names):
                    matched = True
                    break

        # Check body patterns
        if not matched and sig.body_patterns and norm_body:
            for body_pat in sig.body_patterns:
                match = re.search(body_pat, norm_body, re.IGNORECASE)
                if match:
                    matched = True
                    if match.groups() and match.group(1):
                        version = match.group(1)
                    break

        if matched:
            detected.append({
                "name": sig.name,
                "category": sig.category,
                "version": version,
                "confidence": sig.confidence,
            })

    return detected


def detect_sensitive_surfaces(
    hostname: str,
    title: str | None,
    technologies: list[dict],
    status_code: int | None,
) -> list[dict]:
    """Detect exposed administrative panels, API specs, and debug consoles."""
    findings = []
    host_parts = hostname.lower().split(".")
    title_str = (title or "").lower()
    tech_names = {t["name"] for t in technologies}

    # 1. API Documentation Exposure (Swagger / OpenAPI / GraphQL)
    if "Swagger / OpenAPI" in tech_names or "swagger" in title_str or "openapi" in title_str:
        findings.append({
            "rule_id": "EXPOSE-API-DOCS",
            "category": "exposed_api_documentation",
            "classification": "Potential Risk",
            "severity": "medium",
            "mitre_technique": "T1592.002",
            "cwe_id": "CWE-200",
            "cvss_score": 5.3,
            "description": f"Host {hostname} exposes interactive Swagger/OpenAPI documentation. Provides attackers with full endpoint parameters and auth schemes.",
            "evidence": {"hostname": hostname, "title": title, "status_code": status_code},
        })

    if "GraphQL" in tech_names:
        findings.append({
            "rule_id": "EXPOSE-GRAPHQL",
            "category": "exposed_graphql_endpoint",
            "classification": "Needs Manual Verification",
            "severity": "medium",
            "mitre_technique": "T1190",
            "cwe_id": "CWE-200",
            "cvss_score": 5.0,
            "description": f"GraphQL service detected on {hostname}. Verify whether schema introspection and query batching limits are enforced.",
            "evidence": {"hostname": hostname},
        })

    # 2. Monitoring & Metrics Exposure (Prometheus / Actuator / Grafana)
    if "Prometheus" in tech_names:
        findings.append({
            "rule_id": "EXPOSE-METRICS-PROMETHEUS",
            "category": "exposed_metrics_endpoint",
            "classification": "Confirmed Vulnerability",
            "severity": "high",
            "mitre_technique": "T1592.002",
            "cwe_id": "CWE-200",
            "cvss_score": 7.1,
            "description": f"Prometheus telemetry metric endpoint exposed publicly on {hostname}, leaking server internal memory, process names, and network stats.",
            "evidence": {"hostname": hostname, "title": title},
        })

    if "Grafana" in tech_names:
        findings.append({
            "rule_id": "EXPOSE-MONITORING-GRAFANA",
            "category": "exposed_monitoring_dashboard",
            "classification": "Potential Risk",
            "severity": "medium",
            "mitre_technique": "T1592",
            "cwe_id": "CWE-16",
            "cvss_score": 5.3,
            "description": f"Grafana instance exposed on {hostname}. Verify that default credentials (admin/admin) are changed and anonymous access is disabled.",
            "evidence": {"hostname": hostname, "title": title},
        })

    # 3. Administrative Interface Signals
    admin_keywords = {"admin", "administrator", "manage", "portal", "dashboard", "control", "kibana", "cpanel"}
    if any(k in host_parts for k in admin_keywords) or any(k in title_str for k in ("admin login", "control panel", "phpmyadmin", "sign in to admin")):
        findings.append({
            "rule_id": "SURFACE-ADMIN-001",
            "category": "admin_surface",
            "classification": "Needs Manual Verification",
            "severity": "medium",
            "mitre_technique": "T1078",
            "cwe_id": "CWE-200",
            "cvss_score": 4.8,
            "description": f"Administrative or internal control interface surface suggested by hostname or title on {hostname}.",
            "evidence": {"hostname": hostname, "title": title, "status_code": status_code},
        })

    return findings
