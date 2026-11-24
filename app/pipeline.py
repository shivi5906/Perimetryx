"""Passive, scope-gated collection and attack-surface analysis pipeline.

Limits collection to authorized public sources, safe DNS resolution,
and lightweight passive observations of explicitly allowed hostnames.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

import httpx

from .analysis import classify_environment
from .dns_engine import HostDNSProfile, resolve_dns_profile
from .fingerprint import detect_technologies
from .schemas import ScopeConfig
from .scope_guard import allowed, normalize
from .tls_engine import TLSProfile, inspect_tls

TITLE_PATTERN = re.compile(r"<title[^>]*>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
SAFE_HEADERS = {
    "server",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "content-type",
    "location",
    "via",
    "referrer-policy",
    "permissions-policy",
    "x-powered-by",
    "set-cookie",
}


@dataclass
class Observation:
    hostname: str
    source: str
    environment: str
    status_code: int | None
    title: str | None
    headers: dict[str, str]
    addresses: list[str]
    scheme: str | None
    cname: str | None = None
    response_time_ms: float = 0.0
    technologies: list[dict] = field(default_factory=list)
    dns_profile: HostDNSProfile | None = None
    tls_profile: TLSProfile | None = None
    body_preview: str = ""


class RateLimiter:
    def __init__(self, requests_per_second: float):
        self._interval = 1 / max(requests_per_second, 0.1)
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def wait(self) -> None:
        loop = asyncio.get_running_loop()
        async with self._lock:
            delay = self._interval - (loop.time() - self._last_request)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request = loop.time()


async def discover_certificate_transparency(domain: str, scope: ScopeConfig, limiter: RateLimiter) -> set[str]:
    """Read crt.sh entries; passive log search only."""
    await limiter.wait()
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"User-Agent": scope.user_agent}
    names: set[str] = {domain}

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.get(url, params=params, headers=headers)
            if response.status_code == 200:
                for entry in response.json():
                    for name in str(entry.get("name_value", "")).splitlines():
                        candidate = normalize(name.removeprefix("*."))
                        if candidate and allowed(candidate, scope)[0]:
                            names.add(candidate)
    except Exception:
        # Fallback to base domain if external log service is unreachable or rate-limited
        pass

    return names


async def resolve_host(hostname: str) -> list[str]:
    """Resolve IPv4/IPv6 addresses via asyncio getaddrinfo."""
    try:
        records = await asyncio.get_running_loop().getaddrinfo(hostname, None, type=0)
    except OSError:
        return []
    return sorted({record[4][0] for record in records})


def response_title(content: bytes) -> str | None:
    document = content.decode("utf-8", errors="replace")
    match = TITLE_PATTERN.search(document)
    if not match:
        return None
    return " ".join(match.group(1).split())[:240] or None


async def observe_http(
    hostname: str,
    addresses: list[str],
    scope: ScopeConfig,
    limiter: RateLimiter,
    dns_profile: HostDNSProfile | None = None,
) -> Observation:
    headers: dict[str, str] = {}
    cname_target = dns_profile.cname_records[0] if (dns_profile and dns_profile.cname_records) else None

    # Inspect TLS if port 443 is permitted
    tls_profile: TLSProfile | None = None
    if 443 in scope.allowed_ports:
        try:
            tls_profile = await inspect_tls(hostname, port=443, timeout=3.0)
        except Exception:
            tls_profile = None

    for scheme, port in (("https", 443), ("http", 80)):
        if port not in scope.allowed_ports:
            continue
        try:
            await limiter.wait()
            start_t = time.perf_counter()
            async with httpx.AsyncClient(
                timeout=8.0,
                follow_redirects=False,
                verify=False,
                headers={"User-Agent": scope.user_agent, "Accept": "text/html,application/xhtml+xml"},
            ) as client:
                async with client.stream("GET", f"{scheme}://{hostname}/") as response:
                    content = b""
                    async for chunk in response.aiter_bytes():
                        content += chunk
                        if len(content) >= 65_536:
                            break
                    elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
                    headers = {
                        key.lower(): value for key, value in response.headers.items() if key.lower() in SAFE_HEADERS
                    }
                    headers["x-perimetryx-scheme"] = scheme
                    headers["x-perimetryx-addresses"] = ",".join(addresses)

                    body_str = content.decode("utf-8", errors="replace")
                    techs = detect_technologies(headers, body_str)

                    return Observation(
                        hostname=hostname,
                        source="ct-log",
                        environment=classify_environment(hostname),
                        status_code=response.status_code,
                        title=response_title(content),
                        headers=headers,
                        addresses=addresses,
                        scheme=scheme,
                        cname=cname_target,
                        response_time_ms=elapsed_ms,
                        technologies=techs,
                        dns_profile=dns_profile,
                        tls_profile=tls_profile,
                        body_preview=body_str[:1000],
                    )
        except (httpx.HTTPError, OSError):
            continue

    return Observation(
        hostname=hostname,
        source="ct-log",
        environment=classify_environment(hostname),
        status_code=None,
        title=None,
        headers={"x-perimetryx-addresses": ",".join(addresses)},
        addresses=addresses,
        scheme=None,
        cname=cname_target,
        dns_profile=dns_profile,
        tls_profile=tls_profile,
    )


async def collect(domain: str, scope: ScopeConfig) -> Iterable[Observation]:
    limiter = RateLimiter(scope.max_requests_per_second)
    discovered = await discover_certificate_transparency(domain, scope, limiter)
    semaphore = asyncio.Semaphore(scope.max_concurrent_connections)

    async def collect_one(hostname: str) -> Observation:
        async with semaphore:
            # 1. Resolve deep DNS profile
            try:
                dns_prof = await resolve_dns_profile(hostname, timeout=3.0)
            except Exception:
                dns_prof = HostDNSProfile(hostname=hostname)

            # 2. Get IP addresses
            addresses = sorted(set(dns_prof.a_records + dns_prof.aaaa_records))
            if not addresses:
                addresses = await resolve_host(hostname)

            # 3. HTTP and tech observation
            return await observe_http(hostname, addresses, scope, limiter, dns_prof)

    return await asyncio.gather(*(collect_one(hostname) for hostname in sorted(discovered)))
