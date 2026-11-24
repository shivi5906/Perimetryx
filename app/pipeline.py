"""Passive, scope-gated collection pipeline.

The pipeline deliberately limits collection to public CT records, standard DNS
resolution, and one request to the root of each explicitly allowed hostname.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from dataclasses import dataclass

import httpx

from .analysis import classify_environment
from .schemas import ScopeConfig
from .scope_guard import allowed, normalize

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


class RateLimiter:
    def __init__(self, requests_per_second: float):
        self._interval = 1 / requests_per_second
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
    """Read crt.sh entries only; no active target request occurs in this stage."""
    await limiter.wait()
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"User-Agent": scope.user_agent}
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
        response = await client.get(url, params=params, headers=headers)
        response.raise_for_status()
    names: set[str] = {domain}
    for entry in response.json():
        for name in str(entry.get("name_value", "")).splitlines():
            candidate = normalize(name.removeprefix("*."))
            if allowed(candidate, scope)[0]:
                names.add(candidate)
    return names


async def resolve_host(hostname: str) -> list[str]:
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
) -> Observation:
    headers: dict[str, str] = {}
    for scheme, port in (("https", 443), ("http", 80)):
        if port not in scope.allowed_ports:
            continue
        try:
            await limiter.wait()
            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=False,
                headers={"User-Agent": scope.user_agent, "Accept": "text/html,application/xhtml+xml"},
            ) as client:
                async with client.stream("GET", f"{scheme}://{hostname}/") as response:
                    content = b""
                    async for chunk in response.aiter_bytes():
                        content += chunk
                        if len(content) >= 65_536:
                            break
                    headers = {
                        key.lower(): value for key, value in response.headers.items() if key.lower() in SAFE_HEADERS
                    }
                    headers["x-perimetryx-scheme"] = scheme
                    headers["x-perimetryx-addresses"] = ",".join(addresses)
                    return Observation(
                        hostname=hostname,
                        source="ct-log",
                        environment=classify_environment(hostname),
                        status_code=response.status_code,
                        title=response_title(content),
                        headers=headers,
                        addresses=addresses,
                        scheme=scheme,
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
    )


async def collect(domain: str, scope: ScopeConfig) -> Iterable[Observation]:
    limiter = RateLimiter(scope.max_requests_per_second)
    discovered = await discover_certificate_transparency(domain, scope, limiter)
    semaphore = asyncio.Semaphore(scope.max_concurrent_connections)

    async def collect_one(hostname: str) -> Observation:
        async with semaphore:
            addresses = await resolve_host(hostname)
            return await observe_http(hostname, addresses, scope, limiter)

    return await asyncio.gather(*(collect_one(hostname) for hostname in sorted(discovered)))
