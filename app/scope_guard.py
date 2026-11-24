"""Strict scope enforcement. All network-capable code must call this first."""
from __future__ import annotations

from fnmatch import fnmatchcase
from .schemas import ScopeConfig


def normalize(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def matches(pattern: str, hostname: str) -> bool:
    pattern, hostname = normalize(pattern), normalize(hostname)
    if pattern.startswith("*."):
        suffix = pattern[1:]  # preserves the requirement for one subdomain label
        return hostname.endswith(suffix) and hostname != suffix[1:]
    return fnmatchcase(hostname, pattern)


def allowed(hostname: str, scope: ScopeConfig) -> tuple[bool, str]:
    hostname = normalize(hostname)
    if not hostname or "." not in hostname:
        return False, "invalid hostname"
    if any(matches(pattern, hostname) for pattern in scope.excluded):
        return False, "explicitly excluded by scope"
    if not any(matches(pattern, hostname) for pattern in scope.allowed_domains):
        return False, "outside allowed domain patterns"
    return True, "in scope"
