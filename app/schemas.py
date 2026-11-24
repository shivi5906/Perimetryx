from __future__ import annotations

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, field_validator


class ScopeConfig(BaseModel):
    domain: str
    authorization_basis: Literal["owned_asset", "bug_bounty_program", "signed_engagement_letter"]
    allowed_domains: list[str] = Field(min_length=1)
    excluded: list[str] = []
    active_verification: bool = False
    max_requests_per_second: float = Field(default=2, gt=0, le=20)
    max_concurrent_connections: int = Field(default=5, ge=1, le=25)
    allowed_ports: list[int] = [80, 443]
    user_agent: str = Field(min_length=12, max_length=250)

    @field_validator("domain", "allowed_domains", "excluded", mode="before")
    @classmethod
    def lowercase(cls, value):
        if isinstance(value, list):
            return [str(v).lower().rstrip(".") for v in value]
        return str(value).lower().rstrip(".")


class DomainCreate(BaseModel):
    root_domain: str
    scope: ScopeConfig


class ScanCreate(BaseModel):
    dry_run: bool = True


class AssetInput(BaseModel):
    hostname: str
    source: str = "manual"
    environment: Literal["prod", "staging", "dev", "unknown"] = "unknown"
    status_code: int | None = None
    title: str | None = None
    headers: dict[str, str] = {}
    cname: str | None = None


class FindingInput(BaseModel):
    rule_id: str
    category: str
    classification: Literal["Observed", "Potential Risk", "Needs Manual Verification"]
    description: str
    evidence: dict = {}


class CopilotQuestion(BaseModel):
    question: str = Field(min_length=3, max_length=1000)


class AuditEvent(BaseModel):
    at: datetime
    action: str
    target: str
    result: str
