"""Evidence-grounded AI Security Analyst and Reconnaissance Copilot."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

import httpx
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """You are Perimetryx AI, an expert Senior Cybersecurity Analyst & Attack Surface Intelligence specialist.
You operate strictly within ethical, authorized parameters.
Your responses must be strictly grounded in the provided factual scan evidence.
Rules:
1. NEVER invent vulnerabilities, ports, or technologies that do not exist in the evidence.
2. NEVER assign or overwrite numerical risk scores; explain deterministic scores using the cited findings.
3. Reference specific hostnames, CVE/CWE identifiers, and MITRE ATT&CK techniques when present in the evidence.
4. Categorize findings into: Observed, Potential Risk, or Needs Manual Verification.
5. Provide actionable, defensive remediation guidance for DevSecOps and AppSec teams.
"""


class AIProvider(ABC):
    name = "base"

    @abstractmethod
    async def answer(self, question: str, evidence: list[dict]) -> str: ...


class DeterministicProvider(AIProvider):
    name = "deterministic-analyst-v2"

    async def answer(self, question: str, evidence: list[dict]) -> str:
        if not evidence:
            return "No recorded attack surface evidence is available for this target."

        q_lower = question.lower()
        ranked = sorted(evidence, key=lambda item: item.get("score", 0), reverse=True)
        top = ranked[:5]

        # Check for specific inquiry intents
        if any(w in q_lower for w in ("priority", "top", "worst", "highest", "triage")):
            lines = [
                "### Priority Attack Surface Review (Grounded Evidence)",
                f"Evaluated {len(evidence)} assets. The following targets represent the highest attack surface exposure based on deterministic findings:\n",
            ]
            for idx, item in enumerate(top, 1):
                lines.append(
                    f"{idx}. **{item['hostname']}** (Risk Score: `{item.get('score', 0)}/100` | Band: `{item.get('band', 'N/A').upper()}`)"
                )
                if item.get("environment") in ("staging", "dev"):
                    lines.append(f"   - Environment: `{item['environment']}` exposure detected")
                if item.get("findings_count"):
                    lines.append(f"   - Findings count: `{item['findings_count']}` security signals")
            lines.append("\n**Remediation Recommendation**: Verify scope authorization before performing active tests. Ensure administrative endpoints enforce MFA and staging environments are restricted behind a VPN/SSO gateway.")
            return "\n".join(lines)

        if any(w in q_lower for w in ("summary", "executive", "overview", "ciso")):
            critical_count = sum(1 for e in evidence if e.get("score", 0) >= 75)
            high_count = sum(1 for e in evidence if 45 <= e.get("score", 0) < 75)
            medium_count = sum(1 for e in evidence if 20 <= e.get("score", 0) < 45)
            low_count = sum(1 for e in evidence if e.get("score", 0) < 20)

            return (
                f"### Executive Security Posture Summary\n\n"
                f"- **Total Attack Surface Assets**: `{len(evidence)}`\n"
                f"- **Severity Distribution**: `{critical_count}` Critical, `{high_count}` High, `{medium_count}` Medium, `{low_count}` Low\n"
                f"- **Primary Threat Vectors**: Exposure of non-production environments and absence of modern defense-in-depth headers (HSTS, CSP).\n"
                f"- **Immediate Action**: Address high-risk asset `{top[0]['hostname']}` (Score: {top[0].get('score', 0)}) to reduce immediate perimeter exploitability."
            )

        # General inquiry fallback with grounding
        citations_str = ", ".join(f"`{item['hostname']}` (Score: {item.get('score', 0)})" for item in top[:3])
        return (
            f"Based on stored reconnaissance telemetry, the primary targets requiring review are: {citations_str}.\n\n"
            f"**Evidence Assessment**: Deterministic scoring identified elevated exposure. "
            f"Manual verification using approved test accounts is required before filing vulnerability reports."
        )


class OpenAICompatibleProvider(AIProvider):
    def __init__(self, name: str, base_url: str, api_key: str, model: str):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    async def answer(self, question: str, evidence: list[dict]) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"User Security Question: {question}\n\nTarget Evidence Dataset:\n{evidence}",
                },
            ],
            "temperature": 0.1,
            "max_tokens": 800,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        async with httpx.AsyncClient(timeout=25.0) as client:
            response = await client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]


def provider() -> AIProvider:
    choice = os.getenv("PERIMETRYX_AI_PROVIDER", "deterministic").lower()
    if choice == "groq" and os.getenv("GROQ_API_KEY"):
        return OpenAICompatibleProvider(
            "groq",
            "https://api.groq.com/openai/v1",
            os.environ["GROQ_API_KEY"],
            os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        )
    if choice == "openai" and os.getenv("OPENAI_API_KEY"):
        return OpenAICompatibleProvider(
            "openai",
            "https://api.openai.com/v1",
            os.environ["OPENAI_API_KEY"],
            os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        )
    if choice == "ollama":
        return OpenAICompatibleProvider(
            "ollama",
            os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
            os.getenv("OLLAMA_API_KEY", ""),
            os.getenv("OLLAMA_MODEL", "llama3.2"),
        )
    return DeterministicProvider()
