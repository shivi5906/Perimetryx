"""Provider boundary for evidence-only copilot responses."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

import httpx

SYSTEM = """You are Perimetryx, an authorized security-analysis copilot. Answer only from the supplied evidence. Do not infer a vulnerability, recommend exploitation, or use the label Confirmed Vulnerability. State when manual verification is required. Include the cited asset hostnames in your answer."""


class AIProvider(ABC):
    name = "base"

    @abstractmethod
    async def answer(self, question: str, evidence: list[dict]) -> str: ...


class DeterministicProvider(AIProvider):
    name = "deterministic-v2"

    async def answer(self, question: str, evidence: list[dict]) -> str:
        if not evidence:
            return "No recorded evidence is available for this scan."
        ranked = sorted(evidence, key=lambda item: item["score"], reverse=True)[:3]
        return (
            "Review "
            + ", ".join(f"{item['hostname']} (risk {item['score']})" for item in ranked)
            + ". The order is derived from recorded deterministic findings; manual verification is required before any report."
        )


class OpenAICompatibleProvider(AIProvider):
    name = "openai-compatible"

    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url, self.api_key, self.model = base_url.rstrip("/"), api_key, model

    async def answer(self, question: str, evidence: list[dict]) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Question: {question}\nEvidence: {evidence}"},
            ],
            "temperature": 0,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


def provider() -> AIProvider:
    choice = os.getenv("PERIMETRYX_AI_PROVIDER", "deterministic").lower()
    if choice == "openai" and os.getenv("OPENAI_API_KEY"):
        return OpenAICompatibleProvider(
            "https://api.openai.com/v1", os.environ["OPENAI_API_KEY"], os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
        )
    if choice == "ollama":
        return OpenAICompatibleProvider(
            os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"), "", os.getenv("OLLAMA_MODEL", "llama3.2")
        )
    return DeterministicProvider()
