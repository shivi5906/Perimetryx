# Learning Roadmap

Concepts to understand *before* implementing each phase — aimed at someone building toward bug bounty / AppSec / AI-security research capability, not just at "getting the code to run."

## Before Phase 1 — Recon Engine Foundations
```text
DNS fundamentals (record types, resolution flow, TTLs, authoritative vs recursive)
HTTP/HTTPS fundamentals (methods, status codes, headers, redirects)
TLS basics (handshake, certificates, SNI)
Python async programming (asyncio, coroutines, concurrency limits)
REST API consumption (auth, pagination, rate limits)
```
**Why it matters beyond this project:** this is the same foundation every recon and web-security skill builds on — you cannot reason about a misconfiguration you don't understand the correct configuration for.

## Before Phase 2 — Asset Intelligence
```text
Certificate Transparency (how CT logs work, why they leak subdomains via SANs)
OSINT methodology (passive vs active reconnaissance, legal/ethical boundaries)
Technology fingerprinting techniques (headers, cookies, error pages, JS artifacts)
Cloud infrastructure basics (AWS/GCP/Azure hosting indicators, ASN/BGP basics, CDN vs origin)
```
**Why it matters:** understanding *why* a fingerprint is reliable (or spoofable) prevents you from writing brittle detection rules and prepares you to think about fingerprint evasion, which is directly relevant to both bug bounty and red-team work.

## Before Phase 3 — Security Analysis
```text
Web security fundamentals (OWASP Top 10, at least conceptually)
Security headers in depth (CSP, HSTS, X-Frame-Options, Referrer-Policy, and what each actually prevents)
DNS security concepts (dangling CNAMEs / subdomain takeover mechanics, SPF/DMARC misconfig basics)
Attack surface analysis methodology (how professionals triage a large asset list)
Risk assessment fundamentals (likelihood vs impact, why a "score" needs a rationale, not just a number)
```
**Why it matters:** this is the phase where the tool starts making judgment calls. You need to be able to defend every rule's inclusion in a code review or a bug bounty report — "the tool said so" is never an acceptable justification, so you need to *actually know* why each check matters.

## Before Phase 4 — AI Intelligence
```text
LLM API fundamentals (chat completions, system/user roles, context windows)
Prompt engineering (specificity, few-shot examples, avoiding leading questions)
Structured outputs / function calling (JSON schema-constrained generation)
Retrieval-augmented generation concepts (why grounding beats parametric recall for factual tasks)
AI agent design patterns (tool-use loops, ReAct-style reasoning, stopping conditions)
LLM security (prompt injection — especially relevant here since scanned HTTP titles/headers are untrusted input that will flow into prompts; hallucination risk; output validation)
```
**Why it matters:** this is the phase most people get wrong by skipping straight to "call the API." Understanding *why* grounding/structured-output/RAG-style constraints matter is what makes the difference between a toy demo and a defensible security tool. The prompt-injection point is not theoretical here — a malicious target could put attacker-controlled text in an HTTP title or header specifically to manipulate your AI layer, so treat all scanned content as untrusted input to the LLM, same as you'd treat it as untrusted input to a database query.

## Ongoing, Cutting Across All Phases
```text
Secure coding practices (input validation, secrets management, dependency hygiene)
Testing methodology (unit vs integration vs e2e, why security tools especially need regression tests on rule logic)
Responsible disclosure norms and bug bounty program scope rules
Legal basics relevant to security research (CFAA-equivalent laws in your jurisdiction, authorization requirements)
```

## Suggested Study Order If Starting From Scratch
1. Networking/HTTP/DNS/TLS fundamentals (a few weeks of focused study + a networking course)
2. Build Phase 1 while learning — implementation is often the best way to cement these fundamentals
3. Web security fundamentals (OWASP resources, PortSwigger Web Security Academy) in parallel with Phase 2-3
4. LLM/prompt-engineering fundamentals only once Phase 3's data model is solid — you'll get much more out of it once you have real structured data to point an LLM at instead of toy examples
