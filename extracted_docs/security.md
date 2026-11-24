# Security & Ethics

Perimetryx is built under one non-negotiable constraint: **it only ever operates against domains the user owns or is explicitly authorized to assess.** Every architectural decision below exists to make that constraint hard to violate accidentally, not just documented as a policy.

## 1. Scope Enforcement

All scanning goes through the Scope Guard before any network request is made. Scope is declared explicitly, not inferred:

```yaml
scope:
  domain: example.com
  authorization_basis: "bug_bounty_program"   # or "owned_asset", "signed_engagement_letter"
  allowed_domains:
    - example.com
    - "*.example.com"
  excluded:
    - payments.example.com     # e.g. explicitly out of scope per program rules
    - "*.internal.example.com"
  active_verification: false    # must be explicitly true to allow anything beyond passive/safe probing
  max_requests_per_second: 2
  max_concurrent_connections: 5
  allowed_ports: [80, 443]
  user_agent: "Perimetryx/0.1 (+https://example-contact.tld; authorized-recon)"
```

Enforcement rules:
- Every discovered candidate hostname is checked against `allowed_domains`/`excluded` **before** it enters the DNS resolution stage — an excluded or out-of-wildcard hostname is dropped and logged, never silently scanned.
- `active_verification: false` is the default and disables any future feature that goes beyond passive/safe observation (e.g. confirming a subdomain takeover). This has to be flipped deliberately, per-scan, and is logged when it is.
- Port scanning is hard-limited to `allowed_ports` — no arbitrary port sweeps, ever, regardless of what's discovered.
- `authorization_basis` is a required field with no default — the CLI refuses to run a scan if it's missing, forcing the user to actively state why they're authorized.

## 2. Rate Limiting & Politeness

- Token-bucket rate limiter enforced centrally in the HTTP/DNS clients, not per-plugin (so a badly-written discovery plugin can't bypass the global limit).
- `max_requests_per_second` and `max_concurrent_connections` from scope config are hard ceilings, not suggestions — the orchestrator will queue rather than exceed them.
- Exponential backoff on any 429/503 response; a target signaling it's under load is a signal to slow down further, not retry harder.
- No denial-of-service-adjacent behavior: no request flooding, no repeated identical requests beyond what's needed for a single observation.

## 3. Identification & Transparency

- Every HTTP request carries an identifying `User-Agent` string with tool name, version, and a contact reference — never spoofs a browser or another tool.
- No credential attacks, no brute-force login attempts, no directory/path brute-forcing. The tool observes what's already externally visible; it does not attempt to discover hidden content by guessing.
- No exploitation of any kind — Perimetryx stops at "here's a finding that needs manual verification," full stop. It never attempts to confirm a vulnerability by triggering it.

## 4. Audit Logging

- Every scan run is logged with: target, scope config used, timestamp, requesting user, and a complete list of requests made (method, URL, response code — not full response bodies, to avoid bloating logs with target data).
- Scope Guard denials are logged distinctly from normal scan activity — a spike in denied targets is a signal worth surfacing to the user (could mean a misconfigured scope, or accidental scan expansion).
- Logs are treated as sensitive data themselves (they reveal what's been reconnoitered) and are subject to the same access controls as scan results.

## 5. Secrets & API Key Management

- No API keys (passive-source providers, AI providers) are ever stored in scan output, logs, or committed config — loaded from environment variables or a secrets manager, referenced by name only in config files.
- AI provider credentials are scoped separately from passive-source credentials, so a compromised AI key doesn't imply access to paid recon data sources and vice versa.
- `.env` and any local credential files are gitignored by default in the project template; CI includes a secrets-scanning step (e.g. gitleaks) on every commit.

## 6. Preventing Accidental Out-of-Scope Scanning

Beyond the Scope Guard check itself:
- **Wildcard scope requires explicit `*.` syntax** — a bare `example.com` entry does *not* implicitly authorize subdomains, preventing accidental over-broad interpretation.
- **Cross-domain pivoting is blocked by default.** If a discovered asset resolves to an IP that also hosts unrelated domains (shared hosting/CDN), the tool does not follow that pivot into scanning the other domains — it only ever expands within the declared scope's hostname patterns.
- **A dry-run mode** (`--dry-run`) shows exactly which hostnames would be scanned, against the current scope config, without making any external requests — meant to be the default first step for any new scope file.
- **Scope config is versioned and hashed into the Scan record**, so a completed scan can always be traced back to exactly what rules were in effect at the time, even if the scope file is later edited.
