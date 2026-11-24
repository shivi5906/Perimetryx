# Security Controls & Threat Framework Mappings

Perimetryx operates strictly against authorized assets under defensive, non-destructive reconnaissance protocols.

---

## 1. Threat Framework & Taxonomy Mappings

Every security rule in Perimetryx maps directly to **MITRE ATT&CK for Enterprise** and the **Common Weakness Enumeration (CWE)**:

| Rule Identifier | Security Category | Severity | MITRE Technique | CWE Identifier | CVSS v3.1 | Description |
|---|---|---|---|---|---|---|
| `TAKEOVER-001` | `dangling_cname_indicator` | **CRITICAL** | **T1584** (*Compromise Infrastructure*) | **CWE-284** | **8.5** | Dangling CNAME alias to an abandoned or unattached cloud service (S3, GitHub, Azure, Heroku). |
| `DNS-AXFR-001` | `dns_zone_transfer` | **CRITICAL** | **T1590.002** (*DNS Zone Transfer*) | **CWE-200** | **7.5** | Authoritative nameserver permits unrestricted AXFR zone transfers. |
| `DNS-SPF-PERMISSIVE` | `permissive_spf_all` | **HIGH** | **T1566** (*Phishing / Spoofing*) | **CWE-290** | **7.5** | SPF record contains `+all`, explicitly authorizing any server to send spoofed email. |
| `EXPOSE-METRICS-PROMETHEUS`| `exposed_metrics_endpoint` | **HIGH** | **T1592.002** (*Host Information*) | **CWE-200** | **7.1** | Prometheus metric endpoint publicly reachable, leaking memory and process internals. |
| `ENV-001` | `staging_exposed` / `dev_exposed` | **HIGH** | **T1592** (*Gather Host Information*) | **CWE-200** | **6.8** | Non-production staging/dev host responding publicly without access controls. |
| `TLS-CERT-EXPIRED` | `expired_tls_certificate` | **HIGH** | **T1592.004** (*Client Configurations*) | **CWE-295** | **6.5** | TLS certificate has expired, triggering browser warnings and enabling MitM attacks. |
| `TLS-PROTO-DEPRECATED` | `deprecated_tls_version` | **HIGH** | **T1592.004** (*Client Configurations*) | **CWE-326** | **7.4** | Server negotiates deprecated TLS 1.0 or 1.1 vulnerable to POODLE/BEAST. |
| `NET-HTTP-INSECURE` | `unencrypted_http_transport`| **MEDIUM** | **T1557** (*Man-in-the-Middle*) | **CWE-319** | **5.9** | Host serves plain HTTP (port 80) without automatic redirection to HTTPS. |
| `HDR-STRICT-TRANSPORT-SECURITY` | `missing_security_header` | **MEDIUM** | **T1557** (*Man-in-the-Middle*) | **CWE-319** | **4.8** | Response lacks HSTS, enabling SSL-stripping interception. |
| `HDR-CONTENT-SECURITY-POLICY` | `missing_security_header` | **MEDIUM** | **T1189** (*Drive-by Compromise*) | **CWE-693** | **5.0** | Response lacks Content-Security-Policy (CSP), permitting XSS and script injection. |
| `HDR-CSP-UNSAFE-DIRECTIVES` | `weak_csp_policy` | **MEDIUM** | **T1189** (*Drive-by Compromise*) | **CWE-693** | **5.4** | CSP uses `unsafe-inline` or `unsafe-eval`, defeating script isolation guarantees. |
| `EXPOSE-API-DOCS` | `exposed_api_documentation`| **MEDIUM** | **T1592.002** (*Host Information*) | **CWE-200** | **5.3** | Interactive Swagger/OpenAPI documentation exposed publicly. |
| `DNS-SPF-MISSING` | `missing_spf_record` | **MEDIUM** | **T1566** (*Phishing / Spoofing*) | **CWE-345** | **5.3** | Domain lacks SPF record, permitting unauthorized email spoofing. |
| `DNS-DMARC-MISSING` | `missing_dmarc_policy` | **MEDIUM** | **T1566** (*Phishing / Spoofing*) | **CWE-345** | **5.3** | Domain lacks DMARC record, failing email spoofing prevention baselines. |
| `SURFACE-ADMIN-001` | `admin_surface` | **MEDIUM** | **T1078** (*Valid Accounts*) | **CWE-200** | **4.8** | Hostname or title suggests administrative control boundary. |
| `HDR-X-FRAME-OPTIONS` | `missing_security_header` | **LOW** | **T1189** (*Drive-by Compromise*) | **CWE-1021** | **3.7** | Response lacks framing defenses, permitting Clickjacking attacks. |
| `HDR-X-CONTENT-TYPE-OPTIONS` | `missing_security_header` | **LOW** | **T1592** (*Host Information*) | **CWE-16** | **3.1** | Response lacks `nosniff`, permitting MIME-type confusion attacks. |
| `DISC-BANNER-VERSION` | `server_version_disclosure`| **LOW** | **T1592.002** (*Host Information*) | **CWE-200** | **3.3** | Server or X-Powered-By header discloses exact software versions. |
| `DNS-DMARC-NONE` | `dmarc_policy_none` | **LOW** | **T1566** (*Phishing / Spoofing*) | **CWE-345** | **3.7** | DMARC policy is set to `p=none` (monitoring only). |

---

## 2. Ethical Rules & Guardrails

1. **Passive Reconnaissance First:** Default pipeline operations query public certificate logs and perform standard DNS resolution.
2. **No Path Brute-Forcing:** The tool requests only the root document (`/`). It never crawls hidden folders, fuzzes parameters, or executes directory wordlists.
3. **No Exploitation or Credential Attacks:** The tool records observed boundaries. It never attempts credential guessing, SQL injection payloads, or privilege escalation.
4. **Rate Limiting & Politeness:** Requests are throttled through a centralized token-bucket rate limiter (`max_requests_per_second` hard limit).
5. **Identification:** Every network request transmits an identifying User-Agent string specifying tool name, version, and assessment context.
