# Security Assessment Checklist — Pass/Fail Criteria, Evidence & Severity

> **Document type:** Execution checklist for professional security assessments
> **Companion documents:** `Software-Security-Assessment-Skills.md` (rationale & methodology), `Security-Assessment-Playbook.md` (procedures)
> **How to use:** Each item states the control, a **PASS** condition, a **FAIL** condition, the **evidence** to capture, the **default severity** if failed, and framework mappings. Severity is a starting point — adjust for business context (data sensitivity, exposure, exploitability). Mark each item **PASS / FAIL / N/A / NEEDS-REVIEW**.

**Default severity bands** (CVSS-aligned, business-adjusted):

| Severity | CVSS band | Meaning |
|----------|-----------|---------|
| Critical | 9.0–10.0 | Direct compromise of data/system; exploit trivial or unauthenticated |
| High | 7.0–8.9 | Serious impact; realistic exploitation |
| Medium | 4.0–6.9 | Meaningful weakness; conditions or chaining required |
| Low | 0.1–3.9 | Limited impact; hardening |
| Info | 0.0 | Observation / best practice |

---

## 1. Authentication & Identity

| # | Control | PASS | FAIL | Evidence | Severity (if fail) | Mapping |
|---|---------|------|------|----------|--------------------|---------|
| 1.1 | MFA enforced | MFA required for all users; phishing-resistant for admins | MFA optional/absent for privileged users | Auth flow capture, IdP config | Critical | A07 / PCI 8.4 / IA-2 |
| 1.2 | Credential storage | Passwords hashed with bcrypt/argon2/scrypt, salted | Plaintext/MD5/SHA1/unsalted | Code/DB schema | Critical | A02 / CWE-916 |
| 1.3 | Anti-automation on login | Rate limiting + lockout/CAPTCHA on auth | Unlimited attempts | Request series showing no throttle | High | A07 / CWE-307 |
| 1.4 | Account recovery | Recovery cannot enumerate or bypass MFA | Recovery leaks accounts or skips MFA | Recovery flow capture | High | A07 |
| 1.5 | Credential in transit | All auth over TLS 1.2+ | Any auth over HTTP | Network capture | Critical | A02 / SC-8 |
| 1.6 | Default/weak accounts | No default creds; strong password policy enforced | Defaults present or weak policy | Config, login test | High | A05 |
| 1.7 | User enumeration | Uniform responses/timing for valid vs invalid users | Differential response reveals accounts | Comparative responses | Low–Medium | CWE-203 |

---

## 2. Session & Token Management

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 2.1 | Cookie flags | `Secure`, `HttpOnly`, `SameSite` set on session cookies | Missing flags | Response headers | Medium | A05 / CWE-1004 |
| 2.2 | Session timeout | Idle + absolute timeout enforced | No expiry | Long-lived session test | Medium | A07 / CWE-613 |
| 2.3 | Session rotation | New session ID on login & privilege change | Fixed session ID | Before/after capture | High | CWE-384 |
| 2.4 | Logout/revocation | Server-side invalidation on logout | Token still valid post-logout | Replay after logout | High | CWE-613 |
| 2.5 | JWT algorithm | Signature verified; `alg:none` rejected; no RS/HS confusion | Unverified or `none` accepted | Modified-token test | Critical | CWE-347 |
| 2.6 | JWT contents/expiry | Short expiry; no sensitive data in payload | Long-lived / sensitive claims | Decoded token | Medium | CWE-522 |
| 2.7 | Token transport | Tokens not in URLs/logs | Token in query string/logs | URL/log sample | Medium | CWE-598 |

---

## 3. Authorization (RBAC / ABAC / Object-level)

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 3.1 | Server-side authZ | Every request authorized server-side | Client-side-only enforcement | Forced-browsing test | Critical | A01 / API5 |
| 3.2 | BOLA / IDOR | Object access checked against caller ownership | Another user's object retrievable by ID | Cross-object API response | Critical | API1 / CWE-639 |
| 3.3 | BFLA | Privileged functions blocked for lower roles | Role escalation via direct call | Low-role call to admin function | Critical | API5 / CWE-285 |
| 3.4 | Tenant isolation | Every query scoped by `tenant_id`; cross-tenant blocked | Cross-tenant data retrievable | Tenant-A token retrieving Tenant-B data | Critical | A01 / CWE-863 |
| 3.5 | Mass assignment | Server allow-lists writable fields | Client sets `isAdmin`/`role`/`price` | Modified payload accepted | High | API3 / CWE-915 |
| 3.6 | Least privilege | Roles grant only necessary permissions | Broad/wildcard roles | Role definitions | High | AC-6 |
| 3.7 | Vertical/horizontal escalation | Neither possible | Either possible | Exploit capture | Critical | A01 |

---

## 4. Input Validation, Injection & Output

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 4.1 | SQL injection | Parameterized/ORM everywhere | Injectable parameter | Payload + response/error | Critical | A03 / CWE-89 |
| 4.2 | Command injection | No shell concatenation | OS command executes | Command output proof | Critical | CWE-78 |
| 4.3 | XSS (all types) | Context-aware encoding + CSP | Script executes | PoC payload render | High | A03 / CWE-79 |
| 4.4 | CSRF | Anti-CSRF token or SameSite+origin on state changes | State change via forged request | Cross-origin PoC | High | CWE-352 |
| 4.5 | SSRF | Egress allow-list; metadata/link-local blocked | Server fetches attacker URL | Response from internal/metadata | Critical | A10 / API7 / CWE-918 |
| 4.6 | Deserialization | No untrusted deserialization | Object injection works | PoC | Critical | A08 / CWE-502 |
| 4.7 | Path traversal | Canonicalize + confine | File outside base readable | File contents | High | CWE-22 |
| 4.8 | File upload | Type/size/AV validation; stored out of webroot; non-executable | Web shell uploads/executes | Upload + execution proof | Critical | CWE-434 |
| 4.9 | XXE | External entities/DTD disabled | XXE resolves | Injected entity response | High | CWE-611 |
| 4.10 | Output encoding | Encoded per context | Raw reflection | Reflected content | High | CWE-116 |

---

## 5. Cryptography & Secrets

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 5.1 | TLS config | TLS 1.2+; strong ciphers; HSTS | TLS 1.0/1.1, weak ciphers, no HSTS | TLS scan | High | A02 / SC-8 |
| 5.2 | Encryption at rest | Sensitive data encrypted; field-level where needed | Plaintext sensitive storage | Config/DB proof | High | SC-28 |
| 5.3 | Algorithm strength | AES-GCM, SHA-256+, no ECB/DES/RC4 | Weak/deprecated algorithms | Code/config | High | CWE-327 |
| 5.4 | Key management | Vault/KMS; rotation; access-controlled | Keys in code/config | Repo/config scan | Critical | CWE-320 |
| 5.5 | Hard-coded secrets | None in code/history/artifacts | Secrets present | Secret-scan hit | Critical | CWE-798 |
| 5.6 | Randomness | CSPRNG for tokens/keys | Predictable RNG | Code | Medium | CWE-338 |

---

## 6. Sensitive Data & Privacy

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 6.1 | Data minimization | Only necessary data collected/retained | Excess collection/retention | Data map | Medium | Privacy / GV |
| 6.2 | Data in logs | No secrets/PII/card data in logs | Sensitive data logged | Log sample | High | CWE-532 |
| 6.3 | Masking | PAN/PII masked in UI/responses | Full sensitive data returned | Response sample | High | PCI 3 |
| 6.4 | Data residency | Storage pinned to required region | Data in disallowed region | Cloud config | High | PIPEDA/GDPR |
| 6.5 | Error verbosity | Generic errors to client | Stack traces/internal detail | Error response | Medium | CWE-209 |
| 6.6 | Card data (PCI) | No PAN stored; tokenized/masked only | PAN stored | Data store review | Critical | PCI 3 / A02 |

---

## 7. API Security (OWASP API Top 10)

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 7.1 | Resource consumption | Rate/size/pagination limits enforced | Unbounded requests/responses | Flood test | High | API4 / CWE-770 |
| 7.2 | API inventory | Complete inventory; no shadow/deprecated exposed | Undocumented/staging endpoints live | Endpoint discovery | Medium–High | API9 |
| 7.3 | CORS | Restrictive, no wildcard with credentials | `*` + credentials | Response headers | Medium | API8 |
| 7.4 | Schema validation | Strict request/response schema | Unvalidated payloads accepted | Malformed-payload test | Medium | API8 |
| 7.5 | Third-party consumption | Upstream data validated; redirects controlled | Blind trust of upstream | Code/flow | Medium | API10 |
| 7.6 | GraphQL limits | Depth/complexity limits; introspection off in prod | Introspection on; unbounded queries | Introspection query | Medium–High | API4 |
| 7.7 | Webhook security | Signature + replay protection | Unsigned/replayable | Forged webhook accepted | High | API8 |

---

## 8. Cloud & Infrastructure

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 8.1 | Public exposure | No public storage/DB/admin ports | Public bucket/DB/SSH-RDP open | CSPM/scan | Critical | CIS/CCM |
| 8.2 | IAM least privilege | Scoped roles; no wildcard admin; no standing privilege | Over-permissive/`*` policies | IAM export | High | AC-6 |
| 8.3 | MFA on cloud console | Enforced incl. root/break-glass controlled | No MFA | IAM config | Critical | IA-2 |
| 8.4 | Encryption | At rest + in transit enabled | Unencrypted resources | Config | High | SC-28 |
| 8.5 | Logging | Control + data plane logging on, retained, protected | Logging off/short retention | Log config | High | AU-2 |
| 8.6 | Network segmentation | Private endpoints; restricted egress | Flat network; open egress | Network config | High | SC-7 |
| 8.7 | Managed identities | Used vs static keys | Static long-lived keys | Config | High | IA-5 |
| 8.8 | CSPM active | Continuous posture scanning enabled | None | Tool status | Medium | — |

---

## 9. IaC, Containers & Supply Chain

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 9.1 | IaC scanning | Templates scanned pre-deploy; no criticals | Unscanned/critical misconfigs | Checkov/tfsec report | High | SSDF |
| 9.2 | No secrets in IaC | Secrets referenced from vault | Plaintext secrets in templates | Scan hit | Critical | CWE-798 |
| 9.3 | Image vulnerabilities | No critical/high CVEs in images | Critical CVEs present | Trivy/Grype report | High | A06 |
| 9.4 | Container hardening | Non-root, read-only FS, no privileged, dropped caps | Privileged/root containers | Runtime config | High | CIS Docker |
| 9.5 | Base image provenance | Trusted, minimal, pinned digests | Untrusted/latest tags | Dockerfile | Medium | SSDF |
| 9.6 | SBOM | Generated & reviewed per release | None | SBOM artifact | Medium | SSDF / EO |
| 9.7 | Dependency currency | No known-vulnerable deps; timely patching | Outdated vulnerable deps | SCA report | High | A06 |
| 9.8 | Registry security | Signed images; access-controlled registry | Unsigned/public push | Registry config | Medium | SSDF |

---

## 10. Logging, Monitoring & Error Handling

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 10.1 | Security event logging | Auth, authZ, admin, config changes logged | Missing security events | Log review | Medium–High | A09 / AU-2 |
| 10.2 | Tamper-evidence | Append-only/hash-chained, time-synced | Mutable logs | Log architecture | High | AU-9 |
| 10.3 | Alerting | Alerts on failures/anomalies with owners | Monitoring without alerting | Alert config | High | DE.AE |
| 10.4 | No sensitive data in logs | Verified | Secrets/PII present | Log sample | High | CWE-532 |
| 10.5 | Detection coverage | Key attack patterns detectable | Blind spots | Detection map | Medium | DE.CM |

---

## 11. Business Logic & Abuse

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 11.1 | Workflow integrity | State transitions validated server-side | Steps skippable/reorderable | Sequence exploit | High | A04 / CWE-840 |
| 11.2 | Race conditions | Critical operations atomic/locked | TOCTOU exploitable (double-spend) | Concurrent-request PoC | High | CWE-362 |
| 11.3 | Value/quantity limits | Negative/overflow/limit checks | Negative price/qty accepted | Manipulated request | High | CWE-840 |
| 11.4 | Anti-automation on flows | Sensitive flows rate-limited | Bulk automation possible | Automation proof | Medium–High | API6 |
| 11.5 | Replay protection | Nonces/timestamps on sensitive ops | Replay succeeds | Replay proof | High | CWE-294 |

---

## 12. AI / LLM / RAG / Agent Security

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 12.1 | Direct prompt injection | System instructions resist override | User input overrides system prompt | Injection prompt/response | Critical | LLM01 |
| 12.2 | Indirect prompt injection | Retrieved/tool content cannot inject instructions | Malicious doc controls model | PoC document + behavior | Critical | LLM01 |
| 12.3 | System prompt leakage | System prompt not extractable | Prompt disclosed | Extraction transcript | Medium–High | LLM07 |
| 12.4 | Sensitive info disclosure | No PII/secrets/other-tenant data in output | Model leaks data | Transcript | Critical | LLM02 |
| 12.5 | Output handling | Model output sanitized before downstream use | Output causes XSS/SQLi/RCE | Downstream exploit | High | LLM05 |
| 12.6 | RAG authZ filtering | Retrieval filtered by caller authZ before context | Cross-tenant/unauthorized docs retrieved | Cross-tenant retrieval | Critical | LLM02/08 |
| 12.7 | Vector store isolation | Embeddings tenant-scoped & access-controlled | Shared/unrestricted vectors | Store config + query | Critical | LLM08 |
| 12.8 | Excessive agency | Tools/permissions minimized; consequential actions gated | Model can act beyond need | Permission/tool review | High | LLM06 |
| 12.9 | Unsafe tool invocation | Tool params validated; no injection to args | Injection steers tool calls | Tool-call log | Critical | LLM06 |
| 12.10 | Function calling constraints | Allow-listed functions; args validated | Arbitrary/abusable calls | Call log | High | LLM06 |
| 12.11 | Unbounded consumption | Token/rate/cost limits enforced | Cost/DoS via generation | Consumption test | Medium–High | LLM10 |
| 12.12 | Guardrails/content filter | Input+output filtering effective vs jailbreaks | Bypassable | Jailbreak transcript | High | LLM01 |
| 12.13 | AI audit logging | Prompts, retrievals, tool calls, outputs logged | No AI audit trail | Log review | Medium–High | AI RMF MEASURE |
| 12.14 | Model/endpoint security | AuthN/authZ, private network, key in vault | Open endpoint / client-side key | Endpoint config | Critical | LLM03 |
| 12.15 | Memory poisoning | Long-term memory validated before persistence | Malicious content persists | Memory injection PoC | High | LLM04 |
| 12.16 | Multi-agent isolation | Injection cannot propagate across agents | Cross-agent compromise | PoC | High | LLM06 |
| 12.17 | Responsible AI | Bias/fairness tested; human oversight on consequential actions | No RAI validation | Eval records | Medium–High | ISO 42001 |
| 12.18 | Model supply chain | Model/plugin/MCP provenance verified | Untrusted components | Provenance records | High | LLM03 |

---

## 12A. Agentic Frameworks (LangChain / LangGraph / AutoGen / CrewAI / Semantic Kernel / etc.)

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 12A.1 | Tool minimization | Agent exposes only least-privilege tools | Shell/REPL/unrestricted-HTTP/SQL tools on internet-facing agent | Tool inventory | Critical | LLM06 |
| 12A.2 | Dangerous built-ins | No `PythonREPLTool`/`ShellTool`/unrestricted `RequestsToolkit` reachable by untrusted input | Present and reachable | Code/config | Critical | LLM06 / CWE-94/78 |
| 12A.3 | Tool argument validation | Tool args validated independently of model output | Injection controls tool arguments | Tool-call log + PoC | Critical | LLM06 |
| 12A.4 | Agent loop bounds | Max iterations, `recursion_limit`, timeout, cost budget enforced | Unbounded loop possible | Loop/cost test | High | LLM10 / CWE-770 |
| 12A.5 | LangGraph state isolation | Checkpointer state scoped by tenant/user/thread | Cross-thread/user state readable | State store review + PoC | Critical | LLM04 |
| 12A.6 | Node output validation | State written by nodes validated before downstream consumption | Poisoned node output propagates | Graph trace | High | LLM04/06 |
| 12A.7 | Human-in-the-loop gates | Approval interrupts enforced server-side, non-bypassable | Consequential action auto-executes / bypassable via injection | Approval-bypass PoC | High | LLM06 |
| 12A.8 | Memory scoping | Conversation/entity memory scoped per user/session | Cross-user/session memory bleed | Memory leakage PoC | Critical | LLM04 |
| 12A.9 | Output parser safety | Structured output parsed safely; no eval of model output | Unsafe parse/eval → RCE/injection | PoC | Critical | LLM05 / CWE-502/95 |
| 12A.10 | Prompt template/hub trust | Templates local/vetted; user vars cannot inject into template logic | Remote `hub.pull` untrusted / template injection | Template review | High | LLM03 |
| 12A.11 | Callback/tracing hygiene | No secrets/PII over-shared to tracing (e.g., LangSmith); scoped keys | Secrets/PII exported to external tracing | Trace config/sample | Medium–High | LLM02 |
| 12A.12 | Multi-agent isolation | Injection cannot propagate agent-to-agent; no confused-deputy | Cross-agent compromise / privilege confusion | Multi-agent PoC | High | LLM06 |
| 12A.13 | Framework supply chain | Framework + community integrations version-pinned & SCA-scanned | Unpinned/vulnerable integrations, unvetted remote artifacts | SBOM/SCA report | High | LLM03 / A06 |
| 12A.14 | Retriever authZ (agentic RAG) | Retrieval tools filter by caller authZ before context | Agent retriever returns unauthorized/cross-tenant docs | Cross-tenant retrieval | Critical | LLM02/08 |

---

## 13. Governance & Program (CSF 2.0 GOVERN)

| # | Control | PASS | FAIL | Evidence | Severity | Mapping |
|---|---------|------|------|----------|----------|---------|
| 13.1 | Secure SDLC | Security gates in CI/CD | No gates | Pipeline config | High | SSDF |
| 13.2 | Threat modeling | Performed & maintained | Absent | TM artifacts | Medium–High | SDL |
| 13.3 | Vendor/subprocessor risk | Third parties assessed | None | Vendor register | Medium | GV.SC |
| 13.4 | BCDR | Backups tested; RTO/RPO defined | Untested/undefined | DR test records | High | CP-9/10 |
| 13.5 | Incident response plan | Documented & exercised | Absent | IR plan | High | IR-8 |
| 13.6 | AI governance | ISO 42001 / AI RMF program in place | None for AI systems | Governance docs | Medium–High | ISO 42001 |

---

## Scoring & Sign-off

- Record **PASS / FAIL / N/A / NEEDS-REVIEW** per item with evidence reference.
- Every FAIL becomes a report finding (see Skills §12 for the finding template).
- Compute domain-level and overall posture; highlight all Critical/High for the executive summary.
- Re-run failed items at retest; only closed-with-evidence items are marked remediated.

*End of checklist. Procedures for exercising each item are in `Security-Assessment-Playbook.md`.*
