# Security Assessment Playbook — Step-by-Step Procedures

> **Document type:** Operational procedures for executing security assessments
> **Companion documents:** `Software-Security-Assessment-Skills.md` (knowledge), `Security-Assessment-Checklist.md` (pass/fail criteria)
> **Scope:** Web applications, APIs, cloud infrastructure, mobile apps, AI/LLM systems (including Azure AI Foundry and RAG), and agentic frameworks (LangChain, LangGraph, and peers). Each track is a repeatable procedure producing checklist results and report-ready findings.

---

## 0. Pre-Engagement (All Tracks)

**Objective:** authorized, scoped, safe execution.

1. **Obtain written authorization** — signed Rules of Engagement: assets, environments, test windows, prohibited actions, emergency contacts, data-handling terms.
2. **Confirm scope** — enumerate in-scope hosts, domains, endpoints, cloud accounts, repos, and AI systems. Explicitly record exclusions.
3. **Set up safely** — use a non-production environment where possible; if production, agree throttling and destructive-test limits.
4. **Prepare tooling & accounts** — provision test accounts at multiple privilege levels (needed for authZ testing) and at least two tenants (needed for isolation testing).
5. **Establish evidence handling** — encrypted storage; secret/PII redaction policy; retention/destruction terms.
6. **Threat model first** — build/refresh DFDs and STRIDE/LINDDUN model; derive priority test cases (see Skills §4).

**Exit criteria:** signed RoE, scope matrix, threat model, test accounts (multi-role, multi-tenant), evidence store ready.

---

## 1. Web Application Assessment

### 1.1 Reconnaissance & mapping
1. Enumerate content, endpoints, parameters, and technologies (spider + manual browsing).
2. Identify authentication mechanisms, roles, and state-changing operations.
3. Map trust boundaries and data flows against the threat model.

### 1.2 Authentication & session
4. Test MFA enforcement, lockout/anti-automation, and recovery (Checklist §1).
5. Test session: cookie flags, timeout, rotation on login/privilege change, logout revocation (Checklist §2).
6. Attack tokens: JWT `alg:none`, RS/HS confusion, expiry, tampering.

### 1.3 Authorization
7. **Forced browsing / BFLA:** call privileged functions as lower-role users.
8. **IDOR / BOLA:** iterate object identifiers across accounts; attempt to read/modify others' objects.
9. **Tenant isolation:** with Tenant-A credentials, attempt to reach Tenant-B data by ID, filter, and export.
10. **Privilege escalation:** vertical (role) and horizontal (peer) — capture any success.

### 1.4 Injection & input
11. Test SQLi (parameterized?), command injection, XXE, deserialization on all inputs.
12. Test XSS (reflected/stored/DOM) with context-appropriate payloads; verify CSP.
13. Test SSRF on any URL/file/preview/import feature; target metadata endpoints and internal ranges.
14. Test path traversal and file upload (web shell, type/size bypass, execution).
15. Test CSRF on state-changing requests.

### 1.5 Business logic
16. Attempt workflow skips, step reordering, and state manipulation.
17. Test race conditions on balance/coupon/inventory operations (concurrent requests).
18. Test value manipulation: negative amounts, integer overflow, quantity/price tampering.
19. Test replay of sensitive operations.

### 1.6 Configuration & data
20. Check security headers, error verbosity, exposed debug/admin, directory listing.
21. Check sensitive data in responses, URLs, and logs; verify masking.

**Deliverable:** completed Checklist §§1–6, 10, 11 with evidence; report-ready findings.

---

## 2. API Assessment

### 2.1 Inventory & spec
1. Obtain/derive the API spec (OpenAPI/GraphQL schema); enumerate all endpoints, methods, and versions.
2. Hunt **shadow/deprecated APIs**: old versions, staging hosts, undocumented routes (API9).

### 2.2 Authentication & authorization
3. Verify token validation on every endpoint (no unauthenticated sensitive routes).
4. **BOLA (API1):** manipulate object IDs across accounts.
5. **BFLA (API5):** invoke admin/privileged operations as low-privilege users.
6. **BOPLA / Mass assignment (API3):** add unexpected fields (`role`, `isAdmin`, `price`, `verified`) to payloads.

### 2.3 Resource & schema
7. **Unrestricted consumption (API4):** remove pagination, request large ranges, flood endpoints; check rate/size limits.
8. **Schema validation:** send malformed, wrong-type, and extra-field payloads.
9. **GraphQL:** test introspection in prod, deep/nested queries, aliasing/batching amplification, field-level authZ.
10. **gRPC:** check reflection exposure, mTLS, per-method authZ, message-size limits.

### 2.4 Consumption & integration
11. **SSRF (API7):** any server-side fetch/callback/webhook target.
12. **Third-party consumption (API10):** validation of upstream data and redirects.
13. **Webhooks:** signature verification and replay protection.
14. **Config (API8):** CORS (wildcard + credentials?), verbose errors, missing security headers.

**Deliverable:** completed Checklist §7 (+ overlaps with §§1–4); OWASP API Top 10 coverage matrix.

---

## 3. Cloud Infrastructure Assessment

### 3.1 Enumerate & baseline
1. Obtain read-only assessment access (or IaC + config exports) for Azure/AWS/GCP.
2. Run CSPM (Defender for Cloud / Security Hub / SCC; or Prowler/ScoutSuite) against CIS Benchmarks and CCM.

### 3.2 Identity & access
3. Review IAM for least privilege: wildcard/admin policies, standing privileged access, unused identities.
4. Verify MFA on console/root; break-glass accounts controlled and monitored.
5. Prefer managed identities/workload identity over static long-lived keys; flag any static keys.
6. Run privilege-path analysis (who can escalate to admin?).

### 3.3 Data & network
7. Detect public exposure: storage buckets/blobs, databases, admin ports (SSH/RDP) open to 0.0.0.0/0.
8. Verify encryption at rest and in transit across storage, DB, and queues.
9. Review segmentation: private endpoints, restricted egress, no flat networks.

### 3.4 Keys, logging, workloads
10. Review key management: vault usage, rotation, access policies, HSM where required.
11. Verify logging (control + data plane) enabled, retained, and tamper-resistant.
12. Assess serverless (exec-role privilege, secret handling, event-source validation).

### 3.5 IaC review
13. Scan Terraform/Bicep/ARM/CloudFormation with Checkov/tfsec/KICS.
14. Verify: no plaintext secrets, encryption on, network restrictions, logging on, least-privilege roles.
15. Compare IaC to running config; treat drift as a finding.

**Deliverable:** completed Checklist §§8–9; CSPM export; IaC findings; privilege-path diagram.

---

## 4. Container & Supply Chain Assessment

1. **Image scanning:** Trivy/Grype on all images; flag critical/high CVEs; verify base-image provenance and pinned digests.
2. **SBOM:** generate (Syft) and review; confirm produced per release.
3. **Dependency (SCA):** Dependency-Check/Grype/Snyk; flag known-vulnerable and abandoned/malicious packages; check dependency currency.
4. **Secrets:** GitLeaks/Trufflehog across code and full git history and build artifacts.
5. **Runtime hardening:** non-root, read-only filesystem, dropped capabilities, no privileged, network policies.
6. **Registry:** signed images, access control, no anonymous push/pull.
7. **Pipeline:** confirm SAST/SCA/IaC/secret gates block on high severity (SSDF).

**Deliverable:** completed Checklist §9; SBOM; vulnerable-component list; pipeline gate assessment.

---

## 5. Mobile Application Assessment (MASVS)

### 5.1 Static
1. Reverse the package (APK/IPA); review for hard-coded secrets, endpoints, and keys (MASVS-CODE/STORAGE).
2. Check local storage: no sensitive data in plaintext prefs/DB/files; keychain/keystore used (MASVS-STORAGE).
3. Review cryptography usage (MASVS-CRYPTO).

### 5.2 Dynamic & platform
4. Intercept traffic; verify TLS and **certificate pinning**; test pinning bypass resistance (MASVS-NETWORK).
5. Test authentication/session handling and token storage (MASVS-AUTH).
6. Assess platform interactions: exported components, deep links, IPC, WebView config, clipboard (MASVS-PLATFORM).
7. Assess resilience: root/jailbreak detection, anti-tamper, debugging protections where warranted (MASVS-RESILIENCE).

### 5.3 Backend
8. Assess the mobile API using the API track (§2) — the backend is usually the higher-value target.

**Deliverable:** MASVS-mapped findings; static + dynamic evidence; backend API results.

---

## 6. AI / LLM System Assessment

> Applies to chatbots, copilots, RAG systems, and agents. Combines AI red teaming with the underlying app/API/cloud tracks. Map to OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF.

### 6.1 Model & scope the AI system
1. Diagram the AI pipeline: input → prompt assembly → retrieval sources → model → tools/functions → memory → output. Mark trust boundaries; **treat all retrieved/tool content as untrusted**.
2. Enumerate: model(s), system prompt, data sources, tools/plugins/MCP servers, memory stores, and downstream consumers of output.

### 6.2 Prompt injection & jailbreaking (LLM01)
3. **Direct injection:** attempt to override system instructions ("ignore previous instructions", role-play, delimiter confusion, encoding tricks).
4. **Indirect injection:** plant malicious instructions in a document/web page/email/tool output the system will ingest; confirm whether the model executes them.
5. **Jailbreaks:** run known jailbreak families; measure guardrail bypass.
6. Use PyRIT/Garak/Promptfoo to automate and regression-test injection scenarios.

### 6.3 Information disclosure (LLM02, LLM07)
7. Attempt **system prompt extraction**.
8. Attempt to elicit **other users'/tenants' data**, secrets, or training data.
9. Test for sensitive data in outputs, error messages, and tool traces.

### 6.4 Output handling (LLM05)
10. Where model output flows into HTML, SQL, shell, or code execution, test that output is sanitized (inject payloads via the model into the downstream sink).

### 6.5 Excessive agency, tools & functions (LLM06)
11. Inventory tools/functions the model can call and their permissions; test least privilege.
12. Attempt to steer tool/function **arguments** via injection (e.g., cause an email tool to send to attacker, a DB tool to read unauthorized rows).
13. Test that consequential actions require validation/human approval.
14. For **MCP**: verify server trust, tool-poisoning resistance, and credential scope.

### 6.6 Consumption & resilience (LLM10)
15. Test token/rate/cost limits; attempt cost-amplification and generation-based DoS.

### 6.7 Governance (AI RMF / ISO 42001)
16. Verify AI audit logging (prompts, retrievals, tool calls, outputs).
17. Verify guardrail/content-filter coverage on input and output.
18. Review bias/fairness testing and human-oversight controls on consequential actions.
19. Verify model/plugin/MCP supply-chain provenance (LLM03).

**Deliverable:** completed Checklist §12; injection transcripts; tool-abuse evidence; AI red-team scenario results.

---

## 7. RAG System Assessment (Deep-Dive)

> RAG's defining risk: **authorization must be enforced on retrieval, not by the model.** The model cannot be trusted to withhold content it has already been given.

### 7.1 Pipeline mapping
1. Diagram: query → embedding → vector search → document retrieval → context assembly → generation. Identify where authorization is (or isn't) applied.

### 7.2 Retrieval authorization & isolation (LLM02/08) — highest priority
2. **Pre-retrieval authZ:** confirm the vector search is filtered by the caller's identity/tenant/permissions *before* documents enter the context. If filtering happens only in the prompt or after retrieval, that is a Critical finding.
3. **Cross-tenant retrieval:** as Tenant-A, craft queries designed to surface Tenant-B documents; confirm isolation.
4. **Cross-document leakage:** attempt to retrieve documents the user should not access within the same tenant (role/ACL boundaries).
5. **Vector store security:** verify authN/authZ on the vector DB itself, tenant partitioning of embeddings, and that embeddings are not globally queryable.

### 7.3 Injection via retrieved content (LLM01)
6. **Embedding/document poisoning:** insert a document containing injection payloads into an ingest path; confirm whether retrieval + generation executes the embedded instructions (indirect prompt injection through RAG).
7. Test that ingested content is treated as data, not instructions.

### 7.4 Retrieval manipulation
8. Test query crafting to force retrieval of specific/unauthorized documents.
9. Test relevance/ranking abuse to surface attacker-planted content preferentially.

### 7.5 Output & governance
10. Verify citations/sources are accurate and cannot be spoofed to lend false authority (LLM09).
11. Confirm retrieval and source documents are logged for audit.

**Deliverable:** RAG isolation test results; poisoning PoC (if any); vector-store config review; Checklist §12.6–12.7.

---

## 8. Azure AI Foundry Assessment (Platform Deep-Dive)

> For solutions built on Azure AI Foundry / Azure OpenAI. Combines the AI track (§6), RAG track (§7 if applicable), and Azure cloud track (§3).

### 8.1 Resource & isolation
1. Review Foundry **hub/project structure**: confirm project isolation, RBAC scoping, and that resources are not over-shared across projects/teams.
2. Verify **RBAC** on Foundry resources, model deployments, and connected data sources (least privilege).

### 8.2 Network & identity
3. Verify **private endpoints / VNet integration** on the Foundry resource, Azure OpenAI, and connected stores; confirm no public exposure of inference endpoints.
4. Confirm **Managed Identity** is used for service-to-service auth (Foundry → storage/search/OpenAI) instead of keys.
5. **API keys:** ensure keys are in Key Vault, rotated, per-consumer scoped, and never client-side.

### 8.3 Connections & data
6. Review **connections** (to Azure AI Search, storage, other data sources): auth method, scope, and whether they cross trust boundaries.
7. For RAG on Azure AI Search: apply §7 — confirm **security-trimming/filters** enforce document-level authorization per caller; confirm index/tenant isolation.

### 8.4 Content safety & guardrails
8. Verify **Azure AI Content Safety** filters are enabled and tuned (input + output); test bypass resistance.
9. Review **model deployment** settings: data-retention/abuse-monitoring configuration, quota/rate limits, and allowed models.

### 8.5 Evaluation & monitoring
10. Use **Azure AI Foundry evaluations** to run safety, groundedness, and injection-resistance evals; establish these as CI gates.
11. Verify logging/monitoring of prompts, completions, and content-filter events (with appropriate PII handling and retention).

### 8.6 Governance
12. Confirm alignment to Microsoft Responsible AI standard and (where applicable) ISO 42001 / NIST AI RMF program controls.
13. Verify human oversight on consequential agentic actions and documented model-change review.

**Deliverable:** Foundry RBAC/network/identity findings; content-safety & eval results; RAG isolation results; Checklist §12 (esp. 12.6, 12.7, 12.14) + Azure items in §8.

---

## 8A. Agentic Framework Assessment (LangChain / LangGraph / AutoGen / CrewAI / Semantic Kernel / custom)

> For applications built on agentic orchestration frameworks. Extends the AI track (§6) and RAG track (§7) with framework-specific procedures. The core principle: **the agent's control flow is influenced by text the attacker may control, and its blast radius is the union of its tools' capabilities.** Map to OWASP LLM Top 10 (esp. LLM06 Excessive Agency), MITRE ATLAS, NIST AI RMF.

### 8A.1 Enumerate the orchestration
1. Identify the framework(s) and version(s); pull the dependency tree (LangChain community packages, integrations, remote prompt-hub artifacts).
2. Map the topology: chains/graphs, nodes and edges (LangGraph `StateGraph`), agents/executors, and multi-agent structure (supervisor/crew/group chat).
3. Inventory **every tool/function** the agent(s) can invoke and each tool's real capability and permission scope.
4. Identify state/memory: LangGraph checkpointers (`MemorySaver`, SQLite/Postgres savers), conversation/entity memory, and their storage and scoping.
5. Identify human-in-the-loop / interrupt/approval points and where they are enforced.

### 8A.2 Tool surface & excessive agency (LLM06)
6. **Flag dangerous built-ins:** `PythonREPLTool`, `ShellTool`, `requests`/`RequestsToolkit`, SQL agents, filesystem tools, `load_tools` with system access — confirm whether any are reachable from untrusted input. On an internet-facing agent, these are Critical by default.
7. **Least privilege:** for each tool, confirm the agent needs it; recommend removal of unneeded tools.
8. **Argument injection:** via direct and indirect prompt injection, attempt to control tool **arguments** — e.g., make an email tool send to an attacker address, a DB/SQL tool read unauthorized rows, an HTTP tool hit internal/metadata endpoints (SSRF). Confirm whether arguments are validated independently of model output.

### 8A.3 Control-flow & loop abuse
9. **Redirect the agent:** plant injection in a retrieved document or tool result and confirm whether it changes the agent's chosen actions (indirect injection → tool execution).
10. **Conditional-edge steering (LangGraph):** attempt to influence routing/conditional edges via injected content.
11. **Loop bounds (LLM10):** verify max iterations, `recursion_limit`, timeouts, and cost/token budgets; attempt to induce an unbounded or runaway-cost loop.

### 8A.4 State, memory & persistence
12. **Checkpointer isolation:** confirm LangGraph persisted state is scoped by tenant/user/thread; attempt to read or resume another thread's/user's state.
13. **Node output validation:** confirm state written by one node is validated before downstream nodes consume it; test propagation of a poisoned node output through the graph.
14. **Memory scoping:** test conversation/entity memory for cross-user/session bleed; attempt to persist injected instructions into memory (memory poisoning).

### 8A.5 Output handling & parsing
15. **Output parsers:** where model output is parsed into structured actions or objects, test for unsafe parsing/eval; attempt injection or object-injection through crafted model output (LLM05).
16. Confirm model output routed to any downstream sink (HTML/SQL/shell/code) is sanitized.

### 8A.6 Templates, callbacks & supply chain
17. **Prompt templates/hubs:** review whether templates are pulled from remote hubs (`hub.pull`) — treat as untrusted code; test template injection via user-controlled variables.
18. **Callbacks/tracing:** review LangSmith/other tracing config — confirm secrets/PII are not over-shared to external backends and keys are scoped.
19. **Supply chain (LLM03):** run SCA on the framework and all community integrations; confirm version pinning; flag unvetted remote artifacts.

### 8A.7 Multi-agent
20. **Cross-agent propagation:** in multi-agent setups (CrewAI, AutoGen, LangGraph supervisor), confirm injection compromising one agent cannot propagate to others; test confused-deputy (one agent using another's privileges).
21. **Human gates:** confirm approval/interrupt nodes on consequential actions are enforced server-side and cannot be bypassed via injection.

### 8A.8 Agentic RAG
22. If the agent has retrieval tools, apply the RAG track (§7): confirm retrieval is authorization-filtered per caller **before** documents enter the context, and vector-store tenant isolation holds.

**Deliverable:** completed Checklist §12A (+ §12 and §7 where applicable); tool inventory with capability/privilege analysis; injection→tool-execution PoCs; state/memory isolation results; framework SBOM/SCA.

---

## 9. Reporting & Closeout (All Tracks)

1. **Triage** every candidate finding: confirm exploitability, remove false positives.
2. **Score** each finding (CVSS + business context); assign severity.
3. **Document** using the finding template (Skills §12): title, severity, CVSS, business & technical impact, affected components, evidence, attack scenario, MITRE + OWASP mapping, root cause, remediation, verification steps, references.
4. **Prioritize** — order by risk; produce an executive summary of themes and top risks.
5. **Deliver** the report; walk stakeholders through Critical/High findings.
6. **Remediation validation & retest** — re-exercise each original attack; mark closed only with evidence.
7. **Update coverage matrix** — confirm every in-scope component was tested by at least one technique; document any gaps.

**Closeout exit criteria:** all findings triaged, scored, mapped, and evidenced; retest results recorded; coverage matrix complete; evidence stored/handled per RoE.

---

## Appendix A — Track-to-Checklist Map

| Track | Primary checklist sections |
|-------|----------------------------|
| Web application (§1) | 1, 2, 3, 4, 5, 6, 10, 11 |
| API (§2) | 1, 2, 3, 4, 7 |
| Cloud (§3) | 8, 9, 10 |
| Container/supply chain (§4) | 9 |
| Mobile (§5) | 1, 2, 4, 5 + API |
| AI/LLM (§6) | 12, 13 |
| RAG (§7) | 12.6, 12.7 + 12 |
| Azure AI Foundry (§8) | 12, 8 (cloud), 13 |
| Agentic frameworks (§8A) | 12A, 12, 7 (if retrieval) |

## Appendix B — Minimum Tooling by Track

| Track | Tools |
|-------|-------|
| Web/API | Burp Suite, OWASP ZAP, Nuclei |
| SAST/SCA | Semgrep, CodeQL, Trivy, Grype, Dependency-Check |
| Secrets | GitLeaks, Trufflehog |
| Cloud/IaC | Prowler, ScoutSuite, Defender for Cloud, Checkov, tfsec, KICS |
| Container | Trivy, Grype, Syft |
| AI red team | PyRIT, Garak, Promptfoo, Azure AI Foundry evaluations |
| Agentic frameworks | LangSmith (trace review), dependency SCA (Trivy/Grype/Snyk), custom tool-abuse harness, PyRIT/Garak |

*End of Playbook. Use with `Security-Assessment-Checklist.md` for criteria and `Software-Security-Assessment-Skills.md` for methodology.*
