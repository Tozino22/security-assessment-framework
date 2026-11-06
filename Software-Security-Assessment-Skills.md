# Software Security Assessment — Skills & Methodology Reference

> **Document type:** Professional technical reference / grounding knowledge base
> **Audience:** Security assessors, AppSec architects, and AI security-assessment agents
> **Companion documents:** `Security-Assessment-Checklist.md` (pass/fail criteria & evidence), `Security-Assessment-Playbook.md` (step-by-step procedures)
> **Baseline standards:** OWASP Top 10 (2021→2025), OWASP API Top 10 (2023), ASVS 4.0.3/5.0, MASVS, OWASP LLM Top 10 (2025), NIST CSF 2.0, NIST SSDF (SP 800-218), NIST AI RMF (AI 100-1), NIST SP 800-53 Rev 5, PCI DSS v4.0.1, ISO/IEC 27001:2022, ISO/IEC 42001:2023, MITRE ATT&CK/ATLAS/CWE/CAPEC/D3FEND

---

## 1. Purpose

Software security assessment is the systematic evaluation of an application, its dependencies, its runtime environment, and its supporting AI components to determine whether the system resists misuse and protects the confidentiality, integrity, and availability of the data and functions it exposes.

An assessment produces **evidence-backed findings** with reproducible proof, risk-rated impact, and actionable remediation. It is not a scan; a scan is one input.

**Assessment goals:**

| Goal | What it establishes |
|------|---------------------|
| Identify vulnerabilities | Concrete, exploitable weaknesses in code, configuration, or dependencies |
| Identify design weaknesses | Architectural flaws (missing trust boundaries, broken authZ models) not visible in code alone |
| Validate security controls | That controls claimed to exist (MFA, encryption, rate limiting) actually function under adversarial conditions |
| Assess secure coding practices | Whether the SDLC produces secure code repeatably, not by chance |
| Evaluate deployment security | Cloud posture, IaC, container, and pipeline hardening |
| Evaluate AI security posture | Resistance of LLM/RAG/agent systems to prompt injection, data leakage, and model abuse |
| Provide remediation guidance | Prioritized, specific, verifiable fixes mapped to standards |

The output must be **defensible** (mapped to CWE/CVE/MITRE), **prioritized** (CVSS + business context), and **verifiable** (retest steps).

---

## 2. Security Assessment Methodology

The assessment lifecycle is phased. Each phase gates the next; findings loop back for validation.

### 2.1 Lifecycle phases

| # | Phase | Objective | Primary outputs |
|---|-------|-----------|-----------------|
| 1 | **Planning** | Rules of engagement, authorization, timeline, contacts, escalation | Signed RoE, test windows, out-of-scope list |
| 2 | **Scope definition** | Assets, endpoints, environments, data classes, exclusions | Scope matrix, asset inventory |
| 3 | **Threat modeling** | Attacker goals, entry points, trust boundaries, abuse cases | DFDs, STRIDE/LINDDUN model, prioritized threats |
| 4 | **Architecture review** | Design-level control assessment | Control gap list, trust-boundary map |
| 5 | **Source code review** | Manual + assisted review of security-critical paths | Code-level findings, insecure patterns |
| 6 | **Dependency review (SCA)** | Vulnerable/abandoned/malicious components, license risk | SBOM, vulnerable component list |
| 7 | **SAST** | Static detection of injection, crypto, authZ flaws | Triaged static findings |
| 8 | **DAST** | Runtime testing of the deployed app | Dynamic findings with requests/responses |
| 9 | **IAST** | Instrumented runtime correlation (where available) | High-confidence runtime findings |
| 10 | **Secrets scanning** | Exposed credentials in code, history, artifacts | Secret inventory, rotation actions |
| 11 | **Container security** | Image, base OS, runtime, registry posture | CVE list, misconfig list |
| 12 | **Infrastructure review** | Network, host, segmentation, patching | Infra misconfigurations |
| 13 | **Cloud configuration review** | CSPM against benchmarks (CIS/CCM) | Cloud posture findings |
| 14 | **IAM review** | Identities, roles, privilege, federation | Excess-privilege findings, path analysis |
| 15 | **API security testing** | AuthZ, BOLA/BFLA, mass assignment, schema abuse | API findings |
| 16 | **Business logic testing** | Workflow abuse, state manipulation, race conditions | Logic-flaw findings |
| 17 | **AI security testing** | Prompt injection, data leakage, agent/tool abuse | AI findings |
| 18 | **Manual penetration testing** | Chained exploitation, real attack paths | Proven attack chains |
| 19 | **Reporting** | Consolidated, prioritized, evidence-backed findings | Assessment report |
| 20 | **Risk scoring** | CVSS + business impact contextualization | Risk register entries |
| 21 | **Remediation validation** | Confirm fixes address root cause | Verification records |
| 22 | **Retesting** | Re-exercise the original attack | Pass/fail closure |

### 2.2 Methodology principles

- **Threat-model first.** Testing without a model produces coverage gaps. The model drives which paths get manual attention.
- **Depth over breadth on critical paths.** Authentication, authorization, payment, and data-export flows receive manual review regardless of tool output.
- **Tools find candidates; humans confirm exploitability.** Every automated finding is triaged before it becomes a reported finding.
- **Chain, don't isolate.** A medium + a medium can equal a critical (e.g., IDOR + missing rate limit = mass extraction).
- **Assume breach for blast-radius.** Evaluate lateral movement and privilege escalation from any single compromised component.

### 2.3 Coverage model

Map every in-scope component to at least one technique. A component with no technique assigned is a coverage gap. Track this explicitly (see Skills Matrix, §13).

---

## 3. Applicable Standards and Frameworks

### 3.1 OWASP

| Framework | Use in assessment |
|-----------|-------------------|
| **OWASP Top 10 (2021; 2025 update)** | Web application risk taxonomy; baseline categories for web findings (A01 Broken Access Control → A10 SSRF; 2025 adds/reorders around supply chain & misconfig) |
| **OWASP API Security Top 10 (2023)** | API-specific taxonomy: API1 BOLA, API2 Broken Auth, API3 BOPLA, API4 Unrestricted Resource Consumption, API5 BFLA, API6 Sensitive Business Flows, API7 SSRF, API8 Misconfig, API9 Improper Inventory, API10 Unsafe Consumption |
| **OWASP ASVS (4.0.3 / 5.0)** | Verification requirements by level (L1 opportunistic, L2 standard, L3 high-assurance). Use as the requirements checklist for depth |
| **OWASP MASVS** | Mobile verification standard (MASVS-STORAGE, -CRYPTO, -AUTH, -NETWORK, -PLATFORM, -CODE, -RESILIENCE) |
| **OWASP AI Security & Privacy Guide** | AI-specific control guidance |
| **OWASP GenAI Security Project / LLM Top 10 (2025)** | LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption |

### 3.2 MITRE

| Framework | Use |
|-----------|-----|
| **ATT&CK** | Map post-exploitation TTPs; describe attacker behavior in findings |
| **ATLAS** | Adversarial ML tactics/techniques; the ATT&CK analog for AI systems |
| **CWE** | Root-cause weakness classification for every finding |
| **CAPEC** | Attack pattern classification; links CWE to real attack techniques |
| **D3FEND** | Defensive countermeasure taxonomy; map remediations |

### 3.3 NIST

| Framework | Use |
|-----------|-----|
| **CSF 2.0** | Program-level control mapping across GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER |
| **SSDF (SP 800-218)** | Secure development practices (PO, PS, PW, RV groups); assess the SDLC itself |
| **AI RMF (AI 100-1)** | AI risk governance: GOVERN, MAP, MEASURE, MANAGE |
| **SP 800-53 Rev 5** | Control catalog for detailed control assessment (AC, AU, SC, SI, SR, IA, CP, etc.) |

### 3.4 CIS, PCI, ISO, CSA, Microsoft

| Framework | Use |
|-----------|-----|
| **CIS Critical Security Controls v8** | Prioritized safeguards; program maturity |
| **CIS Benchmarks** | Host, OS, cloud, container hardening baselines (pass/fail config checks) |
| **PCI DSS v4.0.1** | Requirements 6 (secure development), 6.4.3/11.6.1 (payment page scripts), 8 (auth/MFA), 10 (logging), 11 (testing) for payment-handling apps |
| **SOC 2 Trust Services Criteria** | Security, Availability, Confidentiality, Processing Integrity, Privacy — control evidence expectations |
| **ISO/IEC 27001:2022 & 27002:2022** | ISMS controls; Annex A control mapping |
| **ISO/IEC 42001:2023** | AI management system requirements; governance of AI lifecycle |
| **CSA Cloud Controls Matrix (CCM)** | Cloud control domains mapped to CSP responsibilities |
| **Microsoft SDL** | Secure development practices and threat-modeling integration |
| **Microsoft Threat Modeling** | STRIDE-per-element methodology + Threat Modeling Tool |
| **Microsoft AI Security Guidance / Responsible AI Standard** | Azure AI/Copilot security & RAI validation |

### 3.5 Cross-framework mapping approach

Every finding carries at minimum: one **CWE**, one **OWASP category** (Top 10 / API / LLM as applicable), and, where post-exploitation is relevant, one **MITRE ATT&CK or ATLAS technique**. Program-level gaps additionally map to **CSF 2.0** and the relevant compliance control (PCI/SOC 2/ISO). This makes findings portable across the client's existing compliance obligations.

---

## 4. Threat Modeling Skills

Threat modeling establishes *what can go wrong* before testing *whether it does*. Perform it at design time and re-run when architecture changes.

### 4.1 Methodologies

| Method | Best for | Core question |
|--------|----------|---------------|
| **STRIDE** | Per-component technical threats | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege — applied per element |
| **PASTA** | Risk-centric, business-aligned | 7-stage process linking business objectives to attacker simulation |
| **LINDDUN** | Privacy threats | Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance |
| **Attack Trees** | Goal decomposition | How can an attacker achieve goal X? |
| **Abuse Cases** | Misuse of legitimate features | How is this feature weaponized? |
| **Trust Boundary Analysis** | Data crossing privilege levels | Where does trust change and is data validated at that crossing? |
| **Data Flow Diagrams (DFD)** | Foundation for STRIDE | Where does data enter, rest, and exit? |

### 4.2 Process

1. **Decompose** the system into external entities, processes, data stores, and data flows.
2. **Draw trust boundaries** (internet↔app, app↔DB, tenant↔tenant, app↔LLM, app↔third-party).
3. **Enumerate threats** per element using STRIDE (technical) and LINDDUN (privacy).
4. **Rank** by likelihood × impact; tie each to an abuse case.
5. **Define mitigations** and map to controls; unmitigated threats become test cases.

### 4.3 AI-specific threat modeling

| Focus | Threats to enumerate |
|-------|----------------------|
| **AI Threat Modeling** | Extend DFDs to include the model, prompt assembly, retrieval sources, tools/functions, and memory as elements with their own trust boundaries |
| **Prompt Injection Threat Modeling** | Direct injection (user input), indirect injection (retrieved/третьей-party content), and injection via tool outputs |
| **Model Supply Chain Analysis** | Provenance of base models, fine-tuning data, embeddings, plugins/MCP servers, and their update integrity |

**Key AI trust boundaries:** untrusted content entering the context window (RAG documents, tool results, web content) is the highest-value boundary — treat all retrieved content as attacker-controlled until proven otherwise.

---

## 5. Software Security Review Skills

Assessment competencies per domain. Each maps to CWE families and ASVS chapters.

### 5.1 Identity & access

| Area | What to verify | Common weaknesses (CWE) |
|------|----------------|-------------------------|
| **Authentication** | Credential strength, MFA enforcement, anti-automation, secure recovery | CWE-287, CWE-306, CWE-620 |
| **Authorization** | Every request authorized server-side against the authenticated principal | CWE-285, CWE-862, CWE-863 |
| **RBAC** | Roles enforce least privilege; no client-side role trust | CWE-269 |
| **ABAC** | Attribute evaluation (tenant, region, ownership) enforced server-side and complete | CWE-863 |
| **Session management** | Secure cookies, idle/absolute timeout, rotation on privilege change, revocation | CWE-384, CWE-613 |
| **Token validation** | Signature, issuer, audience, expiry, algorithm pinning | CWE-347 |
| **JWT** | `alg` not `none`, no key confusion (RS↔HS), short expiry, no sensitive data in payload | CWE-347, CWE-345 |
| **OAuth2** | PKCE for public clients, exact redirect-URI match, state param, no token in URL | CWE-601 |
| **OIDC** | ID-token validation, nonce, correct flow selection | CWE-347 |
| **SAML** | Signature validation, no XML signature wrapping, replay protection | CWE-347, CWE-91 |

### 5.2 Input/output & injection

| Area | Verify | CWE |
|------|--------|-----|
| **Input validation** | Server-side allow-list validation, canonicalization before checks | CWE-20 |
| **Output encoding** | Context-aware encoding (HTML/JS/URL/attr) | CWE-116 |
| **SQL injection** | Parameterized queries/ORM binding everywhere | CWE-89 |
| **Command injection** | No shell concatenation; use safe APIs/arg arrays | CWE-78 |
| **XSS (reflected/stored/DOM)** | Encoding + CSP + trusted types | CWE-79 |
| **CSRF** | Anti-CSRF tokens or SameSite + origin checks on state-changing requests | CWE-352 |
| **Path traversal** | Canonicalize and confine to base dir | CWE-22 |
| **Secure file uploads** | Type/size validation, out-of-webroot storage, AV scan, no execution | CWE-434 |
| **XML attacks (XXE)** | Disable external entities/DTDs | CWE-611 |
| **Deserialization** | No untrusted deserialization; use safe formats/allow-lists | CWE-502 |
| **SSRF** | Egress allow-list, block link-local/metadata IPs, no user-controlled URLs to internal services | CWE-918 |
| **RCE** | Eliminate dynamic eval, template injection, unsafe reflection | CWE-94, CWE-95 |

### 5.3 Data protection & crypto

| Area | Verify | CWE |
|------|--------|-----|
| **Cryptography** | Strong algorithms (AES-GCM, SHA-256+), no ECB, authenticated encryption, proper IV/nonce | CWE-327, CWE-329 |
| **Secrets management** | No hard-coded secrets; vault/KMS; rotation | CWE-798 |
| **Secure storage** | Encryption at rest, field-level for sensitive data, key separation | CWE-311 |
| **Sensitive data exposure** | Minimization, masking, no secrets in logs/URLs/errors | CWE-200, CWE-532 |
| **Memory management** | Bounds checking, safe allocation (native code) | CWE-119, CWE-787 |

### 5.4 Operational & protocol

| Area | Verify | CWE |
|------|--------|-----|
| **Logging** | Security events logged, tamper-evident, no sensitive data | CWE-778, CWE-532 |
| **Monitoring** | Detection of auth failures, anomalies, control failures | — |
| **Secure configuration** | Hardened defaults, no debug in prod, security headers | CWE-16, CWE-1188 |
| **Error handling** | No stack traces/internal detail to clients | CWE-209 |
| **Business logic** | Workflow integrity, state validation, no negative/overflow abuse | CWE-840 |
| **Rate limiting** | Per-user/tenant/token throttling on sensitive & expensive endpoints | CWE-770 |
| **Replay protection** | Nonces/timestamps on sensitive operations | CWE-294 |
| **GraphQL security** | Query depth/complexity limits, introspection disabled in prod, field authZ | CWE-770 |
| **gRPC security** | mTLS, message-size limits, per-method authZ | — |
| **WebSocket security** | Origin validation, authN on connect, per-message authZ | CWE-346 |

---

## 6. API Security Assessment Skills

APIs are the dominant attack surface for modern applications. Assess against the OWASP API Top 10 (2023).

| API type | Assessment focus |
|----------|------------------|
| **REST** | Object/function-level authZ, mass assignment, resource consumption, versioning/inventory |
| **GraphQL** | Query depth/complexity/aliasing DoS, introspection, field-level authZ, batching abuse |
| **SOAP** | XXE, WS-Security misuse, XML signature wrapping |
| **gRPC** | mTLS, reflection exposure, message limits, per-method authZ |
| **Webhooks** | Signature verification, replay protection, SSRF via callback URLs |

**Core API test areas:**

| Area | What it means | OWASP API |
|------|---------------|-----------|
| **BOLA** | Object references not authorized against caller (IDOR at object level) | API1 |
| **Broken authentication** | Weak/absent token validation, credential stuffing | API2 |
| **BOPLA / Mass Assignment** | Client sets properties it should not (e.g., `isAdmin`) | API3/API6 |
| **BFLA** | Access to functions above the caller's role | API5 |
| **Unrestricted resource consumption** | No rate/size limits; cost & DoS | API4 |
| **Sensitive business flows** | Automation of high-value flows (checkout, transfers) | API6 |
| **SSRF** | Server fetches attacker-controlled URLs | API7 |
| **Misconfiguration** | CORS, verbose errors, missing headers | API8 |
| **Improper inventory / Shadow APIs** | Undocumented, deprecated, or staging endpoints exposed | API9 |
| **Unsafe consumption of third-party APIs** | Trusting upstream data/redirects blindly | API10 |
| **API Gateway security** | Central authN/authZ, rate limiting, schema validation, WAF | — |
| **Schema validation** | Strict request/response schema enforcement | — |
| **API inventory** | Complete, current inventory incl. versions and environments | API9 |

---

## 7. Cloud Security Assessment Skills

Assess cloud posture against CIS Benchmarks, CSA CCM, and provider well-architected security pillars. Covers **Azure, AWS, GCP**.

| Domain | Assessment focus | Azure | AWS | GCP |
|--------|------------------|-------|-----|-----|
| **Identity** | Least privilege, no standing admin, MFA, federation, conditional access | Entra ID, PIM, Conditional Access | IAM, SCPs, IAM Identity Center | Cloud IAM, Org Policies |
| **Networking** | Segmentation, private endpoints, egress control, no 0.0.0.0/0 to sensitive ports | NSG, Private Link, Firewall | Security Groups, PrivateLink | VPC-SC, Firewall |
| **Storage** | No public buckets/blobs, encryption, access logging | Blob/Storage, private access | S3 block-public-access | GCS uniform access |
| **Key management** | Managed keys, rotation, HSM where required, access policies | Key Vault, Managed HSM | KMS, CloudHSM | Cloud KMS |
| **Containers** | Image scanning, no privileged, network policy, runtime security | AKS, ACR, Defender | EKS, ECR | GKE, Artifact Registry |
| **Serverless** | Least-privilege exec roles, secret handling, event-source validation | Functions | Lambda | Cloud Functions |
| **Secrets** | Vault-based, no env-plaintext, rotation | Key Vault | Secrets Manager | Secret Manager |
| **Managed identities** | Used instead of static keys, scoped tightly | Managed Identities | IAM Roles for service | Workload Identity |
| **Cloud logging** | Control-plane + data-plane logs, retention, tamper-resistance | Azure Monitor, Activity Log | CloudTrail | Cloud Audit Logs |
| **Posture management (CSPM)** | Continuous misconfig detection against benchmarks | Defender for Cloud | Security Hub | Security Command Center |
| **IaC review** | Security scanning of templates pre-deploy | Bicep, ARM | CloudFormation | Deployment Manager |

**IaC review skills:** Terraform, Bicep, ARM, CloudFormation — scan with Checkov/tfsec/KICS; verify no plaintext secrets, encryption enabled, network restrictions, logging on, least-privilege roles. Treat drift between IaC and running config as a finding.

---

## 8. AI Solution Security Assessment

The most rapidly evolving domain. Assess against **OWASP LLM Top 10 (2025)**, **MITRE ATLAS**, **NIST AI RMF**, and **ISO/IEC 42001**.

### 8.1 LLM & prompt-layer threats

| Threat | Description | LLM Top 10 / ATLAS |
|--------|-------------|--------------------|
| **Direct prompt injection** | User input overrides system instructions | LLM01 |
| **Indirect prompt injection** | Malicious instructions in retrieved/third-party content executed by the model | LLM01 |
| **Prompt leaking / system prompt leakage** | Extraction of hidden system prompt/instructions | LLM07 |
| **Jailbreaking** | Bypassing safety guardrails | LLM01 |
| **Sensitive information disclosure** | Model reveals PII, secrets, or other users' data | LLM02 |
| **Improper output handling** | Model output used unsanitized (XSS, SQLi, RCE downstream) | LLM05 |
| **Misinformation / hallucination** | Confident false output relied upon | LLM09 |
| **Unbounded consumption** | Cost/DoS via expensive generations | LLM10 |

### 8.2 Model-level threats

| Threat | Description | ATLAS |
|--------|-------------|-------|
| **Model theft** | Extraction of model weights or behavior via querying | Exfiltration |
| **Model inversion** | Reconstructing training data from outputs | ML Attack Staging |
| **Membership inference** | Determining if a record was in training data | — |
| **Training data poisoning** | Corrupting training/fine-tuning data | LLM04 / Poison Training Data |
| **Data leakage** | Training data or context leaking through outputs | LLM02 |

### 8.3 RAG & retrieval threats

| Threat | Description | LLM Top 10 |
|--------|-------------|-----------|
| **RAG security** | Injection & leakage through the retrieval pipeline | LLM08 |
| **Vector database security** | AuthZ on the vector store, tenant isolation of embeddings | LLM08 |
| **Embedding poisoning** | Malicious documents skew retrieval | LLM04/08 |
| **Retrieval attacks** | Crafting queries to surface unauthorized documents | LLM08 |
| **Cross-document / cross-tenant leakage** | Retrieval returns another tenant's or user's data | LLM02/08 |

### 8.4 Agent, tool & plugin threats

| Threat | Description | LLM Top 10 |
|--------|-------------|-----------|
| **Excessive agency** | Model has more permissions/autonomy than needed | LLM06 |
| **Unsafe tool invocation** | Model calls tools with attacker-influenced parameters | LLM06 |
| **Function calling abuse** | Injection steering function-call arguments | LLM06 |
| **Plugin security** | Untrusted plugins with broad access | LLM06 |
| **MCP (Model Context Protocol) security** | Trust of MCP servers, tool-poisoning, credential scope | LLM03/06 |
| **Memory poisoning** | Persisting malicious content into long-term memory | LLM04 |
| **Multi-agent risks** | Injection propagating across agents; confused-deputy between agents | LLM06 |

### 8.5 Governance, safety & responsible AI

| Area | What to assess |
|------|----------------|
| **Guardrails evaluation** | Input/output filtering effectiveness against jailbreaks and injection |
| **Content filtering** | Harmful-content detection coverage and bypass resistance |
| **Responsible AI validation** | Alignment to RAI principles; documented review |
| **Bias / fairness testing** | Disparate outcomes across protected attributes |
| **Explainability** | Traceability of decisions where required |
| **Human oversight** | Human-in-the-loop on consequential actions |
| **AI governance** | ISO 42001 / NIST AI RMF program controls |
| **AI audit logging** | Prompts, retrievals, tool calls, and outputs logged for investigation |
| **Model monitoring** | Drift, abuse, and anomaly detection in production |

### 8.6 Agentic framework security (LangChain, LangGraph & peers)

Agentic frameworks add orchestration layers — chains, graphs, tools, memory, and callbacks — each of which is its own attack surface beyond the base model. Applies to **LangChain, LangGraph, LlamaIndex, AutoGen, CrewAI, Semantic Kernel, Haystack, OpenAI Agents SDK/Assistants, and custom orchestrators**.

| Framework element | Security concern | LLM Top 10 |
|-------------------|------------------|-----------|
| **Chains / pipelines** (LangChain `Chain`, LCEL) | Untrusted data flowing between steps carries injection; each link is a trust boundary | LLM01/05 |
| **Agents & executors** (LangChain `AgentExecutor`, ReAct) | The agent decides which tools to call from model output — prompt injection becomes tool execution | LLM06 |
| **Graph state & nodes** (LangGraph `StateGraph`) | Shared mutable state across nodes; a poisoned node output propagates through the graph; conditional edges steered by injected content | LLM04/06 |
| **Checkpointers / persistence** (LangGraph `MemorySaver`, SQLite/Postgres savers) | Persisted graph state is a memory-poisoning target and a cross-session/cross-user leakage risk if not tenant-scoped | LLM04 |
| **Tools / toolkits** (`Tool`, `@tool`, toolkits) | Over-broad tools (shell, Python REPL, requests, SQL) give the model dangerous capability; tool arguments are injectable | LLM06 |
| **Dangerous built-ins** | `PythonREPLTool`, `ShellTool`, `requests`/`RequestsToolkit`, SQL agents, `load_tools` with system access — arbitrary code/command/SSRF | LLM06 |
| **Retrievers / vector stores** (LangChain retrievers, LlamaIndex) | Retrieval authZ and tenant isolation (same as RAG §8.3) | LLM02/08 |
| **Memory** (`ConversationBufferMemory`, entity memory) | Cross-user/session bleed; injection persisted into memory | LLM04 |
| **Callbacks / tracing** (LangChain callbacks, LangSmith) | Prompts, keys, and PII sent to tracing backends; over-broad telemetry | LLM02 |
| **Output parsers** | Model output parsed/eval'd into structured actions — unsafe parsing → injection/RCE | LLM05 |
| **Prompt templates / hubs** (`hub.pull`) | Templates pulled from remote hubs are untrusted code paths; template injection via user-controlled variables | LLM03 |
| **Human-in-the-loop nodes** (LangGraph interrupts) | Missing or bypassable approval gates on consequential actions | LLM06 |
| **Multi-agent orchestration** (CrewAI, AutoGen, LangGraph supervisor) | Injection propagates agent-to-agent; confused-deputy; unbounded agent loops (cost/DoS) | LLM06/10 |

**Framework-specific rules of thumb:**

- **Treat every tool as a privilege grant.** The maximum damage of an agent is the union of all its tools' capabilities under attacker-chosen arguments. Minimize the toolset; never expose shell/REPL/unrestricted-HTTP tools to an internet-facing agent.
- **The agent loop is attacker-influenced control flow.** Because the model chooses the next action from text it may not control, indirect prompt injection in any retrieved document or tool result can redirect the entire agent. Validate tool arguments independently of the model.
- **LangGraph state is shared memory.** Scope checkpointer state by tenant/user/thread; never let one thread's persisted state be readable by another. Validate state written by nodes before downstream nodes consume it.
- **Bound the loop.** Enforce max iterations, recursion limits (`recursion_limit`), timeouts, and token/cost budgets — unbounded agent/graph loops are both a DoS and a runaway-cost vector (LLM10).
- **Gate consequential actions.** Human-in-the-loop / approval interrupts must be enforced server-side and non-bypassable via injection.
- **Pin and vet framework supply chain.** LangChain/community integrations pull many transitive packages and remote prompt-hub artifacts; apply SCA and pin versions (LLM03).

### 8.7 Infrastructure & platform (Azure focus)

| Area | What to assess |
|------|----------------|
| **Inference endpoint security** | AuthN/authZ, network restriction, rate limiting on model endpoints |
| **API key protection** | Keys in vault, rotation, per-consumer scoping, no client-side keys |
| **Azure OpenAI security** | Private networking, Managed Identity, content filters, quota controls, data-retention settings |
| **Azure AI Foundry security** | Project/hub isolation, connection security, evaluation & content-safety integration, RBAC on resources, private endpoints |
| **Microsoft Copilot security** | Data-access scoping (Graph permissions), tenant boundary, prompt/response governance |

**RAG-specific isolation rule:** every retrieval must be filtered by the caller's authorization *before* documents enter the context window — never rely on the model to withhold unauthorized content it has already been given.

---

## 9. Testing Techniques

| Technique | Description | When to use |
|-----------|-------------|-------------|
| **Manual testing** | Human-driven exploration & exploitation | Business logic, authZ, chained attacks |
| **Automated testing** | Tool-driven scanning | Breadth, regression, known patterns |
| **Code review** | Manual reading of security-critical code | AuthZ logic, crypto, input handling |
| **SAST** | Static source analysis | Early SDLC, injection/crypto flaws |
| **DAST** | Runtime black-box testing | Deployed app behavior |
| **IAST** | Instrumented runtime analysis | High-confidence correlation |
| **SCA** | Dependency vulnerability & license analysis | Supply chain |
| **Fuzz testing** | Malformed/random input generation | Parsers, APIs, file handlers |
| **Mutation testing** | Assess test-suite quality | Verifying test coverage effectiveness |
| **Chaos engineering** | Fault injection | Resilience/availability validation |
| **Penetration testing** | Goal-oriented exploitation | Prove real attack paths |
| **Red teaming** | Adversary emulation, objective-based | Program-level defense validation |
| **Purple teaming** | Red + blue collaboration | Detection/response tuning |
| **AI red teaming** | Adversarial prompting & abuse of AI systems | LLM/RAG/agent safety & security |
| **Adversarial AI testing** | Crafted inputs to induce model failure | Robustness, evasion, poisoning resistance |

---

## 10. Security Assessment Checklist

> The complete, itemized checklist with pass/fail criteria, evidence requirements, and severity guidance is maintained in the companion document **`Security-Assessment-Checklist.md`**. It covers: identity & access, injection & I/O, data protection, API, cloud & IaC, container, secrets, logging/monitoring, business logic, and AI/LLM/RAG. Use it as the execution artifact; use this document for the underlying rationale.

Summary domains to cover in every assessment:

- [ ] Authentication & MFA
- [ ] Authorization (RBAC/ABAC, BOLA/BFLA)
- [ ] Session & token security
- [ ] Input validation & output encoding
- [ ] Injection (SQL/command/XSS/SSRF/deserialization)
- [ ] Cryptography & secrets management
- [ ] Sensitive data handling & privacy
- [ ] API security (OWASP API Top 10)
- [ ] Cloud posture & IaC
- [ ] Container & supply chain
- [ ] Logging, monitoring & error handling
- [ ] Business logic & rate limiting
- [ ] AI/LLM/RAG/agent security
- [ ] Governance & responsible AI

---

## 11. Evidence Collection

Every finding must be reproducible from its evidence. Collect and store securely (findings evidence often contains secrets/PII — encrypt it).

| Evidence type | Purpose | Notes |
|---------------|---------|-------|
| **Screenshots** | Visual proof of state/behavior | Timestamped; redact live secrets |
| **HTTP requests/responses** | Reproducible request that triggers the issue | Full request incl. headers; sanitized before sharing |
| **Logs** | Corroborate behavior, show detection gaps | Server, app, cloud, audit |
| **Source code** | Root-cause location | File + line reference |
| **Configurations** | Misconfiguration proof | IaC snippet, cloud export, `terraform plan` |
| **API responses** | Data exposure / authZ proof | Show cross-tenant/object access |
| **Cloud configuration** | Posture proof | CSPM export, CLI output |
| **Attack paths** | Chained-exploit narrative | Diagram of the chain |
| **Risk evidence** | Impact substantiation | Data classes reachable, records exposed |
| **CVE / CWE / MITRE mappings** | Classification & portability | One CWE minimum per finding |

**Chain-of-evidence rules:** timestamp everything; preserve raw artifacts; record the exact environment/version; never include unmasked production secrets in the deliverable.

---

## 12. Reporting

Findings are the product of the assessment. Each finding is a self-contained, actionable record.

**Required fields per finding:**

| Field | Content |
|-------|---------|
| **Title** | Specific, impact-oriented (not "XSS found") |
| **Severity** | Critical/High/Medium/Low/Info (business-contextualized) |
| **CVSS** | v3.1/v4.0 base + environmental where relevant; show vector string |
| **Business impact** | What it means to the organization (revenue, data, compliance) |
| **Technical impact** | CIA effect at the technical level |
| **Affected components** | Endpoints, files, services, versions |
| **Evidence** | Reproducible proof (see §11) |
| **Attack scenario** | Step-by-step realistic exploitation narrative |
| **MITRE mapping** | ATT&CK/ATLAS technique IDs |
| **OWASP mapping** | Top 10 / API / LLM category |
| **Root cause** | Underlying weakness (CWE), not just symptom |
| **Remediation** | Specific, verifiable fix; map to D3FEND/control |
| **Verification steps** | How to confirm the fix during retest |
| **References** | CWE, CVE, vendor advisories, standard sections |

**Report structure:** executive summary (risk posture, top themes, trend) → methodology & scope → findings by severity → strategic recommendations → appendices (evidence, tooling, coverage matrix). Executives read the summary; engineers read the findings; auditors read the mappings.

---

## 13. Skills Matrix

Maps each assessment skill to purpose, framework, technique, tools, evidence, and inherent risk level. (Abbreviated; extend per engagement.)

| Skill | Purpose | Framework | Technique | Tools | Evidence | Risk |
|-------|---------|-----------|-----------|-------|----------|------|
| Access control testing | Verify authZ enforcement | OWASP A01 / API1/5 | Manual + DAST | Burp, Postman | Cross-object API responses | Critical |
| Injection testing | Detect SQLi/cmd/XSS | OWASP A03 | SAST+DAST+manual | Semgrep, ZAP, Burp | Request/response, code | Critical |
| Authentication review | Verify authN & MFA | OWASP A07 / API2 | Manual + config | Burp, IdP config | Auth flow captures | Critical |
| Crypto review | Validate crypto use | OWASP A02 | Code review | CodeQL, manual | Code, config | High |
| Secrets scanning | Find exposed secrets | SSDF PS | SCA/secret scan | GitLeaks, Trufflehog | Repo/history hits | High |
| Dependency (SCA) | Vulnerable components | OWASP A06 | SCA | Trivy, Grype, Dependency-Check | SBOM, CVE list | High |
| Cloud posture | Misconfig detection | CIS/CCM | CSPM | Prowler, ScoutSuite, Defender | Config export | High |
| IaC review | Pre-deploy config safety | SSDF | Static IaC scan | Checkov, tfsec, KICS | Template + findings | High |
| Container security | Image/runtime posture | CIS Docker/K8s | Scan + config | Trivy, Grype | CVE + config | High |
| API security | OWASP API Top 10 | API Top 10 | Manual + DAST | Burp, ZAP, schema | API captures | Critical |
| Business logic | Workflow abuse | OWASP A04 | Manual | Burp, custom | Sequence proof | High |
| Prompt injection | LLM instruction override | LLM01 | AI red team | PyRIT, Garak, manual | Prompt/response | Critical |
| RAG isolation | Retrieval authZ/leakage | LLM02/08 | AI red team | Custom, PyRIT | Cross-tenant retrieval | Critical |
| Agent/tool safety | Excessive agency/tool abuse | LLM06 | AI red team | Custom harness | Tool-call logs | Critical |
| AI governance | RAI & AI RMF controls | ISO 42001 / AI RMF | Review | Foundry evals | Policy & eval records | High |

---

## 14. Recommended Tools

| Category | Open-source | Commercial / platform |
|----------|-------------|-----------------------|
| **Web/API proxy & DAST** | OWASP ZAP | Burp Suite Pro |
| **Recon/network** | Nmap, Nuclei | — |
| **SAST** | Semgrep, CodeQL | SonarQube, GitHub Advanced Security (CodeQL) |
| **SCA / SBOM** | OWASP Dependency-Check, Grype, Syft, Trivy | Snyk, Mend |
| **Secrets scanning** | GitLeaks, Trufflehog | GitHub Advanced Security secret scanning |
| **Container/image** | Trivy, Grype | Defender for Containers |
| **IaC scanning** | Checkov, tfsec, KICS | — |
| **Cloud posture (CSPM)** | Prowler, ScoutSuite | Microsoft Defender for Cloud, AWS Security Hub, GCP SCC |
| **Cloud/SecOps** | — | Microsoft Security Copilot, Microsoft Dev Box (secure dev env), Azure DevOps security tools |
| **AI red teaming** | PyRIT, Garak, Promptfoo | Azure AI Foundry evaluations & content safety |
| **Fuzzing** | AFL++, libFuzzer, RESTler | — |

**Tool discipline:** tools generate candidates; assessors confirm exploitability and business impact. Never report raw scanner output as findings.

---

## 15. Continuous Security Validation

Assessment is not a point-in-time event; it is an activity embedded in the SDLC and operations.

### 15.1 Secure SDLC / DevSecOps integration

| SDLC phase | Security activity | Gate |
|------------|-------------------|------|
| Plan/Design | Threat modeling, security requirements (ASVS) | Design review sign-off |
| Code | IDE SAST, secrets pre-commit hooks, secure-coding standards | Pre-commit block |
| Build (CI) | SAST, SCA, IaC scan, secrets scan | Fail build on high severity |
| Test | DAST, IAST, API tests | Fail pipeline on new criticals |
| Release | Image scan, signing, SBOM generation | Block unsigned/vulnerable artifacts |
| Deploy | CSPM, config validation, least-privilege check | Block non-compliant infra |
| Operate | Continuous monitoring, drift detection, runtime protection | Alert + auto-remediate |

### 15.2 AI-specific continuous validation

- Automated evaluation suites (safety, injection resistance, RAG isolation) run in CI on prompt/model/retrieval changes.
- Production monitoring for prompt-injection patterns, anomalous tool calls, and cost/consumption spikes.
- Re-run AI red-team scenarios on every model or system-prompt change.

### 15.3 Metrics

Track: mean time to remediate by severity, escaped-defect rate, coverage (% components with assigned technique), dependency freshness, secrets-exposure rate, and AI-eval pass rate. Improving trend lines, not single scores, indicate program maturity.

---

*End of Skills & Methodology Reference. See `Security-Assessment-Checklist.md` for execution criteria and `Security-Assessment-Playbook.md` for step-by-step procedures.*
