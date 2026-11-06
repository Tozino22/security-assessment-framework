# AutoScan — Authorized Automated Vulnerability Scanner

A Docker-based orchestrator that runs open-source security scanners against an
**authorized** target and consolidates the output into one report. It is the
*automated breadth layer* of the assessment framework — the manual depth work
still lives in `Security-Assessment-Playbook.md`.

> ⚠ **Only scan systems you own or have SIGNED written authorization to test.**
> Unauthorized scanning is illegal (Criminal Code s.342.1 in Canada; equivalents
> elsewhere). AutoScan refuses to run without an authorization reference and an
> interactive confirmation.

## What it runs

| Mode | Tools (as Docker containers) | Finds |
|------|------------------------------|-------|
| **web** | nuclei, OWASP ZAP baseline, testssl.sh, header check | Known CVEs/misconfigs, common web issues, TLS/cipher weakness, missing headers |
| **mobile** | MobSF static analysis | Hardcoded secrets, insecure storage, weak crypto, permission/manifest issues |

## Requirements

- **Docker Desktop** (WSL2 backend on Windows) — running.
- **Python 3.9+**.
- For MobSF API automation: `pip install requests` (optional; without it, use the MobSF web UI at http://localhost:8000).

## Setup

```bash
python autoscan.py check      # verifies Docker, pulls scanner images (first run only)
```

## Use

```bash
# Web / API
python autoscan.py web --target https://example.com --authorized-by "Jane Doe, RoE-2026-014"

# Mobile (static)
python autoscan.py mobile --file ./app.apk --authorized-by "Jane Doe, RoE-2026-014"
```

You will be prompted to type `I AM AUTHORIZED` before anything runs. Pass
`--confirm` to skip the prompt in scripted use **only if you already hold signed
authorization**.

Results are written to `runs/<timestamp>_<mode>_<target>/`:
- `REPORT.md` — consolidated summary
- raw artifacts: `nuclei.jsonl`, `zap-report.html`/`zap.json`, `testssl.txt`, `headers.json`, `mobsf-report.pdf`/`.json`

## Important limitations (read this)

- **Automated scanning is breadth, not depth.** It does **not** find IDOR/BOLA,
  broken authorization, tenant isolation failures, business logic flaws, or
  AI/agentic issues. Those require the manual Playbook tracks. A scan alone is a
  *vulnerability assessment*, not a *penetration test*.
- **Triage everything.** Scanner output is a candidate list. Confirm each item and
  remove false positives before it becomes a reported finding.
- **Mobile:** MobSF covers the app binary. The **backend API is usually the higher-value
  target** — scan it separately with `web` mode.
- **Production safety:** ZAP baseline and nuclei are relatively non-intrusive but still
  generate traffic; run within your agreed window and throttling, and never against
  out-of-scope hosts.

## Workflow position

1. Signed **RoE** (`../Pentest-Authorization-RoE-Template.docx`).
2. **AutoScan** for breadth (this tool).
3. Manual **Playbook** tracks for depth.
4. Score against the **Checklist**; log in the **Findings Tracker**.
5. Report using the finding template in the **Skills** doc.

License: MIT — Northbridge.
