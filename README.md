# Security Assessment Framework

A complete, authorization-first methodology for running security assessments —
from the rules of engagement through to a findings register a GRC platform will accept.

Roughly 1,350 lines of working methodology plus **AutoScan**, a Docker-based
orchestrator that automates the breadth layer.

Built by **Tosin Aina** — CISSP, CISA, CRISC, ISO/IEC 27001 Lead Auditor, ISACA AAISM.

> ⚠ **Authorization is not optional.** Every procedure here assumes signed, written
> permission to test the target. Unauthorized scanning is a criminal offence
> (Criminal Code s.342.1 in Canada; equivalents elsewhere). AutoScan refuses to run
> without an authorization reference and interactive confirmation.

---

## What's here

| File | What it is |
|---|---|
| **`Security-Assessment-Playbook.md`** | Step-by-step procedures across seven tracks: pre-engagement, web, API, cloud, container & supply chain, mobile (MASVS), and **AI / LLM systems** |
| **`Security-Assessment-Checklist.md`** | Pass/fail criteria with required evidence and severity guidance — authentication, session & token management, authorization, injection, cryptography & secrets, privacy, OWASP API Top 10 |
| **`Web-Pentest-Field-Guide.md`** | Command-level field guide: recon, mapping, discovery, exploitation |
| **`Software-Security-Assessment-Skills.md`** | Methodology reference covering threat modelling, code review, API, and cloud assessment skills, mapped to applicable standards |
| **`autoscan/`** | Docker-orchestrated scanner that runs open-source tools against an authorized target and consolidates output into one report |
| **`Pentest-Authorization-RoE-Template.docx`** | Rules of engagement template — scope, windows, escalation, out-of-scope |
| **`Pentest-Findings-Tracker.xlsx`** | Findings register with CVSS vectors and severity rollup formulas |
| **`VA-vs-Pentest-Service-Guide.docx`** | Scoping guide: when a vulnerability assessment is the right answer and when it is not |

## The design principle

Most assessment material stops at *finding* things. This framework is built around the
step that usually breaks: carrying a technical finding through to an owned, treated,
evidenced entry in a risk register.

**AutoScan handles breadth. The playbook handles depth. The checklist decides what counts
as a finding. The tracker is where it lands.**

## AutoScan

```
cd autoscan
python autoscan.py --help
```

Requires Docker. See `autoscan/README.md` for scanner modes and the authorization gate.

## A note on the sample data

The findings tracker ships with one illustrative row (an IDOR against a generic
`/api/orders/{id}` endpoint). No real client, system or engagement data appears
anywhere in this repository.

## Licence

MIT.
