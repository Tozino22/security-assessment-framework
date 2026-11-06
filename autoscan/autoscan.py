#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AutoScan — authorized automated vulnerability scanning orchestrator
===================================================================
Runs open-source security scanners as Docker containers against an
AUTHORIZED target and consolidates the output into one report.

Web/API mode : nuclei + OWASP ZAP baseline + testssl.sh + header check
Mobile mode  : MobSF static analysis of an .apk/.ipa

Built for Northbridge security services.  License: MIT.

────────────────────────────────────────────────────────────────────
⚠  LEGAL: Only scan systems you own or have SIGNED WRITTEN AUTHORIZATION
   to test. Unauthorized scanning is illegal (e.g. Criminal Code s.342.1
   in Canada). This tool REFUSES to run without an authorization reference.
────────────────────────────────────────────────────────────────────

Requires: Python 3.9+, Docker Desktop (WSL2 backend on Windows).

Usage:
    python autoscan.py check
    python autoscan.py web    --target https://example.com --authorized-by "Jane Doe, RoE-2026-014"
    python autoscan.py mobile --file ./app.apk            --authorized-by "Jane Doe, RoE-2026-014"

Add --confirm to skip the interactive authorization prompt (for scripted use
only when you already hold signed authorization).
"""

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse

# Docker images (open-source)
IMG_NUCLEI  = "projectdiscovery/nuclei:latest"
IMG_ZAP     = "ghcr.io/zaproxy/zaproxy:stable"
IMG_TESTSSL = "drwetter/testssl.sh:latest"
IMG_MOBSF   = "opensecurity/mobile-security-framework-mobsf:latest"

RUN_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs")


# ───────────────────────── helpers ─────────────────────────

def have_docker():
    """True only if the Docker CLI exists AND the engine is reachable.
    Uses server-version probe (not `docker info`, which can exit nonzero on
    warnings even when the engine is healthy)."""
    if not shutil.which("docker"):
        return False
    try:
        p = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, text=True, timeout=30)
        return p.returncode == 0 and bool(p.stdout.strip())
    except Exception:
        return False


def run(cmd, outfile=None, timeout=1800):
    """Run a command, stream nothing, capture output to file and return (rc, text)."""
    print(f"    $ {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        text = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        text = f"[timeout after {timeout}s]"
    except Exception as e:
        text = f"[error: {e}]"
    if outfile:
        with open(outfile, "w", encoding="utf-8", errors="replace") as f:
            f.write(text)
    return text


def pull(image):
    print(f"  pulling {image} ...")
    subprocess.run(["docker", "pull", image], capture_output=True)


def authorize(args, target_desc):
    print("\n" + "=" * 68)
    print("  AUTHORIZED SECURITY SCANNING — AutoScan")
    print("=" * 68)
    print(f"  Target        : {target_desc}")
    print(f"  Authorized by : {args.authorized_by}")
    print(f"  Timestamp     : {datetime.datetime.now().isoformat(timespec='seconds')}")
    print("-" * 68)
    if not args.authorized_by or len(args.authorized_by.strip()) < 3:
        sys.exit("REFUSED: --authorized-by is required (name + signed RoE reference).")
    if args.confirm:
        return
    print("  By continuing you confirm you hold SIGNED written authorization")
    print("  (Rules of Engagement) to scan the target above, and that it is in")
    print("  scope and within the agreed testing window.")
    resp = input("  Type 'I AM AUTHORIZED' to proceed: ").strip()
    if resp != "I AM AUTHORIZED":
        sys.exit("REFUSED: authorization not confirmed. Nothing was scanned.")


def new_run_dir(kind, label):
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in label)[:40]
    d = os.path.join(RUN_ROOT, f"{ts}_{kind}_{safe}")
    os.makedirs(d, exist_ok=True)
    return d


def dockerpath(p):
    # Docker Desktop on Windows accepts absolute paths; normalise separators
    return os.path.abspath(p).replace("\\", "/")


# ───────────────────────── commands ─────────────────────────

def cmd_check(_args):
    print("Environment check:")
    ok = have_docker()
    print(f"  Docker running : {'YES' if ok else 'NO — install/start Docker Desktop (WSL2 backend)'}")
    if not ok:
        sys.exit(1)
    print("  Pulling scanner images (first run only, may take a few minutes)...")
    for img in (IMG_NUCLEI, IMG_ZAP, IMG_TESTSSL, IMG_MOBSF):
        pull(img)
    print("  Done. Ready to scan.")


def cmd_web(args):
    if not have_docker():
        sys.exit("Docker is not available. Run 'python autoscan.py check'.")
    parsed = urllib.parse.urlparse(args.target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        sys.exit("Target must be a full URL, e.g. https://example.com")
    host = parsed.netloc
    authorize(args, args.target)

    outdir = new_run_dir("web", host)
    print(f"\n  Output: {outdir}\n")
    results = {}

    print("  [1/4] TLS / cipher audit (testssl.sh)")
    pull(IMG_TESTSSL)
    results["testssl"] = run(
        ["docker", "run", "--rm", IMG_TESTSSL, "--quiet", "--color", "0", args.target],
        os.path.join(outdir, "testssl.txt"))

    print("  [2/4] Known-vuln & misconfig templates (nuclei)")
    pull(IMG_NUCLEI)
    run(["docker", "run", "--rm", "-v", f"{dockerpath(outdir)}:/out", IMG_NUCLEI,
         "-u", args.target, "-severity", "critical,high,medium,low",
         "-jsonl", "-o", "/out/nuclei.jsonl", "-nc"],
        os.path.join(outdir, "nuclei.log"))
    results["nuclei"] = _read_nuclei(os.path.join(outdir, "nuclei.jsonl"))

    print("  [3/4] Web app baseline scan (OWASP ZAP)")
    pull(IMG_ZAP)
    run(["docker", "run", "--rm", "-v", f"{dockerpath(outdir)}:/zap/wrk:rw", IMG_ZAP,
         "zap-baseline.py", "-t", args.target, "-r", "zap-report.html", "-J", "zap.json", "-I"],
        os.path.join(outdir, "zap.log"))
    results["zap"] = _read_zap(os.path.join(outdir, "zap.json"))

    print("  [4/4] Security header check")
    results["headers"] = _header_check(args.target, outdir)

    report = _web_report(args.target, args.authorized_by, results, outdir)
    print(f"\n  ✔ Consolidated report: {report}")
    print("    NOTE: automated scanning finds surface issues only. Follow with the manual")
    print("    Playbook tracks (authZ/IDOR, business logic, AI) for a full assessment.")


def cmd_mobile(args):
    if not have_docker():
        sys.exit("Docker is not available. Run 'python autoscan.py check'.")
    if not os.path.isfile(args.file) or not args.file.lower().endswith((".apk", ".ipa", ".xapk", ".zip")):
        sys.exit("Provide a valid mobile app file (.apk / .ipa).")
    authorize(args, os.path.basename(args.file))

    outdir = new_run_dir("mobile", os.path.basename(args.file))
    print(f"\n  Output: {outdir}\n")
    print("  Starting MobSF (static analysis)...")
    pull(IMG_MOBSF)

    # Start MobSF detached
    cid = subprocess.run(
        ["docker", "run", "-d", "--rm", "-p", "8000:8000", IMG_MOBSF],
        capture_output=True, text=True).stdout.strip()
    if not cid:
        sys.exit("Could not start MobSF container.")
    try:
        print("  Waiting for MobSF to come up (~30-60s)...")
        time.sleep(45)
        # API key is printed in container logs
        logs = subprocess.run(["docker", "logs", cid], capture_output=True, text=True).stdout
        apikey = _extract_mobsf_key(logs)
        if not apikey:
            print("  Could not auto-read the MobSF API key. MobSF is running at http://localhost:8000")
            print("  Open it in a browser, upload the app manually, and export the report.")
            input("  Press Enter when finished to stop MobSF... ")
            return
        import urllib.request
        # Upload
        print("  Uploading app to MobSF...")
        up = _mobsf_upload(args.file, apikey)
        if not up:
            print("  Upload failed. Use the web UI at http://localhost:8000 manually.")
            input("  Press Enter to stop MobSF... ")
            return
        print("  Running static scan (this can take a few minutes)...")
        _mobsf_scan(up, apikey)
        pdf = os.path.join(outdir, "mobsf-report.pdf")
        _mobsf_pdf(up, apikey, pdf)
        jsonrep = os.path.join(outdir, "mobsf-report.json")
        _mobsf_json(up, apikey, jsonrep)
        print(f"  ✔ MobSF report: {pdf}")
        _mobile_report(args.file, args.authorized_by, jsonrep, outdir)
    finally:
        subprocess.run(["docker", "stop", cid], capture_output=True)
    print("\n  NOTE: also scan the app's BACKEND API with:  python autoscan.py web --target <api-url> ...")
    print("        The backend is usually the higher-value target.")


# ───────────────────── parsers / readers ─────────────────────

def _read_nuclei(path):
    findings = []
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
                info = j.get("info", {})
                findings.append({
                    "severity": info.get("severity", "info"),
                    "name": info.get("name", j.get("template-id", "")),
                    "matched": j.get("matched-at", j.get("host", "")),
                })
            except Exception:
                continue
    return findings


def _read_zap(path):
    findings = []
    if os.path.isfile(path):
        try:
            j = json.load(open(path, encoding="utf-8", errors="replace"))
            for site in j.get("site", []):
                for alert in site.get("alerts", []):
                    risk = alert.get("riskdesc", "").split(" ")[0]
                    findings.append({
                        "severity": risk.lower(),
                        "name": alert.get("alert" , alert.get("name", "")),
                        "count": len(alert.get("instances", [])),
                    })
        except Exception:
            pass
    return findings


def _header_check(target, outdir):
    import urllib.request
    wanted = ["strict-transport-security", "content-security-policy", "x-content-type-options",
              "x-frame-options", "referrer-policy", "permissions-policy"]
    result = {}
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "AutoScan"})
        with urllib.request.urlopen(req, timeout=20) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
        for h in wanted:
            result[h] = hdrs.get(h, "MISSING")
        sc = hdrs.get("set-cookie", "")
        result["cookie_secure"] = "Secure" in sc if sc else "n/a"
        result["cookie_httponly"] = "HttpOnly" in sc if sc else "n/a"
    except Exception as e:
        result["error"] = str(e)
    with open(os.path.join(outdir, "headers.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result


def _extract_mobsf_key(logs):
    import re
    m = re.search(r"REST API Key[:\s]+([0-9a-f]{32,})", logs, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"api[_ ]key[\"'\s:=]+([0-9a-f]{40})", logs, re.IGNORECASE)
    return m.group(1) if m else None


def _mobsf_upload(path, apikey):
    import requests  # optional; fall back if missing
    try:
        with open(path, "rb") as f:
            r = requests.post("http://localhost:8000/api/v1/upload",
                              files={"file": (os.path.basename(path), f, "application/octet-stream")},
                              headers={"Authorization": apikey}, timeout=120)
        return r.json() if r.status_code == 200 else None
    except Exception as e:
        print(f"    upload error: {e}")
        return None


def _mobsf_scan(up, apikey):
    import requests
    try:
        requests.post("http://localhost:8000/api/v1/scan",
                      data={"hash": up.get("hash"), "scan_type": up.get("scan_type"),
                            "file_name": up.get("file_name")},
                      headers={"Authorization": apikey}, timeout=1200)
    except Exception as e:
        print(f"    scan error: {e}")


def _mobsf_pdf(up, apikey, outpath):
    import requests
    try:
        r = requests.post("http://localhost:8000/api/v1/download_pdf",
                          data={"hash": up.get("hash")}, headers={"Authorization": apikey}, timeout=300)
        if r.status_code == 200:
            open(outpath, "wb").write(r.content)
    except Exception as e:
        print(f"    pdf error: {e}")


def _mobsf_json(up, apikey, outpath):
    import requests
    try:
        r = requests.post("http://localhost:8000/api/v1/report_json",
                          data={"hash": up.get("hash")}, headers={"Authorization": apikey}, timeout=300)
        if r.status_code == 200:
            open(outpath, "w", encoding="utf-8").write(r.text)
    except Exception as e:
        print(f"    json error: {e}")


# ───────────────────────── reports ─────────────────────────

def _sev_rank(s):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}.get(s.lower(), 5)


def _web_report(target, auth, results, outdir):
    path = os.path.join(outdir, "REPORT.md")
    now = datetime.datetime.now().isoformat(timespec="seconds")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# AutoScan Web Report\n\n")
        f.write(f"- **Target:** {target}\n- **Authorized by:** {auth}\n- **Scanned:** {now}\n")
        f.write(f"- **Tooling:** nuclei, OWASP ZAP baseline, testssl.sh, header check\n\n")
        f.write("> Automated scan = breadth only. It does NOT cover authorization/IDOR, business logic, "
                "tenant isolation, or AI/agentic issues. Follow with the manual Playbook tracks.\n\n")

        nuclei = sorted(results.get("nuclei", []), key=lambda x: _sev_rank(x["severity"]))
        f.write(f"## nuclei findings ({len(nuclei)})\n\n")
        if nuclei:
            f.write("| Severity | Finding | Location |\n|---|---|---|\n")
            for n in nuclei:
                f.write(f"| {n['severity'].upper()} | {n['name']} | {n['matched']} |\n")
        else:
            f.write("_None reported (or scan produced no parseable output)._\n")
        f.write("\n")

        zap = sorted(results.get("zap", []), key=lambda x: _sev_rank(x["severity"]))
        f.write(f"## OWASP ZAP alerts ({len(zap)})\n\n")
        if zap:
            f.write("| Risk | Alert | Instances |\n|---|---|---|\n")
            for z in zap:
                f.write(f"| {z['severity'].upper()} | {z['name']} | {z.get('count','')} |\n")
        else:
            f.write("_None reported. See zap-report.html for full detail._\n")
        f.write("\n")

        h = results.get("headers", {})
        f.write("## Security headers\n\n| Header | Value |\n|---|---|\n")
        for k, v in h.items():
            f.write(f"| {k} | {v} |\n")
        f.write("\n")

        f.write("## Raw artifacts\n\n")
        f.write("- `testssl.txt` — TLS/cipher detail\n- `nuclei.jsonl` — raw nuclei output\n")
        f.write("- `zap-report.html` / `zap.json` — full ZAP report\n- `headers.json` — header check\n\n")
        f.write("## Next steps (manual)\n\n")
        f.write("1. Triage every item above (remove false positives).\n")
        f.write("2. Run Playbook §1 (web) & §2 (API): authZ/IDOR, business logic, tenant isolation.\n")
        f.write("3. Log confirmed issues in `Pentest-Findings-Tracker.xlsx`.\n")
    return path


def _mobile_report(appfile, auth, jsonrep, outdir):
    path = os.path.join(outdir, "REPORT.md")
    now = datetime.datetime.now().isoformat(timespec="seconds")
    summary = {}
    if os.path.isfile(jsonrep):
        try:
            j = json.load(open(jsonrep, encoding="utf-8", errors="replace"))
            summary = j.get("appsec", {}) or {}
        except Exception:
            pass
    with open(path, "w", encoding="utf-8") as f:
        f.write("# AutoScan Mobile Report (MobSF static analysis)\n\n")
        f.write(f"- **App:** {os.path.basename(appfile)}\n- **Authorized by:** {auth}\n- **Scanned:** {now}\n\n")
        if summary:
            for k in ("high", "warning", "info", "secure", "hotspot"):
                if k in summary:
                    f.write(f"- **{k.title()} issues:** {len(summary[k]) if isinstance(summary[k], list) else summary[k]}\n")
        f.write("\nSee `mobsf-report.pdf` / `mobsf-report.json` for full static-analysis detail "
                "(hardcoded secrets, insecure storage, weak crypto, permissions, manifest issues).\n\n")
        f.write("## Next steps (manual)\n\n")
        f.write("1. Review MobSF findings; confirm real issues.\n")
        f.write("2. **Scan the backend API** (`python autoscan.py web --target <api-url> ...`) — usually the real target.\n")
        f.write("3. Dynamic testing (Frida/objection) for cert pinning, runtime storage — see Playbook §5.\n")
        f.write("4. Log confirmed issues in `Pentest-Findings-Tracker.xlsx`.\n")
    print(f"  ✔ Consolidated report: {path}")
    return path


# ───────────────────────── main ─────────────────────────

def main():
    ap = argparse.ArgumentParser(description="AutoScan — authorized automated vulnerability scanning")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("check", help="verify Docker and pull scanner images")

    w = sub.add_parser("web", help="scan a web app / API")
    w.add_argument("--target", required=True, help="full URL, e.g. https://example.com")
    w.add_argument("--authorized-by", required=True, help='name + signed RoE ref, e.g. "Jane Doe, RoE-2026-014"')
    w.add_argument("--confirm", action="store_true", help="skip interactive authorization prompt")

    m = sub.add_parser("mobile", help="static-analyze a mobile app (.apk/.ipa) via MobSF")
    m.add_argument("--file", required=True, help="path to .apk / .ipa")
    m.add_argument("--authorized-by", required=True, help='name + signed RoE ref')
    m.add_argument("--confirm", action="store_true", help="skip interactive authorization prompt")

    args = ap.parse_args()
    if args.cmd == "check":
        cmd_check(args)
    elif args.cmd == "web":
        cmd_web(args)
    elif args.cmd == "mobile":
        cmd_mobile(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
