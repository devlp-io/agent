"""
evidence.report — audience-tiered reports.
- exec summary (1 page): what was tested, top risks, count by severity
- tech report: per-finding with PoC, request/response, remediation
- wraps reporter.py so make report still works
"""
import os
import re
import json
import pathlib
from datetime import datetime, timezone

# try to import original reporter for markdown fallback
try:
    import sys
    sys.path.insert(0, str(pathlib.Path.home() / "agent"))
    import reporter as _orig_reporter
    _HAVE_REPORTER = True
except Exception:
    _HAVE_REPORTER = False


SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _count_by_sev(findings):
    out = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = (f.get("sev") or "info").lower()
        out[s] = out.get(s, 0) + 1
    return out


def _header(title, target):
    return (
        f"# {title}\n\n"
        f"**Target:** {target}  \n"
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}Z  \n"
        f"**Scanner:** ag v2  \n\n"
    )


def build_exec_summary(run_dir, state):
    target = state.get("target", "?")
    findings = state.get("findings", [])
    endpoints = state.get("endpoints", [])
    probes = state.get("probes", [])
    walks = state.get("walks", [])
    secrets = state.get("secrets", [])
    creds = state.get("creds", [])
    oob = state.get("oob", [])
    attacks = state.get("attacks", [])
    chains = state.get("chains", [])

    sev = _count_by_sev(findings)
    top = [f for f in findings if (f.get("sev") or "").lower() in ("critical", "high")][:10]

    lines = [_header("Executive Summary", target)]
    lines.append("## Scope\n")
    lines.append(f"- endpoints discovered: **{len(endpoints)}**")
    lines.append(f"- probes performed: **{len(probes)}**")
    lines.append(f"- id walks: **{len(walks)}**")
    lines.append(f"- secrets recovered: **{len(secrets)}**")
    lines.append(f"- credentials recovered: **{len(creds)}**")
    lines.append(f"- oob callbacks: **{len(oob)}**")
    lines.append(f"- attack attempts: **{len(attacks)}**")
    lines.append(f"- exploit chains: **{len(chains)}**\n")

    lines.append("## Findings by severity\n")
    for s in SEV_ORDER:
        lines.append(f"- {s.upper()}: **{sev[s]}**")
    lines.append("")

    if top:
        lines.append("## Top risks\n")
        for f in top:
            lines.append(f"### [{f.get('sev','?').upper()}] {f.get('title','?')}\n")
            lines.append(f"{str(f.get('evidence',''))[:400]}\n")

    out = run_dir / "EXEC_SUMMARY.md"
    out.write_text("\n".join(lines))
    return out


def build_tech_report(run_dir, state):
    target = state.get("target", "?")
    findings = state.get("findings", [])
    lines = [_header("Technical Report", target)]

    # group by severity
    for s in SEV_ORDER:
        subset = [f for f in findings if (f.get("sev") or "info").lower() == s]
        if not subset:
            continue
        lines.append(f"## {s.upper()} ({len(subset)})\n")
        for i, f in enumerate(subset, 1):
            lines.append(f"### {i}. {f.get('title','?')}\n")
            lines.append(f"**Severity:** {s.upper()}  ")
            ev = str(f.get("evidence", ""))
            lines.append(f"**Evidence:**\n\n```\n{ev[:3000]}\n```\n")
            # remediation hints by keyword
            lines.append(f"**Remediation hint:** {_remediation_for(f.get('title',''))}\n")

    # attack chronology
    attacks = state.get("attacks", [])
    if attacks:
        lines.append("## Attack chronology\n")
        for a in attacks:
            lines.append(f"- `{a.get('ts', a.get('started',''))}` **{a.get('tool','?')}** → "
                         f"{a.get('target','?')} → {a.get('result','?')}")
        lines.append("")

    out = run_dir / "TECH_REPORT.md"
    out.write_text("\n".join(lines))
    return out


def _remediation_for(title):
    t = (title or "").lower()
    table = {
        "openapi": "Remove /openapi.json, /docs, /redoc from production. If they must stay, require authentication.",
        "swagger": "Remove swagger UI from production builds.",
        "idor": "Enforce object-level authorization. Every request must verify the caller owns the referenced object.",
        "walk": "Enforce object-level authorization on the walked endpoint.",
        "unauth": "Require authentication on the endpoint. Move to a protected route group.",
        "jwt": "Reject alg:none. Use strong HS256 secret (>32 bytes) or RS256 with rotating keys.",
        "rate limit": "Add per-user + per-IP rate limiting on all auth endpoints.",
        "sqli": "Use parameterized queries. Never concatenate user input into SQL.",
        "ssrf": "Allowlist outbound destinations. Block RFC1918 + metadata IPs.",
        "xss": "Escape output. Add CSP. Use a modern template engine with auto-escaping.",
        "secret": "Rotate the leaked key immediately. Move secrets to environment / vault.",
        "cred": "Rotate the leaked credentials. Enable MFA. Investigate for unauthorized access.",
        "cve": "Patch to the fixed version listed in the CVE advisory.",
        "version": "Remove version strings from responses. Keep the service up to date.",
        "shell": "Restrict shell access. Use least-privilege service accounts.",
        "rce": "Patch immediately. Restrict code-execution surfaces. Add WAF signatures.",
    }
    for k, v in table.items():
        if k in t:
            return v
    return "Review the finding, add compensating controls, and retest after fix."


def build_poc_pack(run_dir, state):
    """Emit a per-finding PoC file with request/response if available."""
    poc_dir = run_dir / "pocs"
    poc_dir.mkdir(exist_ok=True)
    findings = state.get("findings", [])
    written = []
    for i, f in enumerate(findings, 1):
        sev = (f.get("sev") or "info").lower()
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", f.get("title", "finding"))[:60]
        fp = poc_dir / f"{i:03d}_{sev}_{slug}.md"
        body = [
            f"# PoC: {f.get('title','?')}",
            f"**Severity:** {sev.upper()}  ",
            f"**Recorded:** {datetime.now(timezone.utc).isoformat()}Z\n",
            "## Evidence\n",
            "```",
            str(f.get("evidence", ""))[:5000],
            "```\n",
            "## Remediation\n",
            _remediation_for(f.get("title", "")),
            "",
        ]
        fp.write_text("\n".join(body))
        written.append(fp)
    return written


def build_all(run_dir, state):
    run_dir = pathlib.Path(run_dir)
    exec_md = build_exec_summary(run_dir, state)
    tech_md = build_tech_report(run_dir, state)
    pocs = build_poc_pack(run_dir, state)

    # delegate to original reporter if available, for PDF / HTML
    if _HAVE_REPORTER:
        try:
            _orig_reporter.generate_all(str(run_dir), state, log=print)
        except Exception as e:
            print(f"[report] original reporter failed: {e}")

    return {
        "exec": str(exec_md),
        "tech": str(tech_md),
        "pocs": [str(p) for p in pocs],
        "count": len(pocs),
    }


if __name__ == "__main__":
    import tempfile
    tmp = pathlib.Path(tempfile.mkdtemp())
    demo_state = {
        "target": "demo.test",
        "findings": [
            {"sev": "high", "title": "Unauth data walk on /api/users",
             "evidence": "300 rows recovered ids 1..300"},
            {"sev": "medium", "title": "OpenAPI spec exposed at /openapi.json",
             "evidence": "150 endpoints disclosed"},
            {"sev": "low", "title": "Server version disclosed: nginx/1.18.0",
             "evidence": "Server: nginx/1.18.0"},
        ],
        "endpoints": [{"method": "GET", "url": "https://demo.test/api/users"}],
        "probes": [{"method": "GET", "url": "https://demo.test/api/users", "no_auth_2xx": True}],
    }
    res = build_all(tmp, demo_state)
    print(json.dumps(res, indent=2))
    print()
    for p in [res["exec"], res["tech"]] + res["pocs"]:
        print(f"--- {p}")
        print(pathlib.Path(p).read_text()[:500])
        print()
