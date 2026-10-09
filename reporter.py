cat > ~/agent/reporter.py <<'PYEOF'
"""
reporter.py — rich report + PDF generation for the agent.
Reads state.json + scan dir, produces:
  REPORT.md    — comprehensive markdown (everything found)
  report.html  — styled HTML (severity colour-coded)
  report.pdf   — final PDF (weasyprint → wkhtmltopdf → chromium)
"""
import os, re, json, subprocess, pathlib, html as html_mod
from datetime import datetime

try:
    import markdown as md_lib
    _HAVE_MD = True
except Exception:
    _HAVE_MD = False


def _sev_sort(f):
    return {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get((f.get("sev") or "").lower(), 5)

def _clip(s, n=8000):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + f"\n... [truncated, {len(s)-n} more chars]"

def _read_if_exists(p, limit=200000):
    try:
        p = pathlib.Path(p)
        if not p.exists() or not p.is_file(): return None
        return p.read_text(errors="ignore")[:limit]
    except Exception:
        return None

def _list_files(run_dir):
    out = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and not p.name.startswith("."):
            try:
                rel = p.relative_to(run_dir)
                size = p.stat().st_size
                out.append((str(rel), size))
            except Exception: pass
    return out

def _tail_file(path, n=200):
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception:
        return ""


def build_report_markdown(run_dir, state):
    run_dir = pathlib.Path(run_dir)
    target = state.get("target", run_dir.parent.name)
    now = datetime.now().isoformat()

    findings = sorted(state.get("findings", []) or [], key=_sev_sort)
    endpoints = state.get("endpoints", []) or []
    probes    = state.get("probes", []) or []
    secrets   = state.get("secrets", []) or []
    creds     = state.get("creds", []) or []
    walks     = state.get("walks", []) or []
    params    = state.get("params", []) or []
    api_maps  = state.get("api_maps", []) or []
    searches  = state.get("web_searches", []) or []
    notes     = state.get("notes", []) or []
    methods   = state.get("methods_used", []) or []
    tech      = state.get("tech_stack", []) or []

    sev_counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        sev_counts[(f.get("sev") or "info").lower()] = sev_counts.get((f.get("sev") or "info").lower(), 0) + 1

    M = []
    M.append(f"# Security Assessment Report")
    M.append(f"")
    M.append(f"**Target:** `{target}`  ")
    M.append(f"**Generated:** {now}  ")
    M.append(f"**Scan dir:** `{run_dir}`")
    M.append("")

    M.append("## Executive Summary")
    M.append("")
    M.append(f"Total findings: **{len(findings)}**")
    M.append("")
    M.append("| Severity | Count |")
    M.append("|---|---|")
    for s in ("critical","high","medium","low","info"):
        M.append(f"| {s.capitalize()} | {sev_counts.get(s,0)} |")
    M.append("")
    M.append(f"- Endpoints discovered: **{len(endpoints)}**")
    M.append(f"- Probes executed: **{len(probes)}**")
    M.append(f"- Secrets leaked: **{len(secrets)}**")
    M.append(f"- Credentials captured: **{len(creds)}**")
    M.append(f"- ID walks performed: **{len(walks)}**")
    M.append(f"- Parameter finds: **{len(params)}**")
    M.append(f"- API maps: **{len(api_maps)}**")
    M.append(f"- Web searches: **{len(searches)}**")
    M.append(f"- Notes: **{len(notes)}**")
    M.append("")

    M.append("## Target & Scope")
    M.append("")
    M.append(f"- Target: `{target}`")
    M.append(f"- Scan root: `{run_dir}`")
    if tech:
        M.append(f"- Detected tech: {', '.join(tech)}")
    if methods:
        M.append(f"- Methodologies used: {', '.join(methods)}")
    M.append("")

    if findings:
        M.append("## Findings")
        M.append("")
        for f in findings:
            sev = (f.get("sev") or "info").upper()
            M.append(f"### [{sev}] {f.get('title','(untitled)')}")
            M.append("")
            M.append(f"**Severity:** {sev}")
            M.append("")
            M.append("**Evidence:**")
            M.append("")
            M.append("```")
            M.append(_clip(f.get("evidence",""), 8000))
            M.append("```")
            M.append("")
    else:
        M.append("## Findings")
        M.append("")
        M.append("_No findings recorded._")
        M.append("")

    M.append("## Endpoints")
    M.append("")
    if endpoints:
        by_host = {}
        for e in endpoints:
            url = e.get("url","")
            m = re.match(r"https?://([^/]+)", url)
            host = m.group(1) if m else "?"
            by_host.setdefault(host, []).append(e)
        for host in sorted(by_host.keys()):
            M.append(f"### `{host}` — {len(by_host[host])} endpoint(s)")
            M.append("")
            M.append("| Method | URL | Note |")
            M.append("|---|---|---|")
            for e in by_host[host][:500]:
                note = (e.get("note") or "").replace("|","\\|")[:120]
                M.append(f"| {e.get('method','GET')} | `{e.get('url','')}` | {note} |")
            M.append("")
    else:
        M.append("_No endpoints recorded._")
        M.append("")

    M.append("## Probes")
    M.append("")
    if probes:
        for p in probes[:200]:
            meth = p.get("method","GET"); url = p.get("url","")
            unauth = "  **[UNAUTH 2xx]**" if p.get("no_auth_2xx") else ""
            auto = " (auto)" if p.get("auto") else ""
            M.append(f"### `{meth} {url}`{auto}{unauth}")
            M.append("")
            M.append("| Variant | Status | Size | Type |")
            M.append("|---|---|---|---|")
            for r in p.get("results", []) or []:
                M.append(f"| {r.get('variant','?')} | {r.get('status','?')} | {r.get('size','?')} | {(r.get('type') or '')[:60]} |")
            M.append("")
    else:
        M.append("_No probes recorded._")
        M.append("")

    if params:
        M.append("## Parameter Discovery")
        M.append("")
        for p in params:
            M.append(f"### `{p.get('method','GET')} {p.get('url','')}`")
            M.append("")
            M.append(f"Tried {p.get('tried',0)} params. Baseline size: {p.get('baseline_size',0)}b.")
            M.append("")
            if p.get("hits"):
                M.append("| Param | Status | Size | JSON |")
                M.append("|---|---|---|---|")
                for h in p["hits"]:
                    M.append(f"| `{h.get('param')}` | {h.get('status')} | {h.get('size')} | {h.get('as_json')} |")
                M.append("")
                for h in p["hits"][:3]:
                    M.append(f"**Preview (`{h.get('param')}`):**")
                    M.append("")
                    M.append("```")
                    M.append(_clip(h.get("preview",""), 1500))
                    M.append("```")
                    M.append("")
            else:
                M.append("_No working params found._")
                M.append("")

    M.append("## Secrets")
    M.append("")
    if secrets:
        M.append("| Type | Source | Value (truncated) |")
        M.append("|---|---|---|")
        for s in secrets[:300]:
            val = (s.get("value") or "")[:80]
            M.append(f"| {s.get('kind','?')} | `{s.get('path','')}` | `{val}` |")
        M.append("")
        M.append("### Full secret values")
        M.append("")
        for s in secrets[:100]:
            M.append(f"- **{s.get('kind','?')}** `{s.get('path','')}`")
            M.append(f"  ```")
            M.append(f"  {s.get('value','')}")
            M.append(f"  ```")
        M.append("")
    else:
        M.append("_No secrets recorded._")
        M.append("")

    M.append("## Credentials")
    M.append("")
    if creds:
        M.append("| User | Pass | Where |")
        M.append("|---|---|---|")
        for c in creds:
            M.append(f"| `{c.get('user','')}` | `{c.get('pass','')}` | `{c.get('where','')}` |")
        M.append("")
    else:
        M.append("_No credentials recorded._")
        M.append("")

    M.append("## ID Walks")
    M.append("")
    if walks:
        M.append("| Method | URL | Param | Range | Hits | File |")
        M.append("|---|---|---|---|---|---|")
        for w in walks:
            M.append(f"| {w.get('method','')} | `{w.get('url','')}` | `{w.get('param','')}` | {w.get('start','')}..{w.get('end','')} | **{w.get('hits',0)}** | `{w.get('file','')}` |")
        M.append("")
        M.append("### Walk data samples")
        M.append("")
        for w in walks:
            f = w.get("file","")
            if not f: continue
            p = pathlib.Path(f)
            if not p.exists():
                p = run_dir / f
            if not p.exists(): continue
            M.append(f"**`{w.get('method','')} {w.get('url','')}` (param `{w.get('param','')}`) — first 5 rows:**")
            M.append("")
            M.append("```")
            lines = p.read_text(errors="ignore").splitlines()[:5]
            M.append("\n".join(lines))
            M.append("```")
            M.append("")
    else:
        M.append("_No ID walks performed._")
        M.append("")

    if api_maps:
        M.append("## API Maps")
        M.append("")
        for am in api_maps:
            base = am.get("base","")
            if am.get("mode") == "openapi":
                M.append(f"### `{base}` — openapi mode")
                M.append("")
                M.append(f"- Spec: `{am.get('spec','')}`")
                M.append(f"- Endpoints: **{am.get('endpoints',0)}**")
                M.append(f"- No-declared-security: **{am.get('unauth_declared',0)}**")
                M.append("")
            else:
                M.append(f"### `{base}` — folder/file enumeration")
                M.append("")
                lf = am.get("live_folders",[]) or []
                M.append(f"- Live folders: {', '.join('`'+f+'`' for f in lf) if lf else '_(none)_'}")
                fh = am.get("file_hits",[]) or []
                M.append(f"- File hits: **{len(fh)}**")
                M.append("")
                if fh:
                    M.append("| Status | Size | Path |")
                    M.append("|---|---|---|")
                    for h in fh[:200]:
                        M.append(f"| {h.get('status','')} | {h.get('size','')} | `{h.get('folder','')}/{h.get('file','')}` |")
                    M.append("")

    if searches:
        M.append("## Web Research")
        M.append("")
        for s in searches[:30]:
            M.append(f"### Query: `{s.get('query','')}`")
            M.append("")
            for i, r in enumerate(s.get("results", [])[:10], 1):
                M.append(f"{i}. [{r.get('title','')}]({r.get('url','')})")
                if r.get("snippet"):
                    M.append(f"   - {r['snippet'][:200]}")
            M.append("")

    if notes:
        M.append("## Analyst Notes")
        M.append("")
        for n in notes:
            M.append(f"- {n}")
        M.append("")

    M.append("## Raw Command Log (last 300 lines)")
    M.append("")
    M.append("```")
    M.append(_tail_file(run_dir / "live_commands.log", 300))
    M.append("```")
    M.append("")

    fm = _read_if_exists(run_dir / "findings.md")
    if fm:
        M.append("## Raw findings.md")
        M.append("")
        M.append("```markdown")
        M.append(_clip(fm, 20000))
        M.append("```")
        M.append("")

    M.append("## File Inventory")
    M.append("")
    M.append("| Path | Size |")
    M.append("|---|---|")
    for rel, size in _list_files(run_dir):
        if rel in ("report.html","report.pdf"):
            continue
        M.append(f"| `{rel}` | {size} |")
    M.append("")

    M.append("---")
    M.append("")
    M.append(f"_Report generated by agent at {now}_")
    M.append("")

    return "\n".join(M)


HTML_CSS = """
@page {
  size: A4;
  margin: 18mm 15mm 18mm 15mm;
  @top-center {
    content: "Security Assessment — {{TARGET}}";
    font-size: 9px; color: #666; font-family: 'DejaVu Sans', sans-serif;
  }
  @bottom-right {
    content: "page " counter(page) " / " counter(pages);
    font-size: 9px; color: #666; font-family: 'DejaVu Sans', sans-serif;
  }
}
* { box-sizing: border-box; }
body {
  font-family: 'DejaVu Sans', 'Helvetica', 'Arial', sans-serif;
  font-size: 10.5pt; line-height: 1.55; color: #1c1c1c;
  background: #fff; margin: 0; padding: 0;
}
h1 { font-size: 22pt; color: #0b3d91; border-bottom: 3px solid #0b3d91;
     padding-bottom: 6px; margin-top: 0; }
h2 { font-size: 15pt; color: #0b3d91; border-bottom: 1px solid #ccd;
     padding-bottom: 3px; margin-top: 26px; page-break-after: avoid; }
h3 { font-size: 12pt; color: #222; margin-top: 18px; page-break-after: avoid; }
h4 { font-size: 11pt; color: #444; }
code {
  font-family: 'DejaVu Sans Mono', 'Courier New', monospace;
  font-size: 9.5pt; background: #f4f6f8; padding: 1px 4px;
  border-radius: 3px; color: #a31515;
}
pre {
  background: #f4f6f8; border-left: 3px solid #4a5a8a;
  padding: 8px 12px; overflow-x: auto; border-radius: 3px;
  font-family: 'DejaVu Sans Mono', monospace; font-size: 8.5pt;
  line-height: 1.4; white-space: pre-wrap; word-wrap: break-word;
  page-break-inside: avoid;
}
pre code { background: none; color: inherit; padding: 0; font-size: 8.5pt; }
table {
  border-collapse: collapse; width: 100%; margin: 8px 0;
  font-size: 9pt; page-break-inside: auto;
}
th {
  background: #0b3d91; color: #fff; text-align: left;
  padding: 5px 8px; font-weight: bold; font-size: 9pt;
}
td { border: 1px solid #ddd; padding: 4px 8px; vertical-align: top; }
tr { page-break-inside: avoid; }
tr:nth-child(even) td { background: #f9fafb; }
blockquote {
  border-left: 3px solid #0b3d91; padding: 3px 12px;
  color: #444; background: #f6f8fa; margin: 8px 0;
}
hr { border: none; border-top: 1px solid #ccc; margin: 22px 0; }
a { color: #0b3d91; text-decoration: none; }
ul, ol { padding-left: 22px; }
li { margin: 3px 0; }
.sev-critical { color: #7a0010; font-weight: bold; }
.sev-high     { color: #a3121c; font-weight: bold; }
.sev-medium   { color: #b55a00; font-weight: bold; }
.sev-low      { color: #a88500; font-weight: bold; }
.sev-info     { color: #23638a; font-weight: bold; }
"""

def _apply_sev_colors(html_text):
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        html_text = html_text.replace(
            f"[{sev}]",
            f'<span class="sev-{sev.lower()}">[{sev}]</span>')
    return html_text

def markdown_to_html(md_text, target):
    if _HAVE_MD:
        body = md_lib.markdown(
            md_text,
            extensions=["tables","fenced_code","toc","sane_lists","nl2br"],
        )
    else:
        body = html_mod.escape(md_text)
        body = "<pre>" + body + "</pre>"
    body = _apply_sev_colors(body)
    css = HTML_CSS.replace("{{TARGET}}", html_mod.escape(target))
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Assessment — {html_mod.escape(target)}</title>
<style>{css}</style></head>
<body>
{body}
</body></html>
"""

def html_to_pdf(html_path, pdf_path):
    html_path = pathlib.Path(html_path); pdf_path = pathlib.Path(pdf_path)

    try:
        from weasyprint import HTML
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        if pdf_path.exists() and pdf_path.stat().st_size > 500:
            return "weasyprint"
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["wkhtmltopdf", "--quiet", "--enable-local-file-access",
             "--print-media-type", str(html_path), str(pdf_path)],
            capture_output=True, text=True, timeout=180)
        if r.returncode == 0 and pdf_path.exists() and pdf_path.stat().st_size > 500:
            return "wkhtmltopdf"
    except Exception:
        pass

    try:
        for binp in ("chromium","chromium-browser","google-chrome"):
            if subprocess.run(["command","-v",binp], shell=True,
                              capture_output=True).returncode != 0:
                continue
            subprocess.run(
                [binp, "--headless", "--no-sandbox", "--disable-gpu",
                 f"--print-to-pdf={pdf_path}",
                 f"file://{html_path.resolve()}"],
                capture_output=True, timeout=120)
            if pdf_path.exists() and pdf_path.stat().st_size > 500:
                return "chromium"
    except Exception:
        pass

    return None


def generate_all(run_dir, state, log=print):
    run_dir = pathlib.Path(run_dir)
    target = state.get("target", run_dir.parent.name)

    md_text = build_report_markdown(run_dir, state)
    md_path = run_dir / "REPORT.md"
    md_path.write_text(md_text)
    log(f"[report] wrote {md_path} ({len(md_text)} chars)")

    html_text = markdown_to_html(md_text, target)
    html_path = run_dir / "report.html"
    html_path.write_text(html_text)
    log(f"[report] wrote {html_path} ({len(html_text)} chars)")

    pdf_path = run_dir / "report.pdf"
    tool = html_to_pdf(html_path, pdf_path)
    if tool:
        log(f"[report] wrote {pdf_path} via {tool} ({pdf_path.stat().st_size} bytes)")
    else:
        log(f"[report] PDF unavailable — HTML kept at {html_path}")
    return pdf_path if tool else None


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python reporter.py <scan_dir>")
        sys.exit(1)
    rd = pathlib.Path(sys.argv[1])
    sp = rd / "state.json"
    if not sp.exists():
        print(f"no state.json in {rd}"); sys.exit(1)
    st = json.loads(sp.read_text())
    generate_all(rd, st)
PYEOF