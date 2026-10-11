"""
intel/poc_fetch.py — fetch public PoCs for a CVE.

Sources (in order, first hit wins per-source):
  1. nomi-sec/PoC-in-GitHub (single JSON index, ~10k CVEs)
  2. GitHub code search "<CVE-YYYY-NNNNN> poc" (top 3 by stars)
  3. ExploitDB via gitlab.com/exploit-database/exploitdb (greps local DB)

Result cached under ~/agent/pocs/<cve>/:
  meta.json       — {cve, source, url, stars, last_commit, lang}
  README.md       — the PoC's own README (if any)
  <files>         — anything the clone produced

Never raises. Returns dict even on miss.
"""
import os
import re
import json
import time
import shutil
import pathlib
import subprocess
import urllib.request
import urllib.error

HERE = pathlib.Path(__file__).resolve().parent.parent  # ~/agent
POCS_ROOT = pathlib.Path(os.environ.get("AG_POCS_ROOT", HERE / "pocs"))
POCS_ROOT.mkdir(parents=True, exist_ok=True)

_NOMI_INDEX = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
_GH_SEARCH = "https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=5"
_TIMEOUT = 12


def _cve_year(cve):
    m = re.match(r"CVE-(\d{4})-", cve, re.I)
    return m.group(1) if m else None


def _http_json(url, timeout=_TIMEOUT):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "ag-poc-fetch/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


# ── source 1: nomi-sec index ──────────────────────────────────────

def _from_nomi(cve):
    y = _cve_year(cve)
    if not y:
        return []
    data = _http_json(_NOMI_INDEX.format(year=y, cve=cve.upper()))
    if not data:
        return []
    out = []
    for item in data:
        url = item.get("html_url") or ""
        if not url:
            continue
        out.append({
            "source": "nomi-sec",
            "url": url,
            "stars": item.get("stargazers_count", 0),
            "last_commit": item.get("pushed_at") or item.get("updated_at"),
            "lang": item.get("language") or "",
            "desc": (item.get("description") or "")[:200],
        })
    out.sort(key=lambda x: -(x.get("stars") or 0))
    return out


# ── source 2: github code search ──────────────────────────────────

def _from_gh_search(cve):
    q = urllib.parse.quote_plus(cve.upper()) if False else cve.upper()
    data = _http_json(_GH_SEARCH.format(q=q))
    if not data:
        return []
    out = []
    for item in data.get("items", []):
        out.append({
            "source": "github-search",
            "url": item.get("html_url", ""),
            "stars": item.get("stargazers_count", 0),
            "last_commit": item.get("pushed_at"),
            "lang": item.get("language") or "",
            "desc": (item.get("description") or "")[:200],
        })
    return out


# ── source 3: exploitdb local grep ────────────────────────────────

def _from_exploitdb(cve):
    for base in (pathlib.Path("/usr/share/exploitdb"),
                 HERE / "tools" / "exploitdb"):
        if not base.exists():
            continue
        try:
            r = subprocess.run(
                ["bash", "-lc",
                 f"grep -irl '{cve.upper()}' {base} 2>/dev/null | head -5"],
                capture_output=True, text=True, timeout=15)
        except Exception:
            continue
        out = []
        for path in r.stdout.splitlines():
            path = path.strip()
            if not path:
                continue
            out.append({
                "source": "exploitdb-local",
                "url": "file://" + path,
                "stars": 0,
                "last_commit": None,
                "lang": pathlib.Path(path).suffix.lstrip("."),
                "desc": "local exploitdb match",
            })
        return out
    return []


# ── orchestration ─────────────────────────────────────────────────

def lookup(cve):
    cve = cve.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve):
        return {"cve": cve, "ok": False, "error": "not a CVE id"}

    # cache hit?
    d = POCS_ROOT / cve
    meta_p = d / "meta.json"
    if meta_p.exists():
        try:
            return json.loads(meta_p.read_text())
        except Exception:
            pass

    candidates = []
    candidates += _from_nomi(cve)
    candidates += _from_gh_search(cve)
    candidates += _from_exploitdb(cve)

    if not candidates:
        meta = {"cve": cve, "ok": False, "error": "no public PoC found",
                "candidates": []}
        d.mkdir(parents=True, exist_ok=True)
        meta_p.write_text(json.dumps(meta, indent=2))
        return meta

    # score: stars * 1 + language weight + recency bonus
    def score(c):
        s = c.get("stars") or 0
        lang = (c.get("lang") or "").lower()
        if lang in ("python", "go", "ruby"):
            s += 5
        if lang in ("shell", "bash"):
            s += 3
        if lang in ("c", "c++", "csharp"):
            s += 2
        if c.get("source") == "nomi-sec":
            s += 10
        return s
    candidates.sort(key=score, reverse=True)
    top = candidates[0]

    meta = {
        "cve": cve,
        "ok": True,
        "source": top["source"],
        "url": top["url"],
        "stars": top.get("stars", 0),
        "last_commit": top.get("last_commit"),
        "lang": top.get("lang"),
        "desc": top.get("desc"),
        "candidates": candidates[:10],
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    d.mkdir(parents=True, exist_ok=True)

    # if it's a github url, clone shallow into the cve dir
    if top["url"].startswith("https://github.com/"):
        try:
            clone_to = d / "repo"
            if clone_to.exists():
                shutil.rmtree(clone_to, ignore_errors=True)
            subprocess.run(
                ["bash", "-lc",
                 f"git clone --depth 1 {top['url']} {clone_to} 2>/dev/null"],
                timeout=60, capture_output=True)
            if clone_to.exists():
                meta["local_path"] = str(clone_to)
                # grab the README for the report
                for readme in ("README.md", "README", "readme.md", "README.txt"):
                    p = clone_to / readme
                    if p.exists():
                        meta["readme"] = p.read_text(errors="ignore")[:4000]
                        break
        except Exception:
            pass

    meta_p.write_text(json.dumps(meta, indent=2))
    return meta


def readme_for(cve):
    """Return the saved README text for a CVE, or empty string."""
    p = POCS_ROOT / cve.upper() / "meta.json"
    if not p.exists():
        return ""
    try:
        return json.loads(p.read_text()).get("readme", "")
    except Exception:
        return ""


def summary(cve):
    m = lookup(cve)
    if not m.get("ok"):
        return f"{cve}: no public PoC found"
    return (f"{cve}: {m.get('source')} — {m.get('url')}  "
            f"(stars={m.get('stars')}  lang={m.get('lang')}  "
            f"local={m.get('local_path','-')})")


import urllib.parse  # keep at bottom to avoid shadowing issues
