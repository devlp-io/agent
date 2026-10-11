"""
core/beliefs.py — stateful defense beliefs per target.

Every probe / exploit / payload result updates typed, confidence-weighted
beliefs about the target. The attack phase reads them and picks the next
action that best discriminates between current hypotheses, instead of
re-trying the same checklist.

Shape (beliefs.json next to recorder.jsonl):

  {
    target, updated_at,
    facts:         [ {kind, path, evidence, ts} ],
    hypotheses:    [ {kind, path, confidence, rationale} ],
    dead_ends:     [ {probe, variants, outcome, ts} ],
    open_questions:[ str ]
  }
"""
import json
import time
import pathlib
import threading
from datetime import datetime

SCAN_ROOT = pathlib.Path(__import__("os").environ.get(
    "AG_SCAN_ROOT", __import__("os").path.expanduser("~/scans")))
_LOCK = threading.Lock()


def _safe(t):
    return "".join(c for c in t if c.isalnum() or c in "._-")


def _path(t):
    return SCAN_ROOT / _safe(t) / "beliefs.json"


def _empty(t):
    return {
        "target": t,
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "facts": [],
        "hypotheses": [],
        "dead_ends": [],
        "open_questions": [],
    }


def read(t):
    p = _path(t)
    if not p.exists():
        return _empty(t)
    try:
        return json.loads(p.read_text())
    except Exception:
        return _empty(t)


def save(t, b):
    b["updated_at"] = datetime.utcnow().isoformat() + "Z"
    p = _path(t)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(b, indent=2, default=str))


# ── inference rules ───────────────────────────────────────────────

def _url_path(url):
    if not url:
        return "/"
    try:
        from urllib.parse import urlparse
        return urlparse(url).path or "/"
    except Exception:
        return url


def _add_fact(b, kind, path, evidence):
    key = (kind, path)
    for f in b["facts"]:
        if (f.get("kind"), f.get("path")) == key:
            return
    b["facts"].append({
        "kind": kind, "path": path,
        "evidence": evidence[:300],
        "ts": datetime.utcnow().isoformat() + "Z",
    })


def _bump_hypothesis(b, kind, path, delta, rationale):
    for h in b["hypotheses"]:
        if h["kind"] == kind and h.get("path") == path:
            h["confidence"] = max(0.0, min(1.0, h["confidence"] + delta))
            if rationale and rationale not in h.get("rationale", ""):
                h["rationale"] = (h.get("rationale", "") + " | " + rationale)[:400]
            return
    b["hypotheses"].append({
        "kind": kind, "path": path,
        "confidence": max(0.0, min(1.0, 0.5 + delta)),
        "rationale": rationale[:400] if rationale else "",
    })


def _add_dead_end(b, probe, variants, outcome):
    for d in b["dead_ends"]:
        if d["probe"] == probe:
            for v in variants:
                if v not in d["variants"]:
                    d["variants"].append(v)
            d["outcome"] = outcome[:200]
            return
    b["dead_ends"].append({
        "probe": probe, "variants": list(variants),
        "outcome": outcome[:200],
        "ts": datetime.utcnow().isoformat() + "Z",
    })


# ── ingest from probe results ─────────────────────────────────────

_AUTH_BYPASS_VARIANTS = {
    "no_auth", "empty_bearer", "admin_bearer", "null_bearer",
    "basic_admin", "x-forwarded-localhost", "x-original-url",
    "x-rewrite-url",
}


def from_probe(t, url, method, results):
    """results: list of {variant, status, ...} from do_probe()."""
    b = read(t)
    path = _url_path(url)
    ok_variants = []
    denied_variants = []
    for r in results or []:
        cap = str(r.get("cap") or "")
        status = str(r.get("status") or "")
        variant = r.get("variant", "?")
        if cap == "ok" or status.startswith("2"):
            ok_variants.append(variant)
        elif cap == "denied" or status in ("401", "403"):
            denied_variants.append(variant)

    if ok_variants:
        # which specific bypass variant worked tells us the gate type
        for v in ok_variants:
            if v == "x-original-url" or v == "x-rewrite-url":
                _add_fact(b, "path_gate", path, "bypassed via " + v)
                _bump_hypothesis(b, "path_gate", path, 0.4, "bypass " + v)
            elif v == "x-forwarded-localhost":
                _add_fact(b, "auth_gate", path, "bypassed via X-Forwarded-For 127.0.0.1")
                _bump_hypothesis(b, "auth_gate", path, 0.3, "trusted-ip bypass")
            elif v in ("empty_bearer", "admin_bearer", "null_bearer"):
                _add_fact(b, "auth_gate", path, "broken auth check")
                _bump_hypothesis(b, "auth_gate", path, -0.3, "auth check is trivially bypassable")
            elif v == "basic_admin":
                _add_fact(b, "auth_gate", path, "default admin creds")
                _bump_hypothesis(b, "auth_gate", path, -0.2, "default creds work")
    else:
        # all denied → likely auth_gate or waf_gate
        if denied_variants and len(denied_variants) >= 5:
            _add_fact(b, "auth_gate", path, "9 auth-bypass variants all denied")
            _bump_hypothesis(b, "auth_gate", path, 0.3, "all bypass variants denied")
            _add_dead_end(b, "PROBE|GET|" + path,
                          [v for v in _AUTH_BYPASS_VARIANTS if v in denied_variants],
                          "all 401/403")

    _persist(t, b)
    return b


# ── ingest from command output ────────────────────────────────────

import re as _re

def from_command(t, cmd, output, ok):
    b = read(t)
    # look for method + status pairs in the output
    url_m = _re.search(r"(https?://[^\s'\"<>]+)", cmd or "")
    if not url_m:
        _persist(t, b); return b
    url = url_m.group(1)
    path = _url_path(url)
    out = output or ""

    # find first HTTP status in output
    status_m = _re.search(r"\bHTTP/(?:\d\.\d)?\s*(\d{3})", out)
    status = int(status_m.group(1)) if status_m else 0

    if status in (401, 403):
        _add_fact(b, "auth_gate", path, "status " + str(status))
        _bump_hypothesis(b, "auth_gate", path, 0.15, "blocked at " + str(status))
    elif status and 200 <= status < 300:
        _add_fact(b, "open", path, "status " + str(status))
        # if we saw same url fail earlier, we've bypassed something
        for h in list(b["hypotheses"]):
            if h.get("path") == path and h["kind"] in ("auth_gate", "path_gate", "waf_gate"):
                _bump_hypothesis(b, h["kind"], path, -0.4, "later request succeeded")
        if "x-original-url" in (cmd or "").lower() or "x-rewrite-url" in (cmd or "").lower():
            _add_fact(b, "path_gate", path, "X-Original-URL bypass confirmed in cmd")
            _bump_hypothesis(b, "path_gate", path, 0.5, "explicit bypass header")

    # detect WAF markers
    if _re.search(r"(cloudflare|akamai|sucuri|mod_security|Attention Required)", out, _re.I):
        _add_fact(b, "waf_gate", path, "WAF marker in response")
        _bump_hypothesis(b, "waf_gate", path, 0.4, "WAF signature present")

    _persist(t, b)
    return b


# ── ingest from explicit BELIEF: directive ────────────────────────

def from_explicit(t, kind, path, confidence, rationale):
    b = read(t)
    try:
        conf = float(confidence)
    except Exception:
        conf = 0.6
    _add_fact(b, kind, path, "explicit assertion: " + rationale)
    _bump_hypothesis(b, kind, path, conf - 0.5, rationale)
    _persist(t, b)
    return b


# ── query / inject ────────────────────────────────────────────────

def confidence_for(t, kind, path):
    b = read(t)
    for h in b["hypotheses"]:
        if h["kind"] == kind and h.get("path") == path:
            return h["confidence"]
    return 0.0


def is_dead_end(t, probe):
    b = read(t)
    for d in b["dead_ends"]:
        if d["probe"] == probe:
            return True
    return False


def inject_context(t, limit=8):
    """Return a compact string to prepend to attack prompts."""
    b = read(t)
    if not b["hypotheses"] and not b["dead_ends"]:
        return ""
    L = ["=== TARGET BELIEFS (what the agent has learned so far) ==="]
    hyps = sorted(b["hypotheses"], key=lambda h: -h["confidence"])[:limit]
    if hyps:
        L.append("hypotheses:")
        for h in hyps:
            L.append("  " + h["kind"] + " on " + str(h.get("path")) +
                     "  confidence=" + format(h["confidence"], ".2f") +
                     "  (" + (h.get("rationale") or "")[:120] + ")")
    if b["dead_ends"]:
        L.append("dead_ends (do NOT re-fire these):")
        for d in b["dead_ends"][-limit:]:
            L.append("  " + d["probe"] + "  tried " +
                     str(len(d.get("variants", []))) + " variants  → " +
                     (d.get("outcome") or "")[:80])
    if b["open_questions"]:
        L.append("open_questions:")
        for q in b["open_questions"][:limit]:
            L.append("  " + q)
    L.append("=== END BELIEFS ===")
    return "\n".join(L)


def _persist(t, b):
    with _LOCK:
        save(t, b)


def summary(t):
    b = read(t)
    return {
        "target": t,
        "facts": len(b["facts"]),
        "hypotheses": len(b["hypotheses"]),
        "dead_ends": len(b["dead_ends"]),
        "top": sorted(b["hypotheses"], key=lambda h: -h["confidence"])[:5],
    }
