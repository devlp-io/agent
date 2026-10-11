"""
scope — allowlist enforcement. Default deny.

Rule (in order):
  1. If scope.txt exists in run_dir or ~/agent, load it.
  2. Else if AG_SCOPE_AUTO is truthy (default "1"), the scope is
     auto-derived from the task target: exact host + wildcard subdomain.
  3. Else — no scope file and auto-scope disabled — BLOCK everything.

`--no-scope` on the CLI (agent_v8.py) sets AG_SCOPE_AUTO=0 and
AG_SCOPE_OPEN=1 for that run.

Format of scope.txt: one pattern per line, wildcards allowed
(*.example.com), # for comments.
"""
import os
import re
import pathlib
from urllib.parse import urlparse

_CACHE = {"mtime": 0, "patterns": [], "path": None, "target": None}

SCOPE_CANDIDATES = [
    "scope.txt",
    os.path.expanduser("~/agent/scope.txt"),
]

# _AUTO_SCOPE marker for idempotent patching
_AUTO_SCOPE = True


def _load_patterns(run_dir=None):
    candidates = []
    if run_dir:
        candidates.append(pathlib.Path(run_dir) / "scope.txt")
    candidates += [pathlib.Path(p) for p in SCOPE_CANDIDATES]
    for p in candidates:
        if p.exists():
            try:
                mt = p.stat().st_mtime
                if _CACHE["path"] == str(p) and _CACHE["mtime"] == mt:
                    return _CACHE["patterns"]
                lines = p.read_text().splitlines()
                pats = [ln.strip().lower() for ln in lines
                        if ln.strip() and not ln.strip().startswith("#")]
                _CACHE["mtime"] = mt
                _CACHE["patterns"] = pats
                _CACHE["path"] = str(p)
                return pats
            except Exception:
                return []

    # no file — auto-derive from target if we know it
    if os.environ.get("AG_SCOPE_AUTO", "1") == "1":
        tgt = _CACHE.get("target") or os.environ.get("AG_TARGET")
        if tgt:
            t = tgt.strip().lower()
            pats = [t, "*." + t]
            _CACHE["patterns"] = pats
            _CACHE["path"] = "auto"
            return pats

    # no file, no auto — refuse everything
    return ["__none__"]


def set_target(target: str):
    """Agent sets this at run start so auto-scope knows the target."""
    _CACHE["target"] = target
    _CACHE["path"] = None
    _CACHE["mtime"] = 0


def _match(host, pattern):
    host = host.lower()
    pattern = pattern.lower()
    if pattern == "__none__":
        return False
    if pattern.startswith("*."):
        tail = pattern[2:]
        return host == tail or host.endswith("." + tail)
    return host == pattern


def in_scope(url, run_dir=None):
    """Returns (True, reason) if allowed, (False, reason) if blocked."""
    # explicit opt-out
    if os.environ.get("AG_SCOPE_OPEN") == "1":
        return True, "scope disabled (--no-scope)"
    pats = _load_patterns(run_dir)
    if not pats:
        return False, "no scope defined and auto-scope disabled"
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False, "unparseable url"
    if not host:
        return False, "no host"
    for p in pats:
        if _match(host, p):
            return True, "matched " + p
    return False, "host " + host + " not in scope " + str(pats[:5])


def enforce(url, run_dir=None):
    ok, reason = in_scope(url, run_dir)
    if not ok:
        raise PermissionError("SCOPE BLOCK: " + url + " — " + reason)
    return True
