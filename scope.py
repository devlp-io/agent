"""
scope — allowlist enforcement. Refuses any URL outside the configured scope.
Reads scope.txt from the run directory (or ~/agent/scope.txt fallback).
Format: one domain per line, wildcards allowed (*.example.com).
Lines starting with # are ignored.
If scope.txt is missing or empty, scope enforcement is DISABLED.
"""
import os
import re
import pathlib
from urllib.parse import urlparse

_CACHE = {"mtime": 0, "patterns": [], "path": None}
SCOPE_CANDIDATES = [
    "scope.txt",
    os.path.expanduser("~/agent/scope.txt"),
]


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
    return []


def _match(host, pattern):
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        tail = pattern[2:]
        return host == tail or host.endswith("." + tail)
    return host == pattern


def in_scope(url, run_dir=None):
    """Returns (True, reason) if allowed, (False, reason) if blocked."""
    pats = _load_patterns(run_dir)
    if not pats:
        return True, "scope disabled"
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False, "unparseable url"
    if not host:
        return False, "no host"
    for p in pats:
        if _match(host, p):
            return True, f"matched {p}"
    return False, f"host {host} not in scope"


def enforce(url, run_dir=None):
    ok, reason = in_scope(url, run_dir)
    if not ok:
        raise PermissionError(f"SCOPE BLOCK: {url} — {reason}")
    return True
