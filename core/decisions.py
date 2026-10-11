"""
core/decisions.py — per-run timeline of agent decisions.

Every turn appends one line to <run_dir>/decisions.jsonl:
  {ts, turn, model_text, directives, results, belief_snapshot}

The report reads this back to reconstruct reasoning: "at turn 12 the
agent observed X, chose PROBE, and the response changed its belief
about the target's auth gate." Evidence alone doesn't tell you WHY.
"""
import os
import json
import pathlib
import threading
from datetime import datetime

_LOCK = threading.Lock()


def _path(run_dir):
    return pathlib.Path(run_dir) / "decisions.jsonl"


def log(run_dir, turn, model_text, directives, results,
        extra=None, reasoning=""):
    """Append one decision record. Never raises — must not break a scan."""
    if not run_dir:
        return
    try:
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "turn": turn,
            "reasoning": (reasoning or "")[:2000],
            "model_text": (model_text or "")[:4000],
            "directives": [{"kind": k, "payload": p[:600]}
                           for k, p in (directives or [])],
            "results": [{"kind": k, "output": str(o)[:2000]}
                        for k, o in (results or [])],
        }
        if extra:
            entry["extra"] = extra
        with _LOCK:
            with open(_path(run_dir), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def read(run_dir, limit=2000):
    p = _path(run_dir)
    if not p.exists():
        return []
    out = []
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out[-limit:]


def timeline(run_dir, limit=200):
    """Compact view: one line per turn."""
    entries = read(run_dir, limit)
    out = []
    for e in entries:
        kinds = ",".join(d.get("kind", "?") for d in e.get("directives", []))
        first_result = ""
        for r in e.get("results", []):
            out_blob = (r.get("output") or "").splitlines()
            if out_blob:
                first_result = out_blob[0][:120]
                break
        out.append({
            "ts": e.get("ts"),
            "turn": e.get("turn"),
            "reasoning": (e.get("reasoning") or "")[:200],
            "directives": kinds,
            "first_result": first_result,
        })
    return out


def summary(run_dir):
    entries = read(run_dir)
    return {
        "turns": len(entries),
        "first_ts": entries[0]["ts"] if entries else None,
        "last_ts": entries[-1]["ts"] if entries else None,
    }
