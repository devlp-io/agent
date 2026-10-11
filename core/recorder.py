"""
core/recorder.py — append-only per-target action log.

Every command, directive, finding, probe, walk, and successful result the
agent produces gets appended here. Keyed by target, not by run, so the
record survives across scans.

The UI-builder agent (uibuilder.py) reads this to know what the target
actually exposes and what actions are worth exposing in the console.
"""
import os
import json
import time
import pathlib
import threading
from datetime import datetime

SCAN_ROOT = pathlib.Path(os.environ.get("AG_SCAN_ROOT", os.path.expanduser("~/scans")))
_LOCK = threading.Lock()


def _path_for(target: str) -> pathlib.Path:
    safe = "".join(c for c in target if c.isalnum() or c in "._-")
    return SCAN_ROOT / safe / "recorder.jsonl"


def record(target: str, kind: str, payload: dict, run_dir=None):
    """Append one event. kind: command|finding|probe|walk|endpoint|secret|
    cred|loot|attack|schema|note|result."""
    try:
        p = _path_for(target)
        p.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "kind": kind,
            "run_dir": str(run_dir) if run_dir else None,
            **payload,
        }
        with _LOCK:
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass  # recorder must never break a scan


def read(target: str, limit: int = 20000) -> list:
    """Return the last N events for a target."""
    p = _path_for(target)
    if not p.exists():
        return []
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return [json.loads(l) for l in lines[-limit:] if l.strip()]
    except Exception:
        return []


def summary(target: str) -> dict:
    """Roll up the recorder into a compact structure the UI builder
    can consume cheaply."""
    events = read(target)
    out = {
        "target": target,
        "events": len(events),
        "first_seen": events[0]["ts"] if events else None,
        "last_seen":  events[-1]["ts"] if events else None,
        "commands": [],   # (ts, cmd, short output)
        "findings": [],
        "probes": [],
        "walks": [],
        "secrets": [],
        "creds": [],
        "loot": [],
        "successful_reads": [],
        "successful_writes": [],
        "endpoints": [],
    }
    for e in events:
        k = e.get("kind")
        if k == "command":
            out["commands"].append({
                "ts": e.get("ts"),
                "cmd": e.get("cmd", "")[:500],
                "out": (e.get("output") or "")[:1000],
                "ok": e.get("ok"),
            })
        elif k == "finding":
            out["findings"].append({
                "ts": e.get("ts"),
                "sev": e.get("sev"),
                "title": e.get("title", "")[:200],
                "evidence": (e.get("evidence") or "")[:800],
            })
        elif k == "probe":
            out["probes"].append({
                "ts": e.get("ts"),
                "method": e.get("method"),
                "url": e.get("url"),
                "unauth_2xx": e.get("unauth_2xx"),
            })
        elif k == "walk":
            out["walks"].append({
                "ts": e.get("ts"),
                "method": e.get("method"),
                "url": e.get("url"),
                "param": e.get("param"),
                "hits": e.get("hits"),
                "sample": (e.get("sample") or "")[:400],
            })
        elif k == "secret":
            out["secrets"].append({
                "ts": e.get("ts"),
                "kind_name": e.get("kind_name"),
                "value": (e.get("value") or "")[:200],
                "path": e.get("path"),
            })
        elif k == "cred":
            out["creds"].append({
                "ts": e.get("ts"),
                "user": e.get("user"),
                "pass_len": len(e.get("pass", "") or ""),
                "where": e.get("where"),
            })
        elif k == "loot":
            out["loot"].append({
                "ts": e.get("ts"),
                "kind_name": e.get("kind_name"),
                "value": (e.get("value") or "")[:200],
            })
        elif k == "endpoint":
            out["endpoints"].append({
                "ts": e.get("ts"),
                "method": e.get("method"),
                "url": e.get("url"),
                "note": e.get("note"),
            })
        elif k == "result":
            # successful reads/writes recorded explicitly by the agent
            if e.get("verb") == "read" and e.get("ok"):
                out["successful_reads"].append(e)
            if e.get("verb") in ("write", "patch", "delete", "create") and e.get("ok"):
                out["successful_writes"].append(e)
    return out
