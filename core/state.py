"""
core.state — checkpoint, scratchpad, heartbeat, kill-switch.
Owns the lifecycle of a run directory. Nothing else.
"""
import os
import json
import time
import pathlib
import threading
from datetime import datetime

HEARTBEAT_INTERVAL = 5.0
KILL_SWITCH_PATHS = [
    "/tmp/ag.stop",
    os.path.expanduser("~/agent/.stop"),
]

STATE_VERSION = 2

_DEFAULT_STATE = {
    "_version": STATE_VERSION,
    "target": None,
    "phase": "init",
    "turn": 0,
    "findings": [],
    "notes": [],
    "endpoints": [],
    "probes": [],
    "secrets": [],
    "creds": [],
    "walks": [],
    "params": [],
    "api_maps": [],
    "methods_used": [],
    "tech_stack": [],
    "web_searches": [],
    "attacks": [],
    "loot": [],
    "chains": [],
    "har": [],
    "oob": [],
    "graphs": [],
    "_auto_probe_queue": [],
    "_auto_probed": [],
    "attack_summary": {"attempted": 0, "succeeded": 0, "chained": 0},
    "budget": {},
}


def _migrate(state):
    v = state.get("_version", 1)
    if v < 2:
        state.setdefault("har", [])
        state.setdefault("oob", [])
        state.setdefault("graphs", [])
        state.setdefault("budget", {})
        state["_version"] = STATE_VERSION
    return state


def load(run_dir):
    p = pathlib.Path(run_dir) / "state.json"
    base = dict(_DEFAULT_STATE)
    base["target"] = pathlib.Path(run_dir).parent.name
    if not p.exists():
        return base
    try:
        raw = json.loads(p.read_text())
        for k, v in base.items():
            raw.setdefault(k, v)
        return _migrate(raw)
    except Exception:
        return base


def save(run_dir, state):
    run_dir = pathlib.Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    tmp = run_dir / "state.json.tmp"
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, run_dir / "state.json")


# ---------- scratchpad ----------

def scratchpad_path(run_dir):
    return pathlib.Path(run_dir) / "scratchpad.md"


def scratchpad_read(run_dir):
    p = scratchpad_path(run_dir)
    if not p.exists():
        return ""
    try:
        return p.read_text()[-8000:]
    except Exception:
        return ""


def scratchpad_append(run_dir, text):
    p = scratchpad_path(run_dir)
    with open(p, "a") as f:
        f.write(f"\n[{datetime.now().isoformat()}] {text}\n")


# ---------- heartbeat ----------

class Heartbeat:
    def __init__(self, run_dir):
        self.path = pathlib.Path(run_dir) / "heartbeat"
        self._stop = threading.Event()
        self._t = None

    def _beat(self):
        while not self._stop.is_set():
            try:
                self.path.write_text(datetime.now().isoformat())
            except Exception:
                pass
            self._stop.wait(HEARTBEAT_INTERVAL)

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._t = threading.Thread(target=self._beat, daemon=True)
        self._t.start()

    def stop(self):
        self._stop.set()
        if self._t:
            self._t.join(timeout=1.0)


# ---------- kill switch ----------

def kill_switch_hit():
    for p in KILL_SWITCH_PATHS:
        if os.path.exists(p):
            return p
    return None


# ---------- summary ----------

def write_summary(run_dir, state):
    run_dir = pathlib.Path(run_dir)
    target = state.get("target", "target")
    md = [f"# Assessment: {target}", f"_updated {datetime.now().isoformat()}_", ""]
    md.append(f"- phase: **{state.get('phase','?')}**")
    md.append(f"- turn: {state.get('turn',0)}")
    md.append(f"- findings: **{len(state.get('findings',[]))}**")
    md.append(f"- endpoints: {len(state.get('endpoints',[]))}")
    md.append(f"- probes: {len(state.get('probes',[]))}")
    md.append(f"- secrets: {len(state.get('secrets',[]))}")
    md.append(f"- creds: {len(state.get('creds',[]))}")
    md.append(f"- walks: {len(state.get('walks',[]))}")
    md.append(f"- oob hits: {len(state.get('oob',[]))}")
    md.append(f"- attacks: {len(state.get('attacks',[]))}")
    md.append("")
    findings = state.get("findings", [])
    if findings:
        by = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            by.setdefault((f.get("sev") or "info").lower(), []).append(f)
        md.append("## Findings\n")
        for sev in ("critical", "high", "medium", "low", "info"):
            for f in by.get(sev, []):
                md.append(f"### [{sev.upper()}] {f.get('title','?')}\n")
                md.append("```")
                md.append(str(f.get("evidence", ""))[:3000])
                md.append("```\n")
    notes = state.get("notes", [])
    if notes:
        md.append("## Notes\n")
        for n in notes:
            md.append(f"- {n}")
    (run_dir / "summary.md").write_text("\n".join(md))
