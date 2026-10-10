#!/usr/bin/env python3
"""
dashboard.py — local monitoring + control UI for the ag security agent.

Reads ~/scans/*/*/ run directories the same way the CLI writes them.
Live-tails live.log / live_commands.log / live_findings.log via SSE.
Dispatches directives through agent_v8.dispatch() — same table the loop uses.
Manages API keys (.env), tools (installer.py), and spawned scans.

Run:  python dashboard.py [--port 8787] [--host 127.0.0.1] [--reload]
      agui    (bash alias)
"""
import os
import re
import io
import sys
import json
import time
import shlex
import signal
import asyncio
import pathlib
import threading
import subprocess
from datetime import datetime
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse, StreamingResponse, JSONResponse, PlainTextResponse,
)
from pydantic import BaseModel

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

SCAN_ROOT = pathlib.Path(
    os.environ.get("AG_SCAN_ROOT", os.path.expanduser("~/scans"))
)
ENV_PATH = HERE / ".env"

# lazy imports — some of these touch the network at import time
_agent_v8 = None
def agent_v8():
    global _agent_v8
    if _agent_v8 is None:
        import agent_v8 as m
        _agent_v8 = m
    return _agent_v8

_state = None
def state_mod():
    global _state
    if _state is None:
        from core import state as s
        _state = s
    return _state

_installer = None
def installer_mod():
    global _installer
    if _installer is None:
        import installer as i
        _installer = i
    return _installer

_tools_db = None
def tools_db():
    global _tools_db
    if _tools_db is None:
        try:
            from tools_db import TOOLS
            _tools_db = TOOLS
        except Exception:
            _tools_db = {}
    return _tools_db


# ══════════════════════════════════════════════════════════════════════
# scan discovery
# ══════════════════════════════════════════════════════════════════════

def _safe_target(t: str) -> str:
    # prevent ../ escapes; targets are always DNS-ish names
    t = t.strip()
    if not re.fullmatch(r"[A-Za-z0-9._\-]+", t):
        raise HTTPException(400, f"bad target name: {t!r}")
    return t


def _safe_ts(t: str) -> str:
    t = t.strip()
    if not re.fullmatch(r"[0-9_\-]+", t):
        raise HTTPException(400, f"bad timestamp: {t!r}")
    return t


def _run_dir(target: str, ts: str) -> pathlib.Path:
    t = _safe_target(target); s = _safe_ts(ts)
    d = SCAN_ROOT / t / s
    if not d.is_dir():
        raise HTTPException(404, f"no such run: {t}/{s}")
    return d


def list_scans() -> list[dict]:
    out: list[dict] = []
    if not SCAN_ROOT.exists():
        return out
    for target_dir in sorted(SCAN_ROOT.iterdir(), key=lambda p: p.name.lower()):
        if not target_dir.is_dir():
            continue
        for run in sorted(target_dir.iterdir(), reverse=True):
            if not run.is_dir():
                continue
            meta = _scan_meta(target_dir.name, run)
            out.append(meta)
    # newest first
    out.sort(key=lambda m: m["started_at"] or "", reverse=True)
    return out


def _scan_meta(target: str, run: pathlib.Path) -> dict:
    st_path = run / "state.json"
    started = None
    turn = 0
    phase = "unknown"
    n_find = n_end = n_att = 0
    if st_path.exists():
        try:
            st = json.loads(st_path.read_text())
            turn = int(st.get("turn", 0))
            phase = st.get("phase", "unknown")
            n_find = len(st.get("findings", []))
            n_end = len(st.get("endpoints", []))
            n_att = len(st.get("attacks", []))
        except Exception:
            pass
    # started at from the timestamp in the dir name (YYYYMMDD_HHMMSS)
    try:
        started = datetime.strptime(run.name, "%Y%m%d_%H%M%S").isoformat()
    except Exception:
        started = None
    # activity: newest mtime among the live logs
    last_activity = None
    for f in ("live.log", "live_findings.log", "live_commands.log"):
        p = run / f
        if p.exists():
            m = p.stat().st_mtime
            if last_activity is None or m > last_activity:
                last_activity = m
    # a scan is "live" only if its log files were touched in the last 90s
    is_live = bool(last_activity and (time.time() - last_activity) < 90)
    return {
        "target": target,
        "ts": run.name,
        "path": str(run),
        "started_at": started,
        "turn": turn,
        "phase": phase,
        "findings": n_find,
        "endpoints": n_end,
        "attacks": n_att,
        "is_live": is_live,
        "last_activity": last_activity,
    }


# ══════════════════════════════════════════════════════════════════════
# file tail
# ══════════════════════════════════════════════════════════════════════

def tail_file(path: pathlib.Path, n: int = 200) -> list[str]:
    if not path.exists():
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = min(size, 64 * 1024)
            f.seek(size - block)
            data = f.read().decode("utf-8", "replace")
        lines = data.splitlines()
        return lines[-n:]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════
# dispatch bridge — binds agent_v8's module globals to a target run dir,
# then calls dispatch(kind, payload). same table as the CLI loop uses.
# ══════════════════════════════════════════════════════════════════════

_dispatch_lock = threading.Lock()

def dispatch_into(target: str, ts: str, kind: str, payload: str) -> str:
    rd = _run_dir(target, ts)
    ag = agent_v8()
    st_mod = state_mod()
    with _dispatch_lock:
        # bind
        ag.RUN_DIR = rd
        ag.STATE = st_mod.load(rd)
        # budget singleton
        try:
            import budget as _budget
            ag.BUD = _budget.get(rd)
        except Exception:
            ag.BUD = None
        # collector (may not be initialized)
        try:
            from evidence import collector as _col
            ag.COLLECTOR = _col.Collector(rd)
        except Exception:
            ag.COLLECTOR = None
        try:
            result = ag.dispatch(kind, payload)
        except Exception as e:
            result = f"dispatch error: {e}"
        # persist state
        try:
            st_mod.save(rd, ag.STATE)
        except Exception:
            pass
    return str(result)


# ══════════════════════════════════════════════════════════════════════
# spawned-process registry
# ══════════════════════════════════════════════════════════════════════

_running: dict[str, dict] = {}

# v4: strip ANSI before showing in UI
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")

def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _drain(key: str, proc: subprocess.Popen):
    buf: list[str] = []
    try:
        for line in iter(proc.stdout.readline, ""):
            line = _strip_ansi(line)
            buf.append(line)
            if len(buf) > 4000:
                buf = buf[-4000:]
            _running[key]["lines"] = buf[-500:]
    except Exception:
        pass
    finally:
        try:
            proc.wait(timeout=1)
        except Exception:
            pass
        _running[key]["exit_code"] = proc.returncode
        _running[key]["finished"] = datetime.now().isoformat()


def spawn_scan(task: str, attack=False, resume=False, dry=False) -> dict:
    ag_file = HERE / "agent_v8.py"
    if not ag_file.exists():
        raise HTTPException(500, "agent_v8.py not found next to dashboard.py")
    args = [sys.executable, str(ag_file)]
    if attack: args.append("--attack")
    if resume: args.append("--resume")
    if dry:    args.append("--dry")
    args.append(task)
    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    proc = subprocess.Popen(
        args, cwd=str(HERE), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
        preexec_fn=os.setsid if os.name == "posix" else None,
    )
    key = f"p{proc.pid}_{int(time.time())}"
    _running[key] = {
        "key": key, "pid": proc.pid, "proc": proc,
        "started": datetime.now().isoformat(),
        "task": task, "lines": [], "exit_code": None, "finished": None,
    }
    threading.Thread(target=_drain, args=(key, proc), daemon=True).start()
    return {"key": key, "pid": proc.pid}


def kill_scan(key: str) -> dict:
    e = _running.get(key)
    if not e:
        raise HTTPException(404, f"no such running scan: {key}")
    proc: subprocess.Popen = e["proc"]
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except Exception:
        pass
    time.sleep(0.5)
    try:
        if proc.poll() is None:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
    except Exception:
        pass
    return {"killed": True, "key": key}


# ══════════════════════════════════════════════════════════════════════
# env / keys
# ══════════════════════════════════════════════════════════════════════

KEY_FIELDS = (
    "AG_MODEL", "AG_BASE", "AG_KEY", "DEEPSEEK_KEY",
    "AG_PROXY", "AG_SCAN_ROOT", "AG_MAX_TURNS", "AG_CTX_MAX",
    "AG_CMD_TIMEOUT", "AG_CURL_TIMEOUT",
)

def read_env() -> dict:
    out: dict[str, str] = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"').strip("'")
    # environment overrides file
    for k in KEY_FIELDS:
        if os.environ.get(k):
            out[k] = os.environ[k]
    return out


def write_env(updates: dict) -> dict:
    cur = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.rstrip("\n")
            if not line.strip() or line.strip().startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            cur[k.strip()] = v.strip()
    for k, v in updates.items():
        if v is None:
            continue
        if k not in KEY_FIELDS:
            continue
        if isinstance(v, str) and v.strip() == "":
            cur.pop(k, None)
            continue
        cur[k] = str(v).strip()
    body = "\n".join(f"{k}={shlex.quote(v)}" for k, v in sorted(cur.items()))
    ENV_PATH.write_text(body + "\n")
    return cur


def mask(v: str) -> str:
    if not v:
        return ""
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 8) + v[-4:]


# ══════════════════════════════════════════════════════════════════════
# FastAPI
# ══════════════════════════════════════════════════════════════════════

app = FastAPI(title="ag dashboard")


class ActionBody(BaseModel):
    kind: str
    payload: str = ""


class StartBody(BaseModel):
    task: str
    attack: bool = False
    resume: bool = False
    dry: bool = False


class RepeaterBody(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: str = ""
    follow: bool = False
    timeout: int = 25


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML


@app.get("/api/directives")
def api_directives():
    try:
        return {"names": list(agent_v8()._DIRECTIVE_NAMES)}
    except Exception:
        # fall back to a sane default
        return {"names": [
            "COMMAND", "PARALLEL", "INSTALL", "NEED_TOOL", "TOOLS", "FILE",
            "LIST", "NOTE", "FINDING", "ENDPOINT", "PROBE", "PLAN", "PAYLOAD",
            "SECRET", "CRED", "SCREENSHOT", "CVE", "METHOD", "PARAMFIND",
            "WALK", "APIMAP", "HARVEST", "SEARCH", "FETCH", "REPORT",
            "PROOF", "EXPLOIT", "SHELL", "LOOT", "CRACK", "PIVOT", "STATUS",
            "CHAIN", "BROWSER", "GRAPHQL", "WS", "OOB", "MUTATE",
            "CHAIN_AUTO", "HAR", "BUDGET", "WAF", "STACK",
        ]}


@app.get("/api/scans")
def api_scans():
    return {"scans": list_scans(), "root": str(SCAN_ROOT)}


@app.get("/api/scan/{target}/{ts}")
def api_scan(target: str, ts: str):
    rd = _run_dir(target, ts)
    meta = _scan_meta(target, rd)
    st = {}
    sp = rd / "state.json"
    if sp.exists():
        try:
            st = json.loads(sp.read_text())
        except Exception:
            st = {"_error": "state.json unreadable"}
    return {"meta": meta, "state": st}


@app.get("/api/scan/{target}/{ts}/state")
def api_scan_state(target: str, ts: str):
    rd = _run_dir(target, ts)
    sp = rd / "state.json"
    if not sp.exists():
        return {"state": {}}
    try:
        return {"state": json.loads(sp.read_text())}
    except Exception as e:
        return {"state": {}, "error": str(e)}


@app.get("/api/scan/{target}/{ts}/stream")
async def api_stream(target: str, ts: str, files: str = "live.log,live_findings.log,live_commands.log"):
    rd = _run_dir(target, ts)
    wanted = [f.strip() for f in files.split(",") if f.strip()]
    # constrain to known names
    allowed = {"live.log", "live_findings.log", "live_commands.log"}
    wanted = [f for f in wanted if f in allowed]

    offsets: dict[str, int] = {}

    def _read_new(path: pathlib.Path, off: int):
        if not path.exists():
            return off, []
        size = path.stat().st_size
        if size < off:
            off = 0  # truncated / rotated
        if size == off:
            return off, []
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read(size - off).decode("utf-8", "replace")
        new_lines = data.splitlines()
        return size, new_lines

    async def gen():
        # initial tail
        for f in wanted:
            p = rd / f
            init_lines = tail_file(p, 200)
            yield f"event: init\ndata: {json.dumps({'file': f, 'lines': init_lines})}\n\n"
            offsets[f] = p.stat().st_size if p.exists() else 0
        # poll
        try:
            while True:
                for f in wanted:
                    p = rd / f
                    new_off, lines = _read_new(p, offsets[f])
                    offsets[f] = new_off
                    for line in lines:
                        yield f"event: log\ndata: {json.dumps({'file': f, 'line': line})}\n\n"
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            return

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


class SayBody(BaseModel):
    kind: str = "message"      # message | focus | goal_add | goal_block | pause | resume | stop
    text: str = ""


@app.post("/api/scan/{target}/{ts}/say")
def api_say(target: str, ts: str, body: SayBody):
    """Write a line into inbox.jsonl. The running agent picks it up next turn."""
    rd = _run_dir(target, ts)
    st_mod = state_mod()
    try:
        st_mod.append_inbox(rd, body.kind, body.text)
    except Exception as e:
        raise HTTPException(500, f"inbox write failed: {e}")
    return {"ok": True, "kind": body.kind, "text": body.text}


@app.get("/api/scan/{target}/{ts}/log")
def api_log(target: str, ts: str, file: str = "live.log", tail: int = 400):
    """Simple polling endpoint for the Logs tab.
    Returns the last N lines of one of the three live logs."""
    rd = _run_dir(target, ts)
    allowed = {"live.log", "live_findings.log", "live_commands.log"}
    if file not in allowed:
        raise HTTPException(400, f"unknown log file: {file}")
    p = rd / file
    lines = tail_file(p, min(max(tail, 1), 2000))
    try:
        size = p.stat().st_size if p.exists() else 0
    except Exception:
        size = 0
    return {"file": file, "size": size, "lines": lines}


@app.post("/api/scan/{target}/{ts}/action")
def api_action(target: str, ts: str, body: ActionBody):
    if not body.kind:
        raise HTTPException(400, "kind required")
    result = dispatch_into(target, ts, body.kind.upper(), body.payload)
    return {"result": result, "kind": body.kind, "payload": body.payload}


@app.post("/api/scan/start")
def api_start(body: StartBody):
    if not body.task.strip():
        raise HTTPException(400, "task required")
    return spawn_scan(body.task, attack=body.attack, resume=body.resume, dry=body.dry)


@app.post("/api/scan/running/{key}/kill")
def api_kill(key: str):
    return kill_scan(key)


@app.get("/api/running")
def api_running():
    out = []
    seen_scans = set()

    # 1) spawned-from-dashboard processes
    for k, e in _running.items():
        try:
            alive = e["proc"].poll() is None
        except Exception:
            alive = False
        lines = [_strip_ansi(l) for l in (e.get("lines", [])[-300:])]
        # try to tag with the run dir the child opened (best-effort)
        target = None
        ts = None
        m = __import__("re").search(r"/scans/([^/]+)/(\d{8}_\d{6})", " ".join(lines[:5]))
        if m:
            target, ts = m.group(1), m.group(2)
            seen_scans.add((target, ts))
        out.append({
            "kind": "spawn",
            "key": k, "pid": e["pid"], "task": e["task"],
            "started": e["started"], "finished": e.get("finished"),
            "exit_code": e.get("exit_code"),
            "alive": alive,
            "target": target, "ts": ts,
            "lines": lines,
        })

    # 2) live-on-disk scans (spawned externally — CLI, cron, ssh)
    for s in list_scans():
        if not s.get("is_live"):
            continue
        if (s["target"], s["ts"]) in seen_scans:
            continue
        rd = SCAN_ROOT / s["target"] / s["ts"]
        lines = []
        for f in ("live.log", "live_findings.log"):
            try:
                for l in tail_file(rd / f, 200):
                    lines.append(_strip_ansi(l))
                lines.append("")
            except Exception:
                pass
        out.append({
            "kind": "disk",
            "key": f"disk:{s['target']}:{s['ts']}",
            "pid": None,
            "task": f"external scan · {s['target']} (turn {s['turn']})",
            "started": s.get("started_at") or "",
            "finished": None,
            "exit_code": None,
            "alive": True,
            "target": s["target"], "ts": s["ts"],
            "lines": lines[-400:],
        })
    return {"running": out}


@app.get("/api/tools")
def api_tools():
    tdb = tools_db()
    inst = installer_mod()
    rows = []
    try:
        st = inst.status()
    except Exception:
        st = {"installed_list": [], "missing_list": [], "platform": "?"}
    installed = set(st.get("installed_list", []))
    missing = set(st.get("missing_list", []))
    for name, entry in sorted(tdb.items()):
        rows.append({
            "name": name,
            "category": entry.get("category", "misc"),
            "desc": entry.get("desc", ""),
            "url": entry.get("url", ""),
            "installed": name in installed,
            "missing": name in missing,
        })
    return {"tools": rows, "platform": st.get("platform", "?")}


class InstallBody(BaseModel):
    name: str

@app.post("/api/tools/install")
def api_tools_install(body: InstallBody):
    inst = installer_mod()
    try:
        out = inst.install_any(body.name)
    except Exception as e:
        out = f"error: {e}"
    return {"result": out}


@app.get("/api/keys")
def api_keys():
    raw = read_env()
    masked = {k: mask(raw.get(k, "")) for k in KEY_FIELDS}
    effective = {k: bool(os.environ.get(k)) for k in KEY_FIELDS}
    overridden = [k for k in KEY_FIELDS
                  if os.environ.get(k) and raw.get(k) != os.environ.get(k)]
    raw_text = ENV_PATH.read_text() if ENV_PATH.exists() else ""
    return {
        "env": masked,
        "path": str(ENV_PATH),
        "raw_keys": sorted(raw.keys()),
        "effective": effective,
        "overridden": overridden,
        "raw_text": raw_text,
    }


class KeysBody(BaseModel):
    updates: dict

@app.post("/api/keys")
def api_keys_save(body: KeysBody):
    saved = write_env(body.updates or {})
    return {"saved": sorted(saved.keys()), "path": str(ENV_PATH)}


@app.get("/api/running/{key}/lines")
def api_running_lines(key: str, tail: int = 400):
    """For disk-kind keys, return fresh tail from the run dir.
    For spawn-kind keys, return in-memory buffer."""
    if key.startswith("disk:"):
        _, target, ts = key.split(":", 2)
        rd = _run_dir(target, ts)
        lines = []
        for f in ("live.log", "live_findings.log"):
            for l in tail_file(rd / f, tail // 2):
                lines.append(_strip_ansi(l))
            lines.append("")
        return {"key": key, "lines": lines[-tail:]}
    e = _running.get(key)
    if not e:
        raise HTTPException(404, f"unknown key: {key}")
    return {"key": key, "lines": [_strip_ansi(l) for l in (e.get("lines", [])[-tail:])]}


@app.post("/api/repeater")
async def api_repeater(body: RepeaterBody):
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(400, "url must start http(s)")
    headers = {str(k): str(v) for k, v in (body.headers or {}).items()}
    try:
        async with httpx.AsyncClient(
            follow_redirects=body.follow, verify=False,
            timeout=body.timeout,
        ) as c:
            r = await c.request(
                body.method.upper(), body.url,
                headers=headers,
                content=body.body.encode() if body.body else None,
            )
        resp_headers = {k: v for k, v in r.headers.items()}
        try:
            pretty = r.text
        except Exception:
            pretty = r.content[:20000].hex()
        return {
            "status": r.status_code,
            "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
            "headers": resp_headers,
            "body": pretty[:200_000],
            "url_final": str(r.url),
        }
    except Exception as e:
        return {
            "status": 0, "elapsed_ms": 0,
            "headers": {}, "body": f"error: {e}",
            "url_final": body.url,
        }


# ══════════════════════════════════════════════════════════════════════
# shell — runs through agent_v8._run_shell (deny-list + scope enforced)
# ══════════════════════════════════════════════════════════════════════

class ShellBody(BaseModel):
    cmd: str
    timeout: int = 0


@app.post("/api/scan/{target}/{ts}/shell")
async def api_shell(target: str, ts: str, body: ShellBody):
    if not body.cmd.strip():
        raise HTTPException(400, "cmd required")
    rd = _run_dir(target, ts)
    ag = agent_v8()
    st_mod = state_mod()

    def _run():
        with _dispatch_lock:
            ag.RUN_DIR = rd
            ag.STATE = st_mod.load(rd)
            try:
                import budget as _budget
                ag.BUD = _budget.get(rd)
            except Exception:
                ag.BUD = None
            try:
                timeout = body.timeout if body.timeout and body.timeout > 0 else None
                out = ag._run_shell(body.cmd, timeout=timeout)
            finally:
                try:
                    st_mod.save(rd, ag.STATE)
                except Exception:
                    pass
        return out

    try:
        out = await asyncio.to_thread(_run)
    except Exception as e:
        out = f"shell error: {e}"
    return {"cmd": body.cmd, "output": str(out)}


# ══════════════════════════════════════════════════════════════════════
# re-scan / resume / attack — spawn agent_v8.py for the same target
# ══════════════════════════════════════════════════════════════════════

def _spawn_for_target(target: str, mode: str) -> dict:
    t = _safe_target(target)
    if mode == "rescan":
        return spawn_scan(f"assess {t}", attack=False, resume=False, dry=False)
    if mode == "resume":
        return spawn_scan(f"continue {t}", attack=False, resume=True, dry=False)
    if mode == "attack":
        return spawn_scan(f"assess {t}", attack=True, resume=False, dry=False)
    raise HTTPException(400, f"unknown mode: {mode}")


@app.post("/api/scan/{target}/{ts}/rescan")
def api_rescan(target: str, ts: str):
    _run_dir(target, ts)
    return _spawn_for_target(target, "rescan")


@app.post("/api/scan/{target}/{ts}/resume")
def api_resume(target: str, ts: str):
    _run_dir(target, ts)
    return _spawn_for_target(target, "resume")


@app.post("/api/scan/{target}/{ts}/attack")
def api_attack(target: str, ts: str):
    _run_dir(target, ts)
    return _spawn_for_target(target, "attack")


# ══════════════════════════════════════════════════════════════════════
# inline UI
# ══════════════════════════════════════════════════════════════════════

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ag · dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#0d1117; --bg2:#161b22; --bg3:#1c2129; --border:#30363d;
  --fg:#c9d1d9; --dim:#8b949e; --accent:#58a6ff; --green:#3fb950;
  --yellow:#d29922; --red:#f85149; --mag:#bc8cff; --cyan:#79c0ff;
  --crit:#7a0010; --hi:#a3121c; --med:#b55a00; --lo:#a88500; --info:#23638a;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;height:100%;background:var(--bg);color:var(--fg);font-family:var(--mono);font-size:12px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
button{background:var(--bg3);color:var(--fg);border:1px solid var(--border);padding:5px 10px;border-radius:4px;cursor:pointer;font-family:var(--mono);font-size:12px}
button:hover{background:#22272e;border-color:#484f58}
button.primary{background:#1f6feb;border-color:#1f6feb;color:#fff}
button.primary:hover{background:#388bfd}
button.danger{background:#6b1e1e;border-color:#6b1e1e;color:#f0a0a0}
button.danger:hover{background:#8a2626}
input,textarea,select{background:var(--bg2);color:var(--fg);border:1px solid var(--border);padding:5px 8px;border-radius:4px;font-family:var(--mono);font-size:12px;width:100%}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--accent)}
textarea{resize:vertical;min-height:60px;line-height:1.4}
.badge{display:inline-block;padding:1px 6px;border-radius:10px;font-size:10px;border:1px solid var(--border)}
.badge.live{background:#132e1a;border-color:#2c7a3d;color:#8ee8a2}
.badge.done{background:#232830;border-color:#3b424d;color:#9ba7b3}
.badge.crit{background:#3a0810;border-color:#7a0010;color:#ffb1b1}
.badge.hi{background:#2e0b0e;border-color:#a3121c;color:#ffb4b4}
.badge.med{background:#2e1a07;border-color:#b55a00;color:#ffce9e}
.badge.lo{background:#2c2405;border-color:#a88500;color:#ffe57a}
.badge.info{background:#0e1e2b;border-color:#23638a;color:#a9d6ff}

/* layout */
#app{display:grid;grid-template-columns:260px 1fr;height:100vh;overflow:hidden}
#side{background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
#side .head{padding:10px;border-bottom:1px solid var(--border);display:flex;gap:6px;align-items:center}
#side .head strong{color:var(--accent);letter-spacing:0.05em}
#side .scans{flex:1;overflow-y:auto;padding:6px}
.scan{padding:8px;border:1px solid transparent;border-radius:5px;cursor:pointer;margin-bottom:3px}
.scan:hover{background:var(--bg3)}
.scan.sel{background:var(--bg3);border-color:var(--accent)}
.scan .row1{display:flex;justify-content:space-between;align-items:center;gap:6px}
.scan .tgt{color:var(--fg);font-weight:bold;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.scan .meta{color:var(--dim);font-size:10px;margin-top:3px;display:flex;gap:8px;flex-wrap:wrap}
.scan .stats{color:var(--dim);font-size:10px;margin-top:4px}
#main{display:flex;flex-direction:column;overflow:hidden}
#top{padding:8px 12px;border-bottom:1px solid var(--border);background:var(--bg2);display:flex;align-items:center;gap:12px;flex-wrap:wrap}
#top .title{font-weight:bold;color:var(--accent)}
#top .path{color:var(--dim);font-size:11px}
#tabs{display:flex;border-bottom:1px solid var(--border);background:var(--bg2)}
.tab{padding:8px 14px;cursor:pointer;border-bottom:2px solid transparent;color:var(--dim)}
.tab:hover{color:var(--fg);background:var(--bg3)}
.tab.on{color:var(--fg);border-bottom-color:var(--accent)}
#body{flex:1;overflow:auto;padding:12px}
.tabpane{display:none}
.tabpane.on{display:block}

/* cards */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px;margin-bottom:14px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px}
.card .lbl{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:0.05em}
.card .val{font-size:20px;font-weight:bold;margin-top:4px}
.card.crit .val{color:var(--red)}
.card.ok .val{color:var(--green)}

h3{margin:16px 0 8px 0;color:var(--accent);font-size:12px;text-transform:uppercase;letter-spacing:0.08em;border-bottom:1px solid var(--border);padding-bottom:4px}
h3:first-child{margin-top:0}

table{width:100%;border-collapse:collapse;font-size:11px}
th,td{padding:5px 8px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--dim);font-weight:normal;text-transform:uppercase;font-size:10px;letter-spacing:0.05em;background:var(--bg2);position:sticky;top:0}
tr:hover td{background:var(--bg2)}
td.mono{font-family:var(--mono);word-break:break-all}

/* log panes */
.logs{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;height:calc(100vh - 220px)}
.logbox{background:#05080c;border:1px solid var(--border);border-radius:6px;display:flex;flex-direction:column;overflow:hidden;min-height:200px}
.logbox .head{padding:5px 8px;background:var(--bg2);border-bottom:1px solid var(--border);color:var(--dim);font-size:10px;display:flex;justify-content:space-between;align-items:center}
.logbox .log{flex:1;overflow-y:auto;padding:6px 8px;font-family:var(--mono);font-size:11px;white-space:pre-wrap;word-break:break-word;line-height:1.35}
.logbox .log .ln{border-bottom:1px solid #0f151c;padding:1px 0}
.logbox.live .head{color:var(--green)}

/* form/panel */
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:12px}
.row{display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
.row label{color:var(--dim);min-width:80px;font-size:11px}
.row .grow{flex:1}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
pre.out{background:#05080c;border:1px solid var(--border);padding:8px;border-radius:4px;overflow:auto;max-height:60vh;font-size:11px;line-height:1.4;white-space:pre-wrap;word-break:break-word;margin:0}

/* findings */
.finding{border:1px solid var(--border);border-radius:6px;margin-bottom:6px;background:var(--bg2)}
.finding .fh{padding:8px;cursor:pointer;display:flex;gap:8px;align-items:center}
.finding .fh:hover{background:var(--bg3)}
.finding .fb{display:none;padding:10px;border-top:1px solid var(--border);background:#05080c}
.finding.open .fb{display:block}
.finding .title{flex:1;overflow:hidden;text-overflow:ellipsis}

/* modal */
#modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.6);display:none;align-items:center;justify-content:center;z-index:100}
#modal-bg.on{display:flex}
#modal{background:var(--bg2);border:1px solid var(--border);border-radius:8px;max-width:900px;max-height:80vh;width:90%;display:flex;flex-direction:column;overflow:hidden}
#modal .mhead{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
#modal .mbody{padding:14px;overflow:auto}

/* misc */
.muted{color:var(--dim)}
.mt6{margin-top:6px}.mt10{margin-top:10px}
.sp{display:flex;gap:6px;flex-wrap:wrap}
.kv{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;font-size:11px}
.kv .k{color:var(--dim)}
.toast{position:fixed;bottom:16px;right:16px;background:var(--bg2);border:1px solid var(--border);padding:10px 14px;border-radius:6px;opacity:0;transition:opacity .2s;z-index:200;pointer-events:none;max-width:400px}
.toast.on{opacity:1}
</style>
</head>
<body>
<div id="app">
  <aside id="side">
    <div class="head">
      <strong>ag · dash</strong>
      <button id="btn-refresh" title="refresh scans">↻</button>
      <button id="btn-new" class="primary" title="start new scan">+ scan</button>
    </div>
    <div class="scans" id="scans"></div>
  </aside>
  <section id="main">
    <div id="top">
      <span class="title" id="cur-title">no scan selected</span>
      <span class="path" id="cur-path"></span>
      <span style="flex:1"></span>
      <button id="btn-rescan" title="start a fresh scan on this target">&#8635; re-scan</button>
      <button id="btn-resume" title="resume the latest run for this target">&#9654; resume</button>
      <button id="btn-attack" title="jump straight to attack phase">&#9876; attack</button>
      <span id="live-dot" class="badge done">idle</span>
    </div>
    <div id="tabs">
      <div class="tab on" data-t="overview">Overview</div>
      <div class="tab" data-t="logs">Logs</div>
      <div class="tab" data-t="findings">Findings</div>
      <div class="tab" data-t="actions">Actions</div>
      <div class="tab" data-t="repeater">Repeater</div>
      <div class="tab" data-t="shell">Shell</div>
      <div class="tab" data-t="tools">Tools</div>
      <div class="tab" data-t="config">Config</div>
      <div class="tab" data-t="running">Running</div>
    </div>
    <div id="body">

      <!-- OVERVIEW -->
      <div class="tabpane on" data-p="overview">
        <div class="cards" id="ov-cards"></div>
        <div id="ov-stack"></div>
        <h3>Recent findings</h3>
        <div id="ov-findings"></div>
      </div>

      <!-- LOGS -->
      <div class="tabpane" data-p="logs">
        <div class="logs">
          <div class="logbox live"><div class="head"><span>live.log</span><span id="l1-n"></span></div><div class="log" id="l1"></div></div>
          <div class="logbox"><div class="head"><span>live_findings.log</span><span id="l2-n"></span></div><div class="log" id="l2"></div></div>
          <div class="logbox"><div class="head"><span>live_commands.log</span><span id="l3-n"></span></div><div class="log" id="l3"></div></div>
        </div>
      </div>

      <!-- FINDINGS -->
      <div class="tabpane" data-p="findings">
        <div class="sp" style="margin-bottom:10px">
          <input id="find-q" placeholder="filter..." style="max-width:300px">
          <select id="find-sev" style="max-width:130px">
            <option value="">all severities</option>
            <option>critical</option><option>high</option><option>medium</option>
            <option>low</option><option>info</option>
          </select>
        </div>
        <div id="find-list"></div>
      </div>

      <!-- ACTIONS -->
      <div class="tabpane" data-p="actions">
        <div class="panel">
          <h3>Dispatch directive into this run</h3>
          <div class="row">
            <label>kind</label>
            <select id="act-kind" style="max-width:220px"></select>
            <span class="muted" id="act-hint"></span>
          </div>
          <div class="row"><label>payload</label><textarea id="act-payload" rows="3" placeholder="e.g. curl -sSILk https://target --max-time 20"></textarea></div>
          <div class="row">
            <button class="primary" id="act-run">Run</button>
            <button id="act-clear">Clear</button>
            <span class="muted">runs through agent_v8.dispatch() — same table the CLI loop uses</span>
          </div>
          <pre class="out" id="act-out">(no action yet)</pre>
        </div>
        <h3>Recent actions (this session)</h3>
        <div id="act-hist"></div>
      </div>

      <!-- REPEATER -->
      <div class="tabpane" data-p="repeater">
        <div class="panel">
          <div class="row">
            <label>method</label>
            <select id="rp-method" style="max-width:120px">
              <option>GET</option><option>POST</option><option>PUT</option>
              <option>PATCH</option><option>DELETE</option><option>HEAD</option><option>OPTIONS</option>
            </select>
            <input id="rp-url" class="grow" placeholder="https://target/path">
          </div>
          <div class="row">
            <label>headers</label>
            <textarea id="rp-headers" rows="3" placeholder='{"User-Agent": "Mozilla/5.0", "Cookie": "..."}'></textarea>
          </div>
          <div class="row">
            <label>body</label>
            <textarea id="rp-body" rows="3" placeholder='{"x":1}'></textarea>
          </div>
          <div class="row">
            <button class="primary" id="rp-send">Send</button>
            <label class="muted"><input type="checkbox" id="rp-follow" style="width:auto;margin-right:4px">follow redirects</label>
            <span class="muted" id="rp-status"></span>
          </div>
        </div>
        <h3>Response</h3>
        <div id="rp-resp"></div>
      </div>

      <!-- SHELL -->
      <div class="tabpane" data-p="shell">
        <div class="panel">
          <h3>Shell — runs in this run dir</h3>
          <div class="row">
            <span style="color:var(--green);font-weight:bold">$</span>
            <input id="sh-cmd" class="grow" placeholder="curl -sSILk https://target --max-time 20" autocomplete="off" spellcheck="false">
            <button class="primary" id="sh-run">Run</button>
            <button id="sh-clear">Clear</button>
          </div>
          <div class="muted mt6">
            history: &#8593;/&#8595; &middot; deny-list + scope enforced &middot; blocking call &mdash; nmap/nuclei will take a while
          </div>
        </div>
        <pre class="out" id="sh-out" style="min-height:300px;max-height:60vh">(nothing yet)</pre>
      </div>

      <!-- TOOLS -->
      <div class="tabpane" data-p="tools">
        <div class="sp" style="margin-bottom:10px">
          <input id="tools-q" placeholder="search tools..." style="max-width:300px">
          <select id="tools-cat" style="max-width:160px"><option value="">all categories</option></select>
          <label class="muted"><input type="checkbox" id="tools-missing" style="width:auto;margin-right:4px">missing only</label>
          <span style="flex:1"></span>
          <button id="tools-reload">reload</button>
        </div>
        <div id="tools-list"></div>
      </div>

      <!-- CONFIG -->
      <div class="tabpane" data-p="config">
        <div class="panel">
          <h3>API keys &amp; env</h3>
          <div class="muted mt6" id="cfg-path"></div>
          <div id="cfg-fields" class="mt10"></div>
          <div class="row mt10">
            <button class="primary" id="cfg-save">Save to .env</button>
            <span class="muted">restart the agent for changes to take effect</span>
          </div>
        </div>
      </div>

      <!-- RUNNING -->
      <div class="tabpane" data-p="running">
        <h3>Scans spawned from this dashboard</h3>
        <div id="run-list"></div>
      </div>

    </div>
  </section>
</div>

<!-- modal -->
<div id="modal-bg">
  <div id="modal">
    <div class="mhead"><strong id="m-title"></strong><button id="m-close">×</button></div>
    <div class="mbody" id="m-body"></div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
// ── state ─────────────────────────────────────────────────────────
const S = {
  scans: [],
  cur: null,          // {target, ts}
  es: null,           // active EventSource
  directives: [],
  actionHist: [],
  tools: [],
  running: [],
};

const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
const esc = s => (s==null?"":String(s)).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function toast(msg, ms=2600){
  const t = $("#toast"); t.textContent = msg; t.classList.add("on");
  setTimeout(()=>t.classList.remove("on"), ms);
}

async function jget(u){ const r=await fetch(u); if(!r.ok) throw new Error(r.status+" "+r.statusText); return r.json(); }
async function jpost(u,b){ const r=await fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})}); if(!r.ok){const t=await r.text(); throw new Error(r.status+" "+t);} return r.json(); }

// ── tabs ──────────────────────────────────────────────────────────
$$(".tab").forEach(t => t.onclick = () => {
  $$(".tab").forEach(x=>x.classList.remove("on"));
  $$(".tabpane").forEach(x=>x.classList.remove("on"));
  t.classList.add("on");
  $(`.tabpane[data-p="${t.dataset.t}"]`).classList.add("on");
  if (t.dataset.t === "tools") loadTools();
  if (t.dataset.t === "config") loadKeys();
  if (t.dataset.t === "shell") setTimeout(shFocus, 40);
  if (t.dataset.t === "logs") startLogPolling();
  else stopLogPolling();
  if (t.dataset.t === "running") {
    loadRunning(true);
    if (RUNNING_TIMER) clearInterval(RUNNING_TIMER);
    RUNNING_TIMER = setInterval(()=>loadRunning(true), 1500);
  } else if (RUNNING_TIMER) {
    clearInterval(RUNNING_TIMER);
    RUNNING_TIMER = null;
  }
});

// ── scans list ────────────────────────────────────────────────────
async function loadScans(){
  const j = await jget("/api/scans");
  S.scans = j.scans || [];
  renderScans();
}
function renderScans(){
  const el = $("#scans");
  if (!S.scans.length){ el.innerHTML = '<div class="muted" style="padding:10px">no scans in '+esc(location.origin)+'/scans</div>'; return; }
  el.innerHTML = S.scans.map(s => {
    const sel = S.cur && S.cur.target===s.target && S.cur.ts===s.ts ? "sel" : "";
    const live = s.is_live ? '<span class="badge live">live</span>' : '<span class="badge done">idle</span>';
    const started = (s.started_at||"").replace("T"," ").slice(0,19);
    return `<div class="scan ${sel}" data-t="${esc(s.target)}" data-ts="${esc(s.ts)}">
      <div class="row1"><span class="tgt">${esc(s.target)}</span>${live}</div>
      <div class="meta"><span>${esc(s.ts)}</span></div>
      <div class="meta"><span>started ${esc(started)}</span></div>
      <div class="stats">t${s.turn} · <b style="color:var(--red)">${s.findings}</b>f · ${s.endpoints}e · ${s.attacks}a</div>
    </div>`;
  }).join("");
  $$("#scans .scan").forEach(d => d.onclick = () => selectScan(d.dataset.t, d.dataset.ts));
}

// ── select scan ───────────────────────────────────────────────────
async function selectScan(target, ts){
  S.cur = {target, ts};
  renderScans();
  $("#cur-title").textContent = target + " / " + ts;
  $("#cur-path").textContent = "";
  try {
    const j = await jget(`/api/scan/${encodeURIComponent(target)}/${encodeURIComponent(ts)}`);
    $("#cur-path").textContent = j.meta.path;
    renderOverview(j.state);
    renderFindings(j.state);
    setLiveBadge(j.meta.is_live);
    if ($(".tab.on")?.dataset.t === "logs") startLogPolling();
  } catch(e){ toast("load failed: "+e.message); }
}

function setLiveBadge(live){
  const d = $("#live-dot");
  d.textContent = live ? "live" : "idle";
  d.className = "badge " + (live ? "live" : "done");
}

window.viewScan = function(target, ts){
  document.querySelector('.tab[data-t="overview"]').click();
  selectScan(target, ts);
};

async function refreshCurrentScan(){
  if (!S.cur) return;
  try {
    const j = await jget(`/api/scan/${encodeURIComponent(S.cur.target)}/${encodeURIComponent(S.cur.ts)}`);
    renderOverview(j.state);
    renderFindings(j.state);
    setLiveBadge(j.meta.is_live);
  } catch(e){ /* silent */ }
}

// ── overview ──────────────────────────────────────────────────────
function renderOverview(st){
  const f = st.findings||[], e = st.endpoints||[], a = st.attacks||[];
  const w = st.walks||[], s = st.secrets||[], c = st.creds||[], ch = st.chains||[];
  const loot = st.loot||[];
  const bysev = {critical:0,high:0,medium:0,low:0,info:0};
  f.forEach(x => { bysev[(x.sev||"info").toLowerCase()] = (bysev[(x.sev||"info").toLowerCase()]||0)+1; });
  const cards = [
    ["findings", f.length, "crit"],
    ["critical", bysev.critical, "crit"],
    ["high", bysev.high, "crit"],
    ["endpoints", e.length, ""],
    ["secrets", s.length, "crit"],
    ["creds", c.length, "crit"],
    ["walks", w.length, ""],
    ["attacks", a.length, ""],
    ["loot", loot.length, ""],
    ["chains", ch.length, ""],
    ["turn", st.turn||0, "ok"],
    ["phase", st.phase||"-", "ok"],
  ];
  $("#ov-cards").innerHTML = cards.map(([l,v,k])=>
    `<div class="card ${k}"><div class="lbl">${esc(l)}</div><div class="val">${esc(v)}</div></div>`).join("");

  const tech = st.tech_stack||[];
  const meth = st.methods_used||[];
  $("#ov-stack").innerHTML = `
    <h3>Stack &amp; methodology</h3>
    <div class="kv">
      <div class="k">tech</div><div>${tech.length?tech.map(esc).join(", "):'<span class="muted">—</span>'}</div>
      <div class="k">methods used</div><div>${meth.length?meth.map(esc).join(", "):'<span class="muted">—</span>'}</div>
      <div class="k">target</div><div>${esc(st.target||"?")}</div>
      <div class="k">attack summary</div><div>${esc(JSON.stringify(st.attack_summary||{}))}</div>
    </div>`;

  const recent = f.slice(-8).reverse();
  $("#ov-findings").innerHTML = recent.length ? recent.map(x=>{
    const sev = (x.sev||"info").toLowerCase();
    return `<div class="finding">
      <div class="fh" onclick="this.parentElement.classList.toggle('open')">
        <span class="badge ${sev}">${esc(sev)}</span>
        <span class="title">${esc(x.title||"?")}</span>
      </div>
      <div class="fb"><pre class="out">${esc(x.evidence||"")}</pre></div>
    </div>`;
  }).join("") : '<div class="muted">no findings yet</div>';
}

// ── findings ──────────────────────────────────────────────────────
let FIND_STATE = {};
function renderFindings(st){
  FIND_STATE = st;
  const q = ($("#find-q").value||"").toLowerCase();
  const sv = $("#find-sev").value;
  const list = (st.findings||[]).filter(x=>{
    if (sv && (x.sev||"").toLowerCase() !== sv) return false;
    if (q && !((x.title||"")+" "+(x.evidence||"")).toLowerCase().includes(q)) return false;
    return true;
  }).reverse();
  $("#find-list").innerHTML = list.length ? list.map((x,i)=>{
    const sev = (x.sev||"info").toLowerCase();
    const gid = "f_"+i+"_"+Math.random().toString(36).slice(2,8);
    return `<div class="finding" id="${gid}">
      <div class="fh" onclick="document.getElementById('${gid}').classList.toggle('open')">
        <span class="badge ${sev}">${esc(sev)}</span>
        <span class="title">${esc(x.title||"?")}</span>
        <button onclick="event.stopPropagation(); useFinding('${gid}')">↗ repeater</button>
      </div>
      <div class="fb"><pre class="out">${esc(x.evidence||"")}</pre></div>
    </div>`;
  }).join("") : '<div class="muted">no findings match</div>';
}
window.useFinding = function(gid){
  const el = document.getElementById(gid);
  const txt = el.querySelector(".fb pre").textContent;
  const m = txt.match(/https?:\/\/[^\s"'<>]+/);
  if (m){ $("#rp-url").value = m[0]; document.querySelector('.tab[data-t="repeater"]').click(); }
  else toast("no URL in this finding's evidence");
};

$("#find-q").oninput = () => renderFindings(FIND_STATE);
$("#find-sev").onchange = () => renderFindings(FIND_STATE);

// ── live stream (SSE) ─────────────────────────────────────────────
// v5: polling replaces SSE (SSE silently failed behind WSL port proxy)
let LOG_TIMER = null;

async function _fetchLog(file){
  if (!S.cur) return;
  try {
    const url = `/api/scan/${encodeURIComponent(S.cur.target)}/${encodeURIComponent(S.cur.ts)}/log?file=${encodeURIComponent(file)}&tail=400`;
    const r = await fetch(url);
    if (!r.ok) return;
    const j = await r.json();
    const box = logboxFor(file);
    if (!box) return;
    const wasNearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    // replace whole box (simpler than diffing; 400 lines is cheap)
    box.innerHTML = "";
    (j.lines||[]).forEach(ln => {
      const div = document.createElement("div");
      div.className = "ln";
      div.textContent = ln;
      box.appendChild(div);
    });
    if (wasNearBottom) box.scrollTop = box.scrollHeight;
  } catch(e){ /* silent */ }
}

async function refreshLogsNow(){
  await Promise.all([
    _fetchLog("live.log"),
    _fetchLog("live_findings.log"),
    _fetchLog("live_commands.log"),
  ]);
}

function startLogPolling(){
  stopLogPolling();
  refreshLogsNow();
  LOG_TIMER = setInterval(refreshLogsNow, 1200);
}
function stopLogPolling(){
  if (LOG_TIMER){ clearInterval(LOG_TIMER); LOG_TIMER = null; }
}

// keep a stub so the existing call site in selectScan doesn't error
function attachStream(target, ts){
  if ($(".tab.on")?.dataset.t === "logs") startLogPolling();
}
function logboxFor(file){
  if (file === "live.log") return $("#l1");
  if (file === "live_findings.log") return $("#l2");
  if (file === "live_commands.log") return $("#l3");
  return null;
}
function appendLog(box, line){
  const div = document.createElement("div");
  div.className = "ln";
  div.textContent = line;
  box.appendChild(div);
  if (box.children.length > 3000) box.removeChild(box.firstChild);
}
function scrollBottom(box){
  const near = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  if (near) box.scrollTop = box.scrollHeight;
}

// ── actions ───────────────────────────────────────────────────────
async function loadDirectives(){
  try {
    const j = await jget("/api/directives");
    S.directives = j.names || [];
    $("#act-kind").innerHTML = S.directives.map(n=>`<option>${esc(n)}</option>`).join("");
    updActHint();
  } catch(_){}
}
const ACT_HINTS = {
  COMMAND:   "raw shell — filtered by deny-list + scope",
  PROBE:     "METHOD|URL — fires 9 auth-bypass variants",
  WALK:      "METHOD|URL|param|start|end",
  ENDPOINT:  "METHOD|URL|note",
  FINDING:   "sev|title|evidence",
  EXPLOIT:   "tool|target|args",
  LOOT:      "kind|value",
  CRACK:     "hash|auto",
  SEARCH:    "query",
  FETCH:     "url",
  FILE:      "path|content",
  GRAPHQL:   "url|query_json",
  WS:        "wss_url|payload",
  OOB:       "method|url|param|payload_{callback}",
  MUTATE:    "payload|context",
  APIMAP:    "base_url",
  PARAMFIND: "METHOD|URL",
  REPORT:    "reason",
  NOTE:      "text",
  CVE:       "product|version",
  WAF:       "url",
  STACK:     "url",
  BROWSER:   "url",
  SECRET:    "text or /path",
  CRED:      "user|pass|where",
};
function updActHint(){
  const k = $("#act-kind").value;
  $("#act-hint").textContent = ACT_HINTS[k] || "";
}
$("#act-kind").onchange = updActHint;
$("#act-clear").onclick = () => { $("#act-payload").value = ""; $("#act-out").textContent = "(no action yet)"; };

$("#act-run").onclick = async () => {
  if (!S.cur){ toast("select a scan first"); return; }
  const kind = $("#act-kind").value;
  const payload = $("#act-payload").value;
  $("#act-out").textContent = "running…";
  try {
    const j = await jpost(`/api/scan/${encodeURIComponent(S.cur.target)}/${encodeURIComponent(S.cur.ts)}/action`, {kind, payload});
    $("#act-out").textContent = j.result || "(empty)";
    S.actionHist.unshift({ts:new Date().toISOString(), kind, payload, result:j.result});
    if (S.actionHist.length > 50) S.actionHist.pop();
    renderActionHist();
    await refreshCurrentScan();
    if ($(".tab.on")?.dataset.t === "running") loadRunning(true);
  } catch(e){
    $("#act-out").textContent = "error: " + e.message;
  }
};
function renderActionHist(){
  $("#act-hist").innerHTML = S.actionHist.length ? `<table>
    <thead><tr><th>when</th><th>kind</th><th>payload</th><th>result</th></tr></thead>
    <tbody>${S.actionHist.map(h=>`<tr>
      <td class="mono">${esc(h.ts.slice(11,19))}</td>
      <td><b>${esc(h.kind)}</b></td>
      <td class="mono">${esc((h.payload||"").slice(0,80))}</td>
      <td class="mono muted">${esc((h.result||"").slice(0,120))}</td>
    </tr>`).join("")}</tbody></table>` : '<div class="muted">nothing yet</div>';
}

// ── repeater ──────────────────────────────────────────────────────
$("#rp-send").onclick = async () => {
  const method = $("#rp-method").value;
  const url = $("#rp-url").value.trim();
  if (!url){ toast("url required"); return; }
  let headers = {};
  const hraw = $("#rp-headers").value.trim();
  if (hraw){
    try { headers = JSON.parse(hraw); }
    catch(e){ toast("headers must be JSON"); return; }
  }
  const body = $("#rp-body").value;
  const follow = $("#rp-follow").checked;
  $("#rp-status").textContent = "sending…";
  try {
    const j = await jpost("/api/repeater", {method, url, headers, body, follow});
    $("#rp-status").textContent = `${j.status} · ${j.elapsed_ms}ms`;
    const h = Object.entries(j.headers||{}).map(([k,v])=>`${esc(k)}: ${esc(v)}`).join("\n");
    $("#rp-resp").innerHTML = `
      <div class="panel">
        <div class="kv">
          <div class="k">status</div><div>${esc(j.status)}</div>
          <div class="k">time</div><div>${esc(j.elapsed_ms)}ms</div>
          <div class="k">final url</div><div>${esc(j.url_final)}</div>
        </div>
      </div>
      <h3>Headers</h3><pre class="out">${h}</pre>
      <h3>Body</h3><pre class="out">${esc(j.body||"")}</pre>`;
  } catch(e){
    $("#rp-status").textContent = "error";
    $("#rp-resp").innerHTML = `<pre class="out">${esc(e.message)}</pre>`;
  }
};

// ── shell (terminal-like) ─────────────────────────────────────────
let SHELL_HIST = [];
let SHELL_HIST_IDX = -1;

function _loadShellHist(){
  try { SHELL_HIST = JSON.parse(localStorage.getItem("ag_shell_hist") || "[]"); }
  catch(e){ SHELL_HIST = []; }
}
function _saveShellHist(){
  try { localStorage.setItem("ag_shell_hist", JSON.stringify(SHELL_HIST.slice(0,200))); }
  catch(e){}
}
_loadShellHist();

function shFocus(){
  const e = document.getElementById("sh-cmd");
  if (e) e.focus();
}

async function runShell(){
  if (!S.cur){ toast("select a scan first"); return; }
  const inp = document.getElementById("sh-cmd");
  if (!inp) return;
  const cmd = inp.value.trim();
  if (!cmd) return;
  SHELL_HIST.unshift(cmd);
  SHELL_HIST_IDX = -1;
  _saveShellHist();

  const out = document.getElementById("sh-out");
  const stamp = new Date().toISOString().slice(11,19);
  out.textContent += "\n[" + stamp + "] $ " + cmd + "\n";
  out.scrollTop = out.scrollHeight;
  const btn = document.getElementById("sh-run");
  btn.disabled = true;
  btn.textContent = "...";
  try {
    const j = await jpost(
      `/api/scan/${encodeURIComponent(S.cur.target)}/${encodeURIComponent(S.cur.ts)}/shell`,
      { cmd }
    );
    out.textContent += (j.output || "(no output)") + "\n";
  } catch(e){
    out.textContent += "[error] " + e.message + "\n";
  } finally {
    out.scrollTop = out.scrollHeight;
    btn.disabled = false;
    btn.textContent = "Run";
    inp.value = "";
    inp.focus();
    refreshCurrentScan();
  }
}

(function bindShell(){
  const inp = document.getElementById("sh-cmd");
  if (!inp) return;
  inp.addEventListener("keydown", (e) => {
    if (e.key === "Enter"){ e.preventDefault(); runShell(); return; }
    if (e.key === "ArrowUp"){
      e.preventDefault();
      if (!SHELL_HIST.length) return;
      SHELL_HIST_IDX = Math.min(SHELL_HIST_IDX + 1, SHELL_HIST.length - 1);
      inp.value = SHELL_HIST[SHELL_HIST_IDX];
      setTimeout(()=>inp.setSelectionRange(9999,9999),0);
    }
    if (e.key === "ArrowDown"){
      e.preventDefault();
      if (SHELL_HIST_IDX <= 0){ SHELL_HIST_IDX = -1; inp.value = ""; return; }
      SHELL_HIST_IDX -= 1;
      inp.value = SHELL_HIST[SHELL_HIST_IDX];
    }
  });
  const run = document.getElementById("sh-run");
  if (run) run.onclick = runShell;
  const clr = document.getElementById("sh-clear");
  if (clr) clr.onclick = () => { document.getElementById("sh-out").textContent = "(nothing yet)"; };
})();


// ── top bar: re-scan / resume / attack ──────────────────────────
async function spawnMode(mode){
  if (!S.cur){ toast("select a scan first"); return; }
  const t = S.cur.target;
  const url = `/api/scan/${encodeURIComponent(t)}/${encodeURIComponent(S.cur.ts)}/${mode}`;
  try {
    const j = await jpost(url, {});
    toast(`${mode} spawned (pid ${j.pid})`);
    document.querySelector('.tab[data-t="running"]').click();
    loadRunning(true);
    setTimeout(()=>loadRunning(true), 600);
  } catch(e){ toast(mode + " failed: " + e.message); }
}
(function bindTopBar(){
  const br = document.getElementById("btn-rescan");
  if (br) br.onclick = () => spawnMode("rescan");
  const brr = document.getElementById("btn-resume");
  if (brr) brr.onclick = () => spawnMode("resume");
  const bra = document.getElementById("btn-attack");
  if (bra) bra.onclick = () => spawnMode("attack");
})();


// ── tools ─────────────────────────────────────────────────────────
async function loadTools(){
  const j = await jget("/api/tools");
  S.tools = j.tools || [];
  const cats = [...new Set(S.tools.map(t=>t.category))].sort();
  $("#tools-cat").innerHTML = '<option value="">all categories</option>' + cats.map(c=>`<option>${esc(c)}</option>`).join("");
  renderTools();
}
function renderTools(){
  const q = ($("#tools-q").value||"").toLowerCase();
  const cat = $("#tools-cat").value;
  const onlyMissing = $("#tools-missing").checked;
  const rows = S.tools.filter(t=>{
    if (cat && t.category !== cat) return false;
    if (onlyMissing && t.installed) return false;
    if (q && !((t.name+" "+t.desc).toLowerCase().includes(q))) return false;
    return true;
  });
  $("#tools-list").innerHTML = `<div class="muted mt6">${rows.length} of ${S.tools.length}</div>
    <table>
      <thead><tr><th>name</th><th>cat</th><th>state</th><th>desc</th><th></th></tr></thead>
      <tbody>${rows.map(t=>`<tr>
        <td class="mono"><b>${esc(t.name)}</b></td>
        <td>${esc(t.category)}</td>
        <td>${t.installed?'<span class="badge live">ok</span>':'<span class="badge done">missing</span>'}</td>
        <td>${esc(t.desc)}</td>
        <td>${t.installed?'':`<button onclick="installTool('${esc(t.name)}')">install</button>`}</td>
      </tr>`).join("")}</tbody></table>`;
}
window.installTool = async (name) => {
  toast("installing "+name+"…");
  try {
    const j = await jpost("/api/tools/install", {name});
    toast((j.result||"").split("\n")[0].slice(0,120));
    loadTools();
  } catch(e){ toast("install error: "+e.message); }
};
$("#tools-q").oninput = renderTools;
$("#tools-cat").onchange = renderTools;
$("#tools-missing").onchange = renderTools;
$("#tools-reload").onclick = loadTools;

// ── config ────────────────────────────────────────────────────────
const CFG_HINTS = {
  AG_MODEL: "e.g. deepseek-chat",
  AG_BASE: "e.g. https://api.deepseek.com/v1",
  AG_KEY: "usually same as DEEPSEEK_KEY",
  DEEPSEEK_KEY: "sk-…",
  AG_PROXY: "socks5://127.0.0.1:9050 (optional)",
  AG_SCAN_ROOT: "where run dirs live (~/scans)",
  AG_MAX_TURNS: "500",
  AG_CTX_MAX: "60",
  AG_CMD_TIMEOUT: "7200",
  AG_CURL_TIMEOUT: "25",
};
async function loadKeys(){
  const j = await jget("/api/keys");
  $("#cfg-path").textContent = "writes to: " + j.path;
  const fields = ["AG_MODEL","AG_BASE","AG_KEY","DEEPSEEK_KEY","AG_PROXY","AG_SCAN_ROOT","AG_MAX_TURNS","AG_CTX_MAX","AG_CMD_TIMEOUT","AG_CURL_TIMEOUT"];
  const warn = (j.overridden||[]).length
    ? `<div class="panel" style="border-color:var(--yellow);background:#2c2405">
         <b style="color:var(--yellow)">env overrides .env for:</b> ${j.overridden.map(esc).join(", ")}
         <div class="muted mt6">editing these in .env has no effect until you unset them in the shell.</div>
       </div>` : "";
  $("#cfg-fields").innerHTML = warn + fields.map(k => {
    const eff = j.effective[k];
    return `<div class="row">
      <label style="min-width:150px">${esc(k)}</label>
      <input data-k="${esc(k)}" value="${esc(j.env[k]||"")}" placeholder="${esc(CFG_HINTS[k]||"")}">
      <span class="muted" style="min-width:90px">${eff?'<span class="badge live">in env</span>':''}</span>
    </div>`;
  }).join("") + `
  <h3 style="margin-top:16px">Raw .env</h3>
  <div class="muted mt6" style="margin-bottom:6px">edit directly — save writes the file. applies on next scan spawn.</div>
  <textarea id="cfg-raw" rows="8" style="font-family:var(--mono);font-size:11px">${esc(j.raw_text||"")}</textarea>
  <div class="row mt6"><button id="cfg-raw-save">Save raw .env</button><span class="muted">overwrites entire file</span></div>`;
  const rawBtn = document.getElementById("cfg-raw-save");
  if (rawBtn) rawBtn.onclick = async () => {
    const text = document.getElementById("cfg-raw").value;
    const updates = {};
    text.split("\n").forEach(line=>{
      const t = line.trim();
      if (!t || t.startsWith("#") || !t.includes("=")) return;
      const parts = t.split("=");
      const k = parts.shift().trim();
      updates[k] = parts.join("=").replace(/^["']|["']$/g,"");
    });
    try { await jpost("/api/keys", {updates}); toast("raw .env saved"); loadKeys(); }
    catch(e){ toast("save failed: "+e.message); }
  };
}
$("#cfg-save").onclick = async () => {
  const updates = {};
  $$("#cfg-fields input").forEach(i => { if (i.value !== i.defaultValue) updates[i.dataset.k] = i.value; });
  if (!Object.keys(updates).length){ toast("no changes"); return; }
  try {
    await jpost("/api/keys", {updates});
    toast("saved " + Object.keys(updates).length + " field(s)");
    loadKeys();
  } catch(e){ toast("save failed: "+e.message); }
};

// ── running ───────────────────────────────────────────────────────
let RUNNING_TIMER = null;
const HIDDEN_RUNS = new Set();

function toggleRunHidden(key){
  if (HIDDEN_RUNS.has(key)) HIDDEN_RUNS.delete(key);
  else HIDDEN_RUNS.add(key);
  renderRunningList();
}

async function copyRunLogs(key){
  const r = (S.running||[]).find(x => x.key === key);
  if (!r){ toast("log gone"); return; }
  let lines = r.lines || [];
  if (r.kind === "disk"){
    try {
      const j = await jget(`/api/running/${encodeURIComponent(key)}/lines?tail=2000`);
      lines = j.lines || lines;
    } catch(e){ /* fall back to cached */ }
  }
  const text = lines.join("");
  try {
    await navigator.clipboard.writeText(text);
    toast(`copied ${text.length} chars`);
  } catch(e){
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); toast(`copied ${text.length} chars`); }
    catch(_) { toast("copy blocked by browser"); }
    document.body.removeChild(ta);
  }
}

function renderRunningList(){
  const wrap = $("#run-list");
  if (!wrap) return;
  if (!S.running.length){
    wrap.innerHTML = '<div class="muted">nothing spawned from the dashboard</div>';
    return;
  }
  const sticky = {};
  $$("#run-list pre.out").forEach((pre,i) => {
    sticky[i] = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 60;
  });
  wrap.innerHTML = S.running.map(r => {
    const hidden = HIDDEN_RUNS.has(r.key);
    const nLines = (r.lines||[]).length;
    const isDisk = r.kind === "disk";
    const badge = r.alive
      ? '<span class="badge live">running</span>'
      : `<span class="badge done">exit ${r.exit_code ?? "?"}</span>`;
    const pidCell = r.pid ? `<span class="muted">pid ${r.pid}</span>` : '';
    const kindCell = isDisk
      ? '<span class="badge" style="background:#232830;border-color:#3b424d;color:#9ba7b3">external</span>'
      : '<span class="badge" style="background:#132e1a;border-color:#2c7a3d;color:#8ee8a2">dash</span>';
    const viewBtn = isDisk && r.target && r.ts
      ? `<button onclick="viewScan('${esc(r.target)}','${esc(r.ts)}')" title="open this scan">\u2197 view</button>`
      : '';
    return `
    <div class="panel" data-run-key="${esc(r.key)}">
      <div class="row">
        <button onclick="toggleRunHidden('${esc(r.key)}')"
                title="${hidden?'show':'hide'} output"
                style="min-width:28px;padding:2px 8px">${hidden?'\u25B8':'\u25BE'}</button>
        ${kindCell}
        <b>${esc((r.target||r.key)+(r.ts?('/'+r.ts):''))}</b>
        ${badge}
        ${pidCell}
        <span class="muted">${esc((r.started||"").slice(11,19))}</span>
        <span class="muted">${nLines} lines</span>
        <span style="flex:1"></span>
        ${viewBtn}
        <button onclick="copyRunLogs('${esc(r.key)}')" title="copy all logs">\u29C9 copy</button>
        ${r.alive && !isDisk ? `<button class="danger" onclick="killScan('${esc(r.key)}')">kill</button>` : ""}
      </div>
      <div class="muted mt6">${esc(r.task||"")}</div>
      <pre class="out mt6" style="max-height:340px;display:${hidden?'none':'block'}">${esc((r.lines||[]).join(""))}</pre>
    </div>`;
  }).join("");
  $$("#run-list pre.out").forEach((pre,i) => {
    if (sticky[i]) pre.scrollTop = pre.scrollHeight;
  });
}

async function loadRunning(quiet){
  let j;
  try { j = await jget("/api/running"); }
  catch(e){ if (!quiet) toast("running fetch: "+e.message); return; }
  const prev = S.running || [];
  S.running = j.running || [];
  // for disk-kind entries, pull fresh tails
  const diskKeys = S.running.filter(r=>r.kind==="disk").map(r=>r.key);
  if (diskKeys.length){
    const tails = await Promise.all(diskKeys.map(k =>
      jget(`/api/running/${encodeURIComponent(k)}/lines?tail=400`).catch(()=>null)
    ));
    diskKeys.forEach((k,i)=>{
      const t = tails[i];
      if (t && t.lines){
        const row = S.running.find(r=>r.key===k);
        if (row) row.lines = t.lines;
      }
    });
  }
  renderRunningList();
}
window.killScan = async (key) => {
  if (!confirm("kill scan "+key+"?")) return;
  try { await jpost(`/api/scan/running/${encodeURIComponent(key)}/kill`, {}); toast("kill sent"); loadRunning(); }
  catch(e){ toast("kill error: "+e.message); }
};

// ── start new scan ────────────────────────────────────────────────
$("#btn-new").onclick = () => {
  openModal("start new scan", `
    <div class="row"><label>task</label>
      <input id="ns-task" placeholder='e.g. assess https://target.example.com'></div>
    <div class="row">
      <label style="min-width:auto"><input type="checkbox" id="ns-attack" style="width:auto;margin-right:4px">attack phase</label>
      <label style="min-width:auto"><input type="checkbox" id="ns-resume" style="width:auto;margin-right:4px">resume</label>
      <label style="min-width:auto"><input type="checkbox" id="ns-dry" style="width:auto;margin-right:4px">dry</label>
    </div>
    <div class="row"><button class="primary" id="ns-go">Start</button>
      <span class="muted">spawns agent_v8.py as a child process</span></div>
    <pre class="out" id="ns-out" style="max-height:200px;display:none"></pre>
  `);
  $("#ns-go").onclick = async () => {
    const task = $("#ns-task").value.trim();
    if (!task){ toast("task required"); return; }
    try {
      const j = await jpost("/api/scan/start", {task, attack:$("#ns-attack").checked, resume:$("#ns-resume").checked, dry:$("#ns-dry").checked});
      $("#ns-out").style.display = "block";
      $("#ns-out").textContent = "spawned key="+j.key+" pid="+j.pid+"\noutput appears in Running tab";
      toast("scan started");
      document.querySelector('.tab[data-t="running"]').click();
      loadRunning(true);
      setTimeout(()=>loadRunning(true), 500);
      setTimeout(()=>loadRunning(true), 1500);
    } catch(e){ toast("start error: "+e.message); }
  };
};

// ── modal ─────────────────────────────────────────────────────────
function openModal(title, html){
  $("#m-title").textContent = title;
  $("#m-body").innerHTML = html;
  $("#modal-bg").classList.add("on");
}
$("#m-close").onclick = () => $("#modal-bg").classList.remove("on");
$("#modal-bg").onclick = (e) => { if (e.target.id === "modal-bg") $("#modal-bg").classList.remove("on"); };

// ── boot ──────────────────────────────────────────────────────────
$("#btn-refresh").onclick = () => { loadScans(); toast("scans refreshed"); };
loadDirectives();
loadScans().then(() => {
  if (S.scans.length && !S.cur) selectScan(S.scans[0].target, S.scans[0].ts);
});
setInterval(loadScans, 8000);
// background poll keeps the sidebar "live" badge fresh even off the Running tab
setInterval(()=>{ if ((S.running||[]).some(r=>r.alive)) loadRunning(true); }, 5000);
window.addEventListener("visibilitychange", () => {
  if (document.hidden) stopLogPolling();
  else if ($(".tab.on")?.dataset.t === "logs") startLogPolling();
});
setInterval(() => {
  if (!S.cur) return;
  jget(`/api/scan/${encodeURIComponent(S.cur.target)}/${encodeURIComponent(S.cur.ts)}/state`)
    .then(j => { renderOverview(j.state); renderFindings(j.state); })
    .catch(()=>{});
}, 3000);
</script>
</body>
</html>
"""


# ══════════════════════════════════════════════════════════════════════
# main
# ══════════════════════════════════════════════════════════════════════

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--reload", action="store_true")
    args = ap.parse_args()

    import uvicorn
    print(f"[dashboard] http://{args.host}:{args.port}/")
    print(f"[dashboard] scans root: {SCAN_ROOT}")
    uvicorn.run(
        "dashboard:app",
        host=args.host, port=args.port,
        reload=args.reload, log_level="warning",
    )


if __name__ == "__main__":
    main()
