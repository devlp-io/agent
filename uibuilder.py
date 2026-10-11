#!/usr/bin/env python3
import os, re, sys, json, time, hashlib, pathlib, argparse, subprocess

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SCAN_ROOT = pathlib.Path(os.environ.get("AG_SCAN_ROOT", os.path.expanduser("~/scans")))
SYS_PROMPT = (HERE / "uibuilder_prompt.txt").read_text(encoding="utf-8")


def _recorder():
    from core import recorder as r
    return r


def _agent_v8():
    import agent_v8 as m
    return m


PORT_BASE = 8801
PORT_RANGE = 200


def _port_for(t):
    h = hashlib.sha256(t.encode()).digest()
    return PORT_BASE + (int.from_bytes(h[:4], "big") % PORT_RANGE)


def _safe(t):
    return "".join(c for c in t if c.isalnum() or c in "._-")


def _uiapp_dir(t):
    p = SCAN_ROOT / _safe(t) / "uiapp"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _meta_path(t):
    return _uiapp_dir(t) / ".meta.json"


def _read_meta(t):
    p = _meta_path(t)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _write_meta(t, m):
    _meta_path(t).write_text(json.dumps(m, indent=2, default=str))


def _newest_run(t):
    base = SCAN_ROOT / _safe(t)
    if not base.exists():
        return None
    runs = sorted([d for d in base.iterdir()
                   if d.is_dir() and re.match(r"\d{8}_\d{6}$", d.name)],
                  reverse=True)
    return runs[0] if runs else None


def _load_json(p):
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _kill_prev(t):
    meta = _read_meta(t)
    pid = meta.get("pid")
    if pid:
        try:
            os.kill(int(pid), 15)
            time.sleep(0.5)
        except Exception:
            pass
    try:
        out = subprocess.run(
            ["bash", "-lc",
             f"pgrep -f 'uiapp/{_safe(t)}/app.py' 2>/dev/null || true"],
            capture_output=True, text=True, timeout=5).stdout
        for line in out.split():
            try:
                os.kill(int(line), 15)
            except Exception:
                pass
    except Exception:
        pass


def _spawn(t, port):
    d = _uiapp_dir(t)
    logp = d / "app.log"
    pidp = d / "app.pid"
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["UIA_TARGET"] = t
    env["UIA_SCANS_ROOT"] = str(SCAN_ROOT)
    py = sys.executable
    with open(logp, "ab") as lf:
        proc = subprocess.Popen(
            [py, "app.py", "--port", str(port)],
            cwd=str(d), env=env, stdout=lf, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
    pidp.write_text(str(proc.pid))
    return proc.pid


def _build_context(t, mode, chat=""):
    rec = _recorder().summary(t)
    run = _newest_run(t)
    state = _load_json(run / "state.json") if run else {}
    schema = _load_json(run / "schema.json") if run else {}
    ctx = {
        "target": t, "mode": mode,
        "newest_run": str(run) if run else None,
        "recorder": {
            "events": rec.get("events"),
            "first_seen": rec.get("first_seen"),
            "last_seen": rec.get("last_seen"),
            "commands_sample": rec.get("commands", [])[-40:],
            "findings": rec.get("findings", [])[-40:],
            "probes": rec.get("probes", [])[-40:],
            "walks": rec.get("walks", [])[-20:],
            "secrets": rec.get("secrets", [])[-40:],
            "creds": rec.get("creds", [])[-20:],
            "loot": rec.get("loot", [])[-20:],
            "endpoints": rec.get("endpoints", [])[-60:],
            "successful_reads": rec.get("successful_reads", [])[-20:],
            "successful_writes": rec.get("successful_writes", [])[-20:],
        },
        "state_summary": {
            "target": state.get("target") or t,
            "findings": (state.get("findings") or [])[-30:],
            "endpoints": (state.get("endpoints") or [])[-60:],
            "attacks": (state.get("attacks") or [])[-20:],
            "creds": (state.get("creds") or [])[-20:],
            "secrets": (state.get("secrets") or [])[-20:],
            "walks": (state.get("walks") or [])[-10:],
            "tech_stack": state.get("tech_stack") or [],
        },
        "schema": schema,
    }
    if chat:
        ctx["user_chat"] = chat
    return json.dumps(ctx, indent=2, default=str)


def extract_two_blocks(text):
    html = py = None
    for m in re.finditer(r"```([a-zA-Z]*)[ \t]*\r?\n(.*?)```", text, re.DOTALL):
        lang = (m.group(1) or "").lower()
        body = m.group(2).strip()
        if lang in ("html", "markup", "htm") and html is None and body:
            html = body
        elif lang in ("python", "py") and py is None and body:
            py = body
        elif lang == "" and html is None and body:
            html = body
    if py is not None and not py.strip():
        py = None
    if html is not None and not html.strip():
        html = None
    if py is None:
        blocks = list(re.finditer(r"```([a-zA-Z]*)[ \t]*\r?\n(.*?)```", text, re.DOTALL))
        for m in reversed(blocks):
            lang = (m.group(1) or "").lower()
            body = m.group(2).strip()
            if lang in ("html", "markup", "htm"):
                continue
            if body and ("FastAPI" in body or "uvicorn" in body or "def main" in body):
                py = body
                break
    return html, py


def _llm_client():
    return _agent_v8().current_client()


def _generate(t, mode, chat=""):
    client, model = _llm_client()
    ctx = _build_context(t, mode, chat)
    user = f"Mode: {mode}\n\nContext JSON:\n{ctx}"
    if mode == "chat":
        user += f"\n\nOperator request:\n{chat}\n\nEmit the FULL updated index.html + app.py."
    r = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": SYS_PROMPT},
                  {"role": "user", "content": user}],
        temperature=0.2,
        max_tokens=16000)
    text = r.choices[0].message.content or ""
    html, py = extract_two_blocks(text)
    if py is None:
        m = re.search(r"```(?:python|py)?\s*\n(.*?)```", text, re.DOTALL)
        py = m.group(1).strip() if m else text.strip()
    if html is None:
        html = ("<!doctype html><meta charset=\'utf-8\'><title>" + t +
                "</title><pre>no html block</pre>")
    if py is None:
        print(f"[ui-builder] no python block detected ({len(text)} chars)")
    return html, py


def _validate(app_path, html_path):
    import ast as _ast
    if not html_path.exists() or html_path.stat().st_size < 200:
        print("[ui-builder] html missing/too small")
        return False
    try:
        src = app_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[ui-builder] app.py unreadable: {e}")
        return False
    try:
        _ast.parse(src)
    except SyntaxError as e:
        print(f"[ui-builder] syntax error: {e}")
        return False
    for route in ["/api/state", "/api/schema", "/api/recorder",
                  "/api/shell", "/api/directive", "/api/logs"]:
        if route not in src:
            print(f"[ui-builder] missing route: {route}")
            return False
    if "FastAPI" not in src:
        print("[ui-builder] no FastAPI")
        return False
    if "UIA_TARGET" not in src:
        print("[ui-builder] no UIA_TARGET binding")
        return False
    return True


def build(t, update=False, chat=""):
    d = _uiapp_dir(t)
    app = d / "app.py"
    html = d / "index.html"
    mode = "chat" if chat else ("update" if update else "initial")
    print(f"[ui-builder] target={t}  mode={mode}")
    print(f"[ui-builder] uiapp={d}")
    print("[ui-builder] generating index.html + app.py ...")
    t0 = time.time()
    html_code, py_code = _generate(t, mode, chat)
    el = time.time() - t0
    print(f"[ui-builder] generated in {el:.1f}s (html={len(html_code)}B py={len(py_code)}B)")
    html.write_text(html_code, encoding="utf-8")
    app.write_text(py_code, encoding="utf-8")
    if not _validate(app, html):
        print("[ui-builder] validation failed - not starting")
        return {"ok": False, "reason": "validation_failed",
                "html_path": str(html), "app_path": str(app)}
    _kill_prev(t)
    port = _port_for(t)
    pid = _spawn(t, port)
    meta = _read_meta(t)
    meta.update({"target": t, "port": port, "pid": pid,
                 "uiapp_dir": str(d), "app_path": str(app), "html_path": str(html),
                 "started_at": time.time(), "last_build_mode": mode,
                 "last_build_ts": time.time(), "last_build_secs": round(el, 1)})
    _write_meta(t, meta)
    import urllib.request
    ok = False
    for _ in range(30):
        time.sleep(0.3)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=1) as r:
                if r.status == 200:
                    ok = True
                    break
        except Exception:
            pass
    url = f"http://127.0.0.1:{port}/"
    print(f"[ui-builder] {'ready' if ok else 'not responding yet'} at {url}")
    print(f"[ui-builder] pid={pid}  log={d/'app.log'}")
    if ok:
        _open_browser(url)
    return {"ok": ok, "port": port, "pid": pid, "url": url,
            "html_path": str(html), "app_path": str(app)}


def _open_browser(url):
    for c in (["wslview", url],
              ["cmd.exe", "/c", "start", url],
              ["powershell.exe", "-Command", f"Start-Process \'{url}\'"],
              ["xdg-open", url]):
        try:
            if subprocess.run(c, capture_output=True, timeout=4).returncode == 0:
                return
        except Exception:
            continue
    print(f"[ui-builder] open: {url}")


def stop(t):
    _kill_prev(t)
    meta = _read_meta(t)
    meta["pid"] = None
    meta["stopped_at"] = time.time()
    _write_meta(t, meta)
    return {"stopped": True, "target": t}


def status(t):
    meta = _read_meta(t)
    if not meta:
        return {"target": t, "built": False}
    pid = meta.get("pid")
    alive = False
    if pid:
        try:
            os.kill(int(pid), 0); alive = True
        except Exception:
            pass
    return {"target": t, "built": True, "port": meta.get("port"),
            "pid": pid, "alive": alive,
            "url": f"http://127.0.0.1:{meta.get('port')}/" if meta.get("port") else None,
            "uiapp_dir": meta.get("uiapp_dir"),
            "last_build_mode": meta.get("last_build_mode"),
            "last_build_ts": meta.get("last_build_ts")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--chat", default="")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--status", action="store_true")
    a = ap.parse_args()
    if a.status:
        print(json.dumps(status(a.target), indent=2)); return
    if a.stop:
        print(json.dumps(stop(a.target), indent=2)); return
    r = build(a.target, update=a.update, chat=a.chat)
    print(json.dumps(r, indent=2))
    sys.exit(0 if r.get("ok") else 1)


if __name__ == "__main__":
    main()
