#!/usr/bin/env python3
"""
somscan — main entry point for SOM-SCAN Terminal Agent.
Inspired by OpenAI Codex CLI and OpenCode.

Usage:
    somscan                     # Launch the interactive Terminal UI
    somscan "query or command"  # Run inline query or task
    somscan --scan <target>     # Launch assessment on target
    somscan --resume            # Resume last scan
"""
import sys
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Load .env without overriding shell environment
try:
    from dotenv import load_dotenv
    load_dotenv(HERE / ".env", override=False)
except Exception:
    pass

from core.version import get_full_version


def _gui_home() -> pathlib.Path:
    d = pathlib.Path.home() / ".somscan"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _gui_healthy(host: str, port: int, timeout: float = 0.6) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/api/v2/health", timeout=timeout) as r:
            return 200 <= getattr(r, "status", 0) < 500
    except Exception:
        return False


def _gui_pid() -> int | None:
    try:
        return int((_gui_home() / "gui.pid").read_text().strip())
    except Exception:
        return None


def run_gui(args: list[str]) -> int:
    """`somscan gui` — build if needed, start the web console detached, print the URL."""
    import os
    import shutil
    import signal
    import subprocess
    import time
    import webbrowser

    host = "127.0.0.1"
    port = int(os.environ.get("AG_GUI_PORT", "8788"))
    open_browser = True
    sub = args[0].lower() if args else ""
    flags = args[1:] if sub in ("start", "run", "serve", "stop", "kill", "status") else args
    it = iter(flags)
    for a in it:
        if a in ("--port", "-p"):
            port = int(next(it))
        elif a.startswith("--port="):
            port = int(a.split("=", 1)[1])
        elif a == "--host":
            host = next(it)
        elif a.startswith("--host="):
            host = a.split("=", 1)[1]
        elif a in ("--no-open", "-n"):
            open_browser = False

    if sub in ("stop", "kill"):
        pid = _gui_pid()
        if not pid:
            print("[gui] no pid file — nothing to stop")
            return 0
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.kill(pid, signal.SIGTERM)
            print(f"[gui] stopped pid {pid}")
        except Exception as e:
            print(f"[gui] could not stop pid {pid}: {e}")
        try:
            (_gui_home() / "gui.pid").unlink()
        except Exception:
            pass
        return 0

    if sub == "status":
        pid = _gui_pid()
        alive = _gui_healthy(host, port)
        print(f"[gui] {'running' if alive else 'not running'}"
              + (f" · pid {pid}" if pid else "")
              + f" · http://{host}:{port}/gui")
        return 0 if alive else 1

    bind = host
    browse_host = "127.0.0.1" if bind in ("0.0.0.0", "::", "") else bind
    if _gui_healthy(browse_host, port):
        print(f"[gui] already running · http://{browse_host}:{port}/gui")
        return 0

    webgui = HERE / "webgui"
    if not (webgui / "server.py").exists():
        print("[gui] webgui/server.py is missing from this checkout.")
        return 1
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        import multipart  # noqa: F401
    except Exception:
        print("[gui] web console packages are missing.")
        print("      Run: somscan setup")
        return 1
    dist = webgui / "dist" / "index.html"
    if not dist.exists():
        npm = shutil.which("npm")
        if not npm:
            print("[gui] frontend not built and npm is missing.")
            print("      Install Node 18+ then run: cd webgui && npm install && npm run build")
            return 1
        if not (webgui / "node_modules").exists():
            print("[gui] installing frontend dependencies (first run)…")
            r = subprocess.run([npm, "install"], cwd=str(webgui))
            if r.returncode != 0:
                print("[gui] npm install failed — check the output above")
                return 1
        print("[gui] building frontend (first run)…")
        r = subprocess.run([npm, "run", "build"], cwd=str(webgui))
        if r.returncode != 0 or not dist.exists():
            print("[gui] build failed — check the output above")
            return 1

    log_path = _gui_home() / "gui.log"
    log = open(log_path, "ab", buffering=0)
    cmd = [sys.executable, str(webgui / "server.py"), "--host", bind, "--port", str(port)]
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(HERE), stdin=subprocess.DEVNULL, stdout=log, stderr=log, **kwargs
        )
    except Exception as e:
        print(f"[gui] failed to start: {e}")
        return 1
    (_gui_home() / "gui.pid").write_text(str(proc.pid), encoding="utf-8")

    ok = False
    for _ in range(80):
        if _gui_healthy(browse_host, port):
            ok = True
            break
        if proc.poll() is not None:
            break
        time.sleep(0.25)

    url = f"http://{browse_host}:{port}/gui"
    if ok:
        print(f"[gui] SOM-SCAN web console: {url}")
        print(f"[gui] pid {proc.pid} · log {log_path}")
        if open_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        return 0
    print(f"[gui] server did not become ready — see {log_path}")
    try:
        tail = log_path.read_text(errors="replace").splitlines()[-12:]
        for ln in tail:
            print("      " + ln)
    except Exception:
        pass
    return 1


def run_headless(task_or_target: str, resume: bool = False):
    """Run SOM-SCAN in direct non-interactive CLI streaming mode (Codex CLI style)."""
    import threading
    from core.agent_router import AgentRouter
    from core.events import (
        AssistantChunkEvent, AssistantMessageEvent, CommandStartEvent,
        CommandFinishEvent, FindingEvent, PhaseTransitionEvent,
        SubagentStartEvent, SubagentFinishEvent, TaskCompleteEvent,
        TaskCancelledEvent, ErrorEvent, QuestionPromptEvent, QuestionAnswerEvent
    )

    done_event = threading.Event()

    def _cli_event_handler(ev):
        if isinstance(ev, AssistantChunkEvent):
            print(ev.chunk, end="", flush=True)
        elif isinstance(ev, AssistantMessageEvent):
            if getattr(ev, "text", ""):
                print(f"\n{ev.text}\n", flush=True)
        elif isinstance(ev, CommandStartEvent):
            print(f"\n[+] Running: $ {ev.command}", flush=True)
        elif isinstance(ev, CommandFinishEvent):
            status = "SUCCESS" if ev.returncode == 0 else f"FAILED ({ev.returncode})"
            print(f"[{status}] duration: {ev.duration_sec:.2f}s\n{ev.output}\n", flush=True)
        elif isinstance(ev, FindingEvent):
            print(f"\n[!] FINDING [{ev.severity.upper()}]: {ev.title}\n{ev.evidence}\n", flush=True)
        elif isinstance(ev, PhaseTransitionEvent):
            print(f"\n=== PHASE: {ev.phase_name.upper()} ===", flush=True)
            for d in getattr(ev, "whats_done", []):
                print(f"  ✓ {d}", flush=True)
            for n in getattr(ev, "whats_next", []):
                print(f"  ▶ {n}", flush=True)
            print("===================================\n", flush=True)
        elif isinstance(ev, SubagentStartEvent):
            print(f"\n[⚡] SUBAGENT STARTED: [{ev.subagent_type.upper()}] — {ev.task}", flush=True)
        elif isinstance(ev, SubagentFinishEvent):
            print(f"[✓] SUBAGENT FINISHED: [{ev.subagent_type.upper()}] — {ev.summary}\n", flush=True)
        elif isinstance(ev, QuestionPromptEvent):
            print(f"\n[🔐] OPERATOR PROMPT: {ev.prompt}", flush=True)
            ans = ""
            if sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                try:
                    if ev.is_secret:
                        import getpass
                        ans = getpass.getpass("Password: ")
                    else:
                        ans = input("> ")
                except Exception:
                    ans = ""
            router.answer_question(ev.question_id, ans)
        elif isinstance(ev, (TaskCompleteEvent, TaskCancelledEvent)):
            print(f"\n[DONE] {getattr(ev, 'status', 'Task Complete')}\n", flush=True)
            done_event.set()
        elif isinstance(ev, ErrorEvent):
            print(f"\n[ERROR] {ev.error}\n", file=sys.stderr, flush=True)

    router = AgentRouter(event_callback=_cli_event_handler)
    router._is_headless = True
    router._is_cli_interactive = True

    if resume:
        cmd = f"/resume {task_or_target}".strip()
    elif task_or_target.startswith("/"):
        cmd = task_or_target
    elif " " not in task_or_target and ("." in task_or_target or "://" in task_or_target):
        cmd = f"/scan {task_or_target}"
    else:
        cmd = task_or_target

    router.dispatch(cmd)

    if getattr(router, "_active_worker", None):
        router._active_worker.join()


def main():
    _reset = None
    try:
        args = sys.argv[1:]

        # Guided environment setup / repair (stdlib only; works before deps).
        if args and args[0].lower() in ("setup", "install", "--setup"):
            from setup_tui import run_setup
            raise SystemExit(run_setup(args[1:]))

        # Web console: somscan gui [start|stop|status] [--host H] [--port P] [--no-open]
        if args and args[0].lower() == "gui":
            raise SystemExit(run_gui(args[1:]))

        # Version flag
        if "-v" in args or "--version" in args:
            print(get_full_version())
            return

        # Pre-install tools flag
        if "--preinstall-tools" in args or "--preinstall" in args:
            flag = "--preinstall-tools" if "--preinstall-tools" in args else "--preinstall"
            idx = args.index(flag)
            cat = args[idx + 1] if idx + 1 < len(args) and not args[idx + 1].startswith("-") else "all"
            import installer
            print(f"[*] Pre-installing red team tools (category: {cat})...")
            if cat == "all":
                res = installer.preinstall_all_categories(on_status=print)
            else:
                res = installer.preinstall_category(cat, on_status=print)
            import json
            print(json.dumps(res, indent=2))
            return

        # Check tools flag
        if "--check-tools" in args:
            idx = args.index("--check-tools")
            target = args[idx + 1] if idx + 1 < len(args) and not args[idx + 1].startswith("-") else "https://target.com"
            import installer, json
            print(f"[*] Pre-flight checking dependencies for: {target}")
            res = installer.ensure_tools_for_task(target, auto_install=False, on_status=print)
            print(json.dumps(res, indent=2))
            return

        # Parse headless / non-interactive flags
        headless = False
        for hf in ("--headless", "--non-interactive", "-n", "--batch", "-q", "--quiet"):
            if hf in args:
                headless = True
                args.remove(hf)

        # The terminal UI is only imported when actually needed, so `gui`,
        # `--version`, and installer flags work without textual installed.
        from tui import run_tui, _reset_terminal_state
        _reset = _reset_terminal_state

        # Interactive TUI mode (default when typing `somscan` with no args)
        if not args:
            run_tui()
            return

        # Direct scan flag
        if "--scan" in args:
            idx = args.index("--scan")
            if idx + 1 < len(args):
                target = args[idx + 1]
                if headless:
                    run_headless(target)
                else:
                    run_tui(initial_input=f"/scan {target}")
                return

        # Resume flag
        if "--resume" in args:
            idx = args.index("--resume")
            target = args[idx + 1] if idx + 1 < len(args) else ""
            if headless:
                run_headless(target, resume=True)
            else:
                run_tui(initial_input=f"/resume {target}".strip())
            return

        # Help flag
        if "-h" in args or "--help" in args:
            print(f"""{get_full_version()} - Autonomous Red Team & Security Assessment Agent

Usage:
  somscan                         Launch interactive Terminal UI
  somscan --scan <target>         Launch assessment in interactive TUI
  somscan -n, --headless <target> Launch direct non-interactive scan (headless/CLI stream)
  somscan --scan <target> -n      Direct non-interactive scan on target
  somscan --resume [-n]           Resume previous assessment (interactive or -n)
  somscan gui [start|stop|status] Web console (background, prints URL)
  somscan -v, --version       Display current version
  somscan -h, --help          Show this help message

Inside SOM-SCAN TUI:
  /help       List available commands and navigation shortcuts
  /phase      Inspect active phase: what's done, what's next move
  /subagent   Dispatch specialist subagent (recon/exploit/malware/reversing/webaudit)
  /malware    Malware Lab: craft weaponized shellcode, loaders, stagers, obfuscate
  /payload    Generate weaponized evasive payload (xss/sqli/ssrf/rce/ssti/nosqli)
  /new        Start fresh assessment session, archive previous scan & clear chat
  /key        Set or update API key (/key sk-...)
  /env        View API keys and environment status
  /model      View or switch active AI model (deepseek-chat, gemini, etc.)
  /scan       Initiate security scan on target
  /attack     Launch exploit and foothold phase on scan findings
  /resume     Resume previous scan
  /tools      Check security tool catalog or status
  /install    Install security tool (/install <name>)
  /file       File manager: create, view, list, delete
  /cancel     Interrupt active task or command (or Ctrl+C)
  /clear      Clear conversation viewport
  /long       Expand full command output
  /short      Collapse long command outputs
  /copy       Export session history to clipboard & log
  /quit       Exit SOM-SCAN (or Ctrl+Q)
""")
            return

        # Direct task or query: headless or interactive TUI
        task = " ".join(args).strip()
        if headless:
            run_headless(task)
        else:
            run_tui(initial_input=task)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        import traceback
        print(f"\n[SOM-SCAN Error Boundary] Caught exception: {type(e).__name__}: {e}", file=sys.stderr)
        traceback.print_exc()
    finally:
        if _reset:
            _reset()


if __name__ == "__main__":
    main()
