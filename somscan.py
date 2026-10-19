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

from tui import run_tui, _reset_terminal_state
from core.version import get_full_version


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
    try:
        args = sys.argv[1:]

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
        _reset_terminal_state()


if __name__ == "__main__":
    main()
