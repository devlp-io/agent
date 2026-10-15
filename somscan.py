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


def main():
    try:
        args = sys.argv[1:]

        # Version flag
        if "-v" in args or "--version" in args:
            print(get_full_version())
            return

        # Interactive TUI mode (default when typing `somscan`)
        if not args:
            run_tui()
            return

        # Direct scan flag
        if "--scan" in args:
            idx = args.index("--scan")
            if idx + 1 < len(args):
                target = args[idx + 1]
                run_tui(initial_input=f"/scan {target}")
                return

        # Resume flag
        if "--resume" in args:
            run_tui(initial_input="/resume")
            return

        # Help flag
        if "-h" in args or "--help" in args:
            print(f"""{get_full_version()} - Autonomous Red Team & Security Assessment Agent

Usage:
  somscan                     Launch interactive Terminal UI
  somscan --scan <target>     Launch assessment on specified target
  somscan --resume            Resume previous assessment
  somscan -v, --version       Display current version
  somscan -h, --help          Show this help message

Inside SOM-SCAN TUI:
  /help       List available commands and navigation shortcuts
  /new        Start fresh assessment session, archive previous scan & clear chat
  /key        Set or update API key (/key sk-...)
  /env        View API keys and environment status
  /model      View or switch active AI model (deepseek-chat, gemini, etc.)
  /scan       Initiate security scan on target
  /resume     Resume previous scan
  /tools      Check security tool catalog or status
  /install    Install security tool (/install <name>)
  /file       File manager: create, view, list, delete
  /cancel     Interrupt active task or command (or Ctrl+C)
  /clear      Clear conversation viewport
  /long       Expand full command output
  /short      Collapse long command outputs
  /copy       Export session history to file
  /quit       Exit SOM-SCAN (or Ctrl+Q)
""")
            return

        # Direct task or query: launch TUI and execute
        task = " ".join(args).strip()
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
