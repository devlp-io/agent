#!/usr/bin/env python3
"""
SOM-SCAN guided setup / environment repair.

Runs with the system Python before any third-party dependency exists, so it
uses only the standard library. It creates the project virtualenv, installs
the core CLI packages, then the optional web console packages, verifies the
imports, and optionally installs the core toolkit profile.

    ./somscan setup             interactive setup
    ./somscan setup --auto      non-interactive (first-run bootstrap)
    ./somscan setup --repair    reinstall missing/broken packages
    python3 setup_tui.py --auto --no-web --no-toolkits
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import platform
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
VENV = pathlib.Path(os.environ.get("SOMSCAN_VENV", str(ROOT / ".venv")))
CORE_IMPORTS = ["rich", "textual", "openai", "httpx", "dotenv", "requests"]
WEB_IMPORTS = ["pydantic", "fastapi", "uvicorn", "multipart"]

CORE_PKGS = [
    "textual>=0.70.0", "rich>=13.7.0", "httpx>=0.25.0", "openai>=1.12.0",
    "python-dotenv>=1.0.0", "requests>=2.28.0",
]
WEB_PKGS = ["pydantic>=2.0.0", "fastapi>=0.100.0", "uvicorn>=0.22.0", "python-multipart>=0.0.9"]

TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def panel_line(text: str, width: int = 58) -> None:
    visible = ANSI_RE.sub("", text)
    pad = max(0, width - len(visible) - 2)
    print(cyan("│") + "  " + text + " " * pad + cyan("│"))


def c(code: str, text: str) -> str:
    if not TTY:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(t: str) -> str:
    return c("1", t)


def dim(t: str) -> str:
    return c("2", t)


def green(t: str) -> str:
    return c("32", t)


def red(t: str) -> str:
    return c("31", t)


def yellow(t: str) -> str:
    return c("33", t)


def cyan(t: str) -> str:
    return c("36", t)


def termux() -> bool:
    return bool(os.environ.get("TERMUX_VERSION")) or "com.termux" in os.environ.get("PREFIX", "")


def venv_python(venv: pathlib.Path) -> pathlib.Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def system_python() -> str:
    if sys.version_info >= (3, 10):
        return sys.executable
    for name in ("python3", "python"):
        p = shutil.which(name)
        if p:
            try:
                out = subprocess.run([p, "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"],
                                     capture_output=True, text=True, timeout=10)
                major, minor = (int(x) for x in out.stdout.split())
                if (major, minor) >= (3, 10):
                    return p
            except Exception:
                pass
    return ""


def line(kind: str, text: str) -> None:
    marks = {"ok": green("✓"), "warn": yellow("!"), "err": red("✗"), "run": cyan("›"), "skip": dim("·")}
    print(f"  {marks.get(kind, '·')} {text}")


def header() -> None:
    title = "SOM-SCAN  ·  SETUP"
    if TTY:
        print()
        print(cyan("╭" + "─" * 58 + "╮"))
        panel_line(bold(title))
        print(cyan("├" + "─" * 58 + "┤"))
        panel_line(f"{'platform':<10} {platform.system().lower()}"
                   + (" / termux" if termux() else ""))
        panel_line(f"{'python':<10} {sys.version.split()[0]}  ({sys.executable})")
        panel_line(f"{'env':<10} {VENV}")
        print(cyan("╰" + "─" * 58 + "╯"))
    else:
        print(f"\n{title}\nplatform: {platform.system().lower()}\n"
              f"python: {sys.version.split()[0]}\nenv: {VENV}\n")


def run_cmd(cmd: list[str], label: str, timeout: int | None = None) -> tuple[bool, str]:
    """Run a command with a spinner, return (ok, captured output)."""
    if not TTY:
        print(f"  › {label}…")
        try:
            p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
            return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return False, str(e)

    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, errors="replace")
    except Exception as e:
        return False, str(e)
    out: list[str] = []
    i = 0
    while p.poll() is None:
        if p.stdout is not None:
            chunk = p.stdout.readline()
            if chunk:
                out.append(chunk)
        sys.stdout.write(f"\r  {cyan(frames[i % len(frames)])} {label}… ")
        sys.stdout.flush()
        i += 1
        time.sleep(0.08)
    rest = p.stdout.read() if p.stdout is not None else ""
    if rest:
        out.append(rest)
    sys.stdout.write("\r" + " " * (len(label) + 10) + "\r")
    return p.returncode == 0, "".join(out)


def imports_ok(py: pathlib.Path, modules: list[str]) -> tuple[bool, str]:
    if not py.exists():
        return False, "interpreter missing"
    code = "import " + ", ".join(modules)
    try:
        p = subprocess.run([str(py), "-c", code], capture_output=True, text=True, timeout=30)
        return p.returncode == 0, (p.stderr or "").strip().splitlines()[-1] if p.stderr else ""
    except Exception as e:
        return False, str(e)


def ensure_venv() -> pathlib.Path:
    py = venv_python(VENV)
    if py.exists():
        line("ok", f"environment found  {dim(str(VENV))}")
        return py
    sys_py = system_python()
    if not sys_py:
        line("err", "Python 3.10+ was not found.")
        if termux():
            print("      pkg install -y python")
        elif platform.system() == "Windows":
            print("      Install Python 3.10+ from https://python.org")
        else:
            print("      sudo apt install -y python3 python3-venv   # Debian/Ubuntu")
        raise SystemExit(1)
    line("run", f"creating environment  {dim(str(VENV))}")
    ok, out = run_cmd([sys_py, "-m", "venv", str(VENV)], "creating venv")
    py = venv_python(VENV)
    if not ok or not py.exists():
        print(out[-1500:])
        line("err", "could not create the virtualenv.")
        if termux():
            print("      pkg install -y python")
        elif platform.system() == "Linux":
            print("      sudo apt install -y python3-venv")
        raise SystemExit(1)
    line("ok", "environment created")
    return py


def pip_install(py: pathlib.Path, packages: list[str], label: str) -> tuple[bool, str]:
    return run_cmd([str(py), "-m", "pip", "install", "--disable-pip-version-check",
                    "--prefer-binary", "--upgrade", *packages], label)


def install_group(py: pathlib.Path, modules: list[str], packages: list[str], label: str) -> bool:
    ok, _ = imports_ok(py, modules)
    if ok:
        line("ok", f"{label} already installed")
        return True
    ok, out = pip_install(py, packages, f"installing {label}")
    if ok:
        ok, _ = imports_ok(py, modules)
    if not ok:
        # One clean retry; interrupted/partial installs are the common failure.
        ok, out = pip_install(py, packages,
                              f"repairing {label}")
        if ok:
            ok, _ = imports_ok(py, modules)
    if not ok and termux() and any(k in out.lower() for k in
                                    ("rust", "cargo", "pydantic-core", "cryptography", "maturin")):
        line("warn", "Rust build required on Termux — installing rust…")
        run_cmd(["pkg", "install", "-y", "rust"], "installing rust", timeout=None)
        ok, out = pip_install(py, packages, f"repairing {label} with rust")
        if ok:
            ok, _ = imports_ok(py, modules)
    if ok:
        line("ok", f"{label} ready")
        return True
    line("err", f"{label} install failed")
    tail = "\n".join([ln for ln in out.strip().splitlines() if ln.strip()][-12:])
    if tail:
        print(dim("      " + tail.replace("\n", "\n      ")))
    if termux():
        print(yellow("      Termux hint: pkg install -y python clang rust openssl libffi rust"))
    return False


def install_toolkits(py: pathlib.Path, auto: bool, skip: bool) -> str:
    if skip:
        line("skip", "toolkits skipped")
        return "skipped"
    if not auto:
        try:
            answer = input("  Install the core toolkit profile now? [Y/n] ").strip().lower()
        except EOFError:
            answer = "n"
        if answer in ("n", "no"):
            line("skip", "toolkits skipped")
            return "skipped"
    if not (ROOT / "installer.py").exists():
        line("warn", "installer.py not found; toolkit install skipped")
        return "missing"
    ok, out = run_cmd([str(py), str(ROOT / "installer.py"), "preinstall", "core"],
                      "installing core toolkits", timeout=None)
    if ok:
        line("ok", "core toolkits ready")
        return "ok"
    line("warn", "toolkit install did not finish (CLI still works)")
    tail = "\n".join([ln for ln in out.strip().splitlines() if ln.strip()][-6:])
    if tail:
        print(dim("      " + tail.replace("\n", "\n      ")))
    return "partial"


def run_setup(argv: list[str]) -> int:
    auto = "--auto" in argv or "--yes" in argv or "-y" in argv
    no_web = "--no-web" in argv
    no_toolkits = "--no-toolkits" in argv or os.environ.get("SOMSCAN_SKIP_TOOLKITS") == "1"
    header()

    py = ensure_venv()
    core_ok = install_group(py, CORE_IMPORTS, CORE_PKGS, "core CLI packages")
    if not core_ok:
        line("err", "core environment is not usable.")
        print("\n  Run this again after fixing the error above:")
        print("    ./somscan setup\n")
        return 1

    web_ok = False
    if no_web:
        line("skip", "web console packages skipped")
    else:
        web_ok = install_group(py, WEB_IMPORTS, WEB_PKGS, "web console packages")
        if not web_ok:
            line("warn", "web console unavailable; CLI is ready")

    auto_skip_toolkits = auto and os.environ.get("SOMSCAN_INSTALL_TOOLKITS") != "1"
    toolkit_state = install_toolkits(py, auto, no_toolkits or auto_skip_toolkits)

    try:
        (ROOT / ".bootstrap.json").write_text(json.dumps({
            "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python": sys.version.split()[0],
            "venv": str(VENV),
            "core": True,
            "web": bool(web_ok),
            "toolkits": toolkit_state,
        }, indent=2), encoding="utf-8")
    except Exception:
        pass

    if TTY:
        print(cyan("╭" + "─" * 58 + "╮"))
        panel_line(f"{green('READY')}  run {bold('somscan')} from any directory")
        panel_line(f"web console: {bold('somscan gui')}")
        print(cyan("╰" + "─" * 58 + "╯"))
    else:
        print("\nREADY — run: somscan\n")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(__doc__)
        return 0
    try:
        return run_setup(args)
    except KeyboardInterrupt:
        print("\n\nSetup cancelled. Re-run: ./somscan setup")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
