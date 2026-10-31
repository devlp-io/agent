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
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
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


def c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if TTY else text


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


def cols() -> int:
    try:
        return max(40, shutil.get_terminal_size((80, 24)).columns)
    except Exception:
        return 80


def truncate(text: str, limit: int | None = None) -> str:
    limit = limit or max(20, cols() - 8)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def termux() -> bool:
    return bool(os.environ.get("TERMUX_VERSION")) or "com.termux" in os.environ.get("PREFIX", "")


def venv_python(venv: pathlib.Path) -> pathlib.Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


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


def header() -> None:
    print()
    print(bold("SOM-SCAN  ·  SETUP"))
    print(f"  {'platform':<9} {platform.system().lower()}" + (" / termux" if termux() else ""))
    print(f"  {'python':<9} {sys.version.split()[0]}")
    print(f"  {'env':<9} {VENV}")
    print()


def line(kind: str, text: str) -> None:
    marks = {"ok": green("✓"), "warn": yellow("!"), "err": red("✗"), "run": cyan("›"), "skip": dim("·")}
    print(f"  {marks.get(kind, '·')} {truncate(text, cols() - 4)}")


def _show_pip_line(text: str) -> bool:
    low = text.lower()
    if not text or text.startswith(("Requirement already satisfied", "Using cached",
                                    "Looking in indexes", "Obtaining ", "Preparing metadata")):
        return False
    if ("downloading" in low or "collecting" in low or "building" in low
            or "installing collected" in low or "successfully installed" in low
            or "error" in low or "failed" in low or "requires" in low):
        return True
    return False


def run_command(cmd: list[str], label: str, timeout: int | None = None) -> tuple[bool, str]:
    """Run a command as a clean line-based log with periodic heartbeats.

    No carriage-return spinner: on narrow Termux terminals that wraps and
    leaves a growing stack of lines. Progress is printed one line at a time.
    """
    print(f"  {cyan('›')} {truncate(label, cols() - 4)}")
    if not TTY:
        try:
            p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
            return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
        except Exception as e:
            return False, str(e)

    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, errors="replace", bufsize=1)
    except Exception as e:
        return False, str(e)

    all_lines: list[str] = []
    q: "queue.Queue[str | None]" = queue.Queue()
    eof = [False]

    def reader():
        try:
            for ln in iter(p.stdout.readline, ""):
                if ln:
                    q.put(ln)
        finally:
            eof[0] = True
            q.put(None)

    threading.Thread(target=reader, daemon=True).start()
    start = time.time()
    last_beat = start
    last_shown = ""
    seen: set[str] = set()
    warned_build = False

    while True:
        while True:
            try:
                item = q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                eof[0] = True
                continue
            all_lines.append(item)
            clean = ANSI_RE.sub("", item.replace("\r", " ")).strip()
            if not _show_pip_line(clean):
                continue
            if clean in seen:
                continue
            seen.add(clean)
            elapsed = int(time.time() - start)
            if "pydantic-core" in clean or "building wheel" in clean.lower():
                if not warned_build and termux():
                    print(dim("      note: pydantic-core compiles from source on Termux; "
                              "this step can take several minutes."))
                    warned_build = True
            print(f"      [{elapsed:>4}s] {truncate(clean, cols() - 14)}")
            last_shown = clean
            last_beat = time.time()

        if p.poll() is not None and eof[0] and q.empty():
            break
        if time.time() - last_beat >= 20:
            elapsed = int(time.time() - start)
            hint = ""
            if "building" in last_shown.lower() or "pydantic-core" in last_shown.lower():
                hint = "  (compiling pydantic-core — this can take several minutes)"
            print(dim(f"      [{elapsed:>4}s] … still working{hint}"))
            last_beat = time.time()
        if timeout and (time.time() - start) > timeout:
            try:
                p.terminate()
            except Exception:
                pass
            break
        time.sleep(0.2)

    rc = p.wait()
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            break
        if item:
            all_lines.append(item)
    elapsed = int(time.time() - start)
    if rc == 0:
        print(dim(f"      ✓ done in {elapsed}s"))
    else:
        print(red(f"      ✗ failed after {elapsed}s"))
    return rc == 0, "".join(all_lines)


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
        pip_ok, _ = imports_ok(py, ["pip"])
        if pip_ok:
            line("ok", f"[1/4] Environment — found  {dim(str(VENV))}")
            return py
        line("warn", "[1/4] Environment — venv is broken, rebuilding")
        shutil.rmtree(VENV, ignore_errors=True)
    sys_py = system_python()
    if not sys_py:
        line("err", "[1/4] Environment — Python 3.10+ was not found.")
        if termux():
            print("      pkg install -y python")
        elif platform.system() == "Windows":
            print("      Install Python 3.10+ from https://python.org")
        else:
            print("      sudo apt install -y python3 python3-venv   # Debian/Ubuntu")
        raise SystemExit(1)
    ok, out = run_command([sys_py, "-m", "venv", str(VENV)], "creating environment")
    py = venv_python(VENV)
    if not ok or not py.exists():
        print(out[-1200:])
        line("err", "[1/4] Environment — could not create the virtualenv.")
        if termux():
            print("      pkg install -y python")
        elif platform.system() == "Linux":
            print("      sudo apt install -y python3-venv")
        raise SystemExit(1)
    line("ok", "[1/4] Environment — created")
    return py


def pip_install(py: pathlib.Path, packages: list[str], label: str) -> tuple[bool, str]:
    return run_command([str(py), "-m", "pip", "install", "--disable-pip-version-check",
                        "--prefer-binary", "--upgrade", *packages], label)


def install_group(py: pathlib.Path, modules: list[str], packages: list[str], label: str) -> bool:
    ok, _ = imports_ok(py, modules)
    if ok:
        line("ok", f"{label} — already installed")
        return True
    ok, out = pip_install(py, packages, f"{label} — installing")
    if ok:
        ok, _ = imports_ok(py, modules)
    if not ok:
        ok, out = pip_install(py, packages, f"{label} — repairing")
        if ok:
            ok, _ = imports_ok(py, modules)
    if not ok and termux() and any(k in out.lower() for k in
                                   ("rust", "cargo", "pydantic-core", "cryptography", "maturin")):
        line("warn", "Rust build required — installing rust, then retrying")
        run_command(["pkg", "install", "-y", "rust"], "installing rust")
        ok, out = pip_install(py, packages, f"{label} — retrying with rust")
        if ok:
            ok, _ = imports_ok(py, modules)
    if ok:
        line("ok", f"{label} — ready")
        return True
    line("err", f"{label} — failed")
    tail = "\n".join([ln for ln in out.strip().splitlines() if ln.strip()][-10:])
    if tail:
        for ln in tail.splitlines():
            print(dim("      " + truncate(ln, cols() - 8)))
    if termux():
        print(yellow("      Termux hint: pkg install -y python clang rust openssl libffi"))
    return False


def install_toolkits(py: pathlib.Path, auto: bool, skip: bool) -> str:
    if skip:
        line("skip", "[4/4] Toolkits — skipped")
        return "skipped"
    if not auto:
        try:
            answer = input("  Install the core toolkit profile now? [Y/n] ").strip().lower()
        except EOFError:
            answer = "n"
        if answer in ("n", "no"):
            line("skip", "[4/4] Toolkits — skipped")
            return "skipped"
    if not (ROOT / "installer.py").exists():
        line("warn", "[4/4] Toolkits — installer.py not found, skipped")
        return "missing"
    ok, out = run_command([str(py), str(ROOT / "installer.py"), "preinstall", "core"],
                          "[4/4] Toolkits — installing")
    if ok:
        line("ok", "[4/4] Toolkits — ready")
        return "ok"
    line("warn", "[4/4] Toolkits — did not finish (CLI still works)")
    tail = "\n".join([ln for ln in out.strip().splitlines() if ln.strip()][-6:])
    if tail:
        for ln in tail.splitlines():
            print(dim("      " + truncate(ln, cols() - 8)))
    return "partial"


def run_setup(argv: list[str]) -> int:
    auto = "--auto" in argv or "--yes" in argv or "-y" in argv
    no_web = "--no-web" in argv
    no_toolkits = "--no-toolkits" in argv or os.environ.get("SOMSCAN_SKIP_TOOLKITS") == "1"
    header()

    py = ensure_venv()
    core_ok = install_group(py, CORE_IMPORTS, CORE_PKGS, "[2/4] Core CLI packages")
    if not core_ok:
        line("err", "core environment is not usable.")
        print("\n  Fix the error above, then run: ./somscan setup\n")
        return 1

    web_ok = False
    if no_web:
        line("skip", "[3/4] Web console — skipped")
    else:
        web_ok = install_group(py, WEB_IMPORTS, WEB_PKGS, "[3/4] Web console packages")
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

    print()
    print(green("Setup complete.") + f"  Run {bold('somscan')} from any directory.")
    if web_ok:
        print(f"  Web console: {bold('somscan gui')}")
    print()
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
