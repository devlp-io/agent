"""
core.task_runner — process lifecycle, command execution, and robust cancellation.
Features:
1. CommandSupervisor: autonomous supervisor agent (Codex / Antigravity style)
   - Evaluates command intent, tool type, and environment.
   - Sets smart dynamic timeouts (fast probes, network tooling, heavy fuzzers/scanners).
   - Monitors live streaming output (heartbeat) and dynamically extends timeout budget
     so active tools are never prematurely terminated.
   - Autonomous stall/deadlock killer: cleanly terminates hung processes that produce
     0 bytes for their stall threshold (e.g. interactive prompts, frozen network sockets).
   - Windows Command Adaptation: pre-rewrites Unix-specific utilities (e.g. getent hosts -> nslookup,
     which -> where.exe, injects curl timeouts).
2. Clean process-group tree cancellation across Windows and POSIX.
3. Single active execution lock preventing race conditions.
"""
import os
import re
import sys
import time
import signal
import threading
import subprocess
from typing import Optional, Tuple, Callable, List, Dict, Any

# Platform capability detection
IS_WIN = sys.platform == "win32"


class CommandResult:
    def __init__(
        self,
        command: str,
        returncode: int,
        output: str,
        duration: float,
        cancelled: bool = False,
        stalled: bool = False,
        timed_out: bool = False,
        supervisor_notes: Optional[List[str]] = None,
    ):
        self.command = command
        self.returncode = returncode
        self.output = output
        self.duration = duration
        self.cancelled = cancelled
        self.stalled = stalled
        self.timed_out = timed_out
        self.supervisor_notes = supervisor_notes or []

    @property
    def is_success(self) -> bool:
        return self.returncode == 0 and not self.cancelled and not self.stalled and not self.timed_out


def get_real_python() -> str:
    """Return valid Python interpreter path, avoiding compiled exe when frozen."""
    if getattr(sys, "frozen", False):
        import shutil
        for candidate in (
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python312\python.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python311\python.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python310\python.exe"),
            r"C:\Program Files\Python312\python.exe",
            r"C:\Program Files\Python311\python.exe",
            r"C:\Program Files\Python310\python.exe",
        ):
            if os.path.exists(candidate):
                return candidate
        p = shutil.which("python") or shutil.which("python3")
        if p and "WindowsApps" not in p:
            return p
        return "python"
    return sys.executable


class CommandSupervisor:
    """
    Autonomous process supervisor agent (Codex / Antigravity style).
    Inspects command profile, sets dynamic timeouts, extends budgets on active streaming,
    and terminates deadlocked/stalled processes.
    """

    # Tool Profiles: (base_timeout, stall_threshold, extension_step, max_timeout)
    PROFILE_FAST_PROBE = (35.0, 15.0, 30.0, 180.0)
    PROFILE_NETWORK_TOOL = (120.0, 30.0, 60.0, 900.0)
    PROFILE_HEAVY_SCANNER = (600.0, 60.0, 120.0, 3600.0)
    PROFILE_DEFAULT = (180.0, 30.0, 60.0, 1200.0)

    @classmethod
    def analyze_and_adapt(cls, command: str) -> Tuple[str, Dict[str, Any]]:
        """
        Analyze command intent and adapt for host environment.
        Returns: (adapted_command, profile_dict)
        """
        adapted = command.strip()
        notes: List[str] = []

        # 0. Sanitize hallucinated model tokens and anti-hang cleanups
        # Strip trailing XML / DSML / tool parameter tags hallucinated by DeepSeek/OpenAI models
        adapted = re.sub(r"</?[a-zA-Z0-9_\-:\s|]+>\s*$", "", adapted).strip()
        adapted = re.sub(r"<\s*/\s*[^>]*parameter\s*>\s*$", "", adapted, flags=re.IGNORECASE).strip()
        adapted = re.sub(r"<\s*/\s*[^>]*DSML[^>]*>\s*$", "", adapted, flags=re.IGNORECASE).strip()
        adapted = re.sub(r"</[^>]*parameter.*$", "", adapted, flags=re.IGNORECASE).strip()
        adapted = re.sub(r"</?$", "", adapted).strip()

        # Strip trailing background '&' operator that breaks stdin/stdout pipes and hangs watchdog
        if adapted.endswith("&") and not adapted.endswith(r"\&") and not adapted.endswith("&&"):
            adapted = adapted[:-1].rstrip()
            notes.append("Stripped trailing background '&' to prevent subprocess pipe deadlock")

        # 1. Windows platform adaptations
        if IS_WIN:
            # Fix: getent hosts <domain> -> nslookup <domain>
            m_getent = re.match(r"^getent\s+hosts\s+(.+)$", adapted, re.IGNORECASE)
            if m_getent:
                target_host = m_getent.group(1).strip()
                adapted = f"nslookup {target_host}"
                notes.append(f"Adapted 'getent hosts' to 'nslookup {target_host}' for Windows host")

            # Fix: which <tool> -> where.exe <tool>
            m_which = re.match(r"^which\s+([a-zA-Z0-9_\-]+)$", adapted, re.IGNORECASE)
            if m_which:
                tool_name = m_which.group(1).strip()
                adapted = f"where {tool_name}"
                notes.append(f"Adapted 'which {tool_name}' to 'where {tool_name}' for Windows host")

            # Fix: dig [+short] <host> [<type>] -> nslookup [-type=<type>] <host>
            if "dig " in adapted or adapted.startswith("dig"):
                def _rewrite_dig(m):
                    host = m.group(1)
                    qtype = m.group(2) if m.lastindex and m.lastindex >= 2 else None
                    if qtype and qtype.upper() in ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "PTR", "ANY"):
                        return f"nslookup -type={qtype} {host}"
                    return f"nslookup {host}"

                adapted_dig = re.sub(
                    r"\bdig(?:\s+\+short)?\s+([a-zA-Z0-9_\-\.]+)(?:\s+([A-Za-z]+))?",
                    _rewrite_dig,
                    adapted
                )
                if adapted_dig != adapted:
                    adapted = adapted_dig
                    notes.append("Adapted 'dig' command(s) to 'nslookup' for Windows host")
            # Fix: python / python3 -> sys.executable (bypasses Windows Store 0.0.0.0 alias stub)
            # Only rewrite python/python3 when it is invoked as an executable at command position,
            # NOT when it appears inside quotes, regexes, arguments, or process names (e.g. ProcessName -match '...python...')
            real_py = get_real_python()
            def _replace_py_cmd(m):
                prefix = m.group(1) or ""
                return f'{prefix}"{real_py}"'

            adapted_py = re.sub(
                r"(^|[\;&|]\s*|(?:^|\s)(?:sudo|nohup|exec|env)\s+)python3?(?=\s+|$)",
                _replace_py_cmd,
                adapted
            )
            if adapted_py != adapted:
                adapted = adapted_py
                notes.append(f"Mapped python/python3 to runtime executable '{real_py}'")

            # PowerShell Deadlock & Junction Loop Safeguard:
            # Prevent infinite loops in recursive directory searches (e.g. C:\Users\<user>\Application Data loop)
            low_a = adapted.lower()
            if "get-childitem" in low_a or " gci " in low_a or low_a.startswith("gci "):
                if "-recurse" in low_a and "-attributes" not in low_a:
                    adapted = re.sub(r"(\b(?:Get-ChildItem|gci)\b)", r"\1 -Attributes !ReparsePoint", adapted, count=1, flags=re.IGNORECASE)
                    notes.append("Injected '-Attributes !ReparsePoint' to prevent NTFS junction loop hangs")

        # 2. Smart Anti-WAF Throttling & Tool Pacing defaults
        # ONLY adapt curl when it is an executable invocation at start of line or after command separator (; && || |)
        curl_pattern = r"(^|[\;&|]\s*|\n\s*)curl\b"
        if re.search(curl_pattern, adapted):
            low_cmd = adapted.lower()
            if "-a " not in low_cmd and "--user-agent" not in low_cmd:
                def _inject_curl_ua(m):
                    prefix = m.group(1) or ""
                    return f'{prefix}curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'
                adapted = re.sub(curl_pattern, _inject_curl_ua, adapted, count=1)
                notes.append("Injected browser User-Agent to avoid default curl WAF blocks")

            low_cmd = adapted.lower()
            if "-m " not in low_cmd and "--max-time" not in low_cmd:
                adapted = re.sub(curl_pattern, r"\g<1>curl -m 25", adapted, count=1)
                notes.append("Injected '-m 25' network timeout safety on curl")

        low_cmd = adapted.lower()
        # ffuf: throttle request burst to avoid instant 429 IP bans
        if low_cmd.startswith("ffuf") or " ffuf " in low_cmd:
            if "-rate" not in low_cmd and " -p " not in low_cmd:
                adapted += " -rate 20 -p 0.05"
                notes.append("Injected '-rate 20 -p 0.05' anti-WAF pacing on ffuf")

        # nuclei: limit concurrency and rate to prevent edge WAF tripping
        if low_cmd.startswith("nuclei") or " nuclei " in low_cmd:
            if "-rate-limit" not in low_cmd and "-rl" not in low_cmd:
                adapted += " -rate-limit 20 -c 5"
                notes.append("Injected '-rate-limit 20 -c 5' anti-WAF pacing on nuclei")

        # sqlmap: inject delay and random-agent to evade simple signature blocks
        if low_cmd.startswith("sqlmap") or " sqlmap " in low_cmd:
            if "--delay" not in low_cmd:
                adapted += " --delay 0.5"
                notes.append("Injected '--delay 0.5' to prevent target throttling on sqlmap")
            if "--random-agent" not in low_cmd:
                adapted += " --random-agent"
                notes.append("Injected '--random-agent' header evasion on sqlmap")

        # gobuster / dirsearch: add pacing if missing
        if (low_cmd.startswith("gobuster") or " gobuster " in low_cmd) and "--delay" not in low_cmd:
            adapted += " --delay 100ms"
            notes.append("Injected '--delay 100ms' pacing on gobuster")
        if (low_cmd.startswith("dirsearch") or " dirsearch " in low_cmd) and "-s " not in low_cmd and "--delay" not in low_cmd:
            adapted += " -s 0.1"
            notes.append("Injected '-s 0.1' pacing on dirsearch")

        # 3. Classify execution profile
        first_token = low_cmd.split()[0] if low_cmd.split() else ""
        bin_name = os.path.basename(first_token).replace(".exe", "").replace(".bat", "")

        fast_probes = {
            "ping", "whoami", "where", "dir", "ls", "type", "cat", "head",
            "echo", "id", "uname", "nslookup", "dig", "host", "date",
            "hostname", "wmic", "pwd", "git"
        }
        network_tools = {
            "subfinder", "httpx", "amass", "whatweb", "wafw00f", "pip", "npm",
            "git-dumper", "arjun", "waybackurls", "gau", "paramspider",
            "katana", "dnsx", "assetfinder", "curl", "python", "python3", "playwright"
        }
        heavy_scanners = {
            "nmap", "masscan", "ffuf", "gobuster", "feroxbuster", "dirsearch",
            "sqlmap", "wpscan", "nuclei", "hydra", "nikto", "commix",
            "hashcat", "john"
        }

        # Check for heavy or network tools ANYWHERE in compound commands before defaulting to fast probe
        if any(tool in low_cmd for tool in heavy_scanners):
            profile_name = "HEAVY_SCANNER"
            base, stall, ext, max_t = cls.PROFILE_HEAVY_SCANNER
        elif any(tool in low_cmd for tool in network_tools) or "install" in low_cmd:
            profile_name = "NETWORK_TOOL"
            base, stall, ext, max_t = cls.PROFILE_NETWORK_TOOL
        elif bin_name in fast_probes and not any(sep in low_cmd for sep in (";", "&&", "||", "|")):
            profile_name = "FAST_PROBE"
            base, stall, ext, max_t = cls.PROFILE_FAST_PROBE
        else:
            profile_name = "DEFAULT"
            base, stall, ext, max_t = cls.PROFILE_DEFAULT

        config = {
            "profile_name": profile_name,
            "base_timeout": base,
            "stall_threshold": stall,
            "extension_step": ext,
            "max_timeout": max_t,
            "notes": notes,
        }
        return adapted, config


class TaskRunner:
    """Manages command execution with streaming output, dynamic supervisor watchdog, and clean tree cancellation."""

    def __init__(self):
        self._active_proc: Optional[subprocess.Popen] = None
        self._cancelled = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._active_proc is not None and self._active_proc.poll() is None

    def cancel(self) -> bool:
        """Cancel the currently active process tree cleanly."""
        with self._lock:
            self._cancelled = True
            proc = self._active_proc
            if proc is None or proc.poll() is not None:
                return False

        # Terminate child process tree
        self._kill_tree(proc)
        return True

    def _kill_tree(self, proc: subprocess.Popen):
        if proc is None:
            return

        if IS_WIN:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True,
                    timeout=5
                )
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        else:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    time.sleep(0.3)
                    if proc.poll() is None:
                        os.killpg(pgid, signal.SIGKILL)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            else:
                try:
                    proc.kill()
                except Exception:
                    pass

    def run_command(
        self,
        command: str,
        timeout: Optional[float] = None,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        on_output_chunk: Optional[Callable[[str], None]] = None,
        on_supervisor_event: Optional[Callable[[str], None]] = None,
    ) -> CommandResult:
        """
        Run a shell command under the CommandSupervisor.
        Dynamically adapts commands, sets smart timeouts, auto-extends on active streaming,
        and kills deadlocks.
        """
        with self._lock:
            self._cancelled = False

        # 1. Analyze and adapt command
        adapted_cmd, sup_cfg = CommandSupervisor.analyze_and_adapt(command)
        supervisor_notes = list(sup_cfg.get("notes", []))

        current_timeout = float(timeout) if timeout is not None else sup_cfg["base_timeout"]
        stall_threshold = sup_cfg["stall_threshold"]
        extension_step = sup_cfg["extension_step"]
        max_timeout = sup_cfg["max_timeout"]

        if supervisor_notes and on_supervisor_event:
            for n in supervisor_notes:
                try:
                    on_supervisor_event(f"ℹ️ {n}")
                except Exception:
                    pass

        run_env = dict(os.environ)
        if env:
            run_env.update(env)

        # Prepend Python executable dir, Scripts dir, and Git bin/usr-bin to PATH
        real_py = get_real_python()
        py_dir = os.path.dirname(real_py)
        py_scripts = os.path.join(py_dir, "Scripts")
        curr_path = run_env.get("PATH", "")
        extra_paths = [py_dir, py_scripts]
        if IS_WIN:
            for extra in (
                r"C:\Program Files\Git\bin",
                r"C:\Program Files\Git\usr\bin",
                r"C:\Program Files\Git\cmd",
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python312\Scripts"),
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python312"),
            ):
                if os.path.exists(extra) and extra not in extra_paths:
                    extra_paths.append(extra)
        run_env["PATH"] = f"{os.pathsep.join(extra_paths)}{os.pathsep}{curr_path}"

        popen_kwargs = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "bufsize": 1,
            "env": run_env,
            "cwd": cwd,
        }

        # Platform-aware shell selection
        spawn_cmd = adapted_cmd
        if IS_WIN:
            if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

            low_cmd = adapted_cmd.strip().lower()
            is_ps = bool(re.match(r"^(?:powershell|pwsh)\b", low_cmd)) or ".ps1" in low_cmd
            is_win_native = bool(re.match(r"^(?:cmd|start|del|copy|move|type|cls|assoc|ftype|reg|taskkill|tasklist|netstat|ipconfig|sc|where)\b", low_cmd))

            posix_needles = (
                "for ", "which ", "command -v", "do ", "done", "export ",
                "head ", "tail ", "grep ", "awk ", "sed ", "chmod ", "curl ",
                "python3 ", "dig ", "cat ", "ls ", "cut ", "tr ", "wc "
            )
            # Never route PowerShell or native Windows tools through git_bash
            has_posix = False
            if not is_ps and not is_win_native:
                has_posix = any(needle in adapted_cmd for needle in posix_needles) or (
                    ("'" in adapted_cmd) or
                    (";" in adapted_cmd or "&&" in adapted_cmd or "||" in adapted_cmd) and not adapted_cmd.startswith("$")
                )

            git_bash = None
            if has_posix:
                for candidate in (
                    r"C:\Program Files\Git\bin\bash.exe",
                    r"C:\Program Files\Git\usr\bin\bash.exe",
                    r"C:\Program Files (x86)\Git\bin\bash.exe",
                ):
                    if os.path.exists(candidate):
                        git_bash = candidate
                        break

            if has_posix and git_bash:
                # Rewrite cmd.exe 'cd /d <path>' to bash 'cd <path>' with forward slashes
                bash_cmd = re.sub(
                    r"\bcd\s+/d\s+([\"']?[A-Za-z]:[^\s\"'&|]+[\"']?)",
                    lambda m: f"cd {m.group(1).replace(chr(92), '/')}",
                    adapted_cmd,
                    flags=re.I
                )
                spawn_cmd = [git_bash, "-c", bash_cmd]
                popen_kwargs["shell"] = False
            else:
                popen_kwargs["shell"] = True
        else:
            if hasattr(os, "setsid"):
                popen_kwargs["preexec_fn"] = os.setsid
            shell_exec = os.environ.get("SHELL") or "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
            if os.path.exists("/data/data/com.termux/files/usr/bin/sh"):
                shell_exec = "/data/data/com.termux/files/usr/bin/sh"
            popen_kwargs["executable"] = shell_exec
            popen_kwargs["shell"] = True

        t0 = time.time()
        output_lines: List[str] = []

        try:
            proc = subprocess.Popen(spawn_cmd, **popen_kwargs)
            with self._lock:
                self._active_proc = proc
        except Exception as e:
            return CommandResult(
                command=adapted_cmd,
                returncode=-1,
                output=f"Failed to start command: {e}",
                duration=time.time() - t0,
                cancelled=False,
                stalled=False,
                timed_out=False,
                supervisor_notes=supervisor_notes,
            )

        # Supervisor tracking state
        last_activity_time = time.time()
        lines_streamed = 0
        extensions_granted = 0
        timed_out = False
        stalled = False

        def _watchdog():
            nonlocal timed_out, stalled, current_timeout
            while True:
                time.sleep(0.2)
                with self._lock:
                    if self._cancelled:
                        return
                    if proc.poll() is not None:
                        # Process itself has terminated. Give at most 1.0s grace period for stdout buffer
                        time.sleep(1.0)
                        try:
                            if proc.stdout and not proc.stdout.closed:
                                proc.stdout.close()
                        except Exception:
                            pass
                        self._kill_tree(proc)
                        return

                now = time.time()
                elapsed = now - t0
                silence = now - last_activity_time

                # 1. Stall / Deadlock Detection
                if silence >= stall_threshold:
                    stalled = True
                    supervisor_notes.append(
                        f"Command supervisor: process stalled with 0 output for {int(silence)}s. Cleanly terminated."
                    )
                    try:
                        if proc.stdout and not proc.stdout.closed:
                            proc.stdout.close()
                    except Exception:
                        pass
                    self._kill_tree(proc)
                    return

                # 2. Hard Max Timeout
                if elapsed >= current_timeout:
                    timed_out = True
                    supervisor_notes.append(
                        f"Command supervisor: process reached timeout budget ({int(current_timeout)}s). Cleanly terminated."
                    )
                    try:
                        if proc.stdout and not proc.stdout.closed:
                            proc.stdout.close()
                    except Exception:
                        pass
                    self._kill_tree(proc)
                    return

        wd = threading.Thread(target=_watchdog, daemon=True)
        wd.start()

        try:
            for line in iter(proc.stdout.readline, ""):
                if not line:
                    break
                now = time.time()
                last_activity_time = now
                lines_streamed += 1
                output_lines.append(line)

                # Supervisor dynamic timeout extension on active streaming
                remaining = current_timeout - (now - t0)
                if remaining < 20 and (current_timeout + extension_step) <= max_timeout:
                    current_timeout += extension_step
                    extensions_granted += 1
                    msg = f"Active output streaming ({lines_streamed} lines). Extended timeout to {int(current_timeout)}s."
                    supervisor_notes.append(f"Supervisor: {msg}")
                    if on_supervisor_event:
                        try:
                            on_supervisor_event(f"⏱️ {msg}")
                        except Exception:
                            pass

                if on_output_chunk:
                    try:
                        on_output_chunk(line)
                    except Exception:
                        pass

                if self._cancelled or timed_out or stalled:
                    break
        except Exception:
            pass
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass
            self._kill_tree(proc)
            try:
                proc.wait(timeout=2)
            except Exception:
                pass
            with self._lock:
                self._active_proc = None

        duration = time.time() - t0
        output_str = "".join(output_lines).strip()

        if self._cancelled:
            output_str += "\n[Command interrupted / cancelled by user]"
            return CommandResult(
                adapted_cmd, -9, output_str, duration,
                cancelled=True, stalled=False, timed_out=False,
                supervisor_notes=supervisor_notes
            )

        if stalled:
            output_str += f"\n[Command supervisor terminated process: 0 output received for {int(stall_threshold)}s (deadlock safeguard)]"
            return CommandResult(
                adapted_cmd, -1, output_str, duration,
                cancelled=False, stalled=True, timed_out=False,
                supervisor_notes=supervisor_notes
            )

        if timed_out:
            output_str += f"\n[Command supervisor terminated process: exceeded timeout of {int(current_timeout)}s]"
            return CommandResult(
                adapted_cmd, -1, output_str, duration,
                cancelled=False, stalled=False, timed_out=True,
                supervisor_notes=supervisor_notes
            )

        if extensions_granted > 0:
            supervisor_notes.append(f"Extended timeout {extensions_granted} time(s) during active stream")

        retcode = proc.returncode if proc.returncode is not None else 0
        return CommandResult(
            adapted_cmd, retcode, output_str, duration,
            cancelled=False, stalled=False, timed_out=False,
            supervisor_notes=supervisor_notes
        )
