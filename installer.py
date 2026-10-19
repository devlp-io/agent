"""
installer — smart multi-method tool installer.

Handles:
  - curated entries from tools_db
  - github:owner/repo
  - pip / pipx / npm / gem / cargo / go
  - pkg (termux) / apt (ubuntu/debian) / brew (macos)
  - direct binary downloads (best-effort)
  - github code search when a name is unknown
  - platform detection

Records installs to ~/agent/installs.json.
"""
import os
import re
import sys
import json
import time
import shlex
import shutil
import pathlib
import subprocess

# load .env so AG_SUDO_PASS / AG_PROXY_ENABLED are visible
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(pathlib.Path(__file__).resolve().parent / ".env",
                 override=False)
except Exception:
    pass

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:
    from tools_db import TOOLS
except Exception:
    TOOLS = {}

INSTALL_LOG = HERE / "installs.json"
VERIFIED_REGISTRY = HERE / "tools_verified.json"


def load_verified():
    try:
        if VERIFIED_REGISTRY.exists():
            return json.loads(VERIFIED_REGISTRY.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def mark_verified(name: str, ok: bool = True, details: str = ""):
    data = load_verified()
    data[name.lower()] = {
        "verified": bool(ok),
        "ts": time.time(),
        "platform": platform(),
        "details": details[:300]
    }
    try:
        VERIFIED_REGISTRY.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def is_verified(name: str) -> bool:
    name_l = name.lower().strip()
    if _which(name_l):
        data = load_verified()
        if name_l not in data or not data[name_l].get("verified"):
            mark_verified(name_l, True, "found on PATH")
        return True
    entry = TOOLS.get(name_l)
    if entry and entry.get("check"):
        rc, _ = _run(entry["check"], timeout=10)
        if rc == 0:
            mark_verified(name_l, True, "check cmd passed")
            return True
    return False


# ── platform detection ───────────────────────────────────────────────

def platform():
    if os.path.exists("/data/data/com.termux"):
        return "termux"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform == "win32":
        return "windows"
    if os.path.exists("/etc/debian_version"):
        return "ubuntu"
    if os.path.exists("/etc/redhat-release"):
        return "redhat"
    return "linux"


# ── sudo helpers ─────────────────────────────────────────────────────
_SUDO_PROBE_CACHE = None
_AUTH_PROMPT_HANDLER = None

def set_auth_prompt_handler(handler):
    """Register interactive operator prompt callback (prompt_str, is_secret) -> str."""
    global _AUTH_PROMPT_HANDLER
    _AUTH_PROMPT_HANDLER = handler


def _save_sudo_to_env(pw: str):
    """Persist verified sudo password to local .env if present."""
    try:
        env_file = HERE / ".env"
        if env_file.exists():
            content = env_file.read_text(encoding="utf-8")
            if "AG_SUDO_PASS=" in content:
                content = re.sub(r"AG_SUDO_PASS=.*", f"AG_SUDO_PASS={pw}", content)
            else:
                content += f"\nAG_SUDO_PASS={pw}\n"
            env_file.write_text(content, encoding="utf-8")
    except Exception:
        pass


def _sudo_password():
    import os as _os
    return _os.environ.get("AG_SUDO_PASS", "").strip()


def request_sudo_auth(prompt: str = "Linux/WSL sudo password required for installation: ") -> bool:
    """Prompt operator for sudo password if not available, test via sudo -S, and cache."""
    global _SUDO_PROBE_CACHE
    if _sudo_available():
        return True
    pw = ""
    if _AUTH_PROMPT_HANDLER is not None:
        try:
            pw = _AUTH_PROMPT_HANDLER(prompt, is_secret=True)
        except Exception:
            pw = ""
    if not pw and sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
        try:
            import getpass
            pw = getpass.getpass(prompt)
        except Exception:
            pass
    if pw:
        pw = str(pw).strip()
        try:
            r = subprocess.run("sudo -S -p '' true", shell=True, input=pw + "\n",
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                os.environ["AG_SUDO_PASS"] = pw
                _SUDO_PROBE_CACHE = True
                _save_sudo_to_env(pw)
                return True
        except Exception:
            pass
    return False


def _sudo_available():
    global _SUDO_PROBE_CACHE
    if _SUDO_PROBE_CACHE is not None:
        return _SUDO_PROBE_CACHE
    if _sudo_password():
        _SUDO_PROBE_CACHE = True
        return True
    import subprocess
    try:
        r = subprocess.run(["sudo", "-n", "true"], capture_output=True,
                           timeout=5)
        _SUDO_PROBE_CACHE = (r.returncode == 0)
    except Exception:
        _SUDO_PROBE_CACHE = False
    return _SUDO_PROBE_CACHE


def _sudo_run(cmd_without_sudo):
    """Run `sudo <cmd>`. Prompts operator or pipes password via stdin if required."""
    import subprocess
    if not _sudo_available() and platform() in ("linux", "ubuntu", "redhat", "macos"):
        request_sudo_auth()

    pw = _sudo_password()
    try:
        if pw:
            # -S reads password from stdin; -p '' suppresses the prompt text
            full = "sudo -S -p '' " + cmd_without_sudo
            r = subprocess.run(full, shell=True, capture_output=True, text=True,
                               input=pw + "\n", timeout=1800)
        else:
            full = "sudo -n " + cmd_without_sudo
            r = subprocess.run(full, shell=True, capture_output=True, text=True,
                               timeout=1800)
        import re as _re
        out = ((r.stdout or "") + (r.stderr or ""))
        # strip any leaked sudo prompt fragments
        out = _re.sub(r"\[sudo[^\]]*\]\s*Password:\s*", "", out)
        out = _re.sub(r"^Password:\s*$", "", out, flags=_re.MULTILINE)
        return r.returncode, out
    except Exception as e:
        return -1, str(e)


PLAT = platform()
PKG_MGR = {
    "termux":  "pkg",
    "ubuntu":  "sudo apt",
    "macos":   "brew",
    "redhat":  "sudo dnf",
    "windows": "winget",
    "linux":   "sudo apt",
}.get(PLAT, "apt")


# ── helpers ──────────────────────────────────────────────────────────

# Data-only repos — clone, don't build.
_DATA_REPOS = {
    "seclists", "payloadsallthethings", "nuclei-templates",
    "payloads", "fuzzdb", "wordlists", "exploitdb",
    "awesome-bugbounty-tools", "bugbountydork", "gf-patterns",
}

def _is_data_repo(name):
    n = (name or "").lower().replace("_", "-")
    return n in _DATA_REPOS or "seclists" in n or "payloadsallthethings" in n


def _which(binary):
    _ensure_path()
    b = str(binary).strip()
    if shutil.which(b) is not None:
        return True
    if PLAT == "windows":
        for ext in (".exe", ".cmd", ".bat", ".ps1"):
            if shutil.which(b + ext) is not None:
                return True
    else:
        # Check user bin directories case-insensitively and auto-symlink if casing differs
        home = pathlib.Path.home()
        b_l = b.lower()
        for d in (home / "go" / "bin", home / ".local" / "bin", home / "agent" / "tools"):
            if d.exists() and d.is_dir():
                try:
                    for f in d.iterdir():
                        if f.is_file() and f.name.lower() == b_l:
                            if f.name != b:
                                link = d / b
                                if not link.exists():
                                    try:
                                        link.symlink_to(f)
                                    except Exception:
                                        pass
                            return True
                except Exception:
                    pass
    return False


def _create_script_wrapper(name: str, target_path: pathlib.Path):
    """Create executable CLI launcher in ~/.local/bin/<name>."""
    home = pathlib.Path.home()
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    wrapper = bin_dir / name.lower()
    script_str = str(target_path).replace("\\", "/")
    if target_path.suffix == ".py":
        content = f"#!/usr/bin/env bash\nexec python3 {shlex.quote(script_str)} \"$@\"\n"
    elif target_path.suffix == ".sh":
        content = f"#!/usr/bin/env bash\nexec bash {shlex.quote(script_str)} \"$@\"\n"
    else:
        content = f"#!/usr/bin/env bash\nexec {shlex.quote(script_str)} \"$@\"\n"
    try:
        wrapper.write_text(content, encoding="utf-8")
        wrapper.chmod(0o755)
        return True
    except Exception:
        return False


def _post_install_fixup(name: str):
    """Ensure casing aliases and Python repo script wrappers exist so command -v <name> works."""
    home = pathlib.Path.home()
    name_l = name.lower()
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    # 1. Casing alias in ~/go/bin, ~/.local/bin, ~/agent/tools
    for d in (home / "go" / "bin", home / ".local" / "bin", home / "agent" / "tools"):
        if d.exists() and d.is_dir():
            try:
                for f in d.iterdir():
                    if f.is_file() and f.name.lower() == name_l and f.name != name_l:
                        link = d / name_l
                        if not link.exists():
                            try:
                                link.symlink_to(f)
                            except Exception:
                                pass
            except Exception:
                pass

    # 2. Python repository launchers: search ~/agent/tools/*
    repo_dirs = [
        home / "agent" / "tools" / f"{name_l}_repo",
        home / "agent" / "tools" / name_l,
        home / "agent" / "tools" / name,
    ]
    for rd in repo_dirs:
        if rd.exists() and rd.is_dir():
            script_candidates = [
                rd / f"{name_l}.py",
                rd / f"{name}.py",
                rd / "main.py",
                rd / f"{name_l}.sh",
                rd / name_l,
            ]
            for sc in script_candidates:
                if sc.exists() and sc.is_file():
                    _create_script_wrapper(name_l, sc)
                    break


def _run(cmd, timeout=1800, cwd=None):
    try:
        _ensure_path()
        inp = None
        if PLAT != "windows":
            home = pathlib.Path.home()
            path_prefix = f'export PATH="{home}/go/bin:{home}/.local/bin:{home}/agent/tools:$PATH"; '
            cmd = path_prefix + cmd
            if "sudo " in cmd:
                pw = _sudo_password()
                if pw:
                    cmd = re.sub(r"\bsudo\b", "sudo -S -p ''", cmd)
                    inp = pw + "\n"
                else:
                    cmd = re.sub(r"\bsudo\b", "sudo -n", cmd)
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           input=inp, timeout=timeout, cwd=cwd)
        out = (r.stdout or "") + (r.stderr or "")
        out = re.sub(r"\[sudo[^\]]*\]\s*Password:\s*", "", out)
        return r.returncode, out
    except subprocess.TimeoutExpired:
        return -1, "[timeout]"
    except Exception as e:
        return -1, str(e)


def _log_install(name, method, ok, extra=""):
    try:
        entries = []
        if INSTALL_LOG.exists():
            try:
                entries = json.loads(INSTALL_LOG.read_text())
            except Exception:
                entries = []
        entries.append({
            "ts": time.time(),
            "name": name,
            "method": method,
            "ok": bool(ok),
            "platform": PLAT,
            "extra": extra[:500],
        })
        INSTALL_LOG.write_text(json.dumps(entries[-500:], indent=2))
    except Exception:
        pass


def _record_tool_dir():
    p = HERE / "tools"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ── curated install from tools_db ────────────────────────────────────

def _try_curated(name):
    entry = TOOLS.get(name.lower())
    if not entry:
        return None
    if _which(name):
        return True, f"{name}: already installed"

    check = entry.get("check")
    if check and PLAT != "windows":
        rc, _ = _run(check, timeout=15)
        if rc == 0:
            return True, f"{name}: already installed"

    # pick platform-specific install
    install = (entry.get(f"install_{PLAT}")
               or entry.get("install"))
    if not install:
        return None

    if PLAT == "windows":
        install = re.sub(r"\bpython3\b", "python", install)
        install = re.sub(r"\bpip3\b", "pip", install)
        if "apt " in install and "pip " in install:
            install = f"pip install --user {name}"
    else:
        # On Linux/Ubuntu/Debian (PEP 668): append --break-system-packages for user pip installs
        if "pip install" in install and "--break-system-packages" not in install:
            install = re.sub(r"\bpip3? install\b", r"\g<0> --break-system-packages", install)
        if "apt install" in install and not install.strip().startswith("sudo "):
            if _sudo_available():
                install = re.sub(r"\bapt install\b", "sudo apt install", install)
            else:
                request_sudo_auth(f"Linux/WSL sudo password required for {name}: ")
                if _sudo_available():
                    install = re.sub(r"\bapt install\b", "sudo apt install", install)

    rc, out = _run(install, timeout=1800)
    _post_install_fixup(name)
    ok = _which(name)
    if not ok and entry.get("url") and "pip" in install:
        # Fallback: install directly from upstream git repository
        url = entry["url"]
        rc2, out2 = _run(f"pipx install git+{url}.git 2>&1 || pip3 install --user --break-system-packages git+{url}.git 2>&1")
        _post_install_fixup(name)
        ok = _which(name)
        out += "\n" + out2

    _log_install(name, install.split()[0], ok, out[-500:])
    return ok, f"{name}: {'installed OK' if ok else 'install failed'}\n{out[-600:]}"


# ── github repo clone + build ────────────────────────────────────────

def install_github(url):
    name = url.rstrip("/").split("/")[-1].replace(".git", "")
    if not name:
        return False, "github: empty repo"
    dest = _record_tool_dir() / name
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    rc, out = _run(f"git clone --depth 1 {url} {dest}", timeout=600)
    if rc != 0:
        return False, f"{name}: clone failed\n{out[-500:]}"
    if _is_data_repo(name):
        _log_install(name, "github-data", True, url)
        return True, f"{name}: cloned as data repo to {dest} (no build)"

    # try every plausible build system, in order
    builds = [
        ("go",     f"cd {shlex.quote(str(dest))} && go build -o {shlex.quote(name)} . 2>&1 || go build -o {shlex.quote(name)} ./cmd/* 2>&1"),
        ("go-cmd", f"cd {shlex.quote(str(dest))} && go build -o {shlex.quote(name)} ./cmd/{shlex.quote(name)} 2>&1"),
        ("cargo",  f"cd {shlex.quote(str(dest))} && cargo build --release 2>&1"),
        ("make",   f"cd {shlex.quote(str(dest))} && make 2>&1"),
        ("python", f"cd {shlex.quote(str(dest))} && pip install --user . 2>&1 || pipx install . 2>&1"),
        ("npm",    f"cd {shlex.quote(str(dest))} && npm install -g . 2>&1"),
    ]
    for label, cmd in builds:
        rc, out = _run(cmd, timeout=1800)
        # hunt for the binary
        candidates = [
            dest / name,
            dest / "target" / "release" / name,
            dest / "bin" / name,
            dest / f"{name}.py",
        ]
        for cand in candidates:
            if cand.exists():
                try:
                    cand.chmod(0o755)
                    link = _record_tool_dir() / name
                    if link.exists() or link.is_symlink():
                        link.unlink()
                    link.symlink_to(cand)
                    _log_install(name, f"github+{label}", True, url)
                    return True, f"{name}: built via {label} → {link}"
                except Exception:
                    pass
    _log_install(name, "github", False, url)
    return False, f"{name}: cloned to {dest} but no binary located\n{out[-400:]}"


# ── github search for unknown tools ──────────────────────────────────

def github_search(term):
    """Query GitHub API for repos matching term. Returns list of full names."""
    try:
        import urllib.request, urllib.parse
        q = urllib.parse.quote_plus(f"{term} in:name")
        req = urllib.request.Request(
            f"https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=5",
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "ag-installer"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        return [item["full_name"] for item in data.get("items", [])]
    except Exception:
        return []


def search_install(term):
    """Fallback: search github for a repo that matches `term` and install it."""
    candidates = github_search(term)
    for c in candidates[:3]:
        ok, msg = install_github(f"https://github.com/{c}.git")
        if ok:
            return True, f"{term}: installed via github/{c}"
    return False, f"{term}: no github match"


# ── generic multi-method install ─────────────────────────────────────

# ── self-bootstrap: Go from tarball (no sudo needed) ───────────────
_GO_TARBALL = "https://go.dev/dl/go1.22.4.linux-amd64.tar.gz"

def _bootstrap_go():
    """Install Go to ~/.local/go and expose ~/go/bin + ~/.local/go/bin.
    Runs without sudo — writes under $HOME. Idempotent."""
    import os, shutil, urllib.request, tarfile
    home = pathlib.Path.home()
    go_root = home / ".local" / "go"
    go_bin  = go_root / "bin" / "go"
    if go_bin.exists():
        return True, f"go already at {go_bin}"
    tarball = home / "go1.22.4.linux-amd64.tar.gz"
    if not tarball.exists():
        try:
            print("  [bootstrap] downloading Go toolchain...")
            urllib.request.urlretrieve(_GO_TARBALL, tarball)
        except Exception as e:
            return False, f"download failed: {e}"
    try:
        (home / ".local").mkdir(exist_ok=True)
        # remove any partial
        if go_root.exists():
            shutil.rmtree(go_root, ignore_errors=True)
        with tarfile.open(tarball, "r:gz") as t:
            t.extractall(home / ".local")
        # normalize: tarball ships "go/" → ~/.local/go/
        if (home / ".local" / "go").exists() and not go_bin.exists():
            # tarball layout is already ~/.local/go/bin/go
            pass
        # add to PATH for this process
        os.environ["PATH"] = f"{home/'go'/'bin'}:{go_root/'bin'}:{os.environ.get('PATH','')}"
        return True, f"go installed at {go_bin}"
    except Exception as e:
        return False, f"extract failed: {e}"


def _bootstrap_pipx():
    """Install pipx and ensure ~/.local/bin is exposed."""
    _ensure_path()
    if _which("pipx"):
        return True, "pipx already installed"
    rc, out = _run("python3 -m pip install --user --break-system-packages pipx 2>&1 || pip3 install --user --break-system-packages pipx 2>&1 || pip install --user --break-system-packages pipx 2>&1")
    _ensure_path()
    if _which("pipx"):
        _run("pipx ensurepath 2>&1")
        _ensure_path()
        return True, "pipx bootstrapped via user pip"
    if _sudo_available():
        _sudo_run("apt install -y pipx")
        _ensure_path()
        if _which("pipx"):
            _run("pipx ensurepath 2>&1")
            _ensure_path()
            return True, "pipx installed via apt"
    return False, f"pipx bootstrap failed:\n{out[-300:]}"


def bootstrap_foundation(on_status=None):
    """Ensure core ecosystem tools (go, pipx, local bin dirs) are available."""
    _ensure_path()
    if PLAT != "windows":
        if not _which("pipx"):
            if on_status: on_status("📦 Bootstrapping pipx environment...")
            _bootstrap_pipx()
        if not _which("go"):
            if on_status: on_status("📦 Bootstrapping Go toolchain...")
            _bootstrap_go()
    _ensure_path()


def _ensure_path():
    """Prepend user-local bin dirs so newly installed tools win over
    distro/pip versions. Call before every _which() check."""
    import os
    home = pathlib.Path.home()
    dirs = [
        home / "agent" / "tools",
        home / "go" / "bin",
        home / ".local" / "bin",
    ]
    if PLAT == "windows":
        dirs.extend([
            pathlib.Path(r"C:\Program Files\Git\bin"),
            pathlib.Path(r"C:\Program Files\Git\usr\bin"),
            pathlib.Path(r"C:\Program Files\Git\cmd"),
            pathlib.Path(os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python312")),
            pathlib.Path(os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python312\Scripts")),
            home / "AppData" / "Roaming" / "Python" / "Python312" / "Scripts",
        ])
    sep = os.pathsep
    curr_parts = os.environ.get("PATH", "").split(sep)
    for p in dirs:
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        s = str(p)
        if s not in curr_parts:
            os.environ["PATH"] = s + sep + os.environ.get("PATH", "")
            curr_parts.insert(0, s)


# ── language inference for NEED_TOOL ───────────────────────────────
# many tools are distributed in one specific ecosystem; trying pip/npm
# for a Go binary is the run-1 and run-2 failure. Classify first, then
# try only the viable managers.

_GO_TOOLS = {
    "subfinder", "httpx", "nuclei", "katana", "naabu", "dnsx", "tlsx",
    "gau", "amass", "assetfinder", "waybackurls", "gf", "anew", "ffuf",
    "gobuster", "dalfox", "gowitness", "gitleaks", "trufflehog", "kr",
    "chisel", "kerbrute", "shuffledns", "puredns", "gospider", "hakrawler",
    "interactsh-client", "httprobe", "gron", "notify", "subzy",
    "jsluice", "cloudlist",
}
_PROJECTDISCOVERY_TOOLS = {
    "subfinder", "httpx", "nuclei", "katana", "naabu", "dnsx", "tlsx",
    "shuffledns", "asnmap", "cdncheck", "interactsh-client", "notify",
    "chaos"
}
_PIP_TOOLS = {
    "sqlmap", "wafw00f", "arjun", "paramspider", "sstimap", "dirsearch",
    "wfuzz", "impacket", "responder", "pypykatz", "certipy", "coercer",
    "netexec", "smbmap", "enum4linux-ng", "ssrfmap", "corsy", "dnsgen", "altdns",
}
_APT_TOOLS = {
    "nmap", "masscan", "nikto", "whatweb", "wpscan", "hydra", "hashcat",
    "john", "smbclient", "sslscan", "redis-cli", "psql", "mongo",
    "jq", "dig", "whois", "chromium",
}

def _tool_language(name):
    n = (name or "").strip().lower()
    if n in _GO_TOOLS: return "go"
    if n in _PIP_TOOLS: return "pip"
    if n in _APT_TOOLS: return "apt"
    return None


def install_any(name):
    name = name.strip()
    if not name:
        return "install: empty name"

    _ensure_path()

    # 0) already installed?
    if _which(name):
        return f"{name}: already installed"

    # 1) Curated entry from tools_db FIRST!
    # tools_db has authoritative, verified upstream URLs and flags.
    curated = _try_curated(name)
    if curated is not None:
        ok, msg = curated
        if ok or _which(name):
            return msg

    # 2) explicit scheme/package-manager prefixes
    if name.startswith(("http://", "https://")):
        ok, msg = install_github(name)
        return msg
    if name.startswith("github:"):
        ok, msg = install_github(f"https://github.com/{name.split(':',1)[1]}.git")
        return msg
    if name.startswith("gitlab:"):
        ok, msg = install_github(f"https://gitlab.com/{name.split(':',1)[1]}.git")
        return msg
    if name.startswith("pip:"):
        pkg = name[4:]
        for cmd in (f"pip3 install --user --break-system-packages {pkg} 2>&1",
                    f"pipx install {pkg} 2>&1",
                    f"pip3 install {pkg} --break-system-packages 2>&1",
                    f"pip install --user --break-system-packages {pkg} 2>&1",
                    f"pip install {pkg} 2>&1"):
            rc, out = _run(cmd)
            if (rc == 0 and _which(pkg)) or _which(pkg):
                return f"{pkg}: installed via {cmd.split()[0]}"
        return f"{pkg}: pip install failed\n{out[-400:]}"
    if name.startswith("pip3:"):
        return install_any("pip:" + name[5:])
    if name.startswith("apt:"):
        pkg = name[4:]
        if not _sudo_available():
            if platform() in ("linux", "ubuntu", "redhat", "macos"):
                request_sudo_auth(f"Linux/WSL sudo password required for {pkg}: ")
            if not _sudo_available():
                return (f"[NO-SUDO] {pkg}: apt not available (no passwordless "
                        f"sudo and AG_SUDO_PASS unset). System package.")
        apt_cmd = f"{PKG_MGR.replace('sudo ', '')} install -y {pkg}"
        rc, out = _sudo_run(apt_cmd)
        rc2, _ = _run(f"dpkg -s {pkg} 2>&1", timeout=15)
        ok = (rc2 == 0) or _which(pkg)
        return f"{pkg}: {'installed OK' if ok else 'install failed'}\n{out[-600:]}"
    if name.startswith("npm:"):
        pkg = name[4:]
        rc, out = _run(f"npm install -g --prefix ~/.local {pkg} 2>&1 || npm install -g {pkg} 2>&1")
        return f"{pkg}: {'installed' if rc==0 else 'failed'}\n{out[-400:]}"
    if name.startswith("cargo:"):
        pkg = name[6:]
        rc, out = _run(f"cargo install {pkg} 2>&1")
        return f"{pkg}: {'installed' if rc==0 else 'failed'}\n{out[-400:]}"
    if name.startswith("go:"):
        pkg = name[3:]
        rc, out = _run(f"go install {pkg}@latest 2>&1")
        return f"{pkg}: {'installed' if rc==0 else 'failed'}\n{out[-400:]}"
    if "/" in name and " " not in name and not name.endswith(".py"):
        ok, msg = install_github(f"https://github.com/{name}.git")
        return msg

    # 3) language-aware short-circuit for uncurated tools
    _lang = _tool_language(name)
    if _lang == "go":
        if not _which("go"):
            ok_go, msg_go = _bootstrap_go()
            if not ok_go:
                return (f"{name}: Go toolchain not installed. This is a Go "
                        f"binary. Run NEED_TOOL: go|bootstrap Go, then retry "
                        f"NEED_TOOL: {name}.")
        name_l = name.lower()
        if name_l in _PROJECTDISCOVERY_TOOLS:
            rc, out = _run(f"go install -v github.com/projectdiscovery/{name}/v2/cmd/{name}@latest", timeout=900)
            if rc != 0:
                rc, out = _run(f"go install -v github.com/projectdiscovery/{name}/cmd/{name}@latest", timeout=900)
        else:
            rc, out = _run(f"go install -v {name}@latest 2>&1", timeout=900)
            if rc != 0 and "/" not in name:
                ok_gh, msg_gh = search_install(name)
                if ok_gh: return msg_gh
        if _which(name):
            _log_install(name, "go-direct", True, "")
            return f"{name}: installed via go install"
        return f"{name}: go install failed\n{out[-400:]}"

    if _lang == "pip":
        rc, out = _run(f"pip3 install --user --break-system-packages {name} 2>&1 || pipx install {name} 2>&1 || pip install --user --break-system-packages {name} 2>&1", timeout=900)
        if _which(name):
            _log_install(name, "pip-direct", True, "")
            return f"{name}: installed via pip3"
        return f"{name}: pip install failed\n{out[-400:]}"

    if _lang == "apt":
        if not _sudo_available():
            if platform() in ("linux", "ubuntu", "redhat", "macos"):
                request_sudo_auth(f"Linux/WSL sudo password required for {name}: ")
            if not _sudo_available():
                return (f"[NO-SUDO] {name} is a system package. Set AG_SUDO_PASS "
                        f"or install manually.")
        rc, out = _sudo_run(f"apt install -y {name}")
        if _which(name):
            return f"{name}: installed via apt"
        return f"{name}: apt install failed\n{out[-400:]}"

    # 4) generic multi-method ladder
    methods = [
        ("pip3-user", f"pip3 install --user --break-system-packages {name} 2>&1 || pip3 install --user {name} 2>&1"),
        ("pipx",      f"pipx install {name} 2>&1"),
        ("pip-user",  f"pip install --user --break-system-packages {name} 2>&1 || pip install --user {name} 2>&1"),
        ("pip3",      f"pip3 install --break-system-packages {name} 2>&1 || pip3 install {name} 2>&1"),
        ("pip",       f"pip install --break-system-packages {name} 2>&1 || pip install {name} 2>&1"),
    ]
    if _sudo_available():
        methods += [
            ("apt", f"sudo apt install -y {name} 2>&1"),
            ("pkg", f"sudo pkg install -y {name} 2>&1"),
        ]
    methods += [
        ("npm",   f"npm install -g {name} 2>&1"),
        ("gem",   f"gem install {name} 2>&1"),
        ("cargo", f"cargo install {name} 2>&1"),
        ("go",    f"go install {name}@latest 2>&1"),
        ("snap",  f"snap install {name} 2>&1"),
    ]
    tried = []
    for label, cmd in methods:
        rc, out = _run(cmd, timeout=900)
        tried.append(f"{label}: rc={rc}")
        if _which(name):
            _log_install(name, label, True, out[-200:])
            return f"{name}: installed via {label}"

    # 5) github search
    gh_ok, gh_msg = search_install(name)
    if gh_ok:
        return gh_msg

    _log_install(name, "none", False, "; ".join(tried))
    return f"{name}: all methods failed\n" + "\n".join(tried)


# ── batch install (used by startup bootstrap) ────────────────────────

def install_many(names, verbose=True):
    results = {}
    for n in names:
        if verbose:
            print(f"[install] {n}")
        results[n] = install_any(n)
    return results


def already_installed(names):
    """Return subset of names that are already on PATH."""
    return [n for n in names if _which(n)]


# ── task-driven requirement detection & auto-provisioning ───────────

def detect_needed_tools(task_or_target: str):
    """Derive list of required tools based on target URL/host, scope, and objective keywords."""
    txt = (task_or_target or "").lower()
    needed = set()

    # Target URL / domain detection
    if re.search(r"https?://|\.com\b|\.net\b|\.org\b|\.io\b|\.local\b|\d+\.\d+\.\d+\.\d+", txt) or "target" in txt or "scan" in txt or "audit" in txt:
        needed.update(["httpx", "subfinder", "nuclei", "wafw00f", "nmap", "ffuf", "katana"])

    if any(k in txt for k in ("subdomain", "dns", "recon", "enum", "discovery")):
        needed.update(["subfinder", "assetfinder", "dnsx", "naabu", "gau", "waybackurls"])

    if any(k in txt for k in ("sql", "sqli", "injection", "database", "blind")):
        needed.update(["sqlmap", "ghauri"])

    if any(k in txt for k in ("xss", "reflection", "dom", "cross-site")):
        needed.update(["dalfox", "katana"])

    if any(k in txt for k in ("api", "graphql", "rest", "swagger", "openapi", "jwt", "token")):
        needed.update(["arjun", "jwt_tool", "graphql-cop", "ffuf"])

    if any(k in txt for k in ("fuzz", "brute", "dirsearch", "dir", "endpoint", "path")):
        needed.update(["ffuf", "gobuster", "dirsearch"])

    if any(k in txt for k in ("c2", "malware", "payload", "shellcode", "stager", "implant", "evasion")):
        needed.update(["msfvenom", "donut", "gcc", "upx", "sliver"])

    if any(k in txt for k in ("ad", "activedirectory", "kerberos", "smb", "winrm", "ldap")):
        needed.update(["nxc", "impacket-mssqlclient", "kerbrute", "bloodhound-python"])

    if any(k in txt for k in ("hash", "crack", "password", "wordlist", "auth")):
        needed.update(["hashcat", "john", "hydra"])

    if any(k in txt for k in ("reverse", "reversing", "binary", "disasm", "rop", "gadget", "elf", "pe")):
        needed.update(["radare2", "checksec", "ropper", "ROPgadget"])

    if any(k in txt for k in ("cloud", "aws", "s3", "azure", "bucket")):
        needed.update(["cloud_enum", "s3scanner"])

    if any(k in txt for k in ("secret", "leak", "truffle", "gitleaks", "credential")):
        needed.update(["gitleaks", "trufflehog"])

    if not needed:
        needed.update(["httpx", "subfinder", "nuclei", "ffuf", "nmap", "wafw00f"])

    return sorted(list(needed))


def ensure_tools_for_task(task_or_target: str, auto_install: bool = True, on_status=None):
    """
    Check if needed tools for task/target are installed & verified.
    Auto-installs any missing tools, prompting for sudo password if required,
    and records verified tools in tools_verified.json.
    """
    tools = detect_needed_tools(task_or_target)
    already_ok = []
    missing = []
    newly_installed = []
    failed = []

    for t in tools:
        if is_verified(t):
            already_ok.append(t)
        else:
            missing.append(t)

    if missing and auto_install:
        bootstrap_foundation(on_status=on_status)
        if on_status:
            on_status(f"🧰 Checking dependencies: {len(missing)} missing ({', '.join(missing)}). Auto-provisioning...")

        # Request sudo credentials if an apt package is missing
        needs_sudo = any(
            _tool_language(m) == "apt" or (TOOLS.get(m, {}).get("install", "").startswith("apt "))
            for m in missing
        )
        if needs_sudo and not _sudo_available() and platform() in ("linux", "ubuntu", "redhat", "macos"):
            request_sudo_auth()

        for m in missing:
            if on_status:
                on_status(f"⚡ Provisioning tool: {m}...")
            res_str = install_any(m)
            if is_verified(m):
                mark_verified(m, True, res_str)
                newly_installed.append(m)
                if on_status:
                    on_status(f"✓ Verified & installed: {m}")
            else:
                failed.append((m, res_str))
                if on_status:
                    on_status(f"✗ Provision failed for {m}: {res_str[:120]}")

    return {
        "target": task_or_target,
        "needed": tools,
        "already_verified": already_ok,
        "newly_installed": newly_installed,
        "failed": failed,
        "ready": len(failed) == 0,
    }


# ── category-by-category red team tool provisioning ─────────────────

REDTEAM_CATEGORIES = [
    "recon", "web", "fuzz", "network", "pivot", "creds",
    "api", "secrets", "cloud", "util", "wordlist", "reversing", "misc"
]


def preinstall_category(category: str, on_status=None):
    """Install and verify all tools in a specific red team category."""
    bootstrap_foundation(on_status=on_status)
    cat = (category or "").lower().strip()
    tools_in_cat = [k for k, v in TOOLS.items() if v.get("category", "").lower() == cat]
    if not tools_in_cat:
        return {"category": cat, "error": f"Unknown category: {cat}", "installed": []}

    needs_sudo = any(
        TOOLS.get(t, {}).get("install", "").startswith("apt ") or _tool_language(t) == "apt"
        for t in tools_in_cat
    )
    if needs_sudo and not _sudo_available() and platform() in ("linux", "ubuntu", "redhat", "macos"):
        request_sudo_auth(f"Linux/WSL sudo password required to install {cat} category: ")

    results = {"category": cat, "already": [], "installed": [], "failed": []}
    for t in tools_in_cat:
        if is_verified(t):
            results["already"].append(t)
            continue
        if on_status:
            on_status(f"[{cat.upper()}] Installing {t}...")
        out = install_any(t)
        if is_verified(t):
            mark_verified(t, True, out)
            results["installed"].append(t)
            if on_status:
                on_status(f"[{cat.upper()}] ✓ {t} installed and verified")
        else:
            results["failed"].append((t, out))
            if on_status:
                on_status(f"[{cat.upper()}] ✗ {t} failed: {out[:80]}")
    return results


def preinstall_all_categories(on_status=None):
    """Pre-install and verify all red team tools category by category."""
    all_res = {}
    for cat in REDTEAM_CATEGORIES:
        if on_status:
            on_status(f"🚀 Pre-installing Category: {cat.upper()}...")
        all_res[cat] = preinstall_category(cat, on_status=on_status)
    return all_res


def status():
    """Report what's installed and verified from tools_db."""
    _ensure_path()
    verified_reg = load_verified()
    installed = []
    missing = []
    for name, entry in TOOLS.items():
        if is_verified(name):
            installed.append(name)
        else:
            missing.append(name)
    return {
        "platform": PLAT,
        "total_in_db": len(TOOLS),
        "installed": len(installed),
        "missing": len(missing),
        "verified_count": len([k for k, v in verified_reg.items() if v.get("verified")]),
        "installed_list": sorted(installed),
        "missing_list": sorted(missing),
        "categories": REDTEAM_CATEGORIES,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(json.dumps(status(), indent=2)[:3000])
        sys.exit(0)
    cmd = sys.argv[1]
    if cmd == "install":
        for n in sys.argv[2:]:
            print(install_any(n))
    elif cmd == "status":
        s = status()
        print(f"platform: {s['platform']}")
        print(f"installed: {s['installed']}/{s['total_in_db']} (verified: {s['verified_count']})")
        print("missing:", ", ".join(s["missing_list"][:40]))
    elif cmd == "check":
        target = sys.argv[2] if len(sys.argv) > 2 else "https://target.com"
        print(json.dumps(ensure_tools_for_task(target, auto_install=False), indent=2))
    elif cmd == "preinstall":
        cat = sys.argv[2] if len(sys.argv) > 2 else "all"
        if cat == "all":
            print(json.dumps(preinstall_all_categories(on_status=print), indent=2))
        else:
            print(json.dumps(preinstall_category(cat, on_status=print), indent=2))
    elif cmd == "search":
        q = sys.argv[2] if len(sys.argv) > 2 else ""
        for c in github_search(q):
            print(c)
    else:
        print(f"unknown cmd: {cmd}")
