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

def _sudo_password():
    import os as _os
    return _os.environ.get("AG_SUDO_PASS", "").strip()


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
    """Run `sudo <cmd>`. Pipes password via stdin if AG_SUDO_PASS is set."""
    import subprocess
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
    return shutil.which(binary) is not None


def _run(cmd, timeout=1800, cwd=None):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
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
    check = entry.get("check")
    if check:
        rc, _ = _run(check, timeout=15)
        if rc == 0:
            return True, f"{name}: already installed"

    # pick platform-specific install
    install = (entry.get(f"install_{PLAT}")
               or entry.get("install"))
    if not install:
        return None

    rc, out = _run(install, timeout=1800)
    rc2, _ = _run(check or f"command -v {name}", timeout=15)
    ok = rc2 == 0
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
    import os, shutil, subprocess, urllib.request, tarfile
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


def _ensure_path():
    """Prepend user-local bin dirs so newly installed tools win over
    distro/pip versions. Call before every _which() check."""
    import os
    home = pathlib.Path.home()
    for p in (home / "agent" / "tools", home / "go" / "bin", home / ".local" / "bin"):
        s = str(p)
        if p.exists() and s not in os.environ.get("PATH", "").split(":"):
            os.environ["PATH"] = s + ":" + os.environ.get("PATH", "")


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
_PIP_TOOLS = {
    "sqlmap", "wafw00f", "arjun", "paramspider", "sstimap", "dirsearch",
    "wfuzz", "impacket", "responder", "pypykatz", "certipy", "coercer",
    "netexec", "smbmap", "enum4linux-ng", "ssrfmap", "corsy",
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
_PIP_TOOLS = {
    "sqlmap", "wafw00f", "arjun", "paramspider", "sstimap", "dirsearch",
    "wfuzz", "impacket", "responder", "pypykatz", "certipy", "coercer",
    "netexec", "smbmap", "enum4linux-ng", "ssrfmap", "corsy",
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

    # language-aware short-circuit — don't try npm for a Go binary
    _lang = _tool_language(name)
    if _lang == "go":
        if not _which("go"):
            return (f"{name}: Go toolchain not installed. This is a Go "
                    f"binary. Run NEED_TOOL: go|bootstrap Go, then retry "
                    f"NEED_TOOL: {name}.")
        import os as _os
        home = pathlib.Path.home()
        _os.environ["PATH"] = (f"{home/'go'/'bin'}:{home/'.local'/'go'/'bin'}:"
                               + _os.environ.get("PATH",""))
        rc, out = _run(f"go install -v github.com/projectdiscovery/{name}/v2/cmd/{name}@latest", timeout=900)
        if rc != 0:
            rc, out = _run(f"go install -v github.com/projectdiscovery/{name}/cmd/{name}@latest", timeout=900)
        if rc == 0 and _which(name):
            _log_install(name, "go-direct", True, "projectdiscovery")
            return f"{name}: installed via go install"
        return f"{name}: go install failed\n{out[-400:]}"
    if _lang == "pip":
        rc, out = _run(f"pip3 install --user {name} 2>&1", timeout=900)
        if _which(name):
            _log_install(name, "pip-direct", True, "")
            return f"{name}: installed via pip3"
        return f"{name}: pip install failed\n{out[-400:]}"
    if _lang == "apt":
        if not _sudo_available():
            return (f"[NO-SUDO] {name} is a system package. Set AG_SUDO_PASS "
                    f"or install manually.")
        rc, out = _sudo_run(f"apt install -y {name}")
        if _which(name):
            return f"{name}: installed via apt"
        return f"{name}: apt install failed\n{out[-400:]}"

    # github/gitlab/http
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
        for cmd in (f"pip3 install {pkg} 2>&1",
                    f"pip3 install --user {pkg} 2>&1",
                    f"pip install --user {pkg} 2>&1",
                    f"pip install {pkg} 2>&1"):
            rc, out = _run(cmd)
            if rc == 0 and _which(pkg):
                return f"{pkg}: installed via {cmd.split()[0]}"
        return f"{pkg}: pip install failed\n{out[-400:]}"
    if name.startswith("pip3:"):
        return install_any("pip:" + name[5:])
    if name.startswith("apt:"):
        pkg = name[4:]
        if not _sudo_available():
            return (f"[NO-SUDO] {pkg}: apt not available (no passwordless "
                    f"sudo and AG_SUDO_PASS unset). System package; pip/npm/"
                    f"gem/cargo/go can't install it. Options: set AG_SUDO_PASS, "
                    f"pre-install at image build, or pick another technique.")
        apt_cmd = f"{PKG_MGR.replace('sudo ', '')} install -y {pkg}"
        rc, out = _sudo_run(apt_cmd)
        rc2, _ = _run(f"dpkg -s {pkg} 2>&1", timeout=15)
        ok = (rc2 == 0)
        return f"{pkg}: {'installed OK' if ok else 'install failed'}\n{out[-600:]}"
    if name.startswith("npm:"):
        pkg = name[4:]
        rc, out = _run(f"npm install -g {pkg} 2>&1")
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

    # already installed?
    if _which(name):
        return f"{name}: already installed"

    # 1) curated
    result = _try_curated(name)
    if result is not None:
        ok, msg = result
        if ok:
            return msg

    # 1.5) ensure go is available before any go install runs
    if not _which("go"):
        ok, msg = _bootstrap_go()
        if ok:
            print(f"  [bootstrap] {msg}")

    # 2) generic multi-method ladder
    # pip first — python packages are the most common ask
    methods = [
        ("pip3-user", f"pip3 install --user {name} 2>&1"),
        ("pip3",      f"pip3 install {name} 2>&1"),
        ("pip-user",  f"pip install --user {name} 2>&1"),
        ("pip",       f"pip install {name} 2>&1"),
        ("pipx",      f"pipx install {name} 2>&1"),
    ]
    # system packages only when sudo works (passwordless or AG_SUDO_PASS)
    if _sudo_available():
        methods += [
            ("apt", f"sudo apt install -y {name} 2>&1"),
            ("pkg", f"sudo pkg install -y {name} 2>&1"),
        ]
    # other ecosystems
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

    # 3) github search
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


def status():
    """Report what's installed from tools_db."""
    installed = []
    missing = []
    for name, entry in TOOLS.items():
        check = entry.get("check") or f"command -v {name}"
        rc, _ = _run(check, timeout=5)
        (installed if rc == 0 else missing).append(name)
    return {
        "platform": PLAT,
        "total_in_db": len(TOOLS),
        "installed": len(installed),
        "missing": len(missing),
        "installed_list": sorted(installed),
        "missing_list": sorted(missing),
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
        print(f"installed: {s['installed']}/{s['total_in_db']}")
        print("missing:", ", ".join(s["missing_list"][:40]))
    elif cmd == "search":
        q = sys.argv[2] if len(sys.argv) > 2 else ""
        for c in github_search(q):
            print(c)
    else:
        print(f"unknown cmd: {cmd}")
