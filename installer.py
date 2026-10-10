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
    if os.path.exists("/etc/debian_version"):
        return "ubuntu"
    if os.path.exists("/etc/redhat-release"):
        return "redhat"
    return "linux"


PLAT = platform()
PKG_MGR = {
    "termux":  "pkg",
    "ubuntu":  "sudo apt",
    "macos":   "brew",
    "redhat":  "sudo dnf",
    "linux":   "sudo apt",
}.get(PLAT, "apt")


# ── helpers ──────────────────────────────────────────────────────────

def _which(binary):
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

def install_any(name):
    name = name.strip()
    if not name:
        return "install: empty name"

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
        rc, out = _run(f"pip install {pkg} 2>&1")
        return f"{pkg}: {'installed' if rc==0 else 'failed'}\n{out[-400:]}"
    if name.startswith("apt:"):
        pkg = name[4:]
        rc, out = _run(f"{PKG_MGR} install -y {pkg} 2>&1")
        return f"{pkg}: {'installed' if rc==0 else 'failed'}\n{out[-400:]}"
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

    # 2) generic multi-method ladder
    methods = [
        ("pkg",    f"pkg install -y {name} 2>&1"),
        ("apt",    f"sudo apt install -y {name} 2>&1 || apt install -y {name} 2>&1"),
        ("pipx",   f"pipx install {name} 2>&1"),
        ("pip",    f"pip install --user {name} 2>&1 || pip install {name} 2>&1"),
        ("npm",    f"npm install -g {name} 2>&1"),
        ("gem",    f"gem install {name} 2>&1"),
        ("cargo",  f"cargo install {name} 2>&1"),
        ("go",     f"go install {name}@latest 2>&1"),
        ("snap",   f"snap install {name} 2>&1"),
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
