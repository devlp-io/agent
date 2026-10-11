"""
evidence/archive.py — full-evidence archive for a run.

Writes raw artifacts alongside the parsed results in state.json:

  archive/
    http/                    one file per HTTP transcript
      <turn>_<host>_<path>.txt
    tool/                    full stdout per command
      <turn>_<tool>.txt
    screenshots/             collector already writes here
    index.jsonl              one line per archived artifact
    README.txt

Both live_tool() and http() are idempotent-safe: repeat calls append.
"""
import re
import json
import pathlib
import hashlib
import threading
from datetime import datetime

_LOCK = threading.Lock()


def _slug(s, n=60):
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "_", s or "")
    return s[:n] or "x"


def _archive_dir(run_dir):
    p = pathlib.Path(run_dir) / "archive"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _index(run_dir, kind, path, meta=None):
    try:
        p = _archive_dir(run_dir) / "index.jsonl"
        with _LOCK:
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "kind": kind,
                    "path": str(path),
                    **(meta or {}),
                }, default=str) + "\n")
    except Exception:
        pass


# ── HTTP transcript ────────────────────────────────────────────────

_HTTP_LINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", re.I)
_STATUS = re.compile(r"HTTP/(\d\.\d)\s+(\d{3})")


def http(run_dir, turn, cmd, output, kind="curl"):
    """Extract HTTP method + URL from a curl/wget command and archive the
    full transcript text. Returns the archive path or None."""
    if not run_dir or not output:
        return None
    m = _HTTP_LINE.search(cmd or "")
    method = m.group(1).upper() if m else "GET"
    url = m.group(2) if m else ""
    if not url:
        um = re.search(r"(https?://\S+)", cmd or "")
        url = um.group(1) if um else "unknown"
    host = "host"
    path = "path"
    try:
        from urllib.parse import urlparse
        u = urlparse(url)
        host = u.hostname or "host"
        path = u.path or "/"
    except Exception:
        pass
    name = f"turn{turn:04d}_{method}_{_slug(host,30)}_{_slug(path,40)}.txt"
    fp = _archive_dir(run_dir) / "http" / name
    fp.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _LOCK:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"# ts: {datetime.utcnow().isoformat()}Z\n")
                f.write(f"# method: {method}\n")
                f.write(f"# url: {url}\n")
                f.write(f"# cmd: {cmd}\n")
                f.write("---\n")
                f.write(output)
        _index(run_dir, "http", fp, {"method": method, "url": url, "turn": turn})
        return fp
    except Exception:
        return None


# ── tool output ────────────────────────────────────────────────────

_TOOL_NAMES = (
    "nmap", "nuclei", "ffuf", "gobuster", "feroxbuster", "sqlmap",
    "subfinder", "amass", "httpx", "katana", "whatweb", "wafw00f",
    "masscan", "nikto", "dalfox", "commix", "sstimap", "ssrfmap",
)


def live_tool(run_dir, turn, cmd, output, threshold=600):
    """Archive full output of any tool command whose stdout exceeds
    threshold chars. Small outputs stay inline in live_commands.log."""
    if not run_dir or not output or len(output) < threshold:
        return None
    tool = "cmd"
    low = (cmd or "").lower()
    for t in _TOOL_NAMES:
        if re.search(rf"\b{t}\b", low):
            tool = t
            break
    name = f"turn{turn:04d}_{tool}_{hashlib.sha1((cmd or '').encode()).hexdigest()[:8]}.txt"
    fp = _archive_dir(run_dir) / "tool" / name
    fp.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _LOCK:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"# ts: {datetime.utcnow().isoformat()}Z\n")
                f.write(f"# tool: {tool}\n")
                f.write(f"# cmd: {cmd}\n")
                f.write(f"# bytes: {len(output)}\n")
                f.write("---\n")
                f.write(output)
        _index(run_dir, "tool", fp, {"tool": tool, "turn": turn, "cmd": cmd[:200]})
        return fp
    except Exception:
        return None


# ── README ─────────────────────────────────────────────────────────

def write_readme(run_dir):
    d = _archive_dir(run_dir)
    try:
        (d / "README.txt").write_text(
            "AG EVIDENCE ARCHIVE\n"
            "===================\n\n"
            "http/       — full HTTP transcripts, one file per request\n"
            "tool/       — full output of any tool whose stdout > 600 chars\n"
            "screenshots/— collector screenshots (populated by evidence/collector.py)\n"
            "index.jsonl — one line per archived artifact\n\n"
            "Every file begins with metadata (# ts, # method, # url, # cmd)\n"
            "followed by '---' then the raw content.\n\n"
            "Report regeneration reads this directory to cite raw evidence.\n"
        )
    except Exception:
        pass


def summary(run_dir):
    p = pathlib.Path(run_dir) / "archive" / "index.jsonl"
    if not p.exists():
        return {"http": 0, "tool": 0}
    http = tool = 0
    try:
        with open(p) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("kind") == "http":
                    http += 1
                elif e.get("kind") == "tool":
                    tool += 1
    except Exception:
        pass
    return {"http": http, "tool": tool}
