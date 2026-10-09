"""
evidence.collector — HAR capture, screenshots, DOM snapshots.
No pip deps. Uses httpx for HTTP and system chromium (if present) for screenshots.
"""
import os
import re
import json
import time
import base64
import pathlib
import subprocess
import urllib.parse
from datetime import datetime, timezone

try:
    import httpx
    _HAVE_HTTPX = True
except Exception:
    _HAVE_HTTPX = False


def _slug(s, maxlen=80):
    s = re.sub(r"[^a-zA-Z0-9]+", "_", s or "")[:maxlen]
    return s or "item"


def _have_chromium():
    for p in os.environ.get("PATH", "").split(os.pathsep):
        for name in ("chromium", "chromium-browser", "chrome", "google-chrome"):
            if pathlib.Path(p, name).exists():
                return pathlib.Path(p, name)
    return None


class Collector:
    def __init__(self, run_dir):
        self.run_dir = pathlib.Path(run_dir)
        self.ev_dir = self.run_dir / "evidence"
        self.har_dir = self.ev_dir / "har"
        self.shot_dir = self.ev_dir / "screenshots"
        self.dom_dir = self.ev_dir / "dom"
        for d in (self.ev_dir, self.har_dir, self.shot_dir, self.dom_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.har_entries = []

    # ---------- HAR ----------

    def record(self, method, url, req_headers=None, req_body=None,
               status=None, resp_headers=None, resp_body=None,
               elapsed=None, label=None):
        """Append an entry to the in-memory HAR log and flush to disk."""
        entry = {
            "startedDateTime": datetime.now(timezone.utc).isoformat() + "Z",
            "time": (elapsed or 0) * 1000,
            "request": {
                "method": method.upper(),
                "url": url,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": str(v)} for k, v in (req_headers or {}).items()],
                "queryString": _parse_qs(url),
                "postData": {"text": req_body or ""} if req_body else None,
            },
            "response": {
                "status": status or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": str(v)} for k, v in (resp_headers or {}).items()],
                "content": {
                    "size": len(resp_body or ""),
                    "mimeType": (resp_headers or {}).get("content-type", ""),
                    "text": (resp_body or "")[:200000],
                },
            },
            "cache": {},
            "timings": {"send": 0, "wait": (elapsed or 0) * 1000, "receive": 0},
            "_label": label,
        }
        self.har_entries.append(entry)
        self._flush_har()
        return entry

    def _flush_har(self):
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "ag", "version": "2.0"},
                "entries": self.har_entries,
            }
        }
        (self.har_dir / "session.har").write_text(json.dumps(har, indent=2)[:50_000_000])

    def get(self, url, label=None, extra_headers=None):
        """Fetch a URL, record to HAR, save DOM body."""
        if not _HAVE_HTTPX:
            return {"error": "httpx not installed"}
        t0 = time.time()
        try:
            h = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Ag/2.0"}
            if extra_headers:
                h.update(extra_headers)
            r = httpx.get(url, headers=h, timeout=20.0, follow_redirects=True, verify=False)
            elapsed = time.time() - t0
            self.record("GET", url, h, None, r.status_code, dict(r.headers),
                        r.text, elapsed, label)
            slug = _slug(label or url)
            (self.dom_dir / f"{slug}.html").write_text(r.text[:500000])
            return {"status": r.status_code, "size": len(r.content), "elapsed": elapsed}
        except Exception as e:
            self.record("GET", url, None, None, 0, {}, str(e), time.time() - t0, label)
            return {"error": str(e)}

    # ---------- screenshots ----------

    def screenshot(self, url, label=None, width=1280, height=800, timeout=30):
        """Capture screenshot via chromium headless. Returns path or None."""
        chrom = _have_chromium()
        slug = _slug(label or url)
        out = self.shot_dir / f"{slug}.png"
        if chrom:
            cmd = [
                str(chrom), "--headless=new", "--disable-gpu", "--no-sandbox",
                "--hide-scrollbars", "--window-size", f"{width},{height}",
                "--screenshot", str(out), "--virtual-time-budget=5000",
                url,
            ]
            try:
                subprocess.run(cmd, capture_output=True, timeout=timeout)
                if out.exists() and out.stat().st_size > 0:
                    return out
            except Exception:
                pass
        # fallback: store page as printable HTML
        dom_path = self.dom_dir / f"{slug}.html"
        if not dom_path.exists():
            self.get(url, label=label)
        return dom_path if dom_path.exists() else None

    # ---------- summarize ----------

    def har_summary(self):
        return {
            "entries": len(self.har_entries),
            "har_path": str(self.har_dir / "session.har"),
            "screenshots": len(list(self.shot_dir.glob("*.png"))),
            "dom_files": len(list(self.dom_dir.glob("*.html"))),
        }


def _parse_qs(url):
    try:
        q = urllib.parse.urlparse(url).query
        if not q:
            return []
        return [{"name": k, "value": v} for k, v in urllib.parse.parse_qsl(q)]
    except Exception:
        return []


if __name__ == "__main__":
    import tempfile
    tmp = pathlib.Path(tempfile.mkdtemp())
    c = Collector(tmp)
    r = c.get("https://example.com", label="example_home")
    print("fetch:", r)
    shot = c.screenshot("https://example.com", label="example_home")
    print("screenshot:", shot)
    print("summary:", json.dumps(c.har_summary(), indent=2))
    print("files in evidence/:")
    for f in sorted(c.ev_dir.rglob("*")):
        if f.is_file():
            print(f"  {f.relative_to(c.ev_dir)}  ({f.stat().st_size} bytes)")
