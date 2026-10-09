"""
core.browser — chromium headless wrapper via subprocess.
No pip dep, no playwright. Uses system chromium if present.
Gate: AG_BROWSER=1 AND chromium on PATH, else clean no-op.
"""
import os
import re
import json
import time
import shutil
import pathlib
import subprocess
import tempfile


def have_chromium():
    for name in ("chromium", "chromium-browser", "chrome", "google-chrome", "headless_shell"):
        p = shutil.which(name)
        if p:
            return p
    return None


def enabled():
    return os.environ.get("AG_BROWSER", "0") == "1" and have_chromium() is not None


def _run(args, timeout=45):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr[:2000]}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "out": "", "err": "timeout"}
    except Exception as e:
        return {"rc": -1, "out": "", "err": str(e)}


def render(url, out_html=None, timeout=30, wait_ms=3000, extra_args=None):
    """
    Render a URL with headless chromium; return final DOM HTML.
    Saves to out_html if given.
    """
    chrom = have_chromium()
    if not chrom:
        return {"error": "chromium not installed (pkg install chromium)"}
    if os.environ.get("AG_BROWSER", "0") != "1":
        return {"error": "browser disabled — set AG_BROWSER=1"}

    with tempfile.TemporaryDirectory() as tmp:
        prof = os.path.join(tmp, "prof")
        args = [
            chrom,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--user-data-dir={prof}",
            "--hide-scrollbars",
            "--virtual-time-budget={}".format(wait_ms),
            "--dump-dom",
            url,
        ]
        if extra_args:
            args[1:1] = extra_args
        r = _run(args, timeout=timeout)
        html = r.get("out") or ""
        if out_html and html:
            try:
                pathlib.Path(out_html).write_text(html)
            except Exception:
                pass
        return {
            "rc": r["rc"],
            "size": len(html),
            "html": html[:500000],
            "err": r.get("err", "")[:500],
        }


def screenshot(url, out_png, width=1280, height=800, timeout=30, wait_ms=4000):
    chrom = have_chromium()
    if not chrom:
        return {"error": "chromium not installed"}
    if os.environ.get("AG_BROWSER", "0") != "1":
        return {"error": "browser disabled — set AG_BROWSER=1"}
    out_png = str(out_png)
    pathlib.Path(out_png).parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        prof = os.path.join(tmp, "prof")
        args = [
            chrom,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--user-data-dir={prof}",
            "--hide-scrollbars",
            f"--window-size={width},{height}",
            "--virtual-time-budget={}".format(wait_ms),
            f"--screenshot={out_png}",
            url,
        ]
        r = _run(args, timeout=timeout)
        exists = pathlib.Path(out_png).exists()
        return {"rc": r["rc"], "png": out_png if exists else None,
                "size": pathlib.Path(out_png).stat().st_size if exists else 0,
                "err": r.get("err", "")[:500]}


def sniff_xhr(url, wait_ms=5000, timeout=30):
    """
    Load a URL and dump any XHR/fetch URLs discovered from the JS.
    Uses --log-net-log to capture network events.
    """
    chrom = have_chromium()
    if not chrom:
        return {"error": "chromium not installed"}
    if os.environ.get("AG_BROWSER", "0") != "1":
        return {"error": "browser disabled — set AG_BROWSER=1"}
    with tempfile.TemporaryDirectory() as tmp:
        netlog = os.path.join(tmp, "netlog.json")
        prof = os.path.join(tmp, "prof")
        args = [
            chrom,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            f"--user-data-dir={prof}",
            f"--log-net-log={netlog}",
            "--net-log-capture-mode=IncludeSensitive",
            "--virtual-time-budget={}".format(wait_ms),
            "--dump-dom",
            url,
        ]
        _run(args, timeout=timeout)
        urls = []
        if os.path.exists(netlog):
            try:
                blob = pathlib.Path(netlog).read_text(errors="ignore")
                for m in re.finditer(r'"url":"(https?://[^"]+)"', blob):
                    u = m.group(1)
                    if u not in urls and u != url:
                        urls.append(u)
            except Exception:
                pass
        return {"xhr_urls": urls[:200], "count": len(urls)}


def status():
    return {
        "chromium_path": have_chromium(),
        "enabled_env": os.environ.get("AG_BROWSER", "0"),
        "ready": enabled(),
    }


if __name__ == "__main__":
    import sys
    print(json.dumps(status(), indent=2))
    if len(sys.argv) > 1 and enabled():
        r = render(sys.argv[1], wait_ms=3000)
        print("render rc:", r.get("rc"), "size:", r.get("size"))
