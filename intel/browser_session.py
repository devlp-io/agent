"""
intel/browser_session.py — persistent headless browser session.

When a target sits behind an anti-bot JS challenge (Cloudflare Turnstile,
"One moment please" gates, custom wsidchk, etc), curl can't get through.
This module:

  1. Launch a persistent chromium context for the target (once).
  2. Navigate. Wait for the challenge to resolve (title/URL heuristic).
  3. Export cookies to a Netscape jar that auth_ctx can read.
  4. Return a representative HTML + headers snapshot so the agent can
     continue with the existing HTTP tools.

The browser stays alive between calls, so a second path pays no challenge.

API:
  solve(target, url) -> dict with {ok, cookies, html, title, url_final, jar}
  is_gate(html_or_title) -> bool — detects the common anti-bot pages
  cookies_for_curl(target) -> str — Cookie: header value
"""
import os
import re
import json
import time
import pathlib
import asyncio
import threading

SCAN_ROOT = pathlib.Path(os.environ.get("AG_SCAN_ROOT",
                                        os.path.expanduser("~/scans")))

_playwright_ready = None
_sessions = {}  # target -> {"ctx": BrowserContext, "page": Page, "loop": Loop}
_lock = threading.Lock()


def _jar_path(target):
    safe = "".join(c for c in target if c.isalnum() or c in "._-")
    p = SCAN_ROOT / safe
    p.mkdir(parents=True, exist_ok=True)
    return p / ".cookiejar"


def _have_playwright():
    global _playwright_ready
    if _playwright_ready is None:
        try:
            import playwright  # noqa
            _playwright_ready = True
        except Exception:
            _playwright_ready = False
    return _playwright_ready


_GATE_SIGNATURES = [
    re.compile(r"one moment,?\s*please", re.I),
    re.compile(r"checking your browser", re.I),
    re.compile(r"just a moment", re.I),
    re.compile(r"__cf_chl", re.I),
    re.compile(r"cf-chl-", re.I),
    re.compile(r"attention required", re.I),
    re.compile(r"wsidchk", re.I),
    re.compile(r"please wait.*challenge", re.I),
    re.compile(r"<title>\s*(verifying|please wait|checking)", re.I),
]


def is_gate(html_or_title):
    t = (html_or_title or "")[:5000]
    return any(p.search(t) for p in _GATE_SIGNATURES)


# ── async core (runs in its own loop per target) ─────────────────────

async def _launch_and_solve(target, url, wait_ms=15000):
    from playwright.async_api import async_playwright
    p = await async_playwright().start()
    browser = await p.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-blink-features=AutomationControlled"],
    )
    ctx = await browser.new_context(
        user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"),
        viewport={"width": 1366, "height": 768},
        locale="en-US",
    )
    page = await ctx.new_page()
    reqs = []
    page.on("request", lambda r: reqs.append((r.method, r.url)))

    resp = await page.goto(url, wait_until="domcontentloaded", timeout=45000)
    status = resp.status if resp else 0

    # wait for title to change from a gate signature
    resolved = False
    deadline = time.time() + (wait_ms / 1000.0)
    while time.time() < deadline:
        try:
            title = await page.title()
        except Exception:
            title = ""
        if not is_gate(title):
            resolved = True
            break
        await page.wait_for_timeout(500)

    html = ""
    try:
        html = await page.content()
    except Exception:
        pass
    title = ""
    try:
        title = await page.title()
    except Exception:
        pass
    url_final = page.url

    # dump cookies
    cookies = []
    try:
        cookies = await ctx.cookies()
    except Exception:
        pass

    # write Netscape jar (auth_ctx reads this)
    jar_lines = ["# Netscape HTTP Cookie File"]
    cookie_header_parts = []
    for c in cookies:
        d = c.get("domain", "")
        dom = d if d.startswith(".") else "." + d
        jar_lines.append("\t".join([
            dom, "TRUE",
            c.get("path", "/"),
            "TRUE" if c.get("secure") else "FALSE",
            str(int(c.get("expires") or 0)),
            c.get("name", ""),
            c.get("value", ""),
        ]))
        cookie_header_parts.append(f"{c.get('name')}={c.get('value')}")

    jar = _jar_path(target)
    try:
        jar.write_text("\n".join(jar_lines) + "\n")
    except Exception:
        pass

    return {
        "ok": resolved,
        "status": status,
        "title": title,
        "url_final": url_final,
        "cookie_count": len(cookies),
        "cookie_header": "; ".join(cookie_header_parts),
        "jar": str(jar),
        "html": html,
        "requests": reqs[-40:],
        "browser": browser,
        "context": ctx,
        "page": page,
        "playwright": p,
    }


# ── sync public API ──────────────────────────────────────────────────

def _ensure_loop(target):
    """Each target gets its own persistent loop + browser session."""
    if target in _sessions:
        return _sessions[target]
    return None


def solve(target, url=None, wait_ms=15000, keep_alive=True):
    """Solve the challenge for `url` (or root of target). Returns dict.
    If keep_alive, the browser stays open — call clear(target) to close."""
    if not _have_playwright():
        return {"ok": False, "error": "playwright not installed"}

    url = url or f"https://{target}/"
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_launch_and_solve(target, url, wait_ms))

        if keep_alive:
            with _lock:
                _sessions[target] = {"result": result, "loop": loop}
        else:
            # close
            try:
                loop.run_until_complete(result["browser"].close())
                loop.run_until_complete(result["playwright"].stop())
            except Exception:
                pass
            loop.close()

        # strip non-serializable objects
        return {k: v for k, v in result.items()
                if k not in ("browser", "context", "page", "playwright")}
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}


def cookies_for_curl(target):
    """Return 'Cookie: name=value; name2=v2' string, or '' if none."""
    sess = _ensure_loop(target)
    if not sess:
        return ""
    return sess["result"].get("cookie_header", "")


def html_for(target):
    sess = _ensure_loop(target)
    if not sess:
        return ""
    return sess["result"].get("html", "")


def fetch_url(target, url, wait_ms=8000):
    """Navigate the existing session to another URL under the same host.
    Returns {ok, status, html, title}."""
    if not _have_playwright():
        return {"ok": False, "error": "playwright not installed"}
    sess = _ensure_loop(target)
    if not sess:
        return {"ok": False, "error": "no session — call solve() first"}

    async def _go():
        page = sess["result"]["page"]
        try:
            r = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(wait_ms // 2)
            title = ""
            try:
                title = await page.title()
            except Exception:
                pass
            # refresh cookies each nav
            try:
                cookies = await sess["result"]["context"].cookies()
                parts = [f"{c.get('name')}={c.get('value')}" for c in cookies]
                sess["result"]["cookie_header"] = "; ".join(parts)
                sess["result"]["cookie_count"] = len(cookies)
            except Exception:
                pass
            html = ""
            try:
                html = await page.content()
            except Exception:
                pass
            return {
                "ok": True,
                "status": r.status if r else 0,
                "title": title,
                "html": html,
                "url_final": page.url,
                "cookie_header": sess["result"].get("cookie_header", ""),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)[:300]}

    try:
        return sess["loop"].run_until_complete(_go())
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}


def clear(target):
    sess = _ensure_loop(target)
    if not sess:
        return {"cleared": False}
    try:
        sess["loop"].run_until_complete(sess["result"]["browser"].close())
        sess["loop"].run_until_complete(sess["result"]["playwright"].stop())
        sess["loop"].close()
    except Exception:
        pass
    with _lock:
        _sessions.pop(target, None)
    return {"cleared": True}


def status(target):
    sess = _ensure_loop(target)
    if not sess:
        return {"target": target, "active": False}
    r = sess["result"]
    return {
        "target": target,
        "active": True,
        "title": r.get("title"),
        "url_final": r.get("url_final"),
        "cookie_count": r.get("cookie_count"),
        "jar": r.get("jar"),
    }
