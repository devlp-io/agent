"""
core/auth_ctx.py — per-target authentication context.

Stores cookies, bearer tokens, and basic-auth creds for a target. Every
subsequent shell command whose URL matches the target scope gets them
injected automatically — no need to hand-craft -b/-H on every curl.

Shape (auth.json next to state.json):

  {
    target,
    mode:      "cookie" | "bearer" | "basic" | "none",
    cookie_jar: "/path/to/.cookiejar"    # netscape format
    headers:    {"Authorization": "Bearer ...", "Cookie": "..."},
    login_url:  "...",
    ok:         bool,
    set_at:     ISO8601,
    sample:     "first 200 chars of login response"
  }
"""
import os
import re
import json
import pathlib
import threading
from datetime import datetime
from urllib.parse import urlparse

SCAN_ROOT = pathlib.Path(os.environ.get("AG_SCAN_ROOT",
                                        os.path.expanduser("~/scans")))
_LOCK = threading.Lock()


def _safe(t):
    return "".join(c for c in t if c.isalnum() or c in "._-")


def _path(t):
    return SCAN_ROOT / _safe(t) / "auth.json"


def _jar_path(t):
    return SCAN_ROOT / _safe(t) / ".cookiejar"


def read(t):
    p = _path(t)
    if not p.exists():
        return {"target": t, "mode": "none", "headers": {}, "ok": False}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"target": t, "mode": "none", "headers": {}, "ok": False}


def save(t, ctx):
    p = _path(t)
    p.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        p.write_text(json.dumps(ctx, indent=2, default=str))


def set_cookie(t, cookie_string):
    """Manually set a Cookie header."""
    ctx = read(t)
    ctx["mode"] = "cookie"
    ctx["headers"] = {"Cookie": cookie_string}
    ctx["ok"] = True
    ctx["set_at"] = datetime.utcnow().isoformat() + "Z"
    save(t, ctx)
    return ctx


def set_bearer(t, token):
    ctx = read(t)
    ctx["mode"] = "bearer"
    ctx["headers"] = {"Authorization": "Bearer " + token}
    ctx["ok"] = True
    ctx["set_at"] = datetime.utcnow().isoformat() + "Z"
    save(t, ctx)
    return ctx


def set_basic(t, userpass):
    import base64
    b = base64.b64encode(userpass.encode()).decode()
    ctx = read(t)
    ctx["mode"] = "basic"
    ctx["headers"] = {"Authorization": "Basic " + b}
    ctx["ok"] = True
    ctx["set_at"] = datetime.utcnow().isoformat() + "Z"
    save(t, ctx)
    return ctx


def set_login(t, login_url, email, password, method="POST", json_body=True,
              extra_headers=None, cookie_name_hint=None):
    """Perform a login request with the harness HTTP client, capture the
    response Set-Cookie into a Netscape cookiejar, and persist it."""
    from core import http as _chttp
    jar = _jjar(t)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (ag)",
    }
    if extra_headers:
        headers.update(extra_headers)
    body = None
    if json_body:
        body = json.dumps({"email": email, "password": password})
    else:
        body = f"email={email}&password={password}"
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        r = _chttp.request_sync(method.upper(), login_url,
                                 headers=headers, data=body, timeout=20)
    except Exception as e:
        return {"ok": False, "error": str(e)}

    set_cookie_header = ""
    try:
        rh = r.get("headers", {}) or {}
        sc = rh.get("set-cookie") or rh.get("Set-Cookie") or ""
        if isinstance(sc, list):
            sc = "; ".join(sc)
        set_cookie_header = sc
    except Exception:
        pass

    if not set_cookie_header:
        # some clients store them elsewhere; check body for a token
        body_text = (r.get("body") or "")[:500]
        ctx = {
            "target": t, "mode": "none", "ok": False,
            "login_url": login_url,
            "set_at": datetime.utcnow().isoformat() + "Z",
            "sample": body_text,
            "error": "no Set-Cookie header — try the login manually and use "
                     "AUTH: cookie|<name>=<value>",
        }
        save(t, ctx)
        return ctx

    # write Netscape-format cookiejar for curl -b
    host = urlparse(login_url).hostname or ""
    lines = ["# Netscape HTTP Cookie File"]
    pairs = []
    for pair in set_cookie_header.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        name, _, value = pair.partition("=")
        name = name.strip()
        value = value.strip()
        if not name or name.lower() in ("path", "domain", "expires",
                                        "max-age", "secure", "httponly",
                                        "samesite"):
            continue
        pairs.append(f"{name}={value}")
        lines.append("\t".join([
            host if host.startswith(".") else "." + host,
            "TRUE", "/", "FALSE", "0", name, value,
        ]))
    try:
        jar.write_text("\n".join(lines) + "\n")
    except Exception:
        pass

    cookie_header = "; ".join(pairs)
    ctx = {
        "target": t, "mode": "cookie",
        "cookie_jar": str(jar),
        "headers": {"Cookie": cookie_header},
        "login_url": login_url,
        "ok": True,
        "set_at": datetime.utcnow().isoformat() + "Z",
        "sample": (r.get("body") or "")[:300],
    }
    save(t, ctx)
    return ctx


def clear(t):
    ctx = {"target": t, "mode": "none", "headers": {}, "ok": False}
    save(t, ctx)
    return ctx


def _jjar(t):
    return _jar_path(t)


# ── shell injection ────────────────────────────────────────────────

_TARGET_RE = None


def _scope_contains(url, target):
    """True if url's host is target or a subdomain of target."""
    if not target:
        return False
    try:
        h = urlparse(url).hostname or ""
    except Exception:
        return False
    h = h.lower()
    t = target.lower()
    return h == t or h.endswith("." + t)


_CMD_URL_RE = re.compile(r"https?://[^\s'\"<>|;)]+")


def inject_curl(cmd, target):
    """If cmd contains curl hitting target scope, inject auth headers.
    Does nothing if the command already has -b, -H 'Cookie', or
    -H 'Authorization'."""
    ctx = read(target)
    if not ctx.get("ok"):
        return cmd
    urls = _CMD_URL_RE.findall(cmd)
    if not urls:
        return cmd
    if not any(_scope_contains(u, target) for u in urls):
        return cmd
    # already injected?
    if re.search(r"\bcurl\b.*(-b\s+\S|--cookie\s+\S|-H\s+['\"]Cookie)", cmd):
        return cmd
    if re.search(r"\bcurl\b.*-H\s+['\"]Authorization", cmd):
        return cmd

    # build injection string
    cookie_jar = ctx.get("cookie_jar")
    headers = ctx.get("headers") or {}
    inject = ""
    if cookie_jar and os.path.exists(cookie_jar):
        inject = f" -b '{cookie_jar}'"
    elif "Cookie" in headers:
        inject = f" -H 'Cookie: {headers['Cookie']}'"
    if "Authorization" in headers:
        inject += f" -H 'Authorization: {headers['Authorization']}'"
    if not inject:
        return cmd

    # insert right after the first 'curl' token
    return re.sub(r"(\bcurl\b)", r"\1" + inject, cmd, count=1)


def status(t):
    ctx = read(t)
    return {
        "target": t,
        "mode": ctx.get("mode", "none"),
        "ok": ctx.get("ok", False),
        "set_at": ctx.get("set_at"),
        "login_url": ctx.get("login_url"),
    }
