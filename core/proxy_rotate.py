"""
core/proxy_rotate.py — direct-first-then-proxy routing with health scoring.

Flow:
  1. For any HTTP command, try DIRECT first (your real IP).
  2. If direct times out / refused / 403 on the target → mark host as
     "needs proxy" and pick a proxy from the pool.
  3. Proxy success → cached as best_proxy for that host.
  4. Subsequent commands to that host use the cached proxy until it fails.

Pool sources (in priority):
  A. AG_PROXY_ENDPOINTS env — comma-separated paid endpoints. If set, ONLY
     these are used. Format: scheme://[user:pass@]host:port
  B. Free lists — fetched on demand, validated in parallel, scored.
     Sources: monosans, TheSpeedX, clarketm, proxyscrape, openproxylist.
     Free proxies are unreliable (5-20% alive at any time). Rotate fast.

Per-target state: ~/scans/<target>/proxies.json
Global pool cache: ~/agent/.proxy_pool.json (shared across targets)
"""
import os
import re
import json
import time
import random
import pathlib
import threading
import concurrent.futures
from datetime import datetime, timedelta

import httpx

HERE = pathlib.Path(__file__).resolve().parent.parent
SCAN_ROOT = pathlib.Path(os.environ.get("AG_SCAN_ROOT",
                                        os.path.expanduser("~/scans")))
POOL_CACHE = HERE / ".proxy_pool.json"
POOL_TTL = 1800  # re-validate pool every 30 min

_LOCK = threading.Lock()

# free list URLs (raw)
_FREE_SOURCES = {
    "monosans-http":   "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "monosans-socks4": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "monosans-socks5": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "speedx-http":     "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "speedx-socks4":   "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "speedx-socks5":   "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "clarketm":        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "proxyscrape":     "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=elite",
}

_VALIDATE_URL = "https://api.ipify.org?format=json"
_VALIDATE_TIMEOUT = 6.0


def _safe(t):
    return "".join(c for c in t if c.isalnum() or c in "._-")


# ── custom endpoints from env ─────────────────────────────────────

def custom_endpoints():
    raw = os.environ.get("AG_PROXY_ENDPOINTS", "").strip()
    if not raw:
        return []
    return [e.strip() for e in raw.split(",") if e.strip()]


# ── free list fetch ───────────────────────────────────────────────

def _fetch_list(url, timeout=8):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as c:
            r = c.get(url)
            if r.status_code != 200:
                return []
            txt = r.text
    except Exception:
        return []
    out = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # formats: "1.2.3.4:80" or "socks5://1.2.3.4:1080" or "1.2.3.4"
        if "://" in line:
            out.append(line)
        elif re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
            scheme = "http"
            if "socks5" in url: scheme = "socks5"
            elif "socks4" in url: scheme = "socks4"
            out.append(f"{scheme}://{line}")
    return out


def fetch_free_pool(max_per_source=150):
    """Fetch from all free sources, dedupe. Returns list of URLs."""
    seen = set()
    all_urls = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(_fetch_list, u): name for name, u in _FREE_SOURCES.items()}
        for f in concurrent.futures.as_completed(futs):
            try:
                items = f.result()[:max_per_source]
            except Exception:
                continue
            for u in items:
                if u not in seen:
                    seen.add(u)
                    all_urls.append(u)
    random.shuffle(all_urls)
    return all_urls


# ── validation ────────────────────────────────────────────────────

def _validate_one(proxy_url):
    """Return (proxy_url, ok, latency_ms)."""
    t0 = time.time()
    try:
        with httpx.Client(timeout=_VALIDATE_TIMEOUT, follow_redirects=True,
                          proxy=proxy_url) as c:
            r = c.get(_VALIDATE_URL)
            if r.status_code == 200 and "ip" in (r.text or ""):
                lat = int((time.time() - t0) * 1000)
                return (proxy_url, True, lat)
    except Exception:
        pass
    return (proxy_url, False, 0)


def validate_pool(candidates, workers=80, keep=200):
    """Validate proxies in parallel. Return live ones sorted by latency."""
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_validate_one, p) for p in candidates[:400]]
        for f in concurrent.futures.as_completed(futs):
            try:
                url, ok, lat = f.result()
            except Exception:
                continue
            if ok:
                alive.append({"url": url, "latency": lat,
                              "ok": 1, "fail": 0,
                              "last_ok": datetime.utcnow().isoformat() + "Z"})
    alive.sort(key=lambda x: x["latency"])
    return alive[:keep]


# ── pool cache ────────────────────────────────────────────────────

def load_pool():
    if not POOL_CACHE.exists():
        return {"fetched_at": None, "proxies": []}
    try:
        return json.loads(POOL_CACHE.read_text())
    except Exception:
        return {"fetched_at": None, "proxies": []}


def save_pool(pool):
    try:
        POOL_CACHE.write_text(json.dumps(pool, indent=2))
    except Exception:
        pass


def _pool_fresh(pool):
    fa = pool.get("fetched_at")
    if not fa:
        return False
    try:
        t = datetime.fromisoformat(fa.replace("Z", "+00:00"))
        return (datetime.utcnow() - t.replace(tzinfo=None)) < timedelta(seconds=POOL_TTL)
    except Exception:
        return False


def refresh_pool(force=False):
    """Fetch + validate if stale (or forced). Returns pool dict."""
    pool = load_pool()
    if not force and _pool_fresh(pool) and pool.get("proxies"):
        return pool
    custom = custom_endpoints()
    if custom:
        proxies = [{"url": u, "latency": 0, "ok": 0, "fail": 0,
                    "last_ok": None, "source": "custom"} for u in custom]
    else:
        candidates = fetch_free_pool()
        proxies = validate_pool(candidates)
        for p in proxies:
            p["source"] = "free"
    pool = {
        "fetched_at": datetime.utcnow().isoformat() + "Z",
        "proxies": proxies,
        "count": len(proxies),
    }
    save_pool(pool)
    return pool


def pool_size():
    return len(load_pool().get("proxies") or [])


# ── per-target state ─────────────────────────────────────────────

def _state_path(target):
    return SCAN_ROOT / _safe(target) / "proxies.json"


def load_target(target):
    p = _state_path(target)
    if not p.exists():
        return {"target": target, "direct_ok": None, "direct_fail": 0,
                "needs_proxy": False, "best_proxy": None, "attempts": []}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"target": target, "direct_ok": None, "direct_fail": 0,
                "needs_proxy": False, "best_proxy": None, "attempts": []}


def save_target(target, st):
    p = _state_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(st, indent=2, default=str))
    except Exception:
        pass


# ── scoring ───────────────────────────────────────────────────────

def _score(p):
    base = p.get("ok", 0) - p.get("fail", 0) * 2
    lat = p.get("latency", 1000)
    if lat <= 0:
        lat = 1000
    return base * 1000 - lat


def pick_proxy(target, exclude=None):
    """Pick best proxy for target. Prefers proven ones, then fastest."""
    exclude = set(exclude or [])
    st = load_target(target)
    best = st.get("best_proxy")
    if best and best not in exclude:
        return best
    pool = load_pool()
    cands = [p for p in (pool.get("proxies") or [])
             if p.get("url") not in exclude]
    if not cands:
        return None
    cands.sort(key=_score, reverse=True)
    # top 10 with random tiebreak → avoids hammering the same exit IP
    top = cands[:10]
    return random.choice(top)["url"]


# ── record outcomes ──────────────────────────────────────────────

def mark_direct_fail(target, error=""):
    st = load_target(target)
    st["direct_fail"] = st.get("direct_fail", 0) + 1
    if st["direct_fail"] >= 2:
        st["needs_proxy"] = True
    st["direct_ok"] = False
    st["last_direct_error"] = error[:200]
    save_target(target, st)


def mark_direct_ok(target):
    st = load_target(target)
    st["direct_ok"] = True
    st["direct_fail"] = 0
    st["needs_proxy"] = False
    save_target(target, st)


def mark_proxy_ok(target, proxy_url, latency=0):
    st = load_target(target)
    st["best_proxy"] = proxy_url
    st["needs_proxy"] = True
    st.setdefault("attempts", []).append({
        "proxy": proxy_url, "ok": True,
        "ts": datetime.utcnow().isoformat() + "Z",
    })
    st["attempts"] = st["attempts"][-50:]
    save_target(target, st)
    # also bump pool score
    pool = load_pool()
    for p in pool.get("proxies") or []:
        if p["url"] == proxy_url:
            p["ok"] = p.get("ok", 0) + 1
            p["latency"] = latency or p.get("latency", 0)
            p["last_ok"] = datetime.utcnow().isoformat() + "Z"
            break
    save_pool(pool)


def mark_proxy_fail(target, proxy_url, error=""):
    st = load_target(target)
    if st.get("best_proxy") == proxy_url:
        st["best_proxy"] = None
    st.setdefault("attempts", []).append({
        "proxy": proxy_url, "ok": False, "error": error[:120],
        "ts": datetime.utcnow().isoformat() + "Z",
    })
    st["attempts"] = st["attempts"][-50:]
    save_target(target, st)
    pool = load_pool()
    for p in pool.get("proxies") or []:
        if p["url"] == proxy_url:
            p["fail"] = p.get("fail", 0) + 1
            break
    save_pool(pool)


# ── env wrapper ───────────────────────────────────────────────────

def env_for(target, force_proxy=False, exclude=None):
    """Return {ALL_PROXY, HTTP_PROXY, HTTPS_PROXY} dict or {} for direct.

    Rules:
      - if force_proxy → always use proxy
      - if target state says needs_proxy → use proxy
      - else → direct (empty dict)
    """
    st = load_target(target)
    if not force_proxy and not st.get("needs_proxy"):
        return {}
    proxy = pick_proxy(target, exclude=exclude)
    if not proxy:
        return {}
    return {
        "ALL_PROXY": proxy,
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "_proxy_used": proxy,
    }


def detect_proxy_failure(output):
    """Given shell output, return True if it looks like a proxy-needed failure."""
    if not output:
        return False
    s = output.lower()
    for sig in (
        "curl: (28)", "curl: (7)", "curl: (35)", "curl: (52)",
        "operation timed out", "connection refused",
        "connection reset by peer", "no route to host",
        "network is unreachable",
    ):
        if sig in s:
            return True
    return False


def status(target):
    st = load_target(target)
    pool = load_pool()
    return {
        "target": target,
        "direct_ok": st.get("direct_ok"),
        "direct_fail": st.get("direct_fail", 0),
        "needs_proxy": st.get("needs_proxy", False),
        "best_proxy": st.get("best_proxy"),
        "pool_size": pool.get("count", 0),
        "pool_fetched_at": pool.get("fetched_at"),
        "recent_attempts": st.get("attempts", [])[-5:],
    }
