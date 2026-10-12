"""
core/proxy_rotate.py v2 — validate-before-use + background health + retry.

Key changes over v1:
  - every proxy is validated within the last _FRESH_SECS (default 60s)
    before being handed to _run_shell. Stale? validate now.
  - pool evicts proxies whose fail count crosses FAIL_EVICT (default 2)
  - background daemon re-validates the pool every _WATCHDOG_SECS (300s)
    without blocking the scan
  - env_for() returns the FIRST live proxy it finds, not just the top-score
    proxy. Dead ones are marked and skipped.
  - pick_valid_proxy() walks top candidates, validating each, and returns
    a proven-live one or None.
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
POOL_TTL = 300               # pool considered stale after 5 min
_FRESH_SECS = 60             # a proxy is "fresh" if validated < 60s ago
FAIL_EVICT = 2               # evict after 2 consecutive failures
_WATCHDOG_SECS = 300         # background revalidation interval
_VALIDATE_URL = "https://api.ipify.org?format=json"
_VALIDATE_TIMEOUT = 5.0
_LOCK = threading.Lock()
_watchdog_started = False

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


def _safe(t):
    return "".join(c for c in t if c.isalnum() or c in "._-")


def _now_iso():
    return datetime.utcnow().isoformat() + "Z"


def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _age_secs(iso_str):
    t = _parse_iso(iso_str)
    if not t:
        return 10**9
    return (datetime.utcnow() - t).total_seconds()


# ── env ───────────────────────────────────────────────────────────

def custom_endpoints():
    raw = os.environ.get("AG_PROXY_ENDPOINTS", "").strip()
    if not raw:
        return []
    return [e.strip() for e in raw.split(",") if e.strip()]


# ── fetch free lists ──────────────────────────────────────────────

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
        if "://" in line:
            out.append(line)
        elif re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
            scheme = "http"
            if "socks5" in url: scheme = "socks5"
            elif "socks4" in url: scheme = "socks4"
            out.append(f"{scheme}://{line}")
    return out


def fetch_free_pool(max_per_source=150):
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

def _validate_one(proxy_url, timeout=_VALIDATE_TIMEOUT):
    t0 = time.time()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True,
                          proxy=proxy_url) as c:
            r = c.get(_VALIDATE_URL)
            if r.status_code == 200 and "ip" in (r.text or ""):
                return (proxy_url, True, int((time.time() - t0) * 1000))
    except Exception:
        pass
    return (proxy_url, False, 0)


def is_alive(proxy_url, max_age=_FRESH_SECS):
    """True if this proxy was validated recently. Validates now if stale."""
    pool = load_pool()
    for p in pool.get("proxies") or []:
        if p.get("url") == proxy_url:
            if _age_secs(p.get("last_validated")) < max_age:
                return True
            url, ok, lat = _validate_one(proxy_url)
            if ok:
                p["last_validated"] = _now_iso()
                p["latency"] = lat
                p["fail"] = 0
                save_pool(pool)
                return True
            else:
                p["fail"] = p.get("fail", 0) + 1
                p["last_validated"] = _now_iso()
                save_pool(pool)
                print(f"[PROXY-FAIL] {proxy_url} revalidation-failed (fail={p['fail']})")
                return False
    return False


def validate_many(proxies, workers=40, timeout=_VALIDATE_TIMEOUT):
    """Validate a list of proxies in parallel. Return live ones."""
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_validate_one, p, timeout) for p in proxies]
        for f in concurrent.futures.as_completed(futs):
            try:
                url, ok, lat = f.result()
            except Exception:
                continue
            if ok:
                out.append({"url": url, "latency": lat,
                            "ok": 1, "fail": 0,
                            "last_validated": _now_iso(),
                            "last_ok": _now_iso()})
    out.sort(key=lambda x: x["latency"])
    return out


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
    return _age_secs(pool.get("fetched_at")) < POOL_TTL


def refresh_pool(force=False, workers=80, keep=200):
    pool = load_pool()
    if not force and _pool_fresh(pool) and pool.get("proxies"):
        return pool

    custom = custom_endpoints()
    if custom:
        proxies = validate_many(custom, workers=min(workers, len(custom)))
        if not proxies:
            # every custom endpoint failed validation — do NOT add them
            # untested. honeypot proxies eat turns.
            for u in custom:
                print(f"[PROXY-FAIL] {u} custom-endpoint-validation-failed")
            proxies = []
    else:
        candidates = fetch_free_pool()
        proxies = validate_many(candidates, workers=workers)
        for p in proxies:
            p["source"] = "free"

    # preserve known-good proxies from old pool that weren't re-validated
    old_urls = {p["url"] for p in proxies}
    for op in pool.get("proxies") or []:
        if op["url"] in old_urls:
            continue
        if _age_secs(op.get("last_validated")) < 300 and op.get("fail", 0) < FAIL_EVICT:
            proxies.append(op)

    pool = {
        "fetched_at": _now_iso(),
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
    base = p.get("ok", 0) - p.get("fail", 0) * 3
    lat = p.get("latency", 1000) or 1000
    fresh_bonus = 500 if _age_secs(p.get("last_validated")) < _FRESH_SECS else 0
    return base * 1000 - lat + fresh_bonus


# ── pick a proven-live proxy ─────────────────────────────────────

def pick_valid_proxy(target, exclude=None, max_candidates=8):
    """Walk top-scored candidates, validate each, return first proven-live.
    Marks dead ones immediately. Returns None if none survive."""
    exclude = set(exclude or [])
    st = load_target(target)
    best = st.get("best_proxy")
    if best and best not in exclude and is_alive(best):
        return best
    pool = load_pool()
    cands = [p for p in (pool.get("proxies") or [])
             if p.get("url") not in exclude]
    if not cands:
        return None
    cands.sort(key=_score, reverse=True)
    for p in cands[:max_candidates]:
        if is_alive(p["url"], max_age=_FRESH_SECS):
            return p["url"]
    # nothing fresh — try refreshing the pool once, then retry
    refresh_pool(force=True)
    pool = load_pool()
    cands = [p for p in (pool.get("proxies") or [])
             if p.get("url") not in exclude]
    if not cands:
        return None
    cands.sort(key=_score, reverse=True)
    for p in cands[:max_candidates]:
        if is_alive(p["url"], max_age=_FRESH_SECS):
            return p["url"]
    return None


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
    print(f"[PROXY-OK] {proxy_url} latency={latency}ms")
    st = load_target(target)
    st["best_proxy"] = proxy_url
    st["needs_proxy"] = True
    st.setdefault("attempts", []).append({
        "proxy": proxy_url, "ok": True, "ts": _now_iso(),
    })
    st["attempts"] = st["attempts"][-50:]
    save_target(target, st)
    pool = load_pool()
    for p in pool.get("proxies") or []:
        if p["url"] == proxy_url:
            p["ok"] = p.get("ok", 0) + 1
            p["fail"] = 0
            p["latency"] = latency or p.get("latency", 0)
            p["last_ok"] = _now_iso()
            p["last_validated"] = _now_iso()
            break
    save_pool(pool)


def mark_proxy_fail(target, proxy_url, error=""):
    print(f"[PROXY-FAIL] {proxy_url} {error or 'unknown'}")
    st = load_target(target)
    if st.get("best_proxy") == proxy_url:
        st["best_proxy"] = None
    st.setdefault("attempts", []).append({
        "proxy": proxy_url, "ok": False, "error": error[:120],
        "ts": _now_iso(),
    })
    st["attempts"] = st["attempts"][-50:]
    save_target(target, st)
    pool = load_pool()
    for p in pool.get("proxies") or []:
        if p["url"] == proxy_url:
            p["fail"] = p.get("fail", 0) + 1
            p["last_validated"] = _now_iso()
            break
    # evict high-fail proxies
    pool["proxies"] = [p for p in (pool.get("proxies") or [])
                       if p.get("fail", 0) < FAIL_EVICT]
    pool["count"] = len(pool["proxies"])
    save_pool(pool)


# ── env wrapper ───────────────────────────────────────────────────

def env_for(target, force_proxy=False, exclude=None):
    st = load_target(target)
    if not force_proxy and not st.get("needs_proxy"):
        return {}
    proxy = pick_valid_proxy(target, exclude=exclude)
    if not proxy:
        # last resort — pool empty/dead. Try one refresh.
        try:
            refresh_pool(force=True)
            proxy = pick_valid_proxy(target, exclude=exclude)
        except Exception:
            proxy = None
    if not proxy:
        return {}
    return {
        "ALL_PROXY": proxy,
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "_proxy_used": proxy,
    }


def detect_proxy_failure(output):
    if not output:
        return False
    s = output.lower()
    for sig in (
        "curl: (28)", "curl: (7)", "curl: (35)", "curl: (52)", "curl: (56)",
        "operation timed out", "connection refused",
        "connection reset by peer", "no route to host",
        "network is unreachable", "proxy", "tunnel connection failed",
    ):
        if sig in s:
            return True
    return False


# ── background watchdog ──────────────────────────────────────────

def _watchdog_loop(interval):
    while True:
        time.sleep(interval)
        try:
            pool = load_pool()
            urls = [p["url"] for p in (pool.get("proxies") or []) if p.get("url")]
            if not urls:
                refresh_pool(force=True)
                continue
            # sample up to 40 to revalidate
            sample = random.sample(urls, min(40, len(urls)))
            results = validate_many(sample, workers=20)
            live = {r["url"] for r in results}
            # update pool in place
            updated = []
            for p in pool.get("proxies") or []:
                if p["url"] in live:
                    for r in results:
                        if r["url"] == p["url"]:
                            p["latency"] = r["latency"]
                            p["last_validated"] = r["last_validated"]
                            p["fail"] = 0
                            break
                    updated.append(p)
                elif _age_secs(p.get("last_validated")) < 240:
                    # give recently-live proxies a pass even if sample missed them
                    updated.append(p)
                # else: drop it — likely dead
            pool["proxies"] = updated
            pool["count"] = len(updated)
            save_pool(pool)
            if len(updated) < 5:
                refresh_pool(force=True)
        except Exception:
            pass


def start_watchdog(interval=_WATCHDOG_SECS):
    global _watchdog_started
    if _watchdog_started:
        return
    _watchdog_started = True
    t = threading.Thread(target=_watchdog_loop, args=(interval,), daemon=True)
    t.start()


def status(target):
    st = load_target(target)
    pool = load_pool()
    fresh = sum(1 for p in (pool.get("proxies") or [])
                if _age_secs(p.get("last_validated")) < _FRESH_SECS)
    return {
        "target": target,
        "direct_ok": st.get("direct_ok"),
        "direct_fail": st.get("direct_fail", 0),
        "needs_proxy": st.get("needs_proxy", False),
        "best_proxy": st.get("best_proxy"),
        "pool_size": pool.get("count", 0),
        "pool_fresh": fresh,
        "pool_fetched_at": pool.get("fetched_at"),
        "watchdog": _watchdog_started,
        "recent_attempts": st.get("attempts", [])[-5:],
    }
