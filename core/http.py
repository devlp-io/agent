"""
core.http — persistent async HTTP client. Cookie jar, keep-alive, HTTP/2.
Wraps httpx.AsyncClient. One instance per run, shared across turns.
Also exposes a sync wrapper for the legacy code path.
"""
import asyncio
import json as _json
import random
import time
from urllib.parse import urlencode

try:
    import httpx
    _HAVE_HTTPX = True
except Exception:
    _HAVE_HTTPX = False

BROWSER_PROFILES = [
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    },
    {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "upgrade-insecure-requests": "1",
    },
    {
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.80 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Chromium";v="123", "Not:A-Brand";v="8", "Google Chrome";v="123"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "upgrade-insecure-requests": "1",
    },
]


def get_random_browser_headers():
    return random.choice(BROWSER_PROFILES).copy()


DEFAULT_UA = BROWSER_PROFILES[0]["User-Agent"]
DEFAULT_TIMEOUT = 25.0
DEFAULT_HEADERS = BROWSER_PROFILES[0].copy()


class AsyncClient:
    def __init__(self, proxy=None, cookies=None, headers=None, timeout=DEFAULT_TIMEOUT):
        if not _HAVE_HTTPX:
            raise RuntimeError("httpx not installed — pip install --user httpx[http2]")
        self._proxy = proxy
        self._timeout = timeout
        h = get_random_browser_headers()
        if headers:
            h.update(headers)
        self._headers = h
        self._cookies = cookies or {}
        self._client = None
        self._lock = asyncio.Lock()

    async def _ensure(self):
        async with self._lock:
            if self._client is None:
                kwargs = {
                    "timeout": self._timeout,
                    "headers": self._headers,
                    "cookies": self._cookies,
                    "follow_redirects": True,
                    "http2": True,
                }
                if self._proxy:
                    kwargs["proxy"] = self._proxy
                self._client = httpx.AsyncClient(**kwargs)
            return self._client

    async def request(self, method, url, params=None, json=None, data=None,
                      headers=None, timeout=None, max_retries=2):
        c = await self._ensure()
        kw = {}
        if params: kw["params"] = params
        if json is not None: kw["json"] = json
        if data is not None: kw["data"] = data
        if headers: kw["headers"] = headers
        if timeout: kw["timeout"] = timeout
        t0 = time.time()
        for attempt in range(max_retries + 1):
            try:
                r = await c.request(method.upper(), url, **kw)
                if r.status_code in (429, 503) and attempt < max_retries:
                    delay = (1.5 ** attempt) + random.uniform(1.0, 3.0)
                    await asyncio.sleep(delay)
                    continue
                return {
                    "status": r.status_code,
                    "headers": dict(r.headers),
                    "body": r.text[:500000],
                    "size": len(r.content),
                    "ctype": r.headers.get("content-type", ""),
                    "url": str(r.url),
                    "elapsed": round(time.time() - t0, 3),
                }
            except Exception as e:
                if attempt < max_retries:
                    await asyncio.sleep(1.0 + random.uniform(0.2, 0.8))
                    continue
                return {
                    "status": 0,
                    "headers": {},
                    "body": f"ERR: {e}",
                    "size": 0,
                    "ctype": "",
                    "url": url,
                    "elapsed": round(time.time() - t0, 3),
                    "error": str(e),
                }

    async def get(self, url, **kw): return await self.request("GET", url, **kw)
    async def post(self, url, **kw): return await self.request("POST", url, **kw)
    async def put(self, url, **kw): return await self.request("PUT", url, **kw)
    async def delete(self, url, **kw): return await self.request("DELETE", url, **kw)

    def cookies_dict(self):
        if self._client:
            return {k: v for k, v in self._client.cookies.items()}
        return {}

    async def close(self):
        async with self._lock:
            if self._client:
                await self._client.aclose()
                self._client = None


# ---------- sync wrapper ----------

_GLOBAL_ASYNC = None


def get_async(proxy=None, cookies=None, headers=None):
    global _GLOBAL_ASYNC
    if _GLOBAL_ASYNC is None:
        _GLOBAL_ASYNC = AsyncClient(proxy=proxy, cookies=cookies, headers=headers)
    return _GLOBAL_ASYNC


def request_sync(method, url, params=None, json=None, data=None,
                 headers=None, timeout=None, proxy=None, max_retries=2):
    """Sync one-shot using httpx.Client with adaptive retry backoff."""
    if not _HAVE_HTTPX:
        return {"status": 0, "body": "httpx not installed", "size": 0,
                "ctype": "", "url": url, "elapsed": 0}
    h = get_random_browser_headers()
    if headers: h.update(headers)
    kw = {"timeout": timeout or DEFAULT_TIMEOUT, "headers": h,
          "follow_redirects": True, "http2": True}
    if proxy: kw["proxy"] = proxy
    t0 = time.time()
    for attempt in range(max_retries + 1):
        try:
            with httpx.Client(**kw) as c:
                r = c.request(method.upper(), url, params=params, json=json, data=data)
                if r.status_code in (429, 503) and attempt < max_retries:
                    delay = (1.5 ** attempt) + random.uniform(1.0, 3.0)
                    time.sleep(delay)
                    continue
                return {
                    "status": r.status_code,
                    "headers": dict(r.headers),
                    "body": r.text[:500000],
                    "size": len(r.content),
                    "ctype": r.headers.get("content-type", ""),
                    "url": str(r.url),
                    "elapsed": round(time.time() - t0, 3),
                }
        except Exception as e:
            if attempt < max_retries:
                time.sleep(1.0 + random.uniform(0.2, 0.8))
                continue
            return {"status": 0, "headers": {}, "body": f"ERR: {e}", "size": 0,
                    "ctype": "", "url": url, "elapsed": round(time.time() - t0, 3),
                    "error": str(e)}
