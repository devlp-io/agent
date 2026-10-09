"""
core.http — persistent async HTTP client. Cookie jar, keep-alive, HTTP/2.
Wraps httpx.AsyncClient. One instance per run, shared across turns.
Also exposes a sync wrapper for the legacy code path.
"""
import asyncio
import json as _json
import time
from urllib.parse import urlencode

try:
    import httpx
    _HAVE_HTTPX = True
except Exception:
    _HAVE_HTTPX = False

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"
DEFAULT_TIMEOUT = 25.0
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_UA,
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


class AsyncClient:
    def __init__(self, proxy=None, cookies=None, headers=None, timeout=DEFAULT_TIMEOUT):
        if not _HAVE_HTTPX:
            raise RuntimeError("httpx not installed — pip install --user httpx[http2]")
        self._proxy = proxy
        self._timeout = timeout
        h = dict(DEFAULT_HEADERS)
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
                      headers=None, timeout=None):
        c = await self._ensure()
        kw = {}
        if params: kw["params"] = params
        if json is not None: kw["json"] = json
        if data is not None: kw["data"] = data
        if headers: kw["headers"] = headers
        if timeout: kw["timeout"] = timeout
        t0 = time.time()
        try:
            r = await c.request(method.upper(), url, **kw)
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
                 headers=None, timeout=None, proxy=None):
    """Sync one-shot using httpx.Client. No persistence."""
    if not _HAVE_HTTPX:
        return {"status": 0, "body": "httpx not installed", "size": 0,
                "ctype": "", "url": url, "elapsed": 0}
    h = dict(DEFAULT_HEADERS)
    if headers: h.update(headers)
    kw = {"timeout": timeout or DEFAULT_TIMEOUT, "headers": h,
          "follow_redirects": True}
    if proxy: kw["proxy"] = proxy
    t0 = time.time()
    try:
        with httpx.Client(**kw) as c:
            r = c.request(method.upper(), url, params=params, json=json, data=data)
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
        return {"status": 0, "headers": {}, "body": f"ERR: {e}", "size": 0,
                "ctype": "", "url": url, "elapsed": round(time.time() - t0, 3),
                "error": str(e)}
