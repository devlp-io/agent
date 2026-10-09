"""
core.async_engine — asyncio concurrent request driver.
- 429-aware auto-throttle (backs off on rate-limit, ramps back up)
- worker pool with dynamic concurrency
- progress callback
- stop-on-success, stop-on-budget
"""
import asyncio
import time
import json
import pathlib

try:
    import aiohttp
    _HAVE_AIOHTTP = True
except Exception:
    _HAVE_AIOHTTP = False

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"


class Engine:
    def __init__(self, concurrency=40, timeout=15.0, proxy_pool=None,
                 headers=None, progress_cb=None, run_dir=None):
        if not _HAVE_AIOHTTP:
            raise RuntimeError("aiohttp not installed")
        self.concurrency = concurrency
        self.base_concurrency = concurrency
        self.timeout = timeout
        self.proxy_pool = proxy_pool
        self.headers = {"User-Agent": DEFAULT_UA}
        if headers:
            self.headers.update(headers)
        self.progress_cb = progress_cb
        self.run_dir = run_dir
        self._session = None
        self._sem = None
        self._stops = {"success": False, "user": False}
        self._stats = {
            "sent": 0, "ok": 0, "err": 0, "429": 0,
            "start": 0.0, "current_concurrency": concurrency,
        }
        self._lock = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.concurrency * 2,
            limit_per_host=self.concurrency,
            ttl_dns_cache=300,
            ssl=False,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=self.headers,
            trust_env=True,
        )
        self._sem = asyncio.Semaphore(self.concurrency)
        self._lock = asyncio.Lock()
        self._stats["start"] = time.time()
        return self

    async def __aexit__(self, *a):
        if self._session:
            await self._session.close()

    def stop(self, reason="user"):
        if reason in self._stops:
            self._stops[reason] = True

    def stopped(self):
        return self._stops["success"] or self._stops["user"]

    def _pick_proxy(self):
        if self.proxy_pool:
            return self.proxy_pool.pick()
        return None

    async def request(self, method, url, params=None, data=None, json_body=None,
                      headers=None, allow_redirects=True):
        if self.stopped():
            return None
        async with self._sem:
            proxy = self._pick_proxy()
            kw = {
                "params": params,
                "data": data,
                "headers": headers,
                "allow_redirects": allow_redirects,
                "ssl": False,
            }
            if json_body is not None:
                kw["json"] = json_body
            if proxy:
                kw["proxy"] = proxy
            t0 = time.time()
            try:
                async with self._session.request(method.upper(), url, **kw) as r:
                    body = await r.text(errors="ignore")
                    size = len(body)
                    async with self._lock:
                        self._stats["sent"] += 1
                        if r.status == 429:
                            self._stats["429"] += 1
                            self.concurrency = max(2, self.concurrency - 5)
                            self._sem = asyncio.Semaphore(self.concurrency)
                            self._stats["current_concurrency"] = self.concurrency
                        else:
                            self._stats["ok"] += 1
                            if self._stats["sent"] % 200 == 0:
                                newc = min(self.concurrency + 2, self.base_concurrency * 2)
                                if newc != self.concurrency:
                                    self.concurrency = newc
                                    self._sem = asyncio.Semaphore(self.concurrency)
                                    self._stats["current_concurrency"] = self.concurrency
                    if self.proxy_pool and proxy:
                        self.proxy_pool.record(proxy, r.status < 500)
                    return {
                        "status": r.status,
                        "headers": dict(r.headers),
                        "body": body,
                        "size": size,
                        "url": str(r.url),
                        "elapsed": round(time.time() - t0, 3),
                    }
            except asyncio.TimeoutError:
                async with self._lock:
                    self._stats["sent"] += 1
                    self._stats["err"] += 1
                if self.proxy_pool and proxy:
                    self.proxy_pool.record(proxy, False)
                return {"status": 0, "body": "", "size": 0, "url": url,
                        "elapsed": round(time.time() - t0, 3), "error": "timeout"}
            except Exception as e:
                async with self._lock:
                    self._stats["sent"] += 1
                    self._stats["err"] += 1
                if self.proxy_pool and proxy:
                    self.proxy_pool.record(proxy, False)
                return {"status": 0, "body": str(e)[:200], "size": 0, "url": url,
                        "elapsed": round(time.time() - t0, 3), "error": str(e)[:200]}

    async def map(self, method, url_template, items, param="id",
                  match_cb=None, out_path=None, fmt="tsv"):
        results = []
        tasks = []
        out_fh = None
        if out_path:
            pathlib.Path(out_path).parent.mkdir(parents=True, exist_ok=True)
            out_fh = open(out_path, "a")

        total = len(items)
        done_count = [0]

        async def one(item):
            if self.stopped():
                return
            url = url_template.format(**{param: item})
            r = await self.request(method, url)
            done_count[0] += 1
            if self.progress_cb and done_count[0] % 50 == 0:
                self.progress_cb(done_count[0], total, self._stats)
            if not r:
                return
            hit = False
            if match_cb:
                verdict = match_cb(r, item)
                if verdict == "STOP":
                    self.stop("success")
                    hit = True
                elif verdict:
                    hit = True
            if hit:
                results.append((item, r))
                if out_fh:
                    if fmt == "tsv":
                        body_snip = r['body'][:2000].replace(chr(10), ' ')
                        out_fh.write(f"{item}\t{r['status']}\t{body_snip}\n")
                    elif fmt == "json":
                        out_fh.write(json.dumps({"item": item, "status": r["status"],
                                                 "body": r["body"][:5000]}) + "\n")
                    out_fh.flush()

        try:
            for i in items:
                if self.stopped():
                    break
                tasks.append(asyncio.create_task(one(i)))
                if len(tasks) >= self.concurrency * 4:
                    await asyncio.gather(*tasks)
                    tasks = []
            if tasks:
                await asyncio.gather(*tasks)
        finally:
            if out_fh:
                out_fh.close()

        return {"sent": self._stats["sent"], "hits": len(results),
                "elapsed": round(time.time() - self._stats["start"], 1)}

    def stats(self):
        s = dict(self._stats)
        s["elapsed"] = round(time.time() - s["start"], 1) if s["start"] else 0
        s["rps"] = round(s["sent"] / s["elapsed"], 1) if s["elapsed"] else 0
        return s


def run(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        return asyncio.ensure_future(coro)
    return asyncio.run(coro)
