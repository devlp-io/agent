"""
core.proxy — proxy pool with health scoring and 3-strike auto-disable.
Loads proxies from env AG_PROXIES (comma-separated) or ~/agent/proxies.txt.
Health: score drops on error/timeout, resets on success. Below threshold -> disabled.
"""
import os
import time
import random
import pathlib
import threading

DEFAULT_THRESHOLD = -5
RESET_AFTER = 300


class ProxyPool:
    def __init__(self, proxies=None, run_dir=None):
        self._lock = threading.Lock()
        self.run_dir = run_dir
        self.proxies = {}
        if proxies is None:
            proxies = self._load()
        for p in proxies:
            self.add(p)

    def _load(self):
        env = os.environ.get("AG_PROXIES", "").strip()
        if env:
            return [x.strip() for x in env.split(",") if x.strip()]
        p = pathlib.Path(os.path.expanduser("~/agent/proxies.txt"))
        if p.exists():
            return [ln.strip() for ln in p.read_text().splitlines()
                    if ln.strip() and not ln.strip().startswith("#")]
        return []

    def add(self, proxy):
        with self._lock:
            self.proxies[proxy] = {
                "score": 0,
                "uses": 0,
                "errors": 0,
                "last_error": 0,
                "disabled": False,
            }

    def healthy(self):
        with self._lock:
            now = time.time()
            out = []
            for p, s in self.proxies.items():
                if s["disabled"]:
                    if now - s["last_error"] > RESET_AFTER:
                        s["disabled"] = False
                        s["score"] = 0
                    else:
                        continue
                out.append(p)
            return out

    def pick(self):
        healthy = self.healthy()
        if not healthy:
            return None
        weights = [max(1, self.proxies[p]["score"] + 10) for p in healthy]
        return random.choices(healthy, weights=weights, k=1)[0]

    def record(self, proxy, ok, latency=None):
        if not proxy or proxy not in self.proxies:
            return
        with self._lock:
            s = self.proxies[proxy]
            s["uses"] += 1
            if ok:
                s["score"] = min(s["score"] + 1, 20)
            else:
                s["errors"] += 1
                s["score"] -= 2
                s["last_error"] = time.time()
                if s["score"] <= DEFAULT_THRESHOLD:
                    s["disabled"] = True

    def status(self):
        with self._lock:
            return {p: dict(s) for p, s in self.proxies.items()}

    def __len__(self):
        return len(self.proxies)


_GLOBAL = None


def get(run_dir=None):
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = ProxyPool(run_dir=run_dir)
    return _GLOBAL
