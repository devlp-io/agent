"""
budget — per-run resource caps. Max requests, max time, max bytes.
Soft-warn at 80%, hard-stop at 100%.
Reads env: AG_MAX_REQ, AG_MAX_TIME (seconds), AG_MAX_BYTES.
Set any to 0 to disable that cap.
"""
import os
import time
import threading
import pathlib

_LOCK = threading.Lock()


class Budget:
    def __init__(self, run_dir=None):
        self.max_req = int(os.environ.get("AG_MAX_REQ", "0"))
        self.max_time = int(os.environ.get("AG_MAX_TIME", "0"))
        self.max_bytes = int(os.environ.get("AG_MAX_BYTES", "0"))
        self.req = 0
        self.bytes = 0
        self.start = time.time()
        self.warned = set()
        self.run_dir = run_dir

    def _warn(self, key, msg):
        if key in self.warned:
            return
        self.warned.add(key)
        print(f"\033[33m[budget] {msg}\033[0m")
        if self.run_dir:
            try:
                with open(pathlib.Path(self.run_dir) / "budget.log", "a") as f:
                    f.write(f"[{time.time():.0f}] {msg}\n")
            except Exception:
                pass

    def check(self):
        """Returns (ok, reason). ok=False means hard-stop."""
        with _LOCK:
            if self.max_req and self.req >= self.max_req:
                return False, f"max_req reached ({self.req}/{self.max_req})"
            if self.max_req and self.req >= int(self.max_req * 0.8):
                self._warn("req80", f"80% request budget ({self.req}/{self.max_req})")
            if self.max_bytes and self.bytes >= self.max_bytes:
                return False, f"max_bytes reached ({self.bytes}/{self.max_bytes})"
            if self.max_bytes and self.bytes >= int(self.max_bytes * 0.8):
                self._warn("bytes80", f"80% byte budget ({self.bytes}/{self.max_bytes})")
            if self.max_time:
                elapsed = time.time() - self.start
                if elapsed >= self.max_time:
                    return False, f"max_time reached ({elapsed:.0f}s/{self.max_time}s)"
                if elapsed >= self.max_time * 0.8:
                    self._warn("time80", f"80% time budget ({elapsed:.0f}s/{self.max_time}s)")
            return True, "ok"

    def record(self, n_bytes=0):
        with _LOCK:
            self.req += 1
            self.bytes += n_bytes

    def status(self):
        elapsed = time.time() - self.start
        return {
            "req": self.req,
            "max_req": self.max_req or "unlimited",
            "bytes": self.bytes,
            "max_bytes": self.max_bytes or "unlimited",
            "elapsed": round(elapsed, 1),
            "max_time": self.max_time or "unlimited",
        }


_GLOBAL = None


def get(run_dir=None):
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = Budget(run_dir)
    return _GLOBAL


def set_global(b):
    global _GLOBAL
    _GLOBAL = b
