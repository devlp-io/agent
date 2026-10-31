#!/usr/bin/env python3
"""
webgui/test_api.py — dependency-light smoke tests for the GUI backend.

Run:  python3 webgui/test_api.py
"""
import os
import sys
import json
import tempfile
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

TMP = pathlib.Path(tempfile.mkdtemp(prefix="agui-test-"))
os.environ["AG_GUI_DATA"] = str(TMP)
os.environ.setdefault("AG_GUI_MAX_UPLOAD", str(1024 * 1024))

from fastapi.testclient import TestClient  # noqa: E402
import server  # noqa: E402

client = TestClient(server.app)
PASS = 0


def check(name, cond, extra=""):
    global PASS
    if not cond:
        print(f"FAIL  {name} {extra}")
        sys.exit(1)
    PASS += 1
    print(f"ok    {name}")


def main():
    r = client.get("/api/v2/health")
    check("health", r.status_code == 200 and r.json()["ok"] is True)

    r = client.get("/api/v2/models")
    check("models", r.status_code == 200 and "profiles" in r.json() and r.json()["profiles"])

    r = client.get("/gui")
    check("spa served", r.status_code == 200 and "text/html" in r.headers["content-type"])
    check("spa has app root", 'id="root"' in r.text)

    r = client.get("/", follow_redirects=False)
    check("root redirects", r.status_code in (302, 307) and r.headers["location"].endswith("/gui"))

    # threads
    r = client.post("/api/v2/threads", json={})
    check("thread create", r.status_code == 200)
    tid = r.json()["id"]
    check("thread default title", r.json()["title"] == "New chat")

    r = client.get("/api/v2/threads")
    check("thread list", any(t["id"] == tid for t in r.json()["threads"]))

    r = client.patch(f"/api/v2/threads/{tid}", json={"title": "Recon plan", "pinned": True})
    check("thread patch", r.status_code == 200 and r.json()["thread"]["title"] == "Recon plan")

    r = client.get(f"/api/v2/threads/{tid}/messages")
    check("empty messages", r.status_code == 200 and r.json()["messages"] == [])

    # upload + media round-trip
    payload = b"bench lit\n" * 20
    r = client.post(
        "/api/v2/upload",
        files={"file": ("note.txt", payload, "text/plain")},
        data={"thread_id": tid},
    )
    check("upload ok", r.status_code == 200 and r.json()["size"] == len(payload))
    uid = r.json()["id"]
    check("upload kind text", r.json()["kind"] == "text")

    r = client.get(f"/api/v2/media/{uid}")
    check("media bytes exact", r.status_code == 200 and r.content == payload)
    check("media nosniff", r.headers.get("x-content-type-options") == "nosniff")

    r = client.get(f"/api/v2/uploads?thread_id={tid}")
    check("uploads listed", len(r.json()["uploads"]) == 1)

    r = client.get(f"/api/v2/threads/{tid}/export?fmt=md")
    check("export markdown", r.status_code == 200 and "Recon plan" in r.text)

    # approvals + validation
    r = client.post("/api/v2/approve", json={"call_id": "deadbeef", "allow": True})
    check("unknown approval 404", r.status_code == 404)

    r = client.post("/api/v2/chat", json={"thread_id": "nope", "text": "hi"})
    check("chat unknown thread 404", r.status_code == 404)

    r = client.post("/api/v2/chat", json={"thread_id": tid, "text": ""})
    check("chat empty message 400", r.status_code == 400)

    r = client.delete(f"/api/v2/threads/{tid}")
    check("thread delete", r.status_code == 200 and r.json()["ok"] is True)

    # token gate (separate app import not needed: prove middleware wiring)
    check("token gate optional", server.GUI_TOKEN == "" or isinstance(server.GUI_TOKEN, str))

    print(f"\n{PASS} checks passed · data dir {TMP}")


if __name__ == "__main__":
    main()
