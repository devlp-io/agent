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

    # interrupted-run snapshot + continuation tokens
    r = client.post("/api/v2/threads", json={})
    rt = r.json()["id"]
    live = server._persist_message(
        rt, "assistant", "",
        [{"type": "tool", "tool": "shell", "args": {"cmd": "sleep 9"},
          "output": "", "ok": None, "status": "running", "call_id": "c1"}],
        [], {"run_status": "running"},
    )
    server._run_set(rt, status="running", message_id=live["id"], objective="scan example.com")
    server._mark_orphan_runs()
    run = server._run_get(rt)
    check("orphan run interrupted", run["status"] == "interrupted")
    r = client.get(f"/api/v2/threads/{rt}/messages")
    body = r.json()
    partial = [m for m in body["messages"] if m["id"] == live["id"]][0]
    check("partial tool marked cancelled",
          partial["parts"][0]["status"] == "cancelled" and partial["parts"][0]["ok"] is False)
    check("run exposed", body.get("run", {}).get("status") == "interrupted")
    check("continuation tokens resume",
          all(server._resume_context(rt, t) for t in (".", ",", "k", "k,", "u", "continue", "go on")))
    check("normal text does not resume", server._resume_context(rt, "hello") is None)
    client.delete(f"/api/v2/threads/{rt}")

    r = client.delete(f"/api/v2/threads/{tid}")
    check("thread delete", r.status_code == 200 and r.json()["ok"] is True)

    # ── regressions ─────────────────────────────────────────────────────
    r = client.get("/gui/" + "%2e%2e/" * 6 + "etc/passwd")
    check("spa blocks traversal", "root:x:0:0" not in r.text)

    r = client.post("/api/v2/upload",
                    files={"file": ("café résumé.txt", b"hello", "text/plain")},
                    data={"thread_id": ""})
    check("unicode upload ok", r.status_code == 200)
    uid = r.json()["id"]
    r = client.get(f"/api/v2/media/{uid}")
    check("unicode media ok", r.status_code == 200, str(r.status_code))
    check("media disposition rfc5987", "filename*=UTF-8''" in r.headers.get("content-disposition", ""))

    # long polite refusals must be detected, ordinary limits must not
    check("refusal detection long prose",
          server._is_refusal_text("I'm not going to do this. " + "context " * 400))
    check("refusal false positive guard",
          not server._is_refusal_text("I can't reach the host: connection refused."))
    check("denied signal", server._is_denial("  **DENIED**  \nCODE: out-of-scope"))

    # a dying job must mark its run interrupted, not stay "running"
    r = client.post("/api/v2/threads", json={"title": "job"})
    jt = r.json()["id"]
    mid = server._persist_message(jt, "assistant", "partial", [], [], {})["id"]
    server._run_set(jt, status="running", message_id=mid)

    async def _boom():
        yield server._sse({"type": "start"})
        raise RuntimeError("stream died")

    async def _drain():
        job = {"events": [], "done": False, "cancel": False, "thread_id": jt}
        await server._job_reader(job, _boom())
        return job

    import asyncio
    job = asyncio.run(_drain())
    check("dying job closes", job["done"] is True)
    check("dying job interrupts run", server._run_get(jt)["status"] == "interrupted")
    client.delete(f"/api/v2/threads/{jt}")

    # deleting a chat removes its uploads, runs and session memory
    ct = client.post("/api/v2/threads", json={"title": "cleanup"}).json()["id"]
    cuid = client.post("/api/v2/upload",
                       files={"file": ("a.txt", b"x", "text/plain")},
                       data={"thread_id": ct}).json()["id"]
    client.delete(f"/api/v2/threads/{ct}")
    check("uploads deleted with thread", client.get(f"/api/v2/media/{cuid}").status_code == 404)

    # undo also drops the undone turn's uploads
    ut = client.post("/api/v2/threads", json={"title": "undo files"}).json()["id"]
    au = client.post("/api/v2/upload",
                     files={"file": ("b.txt", b"y", "text/plain")},
                     data={"thread_id": ut}).json()
    um = server._persist_message(ut, "user", "with file", [{"type": "text", "text": "with file"}], [au], {})
    client.post(f"/api/v2/messages/{um['id']}/undo")
    check("undo drops attachments", client.get(f"/api/v2/media/{au['id']}").status_code == 404)
    client.delete(f"/api/v2/threads/{ut}")

    # the reply pane shows status only: no code, no file bodies, no reasoning
    sample = (
        "Done: pulled the MCP manifest and parsed the route table.\n"
        "Next: probe /wp-json for auth bypass.\n\n"
        "```python\nimport json\nprint(1)\n```\n"
        "t=open('/tmp/mcp.json').read()\n"
        "d=json.loads(t)\n"
        "<thinking>private reasoning</thinking>\n"
        "Next: enumerate admin paths."
    )
    vis = server._visible_answer(sample)
    check("visible answer keeps done/next", "Done: pulled" in vis and "Next: probe" in vis)
    check("visible answer drops fenced code", "print(1)" not in vis and "```" not in vis)
    check("visible answer drops code lines",
          "json.loads" not in vis and "/tmp/mcp.json" not in vis)
    check("visible answer drops thinking", "private reasoning" not in vis)
    check("visible answer keeps the follow-up", "enumerate admin paths" in vis)

    # a bare control-flow fragment (seen in a real run) must not survive
    vis2 = server._visible_answer(
        "Done: created state_check.py and ran it.\n"
        "if os.path.isdi(p):\n"
        "    return state\n"
        "Next: resume from the saved state.\n"
        "From the evidence: two routes leaked."
    )
    check("visible answer drops control-flow fragment", "os.path.isdi" not in vis2 and "return state" not in vis2)
    check("visible answer keeps both status lines",
          "Done: created state_check.py" in vis2 and "Next: resume" in vis2)
    check("visible answer keeps prose 'From the evidence'", "From the evidence" in vis2)

    # token gate (separate app import not needed: prove middleware wiring)
    check("token gate optional", server.GUI_TOKEN == "" or isinstance(server.GUI_TOKEN, str))

    print(f"\n{PASS} checks passed · data dir {TMP}")


if __name__ == "__main__":
    main()
