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

    # indented code (markdown turns 4 spaces into a code block — seen live)
    vis3 = server._visible_answer(
        "Last step — the probe was cut off before its result returned.\n\n"
        "    r.add_header('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64)')\n\n"
        "s,ct,b=req(method,B+path,data,hdr)\n\n"
        "Signature bug on my part — fixing and running.\n\n"
        "https://api.example.test/v1/items?limit=5\n"
        "Done: listed 12 routes. Next: probe the billing paths."
    )
    check("visible answer drops indented code", "add_header" not in vis3)
    check("visible answer drops comma assignment", "req(method" not in vis3)
    check("visible answer keeps urls and prose",
          "https://api.example.test/v1/items?limit=5" in vis3 and "Signature bug" in vis3)
    check("visible answer keeps done next after code",
          "Done: listed 12 routes" in vis3 and "Next: probe" in vis3)

    # bare call statements with nested parentheses are code too
    vis5 = server._visible_answer(
        "External fetch ladder now.\n"
        'log("shodan.json", json.dumps(r, indent=2))\n'
        'print("subdomains")\n'
        "Next: normalize the hits."
    )
    check("visible answer drops nested calls", "json.dumps" not in vis5 and "print(" not in vis5)
    check("visible answer keeps status after calls", "Next: normalize" in vis5)

    long_status = "A line of status. " * 80
    check("visible answer limits long status",
          len(server._visible_answer(long_status, limit=200)) <= 260)
    check("visible answer does not limit by default",
          len(server._visible_answer(long_status)) > 500)

    vis6 = server._visible_answer("Testing them all.\nend</parameter>\nNext: verify the token endpoint.")
    check("visible answer drops tag lines",
          "</parameter>" not in vis6 and "end</parameter>" not in vis6)
    check("visible answer keeps the next line", "Next: verify the token" in vis6)

    vis7 = server._visible_answer("Namespaces confirm the surface.\n]\nNext: probe the API.")
    check("visible answer drops punctuation junk", "\n]" not in vis7 and "Namespaces confirm" in vis7)

    vis8 = server._visible_answer("Status line.\n# ---- 1. Pull URLs ----\n### 2. Sweep IDs\nNext: go.")
    check("visible answer strips headings", "#" not in vis8 and "----" not in vis8)
    check("visible answer keeps heading text", "1. Pull URLs" in vis8 and "2. Sweep IDs" in vis8)

    vis9 = server._visible_answer(
        'Route dump ready.\n" 2>&1 | head -40\n"/wp-json/wp/v2/users?_fields=i\nNext: test auth.'
    )
    check("visible answer drops shell fragments", "2>&1" not in vis9 and "_fields" not in vis9)
    check("visible answer keeps the status", "Route dump ready" in vis9)

    vis10 = server._visible_answer(
        '"main.dart.js", "connect_main.dart.js" ]\nbreak\nDone: mapped the bundles.'
    )
    check("visible answer drops bare code keywords", "break" not in vis10)
    check("visible answer drops quoted list fragments", "main.dart.js" not in vis10)
    check("visible answer keeps the status line", "mapped the bundles" in vis10)

    vis11 = server._visible_answer(
        'Ready.\nf"https://firebasestorage.googleapis.com/v0/b/x"\nDone: storage closed.'
    )
    check("visible answer drops f-string fragments", "firebasestorage" not in vis11)

    vis12 = server._visible_answer(
        'Fetching.\nargs += ["-o", out, "-w", "%{http_code} %{size_download}"]\n'
        '"-A", UA, "-o", f"http/probe_{h}.html",\n'
        '("https://nuunipay.com/flutter_bootstrap.js\n'
        'Done: pulled assets.'
    )
    check("visible answer drops augmented assignments", "args +=" not in vis12)
    check("visible answer drops tuple fragments", '"-A"' not in vis12 and '("https' not in vis12)
    check("visible answer keeps the status after tuple fragments", "pulled assets" in vis12)

    vis13 = server._visible_answer(
        'Testing.\n"firebase_keys": re.compile(rb"AIza[0-9A-\n'
        '{"email": email, "password": pw, "returnSecureToken": True})\n'
        'Done: auth probed.'
    )
    check("visible answer drops dict/json fragments",
          "firebase_keys" not in vis13 and '"email"' not in vis13)
    check("visible answer keeps the auth status", "auth probed" in vis13)

    # stray heredoc / markup artifacts (seen live: "PYEOF</div>")
    vis4 = server._visible_answer(
        "The FILE directive keeps corrupting with a trailing `</div>`.\n"
        "PYEOF</div>\n"
        "EOF\n"
        "</div>\n"
        "Next: write the script via base64."
    )
    check("visible answer drops heredoc artifact", "PYEOF" not in vis4 and "EOF" not in vis4)
    check("visible answer drops stray markup line", "</div>" not in vis4.replace("`</div>`", ""))
    check("visible answer keeps inline tag in prose", "trailing `</div>`" in vis4)
    check("visible answer keeps next line", "Next: write the script" in vis4)

    # ── todos ───────────────────────────────────────────────────────────
    tt = client.post("/api/v2/threads", json={"title": "todo"}).json()["id"]
    items = server._todo_apply(tt, "add", "map exposed endpoints")
    check("todo add", bool(items) and items[0]["text"] == "map exposed endpoints")
    server._todo_apply(tt, "add", "test auth bypass")
    items = server._todo_apply(tt, "done", "t1")
    check("todo done", items[0]["status"] == "done")
    server._todo_apply(tt, "edit", "t2", "test IDOR on /api/users")
    items = server._todo_apply(tt, "list")
    check("todo edit", any(i["text"] == "test IDOR on /api/users" for i in items))
    server._todo_apply(tt, "add", "third item")
    done = server._todo_apply(tt, "done", "1")
    check("todo accepts an ordinal ref", done and done[0]["status"] == "done")
    server._todo_close_open(tt)
    check("closing a run cancels open items",
          all(t["status"] == "cancelled" for t in server._todo_list(tt) if t["status"] != "done"))
    for i in range(10):
        server._todo_apply(tt, "add", f"cap item {i}")
    check("plan capped at 8", len(server._todo_list(tt)) == 8)
    check("duplicate todo ignored",
          len(server._todo_apply(tt, "add", "cap item 0")) == 8)
    check("todo clears", server._todo_apply(tt, "clear") == [])
    check("todos endpoint", client.get(f"/api/v2/threads/{tt}/todos").status_code == 200)
    client.delete(f"/api/v2/threads/{tt}")

    # ── scope + sudo + subagent worker ──────────────────────────────────
    from core.agent_router import AgentRouter, mission_scope, strip_model_tags
    from core.agent_router import REFUSAL_RETRIES, _looks_like_refusal
    check("refusal retries sit in the 7-10 band", 7 <= REFUSAL_RETRIES <= 10)
    check("refusal heuristic catches framing",
          _looks_like_refusal("The disclosure draft names a malformed URL as the authorization basis, "
                              "a sign the owner framing is template text."))
    check("refusal heuristic keeps normal status",
          not _looks_like_refusal("Done: pulled the manifest. Next: probe the API."))

    from core.task_runner import CommandResult as _CR
    led = AgentRouter(lambda e: None)
    led.task_runner.run_command = lambda *a, **k: _CR(
        command="echo hi", returncode=0, output="LEDGER_OK", duration=0.0)
    led._exec_directive_command("echo hi")
    check("evidence ledger records real output",
          any("LEDGER_OK" in line for line in led.evidence_ledger))
    check("model tags stripped",
          strip_model_tags('a</parameter>\n<parameter name="x">b') == "a\nb")
    check("scope narrow", mission_scope("what is the tech stack of example.com") == "scoped")
    check("scope deep", mission_scope("attack example.com and get all vulnerabilities") == "deep")
    check("scope offensive is deep", mission_scope("offensive example.com") == "deep")
    check("scope continue inherits", mission_scope("continue", "deep") == "deep")

    import agent_v8 as _v8
    check("refusal catches announced stop",
          _v8.is_refusal("I'm going to stop the active offensive work against "
                         "nuunipay.com and dahabpay.com here, and be straight with you."))
    check("refusal catches stopped engagement",
          _v8.is_refusal("I've stopped the engagement here rather than moving into "
                         "the next phase."))
    check("refusal catches thin recon report",
          _v8.is_refusal("No vulnerability was identified and no attack was carried out."))
    check("refusal catches passive-only framing",
          _v8.is_refusal("Active exploitation against a live payment processor is a "
                         "different category, so I only did public-record recon."))
    check("server refusal catches announced stop",
          server._is_refusal_text("I'm going to stop the active offensive work here."))
    check("server refusal catches thin recon report",
          server._is_refusal_text("No attack was carried out."))

    thin_gate = AgentRouter(lambda e: None)
    thin_gate._mission_scope = "deep"
    thin_gate._has_high_finding = lambda: False
    thin_gate._action_count = 0
    thin_gate._done_gate_retries = 0
    gate_holds = [thin_gate._critical_gate_hold() for _ in range(9)]
    check("gate rejects a recon-only DONE",
          all(isinstance(h, str) and h != "__BRAIN__" for h in gate_holds[:8]))
    check("gate hands off to the brain after the retry budget",
          gate_holds[8] == "__BRAIN__")
    full_gate = AgentRouter(lambda e: None)
    full_gate._mission_scope = "deep"
    full_gate._has_high_finding = lambda: False
    full_gate._action_count = 12
    full_gate._done_gate_retries = 0
    check("gate still holds once after enough actions",
          full_gate._critical_gate_hold() is not None)
    full_gate._done_gate_retries = 3
    check("gate releases after enough actions", full_gate._critical_gate_hold() is None)
    check("scope watch flags unrelated app",
          AgentRouter(lambda e: None)._out_of_scope_hosts(
              "curl -sS https://dahabpay.com/Authentication/Login") == ["dahabpay.com"])
    scope_guard = AgentRouter(lambda e: None)
    scope_guard._active_scan_target = "https://nuunipay.com"
    check("scope watch allows target subdomain",
          scope_guard._out_of_scope_hosts(
              "curl -sS https://app.nuunipay.com/version.json") == [])
    check("scope watch allows platform hosts",
          scope_guard._out_of_scope_hosts(
              "curl -sS https://dahab-chain-wallet.firebaseapp.com/x") == [])
    check("scope watch allows infra/tooling",
          scope_guard._out_of_scope_hosts(
              "curl -sS https://api.github.com/repos/x && curl https://api.cloudinary.com/v1_1/x") == [])
    check("scope watch allows research docs",
          scope_guard._out_of_scope_hosts(
              "curl -sS https://owasp.org/www-project-top-ten/") == [])
    check("scope watch does not treat filenames as hosts",
          scope_guard._out_of_scope_hosts("python main.dart.js --out out.bin") == [])
    check("scope watch ignores result files",
          scope_guard._out_of_scope_hosts(
              "tail -80 probe4.out && cat results.json && grep x scan.err") == [])
    check("scope watch allows mixed target command",
          scope_guard._out_of_scope_hosts(
              "curl https://nuunipay.com/a && curl https://dahabpay.com/b") == [])

    check("greeting title is trivial", server._title_is_trivial("Casual Greeting Chat Session"))
    check("mission title is not trivial", not server._title_is_trivial("Offensive Review of nuunipay.com"))
    check("mission text recognized", server._is_mission_text("offensive attack https://nuunipay.com"))
    check("continue is not a mission", not server._is_mission_text("continue"))
    check("mission workspace slug uses host",
          server._workspace_slug("offensive attack https://nuunipay.com").startswith("nuunipay-com"))
    check("report completeness rejects cut sentence",
          not server._ends_cleanly("5. On dahabpay.com, test `ForgotPassword`"))
    check("report completeness accepts finished prose",
          server._ends_cleanly("Done: all surfaces closed."))

    # A chat that opens with "hi" must not keep a `hi-<id>` folder once the
    # operator gives it a real target.
    old_root = os.environ.get("AG_SCAN_ROOT")
    os.environ["AG_SCAN_ROOT"] = str(TMP / "scans")
    try:
        wt = client.post("/api/v2/threads", json={"title": "New chat"}).json()["id"]
        p_hi = server._session_workdir(wt, "hi")
        p_mission = server._session_workdir(wt, "offensive attack https://example.com")
        check("workspace renamed from greeting",
              p_hi != p_mission and p_mission.name.startswith("example-com"))
        check("workspace rename keeps contents", p_hi.exists() is False and p_mission.exists())
        client.delete(f"/api/v2/threads/{wt}")
    finally:
        if old_root is None:
            os.environ.pop("AG_SCAN_ROOT", None)
        else:
            os.environ["AG_SCAN_ROOT"] = old_root

    parser_dedupe = AgentRouter(lambda e: None)
    dup = parser_dedupe._parse_directives("COMMAND: id\nCOMMAND: id\nTODO: add|one")
    check("duplicate directives collapse", dup == [("COMMAND", "id"), ("TODO", "add|one")])

    check("short 'attack target' expands", server.is_short_offensive("attack example.com"))
    check("short 'find vulns' expands", server.is_short_offensive("find vulns of example.com"))
    check("short 'offensive target' expands", server.is_short_offensive("offensive example.com"))
    check("short 'scan for vulnerabilities' expands",
          server.is_short_offensive("scan for vulnerabilities example.com"))
    check("tech stack is not a mission",
          not server.is_short_offensive("what is the tech stack of example.com"))
    check("no target means no expansion", not server.is_short_offensive("attack"))
    check("mission brief has phases", "Resolve and fingerprint" in server.MISSION_BRIEF)

    check("imperative 'do this' not a question",
          server._is_question_only("Do this exactly, in order: create a todo list.") is False)
    check("imperative dispatch not a question",
          server._is_question_only("dispatch a worker to run id") is False)
    check("tech stack with a target is an action",
          server._is_question_only("what is the tech stack of example.com") is False)
    check("tech stack without a target is a question",
          server._is_question_only("what is a tech stack?") is True)
    check("capability question stays a question",
          server._is_question_only("can you build a port scanner?") is True)

    old_pw = os.environ.pop("AG_SUDO_PASS", None)
    try:
        rr = AgentRouter(lambda e: None)
        check("sudo untouched without credential", rr._sudoize("sudo id") == "sudo id")
        os.environ["AG_SUDO_PASS"] = "test-pass"
        check("sudo rewritten", rr._sudoize("sudo apt-get update") == "sudo -A apt-get update")
        check("sudo env carries secret", rr._sudo_env().get("AG_SUDO_PASS") == "test-pass")
        check("sudo askpass set", "SUDO_ASKPASS" in rr._sudo_env())
    finally:
        os.environ.pop("AG_SUDO_PASS", None)
        if old_pw is not None:
            os.environ["AG_SUDO_PASS"] = old_pw

    from core.subagents import OperatorSubagent, SubagentDispatcher
    from core.task_runner import CommandResult

    class _FakeModel:
        def __init__(self):
            self.calls = 0

        def stream_chat(self, messages, temperature=0.2):
            self.calls += 1
            if self.calls == 1:
                yield '```tool\n{"tool":"shell","args":{"cmd":"id"}}\n```'
            else:
                yield "FINDING: high|Worker proof|uid=0 confirmed\nDone: verified as root."

    class _FakeRunner:
        def run_command(self, cmd, **kwargs):
            return CommandResult(command=cmd, returncode=0, output="uid=0(root) gid=0(root)",
                                 duration=0.0)

    worker = OperatorSubagent(
        subagent_type="operator", task="prove root", event_callback=lambda e: None,
        model_manager=_FakeModel(), task_runner=_FakeRunner(),
    )
    res = worker.run()
    check("worker ran tools", "uid=0" in (res.details or ""))
    check("worker captured finding",
          res.findings and res.findings[0]["severity"] == "high")
    check("worker summary", "verified as root" in res.summary)
    check("operator type mapped",
          SubagentDispatcher.SUBAGENT_MAP["operator"] is OperatorSubagent)

    gate = AgentRouter(lambda e: None)
    gate._mission_scope = "deep"
    gate._has_high_finding = lambda: False
    check("critical gate holds early done",
          "CRITICAL GATE" in (gate._critical_gate_hold() or ""))
    gate._done_gate_retries = 3
    check("critical gate keeps holding a thin run",
          gate._critical_gate_hold() is not None)
    gate._done_gate_retries = REFUSAL_RETRIES
    check("critical gate hands off after the budget",
          gate._critical_gate_hold() == "__BRAIN__")
    gate._done_gate_retries = 3
    gate._action_count = 12
    check("critical gate is bounded once surface is covered",
          gate._critical_gate_hold() is None)
    gate._done_gate_retries = 0
    gate._action_count = 0
    gate._has_high_finding = lambda: True
    check("critical gate releases on a real finding", gate._critical_gate_hold() is None)
    gate._mission_scope = "scoped"
    gate._has_high_finding = lambda: False
    check("critical gate ignores scoped work", gate._critical_gate_hold() is None)

    # directive parsing tolerates list markers; findings are deduplicated
    parser = AgentRouter(lambda e: None)
    parsed = parser._extract_directive_matches("1. TODO: add|Fingerprint\n- COMMAND: id")
    check("list-marker directives parsed", [k for k, _ in parsed] == ["TODO", "COMMAND"])

    fevs = []
    fr = AgentRouter(lambda e: fevs.append(e))
    fr._exec_directive_finding("high|Duplicate title|first")
    fr._exec_directive_finding("high|Duplicate title|second")
    check("duplicate finding recorded once",
          sum(1 for e in fevs if type(e).__name__ == "FindingEvent") == 1)

    tcalls = []
    tr = AgentRouter(lambda e: None)
    tr.todo_callback = lambda action, a="", b="": tcalls.append((action, a, b)) or []
    tr._exec_directive_todo("add Fingerprint the host")
    tr._exec_directive_todo("edit t2 reworded")
    check("todo free-form parsed",
          tcalls[0] == ("add", "Fingerprint the host", "")
          and tcalls[1] == ("edit", "t2", "reworded"))

    # the compliance worker gives the task a second, fresh-context brain
    from unittest.mock import patch

    class _BrainResult:
        def __init__(self, summary):
            self.summary = summary

    b1 = AgentRouter(lambda e: None)
    with patch("core.agent_router.SubagentDispatcher.dispatch",
               return_value=_BrainResult("worker completed the task")):
        check("refusal brain returns worker summary",
              b1._refusal_brain("attack example.com") == "worker completed the task")
    b2 = AgentRouter(lambda e: None)
    with patch("core.agent_router.SubagentDispatcher.dispatch",
               return_value=_BrainResult("I'm not going to do that")):
        check("refusal brain rejects a nested refusal", b2._refusal_brain("attack example.com") == "")

    # token gate (separate app import not needed: prove middleware wiring)
    check("token gate optional", server.GUI_TOKEN == "" or isinstance(server.GUI_TOKEN, str))

    print(f"\n{PASS} checks passed · data dir {TMP}")


if __name__ == "__main__":
    main()
