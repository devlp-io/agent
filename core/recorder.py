"""
core/recorder.py — append-only per-target action log.

Every command, directive, finding, probe, walk, and successful result the
agent produces gets appended here. Keyed by target, not by run, so the
record survives across scans.
"""
import os
import json
import time
import pathlib
import threading
from datetime import datetime

SCAN_ROOT = pathlib.Path(os.environ.get("AG_SCAN_ROOT", os.path.expanduser("~/scans")))
_LOCK = threading.Lock()


def _path_for(target: str) -> pathlib.Path:
    safe = "".join(c for c in target if c.isalnum() or c in "._-")
    return SCAN_ROOT / safe / "recorder.jsonl"


def record(target: str, kind: str, payload: dict, run_dir=None):
    """Append one event. kind: command|finding|probe|walk|endpoint|secret|
    cred|loot|attack|schema|note|result."""
    try:
        p = _path_for(target)
        p.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "kind": kind,
            "run_dir": str(run_dir) if run_dir else None,
            **payload,
        }
        with _LOCK:
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass  # recorder must never break a scan


def read(target: str, limit: int = 20000) -> list:
    """Return the last N events for a target."""
    p = _path_for(target)
    if not p.exists():
        return []
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return [json.loads(l) for l in lines[-limit:] if l.strip()]
    except Exception:
        return []




import re
import re as _re

_CURL_RE = _re.compile(r"\bcurl\b([^|;&\n]+)", _re.I)

def _parse_curl(cmd: str) -> dict:
    """Best-effort parse of a curl command line into structured fields."""
    m = _CURL_RE.search(cmd)
    if not m:
        return {}
    rest = m.group(1).strip()

    method = "GET"
    mm = _re.search(r"-X\s+([A-Z]+)", rest)
    if mm:
        method = mm.group(1).upper()
    headers = {}
    for hm in _re.finditer(r"-H\s+['\"]([^:]+):\s*([^'\"]+)['\"]", rest):
        headers[hm.group(1).strip()] = hm.group(2).strip()
    cookies = ""
    cm = _re.search(r"-b\s+['\"]([^'\"]+)['\"]", rest)
    if cm:
        cookies = cm.group(1).strip()
    body = ""
    bm = _re.search(r"(?:-d|--data(?:-raw)?|-j|--json)\s+['\"](.+?)['\"](?:\s|$)", rest)
    if bm:
        body = bm.group(1)
    url = ""
    for um in _re.finditer(r"(https?://[^\s'\"]+)", rest):
        u = um.group(1).rstrip("\\")
        if u and not u.startswith("http://127.0.0.1") and not u.startswith("http://localhost"):
            url = u
            break
    return {"method": method, "url": url, "headers": headers,
            "cookies": cookies, "body": body}


def _extract_curl_proof(cmd: str, output: str, ok: bool):
    """If the command looks like a successful curl against an HTTP target,
    return a structured HTTP proof entry. Else None."""
    if not ok or not output:
        return None
    parsed = _parse_curl(cmd)
    if not parsed or not parsed.get("url"):
        return None
    # response snippet — first 800 chars of meaningful body
    snippet = output.strip()[:800]
    # try to sniff status code from output
    status = 0
    sm = _re.search(r"HTTP/(?:1\.[01]|2)\s+(\d{3})", output)
    if sm:
        status = int(sm.group(1))
    if status and status >= 400:
        return None
    return {
        "method": parsed["method"],
        "url": parsed["url"],
        "headers": parsed["headers"],
        "cookies": parsed["cookies"],
        "body": parsed["body"][:2000],
        "status": status,
        "snippet": snippet,
    }


# ── sections: canonical sidebar categories from real data ────────────

_PATH_HINTS = [
    ("users",       r"\b(user|profile|account|customer|member|kyc)\b"),
    ("orders",      r"\b(order|invoice|cart|checkout|purchase)\b"),
    ("payments",    r"\b(payment|transaction|deposit|withdraw|wallet|balance|transfer)\b"),
    ("products",    r"\b(product|catalog|inventory|price|sku|item)\b"),
    ("partners",    r"\b(partner|merchant|vendor|reseller|agent|affiliate)\b"),
    ("auth",        r"\b(auth|login|session|token|oauth|jwt|otp|2fa)\b"),
    ("admin",       r"\b(admin|staff|manage|console|dashboard|panel)\b"),
    ("files",       r"\b(file|upload|download|media|image|attach|doc|bucket|storage)\b"),
    ("messages",    r"\b(message|chat|notification|email|sms|push|inbox)\b"),
    ("logs",        r"\b(log|audit|event|history|activity|track)\b"),
    ("config",      r"\b(config|setting|param|flag|feature|system)\b"),
    ("secrets",     r"\b(secret|key|credential|password|token)\b"),
]


def sections(target: str) -> list:
    """Return ordered list of {name, count} that the console sidebar should
    show, based on the actual endpoints / findings / secrets present."""
    events = read(target)
    counters = {name: 0 for name, _ in _PATH_HINTS}
    counters["_other"] = 0
    urls = set()
    for e in events:
        k = e.get("kind")
        if k in ("endpoint", "probe", "walk"):
            u = e.get("url") or ""
            if u:
                urls.add(u)
        elif k == "command" and e.get("ok"):
            for u in re.findall(r"https?://[^\s'\"]+", e.get("output") or ""):
                urls.add(u)
        elif k == "secret":
            counters["secrets"] += 1
        elif k == "finding":
            t = (e.get("title") or "") + " " + (e.get("evidence") or "")
            matched = False
            for name, pat in _PATH_HINTS:
                if _re.search(pat, t, _re.I):
                    counters[name] += 1
                    matched = True
                    break
            if not matched:
                counters["_other"] += 1
    for u in urls:
        matched = False
        for name, pat in _PATH_HINTS:
            if _re.search(pat, u, _re.I):
                counters[name] += 1
                matched = True
                break
        if not matched:
            counters["_other"] += 1
    out = []
    for name, _ in _PATH_HINTS:
        if counters[name] > 0:
            out.append({"name": name, "count": counters[name]})
    if counters["_other"] > 0:
        out.append({"name": "other", "count": counters["_other"]})
    return out


def http_proofs(target: str, limit: int = 40) -> list:
    """Return the last N successful HTTP proofs for replaying."""
    events = read(target)
    proofs = []
    for e in events:
        if e.get("kind") == "command":
            proof = _extract_curl_proof(
                e.get("cmd", ""), e.get("output", ""), bool(e.get("ok")))
            if proof:
                proof["ts"] = e.get("ts")
                proofs.append(proof)
    return proofs[-limit:]




# ──────────────────────────────────────────────────────────────────
# backfill: ingest every existing run's artifacts into the recorder
# ──────────────────────────────────────────────────────────────────

def _iter_runs(target: str):
    base = SCAN_ROOT / "".join(c for c in target if c.isalnum() or c in "._-")
    if not base.exists():
        return []
    return sorted([d for d in base.iterdir()
                   if d.is_dir() and d.name[:8].isdigit()])


_JSON_BLOB_RE = _re.compile(r"(\{[\s\S]{40,8000}?\}|\[[\s\S]{40,8000}?\])")


def _extract_json_blobs(text: str):
    """Return list of parseable JSON substrings from a blob of text."""
    out = []
    for m in _JSON_BLOB_RE.finditer(text):
        raw = m.group(1)
        try:
            parsed = json.loads(raw)
        except Exception:
            continue
        if isinstance(parsed, (dict, list)):
            out.append(parsed)
    return out


def backfill(target: str, run_dir=None):
    """Ingest artifacts from one or every run of this target.
    Idempotent: marks each run once."""
    marker = _path_for(target).with_name(".backfilled")
    done = set()
    if marker.exists():
        done = set(marker.read_text().splitlines())

    runs = [run_dir] if run_dir else _iter_runs(target)
    ingested = 0
    for rd in runs:
        rd = pathlib.Path(rd)
        if str(rd) in done:
            continue
        st_path = rd / "state.json"
        if st_path.exists():
            try:
                st = json.loads(st_path.read_text())
            except Exception:
                st = {}
            for i, f in enumerate(st.get("findings", []) or []):
                record(target, "finding", {
                    "sev": f.get("sev", "info"),
                    "title": f.get("title", "")[:200],
                    "evidence": str(f.get("evidence", ""))[:4000],
                }, run_dir=rd)
                ingested += 1
            for e in st.get("endpoints", []) or []:
                record(target, "endpoint", {
                    "method": e.get("method", "GET"),
                    "url": e.get("url", ""),
                    "note": e.get("note", "")[:300],
                }, run_dir=rd)
                ingested += 1
            for s in st.get("secrets", []) or []:
                record(target, "secret", {
                    "kind_name": s.get("kind", "secret"),
                    "value": str(s.get("value", ""))[:400],
                    "path": str(s.get("path", ""))[:300],
                }, run_dir=rd)
                ingested += 1
            for c in st.get("creds", []) or []:
                record(target, "cred", {
                    "user": c.get("user", ""),
                    "pass": c.get("pass", ""),
                    "where": c.get("where", "")[:200],
                }, run_dir=rd)
                ingested += 1
            for w in st.get("walks", []) or []:
                record(target, "walk", {
                    "method": w.get("method", "GET"),
                    "url": w.get("url", ""),
                    "param": w.get("param", ""),
                    "hits": w.get("hits", 0),
                    "sample": "",
                }, run_dir=rd)
                ingested += 1

        # live_commands.log — pull successful curls
        cl = rd / "live_commands.log"
        if cl.exists():
            try:
                blob = cl.read_text(errors="ignore")
            except Exception:
                blob = ""
            # split into command blocks: lines beginning with "$ " then
            # subsequent indented lines until next "$ " or EOF
            blocks = []
            cur_cmd, cur_out = None, []
            for line in blob.splitlines():
                if line.startswith("$ "):
                    if cur_cmd:
                        blocks.append((cur_cmd, "\n".join(cur_out)))
                    cur_cmd = line[2:].strip()
                    cur_out = []
                elif cur_cmd is not None:
                    cur_out.append(line)
            if cur_cmd:
                blocks.append((cur_cmd, "\n".join(cur_out)))
            for cmd, out in blocks:
                if not cmd.startswith(("curl", "httpie", "wget")) and "curl " not in cmd:
                    continue
                proof = _extract_curl_proof(cmd, out, True)
                if proof:
                    proof["cmd"] = cmd
                    record(target, "command", {
                        "cmd": cmd[:2000],
                        "output": out[:6000],
                        "ok": True,
                        "http_proof": proof,
                    }, run_dir=rd)
                    ingested += 1

        with open(marker, "a") as f:
            f.write(str(rd) + "\n")

    return {"target": target, "runs": len(runs), "ingested": ingested}


# ──────────────────────────────────────────────────────────────────
# leaks: structured records extracted from findings + command outputs
# ──────────────────────────────────────────────────────────────────

_ENTITY_FROM_URL = _re.compile(r"/(?:api/)?([a-zA-Z][a-zA-Z0-9_-]{2,40})(?:[/?]|$)")


def _entity_of(url: str) -> str:
    if not url:
        return "unknown"
    m = _ENTITY_FROM_URL.search(url.split("?")[0].rstrip("/") + "/")
    if m:
        name = m.group(1).lower()
        if name in ("api", "v1", "v2", "v3", "rest", "graphql"):
            # try next segment
            tail = url.split(f"/{name}/", 1)[-1]
            m2 = _ENTITY_FROM_URL.search("/" + tail)
            if m2:
                return m2.group(1).lower()
        return name
    return "unknown"


def leaks(target: str, limit_runs: int = 3) -> list:
    """Return structured leaked datasets: [{entity, source_url, source_cmd,
    ts, records: [...], count}] by parsing successful command outputs."""
    runs = _iter_runs(target)[-limit_runs:] if limit_runs else _iter_runs(target)
    by_entity = {}
    for rd in runs:
        cl = rd / "live_commands.log"
        if not cl.exists():
            continue
        try:
            blob = cl.read_text(errors="ignore")
        except Exception:
            continue
        blocks = []
        cur_cmd, cur_out = None, []
        for line in blob.splitlines():
            if line.startswith("$ "):
                if cur_cmd:
                    blocks.append((cur_cmd, "\n".join(cur_out)))
                cur_cmd = line[2:].strip()
                cur_out = []
            elif cur_cmd is not None:
                cur_out.append(line)
        if cur_cmd:
            blocks.append((cur_cmd, "\n".join(cur_out)))

        for cmd, out in blocks:
            if not out or len(out) < 60:
                continue
            proof = _extract_curl_proof(cmd, out, True)
            if not proof:
                continue
            blobs = _extract_json_blobs(out)
            if not blobs:
                continue
            # flatten: single object with array field → use that array
            records = []
            for b in blobs:
                if isinstance(b, list):
                    records.extend(b)
                elif isinstance(b, dict):
                    # look for a common array field
                    arr_field = None
                    for k, v in b.items():
                        if isinstance(v, list) and len(v) > 0:
                            arr_field = k
                            break
                    if arr_field:
                        records.extend(b[arr_field])
                    elif len(b) >= 3:
                        records.append(b)
            if not records:
                continue
            entity = _entity_of(proof["url"])
            key = f"{entity}|{proof['url'].split('?')[0]}"
            bucket = by_entity.setdefault(key, {
                "entity": entity,
                "source_url": proof["url"],
                "source_cmd": cmd[:500],
                "ts": None,
                "records": [],
            })
            bucket["records"].extend(records[:500])
            try:
                bucket["ts"] = max(bucket["ts"] or "", rd.name)
            except Exception:
                pass

    out = []
    for k, v in by_entity.items():
        if not v["records"]:
            continue
        # dedupe by json string
        seen = set()
        uniq = []
        for r in v["records"]:
            try:
                s = json.dumps(r, sort_keys=True, default=str)
            except Exception:
                continue
            if s in seen:
                continue
            seen.add(s)
            uniq.append(r)
        v["records"] = uniq[:2000]
        v["count"] = len(uniq)
        out.append(v)
    return sorted(out, key=lambda x: -x["count"])


def leaks_by_section(target: str) -> dict:
    """Group leaked records by section name (entity) with plural aliases."""
    out = {}
    for l in leaks(target):
        key = (l.get("entity") or "unknown").lower().strip()
        if not key:
            continue
        out.setdefault(key, []).extend(l.get("records", [])[:2000])
        # common plural aliases so users/users and user/user both resolve
        if not key.endswith("s"):
            out.setdefault(key + "s", out[key])
        else:
            out.setdefault(key[:-1], out[key])
    return out


def summary(target: str) -> dict:
    """Roll up the recorder into a compact structure the UI builder
    can consume cheaply."""
    events = read(target)
    out = {
        "target": target,
        "events": len(events),
        "first_seen": events[0]["ts"] if events else None,
        "last_seen":  events[-1]["ts"] if events else None,
        "commands": [],   # (ts, cmd, short output)
        "findings": [],
        "probes": [],
        "walks": [],
        "secrets": [],
        "creds": [],
        "loot": [],
        "successful_reads": [],
        "successful_writes": [],
        "endpoints": [],
    }
    for e in events:
        k = e.get("kind")
        if k == "command":
            out["commands"].append({
                "ts": e.get("ts"),
                "cmd": e.get("cmd", "")[:500],
                "out": (e.get("output") or "")[:1000],
                "ok": e.get("ok"),
            })
        elif k == "finding":
            out["findings"].append({
                "ts": e.get("ts"),
                "sev": e.get("sev"),
                "title": e.get("title", "")[:200],
                "evidence": (e.get("evidence") or "")[:800],
            })
        elif k == "probe":
            out["probes"].append({
                "ts": e.get("ts"),
                "method": e.get("method"),
                "url": e.get("url"),
                "unauth_2xx": e.get("unauth_2xx"),
            })
        elif k == "walk":
            out["walks"].append({
                "ts": e.get("ts"),
                "method": e.get("method"),
                "url": e.get("url"),
                "param": e.get("param"),
                "hits": e.get("hits"),
                "sample": (e.get("sample") or "")[:400],
            })
        elif k == "secret":
            out["secrets"].append({
                "ts": e.get("ts"),
                "kind_name": e.get("kind_name"),
                "value": (e.get("value") or "")[:200],
                "path": e.get("path"),
            })
        elif k == "cred":
            out["creds"].append({
                "ts": e.get("ts"),
                "user": e.get("user"),
                "pass_len": len(e.get("pass", "") or ""),
                "where": e.get("where"),
            })
        elif k == "loot":
            out["loot"].append({
                "ts": e.get("ts"),
                "kind_name": e.get("kind_name"),
                "value": (e.get("value") or "")[:200],
            })
        elif k == "endpoint":
            out["endpoints"].append({
                "ts": e.get("ts"),
                "method": e.get("method"),
                "url": e.get("url"),
                "note": e.get("note"),
            })
        elif k == "result":
            if e.get("verb") == "read" and e.get("ok"):
                out["successful_reads"].append(e)
            if e.get("verb") in ("write", "patch", "delete", "create") and e.get("ok"):
                out["successful_writes"].append(e)
    out["sections"] = sections(target)
    out["http_proofs"] = http_proofs(target)
    try:
        out["leaks"] = leaks(target)
    except Exception:
        out["leaks"] = []
    try:
        out["leaks_by_section"] = leaks_by_section(target)
    except Exception:
        out["leaks_by_section"] = {}
    return out
