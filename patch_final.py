#!/usr/bin/env python3
import pathlib, re, ast, shutil, sys

p = pathlib.Path("agent.py")
src = p.read_text()
changed = []

if "FAIL_PATTERNS" not in src:
    pat = re.compile(r'^(\s*)ok = bool\(out\) and not re\.search\(.+?\)\s*$', re.MULTILINE)
    m = pat.search(src)
    if m:
        ind = m.group(1)
        block = (
            f'{ind}FAIL_PATTERNS = (r"curl:\\s*\\(\\d+\\)", r"could not resolve",\n'
            f'{ind}                     r"connection (refused|timed out|reset)",\n'
            f'{ind}                     r"HTTP[:\\s]*[45]\\d\\d", r"HTTP[:\\s]*000",\n'
            f'{ind}                     r"\\berror\\b", r"\\bfailed\\b", r"\\bdenied\\b", r"\\brefused\\b",\n'
            f'{ind}                     r"syntax error", r"unterminated")\n'
            f'{ind}ok = bool(out) and not any(re.search(pp, out, re.I) for pp in FAIL_PATTERNS)'
        )
        src = src[:m.start()] + block + src[m.end():]
        changed.append("FAIL_PATTERNS")

if "%28" not in src:
    old = (
        '    if "curl" in low and "-m " not in low and "--max-time" not in low:\n'
        '        cmd = re.sub(r"\\bcurl\\b(?!\\s+-m\\b)(?!\\s+--max-time\\b)",\n'
        '                     f"curl -m {CURL_TIMEOUT}", cmd)'
    )
    new = (
        '    cmd = re.sub(r\'(https?://[^\\s\\\']*)\\(([^()]*)\\)\', r\'\\1%28\\2%29\', cmd)\n'
        + old
    )
    if old in src:
        src = src.replace(old, new)
        changed.append("URL-paren-encode")

NEW_PATTERNS = (
    '    "EXPLOIT":   r"EXPLOIT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "SHELL":     r"SHELL:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "LOOT":      r"LOOT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "CRACK":     r"CRACK:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "PIVOT":     r"PIVOT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "STATUS":    r"STATUS:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "CHAIN":     r"CHAIN:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
)
if '"EXPLOIT":' not in src:
    src = src.replace(
        '    "REPORT":    r"REPORT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n}',
        '    "REPORT":    r"REPORT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n' + NEW_PATTERNS + '}'
    )
    changed.append("PATTERNS")

if '"attacks": []' not in src and "'attacks': []" not in src:
    src = src.replace(
        '"tech_stack": [], "web_searches": [], "_auto_probe_queue": [],\n            "_auto_probed": []}',
        '"tech_stack": [], "web_searches": [], "_auto_probe_queue": [],\n'
        '            "_auto_probed": [], "attacks": [], "loot": [], "chains": [],\n'
        '            "attack_summary": {"attempted": 0, "succeeded": 0, "chained": 0}}'
    )
    changed.append("state")

if '"loot/hashes"' not in src:
    src = src.replace(
        '"01_raw","02_parsed","03_extracts","04_screenshots","leak","web"):',
        '"01_raw","02_parsed","03_extracts","04_screenshots","leak","web",\n'
        '                "loot/hashes","loot/creds","loot/tokens","loot/shells","loot/data",\n'
        '                "attacks"):'
    )
    changed.append("loot-folders")

if "def attack_phase(" not in src:
    BLOCK = r'''

_ATTACK_MODE = False
_AUTO_YES = False

def _confirm_attack(cmd):
    if not _ATTACK_MODE: return True
    if _AUTO_YES: return True
    print(f"  {C['red']}[EXPLOIT] {cmd}{C['rst']}")
    try: ans = input(f"  {C['yellow']}run? [y/N]: {C['rst']}").strip().lower()
    except Exception: ans = "n"
    return ans in ("y", "yes")

def detect_hash_mode(h):
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"): return 3200
    if re.fullmatch(r"[a-f0-9]{32}", h): return 0
    if re.fullmatch(r"[a-f0-9]{40}", h): return 100
    if re.fullmatch(r"[a-f0-9]{64}", h): return 1400
    return 0

def do_exploit(spec, run_dir, state):
    parts = [p.strip() for p in spec.split("|", 2)]
    if len(parts) < 2: return "ERROR: EXPLOIT needs 'tool|url_or_target[|args]'"
    tool, target = parts[0], parts[1]
    args = parts[2] if len(parts) > 2 else ""
    cmd = f"{tool} {args} {target}".strip()
    if not _confirm_attack(cmd): return "REFUSED by operator"
    started = datetime.now().isoformat()
    out = run_command(cmd, timeout=CMD_TIMEOUT)
    ended = datetime.now().isoformat()
    aid = f"A{len(state.get('attacks', []))+1}"
    entry = {"id": aid, "spec": spec, "target": target, "tool": tool,
             "command": cmd, "started": started, "ended": ended,
             "result": "attempted", "output": out[:4000], "loot": None}
    state.setdefault("attacks", []).append(entry)
    summ = state.setdefault("attack_summary", {"attempted":0,"succeeded":0,"chained":0})
    summ["attempted"] = summ.get("attempted", 0) + 1
    FAIL_LOCAL = (
        r"curl:\s*\(\d+\)", r"could not resolve",
        r"connection (refused|timed out|reset)",
        r"HTTP[:\s]*[45]\d\d", r"HTTP[:\s]*000",
        r"\berror\b", r"\bfailed\b", r"\bdenied\b", r"\brefused\b",
        r"syntax error", r"unterminated",
    )
    ok = bool(out) and not any(re.search(pp, out, re.I) for pp in FAIL_LOCAL)
    if ok:
        entry["result"] = "success"
        summ["succeeded"] = summ.get("succeeded", 0) + 1
    save_state(run_dir, state)
    _live_finding(f"[ATTACK {aid}] {tool} {target} -> {entry['result']}")
    return f"[{aid}] {entry['result']}: {out[:600]}"

def do_shell(spec, run_dir, state):
    parts = [p.strip() for p in spec.split("|")]
    if len(parts) < 3: return "ERROR: SHELL needs 'kind|lhost|lport'"
    kind, lh, lp = parts[0], parts[1], parts[2]
    aid = f"S{len(state.get('attacks', []))+1}"
    note = f"MANUAL: launch {kind} listener on {lh}:{lp}"
    state.setdefault("attacks", []).append({
        "id": aid, "spec": spec, "target": f"{lh}:{lp}", "tool": "shell-intent",
        "command": note, "started": datetime.now().isoformat(),
        "result": "intent_recorded", "output": note, "loot": None})
    save_state(run_dir, state)
    _live_finding(f"[SHELL-INTENT {aid}] {note}")
    return note

def do_loot(spec, run_dir, state):
    parts = spec.split("|", 1)
    if len(parts) != 2: return "ERROR: LOOT needs 'kind|value_or_path'"
    kind, val = parts[0].strip().lower(), parts[1].strip()
    sub = {"hash":"hashes","password":"creds","cred":"creds","token":"tokens",
           "jwt":"tokens","shell":"shells","data":"data"}.get(kind, "data")
    d = run_dir / "loot" / sub
    d.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9]+","_",val)[:60] or "item"
    fp = d / f"{slug}.txt"
    try: fp.write_text(val)
    except Exception as e: return f"LOOT write failed: {e}"
    state.setdefault("loot", []).append({
        "kind": kind, "value": val[:300], "path": str(fp),
        "ts": datetime.now().isoformat()})
    save_state(run_dir, state)
    _live_finding(f"[LOOT:{kind}] {val[:100]}")
    return f"loot stored: {fp}"

def do_crack(spec, run_dir, state):
    parts = spec.split("|", 1)
    if len(parts) != 2: return "ERROR: CRACK needs 'hash|mode_or_auto'"
    h, mode = parts[0].strip(), parts[1].strip()
    if mode.lower() == "auto": mode = str(detect_hash_mode(h))
    hf = run_dir / "loot" / "hashes" / "crack_target.txt"
    hf.parent.mkdir(parents=True, exist_ok=True); hf.write_text(h)
    wl = "/usr/share/wordlists/rockyou.txt"
    if not os.path.exists(wl): wl = os.path.expanduser("~/agent/wordlists/rockyou.txt")
    cmd = f"hashcat -m {mode} -a 0 {hf} {wl} --quiet --potfile-path {run_dir}/loot/hashes/hashcat.pot"
    out = run_command(cmd, timeout=1800)
    cracked = ""
    try:
        potf = run_dir / "loot" / "hashes" / "hashcat.pot"
        if potf.exists():
            cracked = potf.read_text()
            (run_dir / "loot" / "hashes" / "cracked.txt").write_text(cracked)
    except Exception: pass
    return f"crack done (mode {mode}): {'cracked' if cracked else 'not cracked'} {out[:400]}"

def do_pivot(spec, run_dir, state):
    parts = spec.split("|", 1)
    if len(parts) != 2: return "ERROR: PIVOT needs 'target|creds_ref'"
    target, creds = parts[0].strip(), parts[1].strip()
    note = f"pivot candidate: use {creds} against {target}"
    state.setdefault("chains", []).append({"from": creds, "to": target,
                                           "ts": datetime.now().isoformat()})
    save_state(run_dir, state)
    return note

def do_status(spec, run_dir, state):
    summ = state.get("attack_summary", {})
    attacks = state.get("attacks", []); loot = state.get("loot", []); chains = state.get("chains", [])
    lines = [f"attack_summary: {summ}", f"attacks: {len(attacks)}",
             f"loot: {len(loot)}", f"chains: {len(chains)}"]
    for a in attacks[-10:]:
        lines.append(f"  {a.get('id')} {a.get('tool')} {a.get('target')} -> {a.get('result')}")
    return "\n".join(lines)

def do_chain(spec, run_dir, state):
    parts = [p.strip() for p in spec.split("|", 2)]
    if len(parts) < 2: return "ERROR: CHAIN needs 'from|to[|note]'"
    state.setdefault("chains", []).append({
        "from": parts[0], "to": parts[1],
        "note": parts[2] if len(parts) > 2 else "",
        "ts": datetime.now().isoformat()})
    s = state.setdefault("attack_summary", {"attempted":0,"succeeded":0,"chained":0})
    s["chained"] = s.get("chained", 0) + 1
    save_state(run_dir, state)
    return f"chain recorded: {parts[0]} -> {parts[1]}"

def collect_attackables(state):
    out = []; n = 1
    for f in state.get("findings", []):
        if (f.get("sev") or "").lower() in ("critical", "high", "medium"):
            out.append((f"A{n}", f.get("title","?"), f.get("sev","?"),
                        f.get("evidence","")[:200])); n += 1
    for w in state.get("walks", []):
        if w.get("hits", 0) > 0:
            out.append((f"W{n}", f"IDOR walk hits={w.get('hits')} on {w.get('url')}",
                        "high", f"param={w.get('param')}")); n += 1
    for s in state.get("secrets", []):
        out.append((f"S{n}", f"secret {s.get('kind')} from {s.get('path')}",
                    "medium", s.get("value","")[:80])); n += 1
    return out

ATTACK_SYSTEM = """You are in ATTACK MODE. Recon is done.

DIRECTIVES:
  EXPLOIT: <tool>|<url_or_target>|<extra_args>

Example of a correct EXPLOIT:
  EXPLOIT: curl|https://target/api/endpoint|-s -X POST -H 'Content-Type: application/json' -d '{"x":1}'

Harness runs: <tool> <extra_args> <url_or_target>
Position 2 is ALWAYS the target URL. Do NOT put the HTTP method there.
Use `-X POST` for method, not a bare "POST" token.

Other directives:
  LOOT: <kind>|<value>          kind: hash|password|token|shell|data
  CRACK: <hash>|auto
  PIVOT: <target>|<creds_ref>
  CHAIN: <from_id>|<to_id>|<note>
  SEARCH: <query>
  FETCH: <url>
  COMMAND: <shell>
  STATUS:

RULES:
1. ONE directive per turn. Operator approves each EXPLOIT with y/N.
2. On failure: SEARCH error, fetch writeup, try ONE variant. Max 3 retries.
3. URLs with `(default)` MUST be %28/%29 encoded.
4. NO denial-of-service. NO flood. NO destructive writes. Read + pivot only.
5. When done, respond ONLY: DONE <outcome>.
6. Record loot with LOOT:. Record attacks with EXPLOIT:.
"""

def attack_phase(run_dir, state, target):
    global _ATTACK_MODE
    _ATTACK_MODE = True
    hr(); banner(f"  ATTACK PHASE", "red")
    banner(f"  attackables will be listed. You approve each.", "yellow"); hr()
    attackables = collect_attackables(state)
    if not attackables:
        banner(f"  nothing attackable found.", "yellow"); _ATTACK_MODE = False
        return run_dir, state
    print(f"{C['bold']}attackable findings:{C['rst']}")
    for aid, desc, sev, ev in attackables:
        print(f"  {C['red']}{aid}{C['rst']}  [{sev}] {desc}")
        if ev: print(f"       {C['dim']}{ev[:120]}{C['rst']}")
    print(); print(f"{C['bold']}commands: all | A1 A3 ... | skip{C['rst']}")
    try: choice = input(f"{C['bold']}attack> {C['rst']}").strip()
    except (EOFError, KeyboardInterrupt):
        _ATTACK_MODE = False; return run_dir, state
    if choice.lower() in ("", "skip", "done", "quit", "q"):
        _ATTACK_MODE = False; return run_dir, state
    if choice.lower() == "all": targets = attackables
    else:
        ids = choice.split()
        targets = [a for a in attackables if a[0] in ids]
    if not targets:
        print(f"{C['red']}no valid selection.{C['rst']}"); _ATTACK_MODE = False
        return run_dir, state
    print(f"{C['bold']}selected {len(targets)} target(s). y/N each step.{C['rst']}")
    for aid, desc, sev, ev in targets:
        print(); hr(); banner(f"  [{aid}] {desc}", "red")
        if ev: print(f"  evidence: {ev[:200]}")
        hr()
        attack_task = (f"ATTACK MODE. Finding [{aid}]: {desc}. Severity: {sev}. "
                       f"Evidence: {ev}. Use EXPLOIT:, LOOT:, CRACK:, PIVOT:, CHAIN:, "
                       f"SEARCH:, FETCH:, COMMAND:. Operator approves each EXPLOIT. "
                       f"If 3 variants fail, respond DONE with reason. "
                       f"Do NOT perform denial-of-service.")
        history = [
            {"role":"system","content": ATTACK_SYSTEM},
            {"role":"user","content":
                f"TARGET: {state.get('target')}\nSCAN_DIR: {run_dir}\n\n{attack_task}\n\n"
                f"Findings: {json.dumps(state.get('findings',[])[:5], indent=2)[:3000]}\n\nBegin."},
        ]
        for turn in range(12):
            print(f"\n{C['bold']}[attack turn {turn+1}/12]{C['rst']}")
            try: full = generate(history)
            except Exception as e:
                print(f"  {C['red']}[ERROR] {e}{C['rst']}"); break
            full = full.strip()
            history.append({"role":"assistant","content":full})
            if is_refusal(full): break
            actions = parse(full)
            has_action = len(actions) > 0
            said_done = bool(re.search(r"^\s*DONE\b", full, re.MULTILINE))
            if said_done and not has_action:
                print(f"\n{C['green']}[{aid} DONE]{C['rst']}"); break
            if not actions:
                history.append({"role":"user","content":"No directive. Emit EXPLOIT:/LOOT:/CRACK:/SEARCH:/COMMAND: or DONE."}); continue
            results = []
            for kind, payload in actions[:2]:
                print(f"  {C['red']}* {kind}{C['rst']} {C['dim']}{payload[:160]}{C['rst']}")
                r = dispatch(kind, payload, run_dir, state)
                r_str = str(r)
                for line in r_str.splitlines()[:12]:
                    print(f"    {C['gray']}|{C['rst']} {line}")
                results.append(f"{kind} -> {r_str[:1500]}")
            history.append({"role":"user","content":"Results:\n" + "\n".join(results) + "\n\nNext directive, or DONE."})
    _ATTACK_MODE = False
    hr(); banner(f"  attack phase complete.", "green")
    summ = state.get("attack_summary", {})
    banner(f"  {summ.get('attempted',0)} attempted, {summ.get('succeeded',0)} succeeded", "yellow"); hr()
    return run_dir, state
'''
    marker = 'if __name__ == "__main__":'
    idx = src.find(marker)
    if idx < 0:
        print("[patch] cannot find __main__ anchor"); sys.exit(1)
    src = src[:idx] + BLOCK + "\n" + src[idx:]
    changed.append("attack-phase")

if 'if kind == "EXPLOIT"' not in src:
    anchor = '''    if kind == "REPORT":
        if not _HAVE_REPORTER:
            return "REPORT: reporter module not available (check ~/agent/reporter.py)"
        try:
            pdf = _gen_reports(run_dir, state, log=_live_print)
            return "report generated: REPORT.md + report.html" + (f" + {pdf}" if pdf else "")
        except Exception as e:
            return f"REPORT failed: {e}"
    return f"unknown: {kind}"'''
    repl = anchor.replace(
        '    return f"unknown: {kind}"',
        '    if kind == "EXPLOIT": return do_exploit(payload, run_dir, state)\n'
        '    if kind == "SHELL":   return do_shell(payload, run_dir, state)\n'
        '    if kind == "LOOT":    return do_loot(payload, run_dir, state)\n'
        '    if kind == "CRACK":   return do_crack(payload, run_dir, state)\n'
        '    if kind == "PIVOT":   return do_pivot(payload, run_dir, state)\n'
        '    if kind == "STATUS":  return do_status(payload, run_dir, state)\n'
        '    if kind == "CHAIN":   return do_chain(payload, run_dir, state)\n'
        '    return f"unknown: {kind}"'
    )
    if anchor in src:
        src = src.replace(anchor, repl)
        changed.append("dispatch-routing")

if "deeper/report/attack" not in src:
    src = src.replace(
        "go deeper or write report? (deeper/report)",
        "go deeper, write report, or attack? (deeper/report/attack)"
    )
    changed.append("final-prompt")

if 'if ans.startswith("a")' not in src:
    old = '''    while True:
        ans = final_phase_prompt(run_dir, state)
        if ans.startswith("r"): break
        extra = input(f"{C['bold']}what to dig into? {C['rst']}").strip()
        if not extra: break
        run_dir, state = agent(extra, target, run_dir=run_dir, state=state)'''
    new = '''    while True:
        ans = final_phase_prompt(run_dir, state)
        if ans.startswith("r"): break
        if ans.startswith("a"):
            run_dir, state = attack_phase(run_dir, state, target)
            continue
        extra = input(f"{C['bold']}what to dig into? {C['rst']}").strip()
        if not extra: break
        run_dir, state = agent(extra, target, run_dir=run_dir, state=state)'''
    if old in src:
        src = src.replace(old, new)
        changed.append("main-attack-branch")

if not changed:
    print("[patch] nothing to do — already at v7")
    sys.exit(0)

shutil.copy(p, str(p) + ".v7.bak")
try: ast.parse(src)
except SyntaxError as e:
    print(f"[patch] SYNTAX ERROR: {e}")
    print("[patch] rolling back")
    shutil.copy(str(p) + ".v7.bak", p)
    sys.exit(1)

p.write_text(src)
print(f"[patch] applied: {changed}")
print("[patch] syntax ok")
print("[patch] backup: agent.py.v7.bak")
