#!/usr/bin/env python3
import pathlib, ast, shutil, sys

p = pathlib.Path("agent.py")
src = p.read_text()

need = {
    "_ATTACK_MODE":  "def _confirm_attack(" in src and "_ATTACK_MODE = False" in src,
    "attack_phase":  "def attack_phase(" in src,
    "ATTACK_SYSTEM": "ATTACK_SYSTEM = " in src,
    "collect_attackables": "def collect_attackables(" in src,
    "do_exploit":  "def do_exploit(" in src,
    "do_shell":    "def do_shell(" in src,
    "do_loot":     "def do_loot(" in src,
    "do_crack":    "def do_crack(" in src,
    "do_pivot":    "def do_pivot(" in src,
    "do_status":   "def do_status(" in src,
    "do_chain":    "def do_chain(" in src,
    "detect_hash_mode": "def detect_hash_mode(" in src,
    "_confirm_attack":  "def _confirm_attack(" in src,
}
missing = [k for k, v in need.items() if not v]
print("[fix] present:", [k for k, v in need.items() if v])
print("[fix] missing:", missing)

if not missing:
    print("[fix] nothing missing. restart agds and try attack.")
    sys.exit(0)

shutil.copy(p, str(p) + ".pre-fix.bak")
print("[fix] backup: agent.py.pre-fix.bak")

BLOCK = ""

if not need["_ATTACK_MODE"]:
    BLOCK += """
_ATTACK_MODE = False
_AUTO_YES = False
"""

if not need["_confirm_attack"]:
    BLOCK += """
def _confirm_attack(cmd):
    if not _ATTACK_MODE:
        return True
    if _AUTO_YES:
        return True
    print(f"  {C['red']}[EXPLOIT] {cmd}{C['rst']}")
    try:
        ans = input(f"  {C['yellow']}run? [y/N]: {C['rst']}").strip().lower()
    except Exception:
        ans = "n"
    return ans in ("y", "yes")
"""

if not need["detect_hash_mode"]:
    BLOCK += """
def detect_hash_mode(h):
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"): return 3200
    if re.fullmatch(r"[a-f0-9]{32}", h): return 0
    if re.fullmatch(r"[a-f0-9]{40}", h): return 100
    if re.fullmatch(r"[a-f0-9]{64}", h): return 1400
    return 0
"""

if not need["do_exploit"]:
    BLOCK += """
def do_exploit(spec, run_dir, state):
    parts = [p.strip() for p in spec.split("|", 2)]
    if len(parts) < 2:
        return "ERROR: EXPLOIT needs 'tool|target[|args]'"
    tool, target = parts[0], parts[1]
    args = parts[2] if len(parts) > 2 else ""
    cmd = f"{tool} {args} {target}".strip()
    if not _confirm_attack(cmd):
        return "REFUSED by operator"
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
    ok = bool(out) and not re.search(r"\\b(failed|denied|refused|error)\\b", out[:200], re.I)
    if ok:
        entry["result"] = "success"
        summ["succeeded"] = summ.get("succeeded", 0) + 1
    save_state(run_dir, state)
    _live_finding(f"[ATTACK {aid}] {tool} {target} -> {entry['result']}")
    return f"[{aid}] {entry['result']}: {out[:600]}"
"""

if not need["do_shell"]:
    BLOCK += """
def do_shell(spec, run_dir, state):
    parts = [p.strip() for p in spec.split("|")]
    if len(parts) < 3:
        return "ERROR: SHELL needs 'kind|lhost|lport'"
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
"""

if not need["do_loot"]:
    BLOCK += """
def do_loot(spec, run_dir, state):
    parts = spec.split("|", 1)
    if len(parts) != 2:
        return "ERROR: LOOT needs 'kind|value_or_path'"
    kind, val = parts[0].strip().lower(), parts[1].strip()
    sub = {"hash":"hashes","password":"creds","cred":"creds","token":"tokens",
           "jwt":"tokens","shell":"shells","data":"data"}.get(kind, "data")
    d = run_dir / "loot" / sub
    d.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9]+","_",val)[:60] or "item"
    fp = d / f"{slug}.txt"
    try:
        fp.write_text(val)
    except Exception as e:
        return f"LOOT write failed: {e}"
    state.setdefault("loot", []).append({
        "kind": kind, "value": val[:300], "path": str(fp),
        "ts": datetime.now().isoformat()})
    save_state(run_dir, state)
    _live_finding(f"[LOOT:{kind}] {val[:100]}")
    return f"loot stored: {fp}"
"""

if not need["do_crack"]:
    BLOCK += """
def do_crack(spec, run_dir, state):
    parts = spec.split("|", 1)
    if len(parts) != 2:
        return "ERROR: CRACK needs 'hash|mode_or_auto'"
    h, mode = parts[0].strip(), parts[1].strip()
    if mode.lower() == "auto":
        mode = str(detect_hash_mode(h))
    hf = run_dir / "loot" / "hashes" / "crack_target.txt"
    hf.parent.mkdir(parents=True, exist_ok=True)
    hf.write_text(h)
    wl = os.path.expanduser("~/agent/wordlists/rockyou.txt")
    cmd = f"hashcat -m {mode} -a 0 {hf} {wl} --quiet --potfile-path {run_dir}/loot/hashes/hashcat.pot"
    out = run_command(cmd, timeout=1800)
    cracked = ""
    try:
        potf = run_dir / "loot" / "hashes" / "hashcat.pot"
        if potf.exists():
            cracked = potf.read_text()
            (run_dir / "loot" / "hashes" / "cracked.txt").write_text(cracked)
    except Exception:
        pass
    return f"crack done (mode {mode}): {'cracked' if cracked else 'not cracked'} {out[:400]}"
"""

if not need["do_pivot"]:
    BLOCK += """
def do_pivot(spec, run_dir, state):
    parts = spec.split("|", 1)
    if len(parts) != 2:
        return "ERROR: PIVOT needs 'target|creds_ref'"
    target, creds = parts[0].strip(), parts[1].strip()
    note = f"pivot candidate: use {creds} against {target}"
    state.setdefault("chains", []).append({"from": creds, "to": target,
                                           "ts": datetime.now().isoformat()})
    save_state(run_dir, state)
    return note
"""

if not need["do_status"]:
    BLOCK += """
def do_status(spec, run_dir, state):
    summ = state.get("attack_summary", {})
    attacks = state.get("attacks", [])
    loot = state.get("loot", [])
    chains = state.get("chains", [])
    lines = [f"attack_summary: {summ}",
             f"attacks: {len(attacks)}",
             f"loot: {len(loot)}",
             f"chains: {len(chains)}"]
    for a in attacks[-10:]:
        lines.append(f"  {a.get('id')} {a.get('tool')} {a.get('target')} -> {a.get('result')}")
    return "\\n".join(lines)
"""

if not need["do_chain"]:
    BLOCK += """
def do_chain(spec, run_dir, state):
    parts = [p.strip() for p in spec.split("|", 2)]
    if len(parts) < 2:
        return "ERROR: CHAIN needs 'from|to[|note]'"
    state.setdefault("chains", []).append({
        "from": parts[0], "to": parts[1],
        "note": parts[2] if len(parts) > 2 else "",
        "ts": datetime.now().isoformat()})
    s = state.setdefault("attack_summary", {"attempted":0,"succeeded":0,"chained":0})
    s["chained"] = s.get("chained", 0) + 1
    save_state(run_dir, state)
    return f"chain recorded: {parts[0]} -> {parts[1]}"
"""

if not need["collect_attackables"]:
    BLOCK += """
def collect_attackables(state):
    out = []
    n = 1
    for f in state.get("findings", []):
        if (f.get("sev") or "").lower() in ("critical", "high", "medium"):
            out.append((f"A{n}", f.get("title","?"), f.get("sev","?"),
                        f.get("evidence","")[:200]))
            n += 1
    for w in state.get("walks", []):
        if w.get("hits", 0) > 0:
            out.append((f"W{n}", f"IDOR walk hits={w.get('hits')} on {w.get('url')}",
                        "high", f"param={w.get('param')}"))
            n += 1
    for s in state.get("secrets", []):
        out.append((f"S{n}", f"secret {s.get('kind')} from {s.get('path')}",
                    "medium", s.get("value","")[:80]))
        n += 1
    return out
"""

if not need["ATTACK_SYSTEM"]:
    BLOCK += '''
ATTACK_SYSTEM = """You are in ATTACK MODE. Recon is done.

Directives:
  EXPLOIT: <tool>|<target>|<args>
  SHELL: <kind>|<lhost>|<lport>
  LOOT: <kind>|<value>
  CRACK: <hash>|auto
  PIVOT: <target>|<creds_ref>
  CHAIN: <from_id>|<to_id>|<note>
  SEARCH: <query>
  FETCH: <url>
  COMMAND: <shell>
  STATUS:

RULES:
1. ONE directive per turn. Operator confirms each EXPLOIT with y/N.
2. Install missing tools first (INSTALL:).
3. On failure: SEARCH error, fetch writeup, try ONE variant. Max 3 retries.
4. NO denial-of-service. NO flood. NO destructive writes.
5. Read + pivot only.
6. When done, respond ONLY: DONE <outcome>.
7. Record loot with LOOT:. Record attacks with EXPLOIT:.
"""
'''

if not need["attack_phase"]:
    BLOCK += '''
def attack_phase(run_dir, state, target):
    global _ATTACK_MODE
    _ATTACK_MODE = True
    hr()
    banner(f"  ATTACK PHASE", "red")
    banner(f"  attackables will be listed. You approve each.", "yellow")
    hr()
    attackables = collect_attackables(state)
    if not attackables:
        banner(f"  nothing attackable found.", "yellow")
        _ATTACK_MODE = False
        return run_dir, state
    print(f"{C['bold']}attackable findings:{C['rst']}")
    for aid, desc, sev, ev in attackables:
        print(f"  {C['red']}{aid}{C['rst']}  [{sev}] {desc}")
        if ev:
            print(f"       {C['dim']}{ev[:120]}{C['rst']}")
    print()
    print(f"{C['bold']}commands: all | A1 A3 ... | skip{C['rst']}")
    try:
        choice = input(f"{C['bold']}attack> {C['rst']}").strip()
    except (EOFError, KeyboardInterrupt):
        _ATTACK_MODE = False
        return run_dir, state
    if choice.lower() in ("", "skip", "done", "quit", "q"):
        _ATTACK_MODE = False
        return run_dir, state
    if choice.lower() == "all":
        targets = attackables
    else:
        ids = choice.split()
        targets = [a for a in attackables if a[0] in ids]
    if not targets:
        print(f"{C['red']}no valid selection.{C['rst']}")
        _ATTACK_MODE = False
        return run_dir, state
    print(f"{C['bold']}selected {len(targets)} target(s). y/N each step.{C['rst']}")
    for aid, desc, sev, ev in targets:
        print()
        hr()
        banner(f"  [{aid}] {desc}", "red")
        if ev:
            print(f"  evidence: {ev[:200]}")
        hr()
        attack_task = (f"ATTACK MODE. Finding [{aid}]: {desc}. Severity: {sev}. "
                       f"Evidence: {ev}. Use EXPLOIT:, LOOT:, CRACK:, PIVOT:, CHAIN:, "
                       f"SEARCH:, FETCH:, COMMAND: to attempt exploitation. "
                       f"Operator approves each EXPLOIT. Record outcome. "
                       f"If 3 variants fail, respond DONE with reason. "
                       f"Do NOT perform denial-of-service.")
        history = [
            {"role":"system","content": ATTACK_SYSTEM},
            {"role":"user","content":
                f"TARGET: {state.get('target')}\\nSCAN_DIR: {run_dir}\\n\\n{attack_task}\\n\\n"
                f"Findings: {json.dumps(state.get('findings',[])[:5], indent=2)[:3000]}\\n\\nBegin."},
        ]
        for turn in range(12):
            print(f"\\n{C['bold']}[attack turn {turn+1}/12]{C['rst']}")
            try:
                full = generate(history)
            except Exception as e:
                print(f"  {C['red']}[ERROR] {e}{C['rst']}")
                break
            full = full.strip()
            history.append({"role":"assistant","content":full})
            if is_refusal(full):
                break
            actions = parse(full)
            has_action = len(actions) > 0
            said_done = bool(re.search(r"^\\s*DONE\\b", full, re.MULTILINE))
            if said_done and not has_action:
                print(f"\\n{C['green']}[{aid} DONE]{C['rst']}")
                break
            if not actions:
                history.append({"role":"user","content":"No directive. Emit EXPLOIT:/LOOT:/CRACK:/SEARCH:/COMMAND: or DONE."})
                continue
            results = []
            for kind, payload in actions[:2]:
                print(f"  {C['red']}* {kind}{C['rst']} {C['dim']}{payload[:160]}{C['rst']}")
                r = dispatch(kind, payload, run_dir, state)
                r_str = str(r)
                for line in r_str.splitlines()[:12]:
                    print(f"    {C['gray']}|{C['rst']} {line}")
                results.append(f"{kind} -> {r_str[:1500]}")
            history.append({"role":"user","content":"Results:\\n" + "\\n".join(results) + "\\n\\nNext directive, or DONE."})
    _ATTACK_MODE = False
    hr()
    banner(f"  attack phase complete.", "green")
    summ = state.get("attack_summary", {})
    banner(f"  {summ.get('attempted',0)} attempted, {summ.get('succeeded',0)} succeeded", "yellow")
    hr()
    return run_dir, state
'''

marker = 'if __name__ == "__main__":'
idx = src.find(marker)
if idx < 0:
    print("[fix] cannot find __main__ marker in agent.py")
    sys.exit(1)

new_src = src[:idx] + BLOCK + "\n" + src[idx:]

try:
    ast.parse(new_src)
except SyntaxError as e:
    print(f"[fix] syntax error: {e}")
    print("[fix] restoring backup")
    shutil.copy(str(p) + ".pre-fix.bak", p)
    sys.exit(1)

p.write_text(new_src)
print(f"[fix] added {len(BLOCK)} chars")
print("[fix] syntax ok")
print("[fix] done. restart agds and try attack.")
