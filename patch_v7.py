#!/usr/bin/env python3
"""patch_v7.py — upgrade ag v6 -> v7

Adds ~50 tools, 8 new directives (EXPLOIT/SHELL/LOOT/CRACK/PIVOT/STATUS/CHAIN/ATTACK),
attack phase with per-step approval, loot folders, auto-crack, reporter upgrade.

Idempotent — safe to run twice. Backups written as *.v6.bak
"""
import pathlib, sys, shutil, re, ast

HERE = pathlib.Path(__file__).parent
AGENT = HERE / "agent.py"
REPORTER = HERE / "reporter.py"

if not AGENT.exists() or not REPORTER.exists():
    print("error: agent.py and reporter.py must be in the same dir")
    sys.exit(1)

src = AGENT.read_text()
rsc = REPORTER.read_text()

if "─── v7 additions" in src:
    print("[patch] already patched (v7 additions found). nothing to do.")
    sys.exit(0)

shutil.copy(AGENT, str(AGENT) + ".v6.bak")
shutil.copy(REPORTER, str(REPORTER) + ".v6.bak")
print("[patch] backups: agent.py.v6.bak, reporter.py.v6.bak")

# ─── 1. RECIPES additions ───────────────────────────────────────────────────
NEW_RECIPES = '''    # ─── v7 additions ────────────────────────────────────────────────
    "sliver":          ("command -v sliver-server", "curl -fsSL https://sliver.sh/install | sudo bash"),
    "certipy":         ("command -v certipy", "pipx install certipy-ad"),
    "rubeus":          ("test -d ~/agent/tools/Rubeus", "git clone --depth 1 https://github.com/GhostPack/Rubeus.git ~/agent/tools/Rubeus"),
    "gopherus":        ("command -v gopherus", "git clone --depth 1 https://github.com/tarunkant/Gopherus.git ~/agent/tools/Gopherus && ln -sf ~/agent/tools/Gopherus/gopherus.py ~/agent/tools/gopherus && chmod +x ~/agent/tools/gopherus"),
    "sstimap":         ("command -v sstimap", "pipx install sstimap"),
    "jwttool":         ("command -v jwt_tool_cli", "git clone --depth 1 https://github.com/ticarpi/jwt_tool.git ~/agent/tools/jwt_tool && ln -sf ~/agent/tools/jwt_tool/jwt_tool.py ~/agent/tools/jwt_tool_cli && chmod +x ~/agent/tools/jwt_tool_cli"),
    "hakrawler":       ("command -v hakrawler", "go install github.com/hakluke/hakrawler@latest"),
    "paramspider":     ("command -v paramspider", "pipx install paramspider"),
    "aquatone":        ("command -v aquatone", "go install github.com/michenriksen/aquatone@latest"),
    "sn1per":          ("test -d ~/agent/tools/Sn1per", "git clone --depth 1 https://github.com/1N3/Sn1per.git ~/agent/tools/Sn1per"),
    "cewl":            ("command -v cewl", "gem install cewl"),
    "cupp":            ("command -v cupp_cli", "git clone --depth 1 https://github.com/Mebus/cupp.git ~/agent/tools/cupp && ln -sf ~/agent/tools/cupp/cupp.py ~/agent/tools/cupp_cli && chmod +x ~/agent/tools/cupp_cli"),
    "interactsh":      ("command -v interactsh-client", "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    "ysoserial":       ("test -f ~/agent/tools/ysoserial.jar", "curl -fsSL -o ~/agent/tools/ysoserial.jar https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar"),
    "marshalsec":      ("test -f ~/agent/tools/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar", "git clone --depth 1 https://github.com/mbechler/marshalsec.git ~/agent/tools/marshalsec"),
    "xxeinjector":     ("test -f ~/agent/tools/XXEinjector/XXEinjector.rb", "git clone --depth 1 https://github.com/enjoiz/XXEinjector.git ~/agent/tools/XXEinjector"),
    "clairvoyance":    ("command -v clairvoyance", "pipx install clairvoyance"),
    "coercer":         ("command -v coercer", "pipx install coercer"),
    "petitpotam":      ("test -f ~/agent/tools/PetitPotam.py", "curl -fsSL -o ~/agent/tools/PetitPotam.py https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py"),
    "havoc":           ("test -d ~/agent/tools/Havoc", "git clone --depth 1 https://github.com/HavocFramework/Havoc.git ~/agent/tools/Havoc"),
    "nimplant":        ("test -d ~/agent/tools/NimPlant", "git clone --depth 1 https://github.com/chvancooten/NimPlant.git ~/agent/tools/NimPlant"),
    "mythic":          ("test -d ~/agent/tools/Mythic", "git clone --depth 1 https://github.com/its-a-feature/Mythic.git ~/agent/tools/Mythic"),
    "pypykatz":        ("command -v pypykatz", "pipx install pypykatz"),
    "mitm6":           ("command -v mitm6", "pipx install mitm6"),
    "kerbrute":        ("command -v kerbrute", "go install github.com/ropnop/kerbrute@latest"),
    "windapsearch":    ("command -v windapsearch", "go install github.com/ropnop/windapsearch@latest"),
    "adidnsdump":      ("command -v adidnsdump", "pipx install adidnsdump"),
    "sharphound":      ("test -f ~/agent/tools/SharpHound.ps1", "curl -fsSL -o ~/agent/tools/SharpHound.ps1 https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1"),
    "evil-winrm":      ("command -v evil-winrm", "gem install evil-winrm"),
    "hashid":          ("command -v hashid", "pipx install hashid"),
    "haiti":           ("command -v haiti", "gem install haiti-hash"),
    "name-that-hash":  ("command -v nth", "pipx install name-that-hash"),
    "recon-ng":        ("command -v recon-ng", "pipx install recon-ng"),
    "dnsgen":          ("command -v dnsgen", "pipx install dnsgen"),
    "shuffledns":      ("command -v shuffledns", "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),
    "sublist3r":       ("command -v sublist3r", "pipx install sublist3r"),
    "knockpy":         ("command -v knockpy", "pipx install knockpy"),
    "gospider":        ("command -v gospider", "go install github.com/jaeles-project/gospider@latest"),
    "waymore":         ("command -v waymore", "pipx install waymore"),
    "puredns":         ("command -v puredns", "go install github.com/d3mondev/puredns/v2@latest"),
    "gron":            ("command -v gron", "go install github.com/tomnomnom/gron@latest"),
    "httprobe":        ("command -v httprobe", "go install github.com/tomnomnom/httprobe@latest"),
    "notify":          ("command -v notify", "go install -v github.com/projectdiscovery/notify/cmd/notify@latest"),
    "jsluice":         ("command -v jsluice", "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"),
    "evilginx":        ("test -d ~/agent/tools/evilginx2", "git clone --depth 1 https://github.com/kgretzky/evilginx2.git ~/agent/tools/evilginx2"),
    "xnLinkFinder":    ("command -v xnLinkFinder", "pipx install xnLinkFinder"),
    "subzy":           ("command -v subzy", "go install -v github.com/LukaSikic/subzy@latest"),
    "gau-custom":      ("command -v gau", "go install -v github.com/lc/gau/v2/cmd/gau@latest"),
'''

src = src.replace(
    '    "graphql-cop": ("command -v graphql-cop", "pipx install graphql-cop || pip install --user graphql-cop"),\n}',
    '    "graphql-cop": ("command -v graphql-cop", "pipx install graphql-cop || pip install --user graphql-cop"),\n' + NEW_RECIPES + '}'
)

# ─── 2. new PATTERNS ────────────────────────────────────────────────────────
src = src.replace(
    '    "REPORT":    r"REPORT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n}',
    '    "REPORT":    r"REPORT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "EXPLOIT":   r"EXPLOIT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "SHELL":     r"SHELL:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "LOOT":      r"LOOT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "CRACK":     r"CRACK:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "PIVOT":     r"PIVOT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "STATUS":    r"STATUS:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n'
    '    "CHAIN":     r"CHAIN:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",\n}'
)

# ─── 3. state additions ─────────────────────────────────────────────────────
src = src.replace(
    '"tech_stack": [], "web_searches": [], "_auto_probe_queue": [],\n            "_auto_probed": []}',
    '"tech_stack": [], "web_searches": [], "_auto_probe_queue": [],\n'
    '            "_auto_probed": [], "attacks": [], "loot": [], "chains": [],\n'
    '            "attack_summary": {"attempted": 0, "succeeded": 0, "chained": 0}}'
)

# ─── 4. loot folders ────────────────────────────────────────────────────────
src = src.replace(
    '"01_raw","02_parsed","03_extracts","04_screenshots","leak","web"):',
    '"01_raw","02_parsed","03_extracts","04_screenshots","leak","web",\n'
    '                "loot/hashes","loot/creds","loot/tokens","loot/shells","loot/data",\n'
    '                "attacks"):'
)

# ─── 5. attack mode flag + new dispatch helpers ─────────────────────────────
ATTACK_HELPERS = '''

# ── attack mode flag + helpers ──────────────────────────────────────────────
_ATTACK_MODE = False
_AUTO_YES = False

def _confirm_attack(cmd):
    """In attack mode, ask the operator y/N before running."""
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

def do_exploit(spec, run_dir, state):
    """EXPLOIT: <tool>|<target>|<args>"""
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
    summ["attempted"] += 1
    ok = bool(out) and not re.search(r"\\b(failed|denied|refused|error)\\b", out[:200], re.I)
    if ok:
        entry["result"] = "success"
        summ["succeeded"] += 1
    save_state(run_dir, state)
    _live_finding(f"[ATTACK {aid}] {tool} {target} -> {entry['result']}")
    return f"[{aid}] {entry['result']}: {out[:600]}"

def do_shell(spec, run_dir, state):
    """SHELL: <kind>|<lhost>|<lport> — records intent (manual launch required)"""
    parts = [p.strip() for p in spec.split("|")]
    if len(parts) < 3:
        return "ERROR: SHELL needs 'kind|lhost|lport'"
    kind, lh, lp = parts[0], parts[1], parts[2]
    aid = f"S{len(state.get('attacks', []))+1}"
    note = f"MANUAL: launch {kind} listener on {lh}:{lp}. Attach after target connects."
    state.setdefault("attacks", []).append({
        "id": aid, "spec": spec, "target": f"{lh}:{lp}", "tool": "shell-intent",
        "command": note, "started": datetime.now().isoformat(),
        "result": "intent_recorded", "output": note, "loot": None})
    save_state(run_dir, state)
    _live_finding(f"[SHELL-INTENT {aid}] {note}")
    return note

def do_loot(spec, run_dir, state):
    """LOOT: <kind>|<value_or_path>"""
    parts = spec.split("|", 1)
    if len(parts) != 2:
        return "ERROR: LOOT needs 'kind|value_or_path'"
    kind, val = parts[0].strip().lower(), parts[1].strip()
    sub = {"hash":"hashes","password":"creds","cred":"creds","token":"tokens",
           "jwt":"tokens","shell":"shells","data":"data"}.get(kind, "data")
    d = run_dir / "loot" / sub
    d.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9]+","_",val)[:60] or "item"
    p = d / f"{slug}.txt"
    try:
        p.write_text(val)
    except Exception as e:
        return f"LOOT write failed: {e}"
    state.setdefault("loot", []).append({
        "kind": kind, "value": val[:300], "path": str(p),
        "ts": datetime.now().isoformat()})
    save_state(run_dir, state)
    _live_finding(f"[LOOT:{kind}] {val[:100]}")
    # auto-crack if it looks like a hash
    if kind in ("hash",) and re.fullmatch(r"\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", val):
        try:
            hid = detect_hash_mode(val)
            _live_print(f"  [auto-crack] hashcat mode {hid}")
        except Exception:
            pass
    return f"loot stored: {p}"

def detect_hash_mode(h):
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"): return 3200
    if re.fullmatch(r"[a-f0-9]{32}", h): return 0
    if re.fullmatch(r"[a-f0-9]{40}", h): return 100
    if re.fullmatch(r"[a-f0-9]{64}", h): return 1400
    return 0

def do_crack(spec, run_dir, state):
    """CRACK: <hash>|<mode_or_auto>"""
    parts = spec.split("|", 1)
    if len(parts) != 2:
        return "ERROR: CRACK needs 'hash|mode_or_auto'"
    h, mode = parts[0].strip(), parts[1].strip()
    if mode.lower() == "auto":
        mode = str(detect_hash_mode(h))
    hf = run_dir / "loot" / "hashes" / "crack_target.txt"
    hf.parent.mkdir(parents=True, exist_ok=True)
    hf.write_text(h)
    wl = "/usr/share/wordlists/rockyou.txt"
    if not os.path.exists(wl):
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

def do_pivot(spec, run_dir, state):
    """PIVOT: <target>|<creds_ref>"""
    parts = spec.split("|", 1)
    if len(parts) != 2:
        return "ERROR: PIVOT needs 'target|creds_ref'"
    target, creds = parts[0].strip(), parts[1].strip()
    note = f"pivot candidate: use {creds} against {target}"
    state.setdefault("chains", []).append({"from": creds, "to": target,
                                           "ts": datetime.now().isoformat()})
    save_state(run_dir, state)
    return note

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

def do_chain(spec, run_dir, state):
    """CHAIN: <from_attack_id>|<to_attack_id>|<note>"""
    parts = [p.strip() for p in spec.split("|", 2)]
    if len(parts) < 2:
        return "ERROR: CHAIN needs 'from|to[|note]'"
    state.setdefault("chains", []).append({
        "from": parts[0], "to": parts[1],
        "note": parts[2] if len(parts) > 2 else "",
        "ts": datetime.now().isoformat()})
    state.setdefault("attack_summary", {"attempted":0,"succeeded":0,"chained":0})["chained"] += 1
    save_state(run_dir, state)
    return f"chain recorded: {parts[0]} -> {parts[1]}"

def collect_attackables(state):
    """Return list of (id, description, severity) for findings worth attacking."""
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
'''

src = src.replace(
    '''# ── dispatch helpers ───────────────────────────────────────────────────────
def do_probe(spec, run_dir):''',
    ATTACK_HELPERS + '''
# ── dispatch helpers ───────────────────────────────────────────────────────
def do_probe(spec, run_dir):'''
)

# ─── 6. dispatch routing for new directives ─────────────────────────────────
src = src.replace(
    '''    if kind == "REPORT":
        if not _HAVE_REPORTER:
            return "REPORT: reporter module not available (check ~/agent/reporter.py)"
        try:
            pdf = _gen_reports(run_dir, state, log=_live_print)
            return "report generated: REPORT.md + report.html" + (f" + {pdf}" if pdf else "")
        except Exception as e:
            return f"REPORT failed: {e}"
    return f"unknown: {kind}"''',
    '''    if kind == "REPORT":
        if not _HAVE_REPORTER:
            return "REPORT: reporter module not available (check ~/agent/reporter.py)"
        try:
            pdf = _gen_reports(run_dir, state, log=_live_print)
            return "report generated: REPORT.md + report.html" + (f" + {pdf}" if pdf else "")
        except Exception as e:
            return f"REPORT failed: {e}"
    if kind == "EXPLOIT": return do_exploit(payload, run_dir, state)
    if kind == "SHELL":   return do_shell(payload, run_dir, state)
    if kind == "LOOT":    return do_loot(payload, run_dir, state)
    if kind == "CRACK":   return do_crack(payload, run_dir, state)
    if kind == "PIVOT":   return do_pivot(payload, run_dir, state)
    if kind == "STATUS":  return do_status(payload, run_dir, state)
    if kind == "CHAIN":   return do_chain(payload, run_dir, state)
    return f"unknown: {kind}"'''
)

# ─── 7. color dict additions ────────────────────────────────────────────────
src = src.replace(
    '''                     "SEARCH":"blue","FETCH":"blue","REPORT":"cyan"}.get(kind,"gray")''',
    '''                     "SEARCH":"blue","FETCH":"blue","REPORT":"cyan",
                     "EXPLOIT":"red","SHELL":"red","LOOT":"mag","CRACK":"yellow",
                     "PIVOT":"mag","STATUS":"cyan","CHAIN":"green"}.get(kind,"gray")'''
)

# ─── 8. attack phase function ───────────────────────────────────────────────
ATTACK_PHASE = '''

def attack_phase(run_dir, state, target):
    """Interactive attack phase. Lists attackables, operator picks each."""
    global _ATTACK_MODE
    _ATTACK_MODE = True
    hr()
    banner(f"  ATTACK PHASE", "red")
    banner(f"  attackables will be listed. You approve each.", "yellow")
    hr()

    attackables = collect_attackables(state)
    if not attackables:
        banner(f"  nothing attackable found (no high/med findings, no IDOR, no secrets).", "yellow")
        return run_dir, state

    print(f"{C['bold']}attackable findings:{C['rst']}")
    for aid, desc, sev, ev in attackables:
        print(f"  {C['red']}{aid}{C['rst']}  [{sev}] {desc}")
        if ev:
            print(f"       {C['dim']}{ev[:120]}{C['rst']}")
    print()
    print(f"{C['bold']}commands:{C['rst']}")
    print(f"  all            — attack every finding, prompt y/N each step")
    print(f"  A1 A3          — attack specific findings by ID")
    print(f"  skip / done    — leave attack phase")
    print()

    choice = input(f"{C['bold']}attack> {C['rst']}").strip()

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

    print()
    print(f"{C['bold']}selected {len(targets)} target(s). y/N each step. Ctrl+C to abort.{C['rst']}")
    print()

    for aid, desc, sev, ev in targets:
        print()
        hr()
        banner(f"  [{aid}] {desc}", "red")
        if ev:
            print(f"  evidence: {ev[:200]}")
        hr()

        # build an attack task for the model
        attack_task = (
            f"ATTACK MODE. Finding [{aid}]: {desc}. Severity: {sev}. "
            f"Evidence: {ev}. "
            f"Use EXPLOIT:, LOOT:, CRACK:, PIVOT:, CHAIN:, SEARCH:, FETCH:, "
            f"COMMAND: to attempt exploitation. Operator approves each EXPLOIT. "
            f"Record outcome. If 3 variants fail, respond DONE with reason. "
            f"Do NOT perform denial-of-service. Read + pivot only."
        )

        # setup attack-specific system context
        history = [
            {"role":"system","content": ATTACK_SYSTEM},
            {"role":"user","content":
                f"TARGET: {state.get('target')}\\nSCAN_DIR: {run_dir}\\n\\n{attack_task}\\n\\n"
                f"Loaded findings sample: {json.dumps(state.get('findings',[])[:5], indent=2)[:3000]}\\n\\n"
                f"Loaded loot sample: {json.dumps(state.get('loot',[])[:5], indent=2)[:1000]}\\n\\nBegin."},
        ]

        # mini loop — same structure, but capped and with _ATTACK_MODE on
        MAX_ATTACK_TURNS = 12
        for turn in range(MAX_ATTACK_TURNS):
            print(f"\\n{C['bold']}[attack turn {turn+1}/{MAX_ATTACK_TURNS}]{C['rst']}")
            try:
                full = generate(history)
            except Exception as e:
                print(f"  {C['red']}[ERROR] {e}{C['rst']}")
                break
            full = full.strip()
            history.append({"role":"assistant","content":full})

            if is_refusal(full):
                print(f"  {C['red']}[refusal]{C['rst']}")
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
                color = {"COMMAND":"blue","EXPLOIT":"red","SHELL":"red","LOOT":"mag",
                         "CRACK":"yellow","PIVOT":"mag","STATUS":"cyan","CHAIN":"green",
                         "SEARCH":"blue","FETCH":"blue","FINDING":"red","NOTE":"gray",
                         "INSTALL":"yellow"}.get(kind, "gray")
                print(f"  {C[color]}* {kind}{C['rst']} {C['dim']}{payload[:160]}{C['rst']}")
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
    banner(f"  {summ.get('attempted',0)} attempted, {summ.get('succeeded',0)} succeeded, "
           f"{summ.get('chained',0)} chained", "yellow")
    hr()
    return run_dir, state


ATTACK_SYSTEM = """You are in ATTACK MODE. The recon phase is done. Findings are recorded.

Your job: attempt exploitation of ONE finding at a time. The operator approves
every EXPLOIT: step. You do not run DDoS, do not flood, do not mass-scan.

Available directives in attack mode:
  EXPLOIT: <tool>|<target>|<args>      (tool from RECIPES or installed binary)
  SHELL: <kind>|<lhost>|<lport>        (records intent — operator launches manually)
  LOOT: <kind>|<value>                 (kind: hash|password|token|shell|data)
  CRACK: <hash>|auto                   (hashcat auto-detect mode + rockyou)
  PIVOT: <target>|<creds_ref>          (declares a pivot candidate)
  CHAIN: <from_id>|<to_id>|<note>      (A led to B)
  SEARCH: <query>                      (find CVEs, exploits, writeups)
  FETCH: <url>                         (read the writeup)
  COMMAND: <shell>                     (any shell — bounded)
  STATUS:                              (print attack_summary)
  NOTE:, FINDING:, ENDPOINT:           (as usual)

RULES:
1. ONE directive per turn. Operator confirms each EXPLOIT.
2. If a tool is missing, INSTALL it first. Auto-build from github works.
3. On failure: SEARCH the error, fetch the writeup, try ONE variant. Max 3 retries.
4. Do NOT perform denial-of-service, flood, or destructive writes.
5. Read + pivot only. Extract, don't damage.
6. When done with this finding, respond with ONLY: DONE <one-line outcome>
7. Record loot with LOOT:. Record attack with EXPLOIT:.
"""
'''

src = src.replace(
    '''# ─── cli ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":''',
    ATTACK_PHASE + '''
# ─── cli ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":'''
)

# ─── 9. final prompt update ─────────────────────────────────────────────────
src = src.replace(
    'print(f"{C[\'bold\']}go deeper or write report? (deeper/report){C[\'rst\']}")',
    'print(f"{C[\'bold\']}go deeper, write report, or attack? (deeper/report/attack){C[\'rst\']}")'
)

# ─── 10. __main__ loop update ───────────────────────────────────────────────
src = src.replace(
    '''    while True:
        ans = final_phase_prompt(run_dir, state)
        if ans.startswith("r"): break
        extra = input(f"{C['bold']}what to dig into? {C['rst']}").strip()
        if not extra: break
        run_dir, state = agent(extra, target, run_dir=run_dir, state=state)''',
    '''    while True:
        ans = final_phase_prompt(run_dir, state)
        if ans.startswith("r"): break
        if ans.startswith("a"):
            run_dir, state = attack_phase(run_dir, state, target)
            continue
        extra = input(f"{C['bold']}what to dig into? {C['rst']}").strip()
        if not extra: break
        run_dir, state = agent(extra, target, run_dir=run_dir, state=state)'''
)

# ─── 11. reporter.py additions ──────────────────────────────────────────────
REPORTER_PATCH = '''
    # ── attack log
    attacks = state.get("attacks", []) or []
    loot    = state.get("loot", []) or []
    chains  = state.get("chains", []) or []
    a_sum   = state.get("attack_summary", {}) or {}

    if attacks:
        M.append("## Attack Log")
        M.append("")
        M.append(f"Attempted: **{a_sum.get('attempted',0)}**  ")
        M.append(f"Succeeded: **{a_sum.get('succeeded',0)}**  ")
        M.append(f"Chained:   **{a_sum.get('chained',0)}**")
        M.append("")
        M.append("| ID | Tool | Target | Started | Ended | Result |")
        M.append("|---|---|---|---|---|---|")
        for a in attacks:
            M.append(f"| {a.get('id','')} | `{a.get('tool','')}` | `{a.get('target','')}` "
                     f"| {a.get('started','')} | {a.get('ended','')} | **{a.get('result','')}** |")
        M.append("")
        M.append("### Raw attack output")
        M.append("")
        for a in attacks[:30]:
            M.append(f"**{a.get('id','')} — {a.get('tool','')} {a.get('target','')}**")
            M.append("")
            M.append("```")
            M.append(_clip(a.get("output",""), 2000))
            M.append("```")
            M.append("")

    if loot:
        M.append("## Loot Inventory")
        M.append("")
        M.append("| Kind | Value (truncated) | Path |")
        M.append("|---|---|---|")
        for l in loot[:300]:
            M.append(f"| {l.get('kind','')} | `{(l.get('value','') or '')[:80]}` "
                     f"| `{l.get('path','')}` |")
        M.append("")

    if chains:
        M.append("## Exploit Chains")
        M.append("")
        M.append("```")
        for c in chains:
            note = f"  ({c.get('note')})" if c.get("note") else ""
            M.append(f"{c.get('from','')}  ->  {c.get('to','')}{note}")
        M.append("```")
        M.append("")
'''

rsc = rsc.replace(
    '''    # ── notes
    if notes:''',
    REPORTER_PATCH + '''
    # ── notes
    if notes:'''
)

# ─── 12. write files back ───────────────────────────────────────────────────
AGENT.write_text(src)
REPORTER.write_text(rsc)

# ─── 13. syntax check ───────────────────────────────────────────────────────
try:
    ast.parse(src); print("[patch] agent.py syntax ok")
except SyntaxError as e:
    print(f"[patch] agent.py SYNTAX ERROR: {e}")
    print("[patch] rolling back from backup")
    shutil.copy(str(AGENT) + ".v6.bak", AGENT)
    sys.exit(1)

try:
    ast.parse(rsc); print("[patch] reporter.py syntax ok")
except SyntaxError as e:
    print(f"[patch] reporter.py SYNTAX ERROR: {e}")
    print("[patch] rolling back reporter from backup")
    shutil.copy(str(REPORTER) + ".v6.bak", REPORTER)
    sys.exit(1)

print()
print("[patch] done. Restart agds to use the new version.")
print(f"[patch] new tools available via: INSTALL: <name>")
print(f"[patch] new directives: EXPLOIT: SHELL: LOOT: CRACK: PIVOT: STATUS: CHAIN:")
print(f"[patch] new prompt option: attack")
