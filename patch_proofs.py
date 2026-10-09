#!/usr/bin/env python3
import pathlib, re, ast, shutil, sys

HERE = pathlib.Path(__file__).parent
AGENT = HERE / "agent.py"
REPORTER = HERE / "reporter.py"

src = AGENT.read_text()
rsc = REPORTER.read_text()

if "PROOFS_DIR" in src:
    print("[patch] proofs already applied — nothing to do"); sys.exit(0)

shutil.copy(AGENT, str(AGENT) + ".pre-proofs.bak")
shutil.copy(REPORTER, str(REPORTER) + ".pre-proofs.bak")

if "hashlib" not in src.split("\n")[2]:
    src = src.replace(
        "import shutil, concurrent.futures, urllib.parse, html as html_mod",
        "import shutil, concurrent.futures, urllib.parse, html as html_mod, hashlib"
    )

src = src.replace(
    "LIVE_LOG = LIVE_CMD_LOG = LIVE_FIND_LOG = None",
    "LIVE_LOG = LIVE_CMD_LOG = LIVE_FIND_LOG = None\n"
    "PROOFS_DIR = None\nPROOFS_CMDS_SH = None\nPROOFS_CMDS_LOG = None\n"
    "PROOFS_CMDS_JSON = None\nPROOFS_LEAKED = None"
)

HELPERS = '''
def _looks_failed(out):
    if not out: return True
    FAILS = (
        r"curl:\\s*\\(\\d+\\)", r"could not resolve",
        r"connection (refused|timed out|reset)",
        r"HTTP[:\\s]*[45]\\d\\d", r"HTTP[:\\s]*000",
        r"\\berror\\b", r"\\bfailed\\b", r"\\bdenied\\b", r"\\brefused\\b",
        r"syntax error", r"unterminated",
    )
    return any(re.search(p, out, re.I) for p in FAILS)

def _extract_leaked(out, cmd):
    if not PROOFS_LEAKED or not out: return
    try:
        s = out.strip()
        if s.startswith("{") or s.startswith("["):
            try:
                json.loads(s)
                h = hashlib.sha1(s.encode()).hexdigest()[:12]
                (PROOFS_LEAKED / "json" / f"{h}.json").write_text(s)
            except Exception: pass
        user_pat = re.compile(
            r'"(email|fullName|full_name|name|phone|username|role|admin|is_admin|uid|user_id|userid)"\\s*:\\s*"([^"]{1,200})"',
            re.I)
        hits = list(user_pat.finditer(out))
        if hits:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fp = PROOFS_LEAKED / "users" / f"users_{ts}.txt"
            with open(fp, "a") as f:
                f.write(f"# from: {cmd[:200]}\\n")
                for h in hits[:1000]:
                    f.write(f"{h.group(1)}: {h.group(2)}\\n")
        hash_pat = re.compile(r"\\$2[aby]\\$\\d{2}\\$[./A-Za-z0-9]{53}|\\b[a-f0-9]{32,64}\\b")
        hashes = set(hash_pat.findall(out))
        if hashes:
            fp = PROOFS_LEAKED / "hashes" / "hashes.txt"
            with open(fp, "a") as f:
                for h in hashes: f.write(h + "\\n")
        jwt_pat = re.compile(r"eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+")
        jwts = set(jwt_pat.findall(out))
        if jwts:
            fp = PROOFS_LEAKED / "tokens" / "jwts.txt"
            with open(fp, "a") as f:
                for t in jwts: f.write(t + "\\n")
        pw_pat = re.compile(r'(?i)["\\']?(password|passwd|pwd|secret|api_key|apikey|token)["\\']?\\s*[:=]\\s*["\\']([^"\\']{4,128})["\\']', re.I)
        pws = [m.group(2) for m in pw_pat.finditer(out)]
        if pws:
            fp = PROOFS_LEAKED / "creds" / "passwords.txt"
            with open(fp, "a") as f:
                for p in set(pws): f.write(p + "\\n")
        if re.search(r'"role"\\s*:\\s*"admin"|"is_admin"\\s*:\\s*true|"admin"\\s*:\\s*true', out, re.I):
            fp = PROOFS_LEAKED / "dashboards" / "admins.txt"
            with open(fp, "a") as f:
                f.write(f"# from: {cmd[:200]}\\n{out[:4000]}\\n\\n")
    except Exception: pass

def _capture_proof(cmd, out):
    if not PROOFS_CMDS_SH or not out: return
    if _looks_failed(out): return
    if out.strip() in ("(no output)", "(empty)"): return
    if re.match(r"^\\s*command\\s+-v\\s+", cmd): return
    if re.match(r"^\\s*test\\s+-f\\s+", cmd): return
    if len(cmd) < 15 and not re.search(r"curl|http|nmap|httpx|subfinder|nuclei", cmd): return
    try:
        ts = datetime.now().isoformat()
        with open(PROOFS_CMDS_SH, "a") as f:
            f.write(f'echo "=== {ts} ==="\\n')
            f.write(cmd + "\\n\\n")
        with open(PROOFS_CMDS_LOG, "a") as f:
            f.write(f"\\n### [{ts}]\\n$ {cmd}\\n---\\n{out[:8000]}\\n")
        try:
            entries = json.loads(PROOFS_CMDS_JSON.read_text()) if PROOFS_CMDS_JSON.exists() else []
        except Exception:
            entries = []
        entries.append({"ts": ts, "cmd": cmd, "output": out[:8000]})
        PROOFS_CMDS_JSON.write_text(json.dumps(entries[-500:], indent=2))
        _extract_leaked(out, cmd)
    except Exception: pass

'''
src = src.replace("DENY = [\n", HELPERS + "DENY = [\n", 1)

src = src.replace(
    '''    out = "".join(accumulated).strip()[:16000]
    return out if out else "(no output)"''',
    '''    out = "".join(accumulated).strip()[:16000]
    out = out if out else "(no output)"
    try: _capture_proof(cmd, out)
    except Exception: pass
    return out'''
)

src = src.replace(
    '''                "loot/hashes","loot/creds","loot/tokens","loot/shells","loot/data",
                "attacks"):
        (d / sub).mkdir(parents=True, exist_ok=True)''',
    '''                "loot/hashes","loot/creds","loot/tokens","loot/shells","loot/data",
                "attacks",
                "proofs",
                "proofs/leaked_data/json",
                "proofs/leaked_data/users",
                "proofs/leaked_data/creds",
                "proofs/leaked_data/tokens",
                "proofs/leaked_data/hashes",
                "proofs/leaked_data/dashboards",
                "proofs/leaked_data/files",
                "proofs/leaked_data/collections"):
        (d / sub).mkdir(parents=True, exist_ok=True)'''
)

src = src.replace(
    '''    for p in (LIVE_LOG, LIVE_CMD_LOG, LIVE_FIND_LOG):
        pathlib.Path(p).write_text(f"# {os.path.basename(p)} — {datetime.now().isoformat()}\\n")
    return d''',
    '''    for p in (LIVE_LOG, LIVE_CMD_LOG, LIVE_FIND_LOG):
        pathlib.Path(p).write_text(f"# {os.path.basename(p)} — {datetime.now().isoformat()}\\n")

    global PROOFS_DIR, PROOFS_CMDS_SH, PROOFS_CMDS_LOG, PROOFS_CMDS_JSON, PROOFS_LEAKED
    PROOFS_DIR = d / "proofs"
    PROOFS_CMDS_SH = PROOFS_DIR / "commands.sh"
    PROOFS_CMDS_LOG = PROOFS_DIR / "commands.log"
    PROOFS_CMDS_JSON = PROOFS_DIR / "successful_commands.json"
    PROOFS_LEAKED = PROOFS_DIR / "leaked_data"
    PROOFS_CMDS_SH.write_text(
        "#!/bin/bash\\n"
        f"# Re-runnable proofs for scan: {d}\\n"
        "# Every command below executed successfully during the scan.\\n"
        "# Run each to verify findings still reproduce.\\n"
        "# NOTE: some commands are exploitation/write ops — not idempotent.\\n\\n"
        "set -o pipefail\\n"
        "export PATH=\\"$HOME/go/bin:$HOME/.cargo/bin:$HOME/agent/tools:$HOME/.local/bin:$PATH\\"\\n\\n"
    )
    PROOFS_CMDS_SH.chmod(0o755)
    (PROOFS_DIR / "README.txt").write_text(
        "PROOFS FOLDER\\n=============\\n\\n"
        "commands.sh               re-runnable bash of every successful command\\n"
        "commands.log              human log (cmd + output)\\n"
        "successful_commands.json  structured\\n"
        "leaked_data/json/         raw JSON responses\\n"
        "leaked_data/users/        user objects (name, email, role)\\n"
        "leaked_data/creds/        passwords, api keys\\n"
        "leaked_data/tokens/       JWTs\\n"
        "leaked_data/hashes/       bcrypt/md5/sha1/sha256\\n"
        "leaked_data/dashboards/   admin responses\\n"
        "leaked_data/files/        explicit PROOF: saves\\n"
        "leaked_data/collections/  DB collection dumps\\n\\n"
        "re-verify:  bash commands.sh\\n"
    )
    return d'''
)

src = src.replace(
    '''    "REPORT":    r"REPORT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",
    "EXPLOIT":''',
    '''    "REPORT":    r"REPORT:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",
    "PROOF":     r"PROOF:\\s*(.+?)(?=\\n[A-Z]+:\\s|\\Z)",
    "EXPLOIT":'''
)

src = src.replace(
    "def do_exploit(spec, run_dir, state):",
    '''def do_proof(spec, run_dir, state):
    parts = spec.split("|", 1)
    if len(parts) != 2: return "ERROR: PROOF needs 'label|content'"
    label, content = parts[0].strip(), parts[1].strip()
    if not PROOFS_DIR: return "PROOF: proofs not initialized"
    safe = re.sub(r"[^a-zA-Z0-9_\\-]+", "_", label)[:80] or "item"
    fp = PROOFS_DIR / "leaked_data" / "files" / f"{safe}.txt"
    try: fp.write_text(content)
    except Exception as e: return f"PROOF save failed: {e}"
    _capture_proof(f"# PROOF: {label}", content)
    _live_finding(f"[PROOF:{safe}] {content[:120]}")
    return f"proof saved: {fp}"

def do_exploit(spec, run_dir, state):'''
)

src = src.replace(
    '    if kind == "EXPLOIT": return do_exploit(payload, run_dir, state)',
    '    if kind == "EXPLOIT": return do_exploit(payload, run_dir, state)\n'
    '    if kind == "PROOF":   return do_proof(payload, run_dir, state)'
)

PROOF_RPT = '''
    # ── proofs
    proofs_dir = run_dir / "proofs"
    if proofs_dir.exists():
        M.append("## Proofs")
        M.append("")
        M.append(f"Location: `{proofs_dir}`")
        M.append("")
        M.append("- `commands.sh` — re-runnable script of every successful command")
        cmds_log = proofs_dir / "commands.log"
        if cmds_log.exists():
            M.append(f"- `commands.log` — full log ({cmds_log.stat().st_size} bytes)")
        leaked = proofs_dir / "leaked_data"
        if leaked.exists():
            for sub in sorted(leaked.iterdir()):
                if sub.is_dir():
                    count = sum(1 for _ in sub.iterdir())
                    if count:
                        M.append(f"- `leaked_data/{sub.name}/` — {count} file(s)")
        M.append("")
        M.append("### Leaked data samples")
        M.append("")
        for cat in ("users", "creds", "tokens", "hashes", "dashboards"):
            cat_dir = leaked / cat if leaked.exists() else None
            if not cat_dir or not cat_dir.exists(): continue
            for f in sorted(cat_dir.iterdir())[:3]:
                try: content = f.read_text()[:2000]
                except Exception: continue
                M.append(f"**{cat} / {f.name}**")
                M.append("")
                M.append("```")
                M.append(_clip(content, 1500))
                M.append("```")
                M.append("")

'''
rsc = rsc.replace("    # ── attack log", PROOF_RPT + "    # ── attack log", 1)

try: ast.parse(src)
except SyntaxError as e:
    print(f"[patch] agent syntax error: {e}")
    shutil.copy(str(AGENT) + ".pre-proofs.bak", AGENT); sys.exit(1)
try: ast.parse(rsc)
except SyntaxError as e:
    print(f"[patch] reporter syntax error: {e}")
    shutil.copy(str(REPORTER) + ".pre-proofs.bak", REPORTER); sys.exit(1)

AGENT.write_text(src)
REPORTER.write_text(rsc)
print("[patch] proofs added. syntax ok.")
print("[patch] backup: agent.py.pre-proofs.bak, reporter.py.pre-proofs.bak")
