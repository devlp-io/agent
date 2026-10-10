#!/usr/bin/env python3
"""
patch_v8_hardening.py

Surgical patches to agent_v8.py:
  1. deny list + scope-check helpers
  2. wire them into _run_shell
  3. line-anchored directive parser + fence stripping
  4. single current_client() call per summarization
  5. resume past MAX_TURNS now extends the session

Idempotent. Backs up to agent_v8.py.pre-hardening.bak before writing.
"""
import pathlib, sys, shutil, ast

HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE / "agent_v8.py"

if not AGENT.exists():
    print(f"[patch] not found: {AGENT}")
    sys.exit(1)

src = AGENT.read_text()
original = src
applied = []

# ───────────────────────────────────────────────────────────────────
# 1. deny + scope helpers, inserted above current_client()
# ───────────────────────────────────────────────────────────────────
if "_DENY_PATTERNS" not in src:
    anchor = 'def current_client():'
    helper = '''# ────────────────────────────────────────────────────────────────────
# harness-level deny list + scope check
# operator's line, not a moralizing check
# ────────────────────────────────────────────────────────────────────

_DENY_PATTERNS = (
    __import__("re").compile(r"\\brm\\s+(-[rRf]+\\s+)*/\\s*(?:$|[;&|])"),
    __import__("re").compile(r"\\bmkfs(?:\\.[a-z0-9]+)?\\b"),
    __import__("re").compile(r"\\bdd\\s+if=.*\\bof=/dev/"),
    __import__("re").compile(r"\\bfind\\s+/\\s+(?:-\\w+\\s+)*-delete"),
    __import__("re").compile(r":\\(\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\}\\s*;\\s*:"),
    __import__("re").compile(r"\\bchmod\\s+-R\\s+777\\s+/(?:\\s|$)"),
    __import__("re").compile(r">\\s*/dev/sd[a-z]\\b"),
)

def _is_denied(cmd):
    for p in _DENY_PATTERNS:
        if p.search(cmd):
            return True, p.pattern
    return False, None


_URL_IN_CMD = __import__("re").compile(r"https?://[^\\s\\"\\'|;&<>()]+")

def _scope_check_cmd(cmd):
    """Block any command whose URLs fall outside scope.txt (if scope.txt exists)."""
    if _scope is None:
        return True, None
    for u in _URL_IN_CMD.findall(cmd):
        ok, reason = _scope.in_scope(u, RUN_DIR)
        if not ok:
            return False, f"{u} — {reason}"
    return True, None


'''
    if anchor not in src:
        print("[patch] FATAL: anchor 'def current_client():' not found")
        sys.exit(1)
    src = src.replace(anchor, helper + anchor, 1)
    applied.append("1. deny + scope helpers")

# ───────────────────────────────────────────────────────────────────
# 2. wire deny + scope into _run_shell
# ───────────────────────────────────────────────────────────────────
if "_is_denied(cmd)" not in src:
    anchor = '''def _run_shell(cmd, timeout=None):
    base_timeout = timeout if timeout else CMD_TIMEOUT
    low = cmd.lower()

    # inject curl timeout'''
    replacement = '''def _run_shell(cmd, timeout=None):
    base_timeout = timeout if timeout else CMD_TIMEOUT
    low = cmd.lower()

    denied, pat = _is_denied(cmd)
    if denied:
        return f"[DENIED] command matched pattern: {pat}"

    ok, why = _scope_check_cmd(cmd)
    if not ok:
        return f"[SCOPE BLOCK] {why}"

    # inject curl timeout'''
    if anchor not in src:
        print("[patch] FATAL: _run_shell anchor not found")
        sys.exit(1)
    src = src.replace(anchor, replacement, 1)
    applied.append("2. wire deny + scope into _run_shell")

# ───────────────────────────────────────────────────────────────────
# 3. replace PATTERNS dict + parse() with line-anchored version
# ───────────────────────────────────────────────────────────────────
if "_DIRECTIVE_NAMES" not in src:
    start = src.find("PATTERNS = {")
    parse_start = src.find("def parse(msg):")
    if start < 0 or parse_start < 0:
        print("[patch] FATAL: PATTERNS or parse() not found")
        sys.exit(1)
    end = src.index("    return out", parse_start) + len("    return out")

    new_block = '''_DIRECTIVE_NAMES = [
    "COMMAND", "PARALLEL", "INSTALL", "NEED_TOOL", "TOOLS", "FILE", "LIST",
    "NOTE", "FINDING", "ENDPOINT", "PROBE", "PLAN", "PAYLOAD", "SECRET",
    "CRED", "SCREENSHOT", "CVE", "METHOD", "PARAMFIND", "WALK", "APIMAP",
    "HARVEST", "SEARCH", "FETCH", "REPORT", "PROOF", "EXPLOIT", "SHELL",
    "LOOT", "CRACK", "PIVOT", "STATUS", "CHAIN", "BROWSER", "GRAPHQL",
    "WS", "OOB", "MUTATE", "CHAIN_AUTO", "HAR", "BUDGET", "TUI", "WAF",
    "STACK",
]

# line-anchored: directive must start at column 0 (after optional spaces),
# on its own line — prevents mid-sentence and mid-code-block matches.
PATTERNS = {
    name: rf"(?:^|\\n)\\s*{name}:\\s*(.+?)(?=\\n[A-Z_]+:\\s|\\Z)"
    for name in _DIRECTIVE_NAMES
}

# strip fenced code blocks so the model's examples don't trigger execution
_FENCE = re.compile(r"```.*?```", re.DOTALL)


def parse(msg):
    """Split model output into (directive, payload) pairs.
    Fenced code blocks are stripped first — the model uses them for
    examples and they must never be executed."""
    msg = _FENCE.sub("", msg)
    msg = re.sub(r"\\s+\\|\\|\\|\\s+(?=[A-Z_]+:\\s)", "\\n", msg)
    out = []
    for kind, pat in PATTERNS.items():
        for m in re.finditer(pat, msg, re.DOTALL):
            out.append((kind, m.group(1).strip()))
    return out'''

    src = src[:start] + new_block + src[end:]
    applied.append("3. line-anchored parser + fence stripping")

# ───────────────────────────────────────────────────────────────────
# 4. single current_client() call per summarization
# ───────────────────────────────────────────────────────────────────
old_sum_call = 'history = summarize_history(history, current_client()[0], current_client()[1])'
new_sum_call = '''_c, _m = current_client()
            history = summarize_history(history, _c, _m)'''
if old_sum_call in src:
    src = src.replace(old_sum_call, new_sum_call, 1)
    applied.append("4. cache current_client() per summarization")
elif "_c, _m = current_client()" not in src:
    print("[patch] WARN: summarization call not found (skipping)")

# ───────────────────────────────────────────────────────────────────
# 5. resume past MAX_TURNS extends session
# ───────────────────────────────────────────────────────────────────
old_loop = 'for turn in range(start_turn, MAX_TURNS):'
new_loop = '''session_end = MAX_TURNS if start_turn < MAX_TURNS else start_turn + MAX_TURNS
    for turn in range(start_turn, session_end):'''
if old_loop in src and "session_end" not in src:
    src = src.replace(old_loop, new_loop, 1)
    applied.append("5. resume past MAX_TURNS extends session")

# ───────────────────────────────────────────────────────────────────
# write + verify
# ───────────────────────────────────────────────────────────────────
if src == original:
    print("[patch] nothing to do — already at v8-hardened")
    sys.exit(0)

shutil.copy(AGENT, str(AGENT) + ".pre-hardening.bak")
print(f"[patch] backup: {AGENT.name}.pre-hardening.bak")

try:
    ast.parse(src)
except SyntaxError as e:
    print(f"[patch] SYNTAX ERROR: {e}")
    print("[patch] rolling back")
    shutil.copy(str(AGENT) + ".pre-hardening.bak", AGENT)
    sys.exit(1)

AGENT.write_text(src)
print(f"[patch] applied {len(applied)} change(s):")
for a in applied:
    print(f"  - {a}")
print("[patch] syntax ok")
print("[patch] done.")
