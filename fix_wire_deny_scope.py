#!/usr/bin/env python3
"""Wire _is_denied + _scope_check_cmd into _run_shell.
Idempotent. Backs up to agent_v8.py.pre-wire.bak."""

import pathlib, sys, shutil, ast, re

AGENT = pathlib.Path(__file__).resolve().parent / "agent_v8.py"
src = AGENT.read_text()

# already wired?
if "denied, pat = _is_denied(cmd)" in src:
    print("[fix] already wired — nothing to do")
    sys.exit(0)

# match the head of _run_shell through the blank line after low = cmd.lower()
pattern = re.compile(
    r"(def _run_shell\(cmd, timeout=None\):\n"
    r"    base_timeout = timeout if timeout else CMD_TIMEOUT\n"
    r"    low = cmd\.lower\(\)\n)"
)

m = pattern.search(src)
if not m:
    print("[fix] FATAL: _run_shell head not matched")
    sys.exit(1)

insert = (
    "\n"
    "    denied, pat = _is_denied(cmd)\n"
    "    if denied:\n"
    "        return f\"[DENIED] command matched pattern: {pat}\"\n"
    "\n"
    "    ok, why = _scope_check_cmd(cmd)\n"
    "    if not ok:\n"
    "        return f\"[SCOPE BLOCK] {why}\"\n"
)

src = src[:m.end(1)] + insert + src[m.end(1):]

shutil.copy(AGENT, str(AGENT) + ".pre-wire.bak")
print("[fix] backup: agent_v8.py.pre-wire.bak")

try:
    ast.parse(src)
except SyntaxError as e:
    print(f"[fix] SYNTAX ERROR: {e}")
    print("[fix] not written; original intact")
    sys.exit(1)

AGENT.write_text(src)
print("[fix] wired _is_denied + _scope_check_cmd into _run_shell")
print("[fix] syntax ok")
