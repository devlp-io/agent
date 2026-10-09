#!/usr/bin/env python3
import pathlib, re, ast, shutil, sys

p = pathlib.Path("reporter.py")
src = p.read_text()

if "## Proofs" in src:
    print("[patch] proofs already in reporter — nothing to do"); sys.exit(0)

shutil.copy(p, str(p) + ".pre-proofs.bak")

PROOF_RPT = '''    # ── proofs
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

# find any of these anchors, in order of preference
anchors = [
    "    # ── attack log",
    "    # ── notes\n    if notes:",
    "    # ── notes",
    "    if notes:\n        M.append(\"## Analyst Notes\")",
    "    if notes:",
]

placed = False
for a in anchors:
    if a in src:
        src = src.replace(a, PROOF_RPT + a, 1)
        placed = True
        print(f"[patch] inserted before anchor: {a[:40]!r}")
        break

if not placed:
    # last resort: find the "## File Inventory" or last section and insert before it
    m = re.search(r"^(\s*)M\.append\(\"## File Inventory\"\)", src, re.MULTILINE)
    if m:
        src = src[:m.start()] + PROOF_RPT + src[m.start():]
        placed = True
        print("[patch] inserted before File Inventory")
    else:
        m = re.search(r"^(\s*)M\.append\(\"---\"\)", src, re.MULTILINE)
        if m:
            src = src[:m.start()] + PROOF_RPT + src[m.start():]
            placed = True
            print("[patch] inserted before final ---")

if not placed:
    print("[patch] could not find insertion point. paste output of:")
    print("  grep -n 'M.append' reporter.py | tail -20")
    sys.exit(1)

try: ast.parse(src)
except SyntaxError as e:
    print(f"[patch] syntax error: {e}")
    shutil.copy(str(p) + ".pre-proofs.bak", p)
    sys.exit(1)

p.write_text(src)
print("[patch] done. reporter.py patched.")
