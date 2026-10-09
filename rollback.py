"""
rollback — every FILE: write that hits an existing path first copies .bak.
Also provides a manifest of everything the agent wrote.
"""
import os
import shutil
import pathlib
import json
from datetime import datetime


def safe_write(path, content):
    """Write content to path. If path exists, back it up first."""
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    bak = None
    if p.exists():
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = p.with_suffix(p.suffix + f".{ts}.bak")
        try:
            shutil.copy2(p, bak)
        except Exception:
            bak = None
    p.write_text(content)
    return p, bak


def log_write(run_dir, path, backup):
    logp = pathlib.Path(run_dir) / "writes.json"
    entries = []
    if logp.exists():
        try:
            entries = json.loads(logp.read_text())
        except Exception:
            entries = []
    entries.append({
        "ts": datetime.now().isoformat(),
        "path": str(path),
        "backup": str(backup) if backup else None,
    })
    logp.write_text(json.dumps(entries[-1000:], indent=2))


def restore(run_dir, target_path):
    """Restore the most recent .bak for a path. Returns path or None."""
    logp = pathlib.Path(run_dir) / "writes.json"
    if not logp.exists():
        return None
    try:
        entries = json.loads(logp.read_text())
    except Exception:
        return None
    for e in reversed(entries):
        if e["path"] == str(target_path) and e.get("backup"):
            bak = pathlib.Path(e["backup"])
            if bak.exists():
                shutil.copy2(bak, target_path)
                return str(bak)
    return None
