"""
evidence.seal — hash manifest for tamper-evidence.
Every file under evidence/ + loot/ + pocs/ gets a sha256 recorded.
Optional manifest signature (HMAC with AG_SEAL_KEY env).
"""
import os
import hmac
import json
import hashlib
import pathlib
from datetime import datetime, timezone

DEFAULT_DIRS = ("evidence", "loot", "pocs", "proofs")


def _sha256_file(p, chunk=1 << 20):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def walk(run_dir, subdirs=DEFAULT_DIRS):
    run_dir = pathlib.Path(run_dir)
    files = []
    for sub in subdirs:
        d = run_dir / sub
        if not d.exists():
            continue
        for p in sorted(d.rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                files.append(p)
    return files


def build_manifest(run_dir, subdirs=DEFAULT_DIRS):
    run_dir = pathlib.Path(run_dir)
    files = walk(run_dir, subdirs)
    entries = []
    for f in files:
        try:
            entries.append({
                "path": str(f.relative_to(run_dir)),
                "size": f.stat().st_size,
                "sha256": _sha256_file(f),
                "mtime": f.stat().st_mtime,
            })
        except Exception as e:
            entries.append({"path": str(f), "error": str(e)})
    manifest = {
        "generated": datetime.now(timezone.utc).isoformat() + "Z",
        "run_dir": str(run_dir),
        "total_files": len(entries),
        "total_bytes": sum(e.get("size", 0) for e in entries),
        "entries": entries,
    }
    return manifest


def sign(manifest, key=None):
    """HMAC the manifest with AG_SEAL_KEY. Returns hex sig."""
    key = key or os.environ.get("AG_SEAL_KEY", "")
    if not key:
        return None
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()


def save(run_dir, subdirs=DEFAULT_DIRS, key=None):
    run_dir = pathlib.Path(run_dir)
    m = build_manifest(run_dir, subdirs)
    sig = sign(m, key)
    if sig:
        m["signature"] = sig
        m["signature_alg"] = "HMAC-SHA256"
    out = run_dir / "evidence_manifest.json"
    out.write_text(json.dumps(m, indent=2))
    return out


def verify(run_dir, key=None):
    """Return {'ok': bool, 'changed': [...], 'missing': [...], 'added': [...]}."""
    run_dir = pathlib.Path(run_dir)
    manifest_path = run_dir / "evidence_manifest.json"
    if not manifest_path.exists():
        return {"ok": False, "error": "no manifest"}
    m = json.loads(manifest_path.read_text())

    if key or os.environ.get("AG_SEAL_KEY"):
        sig = sign({k: v for k, v in m.items()
                    if k not in ("signature", "signature_alg")}, key)
        if sig != m.get("signature"):
            return {"ok": False, "error": "signature mismatch"}

    old = {e["path"]: e for e in m.get("entries", [])}
    current_files = walk(run_dir)
    current = {str(p.relative_to(run_dir)): p for p in current_files}

    changed, missing, added = [], [], []
    for path, e in old.items():
        if path not in current:
            missing.append(path)
            continue
        try:
            cur_hash = _sha256_file(current[path])
            if cur_hash != e.get("sha256"):
                changed.append(path)
        except Exception as ex:
            changed.append(f"{path}: {ex}")
    for path in current:
        if path not in old:
            added.append(path)

    return {
        "ok": not (changed or missing),
        "changed": changed,
        "missing": missing,
        "added": added,
        "total": len(old),
    }


if __name__ == "__main__":
    import tempfile
    tmp = pathlib.Path(tempfile.mkdtemp())
    (tmp / "evidence").mkdir()
    (tmp / "evidence" / "test.txt").write_text("hello world")
    (tmp / "loot").mkdir()
    (tmp / "loot" / "creds.txt").write_text("admin:admin\n")

    m = save(tmp, key="demo-key")
    print(f"manifest: {m}")
    print()
    print("verify clean:", json.dumps(verify(tmp, key="demo-key"), indent=2))
    print()

    (tmp / "evidence" / "test.txt").write_text("tampered")
    print("verify tampered:", json.dumps(verify(tmp, key="demo-key"), indent=2))
