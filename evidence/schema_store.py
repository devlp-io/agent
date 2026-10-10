"""
evidence/schema_store.py — persist the deduced target schema next to the
run dir. The dashboard reads schema.json; the agent regenerates it.

Functions:
  build(state, run_dir)          -> dict
  save(run_dir, schema)          -> Path
  load(run_dir)                  -> dict | None
  rebuild_and_save(run_dir, state) -> Path
"""
import json
import pathlib
import sys


def _schema_mod():
    root = pathlib.Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from intel import schema as s
    return s


def build(state: dict, run_dir=None) -> dict:
    s = _schema_mod()
    return s.deduce(state, run_dir)


def save(run_dir, schema: dict) -> pathlib.Path:
    p = pathlib.Path(run_dir) / "schema.json"
    p.write_text(json.dumps(schema, indent=2, default=str))
    return p


def load(run_dir) -> dict:
    p = pathlib.Path(run_dir) / "schema.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def rebuild_and_save(run_dir, state: dict) -> pathlib.Path:
    schema = build(state, run_dir)
    return save(run_dir, schema)
