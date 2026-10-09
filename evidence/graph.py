"""
evidence.graph — attack graph JSON for downstream visualization.
Nodes: findings, endpoints, creds, secrets, hosts
Edges: relates_to, uses, leaks_into, exploits
"""
import re
import json
import pathlib
import hashlib
from datetime import datetime, timezone


def _nid(prefix, content):
    h = hashlib.sha1(str(content).encode()).hexdigest()[:10]
    return f"{prefix}_{h}"


def build(state):
    nodes = []
    edges = []
    seen = set()

    def add_node(nid, ntype, label, **meta):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "type": ntype, "label": label[:200], **meta})

    def add_edge(a, b, kind, **meta):
        edges.append({"from": a, "to": b, "kind": kind, **meta})

    target = state.get("target", "target")
    tgt_id = _nid("host", target)
    add_node(tgt_id, "host", target)

    # endpoints
    ep_ids = {}
    for e in state.get("endpoints", [])[:500]:
        nid = _nid("ep", f"{e.get('method')} {e.get('url')}")
        ep_ids[e.get("url")] = nid
        add_node(nid, "endpoint", f"{e.get('method','?')} {e.get('url','?')}",
                 method=e.get("method"), url=e.get("url"), note=e.get("note", "")[:200])
        add_edge(tgt_id, nid, "exposes")

    # findings
    for f in state.get("findings", []):
        nid = _nid("f", f.get("title", "") + str(f.get("evidence", ""))[:60])
        add_node(nid, "finding", f.get("title", "?"),
                 severity=f.get("sev"), evidence=str(f.get("evidence", ""))[:500])
        add_edge(tgt_id, nid, "has_finding")
        # link finding to any endpoint mentioned in evidence
        ev = str(f.get("evidence", "")) + " " + str(f.get("title", ""))
        for url, eid in ep_ids.items():
            if url and url in ev:
                add_edge(nid, eid, "relates_to")

    # secrets
    for s in state.get("secrets", []):
        nid = _nid("sec", s.get("path", "") + s.get("kind", ""))
        add_node(nid, "secret", f"{s.get('kind','?')} @ {s.get('path','?')[:80]}",
                 kind=s.get("kind"), path=s.get("path"))
        add_edge(tgt_id, nid, "leaks")

    # creds
    for c in state.get("creds", []):
        nid = _nid("cred", f"{c.get('user')}:{c.get('where','')}")
        add_node(nid, "cred", f"{c.get('user','?')} @ {c.get('where','?')[:80]}",
                 user=c.get("user"), where=c.get("where"))
        add_edge(tgt_id, nid, "leaks")

    # walks
    for w in state.get("walks", []):
        nid = _nid("walk", f"{w.get('url')}:{w.get('param')}")
        add_node(nid, "walk", f"walk {w.get('method')} {w.get('url')} [{w.get('param')}]",
                 hits=w.get("hits"), start=w.get("start"), end=w.get("end"))
        add_edge(tgt_id, nid, "has_walk")

    # oob
    for o in state.get("oob", []):
        nid = _nid("oob", o.get("url", "") + o.get("payload", ""))
        add_node(nid, "oob", f"OOB: {o.get('kind','?')} via {o.get('url','?')[:80]}")
        add_edge(tgt_id, nid, "callback")

    # chains
    for c in state.get("chains", []):
        a_id = _nid("chain_a", c.get("from", ""))
        b_id = _nid("chain_b", c.get("to", ""))
        add_node(a_id, "chain_node", str(c.get("from", "?"))[:120])
        add_node(b_id, "chain_node", str(c.get("to", "?"))[:120])
        add_edge(a_id, b_id, "chains_to", rule=c.get("rule"), why=c.get("why"))

    # attacks
    for a in state.get("attacks", []):
        nid = _nid("atk", str(a.get("id", "")) + a.get("target", ""))
        add_node(nid, "attack", f"{a.get('tool','?')} → {a.get('target','?')}",
                 result=a.get("result"), ts=a.get("ts") or a.get("started"))
        add_edge(tgt_id, nid, "attacked")

    return {
        "generated": datetime.now(timezone.utc).isoformat() + "Z",
        "target": target,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_type": _count_types(nodes),
        },
    }


def _count_types(nodes):
    out = {}
    for n in nodes:
        out[n["type"]] = out.get(n["type"], 0) + 1
    return out


def save(run_dir, state):
    run_dir = pathlib.Path(run_dir)
    g = build(state)
    out = run_dir / "attack_graph.json"
    out.write_text(json.dumps(g, indent=2))
    return out


def dot(graph):
    """Export as Graphviz dot for quick visualization."""
    lines = ["digraph attack {"]
    for n in graph["nodes"]:
        color = {
            "finding": "red" if n.get("severity") in ("critical", "high") else "orange",
            "secret": "purple", "cred": "purple", "endpoint": "lightblue",
            "host": "black", "walk": "yellow", "attack": "darkred",
            "oob": "pink", "chain_node": "green",
        }.get(n["type"], "grey")
        lines.append(f'  "{n["id"]}" [label="{_esc(n["label"])}", fillcolor="{color}", style=filled];')
    for e in graph["edges"]:
        lines.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{e["kind"]}"];')
    lines.append("}")
    return "\n".join(lines)


def _esc(s):
    return (s or "").replace('"', '\\"').replace("\n", " ")[:80]


if __name__ == "__main__":
    import tempfile
    demo = {
        "target": "demo.test",
        "endpoints": [
            {"method": "GET", "url": "https://demo.test/api/users/1"},
            {"method": "GET", "url": "https://demo.test/api/admin"},
        ],
        "findings": [
            {"sev": "high", "title": "Unauth walk on https://demo.test/api/users/1",
             "evidence": "300 rows recovered"},
            {"sev": "medium", "title": "OpenAPI spec exposed at /openapi.json",
             "evidence": "150 endpoints disclosed"},
        ],
        "secrets": [{"kind": "aws_key", "value": "AKIAxxxx", "path": ".env"}],
        "chains": [{"from": "OpenAPI spec exposed", "to": "https://demo.test/api/users/1",
                    "rule": "openapi_to_idor", "why": "walk it"}],
    }
    g = build(demo)
    print(json.dumps(g["stats"], indent=2))
    print()
    print("DOT preview:")
    print(dot(g)[:600])
