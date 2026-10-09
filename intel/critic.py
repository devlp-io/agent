"""
intel.critic — self-review pass between phases.
Feeds current state to the model and asks: what am I missing, what's next, what's noise.
Returns structured suggestions that the agent can act on.
"""
import json
from datetime import datetime, timezone

CRITIC_SYS = """You are a senior pentester reviewing a junior's assessment notes.
Read the state summary. Then produce a short critique in this exact format:

MISSED: <up to 3 things the junior clearly overlooked>
NEXT: <up to 3 concrete next steps, each one command or directive-shaped>
NOISE: <up to 2 findings that are probably noise and can be downgraded>
CONFIDENCE: <one of: low | medium | high>

Rules:
- Be specific. "Try more endpoints" is useless. "PROBE /api/v1/users/2 for IDOR" is useful.
- Do not repeat what's already been attempted.
- If the target stack is FastAPI/Django/Rails, reference that.
- If nothing meaningful is left, NEXT: DONE.
- No prose. Just the 4 sections.
"""


def _summarize(state):
    lines = []
    lines.append(f"target: {state.get('target')}")
    lines.append(f"phase: {state.get('phase')}  turn: {state.get('turn')}")

    tech = state.get("tech_stack") or []
    if tech:
        lines.append(f"tech: {', '.join(str(t) for t in tech[:8])}")

    eps = state.get("endpoints") or []
    lines.append(f"endpoints ({len(eps)}):")
    for e in eps[:25]:
        lines.append(f"  {e.get('method','?')} {e.get('url','?')} {e.get('note','')[:60]}")

    probes = state.get("probes") or []
    unauth = [p for p in probes if p.get("no_auth_2xx")]
    lines.append(f"probes: {len(probes)} total, {len(unauth)} with unauth 2xx")
    for p in unauth[:10]:
        lines.append(f"  UNAUTH: {p.get('method')} {p.get('url')}")

    findings = state.get("findings") or []
    lines.append(f"findings ({len(findings)}):")
    for f in findings[:15]:
        lines.append(f"  [{f.get('sev','?')}] {f.get('title','?')[:120]}")

    walks = state.get("walks") or []
    if walks:
        lines.append(f"walks ({len(walks)}):")
        for w in walks[:5]:
            lines.append(f"  {w.get('method')} {w.get('url')} param={w.get('param')} hits={w.get('hits')}")

    params = state.get("params") or []
    if params:
        lines.append(f"paramfind: {len(params)} run(s)")
        for p in params[:5]:
            lines.append(f"  {p.get('method')} {p.get('url')} hits={len(p.get('hits',[]))}")

    secrets = state.get("secrets") or []
    if secrets:
        lines.append(f"secrets: {len(secrets)}")
        for s in secrets[:8]:
            lines.append(f"  {s.get('kind')} at {s.get('path','')[:60]}")

    notes = state.get("notes") or []
    if notes:
        lines.append("notes:")
        for n in notes[-8:]:
            lines.append(f"  - {str(n)[:120]}")

    methods = state.get("methods_used") or []
    if methods:
        lines.append(f"methodologies used: {', '.join(methods)}")

    return "\n".join(lines)


def review(state, client, model):
    """Run a critic pass. client + model: OpenAI client and model name."""
    summary = _summarize(state)
    try:
        r = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": CRITIC_SYS},
                {"role": "user", "content": summary},
            ],
            temperature=0.2,
            max_tokens=600,
        )
        raw = (r.choices[0].message.content or "").strip()
    except Exception as e:
        return {"error": str(e), "missed": [], "next": [], "noise": [], "confidence": "low"}

    return parse_critique(raw)


def parse_critique(raw):
    out = {"raw": raw, "missed": [], "next": [], "noise": [], "confidence": "low"}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("MISSED:"):
            rest = line[len("MISSED:"):].strip()
            if rest:
                out["missed"].append(rest)
        elif line.startswith("NEXT:"):
            rest = line[len("NEXT:"):].strip()
            if rest:
                out["next"].append(rest)
        elif line.startswith("NOISE:"):
            rest = line[len("NOISE:"):].strip()
            if rest:
                out["noise"].append(rest)
        elif line.startswith("CONFIDENCE:"):
            out["confidence"] = line[len("CONFIDENCE:"):].strip().lower()
    return out


def should_run(state, every_n_turns=15, last_run_turn=None):
    turn = state.get("turn", 0)
    if last_run_turn is None:
        return turn > 0 and turn % every_n_turns == 0
    return (turn - last_run_turn) >= every_n_turns


if __name__ == "__main__":
    # demo with a fake state
    fake = {
        "target": "demo.test",
        "phase": "auth-probe",
        "turn": 12,
        "endpoints": [
            {"method": "GET", "url": "https://demo.test/api/v1/users/1", "note": "from openapi [UNAUTH?]"},
            {"method": "GET", "url": "https://demo.test/api/v1/admin", "note": "401"},
        ],
        "probes": [
            {"method": "GET", "url": "https://demo.test/api/v1/users/1", "no_auth_2xx": True},
        ],
        "findings": [
            {"sev": "medium", "title": "OpenAPI spec exposed at /openapi.json"},
        ],
    }
    print(_summarize(fake))
