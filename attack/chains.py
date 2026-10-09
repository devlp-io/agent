"""
attack.chains — pattern-match findings into exploit chains.
Pure rules. No LLM. Deterministic.
"""
import re

# each rule: (condition_fn, produces_chain_description, suggested_directive)
# condition_fn(state) -> bool
# rule fires if condition true AND not already in state.chains


def _f(f):
    t = (f.get("title") or "").lower()
    return t


def _has_finding(state, needle):
    for f in state.get("findings", []):
        if needle.lower() in _f(f):
            return f
    return None


def _has_pattern(state, *needles):
    hits = []
    for n in needles:
        f = _has_finding(state, n)
        if f:
            hits.append(f)
    return hits if len(hits) == len(needles) else None


RULES = []


def rule(name, description, template):
    def deco(fn):
        RULES.append({"name": name, "fn": fn, "description": description, "template": template})
        return fn
    return deco


@rule(
    "openapi_to_idor",
    "OpenAPI spec exposed + an endpoint with {id} in path",
    "WALK: GET|<endpoint_url>|<param>|1|500",
)
def _r_openapi_idor(state):
    oa = _has_finding(state, "openapi spec exposed") or _has_finding(state, "swagger")
    if not oa:
        return None
    id_eps = [e for e in state.get("endpoints", [])
              if re.search(r"\{[a-z_]*id[a-z_]*\}|\{[a-z_]+\}", e.get("url", ""), re.I)]
    if not id_eps:
        return None
    ep = id_eps[0]
    m = re.search(r"\{([a-z_]+)\}", ep["url"], re.I)
    param = m.group(1) if m else "id"
    return {
        "from": oa.get("title"),
        "to": ep.get("url"),
        "template": f"WALK: {ep['method']}|{ep['url'].split('{')[0]}1|{param}|1|300",
        "why": "OpenAPI leaked the endpoint; endpoint takes an id; walk it for unauth rows",
    }


@rule(
    "unauth_jwt_to_admin",
    "Unauth endpoint returning a JWT + role/admin field visible",
    "CRACK: <token>|auto",
)
def _r_unauth_jwt_admin(state):
    jwt_secret = _has_finding(state, "jwt") or _has_finding(state, "bearer")
    admin = _has_finding(state, "admin") or _has_finding(state, "role")
    if not (jwt_secret or admin):
        return None
    return {
        "from": "jwt/auth finding",
        "to": "admin surface",
        "template": "SEARCH: jwt alg none weak secret exploitation",
        "why": "JWT in play + admin surface reachable → try alg:none and weak secret",
    }


@rule(
    "idor_to_creds",
    "IDOR walk with >10 hits + password/hash field seen",
    "HARVEST: <walk_out_file>",
)
def _r_idor_creds(state):
    walks = [w for w in state.get("walks", []) if w.get("hits", 0) > 10]
    if not walks:
        return None
    if not (_has_finding(state, "password") or _has_finding(state, "hash")
            or _has_finding(state, "cred")):
        return None
    w = walks[0]
    return {
        "from": f"IDOR walk hits={w['hits']}",
        "to": "credential material",
        "template": f"HARVEST: {w.get('file','')}",
        "why": "IDOR dumps + password fields → extract creds",
    }


@rule(
    "ssrf_to_internal",
    "SSRF finding + internal hostname revealed",
    "COMMAND: curl -sk 'http://<internal>:<port>/' -m 10",
)
def _r_ssrf_internal(state):
    ssrf = _has_finding(state, "ssrf") or _has_finding(state, "server-side request")
    if not ssrf:
        return None
    internal = _has_finding(state, "internal host") or _has_finding(state, "internal ip")
    if not internal:
        return None
    return {
        "from": "SSRF",
        "to": "internal network",
        "template": "SEARCH: aws metadata ssrf exploit",
        "why": "SSRF present + internal host seen → probe metadata endpoints",
    }


@rule(
    "no_rate_limit_to_brute",
    "No rate-limit finding + auth endpoint identified",
    "FILE: brute.py|<generated>",
)
def _r_nolimit_brute(state):
    nrl = _has_finding(state, "rate limit") or _has_finding(state, "rate-limit")
    if not nrl:
        return None
    auth_eps = [e for e in state.get("endpoints", [])
                if any(k in e.get("url", "").lower()
                       for k in ("login", "auth", "otp", "verify", "token", "signin"))]
    if not auth_eps:
        return None
    ep = auth_eps[0]
    return {
        "from": "no rate limit",
        "to": ep.get("url"),
        "template": f"COMMAND: python3 -c \"import aiohttp,asyncio;...\" # brute {ep['url']}",
        "why": "No rate-limit + auth endpoint → brute force",
    }


@rule(
    "cve_to_exploit",
    "Version-disclosed tech + matching CVE",
    "CVE: <product>|<version>",
)
def _r_cve_exploit(state):
    versions = _has_finding(state, "version") or _has_finding(state, "server:")
    if not versions:
        return None
    return {
        "from": "version disclosure",
        "to": "known CVE",
        "template": "CVE: <product>|<version>",
        "why": "Version disclosed → look up CVE and try public PoC",
    }


@rule(
    "secret_to_pivot",
    "API key or token found + external service endpoint known",
    "COMMAND: curl -H 'Authorization: Bearer <token>' 'https://<service>/api/me'",
)
def _r_secret_pivot(state):
    secrets = state.get("secrets", [])
    if not secrets:
        return None
    kinds = {s.get("kind", "") for s in secrets}
    if not (kinds & {"aws_key", "google_api", "github_pat", "slack_token", "stripe"}):
        return None
    return {
        "from": f"secrets ({', '.join(kinds)})",
        "to": "cloud/hosted service",
        "template": "COMMAND: env | grep -iE 'AWS|GCP|GITHUB' # check leaked keys",
        "why": "Cloud API key found → attempt authenticated calls",
    }


def find_chains(state):
    """Run all rules. Returns list of chain dicts that haven't already fired."""
    existing = state.setdefault("chains", [])
    known = {(c.get("from"), c.get("to")) for c in existing}
    out = []
    for r in RULES:
        try:
            result = r["fn"](state)
        except Exception:
            result = None
        if not result:
            continue
        key = (result.get("from"), result.get("to"))
        if key in known:
            continue
        result["rule"] = r["name"]
        out.append(result)
    return out


def commit_chains(state, chains):
    """Append newly found chains to state."""
    for c in chains:
        state["chains"].append({
            "from": c.get("from"),
            "to": c.get("to"),
            "template": c.get("template"),
            "why": c.get("why"),
            "rule": c.get("rule"),
        })
    s = state.setdefault("attack_summary", {"attempted": 0, "succeeded": 0, "chained": 0})
    s["chained"] = s.get("chained", 0) + len(chains)


if __name__ == "__main__":
    import json
    demo = {
        "findings": [
            {"sev": "medium", "title": "OpenAPI spec exposed at /openapi.json"},
            {"sev": "high", "title": "no rate limit on /api/otp/verify"},
        ],
        "endpoints": [
            {"method": "GET", "url": "https://demo.test/api/v1/users/{id}"},
            {"method": "POST", "url": "https://demo.test/api/otp/verify"},
        ],
    }
    chains = find_chains(demo)
    print(json.dumps(chains, indent=2))
