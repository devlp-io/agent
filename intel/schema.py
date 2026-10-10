"""
intel/schema.py — target schema synthesis. v2.

Reads state.json and produces a semantic model of the target:

  entities, capabilities, fields, sensitivity, actions, recommendations.

v3 changes:  drop _root hosts, harvest live_commands.log
v2 changes:
  - _valid_name() guard — rejects shell substrings ($grep, $f, $ref, $(...))
  - _invalid bucket — garbage entities silently dropped
  - global_fields — sensitivity harvested from EVERY finding / secret /
    cred / note, not just title-matched ones
  - version bumped to 3

Deterministic, no LLM. Pure function of state + optional run_dir.

Exports:
  deduce(state, run_dir=None) -> dict
  render_markdown(schema)     -> str
"""
import re
import pathlib
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse


# ── URL → entity ────────────────────────────────────────────────────

_PARAM_SEG = re.compile(
    r"^(\{[^}]+\}|:[a-zA-Z_]\w*|<[^>]+>|[0-9a-fA-F]{8,}|[0-9]+)$"
)

def _is_param_segment(seg: str) -> bool:
    return bool(_PARAM_SEG.match(seg)) or seg in ("{id}", "{uid}", "{user_id}")

_SKIP_SEG = {
    "api", "v1", "v2", "v3", "v4", "rest", "graphql",
    "projects", "databases", "(default)", "documents",
    "index.html", "public",
}

_VALID_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]{0,60}$")

# any shell metachar forces rejection
_BAD_CHARS = set("$(){}<>`;|&*'\" \t\n\\")

def _valid_name(name: str) -> bool:
    """Reject shell substrings ($grep, $f, $(...)), stray symbols, and
    anything that isn't a clean identifier. Endpoint registration from
    unfiltered command output frequently produces garbage like '$(grep'
    or '$ref' — those must not become entities."""
    if not name:
        return False
    if not _VALID_NAME_RE.match(name):
        return False
    if any(ch in _BAD_CHARS for ch in name):
        return False
    return True


def entity_from_url(url: str) -> tuple:
    """Return (host, entity). Entity = last meaningful path segment.
    Returns ('_unparsed', '_invalid') on garbage."""
    try:
        p = urlparse(url)
    except Exception:
        return ("?", "_unparsed")
    host = (p.hostname or "?")
    segs = [s for s in (p.path or "/").split("/") if s]
    if not segs:
        return (host, "_root")
    meaningful = [s for s in segs if not _is_param_segment(s)]
    if not meaningful:
        return (host, "_root")
    filtered = [s for s in meaningful if s.lower() not in _SKIP_SEG]
    if not filtered:
        filtered = meaningful
    candidate = filtered[-1].lower()
    if not _valid_name(candidate):
        return (host, "_invalid")
    return (host, candidate)


# ── field detection ─────────────────────────────────────────────────

_SENSITIVE = {
    "email":    re.compile(r"email|mail_addr|emailAddress", re.I),
    "phone":    re.compile(r"phone|msisdn|mobile|contact_number", re.I),
    "name":     re.compile(r"^(fullName|firstName|lastName|displayName|full_name|first_name|last_name|name)$", re.I),
    "dob":      re.compile(r"dateOfBirth|dob|birthdate|birthday", re.I),
    "address":  re.compile(r"^(address|street|city|postal|zip|country|countryCode)$", re.I),
    "ssn":      re.compile(r"ssn|social_security|tax_id|national_id|idNumber|idDocument", re.I),
    "password": re.compile(r"password|passwd|passwordHash|password_hash|pwd", re.I),
    "token":    re.compile(r"token|access_token|refresh_token|api_key|apikey|bearer|secret_key", re.I),
    "key":      re.compile(r"private_key|public_key|encryption_key|signing_key|secret", re.I),
    "hash":     re.compile(r"^(hash|md5|sha1|sha256|bcrypt|scrypt)$", re.I),
    "balance":  re.compile(r"^(balance|balanceUsd|amount|total|credit|debit)$", re.I),
    "uid":      re.compile(r"^(uid|user_id|userid|account_id|accountId|id)$", re.I),
    "kyc":      re.compile(r"kyc|kycRequired|kycDocs|documentId|idDocument", re.I),
    "admin":    re.compile(r"admin|isAdmin|is_admin|role|permissions|scope", re.I),
    "fcm":      re.compile(r"fcm|push_token|device_token|notification_token", re.I),
}

_FIELD_RE = re.compile(r'"([a-zA-Z_][a-zA-Z0-9_]{1,40})"\s*:')

def extract_fields(blob: str) -> dict:
    hits = defaultdict(set)
    if not blob:
        return hits
    for m in _FIELD_RE.finditer(blob):
        name = m.group(1)
        for kind, pat in _SENSITIVE.items():
            if pat.search(name):
                hits[kind].add(name)
    return hits


# ── capability inference ────────────────────────────────────────────

def _cap(status) -> str:
    s = str(status)
    if s.startswith("2"):
        return "ok"
    if s.startswith("3"):
        return "redirect"
    if s == "401":
        return "auth_required"
    if s == "403":
        return "denied"
    if s == "404":
        return "missing"
    if s == "405":
        return "method_not_allowed"
    if s == "429":
        return "rate_limited"
    if s.startswith("5"):
        return "error"
    return "unknown"


# ── main deducer ────────────────────────────────────────────────────

def deduce(state: dict, run_dir=None) -> dict:
    now = datetime.utcnow().isoformat() + "Z"
    entities: dict = {}
    global_sensitive: dict = defaultdict(set)

    def ent(host: str, name: str) -> dict:
        key = f"{host}/{name}"
        if key not in entities:
            entities[key] = {
                "key": key, "host": host, "name": name,
                "endpoints": [],
                "capabilities": defaultdict(lambda: defaultdict(int)),
                "fields": set(),
                "sensitive": defaultdict(set),
                "probe_results": [],
                "walk_hits": 0,
                "finding_ids": [],
            }
        return entities[key]

    # ── endpoints ────────────────────────────────────────────────
    for e in state.get("endpoints", []) or []:
        url = e.get("url", "")
        method = (e.get("method") or "GET").upper()
        host, name = entity_from_url(url)
        if name == "_invalid":
            continue
        ent(host, name)["endpoints"].append({
            "method": method, "url": url, "note": e.get("note", ""),
        })

    # ── probes → capability tally ────────────────────────────────
    for p in state.get("probes", []) or []:
        url = p.get("url", "")
        method = (p.get("method") or "GET").upper()
        host, name = entity_from_url(url)
        if name == "_invalid":
            continue
        E = ent(host, name)
        for r in p.get("results", []) or []:
            cap = _cap(r.get("status", "?"))
            E["capabilities"][method][cap] += 1
            E["probe_results"].append({
                "variant": r.get("variant", "?"),
                "status": r.get("status", "?"),
                "cap": cap,
            })
        if p.get("no_auth_2xx"):
            E["finding_ids"].append("unauth_2xx")

    # ── walks → hits + sample fields ─────────────────────────────
    for w in state.get("walks", []) or []:
        url = w.get("url", "")
        host, name = entity_from_url(url)
        if name == "_invalid":
            continue
        E = ent(host, name)
        E["walk_hits"] += int(w.get("hits", 0))
        fp = w.get("file", "")
        if fp:
            try:
                data = pathlib.Path(fp).read_text(errors="ignore")[:200_000]
                for kind, names in extract_fields(data).items():
                    E["sensitive"][kind].update(names)
                    E["fields"].update(names)
                    global_sensitive[kind].update(names)
            except Exception:
                pass

    # ── findings → link + global harvest ─────────────────────────
    URL_RE = re.compile(r"https?://[^\s\"'<>]+")
    for i, f in enumerate(state.get("findings", []) or []):
        ev = str(f.get("evidence", ""))
        title = str(f.get("title", ""))
        extracted = extract_fields(ev)
        # everything into global pool
        for kind, names in extracted.items():
            global_sensitive[kind].update(names)
        # attribute to entities by URL
        for m in URL_RE.finditer(ev):
            url = m.group(0)
            host, name = entity_from_url(url)
            if name == "_invalid":
                continue
            E = ent(host, name)
            E["finding_ids"].append(f"F{i}")
            for kind, names in extracted.items():
                E["sensitive"][kind].update(names)
                E["fields"].update(names)
        # loose title match → apply to matching entity
        for key in list(entities.keys()):
            e_name = entities[key]["name"]
            if e_name and len(e_name) >= 3 and e_name.lower() in title.lower():
                for kind, names in extracted.items():
                    entities[key]["sensitive"][kind].update(names)
                    entities[key]["fields"].update(names)

    # ── secrets / creds / notes → global pool ────────────────────
    for s in state.get("secrets", []) or []:
        blob = f"{s.get('kind','')} {s.get('value','')} {s.get('path','')}"
        for kind, names in extract_fields(blob).items():
            global_sensitive[kind].update(names)
        # also try to link secret source to an entity
        src = str(s.get("path", ""))
        for m in URL_RE.finditer(src):
            host, name = entity_from_url(m.group(0))
            if name != "_invalid":
                entities.setdefault(f"{host}/{name}", None)
                if entities[f"{host}/{name}"] is not None:
                    entities[f"{host}/{name}"]["sensitive"][s.get("kind", "secret")].add(s.get("kind", "secret"))

    for c in state.get("creds", []) or []:
        # build a fake JSON to reuse extract_fields
        fake = '{"user":"%s","pass":"%s","where":"%s"}' % (
            str(c.get("user", "")), str(c.get("pass", "")), str(c.get("where", ""))
        )
        for kind, names in extract_fields(fake).items():
            global_sensitive[kind].update(names)

    for n in state.get("notes", []) or []:
        for kind, names in extract_fields(str(n)).items():
            global_sensitive[kind].update(names)

    # ── live_commands.log — the richest source of raw JSON ───────
    if run_dir:
        try:
            rp = pathlib.Path(run_dir)
            cl = rp / "live_commands.log"
            if cl.exists():
                blob = cl.read_text(errors="ignore")
                # harvest fields globally from every JSON-looking region
                for kind, names in extract_fields(blob[:2_000_000]).items():
                    global_sensitive[kind].update(names)
                # per-host attribution: find URL followed by nearby JSON
                # (simple approach — walk each line, find host, harvest next
                #  40 lines for its field names)
                lines = blob.splitlines()
                for i, line in enumerate(lines):
                    for m in URL_RE.finditer(line):
                        host, name = entity_from_url(m.group(0))
                        if name in ("_invalid", "_root", "_unparsed"):
                            continue
                        window = "\n".join(lines[i:i+40])
                        for kind, names in extract_fields(window).items():
                            E = ent(host, name)
                            E["sensitive"][kind].update(names)
                            E["fields"].update(names)
        except Exception:
            pass

    # ── finalize entities ────────────────────────────────────────
    finalized = []
    for key, E in entities.items():
        if not E:
            continue
        if E.get("name") in ("_invalid", "_root", "_unparsed"):
            continue
        E["fields"] = sorted(E["fields"])[:120]
        E["sensitive"] = {k: sorted(v)[:40] for k, v in E["sensitive"].items() if v}
        E["category"] = _categorize(E["name"])
        caps_summary = {}
        for method, dist in E["capabilities"].items():
            if dist.get("ok"):
                caps_summary[method] = "ok"
            elif dist.get("denied") or dist.get("auth_required"):
                caps_summary[method] = "denied"
            elif dist.get("missing"):
                caps_summary[method] = "missing"
            elif dist.get("method_not_allowed"):
                caps_summary[method] = "method_not_allowed"
            elif dist:
                caps_summary[method] = next(iter(dist))
        E["cap_summary"] = caps_summary
        E["actions"] = _actions_for(E)
        E.pop("capabilities", None)
        finalized.append(E)

    by_cat = defaultdict(list)
    for E in finalized:
        by_cat[E["category"]].append(E)
    categories = [
        {"name": c, "items": sorted(items, key=lambda x: x["name"])}
        for c, items in sorted(by_cat.items())
    ]

    global_fields = {k: sorted(v)[:60] for k, v in global_sensitive.items() if v}

    summary = {
        "entities": len(finalized),
        "endpoints": sum(len(E["endpoints"]) for E in finalized),
        "denied_endpoints": sum(
            1 for E in finalized for v in E["cap_summary"].values() if v == "denied"
        ),
        "walk_hits_total": sum(E["walk_hits"] for E in finalized),
        "sensitive_field_total": (
            sum(len(v) for E in finalized for v in E["sensitive"].values())
            + sum(len(v) for v in global_sensitive.values())
        ),
        "categories": len(categories),
    }

    return {
        "target": state.get("target", "?"),
        "built_at": now,
        "version": 3,
        "summary": summary,
        "categories": categories,
        "global_fields": global_fields,
        "recommendations": _recommend(finalized, state),
        "counts": {
            "findings": len(state.get("findings", []) or []),
            "attacks":  len(state.get("attacks", []) or []),
            "secrets":  len(state.get("secrets", []) or []),
            "creds":    len(state.get("creds", []) or []),
        },
    }


# ── categorization ──────────────────────────────────────────────────

_CATEGORY_RULES = [
    ("PEOPLE",    re.compile(r"user|profile|account|person|customer|member|people|kyc", re.I)),
    ("PAYMENTS",  re.compile(r"payment|transaction|deposit|withdraw|wallet|balance|invoice|order|transfer", re.I)),
    ("PARTNERS",  re.compile(r"partner|merchant|vendor|reseller|affiliate|agent", re.I)),
    ("COMMERCE",  re.compile(r"product|catalog|categor|inventory|price|cart|discount|coupon|sku", re.I)),
    ("ADMIN",     re.compile(r"admin|staff|operator|manage|dashboard|panel|console", re.I)),
    ("AUTH",      re.compile(r"auth|login|session|token|oauth|jwt|credential|otp|key", re.I)),
    ("MESSAGING", re.compile(r"message|chat|notification|email|sms|push|fcm", re.I)),
    ("FILES",     re.compile(r"file|upload|download|media|image|attach|doc|storage|bucket", re.I)),
    ("LOGS",      re.compile(r"log|audit|event|history|activity|track", re.I)),
    ("CONFIG",    re.compile(r"config|setting|param|flag|feature|system", re.I)),
    ("MISC",      re.compile(r".*")),
]

def _categorize(name: str) -> str:
    for cat, pat in _CATEGORY_RULES:
        if pat.search(name or ""):
            return cat
    return "MISC"


# ── suggested actions ───────────────────────────────────────────────

def _actions_for(E: dict) -> list:
    out = []
    url0 = E["endpoints"][0]["url"] if E["endpoints"] else None
    if url0:
        out.append({"label": "Fetch one", "kind": "FETCH", "payload": url0})
    if any(v == "denied" for v in E["cap_summary"].values()) and url0:
        out.append({"label": "Try auth-bypass", "kind": "PROBE",
                    "payload": f"GET|{url0}"})
    if E["cap_summary"].get("GET") == "ok" and url0:
        out.append({"label": "Walk IDs 1..500", "kind": "WALK",
                    "payload": f"GET|{url0}|id|1|500"})
    if any(E["cap_summary"].get(m) == "ok" for m in ("POST", "PATCH", "PUT")):
        out.append({"label": "Mass-assign probe", "kind": "NOTE",
                    "payload": f"POST extra fields to {url0}"})
    if E["sensitive"].get("email") or E["sensitive"].get("phone"):
        if url0:
            out.append({"label": "Extract PII sample", "kind": "COMMAND",
                        "payload": f"curl -sSk '{url0}' --max-time 15 | head -c 4000"})
    return out


# ── recommendations ─────────────────────────────────────────────────

def _recommend(finalized: list, state: dict) -> list:
    out = []
    for E in finalized:
        denied = [m for m, c in E["cap_summary"].items() if c == "denied"]
        ok     = [m for m, c in E["cap_summary"].items() if c == "ok"]
        if denied and ok:
            out.append({
                "sev": "high", "entity": E["name"],
                "text": f"{E['name']}: {denied} denied, {ok} allowed — verb-confusion / mass-assignment candidate",
            })
        if E["cap_summary"].get("GET") == "ok" and E["walk_hits"] > 100:
            out.append({
                "sev": "high", "entity": E["name"],
                "text": f"{E['name']}: {E['walk_hits']} rows recoverable unauth — extend walk range",
            })
        if E["sensitive"].get("password"):
            out.append({
                "sev": "critical", "entity": E["name"],
                "text": f"{E['name']}: passwordHash exposed ({', '.join(E['sensitive']['password'][:3])}) — crack",
            })
        if E["sensitive"].get("kyc"):
            out.append({
                "sev": "critical", "entity": E["name"],
                "text": f"{E['name']}: KYC documents referenced — data-protection exposure",
            })
        if len(E["sensitive"].get("token", [])) >= 2:
            out.append({
                "sev": "high", "entity": E["name"],
                "text": f"{E['name']}: multiple token fields — pivot on any leaked value",
            })
        if E["sensitive"].get("fcm"):
            out.append({
                "sev": "med", "entity": E["name"],
                "text": f"{E['name']}: FCM/push tokens — verify send capability",
            })
    if not any("rate limit" in (f.get("title", "").lower())
               for f in state.get("findings", []) or []):
        out.append({"sev": "med", "entity": "*",
                    "text": "No rate-limit finding yet — fire 30x parallel GETs to confirm"})
    if not state.get("probes"):
        out.append({"sev": "med", "entity": "*",
                    "text": "Zero probes recorded — PROBE every 401/403 endpoint"})
    return out[:30]


def render_markdown(schema: dict) -> str:
    L = [f"# Schema — {schema['target']}", ""]
    s = schema["summary"]
    L += [
        f"- entities: **{s['entities']}**",
        f"- endpoints: **{s['endpoints']}**",
        f"- denied: **{s['denied_endpoints']}**",
        f"- sensitive fields: **{s['sensitive_field_total']}**",
        "",
    ]
    for cat in schema["categories"]:
        L.append(f"## {cat['name']}")
        for E in cat["items"]:
            L.append(f"### {E['name']}  `{E['host']}`")
            if E["cap_summary"]:
                L.append("  " + " · ".join(f"{m}:{c}" for m, c in E["cap_summary"].items()))
            for kind, names in E["sensitive"].items():
                L.append(f"  - **{kind}**: {', '.join(names[:6])}")
            L.append("")
    gf = schema.get("global_fields") or {}
    if gf:
        L.append("## Global sensitive fields (all sources)")
        for kind, names in gf.items():
            L.append(f"- **{kind}**: {', '.join(names[:12])}")
        L.append("")
    if schema["recommendations"]:
        L.append("## Recommendations")
        for r in schema["recommendations"]:
            L.append(f"- [{r['sev']}] {r['text']}")
    return "\n".join(L)
