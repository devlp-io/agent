"""
intel.stack_router — tech fingerprint -> methodology auto-attach.
Classifies a target's stack from headers/cookies/body/paths and returns
the name(s) of methodology modules to load.
"""
import re

SIGNATURES = {
    "fastapi": {
        "headers": ["x-request-id", "x-process-time"],
        "cookies": [],
        "body": ['"detail":"not found"', '"detail":[{"loc"'],
        "paths": ["/docs", "/redoc", "/openapi.json"],
    },
    "django": {
        "headers": ["x-frame-options"],
        "cookies": ["csrftoken", "django_language", "sessionid"],
        "body": ["CSRF verification failed", "Traceback", "DisallowedHost"],
        "paths": ["/admin/", "/__debug__/"],
    },
    "rails": {
        "headers": ["x-runtime", "x-request-id"],
        "cookies": ["_rails_session", "_session_id"],
        "body": ["ActionController::", "NoMethodError"],
        "paths": ["/rails/info/routes", "/rails/info/properties"],
    },
    "express": {
        "headers": ["x-powered-by"],
        "cookies": ["connect.sid"],
        "body": ['"Cannot GET', "Error: "],
        "paths": ["/api/", "/graphql"],
    },
    "laravel": {
        "headers": [],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "body": ["Whoops!", "Symfony"],
        "paths": ["/telescope", "/horizon"],
    },
    "php_generic": {
        "headers": ["x-powered-by"],
        "cookies": ["PHPSESSID"],
        "body": ["Fatal error:", "mysqli"],
        "paths": ["/phpinfo.php", "/info.php"],
    },
    "wordpress": {
        "headers": [],
        "cookies": ["wordpress_logged_in", "wp-settings"],
        "body": ["wp-content", "wp-includes", "WordPress"],
        "paths": ["/wp-login.php", "/wp-json/wp/v2/"],
    },
    "aspnet": {
        "headers": ["x-aspnet-version", "x-powered-by"],
        "cookies": ["ASP.NET_SessionId", ".AspNetCore.Cookies", ".AspNetCore.Antiforgery"],
        "body": ["Server Error in '/' Application", "ASP.NET"],
        "paths": ["/trace.axd", "/elmah.axd"],
    },
    "spring_boot": {
        "headers": ["x-application-context"],
        "cookies": ["JSESSIONID"],
        "body": ['"timestamp"', '"status":404,"error":"Not Found","path"'],
        "paths": ["/actuator", "/actuator/env", "/actuator/health"],
    },
    "graphql": {
        "headers": [],
        "cookies": [],
        "body": ['"errors":[{"message"', "GraphQL"],
        "paths": ["/graphql", "/gql", "/graphiql", "/playground", "/api/graphql"],
    },
    "nginx_proxy": {
        "headers": ["server"],
        "cookies": [],
        "body": [],
        "paths": [],
    },
}

# map tech -> methodology name (matches METHODOLOGY_LIB keys in agent.py)
METHODOLOGY_MAP = {
    "fastapi":       ["fastapi-hunt", "openapi-hunt"],
    "django":        ["django-hunt", "auth-bypass"],
    "rails":         ["rails-hunt"],
    "express":       ["node-express-hunt", "auth-bypass"],
    "laravel":       ["php-hunt"],
    "php_generic":   ["php-hunt"],
    "wordpress":     ["wordpress-hunt"],
    "aspnet":        ["auth-bypass"],
    "spring_boot":   ["auth-bypass"],
    "graphql":       ["graphql-hunt"],
    "nginx_proxy":   [],
}


def _has_header(headers, keys):
    if not headers:
        return False
    low = {k.lower() for k in headers.keys()}
    return any(k.lower() in low for k in keys)


def _has_cookie(cookies, keys):
    if not cookies:
        return False
    low = {k.lower() for k in cookies.keys()}
    return any(k.lower() in low for k in keys)


def _body_has(body, needles):
    if not body or not needles:
        return False
    b = body.lower()
    return any(n.lower() in b for n in needles)


def classify(headers=None, cookies=None, body="", paths=None):
    """Returns list of (tech_name, score) sorted desc."""
    scores = {}
    for tech, sig in SIGNATURES.items():
        s = 0
        if sig.get("headers") and _has_header(headers, sig["headers"]):
            s += 3
        if sig.get("cookies") and _has_cookie(cookies, sig["cookies"]):
            s += 3
        if sig.get("body") and _body_has(body, sig["body"]):
            s += 3
        if sig.get("paths") and paths:
            for p in paths:
                if any(p.startswith(pp.rstrip("/")) or pp.rstrip("/") == p for pp in sig["paths"]):
                    s += 2
                    break
        # nginx_proxy is a weak catch-all, only score if server header says nginx and nothing else matches
        if tech == "nginx_proxy" and s > 0:
            s = 1
        if s > 0:
            scores[tech] = s
    return sorted(scores.items(), key=lambda x: -x[1])


def auto_methodologies(headers=None, cookies=None, body="", paths=None):
    """Return ordered list of methodology names to load, deduped."""
    hits = classify(headers, cookies, body, paths)
    out = []
    for tech, _score in hits:
        for m in METHODOLOGY_MAP.get(tech, []):
            if m not in out:
                out.append(m)
    # always load the generic ones too
    for base in ("openapi-hunt", "auth-bypass", "stop-heuristics"):
        if base not in out:
            out.append(base)
    return out


def report(headers=None, cookies=None, body="", paths=None):
    hits = classify(headers, cookies, body, paths)
    return {
        "detected": [h[0] for h in hits],
        "scores": dict(hits),
        "methodologies": auto_methodologies(headers, cookies, body, paths),
    }


if __name__ == "__main__":
    import json
    # demo
    h = {"server": "uvicorn", "x-request-id": "abc", "content-type": "application/json"}
    b = '{"detail":"Not Found"}'
    print(json.dumps(report(h, None, b, ["/docs", "/redoc"]), indent=2))
