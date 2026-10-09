"""
intel.cve_db — local sqlite CVE store.
- schema: cves(id, published, cvss, severity, summary, products, refs)
- sync: pulls from NVD 2.0 API in pages (no key required, rate-limited)
- lookup: by keyword, by CPE, by exact product string
- update: incremental, tracks lastModStartDate
"""
import os
import re
import json
import time
import sqlite3
import pathlib
import urllib.parse
from datetime import datetime, timedelta, timezone

try:
    import httpx
    _HAVE_HTTPX = True
except Exception:
    _HAVE_HTTPX = False

DATA_DIR = pathlib.Path(os.path.expanduser("~/agent/data"))
DB_PATH = DATA_DIR / "cve.db"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
RATE_SLEEP = 6.0  # NVD allows 5 req/30s without key


def _conn():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH))
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init():
    c = _conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS cves (
        id          TEXT PRIMARY KEY,
        published   TEXT,
        modified    TEXT,
        cvss        REAL,
        severity    TEXT,
        summary     TEXT,
        products    TEXT,
        refs        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss);
    CREATE INDEX IF NOT EXISTS idx_sev  ON cves(severity);
    CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
        id, summary, products, content='cves', content_rowid='rowid'
    );
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        val TEXT
    );
    """)
    c.commit()
    c.close()


def _meta_get(key):
    c = _conn()
    r = c.execute("SELECT val FROM meta WHERE key=?", (key,)).fetchone()
    c.close()
    return r[0] if r else None


def _meta_set(key, val):
    c = _conn()
    c.execute("INSERT OR REPLACE INTO meta(key,val) VALUES(?,?)", (key, str(val)))
    c.commit()
    c.close()


def _parse_cve(item):
    cve = item.get("cve", {})
    cid = cve.get("id")
    if not cid:
        return None
    published = cve.get("published", "")
    modified = cve.get("lastModified", "")
    summary = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            summary = d.get("value", "")
            break
    cvss = None
    severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = data.get("baseSeverity") or arr[0].get("baseSeverity")
            break
    products = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    products.append(f"{parts[3]}:{parts[4]}")
    refs = [r.get("url", "") for r in cve.get("references", [])][:10]
    return {
        "id": cid,
        "published": published,
        "modified": modified,
        "cvss": cvss,
        "severity": (severity or "").upper() or None,
        "summary": summary[:4000],
        "products": ",".join(sorted(set(products)))[:2000],
        "refs": json.dumps(refs),
    }


def sync(max_pages=50, start_date=None, quiet=False):
    """
    Pull CVEs from NVD. If start_date is None, resumes from last sync or last 90 days.
    max_pages caps how many pages to fetch per call (2000 CVEs/page).
    """
    if not _HAVE_HTTPX:
        return {"error": "httpx not installed"}
    init()

    last = _meta_get("last_sync")
    if start_date:
        sd = start_date
    elif last:
        sd = last
    else:
        sd = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()

    params = {
        "pubStartDate": sd if sd.endswith("Z") else sd + "Z",
        "pubEndDate": datetime.now(timezone.utc).isoformat() + "Z",
        "resultsPerPage": PAGE_SIZE,
        "startIndex": 0,
    }

    total_inserted = 0
    total_skipped = 0
    pages = 0
    c = _conn()

    with httpx.Client(timeout=60.0) as client:
        while pages < max_pages:
            url = NVD_BASE + "?" + urllib.parse.urlencode(params)
            try:
                r = client.get(url)
                if r.status_code == 403:
                    if not quiet:
                        print("[cve_db] NVD rate-limit hit — sleeping 30s")
                    time.sleep(30)
                    continue
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                if not quiet:
                    print(f"[cve_db] fetch error: {e}")
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                parsed = _parse_cve(item)
                if not parsed:
                    continue
                try:
                    c.execute("""
                        INSERT OR REPLACE INTO cves
                        (id,published,modified,cvss,severity,summary,products,refs)
                        VALUES(?,?,?,?,?,?,?,?)
                    """, (parsed["id"], parsed["published"], parsed["modified"],
                          parsed["cvss"], parsed["severity"], parsed["summary"],
                          parsed["products"], parsed["refs"]))
                    total_inserted += 1
                except Exception:
                    total_skipped += 1

            c.commit()
            pages += 1
            if not quiet:
                print(f"[cve_db] page {pages}: +{len(vulns)} rows, "
                      f"total={total_inserted}, idx={params['startIndex']}")

            params["startIndex"] += PAGE_SIZE
            if params["startIndex"] >= data.get("totalResults", 0):
                break
            time.sleep(RATE_SLEEP)

    c.close()
    _meta_set("last_sync", datetime.now(timezone.utc).isoformat() + "Z")
    _meta_set("last_count", total_inserted)
    return {"inserted": total_inserted, "skipped": total_skipped, "pages": pages}


def lookup(keyword, min_cvss=0, limit=20, severity=None):
    """
    Look up CVEs by keyword. Searches FTS index over summary + products.
    Returns list of dicts sorted by CVSS desc.
    """
    init()
    c = _conn()
    try:
        if severity:
            rows = c.execute("""
                SELECT id,published,cvss,severity,summary,products,refs
                FROM cves
                WHERE severity=? AND cvss>=?
                ORDER BY cvss DESC LIMIT ?
            """, (severity.upper(), min_cvss, limit)).fetchall()
        else:
            # fts search
            q = " OR ".join(re.findall(r"\w+", keyword))
            rows = c.execute("""
                SELECT c.id,c.published,c.cvss,c.severity,c.summary,c.products,c.refs
                FROM cves c
                JOIN cves_fts f ON f.rowid = c.rowid
                WHERE cves_fts MATCH ? AND c.cvss >= ?
                ORDER BY c.cvss DESC LIMIT ?
            """, (q, min_cvss, limit)).fetchall()
    except sqlite3.OperationalError:
        # fts not populated yet — fall back to LIKE
        like = f"%{keyword}%"
        rows = c.execute("""
            SELECT id,published,cvss,severity,summary,products,refs
            FROM cves
            WHERE (summary LIKE ? OR products LIKE ?) AND cvss >= ?
            ORDER BY cvss DESC LIMIT ?
        """, (like, like, min_cvss, limit)).fetchall()
    c.close()
    out = []
    for r in rows:
        out.append({
            "id": r[0], "published": r[1], "cvss": r[2], "severity": r[3],
            "summary": r[4][:400], "products": r[5], "refs": json.loads(r[6] or "[]"),
        })
    return out


def lookup_cpe(cpe_prefix, min_cvss=0, limit=20):
    """Match CVEs whose products[] contains a CPE fragment like 'nginx:nginx'."""
    init()
    c = _conn()
    like = f"%{cpe_prefix}%"
    rows = c.execute("""
        SELECT id,published,cvss,severity,summary,products,refs
        FROM cves
        WHERE products LIKE ? AND cvss >= ?
        ORDER BY cvss DESC LIMIT ?
    """, (like, min_cvss, limit)).fetchall()
    c.close()
    return [{
        "id": r[0], "published": r[1], "cvss": r[2], "severity": r[3],
        "summary": r[4][:400], "products": r[5], "refs": json.loads(r[6] or "[]"),
    } for r in rows]


def rebuild_fts():
    c = _conn()
    c.execute("INSERT INTO cves_fts(cves_fts) VALUES('rebuild')")
    c.commit()
    c.close()


def stats():
    init()
    c = _conn()
    total = c.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    by_sev = c.execute("""
        SELECT severity, COUNT(*) FROM cves
        WHERE severity IS NOT NULL GROUP BY severity
    """).fetchall()
    last = c.execute("SELECT val FROM meta WHERE key='last_sync'").fetchone()
    c.close()
    return {
        "total": total,
        "by_severity": dict(by_sev),
        "last_sync": last[0] if last else None,
        "db_path": str(DB_PATH),
        "db_size_mb": round(DB_PATH.stat().st_size / 1024 / 1024, 2) if DB_PATH.exists() else 0,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: cve_db.py <sync|lookup|stats|rebuild-fts> [args]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "sync":
        pages = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        print(json.dumps(sync(max_pages=pages), indent=2))
    elif cmd == "lookup":
        kw = sys.argv[2] if len(sys.argv) > 2 else ""
        for c in lookup(kw, limit=10):
            print(f"{c['id']}  CVSS={c['cvss']}  {c['severity']}  {c['summary'][:100]}")
    elif cmd == "stats":
        print(json.dumps(stats(), indent=2))
    elif cmd == "rebuild-fts":
        rebuild_fts()
        print("fts rebuilt")
    else:
        print(f"unknown cmd: {cmd}")
