
```bash
cd ~/agent

cat > README.md <<'READMEEOF'
# ag — autonomous security assessment agent

A terminal-run AI agent for **authorized** security assessment. Point it at a
target, walk away, come back to findings + a full report. A localhost
dashboard mirrors every run live, lets you fire directives by hand, run a
terminal, and read the model of the target the agent built for itself.

    agds "assess example.com for vulnerabilities"
    or ag assess example.com for vulnerabilities

The agent extracts the target, confirms scope, runs recon → enumeration →
exploitation → reporting, and writes live logs the whole time so you can
`tail -f` and watch.

---

## What it does

- **Target extraction** — reads the whole prompt with an LLM and picks the
  right host (not regex-first). Handles `admin@beco.so on appservice.beco.so`
  correctly.
- **Recon** — subdomains (subfinder, amass, assetfinder), URLs (gau,
  waybackurls), live probe (httpx), ports (naabu, nmap), content (katana,
  ffuf, gobuster).
- **Adaptive stack detection** — fingerprints the target (FastAPI, Django,
  Rails, Express, PHP, WordPress, GraphQL) and loads the matching methodology.
- **API hunting** — finds `openapi.json` / `swagger.json` and auto-registers
  every path. PARAMFIND brute-forces param names. WALK enumerates IDs.
- **Auth-bypass probing** — 9 header variants fire on every 401/403
  (empty bearer, admin bearer, X-Forwarded-For, X-Original-URL, etc).
- **Secrets** — scans config files, JS bundles, .env, .git/config for AWS,
  GCP, GitHub, Stripe, JWTs, private keys.
- **Web search + fetch** — the model can `SEARCH:` the web for CVEs and
  `FETCH:` writeups mid-scan.
- **Self-installing** — curated recipes for ~130 tools. Any GitHub/GitLab
  repo installs with auto-detected build system (go, cargo, npm, make,
  python, maven, gradle). Data repos (SecLists, PayloadsAllTheThings) are
  cloned without a build attempt.
- **Attack phase** — after recon, walks every finding through an exploitation
  ladder (auth-bypass, path tricks, method swap, payload mutation, chaining).
  Operator approves each `EXPLOIT:` with y/N, or `--attack` to skip the menu.
- **Schema synthesis** — `intel/schema.py` groups endpoints into entities
  (users, orders, payments, admin…), infers per-verb capabilities
  (ok/denied/auth), extracts sensitive fields (email, phone, passwordHash,
  KYC, FCM tokens) from findings, walks, and the raw command log. Produces
  `schema.json` per run.
- **Live logs** — `live.log`, `live_commands.log`, `live_findings.log`
  stream as the scan runs.
- **Dashboard** — `python dashboard.py` serves a localhost UI (port 8787) with:
  live log panes, overview cards, findings table, actions tab (dispatch any
  directive), raw HTTP repeater, interactive shell, tools installer,
  `.env` editor, per-target spawn (re-scan / resume / attack), and a live
  running-scans monitor.
- **Per-target operator console** — `agui <target>` builds a bespoke
  localhost webapp from that target's own data: sidebar of exposed
  entities, action panel, live logs, terminal, repeater. Iterate with
  `agui chat <target> "..."`.
- **Reports** — `REPORT.md` (comprehensive), `report.html` (styled),
  `report.pdf` (final). Auto-generated at scan end, also callable
  mid-scan with `REPORT:`.

---

## Install

### Requirements

- **Linux** or **WSL2 on Windows** (Ubuntu 22.04+ recommended)
- Python 3.10+
- `curl`, `git` — bootstrap handles the rest
- An LLM API key OR a local model server

> **Windows users:** run the agent inside WSL2, not native Windows.
> See [Windows / WSL2](#windows--wsl2) below. `bootstrap.sh` is bash and
> the agent uses Linux process primitives (`os.setsid`, `killpg`).

---

### Linux / WSL2 — one-command install

```bash
cd ~
git clone https://github.com/devlp-io/agent.git
cd agent
bash bootstrap.sh
source ~/.bashrc
```

`bootstrap.sh` is idempotent. It installs Python deps, Go, pipx, cargo,
PDF tooling, wordlists, and creates the venv. Running it twice is harmless.

---

### Windows / WSL2

Native Windows CMD or PowerShell will not work — `bootstrap.sh` is bash,
and the harness depends on POSIX process groups (`os.setsid`, `os.killpg`)
for its watchdog. Use WSL2.

**Step 1 — install WSL2 + Ubuntu**

Open **PowerShell as Administrator** (right-click Start → *Terminal (Admin)*
or *Windows PowerShell (Admin)*).

```powershell
wsl --install -d Ubuntu
```

This installs the Virtual Machine Platform and the Windows Subsystem for
Linux, then downloads Ubuntu.

**Step 2 — reboot**

When it prints *"Please reboot your machine to finish the installation"*,
reboot Windows.

**Step 3 — first-run Ubuntu setup**

After reboot, Ubuntu opens automatically (or search **Ubuntu** in the start
menu). It runs `Installing, this may take a few minutes…`, then asks:

- `Enter new UNIX username:` — pick a lowercase name, e.g. `Libaan`
- `New password:` — type it (nothing echoes on screen), Enter, re-type, Enter

You land at `username@HOSTNAME:~$` — a Linux shell with `~/` mapped to a
real path inside WSL (not your Windows user folder).

**Step 4 — clone and bootstrap**

Inside that Ubuntu shell:

```bash
cd ~
git clone https://github.com/devlp-io/agent.git
cd agent
bash bootstrap.sh
source ~/.bashrc
```

**Step 5 — aliases**

```bash
cat >> ~/.bashrc <<'EOF'

# ag (autonomous security agent)
export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/agent/tools:$HOME/.local/bin:$PATH"
alias agds='cd "$HOME/agent" && source venv/bin/activate && python agent_v8.py'
alias agres='cd "$HOME/agent" && source venv/bin/activate && python agent_v8.py --resume'
alias agreport='cd "$HOME/agent" && source venv/bin/activate && python reporter.py "$(ls -td ~/scans/*/*/ 2>/dev/null | head -1)"'
alias agui-start='cd ~/agent && source venv/bin/activate && (pkill -9 -f dashboard.py 2>/dev/null; sleep 1; nohup python dashboard.py --port 8787 > ~/agent/dashboard.log 2>&1 & echo $! > ~/agent/dashboard.pid; sleep 2; echo "started pid $(cat ~/agent/dashboard.pid)"; cat ~/agent/dashboard.log)'
alias agui-stop='pkill -9 -f dashboard.py 2>/dev/null && echo stopped || echo "not running"'
alias agui-tail='tail -f ~/agent/dashboard.log'
EOF

source ~/.bashrc
```

**Step 6 — API key**

```bash
cd ~/agent
cat > .env <<'EOF'
AG_MODEL=deepseek-chat
AG_BASE=https://api.deepseek.com/v1
DEEPSEEK_KEY=sk-YOUR-REAL-KEY-HERE
AG_KEY=$DEEPSEEK_KEY
EOF
chmod 600 .env
```

Or use the dashboard **Config** tab after starting it once.

**Step 7 — smoke test**

```bash
agds "probe https://example.com for headers and tech stack"
```

Streams agent output. Type `yes` at the authorization prompt. When it hits
`DONE`, the run is done.

**Step 8 — dashboard**

```bash
agui-start
```

Open `http://127.0.0.1:8787/` in your **Windows** browser (Edge, Chrome,
Firefox — anything). WSL2 forwards `localhost` automatically on recent
builds.

If `127.0.0.1:8787` refuses, get the WSL IP and use that instead:

```bash
hostname -I | awk '{print $1}'
# → 172.x.x.x
# open http://172.x.x.x:8787/ in Windows
```

---

### Configure the LLM

The agent reads model config from env vars or `~/agent/.env`. Pick one:

**Option A — DeepSeek** (recommended, cheap and fast)

```bash
cd ~/agent
cat > .env <<'EOF'
AG_MODEL=deepseek-chat
AG_BASE=https://api.deepseek.com/v1
DEEPSEEK_KEY=sk-your-key-here
AG_KEY=$DEEPSEEK_KEY
EOF
```

**Option B — Ollama** (local, free)

```bash
# install ollama first: https://ollama.com
ollama pull dolphin3
# default .env already targets localhost:11434
```

**Option C — Gemini / OpenAI / any OpenAI-compatible endpoint**

```bash
cd ~/agent
cat > .env <<'EOF'
AG_MODEL=gemini-1.5-flash
AG_BASE=https://generativelanguage.googleapis.com/v1beta/openai
AG_KEY=your-gemini-key
EOF
```

---

## Usage

### Run a scan

```bash
agds "assess example.com for vulnerabilities"
```

You will see:

```
extracting target from prompt...
target: example.com
active security assessment — authorized testing only
type 'yes' to continue:
```

Type `yes`. The scan runs. Turn headers + agent output stream to terminal.
Live logs go to `~/scans/<target>/<timestamp>/`.

### Watch live from another terminal

```bash
SCAN=$(ls -td ~/scans/*/* 2>/dev/null | head -1)
tail -f $SCAN/live.log
tail -f $SCAN/live_findings.log
tail -f $SCAN/live_commands.log
```

### Resume

```bash
agres example.com
```

Picks the most recent run of that target and continues from the last turn.

### Dashboard

```bash
agui-start          # background server
agui-stop           # kill it
agui-tail           # follow the server log
```

Open `http://127.0.0.1:8787/`. Tabs:

- **Overview** — finding counts, stack, methodologies, recent findings
- **Logs** — live.log, live_findings.log, live_commands.log (1.2s poll)
- **Findings** — filterable, click a finding to send its URL to the repeater
- **Actions** — dispatch any directive by hand (`PROBE:`, `WALK:`, `CVE:`…)
- **Repeater** — raw HTTP client, arbitrary method / headers / body
- **Shell** — run any command through the same `_run_shell` the agent uses
  (deny-list + scope enforced, history via ↑/↓)
- **Tools** — search the ~130 catalog and install missing tools
- **Config** — view/edit `.env`, warnings when env vars override the file
- **Running** — spawned scans with live stdout, external scans with disk tail

Top bar: **↻ re-scan / ▶ resume / ⚔ attack** spawn the agent on the
currently selected target.

### Regenerate the report

```bash
agreport
```

### Open the PDF (WSL)

```bash
explorer.exe "$(wslpath -w "$(ls -td ~/scans/*/*/ 2>/dev/null | head -1)/report.pdf")"
```

---

## Configuration

| var              | default                        | purpose                                        |
| ---------------- | ------------------------------ | ---------------------------------------------- |
| `AG_MODEL`       | `deepseek-chat`                | model name                                     |
| `AG_BASE`        | `https://api.deepseek.com/v1`  | API base URL                                   |
| `AG_KEY`         | `$DEEPSEEK_KEY`                | API key                                        |
| `AG_MAX_TURNS`   | `500`                          | max turns before stopping                      |
| `AG_CMD_TIMEOUT` | `7200`                         | per-command timeout (seconds)                  |
| `AG_CURL_TIMEOUT`| `25`                           | curl timeout (auto-injected into bare curls)   |
| `AG_PROXY`       | *(empty)*                      | `socks5://127.0.0.1:9050` for tor              |
| `AG_SCAN_ROOT`   | `~/scans`                      | where run dirs are written                     |
| `AG_CTX_MAX`     | `60`                           | max messages before summarizing history        |
| `AG_CTX_KEEP`    | `24`                           | messages kept verbatim after summarization     |
| `AG_MAX_REQ`     | `0` (unlimited)                | budget cap on requests                         |
| `AG_MAX_TIME`    | `0` (unlimited)                | budget cap on wall-clock seconds               |
| `AG_MAX_BYTES`   | `0` (unlimited)                | budget cap on response bytes                   |
| `AG_VERBOSE`     | `0`                            | set to `1` for verbose streaming               |

All vars can go in `~/agent/.env` — the dashboard's **Config** tab edits it.

---

## Architecture

The LLM never touches the machine directly. It emits text in a directive
syntax (`COMMAND:`, `PROBE:`, `FINDING:`, …). The Python harness parses
those directives and decides what actually runs.

This is the safety boundary AND the extensibility point.

```
┌──────────────────────────────────────────────────────────┐
│ 1. send history to LLM                                    │
│ 2. LLM replies with directive(s): COMMAND:, PROBE:, etc  │
│ 3. harness parses directives (line-anchored, fences off) │
│ 4. harness runs each, streams stdout to live logs        │
│ 5. results appended to history                            │
│ 6. loop until DONE / stall / max turns                   │
└──────────────────────────────────────────────────────────┘
```

### Files

| file                       | role                                                     |
| -------------------------- | -------------------------------------------------------- |
| `agent_v8.py`              | entry: main loop, directives, attack phase               |
| `core/state.py`            | checkpoint, heartbeat, scratchpad, kill switch           |
| `core/http.py`             | httpx client (sync + persistent async)                   |
| `core/async_engine.py`     | asyncio engine, 429-aware auto-throttle                  |
| `core/proxy.py`            | proxy pool, 3-strike disable, health score               |
| `core/browser.py`          | chromium subprocess wrapper                              |
| `intel/cve_db.py`          | local sqlite NVD snapshot, FTS                           |
| `intel/waf_matrix.py`      | fingerprint → bypass playbook                            |
| `intel/stack_router.py`    | tech signature → methodology                             |
| `intel/critic.py`          | LLM self-review between phases                           |
| `intel/schema.py`          | state → semantic target model (entities, fields, recs)   |
| `attack/chains.py`         | finding A + finding B → chained exploit rule engine      |
| `attack/mutate.py`         | payload encoder                                          |
| `attack/blind.py`          | time-based SQLi/CMDi + local OOB callback listener       |
| `attack/pivot.py`          | nxc / impacket / hydra wrappers                          |
| `evidence/collector.py`    | HAR + DOM + screenshots per finding                      |
| `evidence/report.py`       | exec / tech / poc tiered reports                         |
| `evidence/graph.py`        | attack graph JSON + DOT export                           |
| `evidence/seal.py`         | sha256 manifest, HMAC                                    |
| `evidence/schema_store.py` | persist `schema.json` next to the run                    |
| `dashboard.py`             | localhost UI (FastAPI + SSE/poll + inline JS)            |
| `reporter.py`              | `REPORT.md` + `report.html` + `report.pdf`               |
| `installer.py`             | platform-aware install engine                            |
| `tools_db.py`              | ~130 tool catalog                                        |
| `scope.py`                 | allowlist enforcement via `scope.txt`                    |
| `budget.py`                | per-run caps (requests / time / bytes)                   |
| `rollback.py`              | `.bak` on every `FILE:` write                            |
| `bootstrap.sh`             | fresh-machine installer                                  |
| `jailbreak.txt`            | ??             |
| `PROJECT.md`               | full project spec — read this for development            |

---

## Directives

Emitted by the model, parsed by the harness. Line-anchored, fenced code
blocks are ignored so examples don't execute.

```
COMMAND      <shell>
PARALLEL     <cmd1> ||| <cmd2> ||| <cmd3>
INSTALL      <name | github:owner/repo | pip:pkg | apt:pkg | …>
NEED_TOOL    <name>|<why>
TOOLS        list | search <q> | status | install <name>
FILE         <path>|<content>
LIST         <dir>
NOTE         <text>
FINDING      <sev>|<title>|<evidence>
ENDPOINT     <METHOD>|<URL>[|note]
PROBE        <METHOD>|<URL>
PLAN         <markdown>
PAYLOAD      xss|sqli|ssrf|lfi|rce|ssti|crlf|nosqli
SECRET       <text or /path>
CRED         <user>|<pass>[|where]
SCREENSHOT   <url>
CVE          <product>|<version>
METHOD       <name>
PARAMFIND    <METHOD>|<URL>[|p1,p2,…]
WALK         <METHOD>|<URL>|<param>|<start>|<end>[|outfile][|conc]
APIMAP       <base_url>
HARVEST      <path>
SEARCH       <query>
FETCH        <url>
REPORT       <reason>
PROOF        <label>|<content>
EXPLOIT      <tool>|<target>|<args>
SHELL        <kind>|<lhost>|<lport>
LOOT         <kind>|<value>
CRACK        <hash>|auto
PIVOT        <target>|<creds_ref>
STATUS
CHAIN        <from>|<to>[|note]
BROWSER      <url>
GRAPHQL      <url>|<query_json>
WS           <wss_url>|<payload>
OOB          <method>|<url>|<param>|<payload_with_{callback}>
MUTATE       <payload>|<context>
CHAIN_AUTO
HAR          <url>
BUDGET       status | set max_req=N
WAF          <url>
STACK        <url>
SCHEMA
```

`DONE` (on its own line, `^\s*DONE\b`) terminates the scan. Max 2 directives
per turn. `DONE` never runs in the same turn as a `COMMAND`.

---

## Scope enforcement

Drop a `scope.txt` in a run dir (or `~/agent/scope.txt`). One host per line,
`*.example.com` wildcards allowed, `#` for comments:

```
# scope for this assessment
example.com
*.example.com
api.partner.net
```

If the file exists, every URL in a shell command, `PROBE:`, `WALK:`,
`APIMAP:`, and `EXPLOIT:` is checked against it. Out-of-scope URLs return
`[SCOPE BLOCK]` and never reach the network. If the file is absent, scope
is disabled (current default for convenience — flip in `scope.py` if you
want default-deny).

---

## Development

```bash
cd ~/agent
code .

# syntax check
python -c "import ast; ast.parse(open('agent_v8.py').read()); print('agent ok')"
python -c "import ast; ast.parse(open('dashboard.py').read()); print('dash ok')"

# regenerate report for a scan without re-running the agent
python reporter.py ~/scans/<target>/<timestamp>/
```

`PROJECT.md` is the source of truth for design decisions and invariants.
Read it before touching anything.

---

## Per-target operator console

Every scanned target gets its own bespoke webapp on localhost. Not one
dashboard for all targets — a console generated from THAT target's actual
recon, findings, leaks, and successful actions, with a category sidebar,
action panel, live logs, and a terminal.

    agui example.com

Output:

    [ui-builder] target=example.com  mode=initial
    [ui-builder] generating index.html + app.py ...
    [ui-builder] generated in 22.7s (html=18467B py=8580B)
    [ui-builder] ready at http://127.0.0.1:8803/
    [ui-builder] pid=12345  log=/home/user/scans/example.com/uiapp/app.log

The browser opens automatically.

### Commands

| command                    | what it does                                  |
| -------------------------- | --------------------------------------------- |
| `agui <target>`            | build + run the console for that target       |
| `agui update <target>`     | rebuild against the newest scan state         |
| `agui chat <target> "..."` | ask the UI agent for a change, rebuild        |
| `agui stop <target>`       | kill the server                               |
| `agui status <target>`     | port, pid, alive, last build time             |

### What gets built

The UI-builder is an LLM loop. It receives a JSON context containing:

- **recorder** — every command / finding / probe / walk / secret / cred /
  loot / endpoint the agent ever produced against this target, appended
  across all runs
- **state** — the newest run's `state.json`
- **schema** — the deduced target model (entities, capabilities, sensitive
  fields, recommendations)

It then emits TWO files into `~/scans/<target>/uiapp/`:

    index.html   self-contained page — inline CSS+JS, dark, monospace
    app.py       single-file FastAPI server (stdlib + fastapi + httpx only)

The sidebar categories, entity cards, and available actions are derived
from what the target actually exposes. A wallet target gets PAYMENTS /
KYC / USERS panels. A blog gets POSTS / COMMENTS / USERS. Nothing is
assumed — everything is read from the target's own data.

### The generated app exposes

| route                 | what it does                                        |
| --------------------- | --------------------------------------------------- |
| `GET  /`              | the console HTML                                    |
| `GET  /api/state`     | newest run's state.json                             |
| `GET  /api/schema`    | schema.json                                         |
| `GET  /api/recorder`  | last N recorder events                              |
| `GET  /api/logs`      | live.log / live_commands.log / live_findings.log    |
| `POST /api/shell`     | `{cmd}` → `agent_v8._run_shell` (deny-list + scope) |
| `POST /api/directive` | `{kind, payload}` → `agent_v8.dispatch()`           |
| `POST /api/scan`      | spawn a fresh `agent_v8` run for this target        |
| `POST /api/attack`    | spawn with `--attack`                               |
| `POST /api/resume`    | spawn with `--resume`                               |

### The recorder

`core/recorder.py` appends every action to
`~/scans/<target>/recorder.jsonl` — one JSON event per line. It survives
across scans: if you scan the same target tomorrow, the console still
knows what happened today.

Recorded kinds:

    command    cmd + output + ok/fail
    finding    sev + title + evidence
    probe      method + url + unauth_2xx
    walk       method + url + param + hits + sample rows
    secret     kind + value + source path
    cred       user + pass-len + where
    loot       kind + value
    endpoint   method + url + note
    result     explicit read/write outcome

Hooked automatically inside `agent_v8.dispatch()` — no per-directive code.

### Iterating on a console

    agui chat nuunipay.com "add a repeater panel with method swap"
    agui chat nuunipay.com "widen the sidebar, group entities by schema category"
    agui chat nuunipay.com "add a button that fires PROBE on every 401 URL"

Each call sends the full prior context plus your message to the UI-builder
agent, which rewrites `index.html` and `app.py` from scratch. The old
server is killed, the new one takes its port.

### Ports

Per-target ports are deterministic — `SHA256(target) % 200 + 8801`. Same
target always binds the same port. Different targets never collide.

### Files

    ~/scans/<target>/
      recorder.jsonl          append-only action log (across all runs)
      uiapp/
        index.html            generated UI
        app.py                generated FastAPI server
        app.log               server stdout + tracebacks
        app.pid               current pid
        .meta.json            port, started_at, last build info

### Notes

- Uses the same model as `agent_v8` — reads `AG_MODEL` / `AG_BASE` / `AG_KEY`
  from `.env` or your shell env. Switch providers with `agm <profile>` before
  invoking `agui` if you want a different model for the UI builder.
- The generated `app.py` MUST NOT embed HTML in a Python string — that's
  the whole point of the two-file structure. If a build fails validation
  with "unterminated triple-quoted string", rerun `agui <target>`.
- `max_tokens=12000` on the LLM call. HTML capped at ~400 lines, Python at
  ~250. Large targets may truncate — rerun, or use `agui chat` to nudge.
- Generated apps are validated for FastAPI + required routes before
  starting. If validation fails, the app is NOT spawned and the old
  version keeps running.

---

## License

Use only on systems you are authorized to test. The operator decides scope.
READMEEOF

python3 -c "import ast; import pathlib; print('readme length:', len(pathlib.Path('README.md').read_text()))"
```

then commit:

```bash
cd ~/agent
git add README.md
git status
git commit -m "docs: expand README with WSL2 setup + dashboard + scope + directives"
git push origin main
```

paste the `git status` and push output. after this, anyone cloning the repo — including you on a fresh machine — gets the full walkthrough from `git clone` to running scan.
