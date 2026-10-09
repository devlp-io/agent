# ag — autonomous security assessment agent

A terminal-run AI agent for **authorized** security assessment. Point it at a
target, walk away, come back to findings + a full PDF report.
$ agds "assess example.com for vulnerabilities"

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
  Rails, Express, PHP, WordPress, GraphQL) and loads the matching
  methodology.
- **API hunting** — finds `openapi.json` / `swagger.json` and auto-registers
  every path. PARAMFIND brute-forces param names. WALK enumerates IDs.
- **Auth-bypass probing** — 9 header variants fire on every 401/403
  (empty bearer, admin bearer, X-Forwarded-For, X-Original-URL, etc).
- **Secrets** — scans config files, JS bundles, .env, .git/config for AWS,
  GCP, GitHub, Stripe, JWTs, private keys.
- **Web search + fetch** — the model can `SEARCH:` the web for CVEs and
  `FETCH:` writeups mid-scan.
- **Self-installing** — curated recipes for ~65 tools. Any GitHub/GitLab
  repo installs with auto-detected build system (go, cargo, npm, make,
  python, maven, gradle).
- **Live logs** — `live.log`, `live_commands.log`, `live_findings.log`
  stream as the scan runs.
- **Reports** — `REPORT.md` (comprehensive), `report.html` (styled),
  `report.pdf` (final). Auto-generated at scan end, also callable
  mid-scan with `REPORT:`.

---

## Install

### Requirements

- Linux or WSL2 (Ubuntu 22.04+ recommended)
- Python 3.10+
- `curl`, `git` (bootstrap handles the rest)
- An LLM API key OR a local model server

### One-command install

```bash
git clone <your-repo-url> ~/agent
cd ~/agent
bash bootstrap.sh
source ~/.bashrc

bootstrap. sh is idempotent. It installs Python deps, Go, pipx, cargo,

wkhtmltopdf/system-PDF-libs, SecLists, and creates the venv. Run it twice,

no harm.

Configure the LLM

The agent reads model config from env vars. Pick

one:

Option A - DeepSeek (recommended, cheap and fast)

echo 'export DEEPSEEK_KEY="sk-your-key-here"' >> ~/.bashrc
source ~/.bashrc

Option B - Ollama (local, free)
# install ollama first (https://ollama.com)
ollama pull dolphin3
# default config already targets localhost:11434

Option C - Gemini / OpenAl / any OpenAl-compatible endpoint

export AG_MODEL=gemini-1.5-flash
export AG_BASE=https://generativelanguage.googleapis.com/v1beta/openai
export AG_KEY=your-gemini-key

Wire the aliases

cat >> ~/.bashrc <<'EOF'
export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/agent/tools:$HOME/.local/bin:$PATH"
alias .ag='ag'
alias agds='AG_MODEL=deepseek-chat AG_BASE=https://api.deepseek.com/v1 AG_KEY=$DEEPSEEK_KEY ag'
alias agres='ag --resume'
EOF
source ~/.bashrc

Usage

Run a scan

you will see:

extracting target from prompt...
target: example.com
active security assessment — authorized testing only
type 'yes' to continue:
type yes the agent runs.

watch live in another terminal:

SCAN=$(ls -td ~/scans/*/* 2>/dev/null | head -1)
tail -f $SCAN/live.log
tail -f $SCAN/live_findings.log
tail -f $SCAN/live_commands.log

Resume scan:
agres example.com

Regenerate the Report:

agreport


Open the PDF (WSL)

explorer.exe "$(wslpath -w "$(ls -td ~/scans/*/*/ 2>/dev/null | head -1)/report.pdf")"



configuration:

var default purpose
AG_MODEL dolphin3 model name
AG_BASE http://localhost:11434/v1 API base URL
AG_KEY ollama API key
AG_FALLBACKS empty model@base\|model@base fallback chain
AG_MAX_TURNS 300 max turns before stopping
AG_CMD_TIMEOUT 1800 per-command timeout (seconds)
AG_CURL_TIMEOUT 25 curl timeout (seconds, auto-injected)
AG_PROXY empty socks5://127.0.0.1:9050 for tor
AG_SCAN_ROOT ~/scans where scans are written
AG_CTX_MAX 40 max messages before summarizing history
AG_VERBOSE 0 set to 1 for verbose streaming

Architecture

The LLM never touches the machine directly. It emits text in a directive

syntax (COMMAND:, PROBE:, FINDING:, etc). The

Python harness parses

those directives and decides what actually runs.

This is the safety

boundary AND the extensibility point.

┌──────────────────────────────────────────────────────────┐
│ 1. send history to LLM                                    │
│ 2. LLM replies with directive(s): COMMAND:, PROBE:, etc  │
│ 3. harness parses directives                              │
│ 4. harness runs each, streams stdout to live logs         │
│ 5. results appended to history                            │
│ 6. loop until DONE / stall / max turns                    │
└──────────────────────────────────────────────────────────┘


file role
agent.py main orchestrator (single file)
reporter.py REPORT.md + HTML + PDF generator
bootstrap.sh fresh-machine installer
jailbreak.txt persona frame prepended to system prompt
PROJECT.md full project spec (read this for development)
tools/ git-installed binaries live here
wordlists/ API wordlists + SecLists
venv/ python virtualenv


development:

# edit files
cd ~/agent
code .

# syntax check
python3 -c "import ast; ast.parse(open('agent.py').read()); print('agent ok')"
python3 -c "import ast; ast.parse(open('reporter.py').read()); print('reporter ok')"

# regenerate report for latest scan without running the agent
python reporter.py ~/scans/<target>/<timestamp>/