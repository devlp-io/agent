# SOM-SCAN & Autonomous offensive & defensive CLI Agent developed by LP

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20|%20macOS%20|%20Windows%20|%20Android%20Termux-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![Interface](https://img.shields.io/badge/interface-Terminal%20UI%20|%20CLI%20|%20Web%20Dashboard-orange.svg)]()

**SOM-SCAN** is an autonomous offensive security and red-team assessment agent engineered for authorized penetration testing, vulnerability discovery, and security auditing. It pairs a high-performance autonomous security engine with an interactive, modern Terminal User Interface (TUI) inspired by OpenAI Codex CLI and OpenCode.

Point it at an authorized target or chat with it directly from your terminal. SOM-SCAN conducts reconnaissance, fingerprints technology stacks, maps exposed APIs, audits authentication mechanisms, hunts for secrets, evaluates vulnerability chains, synthesizes entity schemas, and compiles audit-ready reports.

```
   ███████╗ ██████╗ ███╗   ███╗      ███████╗ ██████╗ █████╗ ███╗   ██╗
   ██╔════╝██╔═══██╗████╗ ████║      ██╔════╝██╔════╝██╔══██╗████╗  ██║
   ███████╗██║   ██║██╔████╔██║█████╗███████╗██║     ███████║██╔██╗ ██║
   ╚════██║██║   ██║██║╚██╔╝██║╚════╝╚════██║██║     ██╔══██║██║╚██╗██║
   ███████║╚██████╔╝██║ ╚═╝ ██║      ███████║╚██████╗██║  ██║██║ ╚████║
   ╚══════╝ ╚═════╝ ╚═╝     ╚═╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
             Autonomous Red Team & Security Assessment Engine
```

---

## Table of Contents

1. [Features & Capabilities](#features--capabilities)
2. [Architecture & Workflow](#architecture--workflow)
3. [Interactive Terminal UI & Shortcuts](#interactive-terminal-ui--shortcuts)
4. [Installation & Setup](#installation--setup)
   - [Linux, macOS, WSL2, Termux](#linux-macos-wsl2-ubuntu-termux)
   - [Windows (PowerShell, cmd, Terminal)](#windows-powershell-cmd-windows-terminal)
   - [WSL2 Ubuntu notes](#wsl2-ubuntu-notes)
   - [What the first run does](#what-the-first-run-does)
5. [Model Configuration & Environment Variables](#model-configuration--environment-variables)
6. [Command Reference & Usage](#command-reference--usage)
7. [Security Tooling & Auto-Installer](#security-tooling--auto-installer)
8. [Reporting & Evidence Artifacts](#reporting--evidence-artifacts)
9. [Running the Test Suite](#running-the-test-suite)
10. [Safety & Scope Guardrails](#safety--scope-guardrails)

---

## Features & Capabilities

- **Intelligent Intent Routing**: Distinguishes greetings, coding tasks, local command execution, and security scans without false rejections.
- **Comprehensive Reconnaissance**: Subdomain enumeration (`subfinder`, `amass`, `assetfinder`), URL aggregation (`gau`, `waybackurls`), live HTTP probing (`httpx`), port scanning (`naabu`, `nmap`), and directory fuzzing (`katana`, `ffuf`, `gobuster`).
- **Stack & Technology Fingerprinting**: Detects frameworks (FastAPI, Django, Rails, Express, PHP, Spring Boot, WordPress, GraphQL) and tailors assessment methodologies accordingly.
- **API Surface Enumeration**: Automatically discovers OpenAPI / Swagger documentation, registers routes, brute-forces hidden query parameters (`PARAMFIND`), and enumerates entity identifiers (`WALK`).
- **Authentication & Authorization Auditing**: Fires 9+ header and token permutations on `401 Unauthorized` / `403 Forbidden` responses (blank bearer, admin bearer, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, etc.).
- **Secret & Token Harvesting**: Scans source trees, JavaScript bundles, environment files, and git configurations for AWS, GCP, Azure, Stripe, JWTs, and private keys.
- **Autonomous Exploit Chaining**: Systematically ladders findings through authentication bypasses, path traversal, HTTP method swaps, parameter mutations, and multi-step exploit chains.
- **Schema & Entity Synthesis**: Automatically groups endpoints into structured entities (users, orders, payments, admin), evaluates per-verb permissions, and flags sensitive fields (PII, credentials, KYC tokens) in `schema.json`.
- **Cross-Platform Terminal UI**: Minimal near-black layout (`#070c14`), real-time token streaming, animated status spinners, interactive Ctrl+C pause menu, slash command autocompletion, and toggleable output cards.
- **Localhost Management Dashboard**: Real-time web UI (`python dashboard.py` on port 8787) featuring live log tails, finding tables, manual directive dispatch, raw HTTP repeater, interactive shell, and scanner process manager.

---

## Architecture & Workflow

```
                        ┌───────────────────────────────┐
                        │      Operator / Terminal      │
                        │    somscan  /  tui.py  / CLI  │
                        └───────────────┬───────────────┘
                                        │ User Prompt / Directive
                                        ▼
                        ┌───────────────────────────────┐
                        │         Agent Router          │
                        │  (Chat / System / Assessment) │
                        └───────┬───────────────┬───────┘
          Direct Conversation   │               │ Security Scan
                                ▼               ▼
     ┌────────────────────────────┐   ┌─────────────────────────────┐
     │      Model Manager         │   │       Autonomous Engine     │
     │ DeepSeek / Gemini / Ollama │   │         agent_v8.py         │
     └────────────────────────────┘   └──────────────┬──────────────┘
                                                     │
         ┌───────────────────┬───────────────────────┼───────────────────────┐
         ▼                   ▼                       ▼                       ▼
  ┌──────────────┐    ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
  │  Recon & OS  │    │ API & Auth   │        │ Exploitation │        │ Evidence &   │
  │ Subdomains,  │    │ OpenAPI,     │        │ Parameter    │        │ Reports      │
  │ Ports, Probe │    │ 403 Bypasses │        │ Mutation, LFI│        │ PDF, HTML, MD│
  └──────────────┘    └──────────────┘        └──────────────┘        └──────────────┘
```

---

## Interactive Terminal UI & Shortcuts

Launch the interactive interface by simply running `somscan`:

```bash
somscan
```

### Slash Commands

| Command | Description |
|---|---|
| `/help` | Display interactive command reference and navigation guide |
| `/new` | Start a fresh assessment session, archive previous logs, and clear view |
| `/key [token]` | Set or update model API key in runtime session and `.env` |
| `/env` | Inspect active environment variables, model provider, and token status |
| `/model [name]` | View active model or switch engine profile (`deepseek-flash`, `gemini-2.5-flash`, etc.) |
| `/scan <target>` | Launch an autonomous security assessment against a URL or hostname |
| `/resume [target]` | Resume previous assessment session from last turn |
| `/phase [name]` | Inspect or switch active assessment phase (`RECON`, `PROBE`, `API_MAP`, `VULN_AUDIT`, `EXPLOIT`, `REPORT`) |
| `/subagent [name]`| Dispatch or inspect autonomous specialist subagents (`recon`, `api_auditor`, `exploit_crafter`, `reporter`) |
| `/malware <type>` | Scaffold specialized offensive tooling, loaders, crypters, and payloads |
| `/attack` | Toggle autonomous intrusive exploitation mode |
| `/tools` | Display installed and available security tooling catalog |
| `/install <name>` | Download and compile tool from the curated catalog |
| `/file <action>` | Built-in file management (`list`, `view <file>`, `cat <file>`, `rm <file>`) |
| `/cancel` | Cancel active background task, tool run, or assessment |
| `/clear`, `/cls` | Clear conversation viewport |
| `/long` | Expand long command outputs to view complete stdout / stderr |
| `/short` | Collapse command output cards back to compact view |
| `/copy` | Export active session conversation and terminal output to file |
| `/quit` | Cleanly exit SOM-SCAN |

### Keybindings

- **`Enter`**: Submit prompt or slash command.
- **`Shift + Enter`**: Insert line break inside the composer.
- **`Tab` / `Enter`**: Auto-complete highlighted slash command popup.
- **`Ctrl + C`**: Open the interactive Pause & Action Menu (allows choosing Continue, Chat, Focus, Copy, Stop, or Quit without terminating the process).
- **`Ctrl + Q`**: Instant clean exit.
- **`PageUp` / `PageDown`**: Scroll conversation history.

---

## Installation & Setup

One-time install, then `somscan` works from any directory — no aliases, no activating venvs.

**Requirements:** Python 3.10+, `git`. Node 18+ is only needed for the web console.

### Linux, macOS, WSL2 Ubuntu, Termux

```bash
git clone https://github.com/devlp-io/agent.git
cd agent
./install.sh
```

`install.sh` creates a local environment, installs requirements, preinstalls the core toolkit,
and puts `somscan` on your PATH (`~/.local/bin`). Then, from anywhere:

```bash
somscan            # interactive CLI
somscan gui        # web console (runs in the background)
```

Skip the toolkit preinstall with `./install.sh --no-toolkits` or `SOMSCAN_SKIP_TOOLKITS=1 somscan`.
You can also skip the installer and run `./somscan` directly from the repo — the first launch
bootstraps the same environment automatically.

### Windows (PowerShell, cmd, Windows Terminal)

```powershell
git clone https://github.com/devlp-io/agent.git
cd agent
powershell -ExecutionPolicy Bypass -File install.ps1
```

Or double-click / run `install.cmd`. Open a **new** terminal so PATH refreshes, then:

```powershell
somscan
somscan gui
```

The installer creates `%LOCALAPPDATA%\Programs\somscan\bin\somscan.cmd` and adds it to your
user PATH. `somscan.bat` / `somscan.ps1` in the repo also work directly on first run.

### WSL2 Ubuntu notes

Run the Linux installer inside the WSL shell. `somscan gui` starts the server inside WSL and
prints `http://127.0.0.1:8788/gui`; open that URL in your Windows browser. To expose it on the
LAN for a phone, run `somscan gui --host 0.0.0.0 --no-open`.

### What the first run does

1. Creates `.venv` (or `.venv_linux`) in the repo.
2. Installs `requirements.txt`.
3. Preinstalls the core toolkit profile (ProjectDiscovery, OSINT, AD, cloud, RE).
4. Launches the CLI (or the requested command).

The bootstrap runs once. Later launches go straight to the CLI.

---

## Updating the Agent (All Platforms)

Whenever new features, attack methodologies, UI enhancements, or supervisor updates are pushed upstream, operators can sync their local installation with a single command:

| Platform | One-Liner Update Command |
|---|---|
| **Linux / macOS / WSL2** | `cd ~/agent && git pull origin main && ./install.sh` |
| **Windows (PowerShell)** | `cd C:\agent; git pull origin main; powershell -ExecutionPolicy Bypass -File install.ps1` |
| **Android (Termux)** | `cd ~/agent && git pull origin main && ./install.sh` |

> [!TIP]
> Your `.env` credentials, custom methodologies, and local scan artifacts (`~/scans/` or `C:\Users\<user>\scans\`) are never overwritten during updates because they are excluded in `.gitignore`.

---

## Model Configuration & Environment Variables

SOM-SCAN supports any OpenAI-compatible inference endpoint, hosted frontier models, or air-gapped local LLMs. Configuration is read from `.env` in the project root:

```bash
# ==============================================================================
# Primary Model Configuration
# ==============================================================================

# Option 1: DeepSeek (Recommended for high speed, reasoning, and cost efficiency)
AG_MODEL=deepseek-flash
AG_BASE=https://api.deepseek.com/v1
DEEPSEEK_KEY=sk-your-deepseek-key-here
AG_KEY=sk-your-deepseek-key-here

# Option 2: DeepSeek Reasoner (Deep thinking / complex vulnerability research)
# AG_MODEL=deepseek-reasoner
# AG_BASE=https://api.deepseek.com/v1
# AG_KEY=sk-your-deepseek-key-here

# Option 3: Google Gemini (via OpenAI compatibility endpoint)
# AG_MODEL=gemini-2.5-flash
# AG_BASE=https://generativelanguage.googleapis.com/v1beta/openai
# GEMINI_KEY=your-gemini-key-here
# AG_KEY=your-gemini-key-here

# Option 4: Local Ollama (Air-gapped / offline testing)
# AG_MODEL=dolphin3
# AG_BASE=http://localhost:11434/v1
# AG_KEY=ollama

# Option 5: OpenAI
# AG_MODEL=gpt-4o
# AG_BASE=https://api.openai.com/v1
# OPENAI_API_KEY=sk-your-openai-key-here

# ==============================================================================
# Agent Execution Parameters
# ==============================================================================
AG_SCAN_ROOT=~/scans           # Directory for session logs, evidence, and reports
AG_TIMEOUT=120                 # Shell execution command timeout in seconds
AG_ATTACK=0                    # Set to 1 to auto-approve exploitation directives
AG_AUTO_INSTALL=1              # Allow agent to install missing security tools
```

Predefined model presets can be viewed and switched live inside the TUI with:
```text
/model deepseek-chat
/model gemini
/model ollama
```

---

## Command Reference & Usage

### 1. Interactive Terminal UI Mode (Recommended)
```bash
somscan
```

### 2. Direct Target Assessment (CLI)
Initiate an assessment directly from shell:
```bash
somscan --scan https://example.com
```

### 3. Non-Interactive / Scriptable Assessment
Run the autonomous backend engine headless:
```bash
python agent_v8.py "assess target.com for authentication flaws and open endpoints"
```

### 4. Resuming an Interrupted Scan
Resume the latest scan or a specific target without losing prior context:
```bash
somscan --resume
# or
python agent_v8.py --resume target.com
```

### 5. Localhost Web Dashboard
Launch the real-time web monitoring and control console:
```bash
python dashboard.py --port 8787
```
Open `http://127.0.0.1:8787` in any browser to inspect live log streams, inspect finding tables, interact with the HTTP repeater, or dispatch operator directives.

### 6. Agent Web GUI (Antigravity-style)

A production, responsive chat console: streaming replies, multi-thread history, media/file
attachments, live tool cards, model + variant switching, per-thread token/cost usage, scan
control, and an artifacts/context panel.

```bash
somscan gui                  # start in the background, prints the URL
somscan gui status           # is it running?
somscan gui stop             # stop it

somscan gui --port 9000      # custom port
somscan gui --host 0.0.0.0   # expose on the LAN (phone/tablet)
somscan gui --no-open        # do not open a browser
```

The first `somscan gui` builds the frontend if needed (Node 18+). Server logs live at
`~/.somscan/gui.log`. Default URL: `http://127.0.0.1:8788/gui`.

Development (Vite HMR on :5173, API proxied to :8788):
```bash
make gui-dev
```

Key routes:
- `http://127.0.0.1:8788/gui` — the SPA
- `http://127.0.0.1:8788/api/v2/docs` — OpenAPI docs
- `python3 webgui/test_api.py` — backend smoke tests (21 checks, no LLM needed)

Behaviour notes:
- Chat is stored in `~/.somscan/webgui/gui.db` (SQLite, WAL), uploads in `~/.somscan/webgui/uploads/`.
- **Agent mode** drives the same brain as the TUI/CLI (`core.agent_router.AgentRouter`): it plans,
  emits real `COMMAND:`/`FILE:`/scan directives, runs them through the supervised task runner,
  self-corrects on failure, and shows each command as a live tool card. If a model leaks native
  tool-call tokens instead, the console recovers the command, runs it, and feeds the result back.
  Operator prompts (sudo, confirmations) surface as inline answer cards.
- **Chat mode** answers without touching the machine.
- Each chat keeps its own CLI agent session; delete the chat to drop the session.
- Agent replies are an **activity feed**, not a code dump: collapsed "Thought for Ns", one row per
  action (`Edited index.html`, `Ran shell command`, `Analyzed app.py L12-25`), the newest shell
  expanded, and a short action summary. File code lives in the action card, never as plain text.
- Chat mode keeps code visible in syntax-highlighted boxes with a language tag and copy button.
- No "create chat" step: typing or dropping a file auto-creates a thread. The hero stays until the
  first message.
- Everything persists locally in `gui.db` — threads, messages, uploads **and** the CLI agent's full
  memory per thread, so a server restart resumes the same conversation.
- Bind is loopback by default. For remote access, set a shared secret and pass it once:
  ```bash
  AG_GUI_TOKEN=long-random-string python webgui/server.py --host 0.0.0.0 --port 8788
  # open http://host:8788/gui?token=long-random-string  (cookie is set for media/SSE)
  ```

### 7. Local SQLite Session Database & Memory Recall
SOM-SCAN automatically maintains an embedded SQLite database (`~/.somscan/sessions.db`) persisting every chat turn, finding, and scan across CLI sessions:
- `/sessions` or `/history` — List saved sessions with targets, message counts, and timestamps.
- `/load <session-id>` — Switch active session and restore full memory context into conversation history.
- `/search <query>` — Full-text search across sessions, findings, targets, and logs.
- Natural language continuation: say `"continue"`, `"resume"`, or ask questions about findings, and the agent recalls target state first-hand.

---

## Security Tooling & Auto-Installer

SOM-SCAN contains an integrated database of ~130 security tools (`tools_db.py`). Missing tools are automatically detected, fetched, and compiled on demand across Go, Cargo, Pip, and package managers.

| Category | Utilities |
|---|---|
| **Subdomain & DNS** | `subfinder`, `amass`, `assetfinder`, `puredns`, `dnsx` |
| **Port Scanning & Probing** | `naabu`, `nmap`, `httpx`, `masscan` |
| **Content Discovery & Crawlers** | `katana`, `gau`, `waybackurls`, `ffuf`, `gobuster`, `dirsearch` |
| **Vulnerability Scanning** | `nuclei`, `dalfox`, `sqlmap`, `ghauri`, `cve-search` |
| **Wordlists & Payloads** | `SecLists`, `PayloadsAllTheThings`, `api_routes` |
| **Analysis & Extraction** | `jq`, `gron`, `trufflehog`, `gitleaks` |

Check installed tool status inside the TUI using `/tools` or trigger a manual install using `/install <tool_name>`.

---

## Reporting & Evidence Artifacts

Every completed or active assessment persists structured artifacts under `~/scans/<target>/<timestamp>/`:

- **`REPORT.md`**: In-depth executive summary, vulnerability breakdown, severity scores, reproduction steps, and remediation advisories.
- **`report.html`**: Clean, self-contained HTML report styled for stakeholders and security teams.
- **`report.pdf`**: Printable PDF audit report (compiled via WeasyPrint or headless browser).
- **`schema.json`**: Entity-relationship map synthesized from observed endpoints, HTTP verbs, and data attributes.
- **`graph.json`**: Attack path graph tracing enumeration to confirmed exploitation.
- **`recorder.jsonl`**: Append-only log of every command executed, exit code, and raw stdout.
- **`live.log`**, **`live_findings.log`**, **`live_commands.log`**: Streaming logs for real-time monitoring.

---

## Running the Test Suite

SOM-SCAN includes an automated unit and integration test suite covering startup, syntax across the entire tree, TUI components, input handling, model fallback, tool dispatch, cancellation lifecycle, and reporting:

```bash
python -m unittest test_somscan.py -v
```

All 39 test cases validate in under 30 seconds with zero external dependencies.

---

## Safety & Scope Guardrails

- **Explicit Authorization**: The autonomous engine requires target validation and explicit operator confirmation before firing destructive or intrusive scans.
- **Scope Restriction**: All crawl targets, parameter tests, and probe requests validate against the authorized target scope. Out-of-scope pivots are blocked.
- **Destructive Command Deny-List**: The harness strictly blocks destructive system commands (e.g., `rm -rf /`, `mkfs`, raw device writes `dd`).
- **Graceful Cancellation**: Immediate process-tree termination upon `/cancel` or `Ctrl+C` prevents orphaned scanner processes or lingering background network activity.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
