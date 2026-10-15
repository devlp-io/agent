# SOM-SCAN & Autonomous Red Team Agent

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
   - [Linux (Ubuntu, Debian, Kali, Arch)](#linux-ubuntu-debian-kali-arch)
   - [macOS (Apple Silicon & Intel)](#macos-apple-silicon--intel)
   - [Windows (Native PowerShell & CMD)](#windows-native-powershell--cmd)
   - [Windows (WSL2 Ubuntu)](#windows-wsl2-ubuntu)
   - [Android Termux](#android-termux)
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
| `/model [name]` | View active model or switch engine profile (`deepseek-chat`, `gemini-2.5-flash`, etc.) |
| `/scan <target>` | Launch an autonomous security assessment against a URL or hostname |
| `/resume [target]` | Resume previous assessment session from last turn |
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

### Linux (Ubuntu, Debian, Kali, Arch)

1. **System Prerequisites**:
   ```bash
   # Debian / Ubuntu / Kali
   sudo apt update && sudo apt install -y python3 python3-pip python3-venv git curl build-essential

   # Arch Linux
   sudo pacman -Syu python python-pip git curl base-devel
   ```

2. **Clone & Set Up Virtual Environment**:
   ```bash
   git clone https://github.com/devlp-io/agent.git ~/agent
   cd ~/agent
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt textual rich openai httpx python-dotenv
   ```

3. **Configure Environment**:
   ```bash
   cp .env.examples .env
   # Edit .env with your preferred editor and insert your API key:
   # DEEPSEEK_KEY=sk-... or AG_KEY=sk-...
   ```

4. **Launch**:
   ```bash
   chmod +x somscan
   ./somscan
   ```

5. *(Optional)* **Add to System PATH**:
   ```bash
   echo 'export PATH="$HOME/agent:$PATH"' >> ~/.bashrc
   source ~/.bashrc
   ```

---

### macOS (Apple Silicon & Intel)

1. **System Prerequisites**:
   Ensure [Homebrew](https://brew.sh) is installed:
   ```bash
   brew install python git curl
   ```

2. **Clone & Install**:
   ```bash
   git clone https://github.com/devlp-io/agent.git ~/agent
   cd ~/agent
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt textual rich openai httpx python-dotenv
   ```

3. **Configure & Run**:
   ```bash
   cp .env.examples .env
   # Set API key in .env
   chmod +x somscan
   ./somscan
   ```

---

### Windows (Native PowerShell & CMD)

SOM-SCAN runs natively on Windows 10 and Windows 11 with full color rendering and responsive layouts via Windows Terminal.

1. **Install Python 3.10+**:
   Download and install from [python.org](https://www.python.org/downloads/windows/). Ensure **"Add Python to PATH"** is checked during setup.

2. **Clone Repository**:
   Open PowerShell:
   ```powershell
   git clone https://github.com/devlp-io/agent.git C:\agent
   cd C:\agent
   ```

3. **Install Dependencies**:
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt textual rich openai httpx python-dotenv
   ```

4. **Configure Environment**:
   ```powershell
   Copy-Item .env.examples .env
   notepad .env
   ```

5. **Launch**:
   Launch directly with PowerShell launcher or batch script:
   ```powershell
   .\somscan.ps1
   # or
   .\somscan.bat
   # or
   python somscan.py
   ```

---

### Windows (WSL2 Ubuntu)

For access to native Linux security utilities (`naabu`, `masscan`, `nmap` raw sockets):

1. **Enable WSL2**:
   ```powershell
   wsl --install -d Ubuntu
   ```
2. **Inside Ubuntu WSL Shell**:
   ```bash
   git clone https://github.com/devlp-io/agent.git ~/agent
   cd ~/agent
   bash bootstrap.sh
   source ~/.bashrc
   ./somscan
   ```

---

### Android Termux

SOM-SCAN supports mobile security testing directly within [Termux](https://termux.dev/) without requiring root permissions.

1. **Install Required Packages**:
   ```bash
   pkg update -y && pkg upgrade -y
   pkg install -y python git clang make libffi libxml2 libxslt openssl
   ```

2. **Grant Storage Access**:
   ```bash
   termux-setup-storage
   ```

3. **Clone & Install Python Dependencies**:
   ```bash
   git clone https://github.com/devlp-io/agent.git ~/agent
   cd ~/agent
   pip install --upgrade pip setuptools wheel
   pip install textual rich openai httpx python-dotenv
   pip install -r requirements.txt --no-build-isolation || pip install -r requirements.txt
   ```

4. **Launch in Termux**:
   ```bash
   python somscan.py
   ```

> **Termux Tips**:
> - Use the Termux extra-keys bar for `ESC`, `CTRL`, and arrow keys.
> - Soft keyboard opens automatically when tapping the input field.
> - To prevent Android from sleeping during background scans: acquire a wake-lock via Termux notification or run `termux-wake-lock`.

---

## Model Configuration & Environment Variables

SOM-SCAN supports any OpenAI-compatible inference endpoint, hosted frontier models, or air-gapped local LLMs. Configuration is read from `.env` in the project root:

```bash
# ==============================================================================
# Primary Model Configuration
# ==============================================================================

# Option 1: DeepSeek (Recommended for high speed, reasoning, and cost efficiency)
AG_MODEL=deepseek-chat
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

All 37 test cases validate in under 30 seconds with zero external dependencies.

---

## Safety & Scope Guardrails

- **Explicit Authorization**: The autonomous engine requires target validation and explicit operator confirmation before firing destructive or intrusive scans.
- **Scope Restriction**: All crawl targets, parameter tests, and probe requests validate against the authorized target scope. Out-of-scope pivots are blocked.
- **Destructive Command Deny-List**: The harness strictly blocks destructive system commands (e.g., `rm -rf /`, `mkfs`, raw device writes `dd`).
- **Graceful Cancellation**: Immediate process-tree termination upon `/cancel` or `Ctrl+C` prevents orphaned scanner processes or lingering background network activity.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
