cat > ~/agent/bootstrap.sh <<'SHEOF'
#!/bin/bash
set -e
RED='\033[31m'; GRN='\033[32m'; YEL='\033[33m'; CYN='\033[36m'; RST='\033[0m'

echo -e "${CYN}[bootstrap] starting${RST}"

if command -v apt >/dev/null; then PM="apt"
elif command -v dnf >/dev/null; then PM="dnf"
elif command -v pacman >/dev/null; then PM="pacman"
elif command -v apk >/dev/null; then PM="apk"
elif command -v brew >/dev/null; then PM="brew"
else echo -e "${RED}[bootstrap] no package manager${RST}"; exit 1
fi
echo -e "${CYN}[bootstrap] pm: $PM${RST}"

sudo_cmd=""
[ "$(id -u)" -ne 0 ] && sudo_cmd="sudo"

install_pkg() {
  case "$PM" in
    apt)    $sudo_cmd apt update -qq && $sudo_cmd apt install -y "$1" ;;
    dnf)    $sudo_cmd dnf install -y "$1" ;;
    pacman) $sudo_cmd pacman -Sy --noconfirm "$1" ;;
    apk)    $sudo_cmd apk add --no-cache "$1" ;;
    brew)   brew install "$1" ;;
  esac
}
need() {
  if ! command -v "$1" >/dev/null; then
    echo -e "${YEL}[bootstrap] installing ${2:-$1}${RST}"
    install_pkg "${2:-$1}" || echo -e "${RED}[bootstrap] failed: $1${RST}"
  else echo -e "${GRN}[bootstrap] have $1${RST}"; fi
}

need curl
need git
need python3
need pip3 python3-pip
need unzip
need jq
need make
need gcc build-essential
need whois
need dnsutils
need ca-certificates
need libpango-1.0-0
need libpangoft2-1.0-0
need libharfbuzz0b
need libffi-dev
need libjpeg-dev
need libopenjp2-7
need libcairo2

if ! command -v go >/dev/null; then
  echo -e "${YEL}[bootstrap] installing go${RST}"
  case "$PM" in
    apt) install_pkg golang-go ;; dnf) install_pkg golang ;;
    pacman) install_pkg go ;; apk) install_pkg go ;; brew) brew install go ;;
  esac
fi

if ! command -v pipx >/dev/null; then
  python3 -m pip install --user --quiet pipx 2>/dev/null || \
    $sudo_cmd python3 -m pip install --break-system-packages --quiet pipx 2>/dev/null || true
  command -v pipx >/dev/null && pipx ensurepath >/dev/null 2>&1 || true
fi

if [ ! -d "$HOME/agent/venv" ]; then
  python3 -m venv "$HOME/agent/venv"
fi
source "$HOME/agent/venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet openai beautifulsoup4 requests markdown weasyprint

export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/agent/tools:$HOME/.local/bin:$PATH"
grep -q 'go/bin' ~/.bashrc || \
  echo 'export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/agent/tools:$HOME/.local/bin:$PATH"' >> ~/.bashrc
grep -q 'local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

if ! command -v cargo >/dev/null; then
  echo -e "${YEL}[bootstrap] installing rustup/cargo${RST}"
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --quiet || true
  [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
fi

if [ ! -d "$HOME/agent/wordlists/SecLists" ]; then
  echo -e "${CYN}[bootstrap] cloning SecLists (shallow)${RST}"
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
    "$HOME/agent/wordlists/SecLists" 2>/dev/null || true
fi

if ! command -v ddgr >/dev/null; then
  echo -e "${YEL}[bootstrap] installing ddgr (duckduckgo cli)${RST}"
  pipx install ddgr 2>/dev/null || pip install --user --quiet ddgr 2>/dev/null || true
fi

echo -e "${GRN}[bootstrap] done. run: source ~/.bashrc && ag <target>${RST}"
SHEOF
chmod +x ~/agent/bootstrap.sh