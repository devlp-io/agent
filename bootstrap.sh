#!/usr/bin/env bash
# SOM-SCAN Bootstrap Script for WSL Ubuntu / Debian & Linux Red-Team Environments
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "========================================================"
echo "  [⚡] SOM-SCAN RED-TEAM CLI BOOTSTRAP (WSL UBUNTU)"
echo "========================================================"

# Check if running under Debian/Ubuntu
if command -v apt-get >/dev/null 2>&1; then
    echo "[+] Updating apt repositories..."
    if command -v sudo >/dev/null 2>&1; then
        sudo apt-get update -y || true
        echo "[+] Installing core build toolchain, compilers, and offensive tooling..."
        sudo apt-get install -y \
            build-essential gcc g++ mingw-w64 nasm \
            python3 python3-pip python3-venv \
            git curl wget unzip jq tmux xclip \
            libffi-dev libssl-dev radare2 gdb strace ltrace binwalk \
            2>/dev/null || true
    else
        apt-get update -y || true
        apt-get install -y \
            build-essential gcc g++ mingw-w64 nasm \
            python3 python3-pip python3-venv \
            git curl wget unzip jq tmux xclip \
            libffi-dev libssl-dev radare2 gdb strace ltrace binwalk \
            2>/dev/null || true
    fi
fi

# Termux fallback
if command -v pkg >/dev/null 2>&1; then
    echo "[+] Installing Termux packages..."
    pkg update -y || true
    pkg install -y python git curl unzip jq openssl clang make || true
fi

echo "[+] Setting up Python virtual environment..."
if [ ! -d ".venv_linux" ] && [ ! -d ".venv" ]; then
    python3 -m venv --copies .venv_linux || python3 -m venv .venv_linux || python -m venv .venv_linux
fi

if [ -f ".venv_linux/bin/activate" ]; then
    source .venv_linux/bin/activate
elif [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

echo "[+] Upgrading pip and installing production requirements..."
pip install --upgrade pip setuptools wheel
pip install --no-compile -r requirements.txt

# Ensure executable permissions on launchers
chmod +x somscan somscan.sh 2>/dev/null || true

# Setup required directory trees
mkdir -p data tools wordlists logs payloads exploits scans/archives

echo "========================================================"
echo "  [✓] SOM-SCAN Setup Complete for WSL Ubuntu!"
echo "  To launch interactive CLI:  ./somscan"
echo "  Or with arguments:         ./somscan --scan <target>"
echo "========================================================"
