#!/usr/bin/env bash
# SOM-SCAN one-time installer for Linux, macOS, WSL2 Ubuntu, and Termux.
# Creates the local environment, installs core toolkits, and puts `somscan`
# on your PATH so it works from any directory.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin"
SKIP_TOOLKITS="${SOMSCAN_SKIP_TOOLKITS:-0}"

for a in "$@"; do
    case "$a" in
        --no-toolkits) SKIP_TOOLKITS=1 ;;
        --prefix=*) PREFIX="${a#*=}"; BIN="$PREFIX/bin" ;;
        -h|--help)
            echo "usage: ./install.sh [--no-toolkits] [--prefix=/path]"
            exit 0 ;;
    esac
done

echo "========================================================"
echo "  SOM-SCAN installer"
echo "  repo: $DIR"
echo "========================================================"

SOMSCAN_SKIP_TOOLKITS="$SKIP_TOOLKITS" "$DIR/somscan" --version >/dev/null

mkdir -p "$BIN"
ln -sf "$DIR/somscan" "$BIN/somscan"
chmod +x "$DIR/somscan" "$BIN/somscan" 2>/dev/null || true

add_path() {
    local rc="$1"
    [ -f "$rc" ] || return 0
    grep -q "SOM-SCAN PATH" "$rc" 2>/dev/null && return 0
    printf '\n# SOM-SCAN PATH\nexport PATH="%s:$PATH"\n' "$BIN" >> "$rc"
}

case ":$PATH:" in
    *":$BIN:"*) ;;
    *)
        add_path "$HOME/.bashrc"
        add_path "$HOME/.zshrc"
        add_path "$HOME/.profile"
        ;;
esac

echo
echo "[✓] installed: $BIN/somscan"
echo "    somscan            launch the CLI"
echo "    somscan gui        start the web console in the background"
echo "    somscan gui stop   stop the web console"
echo
echo "If 'somscan' is not found, open a new terminal or run:"
echo "    export PATH=\"$BIN:\$PATH\""
