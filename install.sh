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

PY_SYS="$(command -v python3 || command -v python)"
[ -n "$PY_SYS" ] || { echo "[!] Python 3.10+ not found." >&2; exit 1; }
SETUP_ARGS=(--auto)
[ "$SKIP_TOOLKITS" = "1" ] && SETUP_ARGS+=(--no-toolkits)
"$PY_SYS" "$DIR/setup_tui.py" "${SETUP_ARGS[@]}" || {
    echo "[!] setup failed — fix the error above and re-run ./install.sh" >&2
    exit 1
}
VENV_PY="$DIR/.venv/bin/python"
if [ ! -x "$VENV_PY" ] || ! "$VENV_PY" -c "import rich, textual, openai, httpx, dotenv, requests" >/dev/null 2>&1; then
    echo "[!] core environment is incomplete — run ./somscan setup" >&2
    exit 1
fi

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
