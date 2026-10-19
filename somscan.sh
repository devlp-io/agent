#!/usr/bin/env bash
# SOM-SCAN CLI Launcher (WSL Ubuntu & Linux)
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

if [ -f "$DIR/.venv_linux/bin/python" ]; then
    PY_BIN="$DIR/.venv_linux/bin/python"
elif [ -f "$DIR/.venv/bin/python" ]; then
    PY_BIN="$DIR/.venv/bin/python"
elif [ -f "$DIR/venv/bin/python" ]; then
    PY_BIN="$DIR/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
else
    echo "[!] Python 3 not found. Run ./bootstrap.sh first." >&2
    exit 1
fi

exec "$PY_BIN" "$DIR/somscan.py" "$@"
