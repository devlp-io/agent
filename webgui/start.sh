#!/usr/bin/env bash
# Build (if needed) and serve the SOM-SCAN web GUI.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f dist/index.html ] || [ "${1:-}" = "--build" ]; then
  echo "[gui] building frontend…"
  [ -d node_modules ] || npm install
  npm run build
fi

exec python3 server.py --host "${AG_GUI_HOST:-127.0.0.1}" --port "${AG_GUI_PORT:-8788}"
