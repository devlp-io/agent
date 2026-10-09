#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"

echo "[bootstrap] termux packages..."
pkg update -y 2>/dev/null || true
pkg install -y python git curl unzip jq openssl libxml2 libxslt libjpeg-turbo \
               freetype harfbuzz pango fontconfig libffi

if [ "${INSTALL_BROWSER:-0}" = "1" ]; then
  echo "[bootstrap] installing chromium (heavy)..."
  pkg install -y chromium || echo "chromium install failed — browser features disabled"
fi

echo "[bootstrap] python deps..."
if [ ! -d venv ]; then
  python -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

mkdir -p data tools wordlists logs

echo "[bootstrap] done."
echo "  activate: source venv/bin/activate"
echo "  run:      python agent_v8.py 'scan https://example.com'"
