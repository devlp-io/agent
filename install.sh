#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"

echo "[install] python deps..."
if [ ! -d venv ]; then
  python -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[install] done. activate with: source venv/bin/activate"
