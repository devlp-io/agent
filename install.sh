cat > ~/.local/bin/ag <<'SHEOF'
#!/bin/bash
cd ~/agent && source venv/bin/activate && python agent.py "$@"
SHEOF
chmod +x ~/.local/bin/ag

cat > ~/.local/bin/agreport <<'SHEOF'
#!/bin/bash
cd ~/agent && source venv/bin/activate
LATEST=$(ls -td ~/scans/*/*/ 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then echo "no scans found"; exit 1; fi
echo "regenerating report for: $LATEST"
python reporter.py "$LATEST"
SHEOF
chmod +x ~/.local/bin/agreport

grep -q 'local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
grep -q 'go/bin' ~/.bashrc || echo 'export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/agent/tools:$HOME/.local/bin:$PATH"' >> ~/.bashrc
grep -q 'alias .ag=' ~/.bashrc || echo "alias .ag='ag'" >> ~/.bashrc
grep -q 'alias agds=' ~/.bashrc || echo 'alias agds="AG_MODEL=deepseek-chat AG_BASE=https://api.deepseek.com/v1 AG_KEY=\$DEEPSEEK_KEY ag"' >> ~/.bashrc
grep -q 'alias agres=' ~/.bashrc || echo 'alias agres="ag --resume"' >> ~/.bashrc
grep -q 'DEEPSEEK_KEY=' ~/.bashrc || echo 'export DEEPSEEK_KEY="sk-your-key-here"' >> ~/.bashrc

grep -q 'scans()' ~/.bashrc || cat >> ~/.bashrc <<'EOF'
scans()  { explorer.exe "$(wslpath -w ~/scans)"; }
latest() { explorer.exe "$(wslpath -w "$(ls -td ~/scans/*/*/ 2>/dev/null | head -1)")"; }
open()   { explorer.exe "$(wslpath -w "$1")"; }
EOF

source ~/.bashrc