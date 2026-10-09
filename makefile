# agent v8 makefile
SHELL := /bin/bash
AGENT := agent_v8.py
VENV  := venv

.PHONY: help install bootstrap run resume report lint clean update sync-cve tui

help:
	@echo "targets:"
	@echo "  make install       pip install -r requirements.txt (into venv)"
	@echo "  make bootstrap     system prereqs (pkg install ...)"
	@echo "  make run TASK='..' scan a target"
	@echo "  make resume TASK='..' resume the latest run"
	@echo "  make report        regenerate reports for the latest scan"
	@echo "  make sync-cve      pull fresh CVE data from NVD"
	@echo "  make lint          syntax-check all .py files"
	@echo "  make clean         drop __pycache__ + tmp"

install:
	@bash install.sh

bootstrap:
	@bash bootstrap.sh

run:
	@if [ -z "$(TASK)" ]; then echo "usage: make run TASK='scan https://x.com'"; exit 1; fi
	@python $(AGENT) "$(TASK)"

resume:
	@if [ -z "$(TASK)" ]; then echo "usage: make resume TASK='<target>'"; exit 1; fi
	@python $(AGENT) --resume "$(TASK)"

report:
	@python -m evidence.report 2>/dev/null || true
	@latest=$$(ls -td ~/scans/*/*/ 2>/dev/null | head -1); \
	if [ -n "$$latest" ]; then \
	  echo "latest: $$latest"; \
	  ls -la $$latest/EXEC_SUMMARY.md $$latest/TECH_REPORT.md 2>/dev/null; \
	fi

sync-cve:
	@python -m intel.cve_db sync 5

lint:
	@python - << 'PYEOF'
import ast, pathlib
bad = 0
for p in pathlib.Path('.').rglob('*.py'):
    if 'venv' in p.parts or '__pycache__' in p.parts or 'tools' in p.parts:
        continue
    try:
        ast.parse(p.read_text())
    except SyntaxError as e:
        print(f"SYNTAX {p}: {e}"); bad += 1
print("lint ok" if not bad else f"{bad} file(s) with errors")
PYEOF

clean:
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned"
