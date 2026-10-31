# agent v8 makefile
SHELL := /bin/bash
AGENT := agent_v8.py
VENV  := venv

.PHONY: help install bootstrap run resume report lint clean update sync-cve tui gui gui-build gui-dev gui-test toolkits

help:
	@echo "targets:"
	@echo "  make install       pip install -r requirements.txt (into venv)"
	@echo "  make bootstrap     system prereqs (pkg install ...)"
	@echo "  make run TASK='..' scan a target"
	@echo "  make resume TASK='..' resume the latest run"
	@echo "  make report        regenerate reports for the latest scan"
	@echo "  make sync-cve      pull fresh CVE data from NVD"
	@echo "  make gui-build     build the web GUI (React/Tailwind)"
	@echo "  make gui           build + serve GUI at http://127.0.0.1:8788/gui"
	@echo "  make gui-dev       Vite dev server on :5173 + API on :8788"
	@echo "  make gui-test      GUI backend smoke tests"
	@echo "  make toolkits      preinstall the modern toolkit (core profile)"
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
	@python3 -m compileall -q -x '(^|/)(venv|\.venv|__pycache__|tools)/' . && echo "lint ok"

clean:
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned"

# ── web GUI ────────────────────────────────────────────────────────────────
gui-build:
	@cd webgui && (test -d node_modules || npm install) && npm run build

gui: gui-build
	@python3 webgui/server.py --host $${AG_GUI_HOST:-127.0.0.1} --port $${AG_GUI_PORT:-8788}

gui-dev:
	@cd webgui && (test -d node_modules || npm install)
	@(cd webgui && npm run dev &) ; python3 webgui/server.py --port $${AG_GUI_PORT:-8788}

gui-test:
	@python3 webgui/test_api.py

toolkits:
	@python3 installer.py preinstall core
