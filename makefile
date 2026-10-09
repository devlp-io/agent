.PHONY: help install install-python install-deps run clean report lint

help:
	@echo "make install       — install python deps + venv"
	@echo "make bootstrap     — full bootstrap (system deps + python + go + cargo)"
	@echo "make run TARGET=x  — run agent against TARGET"
	@echo "make resume T=x    — resume latest scan for T"
	@echo "make report        — regenerate report for latest scan"
	@echo "make lint          — syntax check agent.py + reporter.py"
	@echo "make clean         — remove venv, __pycache__, tools"

bootstrap:
	bash bootstrap.sh

install:
	python3 -m venv venv
	. venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

run:
	@if [ -z "$(TARGET)" ]; then echo "usage: make run TARGET=example.com"; exit 1; fi
	cd $(CURDIR) && . venv/bin/activate && python agent.py "$(TARGET)"

resume:
	@if [ -z "$(T)" ]; then echo "usage: make resume T=example.com"; exit 1; fi
	cd $(CURDIR) && . venv/bin/activate && python agent.py --resume "$(T)"

report:
	cd $(CURDIR) && . venv/bin/activate && python reporter.py "$$(ls -td ~/scans/*/*/ 2>/dev/null | head -1)"

lint:
	python3 -c "import ast; ast.parse(open('agent.py').read()); print('agent ok')"
	python3 -c "import ast; ast.parse(open('reporter.py').read()); print('reporter ok')"

clean:
	rm -rf venv __pycache__ tools/manifest.json
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete