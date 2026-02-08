# BinAgent Makefile
# Common development tasks and CTF runner integration

.PHONY: help install test test-router test-ctf-nc test-ctf-runner ctf-verbal-sleep ctf-auto ctf-apk apk-test solve clean

help:
	@echo "BinAgent Development Commands"
	@echo ""
	@echo "  make install          Install dependencies"
	@echo "  make test             Run test suite"
	@echo "  make test-router      Run router/executor tests"
	@echo "  make test-ctf-runner  Run CTF runner self-tests"
	@echo "  make apk-test         Run APK solver tests"
	@echo "  make clean            Clean build artifacts and runs"
	@echo ""
	@echo "CTF Commands:"
	@echo "  make solve DESC=\"...\"              Unified solver (routes to appropriate tool)"
	@echo "  make solve-file FILE=./chall.apk   Solve file-based challenge"
	@echo "  make ctf-apk APK=/path/to/app.apk  Solve APK RE challenge"
	@echo ""
	@echo "Direct CLI:"
	@echo "  binagent solve \"nc host port\"           Unified solver (netcat)"
	@echo "  binagent solve --file ./chall.apk       Unified solver (APK)"
	@echo "  binagent solve --file ./binary          Unified solver (binary)"
	@echo "  binagent apk ./app.apk --mode solve     Deterministic APK solver"
	@echo ""

install:
	pip install -e .

test:
	python3 -m pytest tests/ -v

test-router:
	python3 -m pytest pentestagent/agents/ctf_agent/tests/ -v

test-ctf-runner:
	python3 scripts/test_ctf_runner.py

# =============================================================================
# CTF Runner Integration
# =============================================================================

# Default values for verbal-sleep challenge
CTF_HOST ?= verbal-sleep.picoctf.net
CTF_PORT ?= 56332
CTF_PAYLOAD ?= test;RETURN 0\n
CTF_REPEAT ?= 8
CTF_TIMEOUT ?= 15
CTF_MODE ?= blind

# Generic CTF nc runner
test-ctf-nc:
	python3 scripts/run_ctf_nc.py \
		--host $(CTF_HOST) \
		--port $(CTF_PORT) \
		--payload "$(CTF_PAYLOAD)" \
		--repeat $(CTF_REPEAT) \
		--timeout $(CTF_TIMEOUT) \
		--mode $(CTF_MODE)

# Convenience target for verbal-sleep challenge
# Usage: make ctf-verbal-sleep PORT=<your-port>
ctf-verbal-sleep:
	@if [ -z "$(PORT)" ]; then \
		echo "Usage: make ctf-verbal-sleep PORT=<port>"; \
		echo "Example: make ctf-verbal-sleep PORT=56332"; \
		exit 1; \
	fi
	python3 scripts/run_ctf_nc.py \
		--host verbal-sleep.picoctf.net \
		--port $(PORT) \
		--payload "test;RETURN 0\n" \
		--repeat 8 \
		--timeout 15 \
		--mode blind

# Auto-solve CTF challenge
# Usage: make ctf-auto DESC="Connect: nc host port ..." or provide PORT and HOST
ctf-auto:
	@if [ -n "$(DESC)" ]; then \
		binagent ctf "$(DESC)"; \
	elif [ -n "$(HOST)" ] && [ -n "$(PORT)" ]; then \
		binagent ctf --connect $(HOST):$(PORT); \
	else \
		echo "Usage: make ctf-auto DESC=\"nc host port ...\""; \
		echo "   or: make ctf-auto HOST=example.com PORT=12345"; \
		exit 1; \
	fi

# =============================================================================
# Unified CTF/RE Solver (LLM-Driven GeneralAgent)
# =============================================================================

# Solve any challenge using the LLM-driven GeneralAgent
# The agent uses a plan → act → observe → re-plan loop
# Usage: make solve DESC="nc cipher.picoctf.net 12345"
solve:
	@if [ -z "$(DESC)" ] && [ -z "$(FILE)" ]; then \
		echo "Usage: make solve DESC=\"challenge description\""; \
		echo "   or: make solve FILE=/path/to/challenge"; \
		echo ""; \
		echo "Examples:"; \
		echo "  make solve DESC=\"nc example.com 12345\""; \
		echo "  make solve FILE=./ctf_tests/minions.apk"; \
		exit 1; \
	fi
	@if [ -n "$(FILE)" ]; then \
		binagent solve --file "$(FILE)"; \
	else \
		binagent solve "$(DESC)"; \
	fi

# =============================================================================
# APK CTF Solver
# =============================================================================

# APK solver unit tests
apk-test:
	python3 -m pytest pentestagent/apk/tests/ -v

# Solve APK CTF challenge
# Usage: make ctf-apk APK=/path/to/app.apk
ctf-apk:
	@if [ -z "$(APK)" ]; then \
		echo "Usage: make ctf-apk APK=/path/to/app.apk"; \
		echo "Example: make ctf-apk APK=./ctf_tests/minions.apk"; \
		exit 1; \
	fi
	binagent apk "$(APK)" --mode solve

# =============================================================================
# Clean
# =============================================================================

clean:
	rm -rf runs/
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
