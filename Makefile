# mcp-authz-range: common tasks, one command each.
.PHONY: help test demo install clean verify-mcphub

help:
	@echo "make test           run the harness test suite (no Docker, no network)"
	@echo "make demo            run the in-process FAIL/PASS demo (no Docker)"
	@echo "make install         editable install so 'range' is on PATH"
	@echo "make verify-mcphub   build + reproduce the MCPHub CVE, then tear down (needs Docker)"
	@echo "make clean           remove caches and local build dirs"

test:
	cd harness && python3 -m pytest -q

demo:
	@python3 harness/cli.py run mcphub-idor-CVE-2026-79750 --version vulnerable --mock || true
	@python3 harness/cli.py run mcphub-idor-CVE-2026-79750 --version fixed --mock || true

install:
	python3 -m pip install -e .

verify-mcphub:
	bash cases/mcphub-idor-CVE-2026-79750/verify.sh

clean:
	rm -rf **/__pycache__ **/.pytest_cache .pytest_cache *.egg-info
	rm -rf mcphub-build mcphub-fixed
