.PHONY: install test check example air run audit production-run clean
install:
	python -m pip install -e '.[dev]'
test:
	pytest -q
check:
	aegis examples/production_fabric.aegis --check
example:
	aegis examples/production_fabric.aegis -t python -o /tmp/aegis_production_fabric.py
air:
	aegis examples/production_fabric.aegis -t air
run:
	@test -n "$$AEGIS_RUNTIME_KEY" || (echo "Set AEGIS_RUNTIME_KEY first"; exit 1)
	aegis run examples/bounded_defense.aegis --context examples/runtime_context.json --audit /tmp/aegis-audit.json
audit:
	aegis verify-audit /tmp/aegis-audit.json
production-run:
	aegis keygen --private /tmp/aegis-cred-private.pem --public /tmp/aegis-cred-public.pem
	aegis keygen --private /tmp/aegis-audit-private.pem --public /tmp/aegis-audit-public.pem
	aegis run examples/production_fabric.aegis --context examples/production_context.json --credential-key AegisAI-Lab=/tmp/aegis-cred-private.pem --trust-key AegisAI-Lab=/tmp/aegis-cred-public.pem --anchor-key /tmp/aegis-audit-private.pem --anchor-issuer AegisAI-Audit --audit /tmp/aegis-v04-audit.json
	aegis verify-audit /tmp/aegis-v04-audit.json --anchor-public-key AegisAI-Audit=/tmp/aegis-audit-public.pem --require-anchor
clean:
	rm -rf .pytest_cache build dist src/*.egg-info src/aegisai/__pycache__ tests/__pycache__
