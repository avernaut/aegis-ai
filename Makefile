.PHONY: install test check example air run audit clean
install:
	python -m pip install -e '.[dev]'
test:
	pytest -q
check:
	aegis examples/bounded_defense.aegis --check
example:
	aegis examples/bounded_defense.aegis -t python -o /tmp/aegis_bounded_defense.py
air:
	aegis examples/bounded_defense.aegis -t air
run:
	@test -n "$$AEGIS_RUNTIME_KEY" || (echo "Set AEGIS_RUNTIME_KEY first"; exit 1)
	aegis run examples/bounded_defense.aegis --context examples/runtime_context.json --audit /tmp/aegis-audit.json
audit:
	aegis verify-audit /tmp/aegis-audit.json
clean:
	rm -rf .pytest_cache build dist src/*.egg-info src/aegisai/__pycache__ tests/__pycache__
