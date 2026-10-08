.PHONY: install test check example air clean
install:
	python -m pip install -e '.[dev]'
test:
	pytest -q
check:
	aegis examples/bounded_defense.aegis --check
example:
	aegis examples/bounded_defense.aegis -t python -o /tmp/aegis_bounded_defense.py
	python /tmp/aegis_bounded_defense.py
air:
	aegis examples/bounded_defense.aegis -t air
clean:
	rm -rf .pytest_cache build dist src/*.egg-info src/aegisai/__pycache__ tests/__pycache__
