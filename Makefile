.PHONY: test install example air
install:
	python -m pip install -e '.[dev]'
test:
	pytest -q
example:
	aegis examples/hello.aegis -t python -o /tmp/aegis_hello.py
	python /tmp/aegis_hello.py
air:
	aegis examples/hello.aegis -t air
