# AegisAI Compiler

> **Intelligence without uncontrolled authority.**

AegisAI is an experimental programming language and compiler for AI-native cybersecurity systems. Its core idea is **bounded intelligence**: an AI component may reason broadly, while the language and runtime strictly constrain what it can observe, disclose and execute.

This repository contains the first working compiler prototype.

## Implemented in v0.1

- Security-qualified data types: `public`, `confidential`, `secret`
- Compile-time prevention of secret/confidential output to public sinks
- Function risk levels: `low`, `medium`, `high`, `critical`
- Explicit effect declarations and undeclared-effect rejection
- `require` guards for high/critical-risk operations
- Native policy declarations
- AIR (Aegis Intermediate Representation) JSON backend
- Python code-generation backend
- CLI compiler
- Unit tests and GitHub Actions CI

## Example

```aegis
data<string, public> banner = "AegisAI secure compiler"
print(banner)

fn isolate(host) risk critical {
    effects [write.firewall]
    require confidence > 0.95
    effect write.firewall
}
```

A security violation is rejected before code generation:

```aegis
data<string, secret> api_key = "do-not-print"
print(api_key)
```

Compiler output:

```text
SECURITY: 'api_key' is secret and cannot flow to public output
```

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development:

```bash
pip install -e '.[dev]'
pytest
```

## Compile

Python backend:

```bash
aegis examples/hello.aegis -t python -o hello.py
python hello.py
```

AIR backend:

```bash
aegis examples/hello.aegis -t air -o hello.air.json
```

Check a deliberately unsafe program:

```bash
aegis examples/security_violation.aegis
```

## Repository structure

```text
src/aegisai/
  ast.py        AST nodes and security lattice
  lexer.py      source preprocessing
  parser.py     AegisAI parser
  checker.py    security/effect/risk static analysis
  ir.py         AIR lowering
  codegen.py    Python backend
  compiler.py   compilation pipeline
  cli.py        `aegis` command
examples/       sample AegisAI programs
tests/          compiler tests
docs/           language and architecture notes
```

## Research roadmap

The goal is to evolve AegisAI into a policy-, trust-, and intent-aware language for autonomous cyber defense, especially for Cloud/Edge/5G/6G environments. Planned first-class concepts include `agent`, `model`, `proposal`, `authorize`, `trust`, `evidence`, `tainted`, `twin`, reversible actions and secure transactions.

See [docs/LANGUAGE.md](docs/LANGUAGE.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status

AegisAI v0.1 is a research prototype. It is not yet intended for production security enforcement.

## License

Apache License 2.0.
