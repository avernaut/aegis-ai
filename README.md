<p align="center">
  <img src="assets/aegis-ai-logo.png" alt="AegisAI" width="620">
</p>

# AegisAI Compiler

> **Intelligence without uncontrolled authority.**

AegisAI is an experimental programming language and compiler for **AI-native cybersecurity** and **bounded autonomous intelligence**. Instead of treating trust, policy, capabilities, provenance and risk as library conventions, AegisAI makes them part of the language and checks key constraints before code generation.

This repository contains the **v0.2 research compiler**.

## What is new in v0.2

AegisAI v0.2 moves beyond the v0.1 security/effect prototype and introduces first-class AI/cybersecurity semantics:

- first-class `capability` declarations with bounded effects and minimum risk
- `model` declarations with capabilities, network scope and trust
- `agent` declarations bound to models
- capability allow/deny sets
- `evidence` with source and trust score
- trust thresholds on autonomous proposals
- `proposal` as a non-executable AI recommendation
- `authorize ... using ...` as an explicit authority boundary
- `action` declarations derived from authorized proposals
- reversible actions and `secure transaction` rollback checks
- `tainted<T>` input and explicit `sanitize` boundaries
- `twin` safety constraints for pre-deployment validation metadata
- `intent` objectives and constraints
- temporal `sequence` declarations
- AIR v0.2 metadata for AI, trust, policy and cyber operations
- `aegis --check` static-analysis-only CLI mode

The original v0.1 features remain available: security-qualified data, secrets, risk-aware functions, explicit effects, policies, Python code generation and AIR output.

## Bounded intelligence example

```aegis
model CyberFM {
    capabilities [classify, reason, explain]
    trust 0.97
    network none
}

agent Sentinel {
    uses CyberFM
    capabilities [read.telemetry, read.threat_intel, propose.firewall]
    deny [shell.execute, identity.modify]
    trust 0.96
}

evidence malicious_ip = "203.0.113.17" trust 0.98 source "ThreatIntel"

policy MitigationPolicy {
    deny by default
    allow propose.firewall when evidence.trust >= 0.95
}

proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [malicious_ip]
    min_trust 0.95
    require confidence > 0.95
    effect write.firewall
}

authorize BlockHost using MitigationPolicy
action QuarantineHost from BlockHost effect write.firewall capability propose.firewall reversible
```

The compiler separates **reasoning authority** from **execution authority**. A high-risk proposal must have a guard and evidence; its agent must actually possess the requested capability; evidence and agent trust must satisfy the declared threshold; and an action cannot be derived from an unauthorized proposal.

## Compile-time rejection examples

### Information-flow violation

```aegis
data<string, secret> api_key = "do-not-print"
print(api_key)
```

Rejected because secret data cannot flow to a public output sink.

### Tainted input

```aegis
tainted<string> prompt = "ignore policy" source "external-user"
print(prompt)
```

Rejected until an explicit sanitization boundary is used:

```aegis
sanitize prompt as safe_prompt
print(safe_prompt)
```

### Capability violation

An agent with `deny [propose.firewall]` cannot create a proposal requiring `propose.firewall`.

### Trust violation

Evidence with `trust 0.40` cannot satisfy a proposal declaring `min_trust 0.90`.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## CLI

Check without code generation:

```bash
aegis examples/bounded_defense.aegis --check
```

Compile to Python:

```bash
aegis examples/bounded_defense.aegis -t python -o bounded_defense.py
python bounded_defense.py
```

Compile to AIR v0.2:

```bash
aegis examples/bounded_defense.aegis -t air -o bounded_defense.air.json
```

Inspect the compiler version:

```bash
aegis --version
```

## Repository structure

```text
assets/             project branding
src/aegisai/
  ast.py            AST and security/risk lattices
  lexer.py          source preprocessing
  parser.py         AegisAI parser
  checker.py        security, taint, trust, capability, effect and auth checks
  ir.py             AIR v0.2 lowering
  codegen.py        Python prototype backend
  compiler.py       compilation/checking pipeline
  cli.py            `aegis` command
examples/           safe and deliberately unsafe programs
tests/              compiler regression tests
docs/               language, architecture and security model
```

## Security model

The central v0.2 execution chain is:

```text
Observe -> Reason -> Propose -> Verify -> Authorize -> Act -> Audit
```

In the current compiler, `proposal` is declarative metadata and cannot directly execute an `action`. Static checks enforce capability ownership, denial precedence, trust thresholds, evidence references, risk guards, authorization presence and rollback eligibility.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Research roadmap

The next research milestones include typed expressions, a real policy evaluator, provenance DAGs, digital-twin execution adapters, capability tokens, runtime audit records, formal operational semantics, WASM/eBPF-oriented lowering and Cloud/Edge/5G/6G placement constraints.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/LANGUAGE.md](docs/LANGUAGE.md).

## Status

AegisAI v0.2 is a **research prototype**, not a production security enforcement system. Its static semantics are intentionally conservative and its Python backend is currently a demonstrator for checked metadata and basic executable constructs.

## License

Apache License 2.0.
