<p align="center">
  <img src="assets/aegis-ai-logo.png" alt="AegisAI" width="620">
</p>

# AegisAI

> **Intelligence without uncontrolled authority.**

AegisAI is an experimental programming language, compiler and bounded-authority runtime for **AI-native cybersecurity**. It makes security levels, trust, evidence, risk, capabilities, policy decisions, digital-twin validation and audit provenance explicit parts of the language rather than conventions hidden in application code.

This repository contains **AegisAI v0.3.0**.

## Why v0.3 matters

AegisAI v0.2 separated an AI `proposal` from an authorized `action`. v0.3 adds the runtime enforcement layer so an action is still not executable merely because it exists in checked source code.

The v0.3 execution chain is:

```text
Observe -> Reason -> Propose -> Verify -> Policy -> Authorize
                                             |
                                             v
                                  Capability Token
                                             |
                                             v
                                  Digital Twin Validate
                                             |
                                             v
                                          Execute
                                             |
                                             v
                              Cryptographic Provenance
```

The default runtime adapter is deliberately **NoOp/simulation-only**: the compiler and runtime validate authority, but this repository does not silently modify a firewall, identity provider or operating system.

## New in v0.3

- executable policy evaluation with security-first default deny
- supported policy rules: `deny by default`, `allow all`, capability-scoped `allow`/`deny ... when ...`, and `require human when ...`
- signed, expiring HMAC-SHA256 capability tokens
- token/agent/capability consistency checks at compile time and runtime
- explicit `confidence` on AI proposals
- explicit `validate <action> with <twin>`
- explicit `execute <action> using <token>`
- mandatory prior twin validation before action execution
- runtime evaluation of proposal guards
- runtime evaluation of Digital Twin constraints against supplied metrics
- human approval gates for critical operations
- tamper-evident SHA-256 provenance hash chain
- evidence values represented in provenance by hashes rather than raw values
- `aegis run` command for bounded-authority execution
- `aegis verify-audit` command for provenance-chain verification
- AIR upgraded to **0.3**
- Python backend embeds AIR and enters the AegisAI runtime for `execute`

All v0.2 static security mechanisms remain: information-flow control, taint tracking, effect checking, risk guards, capability envelopes, trust thresholds, evidence checks, authorization references and rollback validation.

## Complete bounded-authority example

```aegis
capability propose.firewall {
    effects [write.firewall]
    risk high
}

model CyberFM {
    capabilities [classify, reason, explain]
    trust 0.97
    network none
}

agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    trust 0.96
}

evidence malicious_ip = "203.0.113.17" trust 0.98 source "ThreatIntel"

policy MitigationPolicy {
    deny by default
    allow propose.firewall when evidence.trust >= 0.95
    require human when risk == critical
}

proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [malicious_ip]
    min_trust 0.95
    confidence 0.99
    require confidence > 0.95
    effect write.firewall
}

authorize BlockHost using MitigationPolicy
action QuarantineHost from BlockHost effect write.firewall capability propose.firewall reversible

token FirewallToken for Sentinel capability propose.firewall ttl 300

twin EdgeTwin {
    target production
    require availability_loss < 0.01
    require latency_delta < 5
}

validate QuarantineHost with EdgeTwin
execute QuarantineHost using FirewallToken
```

Runtime metrics are supplied separately, preserving a clean separation between checked source and observed runtime state:

```json
{
  "twins": {
    "EdgeTwin": {
      "availability_loss": 0.002,
      "latency_delta": 1.7
    }
  },
  "approvals": {}
}
```

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Static checking

```bash
aegis examples/bounded_defense.aegis --check
```

## Compile to AIR 0.3

```bash
aegis examples/bounded_defense.aegis -t air -o bounded_defense.air.json
```

## Compile to Python

```bash
aegis examples/bounded_defense.aegis -t python -o bounded_defense.py
```

The generated Python does not bypass AegisAI. If the program contains `execute`, it invokes the same bounded-authority runtime and requires `AEGIS_RUNTIME_KEY`.

## Run through the secure runtime

Create a runtime key outside the source tree:

```bash
python -c "import secrets; print(secrets.token_hex(32))" > /tmp/aegis-runtime.key
```

Then execute in simulation mode:

```bash
aegis run examples/bounded_defense.aegis \
  --context examples/runtime_context.json \
  --key-file /tmp/aegis-runtime.key \
  --audit /tmp/aegis-audit.json
```

The built-in adapter records a successful execution but performs **no external side effect**.

Verify the resulting provenance chain:

```bash
aegis verify-audit /tmp/aegis-audit.json
```

## Compile-time security rejection examples

AegisAI rejects, among other cases:

```aegis
data<string, secret> api_key = "do-not-print"
print(api_key)
```

```aegis
tainted<string> prompt = "untrusted" source "user"
print(prompt)
```

It also rejects an `execute` statement unless a matching action exists, its token belongs to the correct agent and capability, and an explicit Digital Twin validation appears first.

## Runtime security rejection examples

Even code that passes static checks can still be blocked at runtime when observations change. Examples include:

- a proposal guard such as `confidence > 0.95` becoming false;
- a policy rule denying the capability;
- a critical policy requiring human approval without an approval record;
- a Digital Twin constraint failing;
- an expired or tampered capability token;
- a token signed with the wrong runtime key.

## Repository structure

```text
assets/                     project branding
src/aegisai/
  ast.py                    AST and security/risk lattices
  lexer.py                  source preprocessing
  parser.py                 AegisAI parser
  checker.py                static security semantics
  ir.py                     AIR 0.3 lowering
  runtime.py                policy/token/twin/provenance runtime
  codegen.py                Python backend
  compiler.py               compile/check/run APIs
  cli.py                    aegis CLI
examples/                   safe, unsafe and runtime-context examples
tests/                      compiler + runtime regression tests
docs/
  LANGUAGE.md               language reference
  ARCHITECTURE.md           compiler/runtime architecture
  SECURITY_MODEL.md         security invariants and threat model
  RUNTIME.md                runtime and adapter model
```

## Core invariant

AegisAI treats these as separate concepts:

```text
intelligence != authority
proposal     != action
action       != execution
authorization != capability token
static safety != runtime safety
```

That separation is the basis of **bounded intelligence**.

## Status

AegisAI v0.3 is a **research prototype**, not a production security enforcement system. The policy engine, capability tokens, Digital Twin validation and provenance ledger are executable, but the default effect adapter is intentionally non-operational. Production adapters would require independent hardening, authentication, isolation, secret management and domain-specific validation.

## License

Apache License 2.0.
