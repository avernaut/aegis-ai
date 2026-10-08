<p align="center">
  <img src="assets/aegis-ai-logo.png" alt="AegisAI" width="620">
</p>

# AegisAI

> **Intelligence without uncontrolled authority.**

AegisAI is an experimental programming language, compiler and secure runtime for **AI-native cybersecurity**. It makes information flow, trust, evidence, risk, capabilities, policy, Digital Twin validation, deployment constraints and audit provenance explicit language concepts.

This repository contains **AegisAI v0.4.0 — Production Trust Fabric**.

## Why v0.4 matters

v0.3 introduced verified autonomous execution: policy, runtime capability checks, Twin validation and a tamper-evident audit chain. v0.4 extends that execution boundary into a distributed trust fabric suitable for research prototypes spanning **Cloud, Edge, 5G/6G and security control planes**.

The v0.4 trust chain is:

```text
AI reasoning
    -> proposal + evidence + trust
    -> policy authorization
    -> Ed25519 capability credential (or legacy HMAC token)
    -> Cloud / Edge / 5G placement validation
    -> Digital Twin connector + safety guards
    -> typed effect adapter
    -> explicit execute
    -> hash-chained provenance
    -> externally verifiable Ed25519 provenance anchor
```

External effects and remote Digital Twin calls remain **explicit and opt-in**. The default adapter is simulation-only.

## New in v0.4

- **Ed25519 capability credentials** with issuer, key ID, TTL, agent and capability binding
- legacy HMAC-SHA256 capability tokens retained for v0.3 compatibility
- **typed effect adapters** with declared effect sets, trust zones and `simulation` / `external` modes
- `execute ... via <adapter>` with compile-time and runtime effect compatibility checks
- **Digital Twin connectors** with `context` and opt-in `https` transports
- HTTPS Twin calls disabled unless `--allow-remote-twin` is explicitly supplied
- **Cloud / Edge / 5G / on-prem placement primitives** with region, data residency, network and latency constraints
- runtime placement validation against observed deployment telemetry
- **Ed25519 provenance anchors** for externally verifiable audit roots
- `aegis keygen` for Ed25519 key generation
- `aegis verify-audit --require-anchor` for anchored audit verification
- AIR upgraded to **0.4**
- URL-safe lexer fix: `//` inside quoted HTTPS URLs is no longer treated as a comment
- 0.1–0.3 security and runtime semantics retained

## Production trust-fabric example

```aegis
capability propose.firewall {
    effects [write.firewall]
    risk high
}

model CyberFM {
    capabilities [classify, reason, explain]
    trust 0.98
    network none
}

agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    trust 0.97
}

placement Sentinel at 5g {
    region "EU"
    data_residency "EU"
    max_latency_ms 10
    network "mec"
}

evidence malicious_ip = "203.0.113.17" trust 0.99 source "ThreatIntel"

policy MitigationPolicy {
    deny by default
    allow propose.firewall when evidence.trust >= 0.95
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

credential FirewallCredential for Sentinel capability propose.firewall ttl 300 issuer "AegisAI-Lab"

adapter EdgeFirewallAdapter {
    effects [write.firewall]
    mode simulation
    trust_zone "edge-prod"
}

twin_connector EdgeTwinConnector {
    transport context
    timeout_ms 1000
}

twin EdgeTwin {
    target production
    connector EdgeTwinConnector
    require availability_loss < 0.01
    require latency_delta < 5
}

validate QuarantineHost with EdgeTwin
execute QuarantineHost using FirewallCredential via EdgeFirewallAdapter
```

See `examples/production_fabric.aegis` for the complete executable example.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Check and compile

```bash
aegis examples/production_fabric.aegis --check
aegis examples/production_fabric.aegis -t air -o production.air.json
aegis examples/production_fabric.aegis -t python -o production.py
```

## Generate Ed25519 keys

```bash
aegis keygen \
  --private /tmp/aegis-credential-private.pem \
  --public /tmp/aegis-credential-public.pem

aegis keygen \
  --private /tmp/aegis-audit-private.pem \
  --public /tmp/aegis-audit-public.pem
```

Private key files are created with restrictive permissions where supported. Never commit them.

## Run v0.4 through the secure runtime

```bash
aegis run examples/production_fabric.aegis \
  --context examples/production_context.json \
  --credential-key AegisAI-Lab=/tmp/aegis-credential-private.pem \
  --trust-key AegisAI-Lab=/tmp/aegis-credential-public.pem \
  --anchor-key /tmp/aegis-audit-private.pem \
  --anchor-issuer AegisAI-Audit \
  --audit /tmp/aegis-audit.json
```

The bundled `EdgeFirewallAdapter` declaration is `simulation`, therefore no real firewall is changed.

Verify the audit chain and the external signature anchor:

```bash
aegis verify-audit /tmp/aegis-audit.json \
  --anchor-public-key AegisAI-Audit=/tmp/aegis-audit-public.pem \
  --require-anchor
```

## Remote Digital Twin connectors

A Twin connector can be declared with HTTPS:

```aegis
twin_connector RemoteTwin {
    transport https
    endpoint "https://twin.example.net/validate"
    timeout_ms 1500
}
```

Network access is denied by default. It must be enabled explicitly:

```bash
aegis run ... --allow-remote-twin
```

Applications may instead inject a custom `TwinConnector` through the Python API, which is the recommended route for authenticated mTLS/service-mesh integrations.

## Typed production adapters

An external adapter declaration is not enough to execute an effect:

```aegis
adapter ProductionFirewall {
    effects [write.firewall]
    mode external
    trust_zone "edge-prod"
}
```

The Python host must also bind an adapter implementation whose `supported_effects` includes `write.firewall`. Missing or mismatched adapters are rejected at runtime.

## Runtime context

v0.4 recognizes placement and Twin observations in addition to proposal confidence and approvals:

```json
{
  "placements": {
    "Sentinel": {
      "environment": "5g",
      "region": "EU",
      "data_residency": "EU",
      "latency_ms": 4.2,
      "network": "mec"
    }
  },
  "twins": {
    "EdgeTwin": {
      "availability_loss": 0.002,
      "latency_delta": 1.7
    }
  },
  "approvals": {}
}
```

## Repository structure

```text
assets/                     branding
src/aegisai/
  ast.py                    AST and security/risk lattices
  lexer.py                  source preprocessing
  parser.py                 AegisAI parser
  checker.py                static security semantics
  ir.py                     AIR 0.4 lowering
  credentials.py            Ed25519 credentials and provenance anchors
  runtime.py                policy/placement/twin/adapter/provenance runtime
  codegen.py                Python backend
  compiler.py               compile/check/run APIs
  cli.py                    aegis CLI
examples/                   safe, unsafe and runtime examples
tests/                      compiler + runtime regression tests
docs/                       language, architecture, security and runtime docs
```

## Core invariant

```text
intelligence       != authority
proposal           != action
action             != execution
authorization      != capability credential
credential         != effect adapter
placement intent   != observed placement
Twin declaration   != Twin validation
hash chain         != externally anchored provenance
static safety      != runtime safety
```

That separation is the basis of **bounded intelligence**.

## Status

AegisAI v0.4 is a **research prototype**, not a certified production security enforcement system. The trust-fabric mechanisms are executable and testable, but production deployments still require independent hardening of key management, adapter implementations, remote Twin authentication, transport security, isolation, observability and domain-specific safety validation.

## License

Apache License 2.0.
