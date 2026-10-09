<p align="center">
  <img src="assets/aegis-ai-logo.png" alt="AegisAI" width="620">
</p>

# AegisAI

> **Intelligence without uncontrolled authority.**

AegisAI is an experimental programming language, compiler, and secure runtime for **AI-native cybersecurity**. It makes information flow, trust, evidence, risk, capability, policy, Digital Twin validation, deployment constraints, multi-agent coordination, runtime attestation, and audit provenance explicit language concepts.

This repository contains **AegisAI v0.5.0 — Federated Autonomous Defense**.

## Why v0.5 matters

v0.4 introduced a production-oriented trust fabric with Ed25519 capability credentials, typed effect adapters, placement constraints, Digital Twin connectors, and signed provenance anchors. v0.5 extends that model to **coordinated autonomous defense across multiple AI agents and security domains**.

The v0.5 authority chain is:

```text
AI reasoning
  -> proposal + evidence + trust
  -> local or federated policy authorization
  -> bounded capability delegation
  -> multi-agent quorum
  -> runtime attestation
  -> revocation check
  -> placement + Digital Twin validation
  -> typed effect adapter
  -> explicit execute
  -> hash-chained provenance + optional Ed25519 anchor
```

No new coordination primitive bypasses the execution boundary: delegation, quorum, attestation, policy federation, and revocation are all checked before an effect is released to an adapter.

## New in v0.5

- **Bounded capability delegation** between agents with source authority checks and a maximum one-hour TTL.
- Ed25519-signed delegated credentials that bind delegator, delegatee, capability, issuer, key ID, and expiration.
- **Multi-agent quorum gates** for sensitive proposals.
- Quorum membership and threshold validation at compile time; approval counting at runtime.
- **Policy federation** with `all`, `any`, and `threshold` strategies.
- Federated authorization decisions preserved in the provenance ledger.
- **Signed runtime attestation** with target, measurement, issuer, key ID, timestamp, freshness window, and Ed25519 verification.
- **Runtime authority revocation** by authority name, issuer, key ID, or authority SHA-256 digest.
- Extended `execute` syntax with optional `quorum` and `attestation` requirements.
- New `aegis attest` command and `aegis run --attestation NAME=PATH` support.
- AIR upgraded to **0.5** with `capability.delegate`, `coordination.quorum`, `policy.federation`, `auth.federated`, and `runtime.attestation` operations.
- Full compatibility tests for the v0.1-v0.4 security model.

## Coordinated-defense example

```aegis
capability propose.firewall {
    effects [write.firewall]
    risk high
}

agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    trust 0.99
}

agent Responder {
    uses CyberFM
    capabilities []
    trust 0.98
}

policy EvidencePolicy {
    deny by default
    allow propose.firewall when evidence.trust >= 0.95
}

policy ConfidencePolicy {
    deny by default
    allow propose.firewall when confidence >= 0.98
}

federation DefenseFederation {
    policies [EvidencePolicy, ConfidencePolicy]
    strategy all
}

proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [ioc]
    min_trust 0.95
    confidence 0.99
    require confidence > 0.95
    effect write.firewall
}

federate authorize BlockHost using DefenseFederation
action QuarantineHost from BlockHost effect write.firewall capability propose.firewall reversible

delegate ResponseDelegation from Sentinel to Responder capability propose.firewall ttl 120 issuer "SOC-CA"
quorum ResponseQuorum for BlockHost approvals 2 from [Sentinel, Responder, Analyst]
attestation EdgeRuntime for Responder issuer "Attest-CA" max_age 300 measurement "sha256:runtime-v1"

validate QuarantineHost with EdgeTwin
execute QuarantineHost using ResponseDelegation via EdgeFirewallAdapter quorum ResponseQuorum attestation EdgeRuntime
```

See `examples/coordinated_defense.aegis` for the complete executable example.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Check and compile

```bash
aegis examples/coordinated_defense.aegis --check
aegis examples/coordinated_defense.aegis -t air -o coordinated.air.json
aegis examples/coordinated_defense.aegis -t python -o coordinated.py
```

## Generate Ed25519 identities

```bash
aegis keygen --private /tmp/soc-private.pem --public /tmp/soc-public.pem
aegis keygen --private /tmp/attest-private.pem --public /tmp/attest-public.pem
```

## Issue a runtime attestation

```bash
aegis attest \
  --name EdgeRuntime \
  --target Responder \
  --measurement sha256:runtime-v1 \
  --issuer Attest-CA \
  --private-key /tmp/attest-private.pem \
  --output /tmp/edge-runtime.att
```

## Run the v0.5 coordinated pipeline

```bash
aegis run examples/coordinated_defense.aegis \
  --context examples/coordinated_context.json \
  --credential-key SOC-CA=/tmp/soc-private.pem \
  --trust-key SOC-CA=/tmp/soc-public.pem \
  --trust-key Attest-CA=/tmp/attest-public.pem \
  --attestation EdgeRuntime=/tmp/edge-runtime.att \
  --audit /tmp/aegis-v05-audit.json
```

The bundled adapter is simulation-only; the repository performs no real firewall change by default.

## Revocation

The runtime context may revoke authority by name, issuer, public-key ID, or serialized-authority SHA-256 digest:

```json
{
  "revocations": {
    "authorities": ["ResponseDelegation"],
    "issuers": [],
    "key_ids": [],
    "sha256": []
  }
}
```

A revoked authority is rejected before adapter execution and the revocation decision is recorded in provenance.

## Quorum context

```json
{
  "quorums": {
    "ResponseQuorum": ["Sentinel", "Responder"]
  }
}
```

Only declared quorum members count toward the threshold.

## Security properties

The compiler/runtime currently enforce, among others:

- security-level information flow and taint boundaries;
- capability and effect containment;
- explicit authorization before actions;
- trust/evidence/risk guards;
- bounded credential/token/delegation TTLs;
- no capability amplification by delegation;
- policy federation reference and threshold consistency;
- quorum membership and threshold consistency;
- signed runtime-attestation freshness and measurement checks;
- authority revocation before execution;
- mandatory Digital Twin validation before `execute`;
- typed effect-adapter compatibility;
- Cloud/Edge/5G placement constraints;
- tamper-evident provenance and optional Ed25519 audit anchoring.

## Repository structure

```text
assets/                     branding
src/aegisai/
  ast.py                    AST and security/risk lattices
  parser.py                 AegisAI parser
  checker.py                static security checker
  ir.py                     AIR 0.5 lowering
  credentials.py            Ed25519 credentials and attestations
  runtime.py                bounded-authority runtime
  codegen.py                Python backend
  cli.py                    aegis CLI
docs/                       language, architecture, runtime, security docs
examples/                   safe and intentionally unsafe examples
tests/                      compiler/runtime regression suite
```

## Status

AegisAI is a **research prototype**, not a production security boundary. External adapters, key custody, remote Twin authentication, revocation distribution, attestation roots, isolation, and deployment hardening require independent production engineering and security review.

## License

Apache License 2.0.
