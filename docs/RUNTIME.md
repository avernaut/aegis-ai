# AegisAI v0.4 Runtime

The v0.4 runtime executes AIR 0.4 as a distributed bounded-authority trust pipeline.

## Runtime order

```text
proposal guards
    -> policy decision
    -> capability authority
         |- HMAC token (legacy)
         `- Ed25519 credential (v0.4)
    -> placement validation
    -> Digital Twin connector + guards
    -> typed effect adapter
    -> execution
    -> provenance hash-chain event
    -> optional Ed25519 root anchor
```

Source ordering still requires Twin validation before `execute`.

## Capability credentials

v0.4 adds asymmetric capability credentials:

```aegis
credential FirewallCredential for Sentinel capability propose.firewall ttl 300 issuer "AegisAI-Lab"
```

The runtime signs the credential with the Ed25519 private key configured for the declared issuer. Verification binds:

- issuer and key ID;
- agent;
- capability;
- issue and expiration times;
- unique nonce.

Legacy `token` declarations continue to use HMAC-SHA256.

## Placement validation

```aegis
placement Sentinel at 5g {
    region "EU"
    data_residency "EU"
    max_latency_ms 10
    network "mec"
}
```

Observed placement telemetry is supplied in runtime context under `placements.<agent>`. A mismatch blocks the pipeline.

## Digital Twin connectors

```aegis
twin_connector EdgeTwinConnector {
    transport context
    timeout_ms 1000
}
```

`context` reads Twin metrics from the supplied runtime context. `https` performs an HTTP JSON request only when `allow_remote_twin=True` / `--allow-remote-twin` is explicitly enabled.

Python hosts can inject a custom connector:

```python
class TwinConnector:
    def metrics(self, twin: dict, action: dict, context: dict) -> dict: ...
```

Custom connectors are preferred for authenticated service-to-service integration.

## Typed effect adapters

```aegis
adapter EdgeFirewallAdapter {
    effects [write.firewall]
    mode external
    trust_zone "edge-prod"
}

execute QuarantineHost using FirewallCredential via EdgeFirewallAdapter
```

At compile time, the adapter must declare the action's effect. At runtime, an external adapter implementation must be explicitly supplied and its `supported_effects` must include the effect.

```python
class EffectAdapter:
    supported_effects: set[str]
    def execute(self, action: dict, context: dict) -> dict: ...
```

Simulation adapters fall back to the built-in no-op implementation if no host adapter is bound.

## Provenance anchoring

The ledger remains a SHA-256 hash chain. v0.4 can additionally sign the final root using Ed25519. This creates an external verification object containing issuer, key ID, root hash, timestamp and signature.

```bash
aegis verify-audit audit.json \
  --anchor-public-key AegisAI-Audit=/path/audit-public.pem \
  --require-anchor
```

## Key generation

```bash
aegis keygen --private private.pem --public public.pem
```

The CLI reports the public key ID derived from SHA-256 of the raw public key.

## Python API

```python
from aegisai import run_source
from aegisai.credentials import SigningIdentity

result = run_source(
    source,
    context=context,
    credential_signers={"AegisAI-Lab": credential_signer},
    trusted_issuers={"AegisAI-Lab": credential_public_key},
    provenance_signer=audit_signer,
    adapters={"EdgeFirewallAdapter": firewall_adapter},
    twin_connectors={"EdgeTwinConnector": twin_connector},
)
```

All external adapters and connectors remain host-controlled dependencies rather than implicit language privileges.

## v0.5 coordination context

Quorum approvals are supplied under `quorums`. Signed attestation tokens are supplied under `attestations`. Revocation state is supplied under `revocations`.

```json
{
  "quorums": {"ResponseQuorum": ["Sentinel", "Responder"]},
  "attestations": {"EdgeRuntime": "aegisatt...."},
  "revocations": {
    "authorities": [],
    "issuers": [],
    "key_ids": [],
    "sha256": []
  }
}
```

The runtime checks revocation after credential verification and before quorum/attestation/adapter execution. Every decision is appended to the provenance chain.
