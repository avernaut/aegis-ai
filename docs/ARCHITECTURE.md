# AegisAI v0.4 Architecture

```text
AegisAI source
    |
    v
logical lexer -> parser -> AST
                        |
                        v
                static semantic checker
                - information flow
                - taint boundaries
                - risk/effects
                - model/agent links
                - capability envelopes
                - evidence/trust
                - policy syntax/references
                - action/token binding
                - Twin-before-execute ordering
                - transaction rollback
                        |
             +----------+-----------+
             |                      |
             v                      v
         AIR 0.4 JSON          Python backend
             |
             v
      bounded-authority runtime
             |
   +---------+----------+------------------+
   |                    |                  |
   v                    v                  v
policy engine     capability tokens    Twin validation
   |                    |                  |
   +--------------------+------------------+
                        |
                        v
                    execute
                        |
                        v
                effect adapter interface
                        |
             default: NoOp simulation
                        |
                        v
              provenance hash chain
```

## Core design invariant

**Reasoning authority is not execution authority.**

v0.4 preserves and extends these authority boundaries:

```text
Agent -> Proposal -> Authorization -> Action -> Execution
           |              |            |          |
      evidence/trust    policy      capability   token + Twin
```

A valid `action` still cannot execute without matching runtime authority and successful Twin validation; v0.4 can use either a legacy HMAC token or an Ed25519 capability credential, and can additionally bind placement and typed adapters.

## AIR 0.4

AIR preserves security semantics rather than erasing them. Important operations include:

- `capability.declare`
- `ai.model`
- `ai.agent`
- `evidence.declare`
- `policy.declare`
- `ai.proposal`
- `auth.authorize`
- `action.declare`
- `capability.token`
- `twin.declare`
- `twin.validate`
- `action.execute`
- `taint.declare`
- `taint.sanitize`
- `intent.declare`
- `sequence.declare`
- `transaction.secure`

## Runtime policy engine

The policy engine evaluates a restricted expression language through Python AST parsing without general-purpose `eval`. Only simple values, attributes, boolean operators, arithmetic and comparisons are accepted. Unknown or unsupported constructs fail closed.

## Capability tokens

Runtime tokens are HMAC-SHA256 authenticated and include:

```text
version, token name, agent, capability, issued-at, expiry, random nonce
```

A token is not persisted in the provenance chain; only its SHA-256 fingerprint is recorded.

## Provenance

The runtime builds an append-only logical ledger. Each entry contains:

```text
sequence number
timestamp
event kind
previous entry hash
payload
current SHA-256 hash
```

Changing an older record invalidates the rest of the chain. This is tamper-evident, not equivalent to an externally anchored or independently signed transparency log.

## Effect adapters

`EffectAdapter` is the runtime boundary for real operational side effects. The repository ships with `NoOpAdapter`, which returns a simulated execution record and performs no external change.

A production adapter should be isolated and should independently validate:

- target identity
- authenticated operator/runtime identity
- least-privilege authorization
- idempotency and rollback semantics
- target-specific constraints
- audit correlation IDs

## Runtime context

Dynamic state is intentionally kept out of source code. Example:

```json
{
  "approvals": {"DisableAccount": true},
  "twins": {
    "EdgeTwin": {
      "availability_loss": 0.002,
      "latency_delta": 1.7
    }
  },
  "proposals": {
    "BlockHost": {"confidence": 0.99}
  }
}
```

Proposal-local `confidence` overrides the runtime-context value when explicitly declared.

## Next research targets

- typed policy/guard expressions at parse time
- asymmetric capability credentials and remote attestation
- externally anchored provenance / transparency logs
- pluggable Digital Twin RPC adapters
- compensation execution for secure transactions
- typed effect adapters and capability-scoped connectors
- WASM/eBPF-oriented AIR lowering
- 5G/6G slice, MEC and data-residency placement constraints
- formal small-step operational semantics and non-interference proofs

---

# v0.4 Architecture Extension: Production Trust Fabric

AIR 0.4 adds four trust/deployment operations:

```text
capability.credential
    -> Ed25519 authority issuance and verification

deployment.placement
    -> Cloud/Edge/5G/on-prem placement constraints

twin.connector
    -> explicit source of Digital Twin observations

effect.adapter
    -> typed boundary from verified action to external side effect
```

The runtime path is deliberately split across trust domains:

```text
Compiler trust domain
    parser -> checker -> AIR 0.4

Authority trust domain
    policy -> capability credential -> issuer trust

Deployment trust domain
    placement telemetry -> placement constraints

Validation trust domain
    Twin connector -> simulation/observations -> Twin guards

Effect trust domain
    typed adapter declaration -> host-bound adapter implementation

Audit trust domain
    provenance hash chain -> Ed25519 root anchor
```

External adapter implementations and remote Twin services are dependencies outside the compiler's intrinsic trust boundary. AIR records the requested effect, adapter, connector, placement and authority metadata so hosts can impose independent controls.
