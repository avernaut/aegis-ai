# AegisAI v0.4 Security Model

AegisAI implements a research prototype of **bounded intelligence**: AI components may reason and recommend, but operational authority is represented separately and checked at multiple boundaries.

## Security invariants

1. **No implicit declassification.** `confidential` and `secret` values cannot reach a public output sink.
2. **Untrusted input remains tainted.** A tainted value cannot reach a public sink before an explicit sanitization boundary.
3. **Deny wins at the capability boundary.** Denied capabilities cannot be used by proposals or tokens.
4. **High-impact proposals need evidence and guards.** `high` and `critical` proposals require both.
5. **Trust is bounded before authority.** Agent and evidence trust must satisfy the proposal minimum.
6. **Proposal is not action.** Actions must derive from structurally authorized proposals.
7. **Action is not execution.** `execute` is a separate statement and requires runtime checks.
8. **Effects cannot expand silently.** Action effects must be permitted by both proposal and capability.
9. **Runtime authority expires.** Capability tokens have a bounded TTL and are authenticated.
10. **Observed safety matters.** Execution requires successful Digital Twin validation against runtime metrics.
11. **Critical authority can require a human.** Policy rules can require an explicit approval record.
12. **Execution is auditable.** Runtime decisions are linked in a SHA-256 provenance hash chain.
13. **Default adapters are safe.** The built-in adapter simulates rather than modifies external systems.

## Policy model

v0.4 evaluates a restricted policy language. Authorization is default deny. A matching deny rule immediately rejects the proposal. Human-approval requirements are evaluated after the condition becomes true and cannot be satisfied implicitly.

## Capability-token model

Tokens are HMAC-SHA256 authenticated using a runtime key external to AegisAI source. The runtime checks signature, expiry, agent and capability before execution.

HMAC protects tokens only as strongly as the secrecy and entropy of the runtime key. Production deployments should use managed secrets and may prefer asymmetric credentials or hardware-backed keys.

## Provenance model

The SHA-256 ledger is tamper-evident within the recorded chain. It does not, by itself, prevent a privileged party from replacing the entire ledger with a newly generated one. Stronger deployments should externally anchor ledger roots or sign checkpoints with independently protected keys.

## Digital Twin model

Twin constraints are evaluated against runtime metrics obtained from a declared connector. v0.4 supports context and opt-in HTTPS connectors, but production systems still require authenticated transport, freshness and provenance guarantees.

## Sanitization model

`sanitize source as target` is an explicit trusted boundary. The prototype does not prove the sanitizer correct.

## Threats addressed by the prototype

- accidental secret/public-flow violations
- direct use of tainted values at public sinks
- undeclared side effects
- capability escalation inside checked AegisAI source
- action creation without authorization structure
- execution without a matching capability token
- execution without prior Digital Twin validation
- token tampering and expiration
- runtime policy violations
- audit-record modification after creation

## Important non-goals

v0.4 does not yet provide:

- production-grade sandbox isolation
- bundled production firewall/IAM/cloud side-effect connectors
- complete mTLS/service-mesh Digital Twin authentication
- hardware-backed key storage
- remote attestation
- prompt-injection detection or LLM-content safety guarantees
- formal non-interference proof
- Byzantine-resistant distributed audit storage

AegisAI v0.4 is a research compiler/runtime and should not be treated as a production security boundary without additional hardening.

---

# v0.4 Security Invariants

v0.4 adds the following invariants:

1. **Asymmetric authority** — a capability credential is accepted only when its Ed25519 signature, issuer/key ID, TTL, agent and capability all verify.
2. **Adapter effect typing** — an action cannot be routed through a declared adapter that does not handle the action's effect.
3. **External adapter explicitness** — `mode external` cannot silently fall back to simulation or implicit system access; a host adapter must be bound.
4. **Remote Twin opt-in** — HTTPS Twin transport is disabled unless the runtime explicitly enables remote Twin access.
5. **Placement consistency** — declared Cloud/Edge/5G/on-prem constraints are checked against observed runtime telemetry before the security pipeline proceeds.
6. **Anchored provenance** — the local SHA-256 audit chain can be bound to an externally verifiable Ed25519 signature over its final root.

These mechanisms reduce, but do not eliminate, trust in the host environment. A compromised host, private-key store, external adapter or Twin service remains outside the guarantees of the language-level checks and therefore requires independent hardening.

## v0.5 Multi-agent trust controls

AegisAI v0.5 adds five independent gates that can be combined before execution:

1. **Delegation containment** — a delegator cannot grant a capability it does not possess, and a delegatee deny rule remains authoritative.
2. **Federated policy** — multiple policies can be composed using all/any/threshold strategies without bypassing proposal guards.
3. **Quorum** — only approvals from statically declared members count toward the configured threshold.
4. **Runtime attestation** — Ed25519 signatures bind issuer, target, measurement, and timestamp; stale or mismatched attestations fail closed.
5. **Revocation** — authority name, issuer, key ID, or credential digest can be revoked at runtime before effects are released.

These controls are cumulative. A successful policy decision does not substitute for quorum, attestation, revocation, Twin validation, placement validation, or adapter authorization when those controls are declared.
