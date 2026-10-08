# Security Policy

AegisAI is a research compiler/runtime and must not be treated as a certified production security enforcement boundary without independent hardening and review.

## Reporting vulnerabilities

Please report vulnerabilities through a private GitHub security advisory when available. Avoid publishing exploit details before maintainers have had an opportunity to investigate.

Relevant issues include information-flow or taint bypasses, capability escalation, policy bypasses, trust-check bypasses, HMAC/Ed25519 credential-verification flaws, adapter type-confusion, placement bypasses, Digital Twin connector/validation bypasses, provenance-anchor verification errors, undeclared effects or rollback-validation errors.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.4.x | Yes |
| 0.3.x | Critical fixes only |
| 0.2.x | Critical fixes only |
| 0.1.x | No |

## Key-management guidance

- Never commit HMAC runtime keys or Ed25519 private keys.
- Prefer a KMS/HSM or secret manager for production experiments.
- HMAC keys should be high entropy; 32 random bytes are recommended.
- Ed25519 private keys generated with `aegis keygen` should be kept with restrictive filesystem permissions.
- Trust public keys by explicit issuer identity; do not accept arbitrary keys supplied by an untrusted workload.
- Rotate credentials and keep TTLs as short as operationally practical.

## Remote Digital Twin guidance

HTTPS Twin connectors are disabled unless explicitly enabled at runtime. In real deployments, use authenticated endpoints, mTLS/service-mesh identity, strict egress policy, bounded timeouts and schema validation. The built-in HTTPS connector is a research reference implementation, not a complete zero-trust transport stack.

## Effect-adapter guidance

`mode external` adapter implementations execute outside the compiler's trust boundary. They must independently enforce authentication, input validation, least privilege, idempotency/rollback where applicable, and auditable error handling. A declaration in AegisAI does not make an external integration safe by itself.
