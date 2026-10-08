# Security Policy

AegisAI is a research compiler/runtime and must not be treated as a production security enforcement boundary without independent hardening.

## Reporting vulnerabilities

Please report vulnerabilities through a private GitHub security advisory when available. Avoid publishing exploit details before maintainers have had an opportunity to investigate.

Relevant issues include information-flow or taint bypasses, capability escalation, policy bypasses, trust-check bypasses, token-verification flaws, Twin-validation bypasses, provenance-chain verification errors, undeclared effects or rollback-validation errors.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.3.x | Yes |
| 0.2.x | Critical fixes only |
| 0.1.x | No |

## Runtime-key guidance

Do not commit runtime keys. Use a secret manager, protected key file or environment injection. Keys should be high entropy and at least 16 bytes; 32 random bytes are recommended for development/testing.
