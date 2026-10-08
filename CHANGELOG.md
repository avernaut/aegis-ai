# Changelog

## 0.3.0

- Added executable bounded-authority runtime.
- Added restricted policy evaluation with security-first default deny and deny override.
- Added proposal `confidence` and runtime guard evaluation.
- Added HMAC-SHA256 signed, expiring capability tokens.
- Added `token <name> for <agent> capability <capability> ttl <seconds>`.
- Added explicit `validate <action> with <twin>` and runtime Twin guard evaluation.
- Added explicit `execute <action> using <token>` authority boundary.
- Added static checks for token TTL, agent/capability binding and Twin-before-execute ordering.
- Added human approval enforcement for `require human when ...` policy rules.
- Added tamper-evident SHA-256 provenance chain and audit verification CLI.
- Added safe default NoOp effect adapter; no external system changes are made by default.
- Added `aegis run` and `aegis verify-audit` commands.
- Upgraded AIR from 0.2 to 0.3 with `capability.token`, `twin.validate` and `action.execute` operations.
- Updated Python backend to preserve the runtime boundary.
- Expanded examples and regression tests.

## 0.2.0

- Added first-class `capability` declarations with effect/risk envelopes.
- Added first-class `model` and `agent` declarations.
- Added agent capability allow/deny semantics.
- Added trust-scored `evidence`.
- Added `proposal` with risk, guard, evidence, trust, capability and effect metadata.
- Added explicit `authorize ... using ...` authority boundary.
- Added `action` declarations and authorization/effect/capability consistency checks.
- Added `tainted<T>` values and `sanitize` boundaries.
- Added `twin`, `intent`, temporal `sequence` and `secure transaction` declarations.
- Added rollback validation for reversible actions.
- Upgraded AIR from 0.1 to 0.2.
- Added `aegis --check` and `aegis --version`.
- Expanded regression suite and security documentation.

## 0.1.0

- Initial compiler prototype.
- Security-qualified data types.
- Secret/public-flow checking.
- Function risk levels and guards.
- Effect declarations.
- Policies, AIR 0.1 and Python code generation.
