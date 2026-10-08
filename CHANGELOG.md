# Changelog

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
