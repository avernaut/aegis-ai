# AegisAI v0.2 Security Model

AegisAI v0.2 implements a prototype of **bounded intelligence**: AI components may reason and recommend, but authority to cause side effects is separately represented and checked.

## Security invariants

1. **No implicit declassification.** `confidential` and `secret` values cannot reach a public output sink.
2. **Untrusted input remains tainted.** A tainted value cannot reach a public sink before an explicit `sanitize` boundary.
3. **Deny wins at the capability boundary.** An agent cannot both allow and deny a capability, and denied capabilities cannot be used by proposals.
4. **High-impact AI proposals need evidence.** `high` and `critical` proposals require guards and explicit evidence.
5. **Trust is checked before authorization can become useful.** Agent and evidence trust must meet the proposal's declared minimum.
6. **Proposal is not action.** An action derived from a proposal requires an explicit authorization statement referencing a declared policy.
7. **Effects cannot expand silently.** Action effects must already appear in the proposal.
8. **Rollback must be declared possible.** Secure transactions can only rollback actions marked `reversible`.

## Current trust model

Trust values are developer-supplied scores in `[0,1]`; the compiler checks consistency but does not attest their truth. A production design should bind trust to provenance, signatures, source reputation and runtime observations.

## Current policy model

Policies are named rule collections and are checked for existence at authorization boundaries. v0.2 does not yet interpret policy expressions. Therefore `authorize X using P` demonstrates the separation of authority, but is not yet a full policy-decision point.

## Current sanitization model

`sanitize source as target` is a trusted language boundary. It does not yet invoke a validator. This is deliberately explicit so future releases can replace it with typed sanitizers without changing the information-flow model.

## Non-goals of v0.2

- production-grade sandboxing
- cryptographic provenance
- real firewall/network execution
- policy decision evaluation
- prompt-injection detection
- formal verification proofs

The compiler is a research prototype intended to make these concerns first-class and testable before introducing real enforcement adapters.
