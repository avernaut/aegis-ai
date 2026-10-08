# Contributing

AegisAI is an experimental research language. Contributions must preserve its central principle: **AI reasoning authority and execution authority remain distinct**.

1. Create a feature branch.
2. Add regression tests for parser, static security semantics, runtime authorization or provenance changes.
3. Run `pytest -q`.
4. Run `aegis examples/bounded_defense.aegis --check`.
5. For runtime changes, run the bounded-authority example with a development key and verify the resulting audit chain.
6. Update `docs/LANGUAGE.md`, `docs/ARCHITECTURE.md` and/or `docs/RUNTIME.md` for syntax or runtime changes.
7. Submit a pull request describing the security implications and any new trusted assumptions.

Production effect adapters should never be added without explicit authentication, least-privilege, idempotency, rollback and audit considerations.
