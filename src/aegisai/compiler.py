from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .parser import parse
from .checker import check, SecurityError, Diagnostic
from .ir import lower
from .codegen import generate_python
from .runtime import RunResult, EffectAdapter, TwinConnector, run_air
from .credentials import SigningIdentity


def check_source(source: str) -> list[Diagnostic]:
    """Parse and statically check AegisAI source without generating output."""
    return check(parse(source))


def compile_source(source: str, target: str = "python") -> str:
    program = parse(source)
    diagnostics = check(program)
    if diagnostics:
        raise SecurityError(diagnostics)
    if target == "python":
        return generate_python(program)
    if target == "air":
        return json.dumps(lower(program), indent=2)
    raise ValueError(f"unknown target: {target}")


def run_source(
    source: str,
    *,
    context: dict[str, Any] | None = None,
    runtime_key: bytes | None = None,
    adapter: EffectAdapter | None = None,
    adapters: dict[str, EffectAdapter] | None = None,
    twin_connectors: dict[str, TwinConnector] | None = None,
    credential_signers: dict[str, SigningIdentity] | None = None,
    trusted_issuers: dict[str, Ed25519PublicKey] | None = None,
    provenance_signer: SigningIdentity | None = None,
    allow_remote_twin: bool = False,
    now: int | None = None,
) -> RunResult:
    """Compile to AIR 0.5 and execute the bounded-authority runtime pipeline."""
    program = parse(source)
    diagnostics = check(program)
    if diagnostics:
        raise SecurityError(diagnostics)
    return run_air(
        lower(program),
        context=context,
        runtime_key=runtime_key,
        adapter=adapter,
        adapters=adapters,
        twin_connectors=twin_connectors,
        credential_signers=credential_signers,
        trusted_issuers=trusted_issuers,
        provenance_signer=provenance_signer,
        allow_remote_twin=allow_remote_twin,
        now=now,
    )
