from __future__ import annotations
import json
from .parser import parse
from .checker import check, SecurityError, Diagnostic
from .ir import lower
from .codegen import generate_python
from .runtime import RunResult, EffectAdapter, run_air


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


def run_source(source: str, *, context: dict | None = None, runtime_key: bytes, adapter: EffectAdapter | None = None, now: int | None = None) -> RunResult:
    """Compile to AIR 0.3 and execute its bounded-authority runtime pipeline."""
    program = parse(source)
    diagnostics = check(program)
    if diagnostics:
        raise SecurityError(diagnostics)
    return run_air(lower(program), context=context, runtime_key=runtime_key, adapter=adapter, now=now)
