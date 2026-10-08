from __future__ import annotations
import json
from .parser import parse
from .checker import check, SecurityError
from .ir import lower
from .codegen import generate_python

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
