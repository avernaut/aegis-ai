from __future__ import annotations
from dataclasses import dataclass
from .ast import *

@dataclass
class Diagnostic:
    line: int
    kind: str
    message: str

class SecurityError(Exception):
    def __init__(self, diagnostics: list[Diagnostic]):
        self.diagnostics = diagnostics
        super().__init__("; ".join(d.message for d in diagnostics))

def check(program: Program) -> list[Diagnostic]:
    symbols: dict[str, tuple[str, str]] = {}
    functions: dict[str, FunctionDecl] = {}
    diagnostics: list[Diagnostic] = []

    for stmt in program.statements:
        if isinstance(stmt, DataDecl):
            if stmt.name in symbols:
                diagnostics.append(Diagnostic(stmt.line, "TYPE", f"duplicate symbol '{stmt.name}'"))
            symbols[stmt.name] = (stmt.base_type, stmt.security)
        elif isinstance(stmt, SecretDecl):
            symbols[stmt.name] = ("secret", "secret")
        elif isinstance(stmt, FunctionDecl):
            functions[stmt.name] = stmt

    def check_print(p: PrintStmt):
        if p.expr in symbols and LEVELS[symbols[p.expr][1]] > LEVELS["public"]:
            diagnostics.append(Diagnostic(p.line, "SECURITY", f"'{p.expr}' is {symbols[p.expr][1]} and cannot flow to public output"))

    for stmt in program.statements:
        if isinstance(stmt, PrintStmt):
            check_print(stmt)
        elif isinstance(stmt, FunctionDecl):
            used_effects = {s.args[0] for s in stmt.body if isinstance(s, CallStmt) and s.function == "__effect__"}
            undeclared = used_effects - stmt.effects
            for eff in sorted(undeclared):
                diagnostics.append(Diagnostic(stmt.line, "EFFECT", f"function '{stmt.name}' uses undeclared effect '{eff}'"))
            if stmt.risk in {"high", "critical"}:
                has_guard = any(isinstance(s, RequireStmt) for s in stmt.body)
                if not has_guard:
                    diagnostics.append(Diagnostic(stmt.line, "RISK", f"{stmt.risk}-risk function '{stmt.name}' requires at least one explicit guard"))
            for s in stmt.body:
                if isinstance(s, PrintStmt): check_print(s)
        elif isinstance(stmt, CallStmt) and stmt.function != "__effect__":
            if stmt.function not in functions:
                diagnostics.append(Diagnostic(stmt.line, "TYPE", f"unknown function '{stmt.function}'"))

    return diagnostics
