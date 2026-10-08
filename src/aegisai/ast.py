from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

LEVELS = {"public": 0, "confidential": 1, "secret": 2}

@dataclass
class Node:
    line: int

@dataclass
class Program(Node):
    statements: list[Node] = field(default_factory=list)

@dataclass
class DataDecl(Node):
    name: str
    base_type: str
    security: str
    value: Any

@dataclass
class SecretDecl(Node):
    name: str
    value: str

@dataclass
class PrintStmt(Node):
    expr: str

@dataclass
class RequireStmt(Node):
    condition: str

@dataclass
class FunctionDecl(Node):
    name: str
    params: list[str]
    effects: set[str]
    risk: str
    body: list[Node]

@dataclass
class PolicyDecl(Node):
    name: str
    rules: list[str]

@dataclass
class CallStmt(Node):
    function: str
    args: list[str]
