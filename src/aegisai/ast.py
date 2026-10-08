from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

LEVELS = {"public": 0, "confidential": 1, "secret": 2}
RISK_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}

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
class TaintedDecl(Node):
    name: str
    base_type: str
    value: Any
    source: str = "external"

@dataclass
class SanitizeStmt(Node):
    source: str
    target: str

@dataclass
class EvidenceDecl(Node):
    name: str
    value: Any
    trust: float
    source: str

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
class CapabilityDecl(Node):
    name: str
    effects: set[str]
    risk: str

@dataclass
class ModelDecl(Node):
    name: str
    capabilities: set[str]
    trust: float
    network: str

@dataclass
class AgentDecl(Node):
    name: str
    model: str | None
    capabilities: set[str]
    denied: set[str]
    trust: float

@dataclass
class ProposalDecl(Node):
    name: str
    agent: str
    risk: str
    capability: str
    effects: set[str]
    guards: list[str]
    evidence: list[str]
    min_trust: float

@dataclass
class AuthorizeStmt(Node):
    proposal: str
    policy: str

@dataclass
class ActionDecl(Node):
    name: str
    proposal: str
    capability: str
    effect: str
    reversible: bool

@dataclass
class TwinDecl(Node):
    name: str
    target: str
    guards: list[str]

@dataclass
class IntentDecl(Node):
    name: str
    objectives: list[str]
    constraints: list[str]

@dataclass
class SequenceDecl(Node):
    name: str
    steps: list[str]

@dataclass
class SecureTransactionDecl(Node):
    name: str
    actions: list[str]
    rollbacks: list[str]

@dataclass
class CallStmt(Node):
    function: str
    args: list[str]
