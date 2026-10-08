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
    tainted: set[str] = set()
    evidence: dict[str, EvidenceDecl] = {}
    functions: dict[str, FunctionDecl] = {}
    policies: dict[str, PolicyDecl] = {}
    capabilities: dict[str, CapabilityDecl] = {}
    models: dict[str, ModelDecl] = {}
    agents: dict[str, AgentDecl] = {}
    proposals: dict[str, ProposalDecl] = {}
    actions: dict[str, ActionDecl] = {}
    diagnostics: list[Diagnostic] = []
    authorized = {s.proposal for s in program.statements if isinstance(s, AuthorizeStmt)}

    def duplicate(name: str, line: int, table: dict | set):
        if name in table:
            diagnostics.append(Diagnostic(line, "TYPE", f"duplicate symbol '{name}'"))

    for stmt in program.statements:
        if isinstance(stmt, DataDecl):
            duplicate(stmt.name, stmt.line, symbols); symbols[stmt.name] = (stmt.base_type, stmt.security)
        elif isinstance(stmt, SecretDecl):
            duplicate(stmt.name, stmt.line, symbols); symbols[stmt.name] = ("secret", "secret")
        elif isinstance(stmt, TaintedDecl):
            duplicate(stmt.name, stmt.line, symbols); symbols[stmt.name] = (stmt.base_type, "public"); tainted.add(stmt.name)
        elif isinstance(stmt, EvidenceDecl):
            duplicate(stmt.name, stmt.line, evidence); evidence[stmt.name] = stmt
        elif isinstance(stmt, FunctionDecl):
            duplicate(stmt.name, stmt.line, functions); functions[stmt.name] = stmt
        elif isinstance(stmt, PolicyDecl):
            duplicate(stmt.name, stmt.line, policies); policies[stmt.name] = stmt
        elif isinstance(stmt, CapabilityDecl):
            duplicate(stmt.name, stmt.line, capabilities); capabilities[stmt.name] = stmt
        elif isinstance(stmt, ModelDecl):
            duplicate(stmt.name, stmt.line, models); models[stmt.name] = stmt
        elif isinstance(stmt, AgentDecl):
            duplicate(stmt.name, stmt.line, agents); agents[stmt.name] = stmt
        elif isinstance(stmt, ProposalDecl):
            duplicate(stmt.name, stmt.line, proposals); proposals[stmt.name] = stmt
        elif isinstance(stmt, ActionDecl):
            duplicate(stmt.name, stmt.line, actions); actions[stmt.name] = stmt

    # Sanitization creates a new public, untainted symbol only from tainted input.
    for stmt in program.statements:
        if isinstance(stmt, SanitizeStmt):
            if stmt.source not in tainted:
                diagnostics.append(Diagnostic(stmt.line, "TAINT", f"'{stmt.source}' is not a tainted value"))
            elif stmt.target in symbols:
                diagnostics.append(Diagnostic(stmt.line, "TYPE", f"duplicate symbol '{stmt.target}'"))
            else:
                symbols[stmt.target] = symbols[stmt.source]

    def check_print(p: PrintStmt):
        if p.expr in tainted:
            diagnostics.append(Diagnostic(p.line, "TAINT", f"tainted value '{p.expr}' cannot flow to public output before sanitization"))
        if p.expr in symbols and LEVELS[symbols[p.expr][1]] > LEVELS["public"]:
            diagnostics.append(Diagnostic(p.line, "SECURITY", f"'{p.expr}' is {symbols[p.expr][1]} and cannot flow to public output"))

    for stmt in program.statements:
        if isinstance(stmt, PrintStmt):
            check_print(stmt)
        elif isinstance(stmt, FunctionDecl):
            used_effects = {s.args[0] for s in stmt.body if isinstance(s, CallStmt) and s.function == "__effect__"}
            for eff in sorted(used_effects - stmt.effects):
                diagnostics.append(Diagnostic(stmt.line, "EFFECT", f"function '{stmt.name}' uses undeclared effect '{eff}'"))
            if stmt.risk in {"high", "critical"} and not any(isinstance(s, RequireStmt) for s in stmt.body):
                diagnostics.append(Diagnostic(stmt.line, "RISK", f"{stmt.risk}-risk function '{stmt.name}' requires at least one explicit guard"))
            for s in stmt.body:
                if isinstance(s, PrintStmt): check_print(s)
        elif isinstance(stmt, AgentDecl):
            if stmt.model and stmt.model not in models:
                diagnostics.append(Diagnostic(stmt.line, "AI", f"agent '{stmt.name}' references unknown model '{stmt.model}'"))
            if capabilities:
                for cap in sorted(stmt.capabilities):
                    if cap not in capabilities:
                        diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"agent '{stmt.name}' references undeclared capability '{cap}'"))
            conflict = stmt.capabilities & stmt.denied
            for cap in sorted(conflict):
                diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"agent '{stmt.name}' both allows and denies capability '{cap}'"))
        elif isinstance(stmt, ProposalDecl):
            agent = agents.get(stmt.agent)
            if not stmt.agent:
                diagnostics.append(Diagnostic(stmt.line, "AI", f"proposal '{stmt.name}' must declare an agent with 'by'"))
            elif agent is None:
                diagnostics.append(Diagnostic(stmt.line, "AI", f"proposal '{stmt.name}' references unknown agent '{stmt.agent}'"))
            if capabilities and stmt.capability and stmt.capability not in capabilities:
                diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"proposal '{stmt.name}' references undeclared capability '{stmt.capability}'"))
            if not stmt.capability:
                diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"proposal '{stmt.name}' must declare a capability"))
            elif agent:
                if stmt.capability in agent.denied:
                    diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"proposal '{stmt.name}' uses capability '{stmt.capability}' denied to agent '{agent.name}'"))
                elif stmt.capability not in agent.capabilities:
                    diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"proposal '{stmt.name}' uses capability '{stmt.capability}' not granted to agent '{agent.name}'"))
            cap_decl = capabilities.get(stmt.capability)
            if cap_decl:
                for eff in sorted(stmt.effects - cap_decl.effects):
                    diagnostics.append(Diagnostic(stmt.line, "EFFECT", f"proposal '{stmt.name}' effect '{eff}' exceeds capability '{stmt.capability}' effect set"))
                if RISK_LEVELS[stmt.risk] < RISK_LEVELS[cap_decl.risk]:
                    diagnostics.append(Diagnostic(stmt.line, "RISK", f"proposal '{stmt.name}' risk '{stmt.risk}' understates capability '{stmt.capability}' minimum risk '{cap_decl.risk}'"))
            if stmt.risk in {"high", "critical"} and not stmt.guards:
                diagnostics.append(Diagnostic(stmt.line, "RISK", f"{stmt.risk}-risk proposal '{stmt.name}' requires at least one explicit guard"))
            if stmt.risk in {"high", "critical"} and not stmt.evidence:
                diagnostics.append(Diagnostic(stmt.line, "EVIDENCE", f"{stmt.risk}-risk proposal '{stmt.name}' requires explicit evidence"))
            for ev_name in stmt.evidence:
                ev = evidence.get(ev_name)
                if ev is None:
                    diagnostics.append(Diagnostic(stmt.line, "EVIDENCE", f"proposal '{stmt.name}' references unknown evidence '{ev_name}'"))
                elif ev.trust < stmt.min_trust:
                    diagnostics.append(Diagnostic(stmt.line, "TRUST", f"evidence '{ev_name}' trust {ev.trust:.2f} is below proposal '{stmt.name}' minimum {stmt.min_trust:.2f}"))
            if agent and agent.trust < stmt.min_trust:
                diagnostics.append(Diagnostic(stmt.line, "TRUST", f"agent '{agent.name}' trust {agent.trust:.2f} is below proposal '{stmt.name}' minimum {stmt.min_trust:.2f}"))
        elif isinstance(stmt, AuthorizeStmt):
            if stmt.proposal not in proposals:
                diagnostics.append(Diagnostic(stmt.line, "AUTH", f"cannot authorize unknown proposal '{stmt.proposal}'"))
            if stmt.policy not in policies:
                diagnostics.append(Diagnostic(stmt.line, "AUTH", f"authorization references unknown policy '{stmt.policy}'"))
        elif isinstance(stmt, ActionDecl):
            proposal = proposals.get(stmt.proposal)
            if stmt.proposal not in authorized:
                diagnostics.append(Diagnostic(stmt.line, "AUTH", f"action '{stmt.name}' is derived from proposal '{stmt.proposal}' without authorization"))
            if proposal is None:
                diagnostics.append(Diagnostic(stmt.line, "ACTION", f"action '{stmt.name}' references unknown proposal '{stmt.proposal}'"))
            else:
                if stmt.capability != proposal.capability:
                    diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"action '{stmt.name}' capability '{stmt.capability}' does not match proposal capability '{proposal.capability}'"))
                if stmt.effect not in proposal.effects:
                    diagnostics.append(Diagnostic(stmt.line, "EFFECT", f"action '{stmt.name}' effect '{stmt.effect}' was not declared by proposal '{proposal.name}'"))
        elif isinstance(stmt, SecureTransactionDecl):
            for action_name in stmt.actions:
                if action_name not in actions:
                    diagnostics.append(Diagnostic(stmt.line, "TRANSACTION", f"transaction '{stmt.name}' references unknown action '{action_name}'"))
            for rb in stmt.rollbacks:
                action = actions.get(rb)
                if action is None:
                    diagnostics.append(Diagnostic(stmt.line, "TRANSACTION", f"transaction '{stmt.name}' rollback references unknown action '{rb}'"))
                elif not action.reversible:
                    diagnostics.append(Diagnostic(stmt.line, "TRANSACTION", f"transaction '{stmt.name}' cannot rollback non-reversible action '{rb}'"))
        elif isinstance(stmt, CallStmt) and stmt.function != "__effect__":
            if stmt.function not in functions:
                diagnostics.append(Diagnostic(stmt.line, "TYPE", f"unknown function '{stmt.function}'"))

    return diagnostics
