from __future__ import annotations

from dataclasses import dataclass
import re
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


_POLICY_RULES = [
    re.compile(r"^deny by default$"),
    re.compile(r"^allow all$"),
    re.compile(r"^(allow|deny) [A-Za-z_]\w*(?:\.[A-Za-z_]\w*)* when .+$"),
    re.compile(r"^require human when .+$"),
]


def _valid_policy_rule(rule: str) -> bool:
    return any(r.match(rule) for r in _POLICY_RULES)


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
    tokens: dict[str, TokenDecl] = {}
    credentials: dict[str, CredentialDecl] = {}
    delegations: dict[str, DelegationDecl] = {}
    quorums: dict[str, QuorumDecl] = {}
    federations: dict[str, FederationDecl] = {}
    attestations: dict[str, AttestationDecl] = {}
    adapters: dict[str, AdapterDecl] = {}
    twin_connectors: dict[str, TwinConnectorDecl] = {}
    twins: dict[str, TwinDecl] = {}
    placements: dict[str, PlacementDecl] = {}
    diagnostics: list[Diagnostic] = []

    positions = {id(s): i for i, s in enumerate(program.statements)}
    auth_stmts = [s for s in program.statements if isinstance(s, (AuthorizeStmt, FederatedAuthorizeStmt))]
    validate_stmts = [s for s in program.statements if isinstance(s, TwinValidateStmt)]
    authorized = {s.proposal for s in auth_stmts}

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
        elif isinstance(stmt, TokenDecl):
            duplicate(stmt.name, stmt.line, tokens); tokens[stmt.name] = stmt
        elif isinstance(stmt, CredentialDecl):
            duplicate(stmt.name, stmt.line, credentials); credentials[stmt.name] = stmt
        elif isinstance(stmt, DelegationDecl):
            duplicate(stmt.name, stmt.line, delegations); delegations[stmt.name] = stmt
        elif isinstance(stmt, QuorumDecl):
            duplicate(stmt.name, stmt.line, quorums); quorums[stmt.name] = stmt
        elif isinstance(stmt, FederationDecl):
            duplicate(stmt.name, stmt.line, federations); federations[stmt.name] = stmt
        elif isinstance(stmt, AttestationDecl):
            duplicate(stmt.name, stmt.line, attestations); attestations[stmt.name] = stmt
        elif isinstance(stmt, AdapterDecl):
            duplicate(stmt.name, stmt.line, adapters); adapters[stmt.name] = stmt
        elif isinstance(stmt, TwinConnectorDecl):
            duplicate(stmt.name, stmt.line, twin_connectors); twin_connectors[stmt.name] = stmt
        elif isinstance(stmt, TwinDecl):
            duplicate(stmt.name, stmt.line, twins); twins[stmt.name] = stmt
        elif isinstance(stmt, PlacementDecl):
            if stmt.target in placements:
                diagnostics.append(Diagnostic(stmt.line, "PLACEMENT", f"target '{stmt.target}' has more than one placement declaration"))
            placements[stmt.target] = stmt

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

    def check_authority(agent: AgentDecl | None, capability: str, name: str, line: int, kind: str):
        if agent is None:
            return
        if capability in agent.denied:
            diagnostics.append(Diagnostic(line, kind, f"{kind.lower()} '{name}' requests capability '{capability}' denied to agent '{agent.name}'"))
        elif capability not in agent.capabilities:
            diagnostics.append(Diagnostic(line, kind, f"{kind.lower()} '{name}' requests capability '{capability}' not granted to agent '{agent.name}'"))

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
                if isinstance(s, PrintStmt):
                    check_print(s)

        elif isinstance(stmt, PolicyDecl):
            if not stmt.rules:
                diagnostics.append(Diagnostic(stmt.line, "POLICY", f"policy '{stmt.name}' must contain at least one rule"))
            for rule in stmt.rules:
                if not _valid_policy_rule(rule):
                    diagnostics.append(Diagnostic(stmt.line, "POLICY", f"policy '{stmt.name}' contains unsupported rule '{rule}'"))

        elif isinstance(stmt, AdapterDecl):
            if not stmt.effects:
                diagnostics.append(Diagnostic(stmt.line, "ADAPTER", f"adapter '{stmt.name}' must declare at least one handled effect"))
            if stmt.mode not in {"simulation", "external"}:
                diagnostics.append(Diagnostic(stmt.line, "ADAPTER", f"adapter '{stmt.name}' has unsupported mode '{stmt.mode}'"))
            if not stmt.trust_zone:
                diagnostics.append(Diagnostic(stmt.line, "ADAPTER", f"adapter '{stmt.name}' must declare a non-empty trust zone"))

        elif isinstance(stmt, TwinConnectorDecl):
            if stmt.transport == "https":
                if not stmt.endpoint or not stmt.endpoint.startswith("https://"):
                    diagnostics.append(Diagnostic(stmt.line, "TWIN", f"HTTPS twin connector '{stmt.name}' requires an https:// endpoint"))
            if stmt.timeout_ms <= 0 or stmt.timeout_ms > 60000:
                diagnostics.append(Diagnostic(stmt.line, "TWIN", f"twin connector '{stmt.name}' timeout_ms must be between 1 and 60000"))

        elif isinstance(stmt, TwinDecl):
            if stmt.connector and stmt.connector not in twin_connectors:
                diagnostics.append(Diagnostic(stmt.line, "TWIN", f"twin '{stmt.name}' references unknown connector '{stmt.connector}'"))
            if not stmt.guards:
                diagnostics.append(Diagnostic(stmt.line, "TWIN", f"twin '{stmt.name}' must declare at least one safety guard"))

        elif isinstance(stmt, AgentDecl):
            if stmt.model and stmt.model not in models:
                diagnostics.append(Diagnostic(stmt.line, "AI", f"agent '{stmt.name}' references unknown model '{stmt.model}'"))
            if capabilities:
                for cap in sorted(stmt.capabilities):
                    if cap not in capabilities:
                        diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"agent '{stmt.name}' references undeclared capability '{cap}'"))
            for cap in sorted(stmt.capabilities & stmt.denied):
                diagnostics.append(Diagnostic(stmt.line, "CAPABILITY", f"agent '{stmt.name}' both allows and denies capability '{cap}'"))

        elif isinstance(stmt, PlacementDecl):
            if stmt.target not in agents:
                diagnostics.append(Diagnostic(stmt.line, "PLACEMENT", f"placement references unknown agent '{stmt.target}'"))
            if stmt.max_latency_ms is not None and stmt.max_latency_ms <= 0:
                diagnostics.append(Diagnostic(stmt.line, "PLACEMENT", f"placement for '{stmt.target}' max_latency_ms must be positive"))
            if stmt.data_residency and stmt.region and stmt.data_residency != stmt.region:
                diagnostics.append(Diagnostic(stmt.line, "PLACEMENT", f"placement for '{stmt.target}' region '{stmt.region}' conflicts with data_residency '{stmt.data_residency}'"))

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

        elif isinstance(stmt, TokenDecl):
            agent = agents.get(stmt.agent)
            if agent is None:
                diagnostics.append(Diagnostic(stmt.line, "TOKEN", f"token '{stmt.name}' references unknown agent '{stmt.agent}'"))
            if stmt.capability not in capabilities:
                diagnostics.append(Diagnostic(stmt.line, "TOKEN", f"token '{stmt.name}' references undeclared capability '{stmt.capability}'"))
            if agent:
                if stmt.capability in agent.denied:
                    diagnostics.append(Diagnostic(stmt.line, "TOKEN", f"token '{stmt.name}' requests capability '{stmt.capability}' denied to agent '{agent.name}'"))
                elif stmt.capability not in agent.capabilities:
                    diagnostics.append(Diagnostic(stmt.line, "TOKEN", f"token '{stmt.name}' requests capability '{stmt.capability}' not granted to agent '{agent.name}'"))
            if stmt.ttl_seconds <= 0 or stmt.ttl_seconds > 86400:
                diagnostics.append(Diagnostic(stmt.line, "TOKEN", f"token '{stmt.name}' ttl must be between 1 and 86400 seconds"))

        elif isinstance(stmt, CredentialDecl):
            agent = agents.get(stmt.agent)
            if agent is None:
                diagnostics.append(Diagnostic(stmt.line, "CREDENTIAL", f"credential '{stmt.name}' references unknown agent '{stmt.agent}'"))
            if stmt.capability not in capabilities:
                diagnostics.append(Diagnostic(stmt.line, "CREDENTIAL", f"credential '{stmt.name}' references undeclared capability '{stmt.capability}'"))
            check_authority(agent, stmt.capability, stmt.name, stmt.line, "CREDENTIAL")
            if stmt.ttl_seconds <= 0 or stmt.ttl_seconds > 86400:
                diagnostics.append(Diagnostic(stmt.line, "CREDENTIAL", f"credential '{stmt.name}' ttl must be between 1 and 86400 seconds"))
            if not stmt.issuer:
                diagnostics.append(Diagnostic(stmt.line, "CREDENTIAL", f"credential '{stmt.name}' must declare an issuer"))

        elif isinstance(stmt, DelegationDecl):
            source = agents.get(stmt.from_agent)
            target = agents.get(stmt.to_agent)
            if source is None:
                diagnostics.append(Diagnostic(stmt.line, "DELEGATION", f"delegation '{stmt.name}' references unknown source agent '{stmt.from_agent}'"))
            if target is None:
                diagnostics.append(Diagnostic(stmt.line, "DELEGATION", f"delegation '{stmt.name}' references unknown target agent '{stmt.to_agent}'"))
            if stmt.capability not in capabilities:
                diagnostics.append(Diagnostic(stmt.line, "DELEGATION", f"delegation '{stmt.name}' references undeclared capability '{stmt.capability}'"))
            if source:
                check_authority(source, stmt.capability, stmt.name, stmt.line, "DELEGATION")
            if target and stmt.capability in target.denied:
                diagnostics.append(Diagnostic(stmt.line, "DELEGATION", f"delegation '{stmt.name}' grants capability '{stmt.capability}' explicitly denied to target agent '{target.name}'"))
            if stmt.ttl_seconds <= 0 or stmt.ttl_seconds > 3600:
                diagnostics.append(Diagnostic(stmt.line, "DELEGATION", f"delegation '{stmt.name}' ttl must be between 1 and 3600 seconds"))
            if not stmt.issuer:
                diagnostics.append(Diagnostic(stmt.line, "DELEGATION", f"delegation '{stmt.name}' must declare an issuer"))

        elif isinstance(stmt, QuorumDecl):
            if stmt.proposal not in proposals:
                diagnostics.append(Diagnostic(stmt.line, "QUORUM", f"quorum '{stmt.name}' references unknown proposal '{stmt.proposal}'"))
            if not stmt.members:
                diagnostics.append(Diagnostic(stmt.line, "QUORUM", f"quorum '{stmt.name}' must contain at least one member"))
            for member in stmt.members:
                if member not in agents:
                    diagnostics.append(Diagnostic(stmt.line, "QUORUM", f"quorum '{stmt.name}' references unknown agent '{member}'"))
            if len(set(stmt.members)) != len(stmt.members):
                diagnostics.append(Diagnostic(stmt.line, "QUORUM", f"quorum '{stmt.name}' contains duplicate members"))
            if stmt.threshold <= 0 or stmt.threshold > len(stmt.members):
                diagnostics.append(Diagnostic(stmt.line, "QUORUM", f"quorum '{stmt.name}' threshold must be between 1 and member count"))

        elif isinstance(stmt, FederationDecl):
            if not stmt.policies:
                diagnostics.append(Diagnostic(stmt.line, "FEDERATION", f"federation '{stmt.name}' must include at least one policy"))
            for policy in stmt.policies:
                if policy not in policies:
                    diagnostics.append(Diagnostic(stmt.line, "FEDERATION", f"federation '{stmt.name}' references unknown policy '{policy}'"))
            if stmt.strategy == "threshold":
                if stmt.threshold is None or stmt.threshold <= 0 or stmt.threshold > len(stmt.policies):
                    diagnostics.append(Diagnostic(stmt.line, "FEDERATION", f"federation '{stmt.name}' threshold must be between 1 and policy count"))
            elif stmt.threshold is not None:
                diagnostics.append(Diagnostic(stmt.line, "FEDERATION", f"federation '{stmt.name}' may set threshold only with strategy threshold"))

        elif isinstance(stmt, FederatedAuthorizeStmt):
            if stmt.proposal not in proposals:
                diagnostics.append(Diagnostic(stmt.line, "AUTH", f"cannot authorize unknown proposal '{stmt.proposal}'"))
            if stmt.federation not in federations:
                diagnostics.append(Diagnostic(stmt.line, "FEDERATION", f"authorization references unknown federation '{stmt.federation}'"))

        elif isinstance(stmt, AttestationDecl):
            if stmt.target not in agents:
                diagnostics.append(Diagnostic(stmt.line, "ATTESTATION", f"attestation '{stmt.name}' references unknown target agent '{stmt.target}'"))
            if not stmt.issuer:
                diagnostics.append(Diagnostic(stmt.line, "ATTESTATION", f"attestation '{stmt.name}' must declare an issuer"))
            if stmt.max_age_seconds <= 0 or stmt.max_age_seconds > 86400:
                diagnostics.append(Diagnostic(stmt.line, "ATTESTATION", f"attestation '{stmt.name}' max_age must be between 1 and 86400 seconds"))
            if not stmt.measurement:
                diagnostics.append(Diagnostic(stmt.line, "ATTESTATION", f"attestation '{stmt.name}' must declare a measurement"))

        elif isinstance(stmt, TwinValidateStmt):
            if stmt.action not in actions:
                diagnostics.append(Diagnostic(stmt.line, "TWIN", f"validation references unknown action '{stmt.action}'"))
            if stmt.twin not in twins:
                diagnostics.append(Diagnostic(stmt.line, "TWIN", f"validation references unknown twin '{stmt.twin}'"))

        elif isinstance(stmt, ExecuteStmt):
            action = actions.get(stmt.action)
            token = tokens.get(stmt.token)
            credential = credentials.get(stmt.token)
            delegation = delegations.get(stmt.token)
            authority = token or credential or delegation
            if action is None:
                diagnostics.append(Diagnostic(stmt.line, "EXECUTE", f"cannot execute unknown action '{stmt.action}'"))
            if authority is None:
                diagnostics.append(Diagnostic(stmt.line, "EXECUTE", f"execution references unknown token, credential, or delegation '{stmt.token}'"))
            prior_validation = any(v.action == stmt.action and positions[id(v)] < positions[id(stmt)] for v in validate_stmts)
            if not prior_validation:
                diagnostics.append(Diagnostic(stmt.line, "TWIN", f"action '{stmt.action}' must pass an explicit twin validation before execution"))
            if stmt.adapter:
                adapter = adapters.get(stmt.adapter)
                if adapter is None:
                    diagnostics.append(Diagnostic(stmt.line, "ADAPTER", f"execution references unknown adapter '{stmt.adapter}'"))
                elif action and action.effect not in adapter.effects:
                    diagnostics.append(Diagnostic(stmt.line, "ADAPTER", f"adapter '{adapter.name}' does not handle action effect '{action.effect}'"))
            if stmt.quorum:
                quorum = quorums.get(stmt.quorum)
                if quorum is None:
                    diagnostics.append(Diagnostic(stmt.line, "QUORUM", f"execution references unknown quorum '{stmt.quorum}'"))
                elif action:
                    proposal = proposals.get(action.proposal)
                    if proposal and quorum.proposal != proposal.name:
                        diagnostics.append(Diagnostic(stmt.line, "QUORUM", f"quorum '{quorum.name}' protects proposal '{quorum.proposal}', not '{proposal.name}'"))
            if stmt.attestation:
                att = attestations.get(stmt.attestation)
                if att is None:
                    diagnostics.append(Diagnostic(stmt.line, "ATTESTATION", f"execution references unknown attestation '{stmt.attestation}'"))
                elif action:
                    proposal = proposals.get(action.proposal)
                    if proposal and att.target not in {proposal.agent, getattr(authority, 'to_agent', None)}:
                        diagnostics.append(Diagnostic(stmt.line, "ATTESTATION", f"attestation '{att.name}' target '{att.target}' is not an execution participant"))

            if action and authority:
                proposal = proposals.get(action.proposal)
                if authority.capability != action.capability:
                    diagnostics.append(Diagnostic(stmt.line, "TOKEN", f"token or credential '{stmt.token}' capability '{authority.capability}' does not match action capability '{action.capability}'"))
                if proposal:
                    if isinstance(authority, DelegationDecl):
                        if authority.from_agent != proposal.agent:
                            diagnostics.append(Diagnostic(stmt.line, "DELEGATION", f"delegation '{stmt.token}' originates from '{authority.from_agent}', not proposal agent '{proposal.agent}'"))
                    elif authority.agent != proposal.agent:
                        diagnostics.append(Diagnostic(stmt.line, "TOKEN", f"token or credential '{stmt.token}' belongs to agent '{authority.agent}', not proposal agent '{proposal.agent}'"))
                if positions[id(authority)] > positions[id(stmt)]:
                    diagnostics.append(Diagnostic(stmt.line, "TOKEN", f"token or credential '{stmt.token}' must be declared before execution"))
                if positions[id(action)] > positions[id(stmt)]:
                    diagnostics.append(Diagnostic(stmt.line, "EXECUTE", f"action '{action.name}' must be declared before execution"))

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
