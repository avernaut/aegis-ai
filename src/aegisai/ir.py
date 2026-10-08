from __future__ import annotations
from .ast import *


def lower(program: Program) -> dict:
    ops = []
    for s in program.statements:
        if isinstance(s, DataDecl):
            ops.append({"op":"data.declare","name":s.name,"type":s.base_type,"security":s.security,"value":s.value,"line":s.line})
        elif isinstance(s, SecretDecl):
            ops.append({"op":"secret.declare","name":s.name,"value":"<redacted>","line":s.line})
        elif isinstance(s, TaintedDecl):
            ops.append({"op":"taint.declare","name":s.name,"type":s.base_type,"source":s.source,"value":s.value,"line":s.line})
        elif isinstance(s, SanitizeStmt):
            ops.append({"op":"taint.sanitize","source":s.source,"target":s.target,"line":s.line})
        elif isinstance(s, EvidenceDecl):
            ops.append({"op":"evidence.declare","name":s.name,"value":s.value,"trust":s.trust,"source":s.source,"line":s.line})
        elif isinstance(s, PrintStmt):
            ops.append({"op":"io.print","expr":s.expr,"effect":"write.stdout","line":s.line})
        elif isinstance(s, RequireStmt):
            ops.append({"op":"guard.require","condition":s.condition,"line":s.line})
        elif isinstance(s, PolicyDecl):
            ops.append({"op":"policy.declare","name":s.name,"rules":s.rules,"line":s.line})
        elif isinstance(s, CapabilityDecl):
            ops.append({"op":"capability.declare","name":s.name,"effects":sorted(s.effects),"risk":s.risk,"line":s.line})
        elif isinstance(s, ModelDecl):
            ops.append({"op":"ai.model","name":s.name,"capabilities":sorted(s.capabilities),"trust":s.trust,"network":s.network,"line":s.line})
        elif isinstance(s, AgentDecl):
            ops.append({"op":"ai.agent","name":s.name,"model":s.model,"capabilities":sorted(s.capabilities),"deny":sorted(s.denied),"trust":s.trust,"line":s.line})
        elif isinstance(s, PlacementDecl):
            ops.append({"op":"deployment.placement","target":s.target,"environment":s.environment,"region":s.region,"data_residency":s.data_residency,"max_latency_ms":s.max_latency_ms,"network":s.network,"line":s.line})
        elif isinstance(s, ProposalDecl):
            ops.append({"op":"ai.proposal","name":s.name,"agent":s.agent,"risk":s.risk,"capability":s.capability,"effects":sorted(s.effects),"guards":s.guards,"evidence":s.evidence,"min_trust":s.min_trust,"confidence":s.confidence,"line":s.line})
        elif isinstance(s, AuthorizeStmt):
            ops.append({"op":"auth.authorize","proposal":s.proposal,"policy":s.policy,"line":s.line})
        elif isinstance(s, ActionDecl):
            ops.append({"op":"action.declare","name":s.name,"proposal":s.proposal,"capability":s.capability,"effect":s.effect,"reversible":s.reversible,"line":s.line})
        elif isinstance(s, TokenDecl):
            ops.append({"op":"capability.token","name":s.name,"agent":s.agent,"capability":s.capability,"ttl_seconds":s.ttl_seconds,"line":s.line})
        elif isinstance(s, CredentialDecl):
            ops.append({"op":"capability.credential","name":s.name,"agent":s.agent,"capability":s.capability,"ttl_seconds":s.ttl_seconds,"issuer":s.issuer,"line":s.line})
        elif isinstance(s, AdapterDecl):
            ops.append({"op":"effect.adapter","name":s.name,"effects":sorted(s.effects),"mode":s.mode,"trust_zone":s.trust_zone,"line":s.line})
        elif isinstance(s, TwinConnectorDecl):
            ops.append({"op":"twin.connector","name":s.name,"transport":s.transport,"endpoint":s.endpoint,"timeout_ms":s.timeout_ms,"line":s.line})
        elif isinstance(s, TwinDecl):
            ops.append({"op":"twin.declare","name":s.name,"target":s.target,"guards":s.guards,"connector":s.connector,"line":s.line})
        elif isinstance(s, TwinValidateStmt):
            ops.append({"op":"twin.validate","action":s.action,"twin":s.twin,"line":s.line})
        elif isinstance(s, ExecuteStmt):
            ops.append({"op":"action.execute","action":s.action,"token":s.token,"adapter":s.adapter,"line":s.line})
        elif isinstance(s, IntentDecl):
            ops.append({"op":"intent.declare","name":s.name,"objectives":s.objectives,"constraints":s.constraints,"line":s.line})
        elif isinstance(s, SequenceDecl):
            ops.append({"op":"sequence.declare","name":s.name,"steps":s.steps,"line":s.line})
        elif isinstance(s, SecureTransactionDecl):
            ops.append({"op":"transaction.secure","name":s.name,"actions":s.actions,"rollbacks":s.rollbacks,"line":s.line})
        elif isinstance(s, FunctionDecl):
            ops.append({"op":"fn.declare","name":s.name,"params":s.params,"risk":s.risk,"effects":sorted(s.effects),"body":lower(Program(s.line,s.body))["ops"],"line":s.line})
        elif isinstance(s, CallStmt):
            ops.append({"op":"fn.call","name":s.function,"args":s.args,"line":s.line})
    return {"air_version":"0.4","language":"AegisAI","ops":ops}
