from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .credentials import (
    CredentialError,
    SigningIdentity,
    issue_capability_credential,
    sign_provenance_anchor,
    verify_capability_credential,
    verify_provenance_anchor,
)


class AegisRuntimeError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _require_key(key: bytes | None) -> bytes:
    if key is None or len(key) < 16:
        raise AegisRuntimeError("runtime key must contain at least 16 bytes")
    return key


def issue_capability_token(name: str, agent: str, capability: str, ttl_seconds: int, key: bytes, now: int | None = None) -> str:
    _require_key(key)
    now = int(time.time()) if now is None else int(now)
    payload = {
        "v": 1,
        "name": name,
        "agent": agent,
        "capability": capability,
        "iat": now,
        "exp": now + int(ttl_seconds),
        "nonce": _b64e(os.urandom(12)),
    }
    body = _b64e(_canonical(payload))
    sig = _b64e(hmac.new(key, body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_capability_token(token: str, key: bytes, *, now: int | None = None, agent: str | None = None, capability: str | None = None) -> dict[str, Any]:
    _require_key(key)
    try:
        body, supplied_sig = token.split(".", 1)
        expected_sig = _b64e(hmac.new(key, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(supplied_sig, expected_sig):
            raise AegisRuntimeError("capability token signature verification failed")
        payload = json.loads(_b64d(body))
    except AegisRuntimeError:
        raise
    except Exception as exc:
        raise AegisRuntimeError("invalid capability token") from exc
    now = int(time.time()) if now is None else int(now)
    if int(payload.get("exp", 0)) < now:
        raise AegisRuntimeError("capability token has expired")
    if agent is not None and payload.get("agent") != agent:
        raise AegisRuntimeError(f"capability token agent mismatch: expected '{agent}'")
    if capability is not None and payload.get("capability") != capability:
        raise AegisRuntimeError(f"capability token mismatch: expected '{capability}'")
    return payload


@dataclass
class ProvenanceLedger:
    entries: list[dict[str, Any]] = field(default_factory=list)

    def append(self, kind: str, payload: dict[str, Any], timestamp: int | None = None) -> dict[str, Any]:
        ts = int(time.time()) if timestamp is None else int(timestamp)
        previous = self.entries[-1]["hash"] if self.entries else "0" * 64
        core = {"seq": len(self.entries), "timestamp": ts, "kind": kind, "previous_hash": previous, "payload": payload}
        digest = hashlib.sha256(_canonical(core)).hexdigest()
        entry = {**core, "hash": digest}
        self.entries.append(entry)
        return entry

    @property
    def root_hash(self) -> str:
        return self.entries[-1]["hash"] if self.entries else "0" * 64

    def verify(self) -> bool:
        previous = "0" * 64
        for i, entry in enumerate(self.entries):
            if entry.get("seq") != i or entry.get("previous_hash") != previous:
                return False
            core = {k: entry[k] for k in ("seq", "timestamp", "kind", "previous_hash", "payload")}
            digest = hashlib.sha256(_canonical(core)).hexdigest()
            if not hmac.compare_digest(digest, entry.get("hash", "")):
                return False
            previous = digest
        return True


class EffectAdapter(Protocol):
    supported_effects: set[str]
    def execute(self, action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...


class TwinConnector(Protocol):
    def metrics(self, twin: dict[str, Any], action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...


class NoOpAdapter:
    """Safe default adapter: records the action but performs no external side effect."""
    supported_effects = {"*"}

    def execute(self, action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return {"mode": "simulation", "status": "executed", "action": action["name"], "effect": action["effect"]}


class ContextTwinConnector:
    """Reads Digital Twin metrics from the explicit runtime context."""
    def metrics(self, twin: dict[str, Any], action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return dict(context.get("twins", {}).get(twin["name"], {}))


@dataclass
class HttpJsonTwinConnector:
    endpoint: str
    timeout_ms: int = 2000

    def metrics(self, twin: dict[str, Any], action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        body = _canonical({"twin": twin["name"], "target": twin.get("target"), "action": action})
        req = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_ms / 1000.0) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise AegisRuntimeError(f"remote digital twin connector failed for '{twin['name']}': {exc}") from exc
        if not isinstance(payload, dict):
            raise AegisRuntimeError(f"remote digital twin connector for '{twin['name']}' returned a non-object payload")
        return payload


@dataclass
class RunResult:
    authorizations: list[dict[str, Any]] = field(default_factory=list)
    placements: list[dict[str, Any]] = field(default_factory=list)
    validations: list[dict[str, Any]] = field(default_factory=list)
    executions: list[dict[str, Any]] = field(default_factory=list)
    provenance: list[dict[str, Any]] = field(default_factory=list)
    provenance_anchor: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        doc = {
            "status": "ok",
            "authorizations": self.authorizations,
            "placements": self.placements,
            "validations": self.validations,
            "executions": self.executions,
            "provenance": self.provenance,
            "provenance_valid": ProvenanceLedger(self.provenance).verify(),
        }
        if self.provenance_anchor is not None:
            doc["provenance_anchor"] = self.provenance_anchor
        return doc


def _resolve_attr(node: ast.AST, ctx: dict[str, Any]) -> Any:
    if isinstance(node, ast.Name):
        if node.id in {"true", "True"}: return True
        if node.id in {"false", "False"}: return False
        if node.id in {"none", "None"}: return None
        return ctx[node.id] if node.id in ctx else node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_attr(node.value, ctx)
        if isinstance(base, dict) and node.attr in base:
            return base[node.attr]
        raise AegisRuntimeError(f"unknown policy/guard attribute '{ast.unparse(node)}'")
    if isinstance(node, ast.Constant):
        return node.value
    raise AegisRuntimeError(f"unsupported value in policy/guard expression: {ast.dump(node, include_attributes=False)}")


def _eval_expr(expr: str, ctx: dict[str, Any]) -> Any:
    try:
        node = ast.parse(expr.replace("&&", " and ").replace("||", " or "), mode="eval").body
    except SyntaxError as exc:
        raise AegisRuntimeError(f"invalid policy/guard expression '{expr}'") from exc

    def ev(n: ast.AST) -> Any:
        if isinstance(n, (ast.Name, ast.Attribute, ast.Constant)):
            return _resolve_attr(n, ctx)
        if isinstance(n, ast.BoolOp):
            vals = [bool(ev(v)) for v in n.values]
            return all(vals) if isinstance(n.op, ast.And) else any(vals)
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            return not bool(ev(n.operand))
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            if isinstance(n.op, ast.Add): return a + b
            if isinstance(n.op, ast.Sub): return a - b
            if isinstance(n.op, ast.Mult): return a * b
            if isinstance(n.op, ast.Div): return a / b
            raise AegisRuntimeError(f"unsupported operator in expression '{expr}'")
        if isinstance(n, ast.Compare):
            left = ev(n.left)
            for op, comp in zip(n.ops, n.comparators):
                right = ev(comp)
                try:
                    if isinstance(op, ast.Eq): ok = left == right
                    elif isinstance(op, ast.NotEq): ok = left != right
                    elif isinstance(op, ast.Gt): ok = left > right
                    elif isinstance(op, ast.GtE): ok = left >= right
                    elif isinstance(op, ast.Lt): ok = left < right
                    elif isinstance(op, ast.LtE): ok = left <= right
                    else: raise AegisRuntimeError(f"unsupported comparison in expression '{expr}'")
                except TypeError as exc:
                    raise AegisRuntimeError(f"incompatible values in expression '{expr}'") from exc
                if not ok: return False
                left = right
            return True
        raise AegisRuntimeError(f"unsupported construct in policy/guard expression '{expr}'")

    return ev(node)


def _proposal_context(proposal: dict[str, Any], evidence: dict[str, dict[str, Any]], agent: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    refs = [evidence[n] for n in proposal.get("evidence", []) if n in evidence]
    min_trust = min((float(e["trust"]) for e in refs), default=0.0)
    pctx = context.get("proposals", {}).get(proposal["name"], {})
    confidence = proposal.get("confidence")
    if confidence is None:
        confidence = pctx.get("confidence")
    return {
        "risk": proposal["risk"],
        "confidence": confidence,
        "evidence": {"trust": min_trust, "count": len(refs)},
        "agent": {"trust": agent.get("trust", 0.0)},
    }


def _evaluate_policy(policy: dict[str, Any], proposal: dict[str, Any], ctx: dict[str, Any], human_approved: bool) -> tuple[bool, list[str]]:
    allowed = False
    reasons: list[str] = []
    for rule in policy.get("rules", []):
        if rule == "deny by default":
            reasons.append("default-deny")
            continue
        if rule == "allow all":
            allowed = True
            reasons.append("allow-all")
            continue
        if rule.startswith("allow ") or rule.startswith("deny "):
            effect, rest = rule.split(" ", 1)
            capability, sep, expr = rest.partition(" when ")
            if not sep:
                raise AegisRuntimeError(f"unsupported policy rule '{rule}'")
            if capability == proposal["capability"] and bool(_eval_expr(expr, ctx)):
                if effect == "deny":
                    return False, reasons + [f"deny:{capability}"]
                allowed = True
                reasons.append(f"allow:{capability}")
            continue
        if rule.startswith("require human when "):
            expr = rule[len("require human when "):]
            if bool(_eval_expr(expr, ctx)):
                if not human_approved:
                    return False, reasons + ["human-approval-required"]
                reasons.append("human-approved")
            continue
        raise AegisRuntimeError(f"unsupported policy rule '{rule}'")
    return allowed, reasons


def _validate_placement(spec: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    actual = context.get("placements", {}).get(spec["target"])
    if not isinstance(actual, dict):
        raise AegisRuntimeError(f"placement telemetry for '{spec['target']}' is required")
    failures: list[str] = []
    if actual.get("environment") != spec["environment"]:
        failures.append(f"environment={actual.get('environment')!r} expected {spec['environment']!r}")
    if spec.get("region") and actual.get("region") != spec["region"]:
        failures.append(f"region={actual.get('region')!r} expected {spec['region']!r}")
    if spec.get("data_residency") and actual.get("data_residency") != spec["data_residency"]:
        failures.append(f"data_residency={actual.get('data_residency')!r} expected {spec['data_residency']!r}")
    if spec.get("network") and actual.get("network") != spec["network"]:
        failures.append(f"network={actual.get('network')!r} expected {spec['network']!r}")
    if spec.get("max_latency_ms") is not None:
        latency = actual.get("latency_ms")
        if latency is None or float(latency) > float(spec["max_latency_ms"]):
            failures.append(f"latency_ms={latency!r} exceeds {spec['max_latency_ms']}")
    return {"target": spec["target"], "passed": not failures, "failures": failures, "actual": actual}


def verify_audit_document(doc: dict[str, Any], trusted_anchor_keys: dict[str, Ed25519PublicKey] | None = None, *, require_anchor: bool = False) -> tuple[bool, bool | None]:
    ledger = ProvenanceLedger(doc.get("entries", []))
    chain_valid = ledger.verify()
    anchor = doc.get("anchor")
    if anchor is None:
        return chain_valid and not require_anchor, None
    if anchor.get("root_hash") != ledger.root_hash:
        return False, False
    if trusted_anchor_keys is None:
        return (chain_valid and not require_anchor), None
    anchor_valid = verify_provenance_anchor(anchor, trusted_anchor_keys)
    return chain_valid and anchor_valid, anchor_valid


def run_air(
    air: dict[str, Any],
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
    if air.get("air_version") not in {"0.3", "0.4"}:
        raise AegisRuntimeError(f"runtime requires AIR 0.3 or 0.4, got {air.get('air_version')!r}")
    context = context or {}
    adapters = adapters or {}
    twin_connectors = twin_connectors or {}
    credential_signers = credential_signers or {}
    trusted = dict(trusted_issuers or {})
    for issuer, signer in credential_signers.items():
        trusted.setdefault(issuer, signer.private_key.public_key())

    fixed_now = None if now is None else int(now)
    def clock() -> int:
        return int(time.time()) if fixed_now is None else fixed_now

    ledger = ProvenanceLedger()
    result = RunResult()

    def index(opname: str) -> dict[str, dict[str, Any]]:
        return {op["name"]: op for op in air["ops"] if op.get("op") == opname and "name" in op}

    policies = index("policy.declare")
    evidence = index("evidence.declare")
    agents = index("ai.agent")
    proposals = index("ai.proposal")
    actions = index("action.declare")
    adapters_decl = index("effect.adapter")
    connector_decl = index("twin.connector")
    twins = index("twin.declare")
    issued_authorities: dict[str, tuple[str, str]] = {}
    authorized: set[str] = set()
    validated: set[str] = set()

    for ev in evidence.values():
        ledger.append("evidence.register", {
            "name": ev["name"], "source": ev["source"], "trust": ev["trust"],
            "value_sha256": hashlib.sha256(_canonical(ev.get("value"))).hexdigest(),
        }, clock())

    for op in air["ops"]:
        kind = op.get("op")

        if kind == "deployment.placement":
            decision = _validate_placement(op, context)
            result.placements.append(decision)
            ledger.append("deployment.placement", decision, clock())
            if not decision["passed"]:
                raise AegisRuntimeError(f"placement constraints failed for '{op['target']}': {', '.join(decision['failures'])}")

        elif kind == "auth.authorize":
            proposal = proposals[op["proposal"]]
            policy = policies[op["policy"]]
            agent_obj = agents[proposal["agent"]]
            pctx = _proposal_context(proposal, evidence, agent_obj, context)
            for guard in proposal.get("guards", []):
                if not bool(_eval_expr(guard, pctx)):
                    ledger.append("authorization.denied", {"proposal": proposal["name"], "policy": policy["name"], "reason": f"guard-failed:{guard}"}, clock())
                    raise AegisRuntimeError(f"proposal '{proposal['name']}' guard failed: {guard}")
            approvals = context.get("approvals", {})
            human_approved = bool(approvals.get(proposal["name"], context.get("human_approved", False)))
            allowed, reasons = _evaluate_policy(policy, proposal, pctx, human_approved)
            decision = {"proposal": proposal["name"], "policy": policy["name"], "allowed": allowed, "reasons": reasons}
            result.authorizations.append(decision)
            ledger.append("authorization.decision", decision, clock())
            if not allowed:
                raise AegisRuntimeError(f"policy '{policy['name']}' denied proposal '{proposal['name']}'")
            authorized.add(proposal["name"])

        elif kind == "capability.token":
            key = _require_key(runtime_key)
            token = issue_capability_token(op["name"], op["agent"], op["capability"], int(op["ttl_seconds"]), key, clock())
            issued_authorities[op["name"]] = ("hmac", token)
            ledger.append("capability.token.issued", {
                "name": op["name"], "agent": op["agent"], "capability": op["capability"],
                "ttl_seconds": op["ttl_seconds"], "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            }, clock())

        elif kind == "capability.credential":
            signer = credential_signers.get(op["issuer"])
            if signer is None:
                raise AegisRuntimeError(f"no Ed25519 signer configured for credential issuer '{op['issuer']}'")
            try:
                credential = issue_capability_credential(op["name"], op["agent"], op["capability"], int(op["ttl_seconds"]), signer, now=clock())
            except CredentialError as exc:
                raise AegisRuntimeError(str(exc)) from exc
            issued_authorities[op["name"]] = ("ed25519", credential)
            ledger.append("capability.credential.issued", {
                "name": op["name"], "agent": op["agent"], "capability": op["capability"], "issuer": op["issuer"],
                "ttl_seconds": op["ttl_seconds"], "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
            }, clock())

        elif kind == "twin.validate":
            action_obj = actions[op["action"]]
            twin = twins[op["twin"]]
            connector_name = twin.get("connector")
            if connector_name:
                decl = connector_decl.get(connector_name)
                if decl is None:
                    raise AegisRuntimeError(f"digital twin '{twin['name']}' references unavailable connector '{connector_name}'")
                conn = twin_connectors.get(connector_name)
                if conn is None:
                    if decl["transport"] == "context":
                        conn = ContextTwinConnector()
                    elif decl["transport"] == "https":
                        if not allow_remote_twin:
                            raise AegisRuntimeError(f"remote twin connector '{connector_name}' requires explicit allow_remote_twin")
                        conn = HttpJsonTwinConnector(decl["endpoint"], int(decl["timeout_ms"]))
                metrics = dict(conn.metrics(twin, action_obj, context))
            else:
                metrics = dict(context.get("twins", {}).get(twin["name"], {}))
            metrics["twin"] = dict(metrics)
            failures = [g for g in twin.get("guards", []) if not bool(_eval_expr(g, metrics))]
            decision = {"action": action_obj["name"], "twin": twin["name"], "connector": connector_name, "passed": not failures, "failed_guards": failures}
            result.validations.append(decision)
            ledger.append("twin.validation", decision, clock())
            if failures:
                raise AegisRuntimeError(f"digital twin '{twin['name']}' rejected action '{action_obj['name']}': {', '.join(failures)}")
            validated.add(action_obj["name"])

        elif kind == "action.execute":
            action_obj = actions[op["action"]]
            proposal = proposals[action_obj["proposal"]]
            if proposal["name"] not in authorized:
                raise AegisRuntimeError(f"action '{action_obj['name']}' has no successful runtime authorization")
            if action_obj["name"] not in validated:
                raise AegisRuntimeError(f"action '{action_obj['name']}' has no successful digital-twin validation")

            authority = issued_authorities.get(op["token"])
            if authority is None:
                raise AegisRuntimeError(f"capability token or credential '{op['token']}' has not been issued")
            auth_kind, auth_value = authority
            try:
                if auth_kind == "hmac":
                    payload = verify_capability_token(auth_value, _require_key(runtime_key), now=clock(), agent=proposal["agent"], capability=action_obj["capability"])
                else:
                    payload = verify_capability_credential(auth_value, trusted, now=clock(), agent=proposal["agent"], capability=action_obj["capability"])
            except CredentialError as exc:
                raise AegisRuntimeError(str(exc)) from exc

            adapter_name = op.get("adapter")
            if adapter_name:
                decl = adapters_decl[adapter_name]
                selected = adapters.get(adapter_name)
                if selected is None:
                    if decl["mode"] == "external":
                        raise AegisRuntimeError(f"external effect adapter '{adapter_name}' is not configured")
                    selected = NoOpAdapter()
                supported = getattr(selected, "supported_effects", {"*"})
                if "*" not in supported and action_obj["effect"] not in supported:
                    raise AegisRuntimeError(f"runtime adapter '{adapter_name}' does not support effect '{action_obj['effect']}'")
                if action_obj["effect"] not in decl["effects"]:
                    raise AegisRuntimeError(f"declared adapter '{adapter_name}' is not authorized for effect '{action_obj['effect']}'")
            else:
                selected = adapter or NoOpAdapter()
                adapter_name = selected.__class__.__name__

            execution = selected.execute(action_obj, context)
            record = {
                "action": action_obj["name"], "proposal": proposal["name"], "effect": action_obj["effect"],
                "authority": payload["name"], "authority_type": auth_kind, "adapter": adapter_name, **execution,
            }
            result.executions.append(record)
            ledger.append("action.executed", record, clock())

    result.provenance = ledger.entries
    if provenance_signer is not None:
        result.provenance_anchor = sign_provenance_anchor(ledger.root_hash, provenance_signer, timestamp=clock())
    return result
