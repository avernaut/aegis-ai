from __future__ import annotations
import ast
import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol


class AegisRuntimeError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _require_key(key: bytes) -> None:
    if len(key) < 16:
        raise AegisRuntimeError("runtime key must contain at least 16 bytes")


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
    def execute(self, action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...


class NoOpAdapter:
    """Safe default adapter: records the action but performs no external side effect."""
    def execute(self, action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return {"mode": "simulation", "status": "executed", "action": action["name"], "effect": action["effect"]}


@dataclass
class RunResult:
    authorizations: list[dict[str, Any]] = field(default_factory=list)
    validations: list[dict[str, Any]] = field(default_factory=list)
    executions: list[dict[str, Any]] = field(default_factory=list)
    provenance: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "authorizations": self.authorizations,
            "validations": self.validations,
            "executions": self.executions,
            "provenance": self.provenance,
            "provenance_valid": ProvenanceLedger(self.provenance).verify(),
        }


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
    allowed = False  # security-first default deny
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


def run_air(air: dict[str, Any], *, context: dict[str, Any] | None = None, runtime_key: bytes, adapter: EffectAdapter | None = None, now: int | None = None) -> RunResult:
    if air.get("air_version") != "0.3":
        raise AegisRuntimeError(f"runtime requires AIR 0.3, got {air.get('air_version')!r}")
    _require_key(runtime_key)
    context = context or {}
    adapter = adapter or NoOpAdapter()
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
    twins = index("twin.declare")
    issued_tokens: dict[str, str] = {}
    authorized: set[str] = set()
    validated: set[str] = set()

    for ev in evidence.values():
        ledger.append("evidence.register", {
            "name": ev["name"], "source": ev["source"], "trust": ev["trust"],
            "value_sha256": hashlib.sha256(_canonical(ev.get("value"))).hexdigest(),
        }, clock())

    for op in air["ops"]:
        kind = op.get("op")
        if kind == "auth.authorize":
            proposal = proposals[op["proposal"]]
            policy = policies[op["policy"]]
            agent = agents[proposal["agent"]]
            pctx = _proposal_context(proposal, evidence, agent, context)
            for guard in proposal.get("guards", []):
                if not bool(_eval_expr(guard, pctx)):
                    ledger.append("authorization.denied", {"proposal": proposal["name"], "policy": policy["name"], "reason": f"guard-failed:{guard}"}, clock())
                    raise AegisRuntimeError(f"proposal '{proposal['name']}' guard failed: {guard}")
            approvals = context.get("approvals", {})
            human_approved = bool(approvals.get(proposal["name"], context.get("human_approved", False)))
            allowed, reasons = _evaluate_policy(policy, proposal, pctx, human_approved)
            decision = {"proposal": proposal["name"], "policy": policy["name"], "allowed": allowed, "reasons": reasons}
            result.authorizations.append(decision)
            ledger.append("authorization.decision", decision, fixed_now)
            if not allowed:
                raise AegisRuntimeError(f"policy '{policy['name']}' denied proposal '{proposal['name']}'")
            authorized.add(proposal["name"])

        elif kind == "capability.token":
            token = issue_capability_token(op["name"], op["agent"], op["capability"], int(op["ttl_seconds"]), runtime_key, clock())
            issued_tokens[op["name"]] = token
            ledger.append("capability.token.issued", {
                "name": op["name"], "agent": op["agent"], "capability": op["capability"],
                "ttl_seconds": op["ttl_seconds"], "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            }, clock())

        elif kind == "twin.validate":
            action = actions[op["action"]]
            twin = twins[op["twin"]]
            metrics = dict(context.get("twins", {}).get(twin["name"], {}))
            metrics["twin"] = dict(metrics)
            failures = [g for g in twin.get("guards", []) if not bool(_eval_expr(g, metrics))]
            decision = {"action": action["name"], "twin": twin["name"], "passed": not failures, "failed_guards": failures}
            result.validations.append(decision)
            ledger.append("twin.validation", decision, fixed_now)
            if failures:
                raise AegisRuntimeError(f"digital twin '{twin['name']}' rejected action '{action['name']}': {', '.join(failures)}")
            validated.add(action["name"])

        elif kind == "action.execute":
            action = actions[op["action"]]
            proposal = proposals[action["proposal"]]
            if proposal["name"] not in authorized:
                raise AegisRuntimeError(f"action '{action['name']}' has no successful runtime authorization")
            if action["name"] not in validated:
                raise AegisRuntimeError(f"action '{action['name']}' has no successful digital-twin validation")
            token = issued_tokens.get(op["token"])
            if token is None:
                raise AegisRuntimeError(f"capability token '{op['token']}' has not been issued")
            payload = verify_capability_token(token, runtime_key, now=clock(), agent=proposal["agent"], capability=action["capability"])
            execution = adapter.execute(action, context)
            record = {"action": action["name"], "proposal": proposal["name"], "effect": action["effect"], "token": payload["name"], **execution}
            result.executions.append(record)
            ledger.append("action.executed", record, fixed_now)

    result.provenance = ledger.entries
    return result
