from __future__ import annotations
import ast as pyast
import re
from .ast import *
from .lexer import logical_lines

class ParseError(Exception):
    pass

IDENT = r"[A-Za-z_]\w*"
CAP = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
DATA_RE = re.compile(rf'^data<(?P<type>{IDENT}),\s*(?P<sec>public|confidential|secret)>\s+(?P<name>{IDENT})\s*=\s*(?P<value>.+)$')
SECRET_RE = re.compile(rf'^secret\s+(?P<name>{IDENT})\s*=\s*(?P<value>.+)$')
TAINT_RE = re.compile(rf'^tainted<(?P<type>{IDENT})>\s+(?P<name>{IDENT})\s*=\s*(?P<value>.+?)(?:\s+source\s+(?P<source>.+))?$')
SANITIZE_RE = re.compile(rf'^sanitize\s+(?P<src>{IDENT})\s+as\s+(?P<dst>{IDENT})$')
EVIDENCE_RE = re.compile(rf'^evidence\s+(?P<name>{IDENT})\s*=\s*(?P<value>.+?)\s+trust\s+(?P<trust>\d+(?:\.\d+)?)\s+source\s+(?P<source>.+)$')
FN_RE = re.compile(rf'^fn\s+(?P<name>{IDENT})\((?P<params>[^)]*)\)\s+risk\s+(?P<risk>low|medium|high|critical)\s*\{{$')
POLICY_RE = re.compile(rf'^policy\s+(?P<name>{IDENT})\s*\{{$')
CAPABILITY_RE = re.compile(rf'^capability\s+(?P<name>{CAP})\s*\{{$')
MODEL_RE = re.compile(rf'^model\s+(?P<name>{IDENT})\s*\{{$')
AGENT_RE = re.compile(rf'^agent\s+(?P<name>{IDENT})\s*\{{$')
PROPOSAL_RE = re.compile(rf'^proposal\s+(?P<name>{IDENT})\s+risk\s+(?P<risk>low|medium|high|critical)\s*\{{$')
AUTHORIZE_RE = re.compile(rf'^authorize\s+(?P<proposal>{IDENT})\s+using\s+(?P<policy>{IDENT})$')
TOKEN_RE = re.compile(rf'^token\s+(?P<name>{IDENT})\s+for\s+(?P<agent>{IDENT})\s+capability\s+(?P<cap>{CAP})\s+ttl\s+(?P<ttl>\d+)(?:s)?$')
CREDENTIAL_RE = re.compile(rf'^credential\s+(?P<name>{IDENT})\s+for\s+(?P<agent>{IDENT})\s+capability\s+(?P<cap>{CAP})\s+ttl\s+(?P<ttl>\d+)(?:s)?\s+issuer\s+(?P<issuer>.+)$')
ADAPTER_RE = re.compile(rf'^adapter\s+(?P<name>{IDENT})\s*\{{$')
TWIN_CONNECTOR_RE = re.compile(rf'^twin_connector\s+(?P<name>{IDENT})\s*\{{$')
ACTION_RE = re.compile(rf'^action\s+(?P<name>{IDENT})\s+from\s+(?P<proposal>{IDENT})\s+effect\s+(?P<effect>{CAP})\s+capability\s+(?P<cap>{CAP})(?P<rev>\s+reversible)?$')
TWIN_RE = re.compile(rf'^twin\s+(?P<name>{IDENT})\s*\{{$')
VALIDATE_RE = re.compile(rf'^validate\s+(?P<action>{IDENT})\s+with\s+(?P<twin>{IDENT})$')
EXECUTE_RE = re.compile(rf'^execute\s+(?P<action>{IDENT})\s+using\s+(?P<token>{IDENT})(?:\s+via\s+(?P<adapter>{IDENT}))?$')
PLACEMENT_RE = re.compile(rf'^placement\s+(?P<target>{IDENT})\s+at\s+(?P<environment>cloud|edge|5g|onprem)\s*\{{$')
INTENT_RE = re.compile(rf'^intent\s+(?P<name>{IDENT})\s*\{{$')
SEQUENCE_RE = re.compile(rf'^sequence\s+(?P<name>{IDENT})\s*\{{$')
TRANSACTION_RE = re.compile(rf'^secure\s+transaction\s+(?P<name>{IDENT})\s*\{{$')
CALL_RE = re.compile(rf'^call\s+(?P<name>{IDENT})\((?P<args>.*)\)$')


def _literal(text: str):
    text = text.strip()
    try:
        return pyast.literal_eval(text)
    except Exception:
        if text in {"true", "false"}:
            return text == "true"
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return text


def _list(raw: str) -> list[str]:
    raw = raw.strip().strip("[]")
    return [x.strip() for x in raw.split(",") if x.strip()]


def _bounded_trust(value: str, line: int) -> float:
    trust = float(value)
    if not 0.0 <= trust <= 1.0:
        raise ParseError(f"line {line}: trust must be between 0.0 and 1.0")
    return trust


def parse(source: str) -> Program:
    lines = logical_lines(source)
    program = Program(line=1, statements=[])
    i = 0
    while i < len(lines):
        sl = lines[i]
        line = sl.text.rstrip(';')

        for regex, factory in [
            (DATA_RE, lambda m: DataDecl(sl.number, m['name'], m['type'], m['sec'], _literal(m['value']))),
            (SECRET_RE, lambda m: SecretDecl(sl.number, m['name'], str(_literal(m['value'])))),
            (TAINT_RE, lambda m: TaintedDecl(sl.number, m['name'], m['type'], _literal(m['value']), str(_literal(m['source'])) if m['source'] else "external")),
        ]:
            m = regex.match(line)
            if m:
                program.statements.append(factory(m)); i += 1; break
        else:
            m = EVIDENCE_RE.match(line)
            if m:
                program.statements.append(EvidenceDecl(sl.number, m['name'], _literal(m['value']), _bounded_trust(m['trust'], sl.number), str(_literal(m['source']))))
                i += 1; continue
            m = SANITIZE_RE.match(line)
            if m:
                program.statements.append(SanitizeStmt(sl.number, m['src'], m['dst']))
                i += 1; continue
            if line.startswith("print(") and line.endswith(")"):
                program.statements.append(PrintStmt(sl.number, line[6:-1].strip())); i += 1; continue
            if line.startswith("require "):
                program.statements.append(RequireStmt(sl.number, line[len("require "):].strip())); i += 1; continue
            m = FN_RE.match(line)
            if m:
                body, effects, i = _parse_function(lines, i)
                params = [p.strip() for p in m['params'].split(',') if p.strip()]
                program.statements.append(FunctionDecl(sl.number, m['name'], params, effects, m['risk'], body)); continue
            m = POLICY_RE.match(line)
            if m:
                body, i = _simple_block(lines, i, "policy")
                program.statements.append(PolicyDecl(sl.number, m['name'], body)); continue
            m = CAPABILITY_RE.match(line)
            if m:
                program.statements.append(_parse_capability(lines, i, m['name'])); i = _block_end(lines, i); continue
            m = MODEL_RE.match(line)
            if m:
                program.statements.append(_parse_model(lines, i, m['name'])); i = _block_end(lines, i); continue
            m = AGENT_RE.match(line)
            if m:
                program.statements.append(_parse_agent(lines, i, m['name'])); i = _block_end(lines, i); continue
            m = PROPOSAL_RE.match(line)
            if m:
                program.statements.append(_parse_proposal(lines, i, m['name'], m['risk'])); i = _block_end(lines, i); continue
            m = AUTHORIZE_RE.match(line)
            if m:
                program.statements.append(AuthorizeStmt(sl.number, m['proposal'], m['policy'])); i += 1; continue
            m = ACTION_RE.match(line)
            if m:
                program.statements.append(ActionDecl(sl.number, m['name'], m['proposal'], m['cap'], m['effect'], bool(m['rev']))); i += 1; continue
            m = TOKEN_RE.match(line)
            if m:
                program.statements.append(TokenDecl(sl.number, m['name'], m['agent'], m['cap'], int(m['ttl']))); i += 1; continue
            m = CREDENTIAL_RE.match(line)
            if m:
                program.statements.append(CredentialDecl(sl.number, m['name'], m['agent'], m['cap'], int(m['ttl']), str(_literal(m['issuer'])))); i += 1; continue
            m = ADAPTER_RE.match(line)
            if m:
                program.statements.append(_parse_adapter(lines, i, m['name'])); i = _block_end(lines, i); continue
            m = TWIN_CONNECTOR_RE.match(line)
            if m:
                program.statements.append(_parse_twin_connector(lines, i, m['name'])); i = _block_end(lines, i); continue
            m = TWIN_RE.match(line)
            if m:
                program.statements.append(_parse_twin(lines, i, m['name'])); i = _block_end(lines, i); continue
            m = VALIDATE_RE.match(line)
            if m:
                program.statements.append(TwinValidateStmt(sl.number, m['action'], m['twin'])); i += 1; continue
            m = EXECUTE_RE.match(line)
            if m:
                program.statements.append(ExecuteStmt(sl.number, m['action'], m['token'], m['adapter'])); i += 1; continue
            m = PLACEMENT_RE.match(line)
            if m:
                program.statements.append(_parse_placement(lines, i, m['target'], m['environment'])); i = _block_end(lines, i); continue
            m = INTENT_RE.match(line)
            if m:
                program.statements.append(_parse_intent(lines, i, m['name'])); i = _block_end(lines, i); continue
            m = SEQUENCE_RE.match(line)
            if m:
                body, i = _simple_block(lines, i, "sequence")
                program.statements.append(SequenceDecl(sl.number, m['name'], body)); continue
            m = TRANSACTION_RE.match(line)
            if m:
                program.statements.append(_parse_transaction(lines, i, m['name'])); i = _block_end(lines, i); continue
            m = CALL_RE.match(line)
            if m:
                program.statements.append(CallStmt(sl.number, m['name'], _list(m['args']))); i += 1; continue
            raise ParseError(f"line {sl.number}: cannot parse: {sl.text}")
            continue
        continue
    return program


def _block_end(lines, start: int) -> int:
    i = start + 1
    depth = 1
    while i < len(lines):
        text = lines[i].text.rstrip(';')
        if text.endswith("{"): depth += 1
        if text == "}":
            depth -= 1
            if depth == 0: return i + 1
        i += 1
    raise ParseError(f"line {lines[start].number}: unterminated block")


def _simple_block(lines, start: int, label: str) -> tuple[list[str], int]:
    body: list[str] = []
    i = start + 1
    while i < len(lines):
        text = lines[i].text.rstrip(';')
        if text == "}": return body, i + 1
        body.append(text); i += 1
    raise ParseError(f"line {lines[start].number}: unterminated {label}")


def _parse_function(lines, start):
    body: list[Node] = []
    effects: set[str] = set()
    i = start + 1
    while i < len(lines):
        sl = lines[i]; line = sl.text.rstrip(';')
        if line == "}": return body, effects, i + 1
        if line.startswith("effects "):
            effects.update(_list(line[len("effects "):]))
        elif line.startswith("print(") and line.endswith(")"):
            body.append(PrintStmt(sl.number, line[6:-1].strip()))
        elif line.startswith("require "):
            body.append(RequireStmt(sl.number, line[len("require "):].strip()))
        elif line.startswith("effect "):
            body.append(CallStmt(sl.number, "__effect__", [line[len("effect "):].strip()]))
        else:
            raise ParseError(f"line {sl.number}: invalid function statement: {sl.text}")
        i += 1
    raise ParseError(f"line {lines[start].number}: unterminated function")


def _parse_capability(lines, start, name) -> CapabilityDecl:
    effects: set[str] = set(); risk = "low"
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("effects "): effects.update(_list(line[len("effects "):]))
        elif line.startswith("risk "):
            risk = line.split(None, 1)[1].strip()
            if risk not in RISK_LEVELS: raise ParseError(f"line {sl.number}: invalid capability risk: {risk}")
        else: raise ParseError(f"line {sl.number}: invalid capability field: {sl.text}")
    return CapabilityDecl(lines[start].number, name, effects, risk)


def _parse_model(lines, start, name) -> ModelDecl:
    caps: set[str] = set(); trust = 1.0; network = "none"
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("capabilities "): caps.update(_list(line[len("capabilities "):]))
        elif line.startswith("trust "): trust = _bounded_trust(line.split(None, 1)[1], sl.number)
        elif line.startswith("network "): network = line.split(None, 1)[1].strip()
        else: raise ParseError(f"line {sl.number}: invalid model field: {sl.text}")
    return ModelDecl(lines[start].number, name, caps, trust, network)


def _parse_agent(lines, start, name) -> AgentDecl:
    caps: set[str] = set(); denied: set[str] = set(); trust = 1.0; model = None
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("uses "): model = line.split(None, 1)[1].strip()
        elif line.startswith("capabilities "): caps.update(_list(line[len("capabilities "):]))
        elif line.startswith("deny "): denied.update(_list(line[len("deny "):]))
        elif line.startswith("trust "): trust = _bounded_trust(line.split(None, 1)[1], sl.number)
        else: raise ParseError(f"line {sl.number}: invalid agent field: {sl.text}")
    return AgentDecl(lines[start].number, name, model, caps, denied, trust)


def _parse_proposal(lines, start, name, risk) -> ProposalDecl:
    agent = ""; capability = ""; effects: set[str] = set(); guards: list[str] = []; evidence: list[str] = []; min_trust = 0.0; confidence = None
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("by "): agent = line.split(None, 1)[1].strip()
        elif line.startswith("capability "): capability = line.split(None, 1)[1].strip()
        elif line.startswith("effect "): effects.add(line.split(None, 1)[1].strip())
        elif line.startswith("require "): guards.append(line[len("require "):].strip())
        elif line.startswith("evidence "): evidence.extend(_list(line[len("evidence "):]))
        elif line.startswith("min_trust "): min_trust = _bounded_trust(line.split(None, 1)[1], sl.number)
        elif line.startswith("confidence "): confidence = _bounded_trust(line.split(None, 1)[1], sl.number)
        else: raise ParseError(f"line {sl.number}: invalid proposal field: {sl.text}")
    return ProposalDecl(lines[start].number, name, agent, risk, capability, effects, guards, evidence, min_trust, confidence)


def _parse_adapter(lines, start, name) -> AdapterDecl:
    effects: set[str] = set(); mode = "simulation"; trust_zone = "default"
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("effects "): effects.update(_list(line[len("effects "):]))
        elif line.startswith("mode "):
            mode = line.split(None, 1)[1].strip()
            if mode not in {"simulation", "external"}: raise ParseError(f"line {sl.number}: adapter mode must be simulation or external")
        elif line.startswith("trust_zone "): trust_zone = str(_literal(line.split(None, 1)[1].strip()))
        else: raise ParseError(f"line {sl.number}: invalid adapter field: {sl.text}")
    return AdapterDecl(lines[start].number, name, effects, mode, trust_zone)


def _parse_twin_connector(lines, start, name) -> TwinConnectorDecl:
    transport = "context"; endpoint = None; timeout_ms = 2000
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("transport "):
            transport = line.split(None, 1)[1].strip()
            if transport not in {"context", "https"}: raise ParseError(f"line {sl.number}: twin connector transport must be context or https")
        elif line.startswith("endpoint "): endpoint = str(_literal(line.split(None, 1)[1].strip()))
        elif line.startswith("timeout_ms "):
            timeout_ms = int(line.split(None, 1)[1].strip())
        else: raise ParseError(f"line {sl.number}: invalid twin connector field: {sl.text}")
    return TwinConnectorDecl(lines[start].number, name, transport, endpoint, timeout_ms)


def _parse_twin(lines, start, name) -> TwinDecl:
    target = "production"; guards: list[str] = []; connector = None
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("target "): target = line.split(None, 1)[1].strip()
        elif line.startswith("connector "): connector = line.split(None, 1)[1].strip()
        elif line.startswith("require "): guards.append(line[len("require "):].strip())
        else: raise ParseError(f"line {sl.number}: invalid twin field: {sl.text}")
    return TwinDecl(lines[start].number, name, target, guards, connector)


def _parse_placement(lines, start, target, environment) -> PlacementDecl:
    region = None; data_residency = None; max_latency_ms = None; network = None
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("region "): region = str(_literal(line.split(None, 1)[1].strip()))
        elif line.startswith("data_residency "): data_residency = str(_literal(line.split(None, 1)[1].strip()))
        elif line.startswith("max_latency_ms "): max_latency_ms = int(line.split(None, 1)[1].strip())
        elif line.startswith("network "): network = str(_literal(line.split(None, 1)[1].strip()))
        else: raise ParseError(f"line {sl.number}: invalid placement field: {sl.text}")
    return PlacementDecl(lines[start].number, target, environment, region, data_residency, max_latency_ms, network)


def _parse_intent(lines, start, name) -> IntentDecl:
    objectives: list[str] = []; constraints: list[str] = []
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("objective "): objectives.append(line[len("objective "):].strip())
        elif line.startswith("constraint "): constraints.append(line[len("constraint "):].strip())
        else: raise ParseError(f"line {sl.number}: invalid intent field: {sl.text}")
    return IntentDecl(lines[start].number, name, objectives, constraints)


def _parse_transaction(lines, start, name) -> SecureTransactionDecl:
    actions: list[str] = []; rollbacks: list[str] = []
    for sl in lines[start + 1:_block_end(lines, start) - 1]:
        line = sl.text.rstrip(';')
        if line.startswith("action "): actions.append(line.split(None, 1)[1].strip())
        elif line.startswith("rollback "): rollbacks.append(line.split(None, 1)[1].strip())
        else: raise ParseError(f"line {sl.number}: invalid secure transaction field: {sl.text}")
    return SecureTransactionDecl(lines[start].number, name, actions, rollbacks)
