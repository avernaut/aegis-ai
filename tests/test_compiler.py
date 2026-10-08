import json
import pytest
from aegisai import compile_source, __version__
from aegisai.checker import SecurityError


def test_version_is_0_3():
    assert __version__ == "0.3.0"


def test_public_program_compiles_to_python():
    src = 'data<string, public> msg = "hello"\nprint(msg)\n'
    out = compile_source(src, "python")
    assert "msg = 'hello'" in out
    assert "print(msg)" in out


def test_secret_cannot_flow_to_print():
    src = 'data<string, secret> token = "x"\nprint(token)\n'
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "cannot flow to public output" in str(e.value)


def test_tainted_value_must_be_sanitized_before_print():
    src = 'tainted<string> prompt = "x" source "user"\nprint(prompt)\n'
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "before sanitization" in str(e.value)


def test_sanitized_tainted_value_can_print():
    src = 'tainted<string> prompt = "x" source "user"\nsanitize prompt as safe_prompt\nprint(safe_prompt)\n'
    out = compile_source(src)
    assert "safe_prompt = prompt" in out


def test_undeclared_effect_rejected():
    src = '''
fn inspect(flow) risk low {
    effects [read.network]
    effect write.firewall
}
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "undeclared effect 'write.firewall'" in str(e.value)


def test_high_risk_requires_guard():
    src = '''
fn isolate(host) risk critical {
    effects [write.firewall]
    effect write.firewall
}
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "requires at least one explicit guard" in str(e.value)


def test_agent_rejects_unknown_model():
    src = '''
agent Sentinel {
    uses MissingModel
    capabilities [read.telemetry]
    trust 0.9
}
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "unknown model 'MissingModel'" in str(e.value)


def test_capability_denial_blocks_proposal():
    src = '''
model CyberFM { 
    capabilities [reason]
    trust 1.0
}
agent Sentinel {
    uses CyberFM
    capabilities [read.telemetry]
    deny [propose.firewall]
    trust 1.0
}
evidence ioc = "ip" trust 1.0 source "intel"
proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [ioc]
    min_trust 0.9
    require confidence > 0.95
    effect write.firewall
}
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "denied to agent 'Sentinel'" in str(e.value)


def test_trust_threshold_blocks_weak_evidence():
    src = '''
model CyberFM {
    capabilities [reason]
    trust 1.0
}
agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    trust 1.0
}
evidence weak = "ip" trust 0.4 source "unknown"
proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [weak]
    min_trust 0.9
    require confidence > 0.95
    effect write.firewall
}
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "below proposal 'BlockHost' minimum" in str(e.value)


def test_high_risk_proposal_requires_evidence():
    src = '''
model CyberFM {
    capabilities [reason]
    trust 1.0
}
agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    trust 1.0
}
proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    min_trust 0.9
    require confidence > 0.95
    effect write.firewall
}
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "requires explicit evidence" in str(e.value)


def test_action_requires_authorization():
    src = '''
model CyberFM {
    capabilities [reason]
    trust 1.0
}
agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    trust 1.0
}
evidence ioc = "ip" trust 1.0 source "intel"
proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [ioc]
    min_trust 0.9
    require confidence > 0.95
    effect write.firewall
}
action Quarantine from BlockHost effect write.firewall capability propose.firewall reversible
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "without authorization" in str(e.value)


def test_secure_transaction_requires_reversible_rollback():
    src = '''
model CyberFM {
    capabilities [reason]
    trust 1.0
}
agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    trust 1.0
}
evidence ioc = "ip" trust 1.0 source "intel"
policy P {
    allow all
}
proposal BlockHost risk high {
    by Sentinel
    capability propose.firewall
    evidence [ioc]
    min_trust 0.9
    require confidence > 0.95
    effect write.firewall
}
authorize BlockHost using P
action Quarantine from BlockHost effect write.firewall capability propose.firewall
secure transaction T {
    action Quarantine
    rollback Quarantine
}
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "cannot rollback non-reversible action 'Quarantine'" in str(e.value)


def test_full_bounded_defense_program_compiles_to_air():
    src = open("examples/bounded_defense.aegis", encoding="utf-8").read()
    air = json.loads(compile_source(src, "air"))
    assert air["air_version"] == "0.3"
    ops = {op["op"] for op in air["ops"]}
    assert {"capability.declare", "ai.model", "ai.agent", "evidence.declare", "ai.proposal", "auth.authorize", "action.declare", "capability.token", "twin.declare", "twin.validate", "action.execute", "intent.declare", "sequence.declare", "transaction.secure"} <= ops


def test_air_keeps_trust_and_capability_metadata():
    src = open("examples/bounded_defense.aegis", encoding="utf-8").read()
    air = json.loads(compile_source(src, "air"))
    proposal = next(op for op in air["ops"] if op["op"] == "ai.proposal")
    assert proposal["min_trust"] == 0.95
    assert proposal["capability"] == "propose.firewall"


def test_capability_decl_limits_proposal_effects():
    src = '''
capability propose.firewall {
    effects [write.firewall]
    risk high
}
model CyberFM {
    capabilities [reason]
    trust 1.0
}
agent Sentinel {
    uses CyberFM
    capabilities [propose.firewall]
    trust 1.0
}
evidence ioc = "ip" trust 1.0 source "intel"
proposal BadProposal risk high {
    by Sentinel
    capability propose.firewall
    evidence [ioc]
    min_trust 0.9
    require confidence > 0.95
    effect write.identity
}
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "exceeds capability 'propose.firewall' effect set" in str(e.value)


def test_v03_air_carries_confidence_and_runtime_ops():
    src = open("examples/bounded_defense.aegis", encoding="utf-8").read()
    air = json.loads(compile_source(src, "air"))
    proposal = next(op for op in air["ops"] if op["op"] == "ai.proposal")
    token = next(op for op in air["ops"] if op["op"] == "capability.token")
    assert proposal["confidence"] == 0.99
    assert token["ttl_seconds"] == 300
    assert any(op["op"] == "twin.validate" for op in air["ops"])
    assert any(op["op"] == "action.execute" for op in air["ops"])


def test_execute_requires_prior_twin_validation():
    src = '''
capability propose.firewall {
    effects [write.firewall]
    risk high
}
model M {
    capabilities [reason]
    trust 1.0
}
agent A {
    uses M
    capabilities [propose.firewall]
    trust 1.0
}
evidence ev = "x" trust 1.0 source "s"
policy P {
    allow all
}
proposal Q risk high {
    by A
    capability propose.firewall
    evidence [ev]
    min_trust 0.9
    confidence 1.0
    require confidence > 0.9
    effect write.firewall
}
authorize Q using P
action Act from Q effect write.firewall capability propose.firewall reversible
token T for A capability propose.firewall ttl 60
execute Act using T
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "must pass an explicit twin validation" in str(e.value)


def test_execute_rejects_token_capability_mismatch():
    src = '''
capability propose.firewall {
    effects [write.firewall]
    risk high
}
capability read.telemetry {
    effects [read.telemetry]
    risk low
}
model M {
    capabilities [reason]
    trust 1.0
}
agent A {
    uses M
    capabilities [propose.firewall, read.telemetry]
    trust 1.0
}
evidence ev = "x" trust 1.0 source "s"
policy P {
    allow all
}
proposal Q risk high {
    by A
    capability propose.firewall
    evidence [ev]
    min_trust 0.9
    confidence 1.0
    require confidence > 0.9
    effect write.firewall
}
authorize Q using P
action Act from Q effect write.firewall capability propose.firewall reversible
token T for A capability read.telemetry ttl 60
twin Twin {
    target production
    require loss < 0.1
}
validate Act with Twin
execute Act using T
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "does not match action capability" in str(e.value)


def test_token_ttl_is_bounded():
    src = '''
capability read.telemetry {
    effects [read.telemetry]
    risk low
}
model M {
    capabilities [reason]
    trust 1.0
}
agent A {
    uses M
    capabilities [read.telemetry]
    trust 1.0
}
token T for A capability read.telemetry ttl 999999
'''
    with pytest.raises(SecurityError) as e:
        compile_source(src)
    assert "ttl must be between 1 and 86400" in str(e.value)


def test_runtime_executes_only_after_policy_and_twin_validation():
    from aegisai import run_source
    src = open("examples/bounded_defense.aegis", encoding="utf-8").read()
    ctx = json.load(open("examples/runtime_context.json", encoding="utf-8"))
    result = run_source(src, context=ctx, runtime_key=b"0123456789abcdef0123456789abcdef", now=1700000000)
    doc = result.to_dict()
    assert doc["status"] == "ok"
    assert doc["authorizations"][0]["allowed"] is True
    assert doc["validations"][0]["passed"] is True
    assert doc["executions"][0]["mode"] == "simulation"
    assert doc["provenance_valid"] is True


def test_runtime_twin_rejection_blocks_execution():
    from aegisai import run_source
    from aegisai.runtime import AegisRuntimeError
    src = open("examples/bounded_defense.aegis", encoding="utf-8").read()
    ctx = json.load(open("examples/twin_violation_context.json", encoding="utf-8"))
    with pytest.raises(AegisRuntimeError) as e:
        run_source(src, context=ctx, runtime_key=b"0123456789abcdef0123456789abcdef", now=1700000000)
    assert "digital twin 'EdgeTwin' rejected" in str(e.value)


def test_critical_policy_requires_human_approval():
    from aegisai import run_source
    from aegisai.runtime import AegisRuntimeError
    src = open("examples/critical_human_approval.aegis", encoding="utf-8").read()
    ctx = json.load(open("examples/critical_context.json", encoding="utf-8"))
    ctx["approvals"]["DisableAccount"] = False
    with pytest.raises(AegisRuntimeError) as e:
        run_source(src, context=ctx, runtime_key=b"0123456789abcdef0123456789abcdef", now=1700000000)
    assert "denied proposal 'DisableAccount'" in str(e.value)


def test_critical_policy_runs_with_human_approval():
    from aegisai import run_source
    src = open("examples/critical_human_approval.aegis", encoding="utf-8").read()
    ctx = json.load(open("examples/critical_context.json", encoding="utf-8"))
    result = run_source(src, context=ctx, runtime_key=b"0123456789abcdef0123456789abcdef", now=1700000000)
    assert result.executions[0]["action"] == "DisableIdentity"


def test_capability_token_detects_tampering_and_expiry():
    from aegisai.runtime import issue_capability_token, verify_capability_token, AegisRuntimeError
    key = b"0123456789abcdef0123456789abcdef"
    token = issue_capability_token("T", "A", "propose.firewall", 10, key, now=100)
    payload = verify_capability_token(token, key, now=105, agent="A", capability="propose.firewall")
    assert payload["name"] == "T"
    body, sig = token.split(".")
    bad = body + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(AegisRuntimeError):
        verify_capability_token(bad, key, now=105)
    with pytest.raises(AegisRuntimeError) as e:
        verify_capability_token(token, key, now=111)
    assert "expired" in str(e.value)


def test_provenance_hash_chain_detects_tampering():
    from aegisai.runtime import ProvenanceLedger
    ledger = ProvenanceLedger()
    ledger.append("one", {"x": 1}, timestamp=1)
    ledger.append("two", {"x": 2}, timestamp=2)
    assert ledger.verify() is True
    ledger.entries[0]["payload"]["x"] = 999
    assert ledger.verify() is False


def test_generated_python_embeds_air_03_runtime_boundary():
    src = open("examples/bounded_defense.aegis", encoding="utf-8").read()
    out = compile_source(src, "python")
    assert "Generated by AegisAI compiler v0.3" in out
    assert "AEGIS_AIR" in out
    assert "AEGIS_RUNTIME_KEY" in out
    assert "run_air" in out
