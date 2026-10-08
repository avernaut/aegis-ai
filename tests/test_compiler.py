import json
import pytest
from aegisai import compile_source, __version__
from aegisai.checker import SecurityError


def test_version_is_0_2():
    assert __version__ == "0.2.0"


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
    assert air["air_version"] == "0.2"
    ops = {op["op"] for op in air["ops"]}
    assert {"capability.declare", "ai.model", "ai.agent", "evidence.declare", "ai.proposal", "auth.authorize", "action.declare", "twin.declare", "intent.declare", "sequence.declare", "transaction.secure"} <= ops


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
