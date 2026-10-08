import json
import pytest
from aegisai import compile_source
from aegisai.checker import SecurityError


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


def test_air_contains_security_metadata():
    src = 'data<string, confidential> telemetry = "x"\n'
    air = json.loads(compile_source(src, "air"))
    assert air["air_version"] == "0.1"
    assert air["ops"][0]["security"] == "confidential"
