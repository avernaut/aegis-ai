from __future__ import annotations
import ast as pyast
import re
from .ast import Program, DataDecl, SecretDecl, PrintStmt, RequireStmt, FunctionDecl, PolicyDecl, CallStmt
from .lexer import logical_lines

class ParseError(Exception):
    pass

DATA_RE = re.compile(r'^data<(?P<type>[A-Za-z_]\w*),\s*(?P<sec>public|confidential|secret)>\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<value>.+)$')
SECRET_RE = re.compile(r'^secret\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<value>.+)$')
FN_RE = re.compile(r'^fn\s+(?P<name>[A-Za-z_]\w*)\((?P<params>[^)]*)\)\s+risk\s+(?P<risk>low|medium|high|critical)\s*\{$')
POLICY_RE = re.compile(r'^policy\s+(?P<name>[A-Za-z_]\w*)\s*\{$')
CALL_RE = re.compile(r'^call\s+(?P<name>[A-Za-z_]\w*)\((?P<args>.*)\)$')

def _literal(text: str):
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

def parse(source: str) -> Program:
    lines = logical_lines(source)
    program = Program(line=1, statements=[])
    i = 0
    while i < len(lines):
        sl = lines[i]
        line = sl.text.rstrip(';')
        m = DATA_RE.match(line)
        if m:
            program.statements.append(DataDecl(sl.number, m['name'], m['type'], m['sec'], _literal(m['value'])))
            i += 1; continue
        m = SECRET_RE.match(line)
        if m:
            program.statements.append(SecretDecl(sl.number, m['name'], str(_literal(m['value']))))
            i += 1; continue
        if line.startswith("print(") and line.endswith(")"):
            program.statements.append(PrintStmt(sl.number, line[6:-1].strip()))
            i += 1; continue
        if line.startswith("require "):
            program.statements.append(RequireStmt(sl.number, line[len("require "):].strip()))
            i += 1; continue
        m = FN_RE.match(line)
        if m:
            body, effects, i = _parse_function(lines, i, m)
            params = [p.strip() for p in m['params'].split(',') if p.strip()]
            program.statements.append(FunctionDecl(sl.number, m['name'], params, effects, m['risk'], body))
            continue
        m = POLICY_RE.match(line)
        if m:
            rules, i = _parse_policy(lines, i)
            program.statements.append(PolicyDecl(sl.number, m['name'], rules))
            continue
        m = CALL_RE.match(line)
        if m:
            args = [a.strip() for a in m['args'].split(',') if a.strip()]
            program.statements.append(CallStmt(sl.number, m['name'], args))
            i += 1; continue
        raise ParseError(f"line {sl.number}: cannot parse: {sl.text}")
    return program

def _parse_function(lines, start, match):
    body = []
    effects: set[str] = set()
    i = start + 1
    depth = 1
    while i < len(lines):
        sl = lines[i]
        line = sl.text.rstrip(';')
        if line.endswith("{"):
            depth += 1
        if line == "}":
            depth -= 1
            if depth == 0:
                return body, effects, i + 1
        if depth == 1 and line.startswith("effects "):
            raw = line[len("effects "):].strip()
            effects.update(x.strip() for x in raw.strip("[]").split(',') if x.strip())
        elif depth == 1 and line.startswith("print(") and line.endswith(")"):
            body.append(PrintStmt(sl.number, line[6:-1].strip()))
        elif depth == 1 and line.startswith("require "):
            body.append(RequireStmt(sl.number, line[len("require "):].strip()))
        elif depth == 1 and line.startswith("effect "):
            body.append(CallStmt(sl.number, "__effect__", [line[len("effect "):].strip()]))
        i += 1
    raise ParseError(f"line {lines[start].number}: unterminated function")

def _parse_policy(lines, start):
    rules=[]; i=start+1
    while i < len(lines):
        sl=lines[i]; line=sl.text.rstrip(';')
        if line == "}": return rules, i+1
        rules.append(line)
        i += 1
    raise ParseError(f"line {lines[start].number}: unterminated policy")
