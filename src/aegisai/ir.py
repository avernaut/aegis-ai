from __future__ import annotations
from dataclasses import asdict
from .ast import *

def lower(program: Program) -> dict:
    ops=[]
    for s in program.statements:
        if isinstance(s, DataDecl):
            ops.append({"op":"data.declare","name":s.name,"type":s.base_type,"security":s.security,"value":s.value,"line":s.line})
        elif isinstance(s, SecretDecl):
            ops.append({"op":"secret.declare","name":s.name,"value":"<redacted>","line":s.line})
        elif isinstance(s, PrintStmt):
            ops.append({"op":"io.print","expr":s.expr,"effect":"write.stdout","line":s.line})
        elif isinstance(s, RequireStmt):
            ops.append({"op":"guard.require","condition":s.condition,"line":s.line})
        elif isinstance(s, PolicyDecl):
            ops.append({"op":"policy.declare","name":s.name,"rules":s.rules,"line":s.line})
        elif isinstance(s, FunctionDecl):
            ops.append({"op":"fn.declare","name":s.name,"params":s.params,"risk":s.risk,"effects":sorted(s.effects),"body":lower(Program(s.line,s.body))["ops"],"line":s.line})
        elif isinstance(s, CallStmt):
            ops.append({"op":"fn.call","name":s.function,"args":s.args,"line":s.line})
    return {"air_version":"0.1","language":"AegisAI","ops":ops}
