from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class SourceLine:
    number: int
    text: str


def logical_lines(source: str) -> list[SourceLine]:
    out: list[SourceLine] = []
    for i, raw in enumerate(source.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if line:
            out.append(SourceLine(i, line))
    return out
