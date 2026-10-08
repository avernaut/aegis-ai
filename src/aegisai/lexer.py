from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceLine:
    number: int
    text: str


def _strip_comment(raw: str) -> str:
    """Strip // comments while preserving // inside quoted strings."""
    quote: str | None = None
    escaped = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if ch == "\\" and quote is not None:
            escaped = True
            i += 1
            continue
        if quote is not None:
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in {'"', "'"}:
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < len(raw) and raw[i + 1] == "/":
            return raw[:i]
        i += 1
    return raw


def logical_lines(source: str) -> list[SourceLine]:
    out: list[SourceLine] = []
    for i, raw in enumerate(source.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if line:
            out.append(SourceLine(i, line))
    return out
