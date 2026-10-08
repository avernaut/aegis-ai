from __future__ import annotations
import argparse
from pathlib import Path
from .compiler import compile_source
from .checker import SecurityError
from .parser import ParseError

def main() -> int:
    p = argparse.ArgumentParser(prog="aegis", description="AegisAI compiler")
    p.add_argument("source", type=Path)
    p.add_argument("-t", "--target", choices=["python", "air"], default="python")
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    try:
        result = compile_source(args.source.read_text(), args.target)
    except (SecurityError, ParseError) as exc:
        if isinstance(exc, SecurityError):
            for d in exc.diagnostics:
                print(f"{args.source}:{d.line}: {d.kind}: {d.message}")
        else:
            print(f"{args.source}: PARSE: {exc}")
        return 1
    if args.output:
        args.output.write_text(result)
    else:
        print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
