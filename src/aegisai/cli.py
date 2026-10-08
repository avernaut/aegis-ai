from __future__ import annotations
import argparse
from pathlib import Path
from . import __version__
from .compiler import compile_source, check_source
from .checker import SecurityError
from .parser import ParseError


def _print_diagnostics(path: Path, exc: SecurityError) -> None:
    for d in exc.diagnostics:
        print(f"{path}:{d.line}: {d.kind}: {d.message}")


def main() -> int:
    p = argparse.ArgumentParser(prog="aegis", description="AegisAI compiler")
    p.add_argument("--version", action="version", version=f"AegisAI {__version__}")
    p.add_argument("source", type=Path)
    p.add_argument("-t", "--target", choices=["python", "air"], default="python")
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--check", action="store_true", help="parse and run static security checks without code generation")
    args = p.parse_args()
    try:
        source = args.source.read_text(encoding="utf-8")
        if args.check:
            diagnostics = check_source(source)
            if diagnostics:
                raise SecurityError(diagnostics)
            print(f"{args.source}: OK")
            return 0
        result = compile_source(source, args.target)
    except (SecurityError, ParseError) as exc:
        if isinstance(exc, SecurityError):
            _print_diagnostics(args.source, exc)
        else:
            print(f"{args.source}: PARSE: {exc}")
        return 1
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
