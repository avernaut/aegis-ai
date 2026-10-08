from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from . import __version__
from .compiler import compile_source, check_source, run_source
from .checker import SecurityError
from .parser import ParseError
from .runtime import AegisRuntimeError, ProvenanceLedger


def _print_diagnostics(path: Path, exc: SecurityError) -> None:
    for d in exc.diagnostics:
        print(f"{path}:{d.line}: {d.kind}: {d.message}")


def _runtime_key(key_file: Path | None) -> bytes:
    if key_file:
        key = key_file.read_bytes().strip()
    else:
        value = os.environ.get("AEGIS_RUNTIME_KEY")
        if not value:
            raise AegisRuntimeError("runtime key required: use --key-file or AEGIS_RUNTIME_KEY")
        key = value.encode("utf-8")
    if len(key) < 16:
        raise AegisRuntimeError("runtime key must contain at least 16 bytes")
    return key


def _run_command(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="aegis run", description="Execute the AegisAI bounded-authority runtime")
    p.add_argument("source", type=Path)
    p.add_argument("--context", type=Path, help="JSON runtime context (confidence, approvals, twin metrics)")
    p.add_argument("--key-file", type=Path, help="file containing the HMAC runtime key; alternatively set AEGIS_RUNTIME_KEY")
    p.add_argument("--audit", type=Path, help="write cryptographic provenance ledger as JSON")
    args = p.parse_args(argv)
    try:
        source = args.source.read_text(encoding="utf-8")
        context = json.loads(args.context.read_text(encoding="utf-8")) if args.context else {}
        result = run_source(source, context=context, runtime_key=_runtime_key(args.key_file))
        payload = result.to_dict()
        if args.audit:
            args.audit.write_text(json.dumps({"air_version": "0.3", "entries": result.provenance, "valid": payload["provenance_valid"]}, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in payload.items() if k != "provenance"}, indent=2))
        return 0
    except (SecurityError, ParseError, AegisRuntimeError, json.JSONDecodeError) as exc:
        if isinstance(exc, SecurityError):
            _print_diagnostics(args.source, exc)
        else:
            print(f"{args.source}: RUNTIME: {exc}")
        return 1


def _verify_audit(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="aegis verify-audit", description="Verify an AegisAI provenance hash chain")
    p.add_argument("audit", type=Path)
    args = p.parse_args(argv)
    try:
        doc = json.loads(args.audit.read_text(encoding="utf-8"))
        ledger = ProvenanceLedger(doc["entries"])
        valid = ledger.verify()
    except Exception as exc:
        print(f"{args.audit}: invalid audit file: {exc}")
        return 1
    print(f"{args.audit}: {'VALID' if valid else 'INVALID'}")
    return 0 if valid else 1


def _compile_command(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="aegis", description="AegisAI compiler")
    p.add_argument("--version", action="version", version=f"AegisAI {__version__}")
    p.add_argument("source", type=Path)
    p.add_argument("-t", "--target", choices=["python", "air"], default="python")
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--check", action="store_true", help="parse and run static security checks without code generation")
    args = p.parse_args(argv)
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


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "run":
        return _run_command(argv[1:])
    if argv and argv[0] == "verify-audit":
        return _verify_audit(argv[1:])
    return _compile_command(argv)


if __name__ == "__main__":
    raise SystemExit(main())
