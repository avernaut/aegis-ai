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
from .runtime import AegisRuntimeError, verify_audit_document
from .credentials import (
    CredentialError,
    SigningIdentity,
    generate_ed25519_keypair,
    load_private_key_pem,
    load_public_key_pem,
    private_key_to_pem,
    public_key_id,
    public_key_to_pem,
    issue_runtime_attestation,
)


def _print_diagnostics(path: Path, exc: SecurityError) -> None:
    for d in exc.diagnostics:
        print(f"{path}:{d.line}: {d.kind}: {d.message}")


def _runtime_key(key_file: Path | None) -> bytes | None:
    if key_file:
        key = key_file.read_bytes().strip()
    else:
        value = os.environ.get("AEGIS_RUNTIME_KEY")
        if not value:
            return None
        key = value.encode("utf-8")
    if len(key) < 16:
        raise AegisRuntimeError("runtime key must contain at least 16 bytes")
    return key


def _mapping(values: list[str] | None, *, private: bool) -> dict:
    out = {}
    for item in values or []:
        if "=" not in item:
            raise AegisRuntimeError("key mapping must use ISSUER=PATH")
        issuer, path = item.split("=", 1)
        data = Path(path).read_bytes()
        out[issuer] = load_private_key_pem(data) if private else load_public_key_pem(data)
    return out


def _text_mapping(values: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise AegisRuntimeError("text mapping must use NAME=PATH")
        name, path = item.split("=", 1)
        out[name] = Path(path).read_text(encoding="utf-8").strip()
    return out


def _run_command(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="aegis run", description="Execute the AegisAI bounded-authority runtime")
    p.add_argument("source", type=Path)
    p.add_argument("--context", type=Path, help="JSON runtime context (confidence, approvals, twin metrics, placement telemetry)")
    p.add_argument("--key-file", type=Path, help="legacy HMAC runtime key for v0.3 token declarations")
    p.add_argument("--credential-key", action="append", metavar="ISSUER=PATH", help="Ed25519 private key used to issue v0.4+ capability credentials; repeatable")
    p.add_argument("--trust-key", action="append", metavar="ISSUER=PATH", help="trusted Ed25519 public key; repeatable")
    p.add_argument("--anchor-key", type=Path, help="Ed25519 private key used to sign the final provenance root")
    p.add_argument("--anchor-issuer", default="AegisAI-Audit", help="issuer name for the provenance anchor")
    p.add_argument("--allow-remote-twin", action="store_true", help="allow declared HTTPS Digital Twin connectors to make network requests")
    p.add_argument("--attestation", action="append", metavar="NAME=PATH", help="signed runtime attestation token to inject into the execution context; repeatable")
    p.add_argument("--audit", type=Path, help="write hash-chained provenance ledger and optional signature anchor as JSON")
    args = p.parse_args(argv)
    try:
        source = args.source.read_text(encoding="utf-8")
        context = json.loads(args.context.read_text(encoding="utf-8")) if args.context else {}
        if args.attestation:
            context.setdefault("attestations", {}).update(_text_mapping(args.attestation))
        private_keys = _mapping(args.credential_key, private=True)
        signers = {issuer: SigningIdentity(issuer, key) for issuer, key in private_keys.items()}
        trusted = _mapping(args.trust_key, private=False)
        provenance_signer = None
        if args.anchor_key:
            provenance_signer = SigningIdentity(args.anchor_issuer, load_private_key_pem(args.anchor_key.read_bytes()))
        result = run_source(
            source,
            context=context,
            runtime_key=_runtime_key(args.key_file),
            credential_signers=signers,
            trusted_issuers=trusted,
            provenance_signer=provenance_signer,
            allow_remote_twin=args.allow_remote_twin,
        )
        payload = result.to_dict()
        if args.audit:
            args.audit.write_text(json.dumps({
                "air_version": "0.5",
                "entries": result.provenance,
                "anchor": result.provenance_anchor,
                "valid": payload["provenance_valid"],
            }, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in payload.items() if k != "provenance"}, indent=2))
        return 0
    except (SecurityError, ParseError, AegisRuntimeError, CredentialError, json.JSONDecodeError, OSError) as exc:
        if isinstance(exc, SecurityError):
            _print_diagnostics(args.source, exc)
        else:
            print(f"{args.source}: RUNTIME: {exc}")
        return 1


def _verify_audit(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="aegis verify-audit", description="Verify an AegisAI provenance hash chain and optional Ed25519 anchor")
    p.add_argument("audit", type=Path)
    p.add_argument("--anchor-public-key", action="append", metavar="ISSUER=PATH", help="trusted provenance anchor public key; repeatable")
    p.add_argument("--require-anchor", action="store_true", help="fail unless a cryptographic provenance anchor is present and verified")
    args = p.parse_args(argv)
    try:
        doc = json.loads(args.audit.read_text(encoding="utf-8"))
        trusted = _mapping(args.anchor_public_key, private=False) if args.anchor_public_key else None
        valid, anchor_valid = verify_audit_document(doc, trusted, require_anchor=args.require_anchor)
    except Exception as exc:
        print(f"{args.audit}: invalid audit file: {exc}")
        return 1
    suffix = ""
    if doc.get("anchor") is not None:
        suffix = " / anchor " + ("VALID" if anchor_valid is True else "INVALID" if anchor_valid is False else "UNVERIFIED")
    print(f"{args.audit}: {'VALID' if valid else 'INVALID'}{suffix}")
    return 0 if valid else 1


def _keygen(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="aegis keygen", description="Generate an Ed25519 key pair for credentials or provenance anchors")
    p.add_argument("--private", type=Path, default=Path("aegis-ed25519-private.pem"))
    p.add_argument("--public", type=Path, default=Path("aegis-ed25519-public.pem"))
    args = p.parse_args(argv)
    try:
        private_key, public_key = generate_ed25519_keypair()
        args.private.write_bytes(private_key_to_pem(private_key))
        args.public.write_bytes(public_key_to_pem(public_key))
        try:
            args.private.chmod(0o600)
        except OSError:
            pass
        print(json.dumps({"private": str(args.private), "public": str(args.public), "key_id": public_key_id(public_key)}, indent=2))
        return 0
    except OSError as exc:
        print(f"keygen: {exc}")
        return 1


def _attest(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="aegis attest", description="Issue a signed Ed25519 runtime attestation for AegisAI v0.5")
    p.add_argument("--name", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--measurement", required=True)
    p.add_argument("--issuer", required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args(argv)
    try:
        signer = SigningIdentity(args.issuer, load_private_key_pem(args.private_key.read_bytes()))
        token = issue_runtime_attestation(args.name, args.target, args.measurement, signer)
        if args.output:
            args.output.write_text(token + "\n", encoding="utf-8")
            print(str(args.output))
        else:
            print(token)
        return 0
    except (OSError, CredentialError) as exc:
        print(f"attest: {exc}")
        return 1


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
    if argv and argv[0] == "keygen":
        return _keygen(argv[1:])
    if argv and argv[0] == "attest":
        return _attest(argv[1:])
    return _compile_command(argv)


if __name__ == "__main__":
    raise SystemExit(main())
