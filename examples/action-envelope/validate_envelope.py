#!/usr/bin/env python3
"""Minimal semantic validator for AegisAI Action Authorization Envelopes.

This intentionally uses only the Python standard library. JSON Schema validation
should be performed separately in production; these checks cover cross-field
semantics that are easy to miss in a schema-only implementation.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate(env: dict) -> list[str]:
    errors: list[str] = []
    now = datetime.now(timezone.utc)

    if env.get("revoked", False):
        errors.append("capability has been revoked")

    try:
        if parse_ts(env["expires_at"]) <= now:
            errors.append("envelope is expired")
        if parse_ts(env["issued_at"]) >= parse_ts(env["expires_at"]):
            errors.append("issued_at must be before expires_at")
    except (KeyError, ValueError) as exc:
        errors.append(f"invalid timestamp: {exc}")

    action = env.get("action", {})
    authority = env.get("authority", {})
    required_scope = {f"action:{action.get('type')}", f"resource:{action.get('target')}"}
    available_scope = set(authority.get("scope", []))
    missing_scope = required_scope - available_scope
    if missing_scope:
        errors.append("action/target outside authority scope: " + ", ".join(sorted(missing_scope)))

    approval = env.get("approval", {})
    if approval.get("mode") == "quorum":
        if len(set(approval.get("approvals", []))) < approval.get("quorum_required", 0):
            errors.append("quorum not satisfied")

    verification = env.get("verification", {})
    required = set(verification.get("required_checks", []))
    passed = set(verification.get("passed_checks", []))
    missing_checks = required - passed
    if missing_checks:
        errors.append("required checks failed/missing: " + ", ".join(sorted(missing_checks)))

    if verification.get("evidence_age_seconds", 10**9) > verification.get("max_age_seconds", -1):
        errors.append("verification evidence is stale")

    risk = env.get("risk", {}).get("level")
    if risk in {"high", "critical"} and not env.get("recovery", {}).get("rollback_supported", False):
        errors.append("high/critical action lacks rollback support")

    if risk == "critical" and approval.get("mode") != "human":
        errors.append("critical action requires human approval")

    if env.get("attestation", {}).get("required") and not env.get("attestation", {}).get("measurement"):
        errors.append("runtime attestation is required but no measurement is present")

    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} envelope.json", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    env = json.loads(path.read_text(encoding="utf-8"))
    errors = validate(env)
    if errors:
        print("DENY")
        for error in errors:
            print(f"- {error}")
        return 1

    print("ALLOW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
