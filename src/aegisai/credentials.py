from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


class CredentialError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_to_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key_pem(data: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise CredentialError("private key is not Ed25519")
    return key


def load_public_key_pem(data: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise CredentialError("public key is not Ed25519")
    return key


@dataclass(frozen=True)
class SigningIdentity:
    issuer: str
    private_key: Ed25519PrivateKey

    @property
    def key_id(self) -> str:
        return public_key_id(self.private_key.public_key())


@dataclass(frozen=True)
class TrustIdentity:
    issuer: str
    public_key: Ed25519PublicKey

    @property
    def key_id(self) -> str:
        return public_key_id(self.public_key)


def issue_capability_credential(
    name: str,
    agent: str,
    capability: str,
    ttl_seconds: int,
    signer: SigningIdentity,
    *,
    now: int | None = None,
    delegated_from: str | None = None,
) -> str:
    now = int(time.time()) if now is None else int(now)
    payload = {
        "v": 2,
        "alg": "Ed25519",
        "name": name,
        "agent": agent,
        "capability": capability,
        "issuer": signer.issuer,
        "key_id": signer.key_id,
        "iat": now,
        "exp": now + int(ttl_seconds),
        "nonce": _b64e(os.urandom(12)),
    }
    if delegated_from is not None:
        payload["v"] = 3
        payload["delegated_from"] = delegated_from
    body = _b64e(_canonical(payload))
    signature = _b64e(signer.private_key.sign(body.encode("ascii")))
    return f"aegiscred.{body}.{signature}"


def verify_capability_credential(
    credential: str,
    trusted_issuers: dict[str, Ed25519PublicKey],
    *,
    now: int | None = None,
    agent: str | None = None,
    capability: str | None = None,
    delegated_from: str | None = None,
) -> dict[str, Any]:
    try:
        prefix, body, signature = credential.split(".", 2)
        if prefix != "aegiscred":
            raise CredentialError("invalid capability credential prefix")
        payload = json.loads(_b64d(body))
        issuer = payload.get("issuer")
        key = trusted_issuers.get(issuer)
        if key is None:
            raise CredentialError(f"untrusted capability credential issuer '{issuer}'")
        if payload.get("key_id") != public_key_id(key):
            raise CredentialError("capability credential key id does not match trusted issuer key")
        key.verify(_b64d(signature), body.encode("ascii"))
    except CredentialError:
        raise
    except InvalidSignature as exc:
        raise CredentialError("capability credential signature verification failed") from exc
    except Exception as exc:
        raise CredentialError("invalid capability credential") from exc

    now = int(time.time()) if now is None else int(now)
    if int(payload.get("exp", 0)) < now:
        raise CredentialError("capability credential has expired")
    if agent is not None and payload.get("agent") != agent:
        raise CredentialError(f"capability credential agent mismatch: expected '{agent}'")
    if capability is not None and payload.get("capability") != capability:
        raise CredentialError(f"capability credential mismatch: expected '{capability}'")
    if delegated_from is not None and payload.get("delegated_from") != delegated_from:
        raise CredentialError(f"capability credential delegation mismatch: expected '{delegated_from}'")
    return payload


def sign_provenance_anchor(root_hash: str, signer: SigningIdentity, *, timestamp: int | None = None) -> dict[str, Any]:
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    payload = {
        "v": 1,
        "alg": "Ed25519",
        "issuer": signer.issuer,
        "key_id": signer.key_id,
        "root_hash": root_hash,
        "timestamp": timestamp,
    }
    signature = _b64e(signer.private_key.sign(_canonical(payload)))
    return {**payload, "signature": signature}


def verify_provenance_anchor(anchor: dict[str, Any], trusted_issuers: dict[str, Ed25519PublicKey]) -> bool:
    try:
        issuer = anchor["issuer"]
        key = trusted_issuers[issuer]
        if anchor.get("key_id") != public_key_id(key):
            return False
        payload = {k: anchor[k] for k in ("v", "alg", "issuer", "key_id", "root_hash", "timestamp")}
        key.verify(_b64d(anchor["signature"]), _canonical(payload))
        return True
    except (KeyError, ValueError, InvalidSignature, TypeError):
        return False


def issue_runtime_attestation(name: str, target: str, measurement: str, signer: SigningIdentity, *, now: int | None = None) -> str:
    now = int(time.time()) if now is None else int(now)
    payload = {
        "v": 1, "alg": "Ed25519", "name": name, "target": target,
        "measurement": measurement, "issuer": signer.issuer, "key_id": signer.key_id,
        "timestamp": now, "nonce": _b64e(os.urandom(12)),
    }
    body = _b64e(_canonical(payload))
    signature = _b64e(signer.private_key.sign(body.encode("ascii")))
    return f"aegisatt.{body}.{signature}"


def verify_runtime_attestation(token: str, trusted_issuers: dict[str, Ed25519PublicKey], *, now: int | None = None, target: str | None = None, measurement: str | None = None, max_age_seconds: int | None = None) -> dict[str, Any]:
    try:
        prefix, body, signature = token.split(".", 2)
        if prefix != "aegisatt":
            raise CredentialError("invalid runtime attestation prefix")
        payload = json.loads(_b64d(body))
        issuer = payload.get("issuer")
        key = trusted_issuers.get(issuer)
        if key is None:
            raise CredentialError(f"untrusted runtime attestation issuer '{issuer}'")
        if payload.get("key_id") != public_key_id(key):
            raise CredentialError("runtime attestation key id does not match trusted issuer key")
        key.verify(_b64d(signature), body.encode("ascii"))
    except CredentialError:
        raise
    except InvalidSignature as exc:
        raise CredentialError("runtime attestation signature verification failed") from exc
    except Exception as exc:
        raise CredentialError("invalid runtime attestation") from exc
    now = int(time.time()) if now is None else int(now)
    age = now - int(payload.get("timestamp", 0))
    if age < 0:
        raise CredentialError("runtime attestation timestamp is in the future")
    if max_age_seconds is not None and age > int(max_age_seconds):
        raise CredentialError("runtime attestation is stale")
    if target is not None and payload.get("target") != target:
        raise CredentialError(f"runtime attestation target mismatch: expected '{target}'")
    if measurement is not None and payload.get("measurement") != measurement:
        raise CredentialError("runtime attestation measurement mismatch")
    return payload
