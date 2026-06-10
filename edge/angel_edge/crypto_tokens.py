"""Signed visitor QR token helpers.

The edge verifies Ed25519-signed compact tokens without cloud access. Signing is
included as a development and cloud-service helper; deployed edge devices should
only need public keys.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class TokenError(ValueError):
    """Raised when a signed QR token is malformed or fails verification."""


@dataclass(frozen=True)
class VerifiedToken:
    header: dict[str, Any]
    payload: dict[str, Any]
    signing_input: bytes


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
      return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as exc:  # noqa: BLE001
      raise TokenError("invalid_base64") from exc


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as handle:
        key_data = handle.read()
    key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TokenError("private_key_is_not_ed25519")
    return key


def load_public_key_from_pem(pem_text: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_text.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise TokenError("public_key_is_not_ed25519")
    return key


def generate_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def sign_token(private_key: Ed25519PrivateKey, key_id: str, payload: dict[str, Any]) -> str:
    header = {"alg": "EdDSA", "typ": "AG-JWT", "kid": key_id}
    signing_input = b".".join([b64url_encode(canonical_json(header)).encode("ascii"), b64url_encode(canonical_json(payload)).encode("ascii")])
    signature = private_key.sign(signing_input)
    return ".".join([signing_input.decode("ascii"), b64url_encode(signature)])


def verify_token(token: str, public_keys: dict[str, str], now: int | None = None) -> VerifiedToken:
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("token_must_have_three_parts")

    header_raw, payload_raw, signature_raw = parts
    try:
        header = json.loads(b64url_decode(header_raw))
        payload = json.loads(b64url_decode(payload_raw))
    except json.JSONDecodeError as exc:
        raise TokenError("invalid_token_json") from exc

    if header.get("alg") != "EdDSA":
        raise TokenError("unsupported_token_algorithm")
    key_id = header.get("kid")
    if not key_id or key_id not in public_keys:
        raise TokenError("unknown_key_id")

    public_key = load_public_key_from_pem(public_keys[key_id])
    signing_input = f"{header_raw}.{payload_raw}".encode("ascii")
    signature = b64url_decode(signature_raw)
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise TokenError("invalid_signature") from exc

    current = int(time.time() if now is None else now)
    not_before = payload.get("nbf")
    expires_at = payload.get("exp")
    if not_before is not None and current < int(not_before):
        raise TokenError("token_not_yet_valid")
    if expires_at is None:
        raise TokenError("token_missing_expiry")
    if current > int(expires_at):
        raise TokenError("token_expired")

    required = ["token_id", "principal_id", "principal_label", "gate_scope"]
    missing = [field for field in required if field not in payload]
    if missing:
        raise TokenError("token_missing_" + "_".join(missing))
    if not isinstance(payload["gate_scope"], list):
        raise TokenError("gate_scope_must_be_list")

    return VerifiedToken(header=header, payload=payload, signing_input=signing_input)
