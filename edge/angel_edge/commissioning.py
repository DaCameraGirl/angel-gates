"""Commissioning identity and binding helpers for Angel Gates edge devices."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .crypto_tokens import TokenError
from .store import (
    EdgeError,
    append_event,
    begin_write,
    canonical_json,
    create_event_anchor,
    get_metadata,
    issue_api_token_hash,
    set_metadata,
    utc_now,
)

DEVICE_ID_PREFIX = "agd"
FACTORY_RESET_CONFIRMATION = "FACTORY-RESET"
COMMISSIONING_KEYS = [
    "device_id",
    "device_public_key_pem",
    "bootstrap_nonce",
    "commissioning_status",
    "binding_id",
    "property_id",
    "gate_id",
    "property_label",
    "binding_issued_at",
    "binding_expires_at",
    "binding_artifact_hash",
    "binding_revoked_at",
    "binding_revoked_reason",
]


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def public_key_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def private_key_pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def default_public_key_file(key_file: str | Path) -> Path:
    return Path(f"{key_file}.pub")


def atomic_write_private(path: Path, content: str) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(tmp_path, flags, 0o600), "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def atomic_write_public(path: Path, content: str) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)
    try:
        path.chmod(0o644)
    except OSError:
        pass


def load_private_key(key_file: str | Path) -> Ed25519PrivateKey:
    data = Path(key_file).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TokenError("device_key_is_not_ed25519")
    return key


def load_public_key(pem_text: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_text.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise TokenError("public_key_is_not_ed25519")
    return key


def device_id_for_public_key(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"{DEVICE_ID_PREFIX}_{hashlib.sha256(der).hexdigest()[:32]}"


def ensure_device_identity(key_file: str | Path, public_key_file: str | Path | None = None) -> dict[str, str]:
    path = Path(key_file)
    pub_path = Path(public_key_file) if public_key_file else default_public_key_file(path)
    if path.exists() != pub_path.exists():
        raise EdgeError("device_identity_half_present_refusing_to_reidentify")

    if path.exists() and pub_path.exists():
        private_key = load_private_key(path)
        expected_public = public_key_pem(private_key.public_key())
        stored_public = pub_path.read_text(encoding="utf-8")
        if stored_public.strip() != expected_public.strip():
            raise EdgeError("device_public_key_mismatch")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        pub_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        atomic_write_private(path, private_key_pem(private_key))
        atomic_write_public(pub_path, public_key_pem(private_key.public_key()))

    public_key = private_key.public_key()
    return {
        "device_id": device_id_for_public_key(public_key),
        "public_key_pem": public_key_pem(public_key),
    }


def commissioning_payload(connection, key_file: str | Path) -> dict[str, Any]:  # noqa: ANN001
    identity = ensure_device_identity(key_file)
    begin_write(connection)
    bootstrap_nonce = get_metadata(connection, "bootstrap_nonce")
    if not bootstrap_nonce:
        bootstrap_nonce = secrets.token_urlsafe(24)
        set_metadata(connection, "bootstrap_nonce", bootstrap_nonce)

    set_metadata(connection, "device_id", identity["device_id"])
    set_metadata(connection, "device_public_key_pem", identity["public_key_pem"])
    if not get_metadata(connection, "commissioning_status"):
        set_metadata(connection, "commissioning_status", "unclaimed")
    connection.commit()

    return {
        "device_id": identity["device_id"],
        "public_key_pem": identity["public_key_pem"],
        "bootstrap_nonce": bootstrap_nonce,
        "commissioning_status": get_metadata(connection, "commissioning_status"),
        "payload_version": 1,
    }


def sign_claim_challenge(key_file: str | Path, challenge: dict[str, Any]) -> dict[str, Any]:
    private_key = load_private_key(key_file)
    public_key = private_key.public_key()
    device_id = device_id_for_public_key(public_key)
    required = ["nonce", "device_id", "property_id", "gate_id", "issued_at"]
    missing = [field for field in required if not challenge.get(field)]
    if missing:
        raise EdgeError("claim_challenge_missing_" + "_".join(missing))
    if challenge["device_id"] != device_id:
        raise EdgeError("claim_challenge_device_id_mismatch")
    signature = private_key.sign(canonical_json(challenge).encode("utf-8"))
    return {
        "device_id": device_id,
        "signature": b64url_encode(signature),
        "algorithm": "Ed25519",
    }


def verify_device_signature(public_key_text: str, challenge: dict[str, Any], signature: str) -> bool:
    public_key = load_public_key(public_key_text)
    try:
        public_key.verify(b64url_decode(signature), canonical_json(challenge).encode("utf-8"))
        return True
    except InvalidSignature:
        return False


def sign_binding_payload(cloud_private_key: Ed25519PrivateKey, payload: dict[str, Any]) -> dict[str, Any]:
    signature = cloud_private_key.sign(canonical_json(payload).encode("utf-8"))
    return {
        "payload": payload,
        "signature": b64url_encode(signature),
        "algorithm": "Ed25519",
    }


def verify_binding_artifact(artifact: dict[str, Any], cloud_public_key_pem: str) -> dict[str, Any]:
    payload = artifact.get("payload")
    signature = artifact.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise EdgeError("invalid_binding_artifact")
    public_key = load_public_key(cloud_public_key_pem)
    try:
        public_key.verify(b64url_decode(signature), canonical_json(payload).encode("utf-8"))
    except InvalidSignature as exc:
        raise EdgeError("binding_signature_invalid") from exc
    return payload


def apply_binding_artifact(
    connection,  # noqa: ANN001
    *,
    key_file: str | Path,
    artifact: dict[str, Any],
    cloud_public_key_pem: str,
) -> dict[str, Any]:
    payload = verify_binding_artifact(artifact, cloud_public_key_pem)
    local_payload = commissioning_payload(connection, key_file)
    if payload.get("device_id") != local_payload["device_id"]:
        raise EdgeError("binding_device_id_mismatch")
    if payload.get("bootstrap_nonce") != local_payload["bootstrap_nonce"]:
        raise EdgeError("binding_bootstrap_nonce_mismatch")
    property_id = str(payload.get("property_id") or "")
    gate_id = str(payload.get("gate_id") or "")
    binding_id = str(payload.get("binding_id") or "")
    if not property_id or not gate_id or not binding_id:
        raise EdgeError("binding_requires_property_id_gate_id_and_binding_id")

    begin_write(connection)
    set_metadata(connection, "commissioning_status", payload.get("status", "claimed_pending_cloud"))
    set_metadata(connection, "binding_id", binding_id)
    set_metadata(connection, "property_id", property_id)
    set_metadata(connection, "gate_id", gate_id)
    set_metadata(connection, "property_label", str(payload.get("property_label") or ""))
    set_metadata(connection, "binding_issued_at", str(payload.get("issued_at") or utc_now()))
    if payload.get("expires_at"):
        set_metadata(connection, "binding_expires_at", str(payload["expires_at"]))
    set_metadata(connection, "binding_artifact_hash", hashlib.sha256(canonical_json(artifact).encode("utf-8")).hexdigest())

    issued_tokens = []
    for token in payload.get("api_tokens", []):
        token_record = issue_api_token_hash(
            connection,
            token_id=str(token["token_id"]),
            token_hash=str(token["token_hash"]),
            label=str(token.get("label") or token["token_id"]),
            scope=str(token.get("scope") or "dashboard"),
            expires_at=str(token["expires_at"]),
        )
        issued_tokens.append(token_record)

    append_event(
        connection,
        event_type="commissioning",
        reason="binding_applied",
        extra={"binding_id": binding_id, "property_id": property_id, "gate_id": gate_id, "token_count": len(issued_tokens)},
    )
    connection.commit()
    return {
        "ok": True,
        "device_id": local_payload["device_id"],
        "binding_id": binding_id,
        "property_id": property_id,
        "gate_id": gate_id,
        "commissioning_status": get_metadata(connection, "commissioning_status"),
        "api_tokens": issued_tokens,
    }


def revoke_binding(connection, *, reason: str) -> dict[str, Any]:  # noqa: ANN001
    begin_write(connection)
    set_metadata(connection, "commissioning_status", "revoked")
    set_metadata(connection, "binding_revoked_at", utc_now())
    set_metadata(connection, "binding_revoked_reason", reason)
    connection.execute("UPDATE api_tokens SET revoked_at = ? WHERE revoked_at IS NULL", (utc_now(),))
    append_event(connection, event_type="commissioning", reason="binding_revoked", extra={"reason": reason})
    anchor = create_event_anchor(connection, anchor_type="binding_revocation_local")
    connection.commit()
    return {"ok": True, "commissioning_status": "revoked", "anchor": anchor}


def factory_reset(connection, *, key_file: str | Path, confirmation: str) -> dict[str, Any]:  # noqa: ANN001
    if confirmation != FACTORY_RESET_CONFIRMATION:
        raise EdgeError("factory_reset_requires_confirmation")
    begin_write(connection)
    append_event(connection, event_type="commissioning", reason="factory_reset")
    connection.execute("DELETE FROM api_tokens")
    for key in COMMISSIONING_KEYS:
        connection.execute("DELETE FROM metadata WHERE key = ?", (key,))
    set_metadata(connection, "commissioning_status", "unclaimed")
    connection.commit()

    path = Path(key_file)
    if path.exists():
        path.unlink()
    pub_path = default_public_key_file(path)
    if pub_path.exists():
        pub_path.unlink()
    return {"ok": True, "commissioning_status": "unclaimed", "device_key_removed": True}


def commissioning_status(connection) -> dict[str, Any]:  # noqa: ANN001
    return {
        "device_id": get_metadata(connection, "device_id"),
        "commissioning_status": get_metadata(connection, "commissioning_status") or "unclaimed",
        "binding_id": get_metadata(connection, "binding_id"),
        "property_id": get_metadata(connection, "property_id"),
        "gate_id": get_metadata(connection, "gate_id"),
        "property_label": get_metadata(connection, "property_label"),
        "binding_issued_at": get_metadata(connection, "binding_issued_at"),
        "binding_expires_at": get_metadata(connection, "binding_expires_at"),
        "binding_revoked_at": get_metadata(connection, "binding_revoked_at"),
        "binding_revoked_reason": get_metadata(connection, "binding_revoked_reason"),
    }
