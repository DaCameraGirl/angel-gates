"""SQLite-backed edge authorization and event-log store."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .crypto_tokens import TokenError, verify_token

ZERO_HASH = "0" * 64
GENESIS_SEQUENCE = 1
GENESIS_EVENT_ID = "evt_genesis_v1"
GENESIS_OCCURRED_AT = "1970-01-01T00:00:00Z"
GENESIS_REASON = "angel_gates_event_log_genesis_v1"
DEFAULT_REVOCATION_TARGET_SECONDS = 30


class EdgeError(RuntimeError):
    """Base runtime error for edge operations."""


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).astimezone(UTC)


def to_epoch(value: str) -> int:
    parsed = parse_time(value)
    if parsed is None:
        raise EdgeError("time_required")
    return int(parsed.timestamp())


def normalize_credential(credential_type: str, value: str) -> str:
    raw = str(value or "").strip()
    if credential_type == "plate":
        alphanumeric = "".join(character for character in raw.upper() if character.isalnum())
        return alphanumeric.translate(str.maketrans({"O": "0", "I": "1"}))
    if credential_type == "pin":
        return "".join(raw.split())
    return raw


def credential_hash(credential_type: str, value: str) -> str:
    normalized = normalize_credential(credential_type, value)
    return hashlib.sha256(f"{credential_type}:{normalized}".encode("utf-8")).hexdigest()


def mask_credential(credential_type: str, value: str) -> str:
    normalized = normalize_credential(credential_type, value)
    if credential_type == "pin":
        return "*" * min(len(normalized), 8)
    if len(normalized) <= 4:
        return normalized
    return f"{normalized[:2]}...{normalized[-2:]}"


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def connect(db_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path), timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def begin_write(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")


def migrate(connection: sqlite3.Connection, edge_id: str | None = None) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS gates (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          site_area TEXT NOT NULL,
          provider TEXT NOT NULL,
          interface_type TEXT NOT NULL,
          operator_class TEXT NOT NULL,
          hardware_id TEXT NOT NULL,
          safety_acknowledged INTEGER NOT NULL CHECK (safety_acknowledged IN (0, 1)),
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS credentials (
          id TEXT PRIMARY KEY,
          principal_id TEXT NOT NULL,
          principal_label TEXT NOT NULL,
          principal_type TEXT NOT NULL,
          credential_type TEXT NOT NULL CHECK (credential_type IN ('pin', 'plate')),
          credential_hash TEXT NOT NULL,
          credential_display TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
          gate_scope_json TEXT NOT NULL,
          valid_from TEXT NOT NULL,
          valid_until TEXT,
          max_uses INTEGER,
          use_count INTEGER NOT NULL DEFAULT 0,
          confidence_threshold REAL,
          source_version TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          revoked_at TEXT,
          revoked_reason TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_credentials_lookup
          ON credentials (credential_type, credential_hash, status);

        CREATE TABLE IF NOT EXISTS qr_public_keys (
          key_id TEXT PRIMARY KEY,
          public_key_pem TEXT NOT NULL,
          active INTEGER NOT NULL CHECK (active IN (0, 1)),
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS revoked_qr_tokens (
          token_id TEXT PRIMARY KEY,
          reason TEXT NOT NULL,
          created_at TEXT NOT NULL,
          source_created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS qr_token_usage (
          token_id TEXT PRIMARY KEY,
          use_count INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL UNIQUE,
          occurred_at TEXT NOT NULL,
          event_type TEXT NOT NULL,
          principal_id TEXT,
          principal_label TEXT,
          credential_id TEXT,
          credential_type TEXT,
          gate_id TEXT,
          decision TEXT,
          reason TEXT NOT NULL,
          confidence REAL,
          fallback_required INTEGER NOT NULL DEFAULT 0,
          request_json TEXT NOT NULL,
          media_json TEXT NOT NULL,
          extra_json TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          event_hash TEXT NOT NULL,
          queued_for_sync INTEGER NOT NULL DEFAULT 1,
          synced_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_sync ON events (queued_for_sync, synced_at);
        CREATE INDEX IF NOT EXISTS idx_events_gate_time ON events (gate_id, occurred_at);

        CREATE TABLE IF NOT EXISTS event_anchors (
          anchor_id TEXT PRIMARY KEY,
          anchor_type TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          event_hash TEXT NOT NULL,
          anchored_at TEXT NOT NULL,
          upstream_ref TEXT,
          extra_json TEXT NOT NULL,
          FOREIGN KEY(sequence) REFERENCES events(sequence)
        );

        CREATE INDEX IF NOT EXISTS idx_event_anchors_sequence
          ON event_anchors (sequence DESC);
        """
    )
    set_metadata(connection, "schema_version", "1")
    if edge_id:
        set_metadata(connection, "edge_id", edge_id)
    if get_metadata(connection, "revocation_target_seconds") is None:
        set_metadata(connection, "revocation_target_seconds", str(DEFAULT_REVOCATION_TARGET_SECONDS))
    ensure_genesis_event(connection)
    connection.commit()


def get_metadata(connection: sqlite3.Connection, key: str) -> str | None:
    row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row["value"])


def set_metadata(connection: sqlite3.Connection, key: str, value: str) -> None:
    connection.execute(
        "INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def build_event_payload(
    *,
    sequence: int,
    event_id: str,
    occurred_at: str,
    event_type: str,
    principal_id: str | None,
    principal_label: str | None,
    credential_id: str | None,
    credential_type: str | None,
    gate_id: str | None,
    decision: str | None,
    reason: str,
    confidence: float | None,
    fallback_required: bool,
    request_json: str,
    media_json: str,
    extra_json: str,
    previous_hash: str,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "event_id": event_id,
        "occurred_at": occurred_at,
        "event_type": event_type,
        "principal_id": principal_id,
        "principal_label": principal_label,
        "credential_id": credential_id,
        "credential_type": credential_type,
        "gate_id": gate_id,
        "decision": decision,
        "reason": reason,
        "confidence": confidence,
        "fallback_required": fallback_required,
        "request_json": request_json,
        "media_json": media_json,
        "extra_json": extra_json,
        "previous_hash": previous_hash,
    }


def hash_event_payload(previous_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(f"{previous_hash}.{canonical_json(payload)}".encode("utf-8")).hexdigest()


def ensure_genesis_event(connection: sqlite3.Connection) -> None:
    existing = connection.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"]
    if existing:
        return
    request_json = canonical_json({})
    media_json = canonical_json({})
    extra_json = canonical_json({"schema_version": "1"})
    payload = build_event_payload(
        sequence=GENESIS_SEQUENCE,
        event_id=GENESIS_EVENT_ID,
        occurred_at=GENESIS_OCCURRED_AT,
        event_type="genesis",
        principal_id=None,
        principal_label=None,
        credential_id=None,
        credential_type=None,
        gate_id=None,
        decision=None,
        reason=GENESIS_REASON,
        confidence=None,
        fallback_required=False,
        request_json=request_json,
        media_json=media_json,
        extra_json=extra_json,
        previous_hash=ZERO_HASH,
    )
    event_hash = hash_event_payload(ZERO_HASH, payload)
    connection.execute(
        """
        INSERT INTO events (
          sequence, event_id, occurred_at, event_type, principal_id, principal_label,
          credential_id, credential_type, gate_id, decision, reason, confidence,
          fallback_required, request_json, media_json, extra_json,
          previous_hash, event_hash, queued_for_sync
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            GENESIS_SEQUENCE,
            GENESIS_EVENT_ID,
            GENESIS_OCCURRED_AT,
            "genesis",
            None,
            None,
            None,
            None,
            None,
            None,
            GENESIS_REASON,
            None,
            0,
            request_json,
            media_json,
            extra_json,
            ZERO_HASH,
            event_hash,
        ),
    )


def add_gate(
    connection: sqlite3.Connection,
    *,
    gate_id: str,
    name: str,
    site_area: str,
    provider: str,
    interface_type: str,
    operator_class: str,
    hardware_id: str,
    safety_acknowledged: bool,
) -> None:
    if not safety_acknowledged:
        raise EdgeError("safety_acknowledgement_required")
    begin_write(connection)
    now = utc_now()
    connection.execute(
        """
        INSERT INTO gates (
          id, name, site_area, provider, interface_type, operator_class,
          hardware_id, safety_acknowledged, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name = excluded.name,
          site_area = excluded.site_area,
          provider = excluded.provider,
          interface_type = excluded.interface_type,
          operator_class = excluded.operator_class,
          hardware_id = excluded.hardware_id,
          safety_acknowledged = excluded.safety_acknowledged,
          updated_at = excluded.updated_at
        """,
        (
            gate_id,
            name,
            site_area,
            provider,
            interface_type,
            operator_class,
            hardware_id,
            1,
            now,
            now,
        ),
    )
    append_event(
        connection,
        event_type="configuration",
        reason="gate_upserted",
        gate_id=gate_id,
        extra={"name": name, "provider": provider, "interface_type": interface_type},
    )
    connection.commit()


def add_credential(
    connection: sqlite3.Connection,
    *,
    credential_id: str,
    principal_id: str,
    principal_label: str,
    principal_type: str,
    credential_type: str,
    credential_value: str,
    gate_scope: list[str],
    valid_from: str | None = None,
    valid_until: str | None = None,
    max_uses: int | None = None,
    confidence_threshold: float | None = None,
    source_version: str | None = None,
) -> None:
    if credential_type not in {"pin", "plate"}:
        raise EdgeError("credential_type_must_be_pin_or_plate")
    if not gate_scope:
        raise EdgeError("gate_scope_required")
    begin_write(connection)
    now = utc_now()
    start = valid_from or now
    connection.execute(
        """
        INSERT INTO credentials (
          id, principal_id, principal_label, principal_type, credential_type,
          credential_hash, credential_display, status, gate_scope_json, valid_from,
          valid_until, max_uses, confidence_threshold, source_version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          principal_id = excluded.principal_id,
          principal_label = excluded.principal_label,
          principal_type = excluded.principal_type,
          credential_type = excluded.credential_type,
          credential_hash = excluded.credential_hash,
          credential_display = excluded.credential_display,
          status = 'active',
          gate_scope_json = excluded.gate_scope_json,
          valid_from = excluded.valid_from,
          valid_until = excluded.valid_until,
          max_uses = excluded.max_uses,
          confidence_threshold = excluded.confidence_threshold,
          source_version = excluded.source_version,
          updated_at = excluded.updated_at,
          revoked_at = NULL,
          revoked_reason = NULL
        """,
        (
            credential_id,
            principal_id,
            principal_label,
            principal_type,
            credential_type,
            credential_hash(credential_type, credential_value),
            mask_credential(credential_type, credential_value),
            canonical_json({"gates": gate_scope}),
            start,
            valid_until,
            max_uses,
            confidence_threshold,
            source_version,
            now,
            now,
        ),
    )
    append_event(
        connection,
        event_type="configuration",
        reason="credential_upserted",
        principal_id=principal_id,
        principal_label=principal_label,
        credential_id=credential_id,
        credential_type=credential_type,
        extra={"principal_type": principal_type, "gate_scope": gate_scope},
    )
    connection.commit()


def revoke_credential(
    connection: sqlite3.Connection,
    *,
    credential_id: str,
    reason: str,
    source_created_at: str | None = None,
) -> None:
    begin_write(connection)
    now = utc_now()
    cursor = connection.execute(
        """
        UPDATE credentials
        SET status = 'revoked', revoked_at = ?, revoked_reason = ?, updated_at = ?
        WHERE id = ?
        """,
        (now, reason, now, credential_id),
    )
    if cursor.rowcount == 0:
        raise EdgeError("credential_not_found")
    record_revocation_latency(connection, source_created_at)
    append_event(
        connection,
        event_type="revocation",
        reason=reason,
        credential_id=credential_id,
        extra={"source_created_at": source_created_at},
    )
    connection.commit()


def add_qr_public_key(connection: sqlite3.Connection, *, key_id: str, public_key_pem: str) -> None:
    begin_write(connection)
    now = utc_now()
    connection.execute(
        """
        INSERT INTO qr_public_keys (key_id, public_key_pem, active, created_at)
        VALUES (?, ?, 1, ?)
        ON CONFLICT(key_id) DO UPDATE SET public_key_pem = excluded.public_key_pem, active = 1
        """,
        (key_id, public_key_pem, now),
    )
    append_event(
        connection,
        event_type="configuration",
        reason="qr_public_key_upserted",
        extra={"key_id": key_id},
    )
    connection.commit()


def revoke_qr_token(
    connection: sqlite3.Connection,
    *,
    token_id: str,
    reason: str,
    source_created_at: str | None = None,
) -> None:
    begin_write(connection)
    now = utc_now()
    connection.execute(
        """
        INSERT INTO revoked_qr_tokens (token_id, reason, created_at, source_created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(token_id) DO UPDATE SET reason = excluded.reason
        """,
        (token_id, reason, now, source_created_at),
    )
    record_revocation_latency(connection, source_created_at)
    append_event(
        connection,
        event_type="revocation",
        reason=reason,
        credential_id=token_id,
        credential_type="qr",
        extra={"source_created_at": source_created_at},
    )
    connection.commit()


def authorize(
    connection: sqlite3.Connection,
    *,
    credential_type: str,
    credential_value: str,
    gate_id: str,
    confidence: float | None = None,
    media: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    begin_write(connection)
    if gate_exists(connection, gate_id) is False:
        return deny_and_log(
            connection,
            credential_type=credential_type,
            gate_id=gate_id,
            reason="gate_not_configured",
            confidence=confidence,
            request=request,
            media=media,
            fallback_required=False,
        )

    if credential_type == "qr":
        return authorize_qr(connection, credential_value=credential_value, gate_id=gate_id, media=media, request=request)

    if credential_type not in {"pin", "plate"}:
        return deny_and_log(
            connection,
            credential_type=credential_type,
            gate_id=gate_id,
            reason="unsupported_credential_type",
            confidence=confidence,
            request=request,
            media=media,
            fallback_required=False,
        )

    row = connection.execute(
        """
        SELECT * FROM credentials
        WHERE credential_type = ? AND credential_hash = ? AND status = 'active'
        ORDER BY updated_at DESC
        LIMIT 1
        """,
        (credential_type, credential_hash(credential_type, credential_value)),
    ).fetchone()
    if row is None:
        fallback = credential_type == "plate" and (confidence is None or confidence < 0.85)
        return deny_and_log(
            connection,
            credential_type=credential_type,
            gate_id=gate_id,
            reason="credential_not_found",
            confidence=confidence,
            request=request,
            media=media,
            fallback_required=fallback,
        )

    if not gate_in_scope(row["gate_scope_json"], gate_id):
        return deny_and_log(
            connection,
            credential_type=credential_type,
            gate_id=gate_id,
            reason="gate_not_in_credential_scope",
            principal_id=row["principal_id"],
            principal_label=row["principal_label"],
            credential_id=row["id"],
            confidence=confidence,
            request=request,
            media=media,
            fallback_required=False,
        )

    time_reason = credential_time_reason(row)
    if time_reason:
        return deny_and_log(
            connection,
            credential_type=credential_type,
            gate_id=gate_id,
            reason=time_reason,
            principal_id=row["principal_id"],
            principal_label=row["principal_label"],
            credential_id=row["id"],
            confidence=confidence,
            request=request,
            media=media,
            fallback_required=False,
        )

    if row["max_uses"] is not None and int(row["use_count"]) >= int(row["max_uses"]):
        return deny_and_log(
            connection,
            credential_type=credential_type,
            gate_id=gate_id,
            reason="credential_use_limit_reached",
            principal_id=row["principal_id"],
            principal_label=row["principal_label"],
            credential_id=row["id"],
            confidence=confidence,
            request=request,
            media=media,
            fallback_required=False,
        )

    if credential_type == "plate":
        threshold = float(row["confidence_threshold"] if row["confidence_threshold"] is not None else 0.85)
        if confidence is None:
            return deny_and_log(
                connection,
                credential_type=credential_type,
                gate_id=gate_id,
                reason="plate_confidence_missing",
                principal_id=row["principal_id"],
                principal_label=row["principal_label"],
                credential_id=row["id"],
                confidence=confidence,
                request=request,
                media=media,
                fallback_required=True,
            )
        if confidence < threshold:
            return deny_and_log(
                connection,
                credential_type=credential_type,
                gate_id=gate_id,
                reason="plate_confidence_below_threshold",
                principal_id=row["principal_id"],
                principal_label=row["principal_label"],
                credential_id=row["id"],
                confidence=confidence,
                request=request,
                media=media,
                fallback_required=True,
            )

    connection.execute(
        "UPDATE credentials SET use_count = use_count + 1, updated_at = ? WHERE id = ?",
        (utc_now(), row["id"]),
    )
    event = append_event(
        connection,
        event_type="access_attempt",
        principal_id=row["principal_id"],
        principal_label=row["principal_label"],
        credential_id=row["id"],
        credential_type=credential_type,
        gate_id=gate_id,
        decision="allow",
        reason="authorized",
        confidence=confidence,
        request=request or {"credential_type": credential_type, "gate_id": gate_id},
        media=media or {},
        extra={"relay_intent": "authorized_local_decision"},
    )
    connection.commit()
    return decision_response("allow", "authorized", event, fallback_required=False)


def authorize_qr(
    connection: sqlite3.Connection,
    *,
    credential_value: str,
    gate_id: str,
    media: dict[str, Any] | None,
    request: dict[str, Any] | None,
) -> dict[str, Any]:
    public_keys = {
        row["key_id"]: row["public_key_pem"]
        for row in connection.execute("SELECT key_id, public_key_pem FROM qr_public_keys WHERE active = 1")
    }
    try:
        token = verify_token(credential_value, public_keys)
    except TokenError as exc:
        return deny_and_log(
            connection,
            credential_type="qr",
            gate_id=gate_id,
            reason=str(exc),
            request=request,
            media=media,
            fallback_required=True,
        )

    payload = token.payload
    token_id = str(payload["token_id"])
    if not gate_allowed(payload["gate_scope"], gate_id):
        return deny_and_log(
            connection,
            credential_type="qr",
            gate_id=gate_id,
            reason="gate_not_in_token_scope",
            credential_id=token_id,
            principal_id=str(payload["principal_id"]),
            principal_label=str(payload["principal_label"]),
            request=request,
            media=media,
            fallback_required=False,
        )
    if connection.execute("SELECT 1 FROM revoked_qr_tokens WHERE token_id = ?", (token_id,)).fetchone():
        return deny_and_log(
            connection,
            credential_type="qr",
            gate_id=gate_id,
            reason="qr_token_revoked",
            credential_id=token_id,
            principal_id=str(payload["principal_id"]),
            principal_label=str(payload["principal_label"]),
            request=request,
            media=media,
            fallback_required=True,
        )

    max_uses = payload.get("max_uses")
    usage = get_qr_usage(connection, token_id)
    if max_uses is not None and usage >= int(max_uses):
        return deny_and_log(
            connection,
            credential_type="qr",
            gate_id=gate_id,
            reason="qr_token_use_limit_reached",
            credential_id=token_id,
            principal_id=str(payload["principal_id"]),
            principal_label=str(payload["principal_label"]),
            request=request,
            media=media,
            fallback_required=False,
        )

    set_qr_usage(connection, token_id, usage + 1)
    event = append_event(
        connection,
        event_type="access_attempt",
        principal_id=str(payload["principal_id"]),
        principal_label=str(payload["principal_label"]),
        credential_id=token_id,
        credential_type="qr",
        gate_id=gate_id,
        decision="allow",
        reason="authorized_signed_qr",
        request=request or {"credential_type": "qr", "gate_id": gate_id},
        media=media or {},
        extra={"key_id": token.header["kid"], "relay_intent": "authorized_local_decision"},
    )
    connection.commit()
    return decision_response("allow", "authorized_signed_qr", event, fallback_required=False)


def deny_and_log(
    connection: sqlite3.Connection,
    *,
    credential_type: str,
    gate_id: str,
    reason: str,
    principal_id: str | None = None,
    principal_label: str | None = None,
    credential_id: str | None = None,
    confidence: float | None = None,
    request: dict[str, Any] | None = None,
    media: dict[str, Any] | None = None,
    fallback_required: bool = False,
) -> dict[str, Any]:
    event = append_event(
        connection,
        event_type="access_attempt",
        principal_id=principal_id,
        principal_label=principal_label,
        credential_id=credential_id,
        credential_type=credential_type,
        gate_id=gate_id,
        decision="deny",
        reason=reason,
        confidence=confidence,
        fallback_required=fallback_required,
        request=request or {"credential_type": credential_type, "gate_id": gate_id},
        media=media or {},
    )
    connection.commit()
    return decision_response("deny", reason, event, fallback_required=fallback_required)


def append_event(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    reason: str,
    principal_id: str | None = None,
    principal_label: str | None = None,
    credential_id: str | None = None,
    credential_type: str | None = None,
    gate_id: str | None = None,
    decision: str | None = None,
    confidence: float | None = None,
    fallback_required: bool = False,
    request: dict[str, Any] | None = None,
    media: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    occurred_at = utc_now()
    previous = connection.execute("SELECT sequence, event_hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
    previous_hash = previous["event_hash"] if previous else ZERO_HASH
    sequence_hint = connection.execute("SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM events").fetchone()["next_sequence"]
    event_id = f"evt_{int(time.time() * 1000)}_{sequence_hint}"
    request_json = canonical_json(request or {})
    media_json = canonical_json(media or {})
    extra_json = canonical_json(extra or {})
    payload = build_event_payload(
        sequence=sequence_hint,
        event_id=event_id,
        occurred_at=occurred_at,
        event_type=event_type,
        principal_id=principal_id,
        principal_label=principal_label,
        credential_id=credential_id,
        credential_type=credential_type,
        gate_id=gate_id,
        decision=decision,
        reason=reason,
        confidence=confidence,
        fallback_required=bool(fallback_required),
        request_json=request_json,
        media_json=media_json,
        extra_json=extra_json,
        previous_hash=previous_hash,
    )
    event_hash = hash_event_payload(previous_hash, payload)
    connection.execute(
        """
        INSERT INTO events (
          sequence, event_id, occurred_at, event_type, principal_id, principal_label,
          credential_id, credential_type, gate_id, decision, reason, confidence,
          fallback_required, request_json, media_json, extra_json,
          previous_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sequence_hint,
            event_id,
            occurred_at,
            event_type,
            principal_id,
            principal_label,
            credential_id,
            credential_type,
            gate_id,
            decision,
            reason,
            confidence,
            1 if fallback_required else 0,
            request_json,
            media_json,
            extra_json,
            previous_hash,
            event_hash,
        ),
    )
    return {"event_id": event_id, "event_hash": event_hash, "occurred_at": occurred_at, "sequence": sequence_hint}


def verify_event_log(connection: sqlite3.Connection) -> dict[str, Any]:
    previous_hash = ZERO_HASH
    checked = 0
    last_sequence = 0
    for row in connection.execute("SELECT * FROM events ORDER BY sequence ASC"):
        if checked == 0:
            genesis_error = validate_genesis_row(row)
            if genesis_error:
                return {"ok": False, "checked": checked, "failed_sequence": row["sequence"], "error": genesis_error}
        payload = build_event_payload(
            sequence=row["sequence"],
            event_id=row["event_id"],
            occurred_at=row["occurred_at"],
            event_type=row["event_type"],
            principal_id=row["principal_id"],
            principal_label=row["principal_label"],
            credential_id=row["credential_id"],
            credential_type=row["credential_type"],
            gate_id=row["gate_id"],
            decision=row["decision"],
            reason=row["reason"],
            confidence=row["confidence"],
            fallback_required=bool(row["fallback_required"]),
            request_json=row["request_json"],
            media_json=row["media_json"],
            extra_json=row["extra_json"],
            previous_hash=row["previous_hash"],
        )
        expected_hash = hash_event_payload(previous_hash, payload)
        if row["previous_hash"] != previous_hash or row["event_hash"] != expected_hash:
            return {
                "ok": False,
                "checked": checked,
                "failed_sequence": row["sequence"],
                "expected_previous_hash": previous_hash,
                "actual_previous_hash": row["previous_hash"],
                "expected_event_hash": expected_hash,
                "actual_event_hash": row["event_hash"],
            }
        previous_hash = row["event_hash"]
        last_sequence = row["sequence"]
        checked += 1

    if checked == 0:
        return {"ok": False, "checked": 0, "error": "missing_genesis_event"}

    anchor_check = verify_latest_anchor(connection, last_sequence)
    if not anchor_check["ok"]:
        return {"ok": False, "checked": checked, **anchor_check}

    return {"ok": True, "checked": checked, "head_hash": previous_hash, "head_sequence": last_sequence, **anchor_check}


def validate_genesis_row(row: sqlite3.Row) -> str | None:
    if row["sequence"] != GENESIS_SEQUENCE:
        return "genesis_sequence_mismatch"
    if row["event_id"] != GENESIS_EVENT_ID:
        return "genesis_event_id_mismatch"
    if row["occurred_at"] != GENESIS_OCCURRED_AT:
        return "genesis_timestamp_mismatch"
    if row["event_type"] != "genesis" or row["reason"] != GENESIS_REASON:
        return "genesis_payload_mismatch"
    if row["previous_hash"] != ZERO_HASH:
        return "genesis_previous_hash_mismatch"
    return None


def verify_latest_anchor(connection: sqlite3.Connection, last_sequence: int) -> dict[str, Any]:
    anchor = connection.execute(
        "SELECT * FROM event_anchors ORDER BY sequence DESC, anchored_at DESC LIMIT 1"
    ).fetchone()
    if anchor is None:
        return {"ok": True, "latest_anchor": None}
    if int(anchor["sequence"]) > last_sequence:
        return {
            "ok": False,
            "error": "event_log_truncated_below_latest_anchor",
            "anchor_sequence": anchor["sequence"],
            "head_sequence": last_sequence,
        }
    row = connection.execute("SELECT event_hash FROM events WHERE sequence = ?", (anchor["sequence"],)).fetchone()
    if row is None:
        return {
            "ok": False,
            "error": "anchored_event_missing",
            "anchor_sequence": anchor["sequence"],
            "anchor_hash": anchor["event_hash"],
        }
    if row["event_hash"] != anchor["event_hash"]:
        return {
            "ok": False,
            "error": "anchor_hash_mismatch",
            "anchor_sequence": anchor["sequence"],
            "anchor_hash": anchor["event_hash"],
            "actual_hash": row["event_hash"],
        }
    return {
        "ok": True,
        "latest_anchor": {
            "anchor_id": anchor["anchor_id"],
            "anchor_type": anchor["anchor_type"],
            "sequence": anchor["sequence"],
            "event_hash": anchor["event_hash"],
            "anchored_at": anchor["anchored_at"],
            "upstream_ref": anchor["upstream_ref"],
        },
    }


def list_events(connection: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM events ORDER BY sequence DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_events_after(connection: sqlite3.Connection, sequence: int, limit: int = 50) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM events WHERE sequence > ? ORDER BY sequence ASC LIMIT ?",
        (sequence, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def current_head(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        "SELECT sequence, event_id, event_hash, occurred_at FROM events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return {"sequence": 0, "event_id": None, "event_hash": ZERO_HASH, "occurred_at": None}
    return dict(row)


def create_event_anchor(
    connection: sqlite3.Connection,
    *,
    anchor_type: str = "cloud_pending",
    upstream_ref: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    begin_write(connection)
    head = current_head(connection)
    anchor_id = f"anchor_{uuid.uuid4()}"
    anchored_at = utc_now()
    connection.execute(
        """
        INSERT INTO event_anchors (
          anchor_id, anchor_type, sequence, event_hash, anchored_at, upstream_ref, extra_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            anchor_id,
            anchor_type,
            head["sequence"],
            head["event_hash"],
            anchored_at,
            upstream_ref,
            canonical_json(extra or {}),
        ),
    )
    connection.commit()
    return {
        "anchor_id": anchor_id,
        "anchor_type": anchor_type,
        "sequence": head["sequence"],
        "event_id": head["event_id"],
        "event_hash": head["event_hash"],
        "anchored_at": anchored_at,
        "upstream_ref": upstream_ref,
    }


def sync_status(connection: sqlite3.Connection) -> dict[str, Any]:
    unsynced = connection.execute("SELECT COUNT(*) AS count FROM events WHERE queued_for_sync = 1 AND synced_at IS NULL").fetchone()["count"]
    credentials = connection.execute("SELECT COUNT(*) AS count FROM credentials WHERE status = 'active'").fetchone()["count"]
    gates = connection.execute("SELECT COUNT(*) AS count FROM gates").fetchone()["count"]
    head = current_head(connection)
    latest_anchor = verify_latest_anchor(connection, int(head["sequence"]))
    return {
        "edge_id": get_metadata(connection, "edge_id"),
        "revocation_target_seconds": int(get_metadata(connection, "revocation_target_seconds") or DEFAULT_REVOCATION_TARGET_SECONDS),
        "last_delta_at": get_metadata(connection, "last_delta_at"),
        "last_revocation_latency_ms": get_metadata(connection, "last_revocation_latency_ms"),
        "unsynced_events": unsynced,
        "cached_active_credentials": credentials,
        "configured_gates": gates,
        "offline_authorization_ready": gates > 0,
        "head_sequence": head["sequence"],
        "head_hash": head["event_hash"],
        "latest_anchor": latest_anchor.get("latest_anchor"),
    }


def mark_events_synced(connection: sqlite3.Connection, through_sequence: int | None = None) -> None:
    begin_write(connection)
    now = utc_now()
    if through_sequence is None:
        connection.execute(
            "UPDATE events SET queued_for_sync = 0, synced_at = ? WHERE queued_for_sync = 1 AND synced_at IS NULL",
            (now,),
        )
    else:
        connection.execute(
            "UPDATE events SET queued_for_sync = 0, synced_at = ? WHERE queued_for_sync = 1 AND synced_at IS NULL AND sequence <= ?",
            (now, through_sequence),
        )
    connection.commit()


def apply_delta(connection: sqlite3.Connection, delta: dict[str, Any]) -> dict[str, Any]:
    applied = {"gates": 0, "credentials": 0, "credential_revocations": 0, "qr_public_keys": 0, "qr_token_revocations": 0}
    for gate in delta.get("gates", []):
        add_gate(connection, safety_acknowledged=bool(gate.get("safety_acknowledged")), **{key: gate[key] for key in ["gate_id", "name", "site_area", "provider", "interface_type", "operator_class", "hardware_id"]})
        applied["gates"] += 1
    for credential in delta.get("credentials", []):
        add_credential(connection, **credential)
        applied["credentials"] += 1
    for revocation in delta.get("credential_revocations", []):
        revoke_credential(connection, **revocation)
        applied["credential_revocations"] += 1
    for key in delta.get("qr_public_keys", []):
        add_qr_public_key(connection, **key)
        applied["qr_public_keys"] += 1
    for revocation in delta.get("qr_token_revocations", []):
        revoke_qr_token(connection, **revocation)
        applied["qr_token_revocations"] += 1
    begin_write(connection)
    set_metadata(connection, "last_delta_at", utc_now())
    if "sync_cursor" in delta:
        set_metadata(connection, "sync_cursor", str(delta["sync_cursor"]))
    connection.commit()
    return applied


def decision_response(decision: str, reason: str, event: dict[str, Any], *, fallback_required: bool) -> dict[str, Any]:
    return {
        "decision": decision,
        "reason": reason,
        "fallback_required": fallback_required,
        "relay_intent": decision == "allow",
        "event_id": event["event_id"],
        "event_hash": event["event_hash"],
        "occurred_at": event["occurred_at"],
    }


def gate_exists(connection: sqlite3.Connection, gate_id: str) -> bool:
    return connection.execute("SELECT 1 FROM gates WHERE id = ?", (gate_id,)).fetchone() is not None


def gate_in_scope(scope_json: str, gate_id: str) -> bool:
    try:
        scope = json.loads(scope_json).get("gates", [])
    except json.JSONDecodeError:
        return False
    return gate_allowed(scope, gate_id)


def gate_allowed(scope: list[Any], gate_id: str) -> bool:
    normalized = [str(item) for item in scope]
    return "*" in normalized or gate_id in normalized


def credential_time_reason(row: sqlite3.Row) -> str | None:
    now = datetime.now(UTC)
    valid_from = parse_time(row["valid_from"])
    valid_until = parse_time(row["valid_until"])
    if valid_from and now < valid_from:
        return "credential_not_yet_valid"
    if valid_until and now > valid_until:
        return "credential_expired"
    return None


def get_qr_usage(connection: sqlite3.Connection, token_id: str) -> int:
    row = connection.execute("SELECT use_count FROM qr_token_usage WHERE token_id = ?", (token_id,)).fetchone()
    return 0 if row is None else int(row["use_count"])


def set_qr_usage(connection: sqlite3.Connection, token_id: str, use_count: int) -> None:
    connection.execute(
        """
        INSERT INTO qr_token_usage (token_id, use_count, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(token_id) DO UPDATE SET use_count = excluded.use_count, updated_at = excluded.updated_at
        """,
        (token_id, use_count, utc_now()),
    )


def record_revocation_latency(connection: sqlite3.Connection, source_created_at: str | None) -> None:
    if not source_created_at:
        return
    source_time = parse_time(source_created_at)
    if source_time is None:
        return
    latency_ms = int((datetime.now(UTC) - source_time).total_seconds() * 1000)
    set_metadata(connection, "last_revocation_latency_ms", str(max(latency_ms, 0)))
