"""Cloud-side binding registry helpers for SD-card-loss rebinds."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .commissioning import sign_binding_payload
from .store import canonical_json, utc_now


class RebindError(RuntimeError):
    """Binding registry or rebind error."""


def connect(db_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path), timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def migrate(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS cloud_bindings (
          binding_id TEXT PRIMARY KEY,
          property_id TEXT NOT NULL,
          property_label TEXT NOT NULL,
          gate_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('active', 'superseded', 'revoked')),
          bootstrap_nonce TEXT,
          event_history_ref TEXT,
          superseded_by_binding_id TEXT,
          superseded_at TEXT,
          payload_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_bindings_active_slot
          ON cloud_bindings (property_id, gate_id)
          WHERE status = 'active';

        CREATE INDEX IF NOT EXISTS idx_cloud_bindings_device
          ON cloud_bindings (device_id);

        CREATE TABLE IF NOT EXISTS cloud_binding_events (
          event_id TEXT PRIMARY KEY,
          binding_id TEXT NOT NULL,
          event_type TEXT NOT NULL,
          occurred_at TEXT NOT NULL,
          payload_json TEXT NOT NULL
        );
        """
    )
    connection.commit()


def register_binding(
    connection: sqlite3.Connection,
    *,
    payload: dict[str, Any],
    event_history_ref: str | None = None,
) -> dict[str, Any]:
    required = ["binding_id", "property_id", "gate_id", "device_id"]
    missing = [field for field in required if not payload.get(field)]
    if missing:
        raise RebindError("binding_payload_missing_" + "_".join(missing))
    now = utc_now()
    binding_id = str(payload["binding_id"])
    connection.execute(
        """
        INSERT INTO cloud_bindings (
          binding_id, property_id, property_label, gate_id, device_id, status,
          bootstrap_nonce, event_history_ref, payload_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
        """,
        (
            binding_id,
            str(payload["property_id"]),
            str(payload.get("property_label") or ""),
            str(payload["gate_id"]),
            str(payload["device_id"]),
            str(payload.get("bootstrap_nonce") or ""),
            event_history_ref,
            canonical_json(payload),
            now,
            now,
        ),
    )
    record_binding_event(
        connection,
        binding_id=binding_id,
        event_type="binding_registered",
        payload={"event_history_ref": event_history_ref},
    )
    connection.commit()
    return binding_to_dict(active_binding_for_slot(connection, property_id=str(payload["property_id"]), gate_id=str(payload["gate_id"])))


def create_rebind_artifact(
    connection: sqlite3.Connection,
    *,
    cloud_private_key: Ed25519PrivateKey,
    new_device_id: str,
    new_bootstrap_nonce: str,
    property_id: str,
    gate_id: str,
    property_label: str,
    reason: str,
    preserved_history_ref: str,
    api_tokens: list[dict[str, Any]] | None = None,
    binding_id: str | None = None,
    issued_at: str | None = None,
) -> dict[str, Any]:
    old = active_binding_for_slot(connection, property_id=property_id, gate_id=gate_id)
    if old is None:
        raise RebindError("active_binding_not_found_for_slot")
    if old["device_id"] == new_device_id:
        raise RebindError("rebind_requires_new_device_identity")

    now = utc_now()
    new_binding_id = binding_id or f"binding_{uuid.uuid4()}"
    rebind_id = f"rebind_{uuid.uuid4()}"
    payload = {
        "binding_id": new_binding_id,
        "device_id": new_device_id,
        "bootstrap_nonce": new_bootstrap_nonce,
        "property_id": property_id,
        "property_label": property_label,
        "gate_id": gate_id,
        "issued_at": issued_at or now,
        "status": "claimed_pending_cloud",
        "api_tokens": api_tokens or [],
        "rebind": {
            "rebind_id": rebind_id,
            "replaces_binding_id": old["binding_id"],
            "replaces_device_id": old["device_id"],
            "preserved_history_ref": preserved_history_ref,
            "reason": reason,
        },
    }

    connection.execute(
        """
        UPDATE cloud_bindings
        SET status = 'superseded',
            superseded_by_binding_id = ?,
            superseded_at = ?,
            event_history_ref = COALESCE(event_history_ref, ?),
            updated_at = ?
        WHERE binding_id = ? AND status = 'active'
        """,
        (new_binding_id, now, preserved_history_ref, now, old["binding_id"]),
    )
    connection.execute(
        """
        INSERT INTO cloud_bindings (
          binding_id, property_id, property_label, gate_id, device_id, status,
          bootstrap_nonce, event_history_ref, payload_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
        """,
        (
            new_binding_id,
            property_id,
            property_label,
            gate_id,
            new_device_id,
            new_bootstrap_nonce,
            preserved_history_ref,
            canonical_json(payload),
            now,
            now,
        ),
    )
    record_binding_event(
        connection,
        binding_id=old["binding_id"],
        event_type="binding_superseded",
        payload={
            "superseded_by_binding_id": new_binding_id,
            "new_device_id": new_device_id,
            "preserved_history_ref": preserved_history_ref,
            "reason": reason,
        },
    )
    record_binding_event(
        connection,
        binding_id=new_binding_id,
        event_type="rebind_created",
        payload=payload["rebind"],
    )
    connection.commit()
    return sign_binding_payload(cloud_private_key, payload)


def active_binding_for_slot(connection: sqlite3.Connection, *, property_id: str, gate_id: str) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT *
        FROM cloud_bindings
        WHERE property_id = ? AND gate_id = ? AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (property_id, gate_id),
    ).fetchone()


def binding_by_id(connection: sqlite3.Connection, binding_id: str) -> dict[str, Any] | None:
    row = connection.execute("SELECT * FROM cloud_bindings WHERE binding_id = ?", (binding_id,)).fetchone()
    return None if row is None else binding_to_dict(row)


def record_binding_event(
    connection: sqlite3.Connection,
    *,
    binding_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    connection.execute(
        """
        INSERT INTO cloud_binding_events (event_id, binding_id, event_type, occurred_at, payload_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (f"cbe_{uuid.uuid4()}", binding_id, event_type, utc_now(), canonical_json(payload)),
    )


def binding_to_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise RebindError("binding_not_found")
    return {
        "binding_id": row["binding_id"],
        "property_id": row["property_id"],
        "property_label": row["property_label"],
        "gate_id": row["gate_id"],
        "device_id": row["device_id"],
        "status": row["status"],
        "bootstrap_nonce": row["bootstrap_nonce"],
        "event_history_ref": row["event_history_ref"],
        "superseded_by_binding_id": row["superseded_by_binding_id"],
        "superseded_at": row["superseded_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
