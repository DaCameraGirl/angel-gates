"""Append-only cloud witness storage for edge event-log anchors."""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import uuid
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import store

HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class WitnessError(RuntimeError):
    """Witness storage error."""


class WitnessForkError(WitnessError):
    """Anchor would fork or rewind an already witnessed edge stream."""


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
        CREATE TABLE IF NOT EXISTS witness_anchors (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          witness_anchor_id TEXT NOT NULL UNIQUE,
          edge_id TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          event_id TEXT,
          event_hash TEXT NOT NULL,
          occurred_at TEXT,
          previous_witness_sequence INTEGER,
          previous_witness_hash TEXT,
          reason_json TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          received_at TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_witness_edge_sequence
          ON witness_anchors (edge_id, sequence);

        CREATE INDEX IF NOT EXISTS idx_witness_edge_latest
          ON witness_anchors (edge_id, sequence DESC, id DESC);
        """
    )
    connection.commit()


def record_anchor(connection: sqlite3.Connection, payload: dict[str, Any]) -> dict[str, Any]:
    anchor = normalize_anchor_payload(payload)
    latest = latest_anchor(connection, anchor["edge_id"])
    existing = anchor_at_sequence(connection, anchor["edge_id"], anchor["sequence"])
    if existing is not None:
        if existing["event_hash"] != anchor["event_hash"]:
            raise WitnessForkError("anchor_fork_at_sequence")
        return {"accepted": False, "duplicate": True, "anchor": row_to_anchor(existing)}

    if latest is not None:
        latest_sequence = int(latest["sequence"])
        if anchor["sequence"] < latest_sequence:
            raise WitnessForkError("anchor_sequence_below_witnessed_head")
        if anchor["previous_witness_sequence"] != latest_sequence or anchor["previous_witness_hash"] != latest["event_hash"]:
            raise WitnessForkError("anchor_previous_witness_mismatch")
    elif anchor["previous_witness_sequence"] not in (None, 0) or anchor["previous_witness_hash"] not in (None, "", store.ZERO_HASH):
        raise WitnessForkError("first_anchor_previous_witness_mismatch")

    witness_anchor_id = f"wit_{uuid.uuid4()}"
    received_at = store.utc_now()
    connection.execute(
        """
        INSERT INTO witness_anchors (
          witness_anchor_id, edge_id, sequence, event_id, event_hash, occurred_at,
          previous_witness_sequence, previous_witness_hash, reason_json, payload_json, received_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            witness_anchor_id,
            anchor["edge_id"],
            anchor["sequence"],
            anchor["event_id"],
            anchor["event_hash"],
            anchor["occurred_at"],
            anchor["previous_witness_sequence"],
            anchor["previous_witness_hash"],
            store.canonical_json({"reasons": anchor["reasons"]}),
            store.canonical_json(payload),
            received_at,
        ),
    )
    connection.commit()
    row = connection.execute(
        "SELECT * FROM witness_anchors WHERE witness_anchor_id = ?",
        (witness_anchor_id,),
    ).fetchone()
    return {"accepted": True, "duplicate": False, "anchor": row_to_anchor(row)}


def normalize_anchor_payload(payload: dict[str, Any]) -> dict[str, Any]:
    edge_id = str(payload.get("edge_id") or "").strip()
    if not edge_id:
        raise WitnessError("edge_id_required")
    sequence = int(payload.get("sequence") or 0)
    if sequence < store.GENESIS_SEQUENCE:
        raise WitnessError("sequence_must_be_positive")
    event_hash = str(payload.get("event_hash") or "").lower()
    if HASH_RE.match(event_hash) is None:
        raise WitnessError("event_hash_must_be_sha256_hex")
    previous_sequence = payload.get("previous_witness_sequence")
    if previous_sequence in ("", None):
        previous_sequence = None
    else:
        previous_sequence = int(previous_sequence)
    previous_hash = payload.get("previous_witness_hash")
    if previous_hash in ("", None):
        previous_hash = None
    else:
        previous_hash = str(previous_hash).lower()
        if HASH_RE.match(previous_hash) is None:
            raise WitnessError("previous_witness_hash_must_be_sha256_hex")
    reasons = payload.get("reasons") or []
    if not isinstance(reasons, list):
        raise WitnessError("reasons_must_be_list")
    return {
        "edge_id": edge_id,
        "sequence": sequence,
        "event_id": str(payload.get("event_id") or ""),
        "event_hash": event_hash,
        "occurred_at": payload.get("occurred_at"),
        "previous_witness_sequence": previous_sequence,
        "previous_witness_hash": previous_hash,
        "reasons": [str(reason) for reason in reasons],
    }


def latest_anchor(connection: sqlite3.Connection, edge_id: str) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT *
        FROM witness_anchors
        WHERE edge_id = ?
        ORDER BY sequence DESC, id DESC
        LIMIT 1
        """,
        (edge_id,),
    ).fetchone()


def anchor_at_sequence(connection: sqlite3.Connection, edge_id: str, sequence: int) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM witness_anchors WHERE edge_id = ? AND sequence = ?",
        (edge_id, int(sequence)),
    ).fetchone()


def list_anchors(connection: sqlite3.Connection, *, edge_id: str, limit: int = 50) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT *
        FROM witness_anchors
        WHERE edge_id = ?
        ORDER BY sequence DESC
        LIMIT ?
        """,
        (edge_id, int(limit)),
    ).fetchall()
    return [row_to_anchor(row) for row in rows]


def row_to_anchor(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise WitnessError("anchor_not_found")
    return {
        "witness_anchor_id": row["witness_anchor_id"],
        "edge_id": row["edge_id"],
        "sequence": int(row["sequence"]),
        "event_id": row["event_id"],
        "event_hash": row["event_hash"],
        "occurred_at": row["occurred_at"],
        "previous_witness_sequence": row["previous_witness_sequence"],
        "previous_witness_hash": row["previous_witness_hash"],
        "reasons": json.loads(row["reason_json"]).get("reasons", []),
        "received_at": row["received_at"],
    }


def run_witness_service(db_path: str, host: str, port: int, *, token: str) -> None:
    if not token:
        raise WitnessError("witness_service_token_required")
    with closing(connect(db_path)) as connection:
        migrate(connection)

    class Handler(BaseHTTPRequestHandler):
        server_version = "AngelWitness/0.1"

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/anchors":
                self.send_json(404, {"error": "not_found"})
                return
            if not self.authorized():
                self.send_json(401, {"error": "unauthorized"})
                return
            try:
                payload = self.read_json()
                with closing(connect(db_path)) as connection:
                    migrate(connection)
                    result = record_anchor(connection, payload)
            except WitnessForkError as exc:
                self.send_json(409, {"ok": False, "error": str(exc)})
                return
            except (WitnessError, ValueError, KeyError, json.JSONDecodeError) as exc:
                self.send_json(400, {"ok": False, "error": str(exc)})
                return
            self.send_json(201 if result["accepted"] else 200, {"ok": True, **result})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path != "/anchors":
                self.send_json(404, {"error": "not_found"})
                return
            if not self.authorized():
                self.send_json(401, {"error": "unauthorized"})
                return
            query = parse_qs(parsed.query)
            edge_id = query.get("edge_id", [""])[0]
            if not edge_id:
                self.send_json(400, {"ok": False, "error": "edge_id_required"})
                return
            limit = bounded_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=250)
            with closing(connect(db_path)) as connection:
                migrate(connection)
                self.send_json(200, {"ok": True, "anchors": list_anchors(connection, edge_id=edge_id, limit=limit)})

        def authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            expected = f"Bearer {token}"
            return secrets.compare_digest(header, expected)

        def read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Angel Witness listening on http://{host}:{port}")
    httpd.serve_forever()


def bounded_int(value: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))
