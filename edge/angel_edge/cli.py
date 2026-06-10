"""Command line interface for the Angel Gates edge runtime."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .crypto_tokens import generate_keypair, load_private_key, sign_token
from .http_api import run_server
from .store import (
    EdgeError,
    add_credential,
    add_gate,
    add_qr_public_key,
    apply_delta,
    authorize,
    connect,
    create_event_anchor,
    list_events,
    mark_events_synced,
    migrate,
    revoke_credential,
    revoke_qr_token,
    sync_status,
    to_epoch,
    verify_event_log,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="angel-edge", description="Angel Gates local edge authorization runtime")
    parser.add_argument("--db", default="edge-data/angel-edge.sqlite3", help="SQLite database path")
    parser.add_argument("--version", action="version", version=f"angel-edge {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize the edge SQLite store")
    init_parser.add_argument("--edge-id", required=True)

    gate_parser = subparsers.add_parser("add-gate", help="Add or update a configured controller")
    gate_parser.add_argument("--gate-id", required=True)
    gate_parser.add_argument("--name", required=True)
    gate_parser.add_argument("--site-area", required=True)
    gate_parser.add_argument("--provider", required=True)
    gate_parser.add_argument("--interface-type", required=True, choices=["dry-contact", "wiegand", "api-callback"])
    gate_parser.add_argument("--operator-class", required=True)
    gate_parser.add_argument("--hardware-id", required=True)
    gate_parser.add_argument("--safety-ack", action="store_true", help="Acknowledge certified operator and safety devices remain untouched")

    credential_parser = subparsers.add_parser("add-credential", help="Add or update a local credential")
    credential_parser.add_argument("--credential-id", required=True)
    credential_parser.add_argument("--principal-id", required=True)
    credential_parser.add_argument("--principal-label", required=True)
    credential_parser.add_argument("--principal-type", required=True, choices=["resident", "visitor", "employee", "service"])
    credential_parser.add_argument("--credential-type", required=True, choices=["pin", "plate"])
    credential_parser.add_argument("--credential-value", required=True)
    credential_parser.add_argument("--gate", action="append", required=True, dest="gate_scope")
    credential_parser.add_argument("--valid-from")
    credential_parser.add_argument("--valid-until")
    credential_parser.add_argument("--max-uses", type=int)
    credential_parser.add_argument("--confidence-threshold", type=float)
    credential_parser.add_argument("--source-version")

    revoke_parser = subparsers.add_parser("revoke-credential", help="Revoke a local credential")
    revoke_parser.add_argument("--credential-id", required=True)
    revoke_parser.add_argument("--reason", required=True)
    revoke_parser.add_argument("--source-created-at")

    auth_parser = subparsers.add_parser("authorize", help="Evaluate a local access attempt")
    auth_parser.add_argument("--credential-type", required=True, choices=["pin", "plate", "qr"])
    auth_parser.add_argument("--credential-value", required=True)
    auth_parser.add_argument("--gate-id", required=True)
    auth_parser.add_argument("--confidence", type=float)
    auth_parser.add_argument("--media-json", default="{}")

    keygen_parser = subparsers.add_parser("generate-keypair", help="Generate an Ed25519 signing keypair")
    keygen_parser.add_argument("--private-key-file", required=True)
    keygen_parser.add_argument("--public-key-file", required=True)

    public_key_parser = subparsers.add_parser("add-qr-public-key", help="Cache a QR token public verification key")
    public_key_parser.add_argument("--key-id", required=True)
    public_key_parser.add_argument("--public-key-file", required=True)

    token_parser = subparsers.add_parser("issue-qr-token", help="Sign a visitor QR token with a cloud/dev private key")
    token_parser.add_argument("--private-key-file", required=True)
    token_parser.add_argument("--key-id", required=True)
    token_parser.add_argument("--token-id", required=True)
    token_parser.add_argument("--principal-id", required=True)
    token_parser.add_argument("--principal-label", required=True)
    token_parser.add_argument("--gate", action="append", required=True, dest="gate_scope")
    token_parser.add_argument("--expires-at", required=True)
    token_parser.add_argument("--not-before")
    token_parser.add_argument("--max-uses", type=int)

    revoke_token_parser = subparsers.add_parser("revoke-qr-token", help="Revoke a signed QR token ID")
    revoke_token_parser.add_argument("--token-id", required=True)
    revoke_token_parser.add_argument("--reason", required=True)
    revoke_token_parser.add_argument("--source-created-at")

    delta_parser = subparsers.add_parser("apply-delta", help="Apply a cloud sync delta JSON file")
    delta_parser.add_argument("--file", required=True)

    subparsers.add_parser("status", help="Show local sync and cache status")
    subparsers.add_parser("verify-log", help="Verify the tamper-evident event hash chain")

    events_parser = subparsers.add_parser("events", help="Print recent events")
    events_parser.add_argument("--limit", type=int, default=20)

    synced_parser = subparsers.add_parser("mark-events-synced", help="Mark queued events as synced")
    synced_parser.add_argument("--through-sequence", type=int)

    serve_parser = subparsers.add_parser("serve", help="Run the local HTTP API")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--api-token", required=True, help="Required bearer token for every local API request")

    anchor_parser = subparsers.add_parser("anchor-head", help="Record the current event-log head for upstream anchoring")
    anchor_parser.add_argument("--anchor-type", default="cloud_pending")
    anchor_parser.add_argument("--upstream-ref")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if args.command == "generate-keypair":
            private_pem, public_pem = generate_keypair()
            Path(args.private_key_file).write_text(private_pem, encoding="utf-8")
            Path(args.public_key_file).write_text(public_pem, encoding="utf-8")
            print_json({"private_key_file": args.private_key_file, "public_key_file": args.public_key_file})
            return 0

        if args.command == "issue-qr-token":
            payload = {
                "token_id": args.token_id,
                "principal_id": args.principal_id,
                "principal_label": args.principal_label,
                "gate_scope": args.gate_scope,
                "exp": to_epoch(args.expires_at),
            }
            if args.not_before:
                payload["nbf"] = to_epoch(args.not_before)
            if args.max_uses is not None:
                payload["max_uses"] = args.max_uses
            token = sign_token(load_private_key(args.private_key_file), args.key_id, payload)
            print_json({"token": token, "payload": payload})
            return 0

        if args.command == "serve":
            run_server(str(db_path), args.host, args.port, args.api_token)
            return 0

        with connect(db_path) as connection:
            if args.command == "init":
                migrate(connection, edge_id=args.edge_id)
                print_json({"ok": True, "db": str(db_path), "edge_id": args.edge_id})
            else:
                migrate(connection)
                run_db_command(connection, args)
        return 0
    except (EdgeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print_json({"ok": False, "error": str(exc)}, stream=sys.stderr)
        return 1


def run_db_command(connection, args: argparse.Namespace) -> None:  # noqa: ANN001
    if args.command == "add-gate":
        add_gate(
            connection,
            gate_id=args.gate_id,
            name=args.name,
            site_area=args.site_area,
            provider=args.provider,
            interface_type=args.interface_type,
            operator_class=args.operator_class,
            hardware_id=args.hardware_id,
            safety_acknowledged=args.safety_ack,
        )
        print_json({"ok": True, "gate_id": args.gate_id})
    elif args.command == "add-credential":
        add_credential(
            connection,
            credential_id=args.credential_id,
            principal_id=args.principal_id,
            principal_label=args.principal_label,
            principal_type=args.principal_type,
            credential_type=args.credential_type,
            credential_value=args.credential_value,
            gate_scope=args.gate_scope,
            valid_from=args.valid_from,
            valid_until=args.valid_until,
            max_uses=args.max_uses,
            confidence_threshold=args.confidence_threshold,
            source_version=args.source_version,
        )
        print_json({"ok": True, "credential_id": args.credential_id})
    elif args.command == "revoke-credential":
        revoke_credential(
            connection,
            credential_id=args.credential_id,
            reason=args.reason,
            source_created_at=args.source_created_at,
        )
        print_json({"ok": True, "credential_id": args.credential_id})
    elif args.command == "authorize":
        result = authorize(
            connection,
            credential_type=args.credential_type,
            credential_value=args.credential_value,
            gate_id=args.gate_id,
            confidence=args.confidence,
            media=json.loads(args.media_json),
        )
        print_json(result)
    elif args.command == "add-qr-public-key":
        public_key_pem = Path(args.public_key_file).read_text(encoding="utf-8")
        add_qr_public_key(connection, key_id=args.key_id, public_key_pem=public_key_pem)
        print_json({"ok": True, "key_id": args.key_id})
    elif args.command == "revoke-qr-token":
        revoke_qr_token(
            connection,
            token_id=args.token_id,
            reason=args.reason,
            source_created_at=args.source_created_at,
        )
        print_json({"ok": True, "token_id": args.token_id})
    elif args.command == "apply-delta":
        delta = json.loads(Path(args.file).read_text(encoding="utf-8"))
        print_json({"ok": True, "applied": apply_delta(connection, delta)})
    elif args.command == "status":
        print_json(sync_status(connection))
    elif args.command == "verify-log":
        print_json(verify_event_log(connection))
    elif args.command == "events":
        print_json({"events": list_events(connection, limit=args.limit)})
    elif args.command == "mark-events-synced":
        mark_events_synced(connection, through_sequence=args.through_sequence)
        print_json({"ok": True})
    elif args.command == "anchor-head":
        print_json({"anchor": create_event_anchor(connection, anchor_type=args.anchor_type, upstream_ref=args.upstream_ref)})
    else:
        raise EdgeError(f"unknown_command:{args.command}")


def print_json(payload: dict, stream=None) -> None:  # noqa: ANN001
    print(json.dumps(payload, indent=2, sort_keys=True), file=stream or sys.stdout)
