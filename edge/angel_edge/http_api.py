"""Small local HTTP API for reader/controller integration."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .drivers.camera import dispatch_camera_capture_async
from .drivers.relay import dispatch_relay_pulse_async
from . import store


def build_server(
    db_path: str,
    host: str,
    port: int,
    *,
    relay_url: str | None = None,
    relay_token: str | None = None,
    camera_url: str | None = None,
    camera_token: str | None = None,
) -> None:
    class Handler(BaseHTTPRequestHandler):
        server_version = "AngelEdge/0.1"

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_cors_headers()
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if not self.authorized(scopes_for_get(parsed.path)):
                self.send_json(401, {"error": "unauthorized"})
                return

            query = parse_qs(parsed.query)
            if parsed.path == "/health":
                with closing(store.connect(db_path)) as connection:
                    store.migrate(connection)
                    self.send_json(200, store.sync_status(connection))
                return
            if parsed.path == "/events":
                limit = bounded_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=250)
                after_sequence = bounded_int(query.get("after_sequence", ["0"])[0], default=0, minimum=0, maximum=10**12)
                with closing(store.connect(db_path)) as connection:
                    store.migrate(connection)
                    if after_sequence:
                        events = store.list_events_after(connection, sequence=after_sequence, limit=limit)
                    else:
                        events = store.list_events(connection, limit=limit)
                    self.send_json(200, {"events": events, "head": store.current_head(connection)})
                return
            if parsed.path == "/verify-log":
                with closing(store.connect(db_path)) as connection:
                    store.migrate(connection)
                    self.send_json(200, store.verify_event_log(connection))
                return
            if parsed.path == "/events/stream":
                after_sequence = bounded_int(query.get("after_sequence", ["0"])[0], default=0, minimum=0, maximum=10**12)
                if not after_sequence:
                    after_sequence = bounded_int(self.headers.get("Last-Event-ID", "0"), default=0, minimum=0, maximum=10**12)
                self.stream_events(after_sequence=after_sequence)
                return
            self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            required_scopes = scopes_for_post(parsed.path)
            if not self.authorized(required_scopes):
                self.send_json(401, {"error": "unauthorized"})
                return

            if parsed.path == "/authorize":
                payload = self.read_json()
                with closing(store.connect(db_path)) as connection:
                    store.migrate(connection)
                    result = store.authorize(
                        connection,
                        credential_type=payload.get("credential_type", ""),
                        credential_value=payload.get("credential_value", ""),
                        gate_id=payload.get("gate_id", ""),
                        confidence=payload.get("confidence"),
                        media=payload.get("media") or {},
                        request=store.sanitize_authorize_request(payload),
                    )
                result["camera_dispatch"] = dispatch_camera_capture_async(
                    camera_url=camera_url,
                    camera_token=camera_token,
                    authorization_result=result,
                )
                result["relay_dispatch"] = dispatch_relay_pulse_async(
                    relay_url=relay_url,
                    relay_token=relay_token,
                    authorization_result=result,
                )
                self.send_json(200, result)
                return
            if parsed.path == "/sync/delta":
                payload = self.read_json()
                with closing(store.connect(db_path)) as connection:
                    store.migrate(connection)
                    applied = store.apply_delta(connection, payload)
                self.send_json(200, {"applied": applied})
                return
            if parsed.path == "/anchors/head":
                payload = self.read_json()
                with closing(store.connect(db_path)) as connection:
                    store.migrate(connection)
                    anchor = store.create_event_anchor(
                        connection,
                        anchor_type=payload.get("anchor_type", "cloud_pending"),
                        upstream_ref=payload.get("upstream_ref"),
                        extra=payload.get("extra") or {},
                    )
                self.send_json(200, {"anchor": anchor})
                return
            self.send_json(404, {"error": "not_found"})

        def authorized(self, allowed_scopes: set[str]) -> bool:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return False
            token = header.removeprefix("Bearer ").strip()
            if not token:
                return False
            with closing(store.connect(db_path)) as connection:
                store.migrate(connection)
                return store.validate_api_token(connection, token, allowed_scopes=allowed_scopes) is not None

        def stream_events(self, after_sequence: int) -> None:
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            last_sequence = after_sequence
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    with closing(store.connect(db_path)) as connection:
                        store.migrate(connection)
                        events = store.list_events_after(connection, sequence=last_sequence, limit=100)
                except (OSError, sqlite3.Error):
                    return
                for event in events:
                    last_sequence = max(last_sequence, int(event["sequence"]))
                    try:
                        self.write_sse("event", event)
                    except OSError:
                        return
                if not events:
                    try:
                        self.write_sse("heartbeat", {"after_sequence": last_sequence})
                    except OSError:
                        return
                time.sleep(1)

        def write_sse(self, event_name: str, payload: dict[str, Any]) -> None:
            event_id = payload.get("sequence") or payload.get("after_sequence") or 0
            body = f"id: {event_id}\nevent: {event_name}\ndata: {json.dumps(payload, sort_keys=True)}\n\n".encode("utf-8")
            self.wfile.write(body)
            self.wfile.flush()

        def read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))

        def send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def send_cors_headers(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")

    httpd = ThreadingHTTPServer((host, port), Handler)
    return httpd


def run_server(
    db_path: str,
    host: str,
    port: int,
    *,
    relay_url: str | None = None,
    relay_token: str | None = None,
    camera_url: str | None = None,
    camera_token: str | None = None,
) -> None:
    httpd = build_server(
        db_path,
        host,
        port,
        relay_url=relay_url,
        relay_token=relay_token,
        camera_url=camera_url,
        camera_token=camera_token,
    )
    print(f"Angel Edge listening on http://{host}:{port}")
    httpd.serve_forever()


def bounded_int(value: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def scopes_for_post(path: str) -> set[str]:
    if path == "/authorize":
        return {"edge-api", "dashboard", "installer"}
    if path == "/sync/delta":
        return {"edge-sync", "installer"}
    if path == "/anchors/head":
        return {"anchor-publish", "installer"}
    return {"dashboard", "installer"}


def scopes_for_get(path: str) -> set[str]:
    if path == "/health":
        return {"dashboard", "installer", "edge-api", "edge-sync", "anchor-publish"}
    if path in {"/events", "/events/stream", "/verify-log"}:
        return {"dashboard", "installer"}
    return {"dashboard", "installer"}
