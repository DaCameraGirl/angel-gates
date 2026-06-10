"""Small local HTTP API for reader/controller integration."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import store


def run_server(db_path: str, host: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        server_version = "AngelEdge/0.1"

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                with store.connect(db_path) as connection:
                    store.migrate(connection)
                    self.send_json(200, store.sync_status(connection))
                return
            if self.path.startswith("/events"):
                with store.connect(db_path) as connection:
                    store.migrate(connection)
                    self.send_json(200, {"events": store.list_events(connection, limit=50)})
                return
            self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/authorize":
                payload = self.read_json()
                with store.connect(db_path) as connection:
                    store.migrate(connection)
                    result = store.authorize(
                        connection,
                        credential_type=payload.get("credential_type", ""),
                        credential_value=payload.get("credential_value", ""),
                        gate_id=payload.get("gate_id", ""),
                        confidence=payload.get("confidence"),
                        media=payload.get("media") or {},
                        request=payload,
                    )
                self.send_json(200, result)
                return
            if self.path == "/sync/delta":
                payload = self.read_json()
                with store.connect(db_path) as connection:
                    store.migrate(connection)
                    applied = store.apply_delta(connection, payload)
                self.send_json(200, {"applied": applied})
                return
            self.send_json(404, {"error": "not_found"})

        def read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))

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
    print(f"Angel Edge listening on http://{host}:{port}")
    httpd.serve_forever()
