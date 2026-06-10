"""Local relay pulse service.

This process owns GPIO access. The HTTP authorization service sends it a short
pulse request after an allow event has been committed to the event log.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .drivers.relay import LoggingRelayDriver, RelayController, RelayError


def run_relay_service(db_path: str, host: str, port: int, *, token: str, driver_name: str = "logging") -> None:
    if not token:
        raise RelayError("relay_service_token_required")
    controller = RelayController(db_path=db_path, driver=build_driver(driver_name))

    class Handler(BaseHTTPRequestHandler):
        server_version = "AngelRelay/0.1"

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/pulse":
                self.send_json(404, {"error": "not_found"})
                return
            if not self.authorized():
                self.send_json(401, {"error": "unauthorized"})
                return
            try:
                result = controller.request_pulse(self.read_json())
            except (RelayError, ValueError, KeyError, json.JSONDecodeError) as exc:
                self.send_json(400, {"ok": False, "error": str(exc)})
                return
            self.send_json(200, result)

        def authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            return header == f"Bearer {token}"

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
    print(f"Angel Relay listening on http://{host}:{port} with {controller.driver.name} driver")
    httpd.serve_forever()


def build_driver(driver_name: str):
    if driver_name == "logging":
        return LoggingRelayDriver()
    if driver_name == "gpio":
        from .drivers.gpio_relay import GpioRelayDriver

        return GpioRelayDriver()
    raise RelayError(f"unsupported_relay_driver:{driver_name}")

