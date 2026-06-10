from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from edge.angel_edge import store
from edge.angel_edge.http_api import build_server
from edge.angel_edge.pilot_acceptance import EdgeHttpClient, run_pilot_acceptance


class PilotAcceptanceTest(unittest.TestCase):
    def test_acceptance_runner_exercises_real_http_service(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "edge.sqlite3"
            token = "pilot-acceptance-token"
            with closing(store.connect(db_path)) as connection:
                store.migrate(connection, edge_id="edge-acceptance")
                store.issue_api_token_hash(
                    connection,
                    token_id="pilot-acceptance",
                    token_hash=store.hash_api_token(token),
                    label="Pilot acceptance",
                    scope="installer",
                    expires_at=(datetime.now(UTC) + timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                )
                connection.commit()

            port = free_port()
            httpd = build_server(str(db_path), "127.0.0.1", port)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            edge_url = f"http://127.0.0.1:{port}"
            try:
                wait_for_edge(edge_url=edge_url, token=token)

                result = run_pilot_acceptance(
                    edge_url=edge_url,
                    token=token,
                    gate_id="pilot-acceptance-test-gate",
                    include_binding_revocation=True,
                )

                self.assertTrue(result["ok"])
                step_names = {step["name"] for step in result["results"]}
                self.assertIn("pin_allow", step_names)
                self.assertIn("qr_allow", step_names)
                self.assertIn("plate_allow", step_names)
                self.assertIn("events_stream_returns_event", step_names)
                self.assertIn("verify_log", step_names)
                self.assertIn("binding_revocation_revokes_api_tokens", step_names)
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_edge(*, edge_url: str, token: str) -> None:
    client = EdgeHttpClient(edge_url=edge_url, token=token, timeout_seconds=0.5)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            client.get("/health")
            return
        except Exception:
            time.sleep(0.05)
    raise AssertionError("edge service did not start")


if __name__ == "__main__":
    unittest.main()
