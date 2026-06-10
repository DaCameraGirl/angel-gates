from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from edge.angel_edge.scanner import (
    EV_KEY,
    KEY_DOWN,
    KEY_ENTER,
    KEY_LEFTSHIFT,
    EvdevKeyboardDecoder,
    ScanResult,
    normalize_scan,
    process_scan,
    scan_result_from_authorize_response,
)
from edge.angel_edge.store import add_gate, authorize, connect, migrate, sanitize_authorize_request, verify_event_log


class ScannerInputTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "edge.sqlite3"
        self.connection = connect(self.db_path)
        migrate(self.connection, edge_id="edge-test")
        add_gate(
            self.connection,
            gate_id="front",
            name="Front Gate",
            site_area="Entry",
            provider="DoorKing",
            interface_type="dry-contact",
            operator_class="barrier",
            hardware_id="relay-1",
            safety_acknowledged=True,
        )

    def tearDown(self) -> None:
        self.connection.close()
        self.tempdir.cleanup()

    def test_normalize_scan_strips_scanner_suffix(self) -> None:
        self.assertEqual("token.payload.signature", normalize_scan("  token.payload.signature\r\n"))
        self.assertEqual("abc", normalize_scan(b"\tabc\n"))

    def test_process_scan_ignores_empty_input(self) -> None:
        calls = []

        def authorize_scan(token: str) -> ScanResult:
            calls.append(token)
            return ScanResult(ok=True, decision="allow", reason="authorized")

        result = process_scan(" \r\n", source="stdin", authorize=authorize_scan)

        self.assertFalse(result.ok)
        self.assertEqual("empty_scan_ignored", result.reason)
        self.assertEqual([], calls)

    def test_evdev_decoder_handles_base64url_characters(self) -> None:
        decoder = EvdevKeyboardDecoder()

        def key(code: int, shifted: bool = False) -> str | None:
            if shifted:
                decoder.feed(EV_KEY, KEY_LEFTSHIFT, KEY_DOWN)
            result = decoder.feed(EV_KEY, code, KEY_DOWN)
            if shifted:
                decoder.feed(EV_KEY, KEY_LEFTSHIFT, 0)
            return result

        key(30, shifted=True)  # A
        key(48)  # b
        key(46, shifted=True)  # C
        key(52)  # .
        key(12, shifted=True)  # _
        key(12)  # -
        token = decoder.feed(EV_KEY, KEY_ENTER, KEY_DOWN)

        self.assertEqual("AbC._-", token)

    def test_malformed_scanner_qr_logs_deny_without_raw_token_in_request(self) -> None:
        raw_scan = "not-a-signed-token"

        def authorize_scan(token: str) -> ScanResult:
            response = authorize(
                self.connection,
                credential_type="qr",
                credential_value=token,
                gate_id="front",
                request=sanitize_authorize_request(
                    {
                        "credential_type": "qr",
                        "credential_value": token,
                        "gate_id": "front",
                        "media": {"scanner_id": "bench-scanner"},
                    }
                ),
                media={"scanner_id": "bench-scanner"},
            )
            return scan_result_from_authorize_response(response)

        result = process_scan(raw_scan, source="stdin", authorize=authorize_scan)

        self.assertFalse(result.ok)
        self.assertEqual("deny", result.decision)
        self.assertEqual("token_must_have_three_parts", result.reason)
        row = self.connection.execute(
            """
            SELECT request_json
            FROM events
            WHERE event_type = 'access_attempt' AND credential_type = 'qr'
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()
        self.assertIsNotNone(row)
        request_json = json.loads(row["request_json"])
        self.assertNotEqual(raw_scan, request_json["credential_value"])
        self.assertTrue(str(request_json["credential_value"]).startswith("qr_sha256:"))
        self.assertTrue(verify_event_log(self.connection)["ok"])


if __name__ == "__main__":
    unittest.main()
