from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from edge.angel_edge.crypto_tokens import generate_keypair, load_private_key, sign_token
from edge.angel_edge.store import (
    add_credential,
    add_gate,
    add_qr_public_key,
    authorize,
    connect,
    create_event_anchor,
    migrate,
    revoke_credential,
    revoke_qr_token,
    verify_event_log,
)


class EdgeRuntimeTest(unittest.TestCase):
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

    def test_pin_authorization_revocation_and_hash_chain(self) -> None:
        add_credential(
            self.connection,
            credential_id="cred-pin-1",
            principal_id="unit-101",
            principal_label="Unit 101",
            principal_type="resident",
            credential_type="pin",
            credential_value="123456",
            gate_scope=["front"],
        )

        allowed = authorize(
            self.connection,
            credential_type="pin",
            credential_value="123456",
            gate_id="front",
        )
        self.assertEqual("allow", allowed["decision"])
        self.assertTrue(allowed["relay_intent"])

        revoke_credential(self.connection, credential_id="cred-pin-1", reason="move_out")
        denied = authorize(
            self.connection,
            credential_type="pin",
            credential_value="123456",
            gate_id="front",
        )
        self.assertEqual("deny", denied["decision"])
        self.assertEqual("credential_not_found", denied["reason"])
        verification = verify_event_log(self.connection)
        self.assertTrue(verification["ok"])
        self.assertGreaterEqual(verification["checked"], 5)

    def test_plate_requires_confidence_threshold(self) -> None:
        add_credential(
            self.connection,
            credential_id="cred-plate-1",
            principal_id="unit-102",
            principal_label="Unit 102",
            principal_type="resident",
            credential_type="plate",
            credential_value="ABO-I23",
            gate_scope=["front"],
            confidence_threshold=0.85,
        )

        low = authorize(
            self.connection,
            credential_type="plate",
            credential_value="AB0-123",
            gate_id="front",
            confidence=0.72,
        )
        self.assertEqual("deny", low["decision"])
        self.assertTrue(low["fallback_required"])

        high = authorize(
            self.connection,
            credential_type="plate",
            credential_value="AB0 123",
            gate_id="front",
            confidence=0.91,
        )
        self.assertEqual("allow", high["decision"])

    def test_signed_qr_token_works_offline_and_can_be_revoked(self) -> None:
        private_pem, public_pem = generate_keypair()
        private_file = Path(self.tempdir.name) / "qr-private.pem"
        private_file.write_text(private_pem, encoding="utf-8")
        add_qr_public_key(self.connection, key_id="cloud-key-1", public_key_pem=public_pem)

        token = sign_token(
            load_private_key(str(private_file)),
            "cloud-key-1",
            {
                "token_id": "pass-1",
                "principal_id": "visitor-1",
                "principal_label": "Visitor One",
                "gate_scope": ["front"],
                "exp": int(time.time()) - 30,
                "max_uses": 1,
            },
        )

        allowed = authorize(
            self.connection,
            credential_type="qr",
            credential_value=token,
            gate_id="front",
        )
        self.assertEqual("allow", allowed["decision"])

        exhausted = authorize(
            self.connection,
            credential_type="qr",
            credential_value=token,
            gate_id="front",
        )
        self.assertEqual("deny", exhausted["decision"])
        self.assertEqual("qr_token_use_limit_reached", exhausted["reason"])

        revoke_qr_token(self.connection, token_id="pass-1", reason="visitor_cancelled")
        revoked = authorize(
            self.connection,
            credential_type="qr",
            credential_value=token,
            gate_id="front",
        )
        self.assertEqual("deny", revoked["decision"])
        self.assertEqual("qr_token_revoked", revoked["reason"])

    def test_anchor_detects_tail_truncation(self) -> None:
        add_credential(
            self.connection,
            credential_id="cred-pin-anchor",
            principal_id="unit-103",
            principal_label="Unit 103",
            principal_type="resident",
            credential_type="pin",
            credential_value="654321",
            gate_scope=["front"],
        )
        authorize(
            self.connection,
            credential_type="pin",
            credential_value="654321",
            gate_id="front",
        )
        anchor = create_event_anchor(self.connection, anchor_type="cloud_ack", upstream_ref="cloud-log-1")
        self.connection.execute("PRAGMA foreign_keys = OFF")
        self.connection.execute("DELETE FROM events WHERE sequence = ?", (anchor["sequence"],))
        self.connection.commit()
        self.connection.execute("PRAGMA foreign_keys = ON")

        verification = verify_event_log(self.connection)
        self.assertFalse(verification["ok"])
        self.assertEqual("event_log_truncated_below_latest_anchor", verification["error"])


if __name__ == "__main__":
    unittest.main()
