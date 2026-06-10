from __future__ import annotations

import json
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from edge.angel_edge.commissioning import (
    FACTORY_RESET_CONFIRMATION,
    apply_binding_artifact,
    commissioning_payload,
    commissioning_status,
    factory_reset,
    public_key_pem,
    revoke_binding,
    sign_binding_payload,
    sign_claim_challenge,
    verify_device_signature,
)
from edge.angel_edge.crypto_tokens import generate_keypair, load_private_key, sign_token
from edge.angel_edge.drivers.camera import (
    CameraCaptureRequest,
    CameraCaptureResult,
    CameraController,
    capture_payload_from_authorization,
)
from edge.angel_edge.drivers.relay import LoggingRelayDriver, RelayController, relay_payload_from_authorization
from edge.angel_edge.store import (
    EdgeError,
    add_credential,
    add_gate,
    add_qr_public_key,
    authorize,
    connect,
    create_event_anchor,
    hash_api_token,
    issue_api_token_hash,
    migrate,
    revoke_credential,
    revoke_qr_token,
    utc_now,
    validate_api_token,
    verify_event_log,
)


class FakeCameraDriver:
    name = "fake-camera"

    def capture(self, capture_request: CameraCaptureRequest) -> CameraCaptureResult:
        capture_request.storage_path.mkdir(parents=True, exist_ok=True)
        capture_request.output_path.write_bytes(b"fake mp4 bytes")
        started_at = utc_now()
        ended_at = utc_now()
        return CameraCaptureResult(
            clip_path=capture_request.output_path,
            bytes_written=capture_request.output_path.stat().st_size,
            started_at=started_at,
            ended_at=ended_at,
            driver=self.name,
        )


class FailingCameraDriver:
    name = "failing-camera"

    def capture(self, capture_request: CameraCaptureRequest) -> CameraCaptureResult:
        raise RuntimeError(f"{capture_request.rtsp_url} unreachable")


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

    def future_time(self, hours: int = 24) -> str:
        return (datetime.now(UTC) + timedelta(hours=hours)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

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

    def test_relay_controller_records_pulse_and_suppresses_duplicate(self) -> None:
        add_gate(
            self.connection,
            gate_id="front",
            name="Front Gate",
            site_area="Entry",
            provider="DoorKing",
            interface_type="dry-contact",
            operator_class="barrier",
            hardware_id="relay-1",
            relay_channel=26,
            relay_pulse_ms=50,
            relay_cooldown_ms=1500,
            safety_acknowledged=True,
        )
        add_credential(
            self.connection,
            credential_id="cred-pin-relay",
            principal_id="unit-106",
            principal_label="Unit 106",
            principal_type="resident",
            credential_type="pin",
            credential_value="121212",
            gate_scope=["front"],
        )

        allowed = authorize(
            self.connection,
            credential_type="pin",
            credential_value="121212",
            gate_id="front",
        )
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual(
            {"gate_id": "front", "hardware_id": "relay-1", "channel": 26, "pulse_ms": 50, "cooldown_ms": 1500},
            allowed["relay"],
        )

        driver = LoggingRelayDriver()
        controller = RelayController(db_path=str(self.db_path), driver=driver)
        pulse_payload = relay_payload_from_authorization(allowed)
        self.assertIsNotNone(pulse_payload)

        pulsed = controller.request_pulse(pulse_payload or {})
        self.assertEqual("pulsed", pulsed["status"])
        self.assertEqual(1, len(driver.pulses))

        suppressed = controller.request_pulse(pulse_payload or {})
        self.assertEqual("suppressed_cooldown", suppressed["status"])
        self.assertEqual(1, len(driver.pulses))

        reasons = [
            row["reason"]
            for row in self.connection.execute(
                "SELECT reason FROM events WHERE event_type = 'relay' ORDER BY sequence ASC"
            )
        ]
        self.assertEqual(["relay_pulse", "relay_pulse_suppressed_cooldown"], reasons)
        self.assertTrue(verify_event_log(self.connection)["ok"])

    def test_camera_controller_records_clip_metadata_linked_to_access_event(self) -> None:
        add_credential(
            self.connection,
            credential_id="cred-pin-camera",
            principal_id="unit-107",
            principal_label="Unit 107",
            principal_type="resident",
            credential_type="pin",
            credential_value="777888",
            gate_scope=["front"],
        )

        allowed = authorize(
            self.connection,
            credential_type="pin",
            credential_value="777888",
            gate_id="front",
        )
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual("front", allowed["gate_id"])

        controller = CameraController(
            db_path=str(self.db_path),
            rtsp_url="rtsp://user:pass@example.local/front",
            storage_path=Path(self.tempdir.name) / "clips",
            camera_id="front-cam",
            clip_seconds=1,
            retention_days=7,
            driver=FakeCameraDriver(),
        )
        payload = capture_payload_from_authorization(allowed)
        self.assertIsNotNone(payload)

        captured = controller.capture_once(payload or {})
        self.assertTrue(captured["ok"])
        self.assertEqual("captured", captured["status"])

        row = self.connection.execute(
            "SELECT * FROM events WHERE event_type = 'camera' AND reason = 'camera_clip_captured'"
        ).fetchone()
        self.assertIsNotNone(row)
        media = json.loads(row["media_json"])
        extra = json.loads(row["extra_json"])
        self.assertEqual(allowed["event_id"], extra["decision_event_id"])
        self.assertEqual(allowed["event_hash"], extra["decision_event_hash"])
        self.assertEqual("allow", extra["access_decision"])
        self.assertEqual("front-cam", media["clips"][0]["camera_id"])
        self.assertTrue(Path(media["clips"][0]["path"]).exists())
        self.assertTrue(verify_event_log(self.connection)["ok"])

    def test_camera_capture_failure_records_diagnostic_without_blocking_decision(self) -> None:
        add_credential(
            self.connection,
            credential_id="cred-pin-camera-fail",
            principal_id="unit-108",
            principal_label="Unit 108",
            principal_type="resident",
            credential_type="pin",
            credential_value="888999",
            gate_scope=["front"],
        )

        allowed = authorize(
            self.connection,
            credential_type="pin",
            credential_value="888999",
            gate_id="front",
        )
        self.assertEqual("allow", allowed["decision"])
        self.assertTrue(allowed["relay_intent"])

        controller = CameraController(
            db_path=str(self.db_path),
            rtsp_url="rtsp://user:pass@example.local/front",
            storage_path=Path(self.tempdir.name) / "clips",
            camera_id="front-cam",
            clip_seconds=1,
            retention_days=7,
            driver=FailingCameraDriver(),
        )
        payload = capture_payload_from_authorization(allowed)
        failed = controller.capture_once(payload or {})
        self.assertFalse(failed["ok"])
        self.assertEqual("capture_error", failed["status"])

        row = self.connection.execute(
            "SELECT * FROM events WHERE event_type = 'camera' AND reason = 'camera_capture_error'"
        ).fetchone()
        self.assertIsNotNone(row)
        extra = json.loads(row["extra_json"])
        self.assertEqual(allowed["event_id"], extra["decision_event_id"])
        self.assertEqual("allow", extra["access_decision"])
        self.assertNotIn("user:pass", extra["error"])
        self.assertTrue(verify_event_log(self.connection)["ok"])

    def test_pin_rate_limit_locks_gate_persists_and_expires(self) -> None:
        add_credential(
            self.connection,
            credential_id="cred-pin-rate-limit",
            principal_id="unit-105",
            principal_label="Unit 105",
            principal_type="resident",
            credential_type="pin",
            credential_value="222333",
            gate_scope=["front"],
        )

        for _ in range(3):
            denied = authorize(
                self.connection,
                credential_type="pin",
                credential_value="000000",
                gate_id="front",
            )
            self.assertEqual("deny", denied["decision"])
            self.assertEqual("credential_not_found", denied["reason"])

        reasons = [
            row["reason"]
            for row in self.connection.execute(
                "SELECT reason FROM events WHERE event_type = 'rate_limit' ORDER BY sequence ASC"
            )
        ]
        self.assertIn("rate_limit_pin_gate_lockout", reasons)
        self.assertIn("rate_limit_pin_credential_lockout", reasons)

        locked = authorize(
            self.connection,
            credential_type="pin",
            credential_value="222333",
            gate_id="front",
        )
        self.assertEqual("deny", locked["decision"])
        self.assertEqual("rate_limit_pin_gate_locked", locked["reason"])
        self.assertFalse(locked["relay_intent"])

        self.connection.close()
        self.connection = connect(self.db_path)
        migrate(self.connection, edge_id="edge-test")
        still_locked = authorize(
            self.connection,
            credential_type="pin",
            credential_value="222333",
            gate_id="front",
        )
        self.assertEqual("rate_limit_pin_gate_locked", still_locked["reason"])

        expired_at = (
            (datetime.now(UTC) - timedelta(seconds=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        self.connection.execute("UPDATE rate_limit_lockouts SET locked_until = ?", (expired_at,))
        self.connection.commit()
        allowed = authorize(
            self.connection,
            credential_type="pin",
            credential_value="222333",
            gate_id="front",
        )
        self.assertEqual("allow", allowed["decision"])
        self.assertTrue(verify_event_log(self.connection)["ok"])

    def test_qr_rate_limit_blocks_before_signature_verification(self) -> None:
        for _ in range(3):
            denied = authorize(
                self.connection,
                credential_type="qr",
                credential_value="not-a-signed-token",
                gate_id="front",
            )
            self.assertEqual("deny", denied["decision"])
            self.assertNotEqual("rate_limit_qr_gate_locked", denied["reason"])

        locked = authorize(
            self.connection,
            credential_type="qr",
            credential_value="not-a-signed-token",
            gate_id="front",
        )
        self.assertEqual("deny", locked["decision"])
        self.assertEqual("rate_limit_qr_gate_locked", locked["reason"])

        reasons = [
            row["reason"]
            for row in self.connection.execute(
                "SELECT reason FROM events WHERE event_type = 'rate_limit' ORDER BY sequence ASC"
            )
        ]
        self.assertIn("rate_limit_qr_gate_lockout", reasons)
        self.assertTrue(verify_event_log(self.connection)["ok"])

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

    def test_commissioning_claim_binding_tokens_and_reset(self) -> None:
        key_file = Path(self.tempdir.name) / "device.key"
        payload = commissioning_payload(self.connection, key_file)
        self.assertTrue(key_file.exists())
        self.assertTrue(Path(f"{key_file}.pub").exists())
        self.assertEqual(payload["commissioning_status"], "unclaimed")

        challenge = {
            "nonce": "claim-nonce-1",
            "device_id": payload["device_id"],
            "property_id": "property-1",
            "gate_id": "front",
            "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        }
        claim = sign_claim_challenge(key_file, challenge)
        self.assertTrue(verify_device_signature(payload["public_key_pem"], challenge, claim["signature"]))

        cloud_private_key = Ed25519PrivateKey.generate()
        dashboard_token = "dashboard-token-value"
        artifact = sign_binding_payload(
            cloud_private_key,
            {
                "binding_id": "binding-1",
                "device_id": payload["device_id"],
                "bootstrap_nonce": payload["bootstrap_nonce"],
                "property_id": "property-1",
                "property_label": "Pilot Property",
                "gate_id": "front",
                "issued_at": challenge["issued_at"],
                "status": "claimed_pending_cloud",
                "api_tokens": [
                    {
                        "token_id": "dashboard-1",
                        "token_hash": hash_api_token(dashboard_token),
                        "label": "Manager dashboard",
                        "scope": "dashboard",
                        "expires_at": self.future_time(),
                    }
                ],
            },
        )
        result = apply_binding_artifact(
            self.connection,
            key_file=key_file,
            artifact=artifact,
            cloud_public_key_pem=public_key_pem(cloud_private_key.public_key()),
        )
        self.assertEqual(result["commissioning_status"], "claimed_pending_cloud")
        self.assertEqual(result["gate_id"], "front")
        self.assertIsNotNone(validate_api_token(self.connection, dashboard_token, allowed_scopes={"dashboard"}))

        issue_api_token_hash(
            self.connection,
            token_id="expired-1",
            token_hash=hash_api_token("expired-token"),
            label="Expired token",
            scope="dashboard",
            expires_at=(datetime.now(UTC) - timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        )
        self.assertIsNone(validate_api_token(self.connection, "expired-token", allowed_scopes={"dashboard"}))

        add_credential(
            self.connection,
            credential_id="cred-pin-commissioned",
            principal_id="unit-104",
            principal_label="Unit 104",
            principal_type="resident",
            credential_type="pin",
            credential_value="111222",
            gate_scope=["front"],
        )
        revoke_binding(self.connection, reason="property_sold")
        denied = authorize(
            self.connection,
            credential_type="pin",
            credential_value="111222",
            gate_id="front",
        )
        self.assertEqual("deny", denied["decision"])
        self.assertEqual("edge_binding_revoked", denied["reason"])

        reset = factory_reset(self.connection, key_file=key_file, confirmation=FACTORY_RESET_CONFIRMATION)
        self.assertTrue(reset["ok"])
        self.assertFalse(key_file.exists())
        self.assertFalse(Path(f"{key_file}.pub").exists())
        self.assertEqual(commissioning_status(self.connection)["commissioning_status"], "unclaimed")
        self.assertIsNone(validate_api_token(self.connection, dashboard_token, allowed_scopes={"dashboard"}))

    def test_device_identity_refuses_half_present_keypair(self) -> None:
        key_file = Path(self.tempdir.name) / "broken-device.key"
        key_file.write_text("not a real key", encoding="utf-8")
        with self.assertRaises(EdgeError):
            commissioning_payload(self.connection, key_file)


if __name__ == "__main__":
    unittest.main()
