from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from edge.angel_edge import store
from edge.angel_edge.incident_report import build_incident_report, incident_report_csv, incident_report_markdown


class IncidentReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "edge.sqlite3"
        self.connection = store.connect(self.db_path)
        store.migrate(self.connection, edge_id="edge-test")
        store.add_gate(
            self.connection,
            gate_id="front",
            name="Front Gate",
            site_area="Entry",
            provider="DoorKing",
            interface_type="dry-contact",
            operator_class="barrier-arm",
            hardware_id="DK-1601",
            safety_acknowledged=True,
        )

    def tearDown(self) -> None:
        self.connection.close()
        self.tempdir.cleanup()

    def test_report_exports_real_window_with_camera_clip_and_anchor(self) -> None:
        started_at = self.window_time(minutes=-1)
        store.add_credential(
            self.connection,
            credential_id="unit-301-pin",
            principal_id="unit-301",
            principal_label="Unit 301",
            principal_type="resident",
            credential_type="pin",
            credential_value="301301",
            gate_scope=["front"],
        )
        allowed = store.authorize(
            self.connection,
            credential_type="pin",
            credential_value="301301",
            gate_id="front",
        )
        store.record_camera_clip(
            self.connection,
            gate_id="front",
            camera_id="front-cam",
            decision_event_id=allowed["event_id"],
            decision_event_hash=allowed["event_hash"],
            decision_occurred_at=allowed["occurred_at"],
            access_decision="allow",
            access_reason="authorized",
            clip_path="edge-data/camera-clips/front/unit-301.mp4",
            started_at=allowed["occurred_at"],
            ended_at=store.utc_now(),
            duration_seconds=8,
            bytes_written=1234,
            driver="test-camera",
            retention_days=14,
        )
        store.create_event_anchor(self.connection, anchor_type="cloud_pending", upstream_ref="cloud-anchor-incident-1")
        ended_at = self.window_time(minutes=1)

        report = build_incident_report(
            self.connection,
            property_id="property-1",
            property_label="Ansley Commons",
            gate_id="front",
            started_at=started_at,
            ended_at=ended_at,
            selected_event_id=allowed["event_id"],
            manager_notes="Arm was reported damaged during this window.",
        )

        self.assertEqual("damaged_arm_incident", report["report_type"])
        self.assertEqual("front", report["gate_id"])
        self.assertEqual(2, report["summary"]["event_count"])
        self.assertEqual(1, report["summary"]["access_attempts"])
        self.assertEqual(1, report["summary"]["allow_count"])
        self.assertEqual(1, report["summary"]["camera_clip_count"])
        self.assertEqual(allowed["event_id"], report["selected_event"]["event_id"])
        self.assertEqual("cloud-anchor-incident-1", report["latest_anchor"]["upstream_ref"])
        self.assertTrue(report["log_verification"]["ok"])

        access_event = next(event for event in report["events"] if event["event_type"] == "access_attempt")
        self.assertEqual("Unit 301", access_event["principal_label"])
        self.assertEqual("pin", access_event["credential_type"])
        camera_event = next(event for event in report["events"] if event["event_type"] == "camera")
        self.assertEqual(allowed["event_id"], camera_event["linked_decision_event_id"])
        self.assertEqual(["edge-data/camera-clips/front/unit-301.mp4"], camera_event["media_refs"])

        csv_report = incident_report_csv(report)
        self.assertIn("Unit 301", csv_report)
        self.assertIn("edge-data/camera-clips/front/unit-301.mp4", csv_report)
        markdown_report = incident_report_markdown(report)
        self.assertIn("# Gate Incident Report", markdown_report)
        self.assertIn("Ansley Commons", markdown_report)
        self.assertIn("Arm was reported damaged", markdown_report)

    def test_selected_event_must_be_inside_report_window(self) -> None:
        started_at = self.window_time(minutes=-1)
        ended_at = self.window_time(minutes=1)

        with self.assertRaisesRegex(store.EdgeError, "selected_event_outside_incident_report"):
            build_incident_report(
                self.connection,
                gate_id="front",
                started_at=started_at,
                ended_at=ended_at,
                selected_event_id="evt-not-in-window",
            )

    def test_report_rejects_invalid_window(self) -> None:
        with self.assertRaisesRegex(store.EdgeError, "incident_window_invalid"):
            build_incident_report(
                self.connection,
                gate_id="front",
                started_at=self.window_time(minutes=1),
                ended_at=self.window_time(minutes=-1),
            )

    def window_time(self, *, minutes: int) -> str:
        return store.format_utc(datetime.now(UTC) + timedelta(minutes=minutes))


if __name__ == "__main__":
    unittest.main()

