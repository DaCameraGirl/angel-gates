from __future__ import annotations

import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from edge.angel_edge import store, witness
from edge.angel_edge.anchor_publisher import AnchorPublisher


class InProcessWitnessClient:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def publish_anchor(self, payload: dict[str, Any]) -> dict[str, Any]:
        with closing(witness.connect(self.db_path)) as connection:
            witness.migrate(connection)
            return {"ok": True, **witness.record_anchor(connection, payload)}


class AnchorWitnessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.edge_db_path = Path(self.tempdir.name) / "edge.sqlite3"
        self.witness_db_path = Path(self.tempdir.name) / "witness.sqlite3"
        self.edge = store.connect(self.edge_db_path)
        store.migrate(self.edge, edge_id="edge-test")

    def tearDown(self) -> None:
        self.edge.close()
        self.tempdir.cleanup()

    def test_witness_accepts_linear_stream_and_rejects_forks(self) -> None:
        with closing(witness.connect(self.witness_db_path)) as connection:
            witness.migrate(connection)
            first = witness.record_anchor(connection, anchor_payload(sequence=5, event_hash="a" * 64))
            self.assertTrue(first["accepted"])

            duplicate = witness.record_anchor(connection, anchor_payload(sequence=5, event_hash="a" * 64))
            self.assertFalse(duplicate["accepted"])
            self.assertTrue(duplicate["duplicate"])

            with self.assertRaises(witness.WitnessForkError):
                witness.record_anchor(connection, anchor_payload(sequence=5, event_hash="b" * 64))

            with self.assertRaises(witness.WitnessForkError):
                witness.record_anchor(
                    connection,
                    anchor_payload(
                        sequence=6,
                        event_hash="c" * 64,
                        previous_sequence=5,
                        previous_hash="d" * 64,
                    ),
                )

            second = witness.record_anchor(
                connection,
                anchor_payload(
                    sequence=6,
                    event_hash="c" * 64,
                    previous_sequence=5,
                    previous_hash="a" * 64,
                ),
            )
            self.assertTrue(second["accepted"])

            with self.assertRaises(witness.WitnessForkError):
                witness.record_anchor(connection, anchor_payload(sequence=4, event_hash="e" * 64))

    def test_publisher_records_cloud_ack_and_publishes_after_event_count(self) -> None:
        publisher = AnchorPublisher(
            db_path=str(self.edge_db_path),
            client=InProcessWitnessClient(self.witness_db_path),
            event_interval=2,
            max_age_seconds=300,
        )
        bootstrap = publisher.publish_once(force=True, reason="bootstrap")
        self.assertTrue(bootstrap["published"])

        self.append_diagnostic_event("first")
        self.append_diagnostic_event("second")

        published = publisher.publish_once()
        self.assertTrue(published["published"])
        self.assertIn("event_count", published["payload"]["reasons"])
        self.assertEqual(bootstrap["payload"]["sequence"], published["payload"]["previous_witness_sequence"])
        self.assertEqual(published["witness_anchor"]["witness_anchor_id"], published["local_anchor"]["upstream_ref"])
        self.assertTrue(store.verify_event_log(self.edge)["ok"])

    def test_publisher_publishes_after_elapsed_time_with_new_events(self) -> None:
        publisher = AnchorPublisher(
            db_path=str(self.edge_db_path),
            client=InProcessWitnessClient(self.witness_db_path),
            event_interval=100,
            max_age_seconds=60,
        )
        publisher.publish_once(force=True, reason="bootstrap")
        stale_anchor_time = (datetime.now(UTC) - timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.edge.execute("UPDATE event_anchors SET anchored_at = ? WHERE anchor_type = 'cloud_published'", (stale_anchor_time,))
        self.edge.commit()
        self.append_diagnostic_event("time-window")

        published = publisher.publish_once()
        self.assertTrue(published["published"])
        self.assertIn("time_elapsed", published["payload"]["reasons"])

    def test_publisher_publishes_after_revocation_anchor(self) -> None:
        publisher = AnchorPublisher(
            db_path=str(self.edge_db_path),
            client=InProcessWitnessClient(self.witness_db_path),
            event_interval=100,
            max_age_seconds=300,
        )
        publisher.publish_once(force=True, reason="bootstrap")
        store.add_credential(
            self.edge,
            credential_id="cred-revoked-anchor",
            principal_id="unit-201",
            principal_label="Unit 201",
            principal_type="resident",
            credential_type="pin",
            credential_value="201201",
            gate_scope=["front"],
        )
        store.revoke_credential(self.edge, credential_id="cred-revoked-anchor", reason="move_out")

        published = publisher.publish_once()
        self.assertTrue(published["published"])
        self.assertIn("revocation", published["payload"]["reasons"])

    def append_diagnostic_event(self, reason: str) -> None:
        store.append_event(self.edge, event_type="diagnostic", reason=reason)
        self.edge.commit()


def anchor_payload(
    *,
    sequence: int,
    event_hash: str,
    previous_sequence: int | None = None,
    previous_hash: str | None = None,
) -> dict[str, Any]:
    return {
        "edge_id": "edge-test",
        "sequence": sequence,
        "event_id": f"evt_{sequence}",
        "event_hash": event_hash,
        "occurred_at": "2026-06-10T00:00:00Z",
        "previous_witness_sequence": previous_sequence,
        "previous_witness_hash": previous_hash,
        "reasons": ["test"],
        "created_at": "2026-06-10T00:00:01Z",
    }


if __name__ == "__main__":
    unittest.main()
