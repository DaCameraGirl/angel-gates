from __future__ import annotations

import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from edge.angel_edge import rebind, store
from edge.angel_edge.commissioning import (
    apply_binding_artifact,
    commissioning_payload,
    commissioning_status,
    public_key_pem,
)


class RebindTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.registry_path = Path(self.tempdir.name) / "registry.sqlite3"
        self.registry = rebind.connect(self.registry_path)
        rebind.migrate(self.registry)
        self.cloud_private_key = Ed25519PrivateKey.generate()
        self.cloud_public_key = public_key_pem(self.cloud_private_key.public_key())

    def tearDown(self) -> None:
        self.registry.close()
        self.tempdir.cleanup()

    def test_cloud_rebind_supersedes_old_binding_and_new_edge_records_lineage(self) -> None:
        old_edge_payload = self.edge_payload("old-edge.sqlite3", "old-device.key")
        old_binding_payload = {
            "binding_id": "binding-old",
            "device_id": old_edge_payload["device_id"],
            "bootstrap_nonce": old_edge_payload["bootstrap_nonce"],
            "property_id": "property-1",
            "property_label": "Pilot Property",
            "gate_id": "front",
            "issued_at": "2026-06-10T00:00:00Z",
            "status": "claimed",
        }
        rebind.register_binding(
            self.registry,
            payload=old_binding_payload,
            event_history_ref="witness:edge-old:sequence-42",
        )

        new_db_path = Path(self.tempdir.name) / "new-edge.sqlite3"
        new_key_path = Path(self.tempdir.name) / "new-device.key"
        with closing(store.connect(new_db_path)) as new_edge:
            store.migrate(new_edge, edge_id="edge-new")
            new_payload = commissioning_payload(new_edge, new_key_path)
            artifact = rebind.create_rebind_artifact(
                self.registry,
                cloud_private_key=self.cloud_private_key,
                new_device_id=new_payload["device_id"],
                new_bootstrap_nonce=new_payload["bootstrap_nonce"],
                property_id="property-1",
                gate_id="front",
                property_label="Pilot Property",
                reason="sd_card_loss",
                preserved_history_ref="witness:edge-old:sequence-42",
                binding_id="binding-new",
            )

            result = apply_binding_artifact(
                new_edge,
                key_file=new_key_path,
                artifact=artifact,
                cloud_public_key_pem=self.cloud_public_key,
            )
            status = commissioning_status(new_edge)
            reason = new_edge.execute(
                "SELECT reason FROM events WHERE event_type = 'commissioning' ORDER BY sequence DESC LIMIT 1"
            ).fetchone()["reason"]

            self.assertTrue(result["ok"])
            self.assertEqual(new_payload["device_id"], result["device_id"])
            self.assertEqual("binding-new", result["binding_id"])
            self.assertEqual("binding-old", result["rebind"]["replaces_binding_id"])
            self.assertEqual(old_edge_payload["device_id"], result["rebind"]["replaces_device_id"])
            self.assertEqual("witness:edge-old:sequence-42", status["rebind_preserved_history_ref"])
            self.assertEqual("binding_rebind_applied", reason)
            self.assertTrue(store.verify_event_log(new_edge)["ok"])

        old_binding = rebind.binding_by_id(self.registry, "binding-old")
        new_binding = rebind.binding_by_id(self.registry, "binding-new")
        self.assertEqual("superseded", old_binding["status"])
        self.assertEqual("binding-new", old_binding["superseded_by_binding_id"])
        self.assertEqual("active", new_binding["status"])
        self.assertEqual("front", new_binding["gate_id"])
        self.assertNotEqual(old_binding["device_id"], new_binding["device_id"])

    def test_rebind_refuses_same_device_identity(self) -> None:
        old_edge_payload = self.edge_payload("same-edge.sqlite3", "same-device.key")
        rebind.register_binding(
            self.registry,
            payload={
                "binding_id": "binding-same",
                "device_id": old_edge_payload["device_id"],
                "bootstrap_nonce": old_edge_payload["bootstrap_nonce"],
                "property_id": "property-1",
                "property_label": "Pilot Property",
                "gate_id": "front",
            },
        )

        with self.assertRaises(rebind.RebindError):
            rebind.create_rebind_artifact(
                self.registry,
                cloud_private_key=self.cloud_private_key,
                new_device_id=old_edge_payload["device_id"],
                new_bootstrap_nonce="new-nonce",
                property_id="property-1",
                gate_id="front",
                property_label="Pilot Property",
                reason="same_device_test",
                preserved_history_ref="witness:edge-old:sequence-42",
            )

    def edge_payload(self, db_name: str, key_name: str):
        db_path = Path(self.tempdir.name) / db_name
        key_path = Path(self.tempdir.name) / key_name
        with closing(store.connect(db_path)) as connection:
            store.migrate(connection, edge_id=db_name)
            return commissioning_payload(connection, key_path)


if __name__ == "__main__":
    unittest.main()
