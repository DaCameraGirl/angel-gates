from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PI_DIR = ROOT / "deploy" / "pi"
UNIT_DIR = PI_DIR / "systemd"
BIN_DIR = PI_DIR / "bin"


class PiPackagingTest(unittest.TestCase):
    def test_systemd_units_reference_existing_runner_scripts(self) -> None:
        units = sorted(UNIT_DIR.glob("angel-edge*.service"))
        self.assertGreaterEqual(len(units), 6)
        for unit in units:
            text = unit.read_text(encoding="utf-8")
            self.assertIn("User=angel", text, unit.name)
            self.assertIn("EnvironmentFile=/etc/angel-gates/edge.env", text, unit.name)
            exec_start = next(line for line in text.splitlines() if line.startswith("ExecStart="))
            absolute_runner = exec_start.removeprefix("ExecStart=")
            self.assertTrue(absolute_runner.startswith("/opt/angel-gates/deploy/pi/bin/"), unit.name)
            runner = BIN_DIR / Path(absolute_runner).name
            self.assertTrue(runner.exists(), f"{unit.name} points to missing {runner}")
            if "Type=simple" in text:
                self.assertIn("Restart=always", text, unit.name)
                self.assertIn("NoNewPrivileges=true", text, unit.name)

    def test_env_template_contains_required_runtime_settings(self) -> None:
        env_text = (PI_DIR / "env" / "angel-edge.env.example").read_text(encoding="utf-8")
        required = [
            "ANGEL_EDGE_DB=/var/lib/angel-edge/angel-edge.sqlite3",
            "ANGEL_DEVICE_KEY_FILE=/var/lib/angel-edge/device.key",
            "ANGEL_COMMISSIONING_PAYLOAD_FILE=/var/lib/angel-edge/commissioning-payload.json",
            "ANGEL_RELAY_TOKEN=replace-with-local-relay-token",
            "ANGEL_CAMERA_RTSP_URL=",
            "ANGEL_WITNESS_URL=",
        ]
        for line in required:
            self.assertIn(line, env_text)

    def test_first_boot_setup_covers_key_dirs_watchdog_and_services(self) -> None:
        setup_text = (PI_DIR / "first-boot-setup.sh").read_text(encoding="utf-8")
        self.assertIn("install -d -o \"$EDGE_USER\" -g \"$EDGE_GROUP\" -m 0750 /var/lib/angel-edge", setup_text)
        self.assertIn("systemctl enable angel-edge-commissioning.service angel-edge.service", setup_text)
        self.assertIn("systemd/system.conf.d/*.conf", setup_text)
        self.assertTrue((UNIT_DIR / "system.conf.d" / "10-angel-edge-watchdog.conf").exists())
        self.assertIn("gpiozero pyserial", setup_text)

    def test_commissioning_runner_writes_payload_with_private_umask(self) -> None:
        runner_text = (BIN_DIR / "write-commissioning-payload.sh").read_text(encoding="utf-8")
        self.assertIn("umask 0077", runner_text)
        self.assertIn("commissioning-payload", runner_text)
        self.assertIn("chmod 0640", runner_text)


if __name__ == "__main__":
    unittest.main()
