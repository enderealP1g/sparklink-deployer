from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from sparklink_deployer.cli import main
from sparklink_deployer.model import DeploymentConfig
from sparklink_deployer.preflight import _linux_checks


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_plan_passes_without_vps_mutation(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            result = main(["plan", "--config", str(ROOT / "config" / "host.example.json")])
        self.assertEqual(result, 0)
        self.assertIn("Secrets: generated on VPS", output.getvalue())

    def test_dummy_render_excludes_private_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result = main(
                [
                    "render-example",
                    "--config",
                    str(ROOT / "config" / "host.example.json"),
                    "--output",
                    raw,
                    "--allow-dummy",
                ]
            )
            self.assertEqual(result, 0)
            self.assertFalse((Path(raw) / "var/lib/sparklink/private").exists())

    def test_describe_is_credential_free_and_reports_recommended(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            result = main(["describe", "--config", str(ROOT / "config" / "host.example.json")])
        self.assertEqual(result, 0)
        value = output.getvalue()
        self.assertIn('"mode": "recommended"', value)
        self.assertIn('"singbox_state": "standby"', value)
        self.assertNotIn("PRIVATE_KEY_PLACEHOLDER", value)

    def test_inventory_status_is_read_only_when_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = StringIO()
            with redirect_stdout(output):
                result = main(["inventory-status", "--inventory-root", raw])
            self.assertEqual(result, 0)
            self.assertIn("No local host inventories", output.getvalue())

    def test_vps_preflight_reports_non_linux_without_geteuid_traceback(self) -> None:
        config = DeploymentConfig.load(ROOT / "config" / "host.example.json")
        with (
            patch("sparklink_deployer.preflight.platform.system", return_value="Windows"),
            patch("sparklink_deployer.preflight.platform.machine", return_value="AMD64"),
            patch("sparklink_deployer.preflight._read_os_release", return_value={}),
            patch("sparklink_deployer.preflight.shutil.which", return_value=None),
            patch("sparklink_deployer.preflight._listeners", return_value=set()),
            patch("sparklink_deployer.preflight._resolve", return_value=set()),
            patch("sparklink_deployer.preflight._native_public_ipv4", return_value=None),
        ):
            checks = _linux_checks(config)
        self.assertFalse(next(check for check in checks if check.name == "root").ok)
        self.assertFalse(next(check for check in checks if check.name == "kernel").ok)


if __name__ == "__main__":
    unittest.main()
