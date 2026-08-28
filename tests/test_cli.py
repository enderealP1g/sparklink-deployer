from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from sparklink_deployer.cli import main


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


if __name__ == "__main__":
    unittest.main()
