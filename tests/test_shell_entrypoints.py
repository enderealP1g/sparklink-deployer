from __future__ import annotations

import unittest
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ShellEntrypointTests(unittest.TestCase):
    def test_entrypoints_have_strict_bash_headers(self) -> None:
        for name in ("install.sh", "sparklinkctl"):
            lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[0], "#!/usr/bin/env bash")
            self.assertEqual(lines[1], "set -euo pipefail")

    def test_install_has_balanced_control_tokens(self) -> None:
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertEqual(text.count("case "), text.count("esac"))
        if_count = len(re.findall(r"(?m)^\s*if\b", text))
        fi_count = len(re.findall(r"(?m)^\s*fi\s*$", text))
        self.assertEqual(if_count, fi_count)
        self.assertIn("Type INSTALL", text)
        self.assertIn("plan --config", text)


if __name__ == "__main__":
    unittest.main()
