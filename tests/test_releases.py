from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from sparklink_deployer.releases import extract_binary, load_releases


ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_lock_has_three_pinned_components(self) -> None:
        releases = load_releases(ROOT / "versions.lock.json")
        self.assertEqual(set(releases), {"xray", "sing_box", "wireproxy"})
        self.assertTrue(all(release.version for release in releases.values()))
        self.assertTrue(all(len(release.sha256) == 64 for release in releases.values()))

    def test_invalid_pinned_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            lock = json.loads((ROOT / "versions.lock.json").read_text(encoding="utf-8"))
            lock["xray"]["sha256"] = "not-a-digest"
            path = Path(raw) / "versions.lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid SHA-256"):
                load_releases(path)

    def test_zip_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escape", b"bad")
            with self.assertRaisesRegex(ValueError, "path traversal"):
                extract_binary(archive, "escape", root / "output")


if __name__ == "__main__":
    unittest.main()
