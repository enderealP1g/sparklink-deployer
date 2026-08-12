from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sparklink_deployer.transaction import Transaction


class TransactionTests(unittest.TestCase):
    def test_rollback_restores_existing_and_removes_created_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "root"
            backups = base / "backups"
            root.mkdir()
            existing = root / "etc" / "example.conf"
            existing.parent.mkdir(parents=True)
            existing.write_text("before\n", encoding="utf-8")
            source = base / "source"
            source.write_text("after\n", encoding="utf-8")

            transaction = Transaction(backups, root=root, transaction_id="20260810T000000Z")
            transaction.install_file(source, "/etc/example.conf", 0o600)
            transaction.install_file(source, "/etc/new.conf", 0o600)
            self.assertEqual(existing.read_text(encoding="utf-8"), "after\n")
            transaction.rollback()

            self.assertEqual(existing.read_text(encoding="utf-8"), "before\n")
            self.assertFalse((root / "etc" / "new.conf").exists())

    def test_relative_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "root"
            root.mkdir()
            transaction = Transaction(base / "backups", root=root, transaction_id="20260810T000001Z")
            with self.assertRaisesRegex(ValueError, "must be absolute"):
                transaction.capture("etc/not-absolute")

    def test_final_symlink_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            root = base / "root"
            backups = base / "backups"
            available = root / "etc" / "nginx" / "sites-available"
            enabled = root / "etc" / "nginx" / "sites-enabled"
            available.mkdir(parents=True)
            enabled.mkdir(parents=True)
            target = available / "default"
            target.write_text("original target\n", encoding="utf-8")
            link = enabled / "default"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks are unavailable in this Windows session")
            transaction = Transaction(backups, root=root, transaction_id="20260810T000002Z")
            transaction.remove("/etc/nginx/sites-enabled/default")
            self.assertTrue(target.exists())
            self.assertFalse(link.exists())
            transaction.rollback()
            self.assertTrue(link.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "original target\n")


if __name__ == "__main__":
    unittest.main()
