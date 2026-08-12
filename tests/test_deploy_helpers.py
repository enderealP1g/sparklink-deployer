from __future__ import annotations

import unittest

from sparklink_deployer.deploy import parse_reality_keypair
from sparklink_deployer.warp import WarpIdentity, render_wireproxy


class DeployHelperTests(unittest.TestCase):
    def test_parses_current_xray_key_labels(self) -> None:
        private_key, public_key = parse_reality_keypair("PrivateKey: private\nPassword (PublicKey): public\n")
        self.assertEqual((private_key, public_key), ("private", "public"))

    def test_rejects_incomplete_key_output(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "could not parse"):
            parse_reality_keypair("PrivateKey: only-one\n")

    def test_wireproxy_is_loopback_and_keeps_dual_stack(self) -> None:
        identity = WarpIdentity(
            private_key="private",
            addresses=("172.16.0.2/32", "2606:4700:110::2/128"),
            peer_public_key="public",
            endpoint="engage.cloudflareclient.com:2408",
        )
        value = render_wireproxy(identity, 40000)
        self.assertIn("BindAddress = 127.0.0.1:40000", value)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", value)


if __name__ == "__main__":
    unittest.main()
