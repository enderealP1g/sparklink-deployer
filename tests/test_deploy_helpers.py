from __future__ import annotations

import unittest
import json
from pathlib import Path
from unittest.mock import patch

from sparklink_deployer.deploy import _activate_services, _restore_ufw_state, _ufw_is_active, parse_reality_keypair
from sparklink_deployer.model import DeploymentConfig
from sparklink_deployer.render import build_client_links as render_build_client_links
from sparklink_deployer.verify import build_client_links as verify_build_client_links
from sparklink_deployer.warp import WarpIdentity, _build_identity, render_wireproxy


ROOT = Path(__file__).resolve().parents[1]


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

    def test_normalizes_registration_endpoint_zero_port(self) -> None:
        account = {
            "id": "account-id",
            "token": "account-token",
            "config": {
                "interface": {
                    "addresses": {
                        "v4": "172.16.0.2",
                        "v6": "2606:4700:110::2",
                    }
                },
                "peers": [
                    {
                        "endpoint": {"v4": "162.159.192.3:0"},
                        "public_key": "public",
                    }
                ],
            },
        }
        identity = _build_identity(account, "private")
        self.assertEqual(identity.endpoint, "162.159.192.3:2408")

    @patch("sparklink_deployer.deploy.subprocess.run")
    def test_ufw_state_helpers_preserve_inactive_state(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = "Status: inactive\n"
        self.assertFalse(_ufw_is_active())
        _restore_ufw_state(False)
        self.assertEqual(run.call_args.args[0], ["ufw", "disable"])

    def test_runtime_verification_uses_render_client_link_builder(self) -> None:
        self.assertIs(verify_build_client_links, render_build_client_links)

    @patch("sparklink_deployer.deploy.subprocess.run")
    def test_cdn_activation_reloads_nginx_after_installing_config(self, run) -> None:
        raw = json.loads((ROOT / "config" / "host.example.json").read_text(encoding="utf-8"))
        raw["profile"] = {
            "mode": "custom",
            "capabilities": ["xray-reality-vision", "egress-native", "cdn-vless-ws"],
            "primary_core": "xray",
            "standby_cores": [],
        }
        config = DeploymentConfig.from_dict(raw)
        _activate_services(config)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(["systemctl", "enable", "--now", "nginx.service"], commands)
        self.assertIn(["systemctl", "reload", "nginx.service"], commands)


if __name__ == "__main__":
    unittest.main()
