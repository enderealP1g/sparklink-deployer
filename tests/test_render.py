from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sparklink_deployer.model import DeploymentConfig
from sparklink_deployer.render import (
    build_client_links,
    build_nginx,
    build_sing_box,
    build_wireproxy_service,
    build_xray,
    render_bundle,
)
from sparklink_deployer.secrets_store import DeploymentSecrets
from sparklink_deployer.verify import verify_structure


ROOT = Path(__file__).resolve().parents[1]


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        example = json.loads((ROOT / "config" / "host.example.json").read_text(encoding="utf-8"))
        example["profile"] = {
            "mode": "custom",
            "capabilities": [
                "xray-reality-vision",
                "egress-native",
                "egress-hytru-warp",
                "singbox-anytls",
                "cdn-vless-ws",
            ],
            "primary_core": "xray",
            "standby_cores": ["sing-box"],
        }
        self.config = DeploymentConfig.from_dict(example)
        self.recommended = DeploymentConfig.load(ROOT / "config" / "host.example.json")
        self.secret = DeploymentSecrets.dummy()
        self.secret.validate()

    def test_xray_routes_only_hytru_users_to_warp(self) -> None:
        value = build_xray(self.config, self.secret)
        rules = value["routing"]["rules"]
        warp = [rule for rule in rules if rule["outboundTag"] == "warp"]
        direct = [rule for rule in rules if rule["outboundTag"] == "direct"]
        self.assertEqual(len(warp), 1)
        self.assertEqual(set(warp[0]["user"]), {"hytru-reality", "hytru-cdn"})
        self.assertEqual(set(direct[0]["user"]), {"origin-reality", "origin-cdn"})

    def test_cdn_is_loopback_and_private_path(self) -> None:
        value = build_xray(self.config, self.secret)
        cdn = next(item for item in value["inbounds"] if item["tag"] == "cdn-ws-in")
        self.assertEqual(cdn["listen"], "127.0.0.1")
        self.assertEqual(cdn["streamSettings"]["wsSettings"]["path"], self.secret.cdn_path)
        nginx = build_nginx(self.config, self.secret)
        self.assertIn(f"location = {self.secret.cdn_path}", nginx)
        self.assertIn("proxy_pass http://127.0.0.1:10080", nginx)

    def test_singbox_has_two_anytls_users(self) -> None:
        value = build_sing_box(self.config, self.secret)
        users = value["inbounds"][0]["users"]
        self.assertEqual({user["name"] for user in users}, {"origin-anytls", "hytru-anytls"})
        self.assertEqual(value["route"]["rules"][0]["outbound"], "warp")

    def test_wireproxy_unit_retains_af_netlink(self) -> None:
        unit = build_wireproxy_service(self.config)
        self.assertIn("AF_NETLINK", unit)
        self.assertIn("127.0.0.1:40002", unit)

    def test_client_delivery_contains_exactly_six_entries(self) -> None:
        links = build_client_links(self.config, self.secret)
        self.assertEqual(len(links), 6)
        self.assertEqual(sum(link.startswith("vless://") for link in links), 4)
        self.assertEqual(sum(link.startswith("anytls://") for link in links), 2)
        self.assertEqual(sum("-Origin-" in link for link in links), 3)
        self.assertEqual(sum("-HyTru-" in link for link in links), 3)

    def test_public_bundle_excludes_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw)
            digests = render_bundle(self.config, self.secret, output, include_private=False)
            self.assertFalse((output / "var/lib/sparklink/private").exists())
            self.assertIn("etc/xray/config.json", digests)

    def test_private_bundle_delivery_is_six_lines(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw)
            render_bundle(self.config, self.secret, output, include_private=True)
            path = output / "var/lib/sparklink/private/delivery/client-links.txt"
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 6)

    def test_structural_verification_passes(self) -> None:
        results = verify_structure(self.config, self.secret)
        self.assertTrue(results)
        self.assertTrue(all(result.passed for result in results))

    def test_recommended_only_exposes_reality_and_keeps_singbox_standby(self) -> None:
        xray = build_xray(self.recommended, self.secret)
        self.assertEqual({item["tag"] for item in xray["inbounds"]}, {"reality-in"})
        singbox = build_sing_box(self.recommended, self.secret)
        self.assertEqual({item["tag"] for item in singbox["inbounds"]}, {"anytls-in"})
        self.assertEqual(len(build_client_links(self.recommended, self.secret)), 2)

    def test_recommended_bundle_omits_cdn_and_nginx(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw)
            render_bundle(self.recommended, self.secret, output, include_private=False)
            self.assertFalse((output / "etc/nginx").exists())
            self.assertTrue((output / "etc/systemd/system/sparklink-wireproxy.service").exists())


if __name__ == "__main__":
    unittest.main()
