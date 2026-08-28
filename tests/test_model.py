from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sparklink_deployer.model import ConfigError, DeploymentConfig
from sparklink_deployer.capabilities import CAPABILITY_CATALOG


ROOT = Path(__file__).resolve().parents[1]


class ModelTests(unittest.TestCase):
    def example(self) -> dict:
        return json.loads((ROOT / "config" / "host.example.json").read_text(encoding="utf-8"))

    def test_example_is_valid(self) -> None:
        config = DeploymentConfig.from_dict(self.example())
        self.assertEqual(config.host.name, "example-la-01")
        self.assertEqual(config.ports.warp_socks, 40000)
        self.assertEqual(config.profile.mode, "recommended")
        self.assertFalse(config.profile.has("cdn-vless-ws"))

    def test_rejects_same_domains(self) -> None:
        raw = self.example()
        raw["host"]["cdn_domain"] = raw["host"]["direct_domain"]
        with self.assertRaisesRegex(ConfigError, "must differ"):
            DeploymentConfig.from_dict(raw)

    def test_rejects_port_collision(self) -> None:
        raw = self.example()
        raw["profile"]["mode"] = "custom"
        raw["profile"]["capabilities"].append("singbox-anytls")
        raw["ports"]["anytls"] = raw["ports"]["reality"]
        with self.assertRaisesRegex(ConfigError, "must be distinct"):
            DeploymentConfig.from_dict(raw)

    def test_schema_one_loads_as_legacy_custom_profile(self) -> None:
        raw = self.example()
        raw.pop("profile")
        raw["schema_version"] = 1
        config = DeploymentConfig.from_dict(raw)
        self.assertEqual(config.schema_version, 2)
        self.assertEqual(config.profile.mode, "custom")
        self.assertTrue(config.profile.has("cdn-vless-ws"))

    def test_hysteria2_is_custom_only(self) -> None:
        raw = self.example()
        raw["profile"]["capabilities"].append("hysteria2")
        with self.assertRaisesRegex(ConfigError, "recommended profile"):
            DeploymentConfig.from_dict(raw)

        raw["profile"]["mode"] = "custom"
        raw["profile"]["capabilities"] = ["hysteria2", "egress-native"]
        with self.assertRaisesRegex(ConfigError, "PR3 renderer"):
            DeploymentConfig.from_dict(raw)

    def test_catalog_has_stable_pr2_ids(self) -> None:
        ids = {spec.capability_id for spec in CAPABILITY_CATALOG}
        self.assertTrue({"xray-reality-vision", "egress-native", "egress-hytru-warp", "hysteria2"} <= ids)

    def test_custom_can_omit_cdn_and_accept_empty_cloudflare_facts(self) -> None:
        raw = self.example()
        raw["profile"] = {
            "mode": "custom",
            "capabilities": ["singbox-anytls", "egress-native"],
            "primary_core": "xray",
            "standby_cores": [],
        }
        raw["host"]["cdn_domain"] = ""
        raw["cloudflare"]["managed_externally"] = False
        config = DeploymentConfig.from_dict(raw)
        self.assertFalse(config.profile.has("cdn-vless-ws"))

    def test_rejects_unknown_key(self) -> None:
        raw = self.example()
        raw["host"]["private_key"] = "must-never-be-here"
        with self.assertRaisesRegex(ConfigError, "unexpected host keys"):
            DeploymentConfig.from_dict(raw)

    def test_reality_target_must_match_server_names(self) -> None:
        raw = self.example()
        raw["reality"]["server_names"] = ["www.example.org"]
        with self.assertRaisesRegex(ConfigError, "must be included"):
            DeploymentConfig.from_dict(raw)


if __name__ == "__main__":
    unittest.main()
