from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sparklink_deployer.model import ConfigError, DeploymentConfig


ROOT = Path(__file__).resolve().parents[1]


class ModelTests(unittest.TestCase):
    def example(self) -> dict:
        return json.loads((ROOT / "config" / "host.example.json").read_text(encoding="utf-8"))

    def test_example_is_valid(self) -> None:
        config = DeploymentConfig.from_dict(self.example())
        self.assertEqual(config.host.name, "example-la-01")
        self.assertEqual(config.ports.warp_socks, 40000)

    def test_rejects_same_domains(self) -> None:
        raw = self.example()
        raw["host"]["cdn_domain"] = raw["host"]["direct_domain"]
        with self.assertRaisesRegex(ConfigError, "must differ"):
            DeploymentConfig.from_dict(raw)

    def test_rejects_port_collision(self) -> None:
        raw = self.example()
        raw["ports"]["anytls"] = raw["ports"]["reality"]
        with self.assertRaisesRegex(ConfigError, "must be distinct"):
            DeploymentConfig.from_dict(raw)

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
