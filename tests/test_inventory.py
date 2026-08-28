from __future__ import annotations

import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from sparklink_deployer.inventory import (
    HostObservation,
    build_adoption_plan,
    load_inventory,
    load_manager_inventories,
    write_manager_inventory,
)


class InventoryTests(unittest.TestCase):
    def fixture(self, family: str) -> dict:
        services = {
            "xray": {
                "installed": True,
                "version": "Xray 26.7.28",
                "manager": "systemd",
                "active": True,
                "enabled": True,
                "config_paths": ["/etc/xray/config.json"],
            }
        }
        markers = ["xray_config", "xray_reality_listener"]
        listeners = [{"protocol": "tcp", "address": "0.0.0.0", "port": 443, "process": "xray"}]
        if family == "racknerd":
            markers += ["xui", "xray_api"]
            services["xray"]["config_paths"] = ["/usr/local/x-ui/bin/config.json"]
            services["xray"]["manager"] = "x-ui"
        elif family == "vmiss":
            markers += ["xui", "sing_box_config", "anytls_listener", "wireproxy_config", "warp", "nginx_config", "nginx_cdn"]
            services.update(
                {
                    "sing-box": {"installed": True, "version": "sing-box 1.13.16", "manager": "systemd", "active": True, "enabled": True, "config_paths": ["/etc/sing-box/config.json"]},
                    "nginx": {"installed": True, "version": "nginx/1.24", "manager": "systemd", "active": True, "enabled": True, "config_paths": ["/etc/nginx/nginx.conf"]},
                    "wireproxy": {"installed": True, "version": "WireProxy 1.1.3", "manager": "systemd", "active": True, "enabled": True, "config_paths": ["/etc/wireguard/proxy.conf"]},
                }
            )
            listeners += [
                {"protocol": "tcp", "address": "0.0.0.0", "port": 9443, "process": "sing-box"},
                {"protocol": "tcp", "address": "0.0.0.0", "port": 2053, "process": "nginx"},
            ]
        else:
            markers += ["sing_box_config", "anytls_listener", "nginx_config"]
            services.update(
                {
                    "sing-box": {"installed": True, "version": "sing-box 1.13.16", "manager": "systemd", "active": True, "enabled": True, "config_paths": ["/etc/sing-box/config.json"]},
                    "nginx": {"installed": True, "version": "nginx/1.24", "manager": "systemd", "active": True, "enabled": True, "config_paths": ["/etc/nginx/nginx.conf"]},
                }
            )
            listeners.append({"protocol": "tcp", "address": "0.0.0.0", "port": 9443, "process": "sing-box"})
        return {
            "schema_version": 1,
            "host": {"name": family + "-01", "provider": family, "endpoint": "198.51.100.10"},
            "system": {"os_id": "ubuntu", "os_version": "24.04", "architecture": "x86_64", "kernel": "6.8"},
            "services": services,
            "listeners": listeners,
            "markers": markers,
            "config_fingerprints": {"/etc/xray/config.json": "a" * 64},
            "observed_capabilities": [],
            "collected_at": "2026-08-28T00:00:00+00:00",
            "source": "fixture",
        }

    def test_three_known_layouts_are_distinguished(self) -> None:
        racknerd = HostObservation.from_dict(self.fixture("racknerd"))
        vmiss = HostObservation.from_dict(self.fixture("vmiss"))
        dedirock = HostObservation.from_dict(self.fixture("dedirock"))
        self.assertEqual(racknerd.family(), "known-xui-xray")
        self.assertEqual(vmiss.family(), "known-xui-xray-singbox")
        self.assertEqual(dedirock.family(), "known-systemd-xray-singbox")
        self.assertIn("egress-hytru-warp", vmiss.capabilities())
        self.assertNotIn("hysteria2", vmiss.capabilities())

    def test_sparklink_descriptor_marks_managed_host(self) -> None:
        raw = self.fixture("dedirock")
        raw["markers"].append("sparklink_descriptor")
        raw["observed_capabilities"] = ["xray-reality-vision", "egress-native"]
        observation = HostObservation.from_dict(raw)
        plan = build_adoption_plan(observation)
        self.assertEqual(observation.family(), "sparklink-managed")
        self.assertEqual(plan.status, "managed")

    def test_adoption_plan_is_read_only_and_reports_gaps(self) -> None:
        observation = HostObservation.from_dict(self.fixture("racknerd"))
        plan = build_adoption_plan(observation)
        self.assertEqual(plan.status, "review-required")
        self.assertTrue(plan.to_dict()["requires_explicit_approval"])
        self.assertIn("egress-hytru-warp", plan.gaps)
        self.assertTrue(any("x-ui" in risk for risk in plan.risks))

    def test_secret_like_input_is_redacted_before_storage(self) -> None:
        raw = self.fixture("dedirock")
        raw["host"]["subscription_token"] = "do-not-store"
        with tempfile.TemporaryDirectory() as raw_dir:
            source = Path(raw_dir) / "input.json"
            source.write_text(json.dumps(raw), encoding="utf-8")
            loaded = load_inventory(source)
            destination = write_manager_inventory(loaded, Path(raw_dir) / "manager")
            text = destination.read_text(encoding="utf-8")
            self.assertNotIn("do-not-store", text)
            self.assertNotIn("subscription_token", text)

    def test_manager_inventory_round_trip(self) -> None:
        observation = HostObservation.from_dict(self.fixture("vmiss"))
        with tempfile.TemporaryDirectory() as raw_dir:
            manager_root = Path(raw_dir)
            path = write_manager_inventory(observation, manager_root)
            self.assertTrue(path.is_file())
            loaded = load_manager_inventories(manager_root)
            self.assertEqual([item.name for item in loaded], ["vmiss-01"])

    def test_remote_collection_uses_stdin_python_and_no_mutating_command(self) -> None:
        from sparklink_deployer.inventory import REMOTE_COLLECTOR_SCRIPT, collect_remote_inventory

        class Result:
            returncode = 0
            stderr = ""
            stdout = json.dumps(self.fixture("dedirock"))

        with patch("sparklink_deployer.inventory.subprocess.run", return_value=Result()) as mocked:
            observation = collect_remote_inventory("dedirock-admin", name="dedirock-01")
        command = mocked.call_args.args[0]
        self.assertEqual(command[:1], ["ssh"])
        self.assertEqual(command[-2:], ["python3", "-"])
        self.assertIn("systemctl", mocked.call_args.kwargs["input"])
        self.assertNotIn("systemctl restart", mocked.call_args.kwargs["input"])
        self.assertEqual(observation.name, "dedirock-01")
        compile(REMOTE_COLLECTOR_SCRIPT, "remote-collector", "exec")


if __name__ == "__main__":
    unittest.main()
