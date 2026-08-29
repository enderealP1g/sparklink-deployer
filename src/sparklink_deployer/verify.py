from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .model import DeploymentConfig
from .render import HYTRU_CDN_USER, HYTRU_REALITY_USER, build_client_links, build_sing_box, build_xray
from .secrets_store import DeploymentSecrets
from .udp_probe import probe_socks5_udp


@dataclass(frozen=True)
class Verification:
    name: str
    passed: bool
    detail: str


def verify_structure(config: DeploymentConfig, secret: DeploymentSecrets) -> list[Verification]:
    xray = build_xray(config, secret)
    sing_box = build_sing_box(config, secret)
    results: list[Verification] = []

    inbounds = {item["tag"]: item for item in xray["inbounds"]}
    expected = set()
    if config.profile.has("xray-reality-vision"):
        expected.add("reality-in")
    if config.profile.has("cdn-vless-ws"):
        expected.add("cdn-ws-in")
    results.append(Verification("xray-inbounds", set(inbounds) == expected, "selected Xray inbounds"))
    if config.profile.has("cdn-vless-ws"):
        results.append(
            Verification(
                "cdn-loopback",
                inbounds.get("cdn-ws-in", {}).get("listen") == "127.0.0.1",
                "CDN Xray listener is loopback-only",
            )
        )
    if config.profile.has("egress-hytru-warp"):
        warp_rules = [rule for rule in xray["routing"]["rules"] if rule.get("outboundTag") == "warp"]
        expected_users = set()
        if config.profile.has("xray-reality-vision"):
            expected_users.add(HYTRU_REALITY_USER)
        if config.profile.has("cdn-vless-ws"):
            expected_users.add(HYTRU_CDN_USER)
        results.append(
            Verification(
                "xray-hytru-routing",
                len(warp_rules) == 1 and set(warp_rules[0]["user"]) == expected_users,
                "selected HyTru identities route to WireProxy",
            )
        )
    anytls = next((item for item in sing_box["inbounds"] if item.get("tag") == "anytls-in"), None)
    if config.profile.has("singbox-anytls") or "sing-box" in config.profile.standby_cores:
        expected_users = set()
        if config.profile.has("egress-native"):
            expected_users.add("origin-anytls")
        if config.profile.has("egress-hytru-warp"):
            expected_users.add("hytru-anytls")
        results.append(
            Verification(
                "anytls-users",
                anytls is not None and {user["name"] for user in anytls["users"]} == expected_users,
                "selected AnyTLS identities",
            )
        )
        if config.profile.has("egress-hytru-warp"):
            results.append(
                Verification(
                    "singbox-hytru-routing",
                    any(rule.get("auth_user") == ["hytru-anytls"] for rule in sing_box["route"]["rules"]),
                    "HyTru AnyTLS routes to WireProxy",
                )
            )
    if config.profile.has("hysteria2"):
        hysteria2 = next((item for item in sing_box["inbounds"] if item.get("tag") == "hysteria2-in"), None)
        expected_users = set()
        if config.profile.has("egress-native"):
            expected_users.add("origin-hy2")
        if config.profile.has("egress-hytru-warp"):
            expected_users.add("hytru-hy2")
        results.append(
            Verification(
                "hysteria2-inbound",
                hysteria2 is not None
                and hysteria2.get("listen_port") == config.ports.hysteria2
                and {user["name"] for user in hysteria2.get("users", [])} == expected_users,
                "selected Hysteria2 identities and UDP port",
            )
        )
        results.append(
            Verification(
                "hysteria2-obfs",
                hysteria2 is not None and hysteria2.get("obfs", {}).get("type") == "salamander",
                "Hysteria2 Salamander obfuscation",
            )
        )
        if config.profile.has("egress-hytru-warp"):
            results.append(
                Verification(
                    "singbox-hytru-hy2-routing",
                    any(
                        rule.get("inbound") == ["hysteria2-in"]
                        and rule.get("auth_user") == ["hytru-hy2"]
                        and rule.get("outbound") == "warp"
                        for rule in sing_box["route"]["rules"]
                    ),
                    "HyTru Hysteria2 routes to WireProxy",
                )
            )
    return results


def verify_runtime(config: DeploymentConfig) -> list[Verification]:
    if os.name == "nt" or os.geteuid() != 0:
        raise RuntimeError("runtime verification requires root on Linux")
    results: list[Verification] = []
    commands = []
    if config.profile.requires_xray:
        commands.append(("xray-config", ["/usr/local/bin/xray", "run", "-test", "-config", "/etc/xray/config.json"]))
    if config.profile.active_singbox or "sing-box" in config.profile.standby_cores:
        commands.append(("singbox-config", ["/usr/local/bin/sing-box", "check", "-c", "/etc/sing-box/config.json"]))
    if config.profile.has("cdn-vless-ws"):
        commands.append(("nginx-config", ["nginx", "-t"]))
    for name, command in commands:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        results.append(Verification(name, completed.returncode == 0, "syntax check"))

    services = []
    if config.profile.requires_xray:
        services.append("xray.service")
    if config.profile.active_singbox:
        services.append("sing-box.service")
    if config.profile.has("cdn-vless-ws"):
        services.append("nginx.service")
    if config.profile.requires_warp:
        services.append("sparklink-wireproxy.service")
        services.append("sparklink-wireproxy-watchdog.timer")
    if config.profile.requires_certificate:
        services.append("certbot.timer")
    for service in services:
        completed = subprocess.run(["systemctl", "is-active", "--quiet", service], check=False)
        results.append(Verification(f"service-{service}", completed.returncode == 0, "active"))

    if config.profile.requires_warp:
        health_url = f"http://127.0.0.1:{config.ports.warp_health}/readyz"
        try:
            with urllib.request.urlopen(health_url, timeout=3) as response:
                health_ok = response.status == 200
        except OSError:
            health_ok = False
        results.append(Verification("wireproxy-readiness", health_ok, "loopback readiness"))

    if config.profile.requires_warp:
        warp_trace = _curl_trace(config.ports.warp_socks)
        results.append(Verification("hytru-trace", warp_trace.get("warp") == "on", "HyTru reports warp=on"))
        try:
            answers = probe_socks5_udp(config.ports.warp_socks)
            udp_ok = answers > 0
        except (OSError, RuntimeError):
            udp_ok = False
        results.append(Verification("hytru-udp", udp_ok, "SOCKS5 UDP DNS"))
        if config.profile.has("egress-native"):
            direct_trace = _curl_trace(None)
            results.append(Verification("native-trace", direct_trace.get("warp") != "on", "native is not WARP"))
            results.append(
                Verification(
                    "exit-separation",
                    bool(direct_trace.get("ip")) and bool(warp_trace.get("ip")) and direct_trace.get("ip") != warp_trace.get("ip"),
                    "native and HyTru exits differ",
                )
            )

    links = Path("/var/lib/sparklink/private/delivery/client-links.txt")
    link_count = len([line for line in links.read_text(encoding="utf-8").splitlines() if line]) if links.is_file() else 0
    expected_links = len(build_client_links(config, DeploymentSecrets.dummy()))
    results.append(Verification("delivery", link_count == expected_links, f"private client entries={link_count}; expected={expected_links}"))
    return results


def _curl_trace(socks_port: int | None) -> dict[str, str]:
    command = ["curl", "-4fsS", "--max-time", "20"]
    if socks_port is not None:
        command.extend(["--socks5-hostname", f"127.0.0.1:{socks_port}"])
    else:
        command.extend(["--noproxy", "*"])
    command.append("https://www.cloudflare.com/cdn-cgi/trace")
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        return {}
    result = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result
