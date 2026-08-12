from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .model import DeploymentConfig
from .render import HYTRU_CDN_USER, HYTRU_REALITY_USER, build_sing_box, build_xray
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
    results.append(Verification("xray-inbounds", set(inbounds) == {"reality-in", "cdn-ws-in"}, "Reality and CDN"))
    results.append(
        Verification(
            "cdn-loopback",
            inbounds["cdn-ws-in"]["listen"] == "127.0.0.1",
            "CDN Xray listener is loopback-only",
        )
    )
    warp_rules = [rule for rule in xray["routing"]["rules"] if rule.get("outboundTag") == "warp"]
    results.append(
        Verification(
            "xray-hytru-routing",
            len(warp_rules) == 1 and set(warp_rules[0]["user"]) == {HYTRU_REALITY_USER, HYTRU_CDN_USER},
            "HyTru identities route to WireProxy",
        )
    )
    anytls = sing_box["inbounds"][0]
    results.append(
        Verification(
            "anytls-users",
            {user["name"] for user in anytls["users"]} == {"origin-anytls", "hytru-anytls"},
            "two independent AnyTLS identities",
        )
    )
    results.append(
        Verification(
            "singbox-hytru-routing",
            sing_box["route"]["rules"][0].get("auth_user") == ["hytru-anytls"],
            "HyTru AnyTLS routes to WireProxy",
        )
    )
    return results


def verify_runtime(config: DeploymentConfig) -> list[Verification]:
    if os.name == "nt" or os.geteuid() != 0:
        raise RuntimeError("runtime verification requires root on Linux")
    results: list[Verification] = []
    commands = [
        ("xray-config", ["/usr/local/bin/xray", "run", "-test", "-config", "/etc/xray/config.json"]),
        ("singbox-config", ["/usr/local/bin/sing-box", "check", "-c", "/etc/sing-box/config.json"]),
        ("nginx-config", ["nginx", "-t"]),
    ]
    for name, command in commands:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        results.append(Verification(name, completed.returncode == 0, "syntax check"))

    services = (
        "xray.service",
        "sing-box.service",
        "nginx.service",
        "sparklink-wireproxy.service",
        "sparklink-wireproxy-watchdog.timer",
        "certbot.timer",
    )
    for service in services:
        completed = subprocess.run(["systemctl", "is-active", "--quiet", service], check=False)
        results.append(Verification(f"service-{service}", completed.returncode == 0, "active"))

    health_url = f"http://127.0.0.1:{config.ports.warp_health}/readyz"
    try:
        with urllib.request.urlopen(health_url, timeout=3) as response:
            health_ok = response.status == 200
    except OSError:
        health_ok = False
    results.append(Verification("wireproxy-readiness", health_ok, "loopback readiness"))

    direct_trace = _curl_trace(None)
    warp_trace = _curl_trace(config.ports.warp_socks)
    results.append(Verification("native-trace", direct_trace.get("warp") != "on", "native is not WARP"))
    results.append(Verification("hytru-trace", warp_trace.get("warp") == "on", "HyTru reports warp=on"))
    results.append(
        Verification(
            "exit-separation",
            bool(direct_trace.get("ip")) and bool(warp_trace.get("ip")) and direct_trace.get("ip") != warp_trace.get("ip"),
            "native and HyTru exits differ",
        )
    )
    try:
        answers = probe_socks5_udp(config.ports.warp_socks)
        udp_ok = answers > 0
    except (OSError, RuntimeError):
        udp_ok = False
    results.append(Verification("hytru-udp", udp_ok, "SOCKS5 UDP DNS"))

    links = Path("/var/lib/sparklink/private/delivery/client-links.txt")
    link_count = len([line for line in links.read_text(encoding="utf-8").splitlines() if line]) if links.is_file() else 0
    results.append(Verification("delivery", link_count == 6, f"private client entries={link_count}"))
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
