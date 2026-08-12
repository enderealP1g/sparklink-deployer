from __future__ import annotations

import dataclasses
import ipaddress
import os
import platform
import shutil
import socket
import ssl
import subprocess
import urllib.request
from pathlib import Path

from .model import DeploymentConfig, split_host_port


@dataclasses.dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


@dataclasses.dataclass(frozen=True)
class PreflightReport:
    checks: tuple[Check, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def require_ok(self) -> None:
        failed = [check for check in self.checks if not check.ok]
        if failed:
            summary = "; ".join(f"{check.name}: {check.detail}" for check in failed)
            raise RuntimeError(f"preflight failed: {summary}")


def planned_changes(config: DeploymentConfig) -> list[str]:
    return [
        "install pinned Xray, sing-box, WireProxy, Nginx, Certbot and required utilities",
        f"open SSH TCP/{config.host.ssh_port} before enabling UFW",
        f"open VLESS REALITY TCP/{config.ports.reality}",
        f"open AnyTLS TCP/{config.ports.anytls}",
        f"restrict CDN origin TCP/{config.ports.cdn_origin} to official Cloudflare ranges",
        "generate six independent client identities and one WARP identity as root-only files",
        "install dedicated xray, sing-box and certificate-access system users/groups",
        "install Xray, sing-box, WireProxy and watchdog systemd units",
        "obtain a two-hostname certificate with Certbot and install a renewal hook",
        "write private delivery links below /var/lib/sparklink/private/delivery",
        "record every touched file and firewall baseline in a transaction backup",
    ]


def run_preflight(config: DeploymentConfig, strict_host: bool) -> PreflightReport:
    checks: list[Check] = []
    checks.append(Check("configuration", True, "schema and invariants passed"))
    if not strict_host:
        checks.append(Check("host-mode", True, "portable plan; VPS checks deferred"))
        return PreflightReport(tuple(checks))

    checks.extend(_linux_checks(config))
    return PreflightReport(tuple(checks))


def _linux_checks(config: DeploymentConfig) -> list[Check]:
    checks: list[Check] = []
    checks.append(Check("root", os.geteuid() == 0, "root required" if os.geteuid() else "root"))
    checks.append(Check("kernel", platform.system() == "Linux", platform.system()))
    machine = platform.machine().lower()
    checks.append(Check("architecture", machine in {"x86_64", "amd64"}, machine))

    os_release = _read_os_release()
    distro_ok = os_release.get("ID") == "ubuntu" and os_release.get("VERSION_ID") == "24.04"
    checks.append(
        Check(
            "distribution",
            distro_ok,
            f"{os_release.get('ID', 'unknown')} {os_release.get('VERSION_ID', 'unknown')}",
        )
    )
    checks.append(Check("systemd", Path("/run/systemd/system").is_dir(), "systemd runtime"))

    required = ("apt-get", "systemctl", "ss")
    missing = [command for command in required if shutil.which(command) is None]
    checks.append(Check("required-commands", not missing, "missing=" + ",".join(missing) if missing else "present"))

    conflicts = []
    for path in (
        Path("/etc/x-ui"),
        Path("/usr/local/x-ui"),
        Path("/etc/xray/config.json"),
        Path("/etc/sing-box/config.json"),
        Path("/etc/nginx/nginx.conf"),
        Path("/etc/nginx/sites-enabled/sparklink"),
        Path("/var/lib/sparklink/secure/secrets.json"),
    ):
        if path.exists() or path.is_symlink():
            conflicts.append(os.fspath(path))
    checks.append(Check("fresh-host", not conflicts, "conflicts=" + ",".join(conflicts) if conflicts else "clean"))

    listeners = _listeners()
    intended = {
        config.host.ssh_port,
        config.ports.reality,
        config.ports.anytls,
        config.ports.cdn_origin,
        config.ports.cdn_loopback,
        config.ports.warp_socks,
        config.ports.warp_health,
    }
    occupied = sorted(intended.intersection(listeners).difference({config.host.ssh_port}))
    checks.append(Check("ports", not occupied, "occupied=" + ",".join(map(str, occupied)) if occupied else "available"))

    direct_addresses = _resolve(config.host.direct_domain)
    checks.append(Check("direct-dns", bool(direct_addresses), f"answers={len(direct_addresses)}"))
    cdn_addresses = _resolve(config.host.cdn_domain)
    checks.append(Check("cdn-dns", bool(cdn_addresses), f"answers={len(cdn_addresses)}"))
    public_ipv4 = _native_public_ipv4()
    checks.append(Check("public-ip", bool(public_ipv4), "native IPv4 detected" if public_ipv4 else "unavailable"))
    checks.append(
        Check(
            "direct-dns-target",
            bool(public_ipv4) and public_ipv4 in direct_addresses,
            "direct hostname points to this VPS" if public_ipv4 in direct_addresses else "does not match native IPv4",
        )
    )
    checks.append(
        Check(
            "cdn-certificate-phase",
            bool(public_ipv4) and public_ipv4 in cdn_addresses,
            "CDN hostname is DNS-only for certificate issuance"
            if public_ipv4 in cdn_addresses
            else "CDN must be DNS-only and point to this VPS before install",
        )
    )

    target_host, target_port = split_host_port(config.reality.target)
    tls_ok, tls_detail = _tls_probe(target_host, target_port)
    checks.append(Check("reality-target-tls", tls_ok, tls_detail))
    return checks


def _read_os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.is_file():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def _listeners() -> set[int]:
    completed = subprocess.run(["ss", "-H", "-lntup"], capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        return set()
    ports: set[int] = set()
    for line in completed.stdout.splitlines():
        fields = line.split()
        for field in fields:
            if ":" not in field:
                continue
            candidate = field.rsplit(":", 1)[-1].rstrip(",")
            if candidate.isdigit():
                ports.add(int(candidate))
                break
    return ports


def _resolve(host: str) -> set[str]:
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return set()
    return {answer[4][0] for answer in answers}


def _tls_probe(host: str, port: int) -> tuple[bool, str]:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((host, port), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=host) as wrapped:
                return True, f"TLS={wrapped.version()} ALPN={wrapped.selected_alpn_protocol() or 'none'}"
    except OSError as exc:
        return False, type(exc).__name__


def _native_public_ipv4() -> str | None:
    request = urllib.request.Request(
        "https://www.cloudflare.com/cdn-cgi/trace",
        headers={"User-Agent": "SparkLink-Deployer/0.1"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            text = response.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    candidate = values.get("ip")
    if not candidate:
        return None
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(parsed) if parsed.version == 4 else None
