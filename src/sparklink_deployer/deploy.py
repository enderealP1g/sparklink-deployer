from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

from .descriptor import build_node_descriptor
from .model import DeploymentConfig
from .preflight import run_preflight
from .releases import download_release, extract_binary, load_releases, sha256_file
from .render import render_bundle
from .secrets_store import DeploymentSecrets
from .transaction import Transaction
from .verify import verify_runtime
from .warp import register_or_load, render_wireproxy

if os.name != "nt":
    import grp
    import pwd
else:  # Imported by Windows plan/render tests; install paths remain Linux-only.
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


BACKUP_BASE = Path("/var/backups/sparklink-deployer")
STATE_BASE = Path("/var/lib/sparklink")
MANAGED_SERVICES = (
    "xray.service",
    "sing-box.service",
    "nginx.service",
    "sparklink-wireproxy.service",
    "sparklink-wireproxy-watchdog.timer",
    "certbot.timer",
)


def install(config: DeploymentConfig, project_root: Path, assume_yes: bool) -> str:
    if not assume_yes:
        raise RuntimeError("installation requires explicit --yes after reviewing plan")
    if os.name == "nt" or os.geteuid() != 0:
        raise RuntimeError("installation requires root on Linux")

    preflight = run_preflight(config, strict_host=True)
    preflight.require_ok()
    firewall_was_active = _ufw_is_active()
    transaction = Transaction(BACKUP_BASE)
    staging = STATE_BASE / "staging" / transaction.transaction_id
    staging.mkdir(parents=True, mode=0o700)
    os.chmod(staging, 0o700)
    transaction.add_note(
        f"schema-2 {config.profile.mode} install on a fresh Ubuntu 24.04 host; "
        f"capabilities={','.join(config.profile.capabilities)}"
    )
    try:
        _record_packages(transaction.directory / "packages-before.txt")
        _install_packages(config)
        _ensure_identities()

        releases = load_releases(project_root / "versions.lock.json")
        binary_stage = staging / "binaries"
        installed_versions = {}
        binaries = []
        if config.profile.requires_xray:
            binaries.append(("xray", "xray"))
        if config.profile.active_singbox or "sing-box" in config.profile.standby_cores:
            binaries.append(("sing_box", "sing-box"))
        if config.profile.requires_warp:
            binaries.append(("wireproxy", "wireproxy"))
        for key, binary_name in binaries:
            release = releases[key]
            archive = download_release(release, binary_stage / key)
            binary = extract_binary(archive, binary_name, binary_stage / key)
            installed_versions[key] = {
                "version": release.version,
                "archive_sha256": sha256_file(archive),
                "binary_sha256": sha256_file(binary),
            }
            target_name = "sing-box" if key == "sing_box" else binary_name
            transaction.install_file(binary, f"/usr/local/libexec/sparklink/{target_name}", 0o755, 0, 0)
            transaction.install_symlink(f"/usr/local/libexec/sparklink/{target_name}", f"/usr/local/bin/{target_name}")

        secure_stage = staging / "secure"
        secure_stage.mkdir(mode=0o700)
        if config.profile.requires_xray:
            private_key, public_key = generate_reality_keypair(Path("/usr/local/bin/xray"))
        else:
            private_key, public_key = "", ""
        secrets = DeploymentSecrets.generate(private_key, public_key)
        secrets_path = secure_stage / "secrets.json"
        secrets.write(secrets_path)
        wireproxy_path = None
        if config.profile.requires_warp:
            warp_identity = register_or_load(secure_stage)
            wireproxy_path = secure_stage / "sparklink-hytru.conf"
            wireproxy_path.write_text(render_wireproxy(warp_identity, config.ports.warp_socks), encoding="utf-8")
            os.chmod(wireproxy_path, 0o600)

        _obtain_certificate(config, transaction)
        cert_source = Path(f"/etc/letsencrypt/live/{config.host.direct_domain}")
        rendered = staging / "rendered"
        render_bundle(config, secrets, rendered, include_private=True)
        public_ranges = fetch_cloudflare_ranges() if config.profile.has("cdn-vless-ws") else {}
        ranges_path = staging / "cloudflare-ranges.json"
        ranges_path.write_text(json.dumps(public_ranges, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        _prepare_directories()
        _install_deployer_runtime(project_root, transaction)
        _install_rendered(rendered, transaction)
        transaction.install_file(secrets_path, "/var/lib/sparklink/secure/secrets.json", 0o600, 0, 0)
        if config.profile.requires_warp and wireproxy_path is not None:
            transaction.install_file(secure_stage / "warp-account.json", "/var/lib/sparklink/secure/warp-account.json", 0o600, 0, 0)
            transaction.install_file(secure_stage / "warp-identity.json", "/var/lib/sparklink/secure/warp-identity.json", 0o600, 0, 0)
            transaction.install_file(wireproxy_path, "/etc/wireguard/sparklink-hytru.conf", 0o600, 0, 0)
        if config.profile.requires_certificate:
            _install_certificates(cert_source, transaction)
        versions_path = staging / "versions.json"
        versions_path.write_text(json.dumps(installed_versions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        transaction.install_file(versions_path, "/var/lib/sparklink/public/versions.json", 0o644, 0, 0)
        if config.profile.has("cdn-vless-ws"):
            transaction.install_file(ranges_path, "/var/lib/sparklink/public/cloudflare-ranges.json", 0o644, 0, 0)

        if config.profile.has("cdn-vless-ws"):
            transaction.remove("/etc/nginx/sites-enabled/default")
            transaction.install_symlink("/etc/nginx/sites-available/sparklink", "/etc/nginx/sites-enabled/sparklink")
        _apply_firewall(config, public_ranges, transaction)
        _validate_before_activation(config)
        _activate_services(config)

        results = verify_runtime(config)
        failed = [result.name for result in results if not result.passed]
        if failed:
            raise RuntimeError("server verification failed: " + ", ".join(failed))
        descriptor = build_node_descriptor(config, versions=installed_versions)
        descriptor["health"].update({"state": "verified", "runtime_verified": True})
        transaction.install_text(
            json.dumps(descriptor, indent=2, ensure_ascii=False) + "\n",
            "/var/lib/sparklink/public/node-descriptor.json",
            0o644,
            0,
            0,
        )
        _record_packages(transaction.directory / "packages-after.txt")
        transaction.add_note("server-side verification passed; external client and non-Cloudflare probes remain")
        transaction.finalize()
        return transaction.transaction_id
    except Exception:
        _stop_managed_services()
        transaction.rollback()
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        _restore_ufw_state(firewall_was_active)
        raise


def rollback(transaction_id: str, assume_yes: bool) -> None:
    if not assume_yes:
        raise RuntimeError("rollback requires explicit --yes")
    if not re.fullmatch(r"\d{8}T\d{6}Z", transaction_id):
        raise ValueError("invalid transaction id")
    directory = (BACKUP_BASE / transaction_id).resolve()
    if directory.parent != BACKUP_BASE.resolve() or not directory.is_dir():
        raise ValueError("transaction does not exist under the approved backup root")
    transaction = Transaction.load(directory)
    _stop_managed_services()
    transaction.rollback()
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["ufw", "reload"], check=False)


def generate_reality_keypair(xray_binary: Path) -> tuple[str, str]:
    completed = subprocess.run([os.fspath(xray_binary), "x25519"], capture_output=True, text=True, check=True)
    return parse_reality_keypair(completed.stdout + "\n" + completed.stderr)


def parse_reality_keypair(text: str) -> tuple[str, str]:
    private_key = None
    public_key = None
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        normalized = label.lower().replace(" ", "")
        candidate = value.strip()
        if not candidate:
            continue
        if "private" in normalized:
            private_key = candidate
        elif "public" in normalized or normalized.startswith("password"):
            public_key = candidate
    if not private_key or not public_key or private_key == public_key:
        raise RuntimeError("could not parse Xray x25519 key pair")
    return private_key, public_key


def fetch_cloudflare_ranges() -> dict[str, list[str]]:
    result = {}
    for family, url in (
        ("ipv4", "https://www.cloudflare.com/ips-v4"),
        ("ipv6", "https://www.cloudflare.com/ips-v6"),
    ):
        request = urllib.request.Request(url, headers={"User-Agent": "SparkLink-Deployer/0.1"})
        with urllib.request.urlopen(request, timeout=30) as response:
            lines = [line.strip() for line in response.read().decode().splitlines() if line.strip()]
        networks = [ipaddress.ip_network(line, strict=True) for line in lines]
        expected_version = 4 if family == "ipv4" else 6
        if not networks or any(network.version != expected_version for network in networks):
            raise RuntimeError(f"invalid Cloudflare {family} range response")
        result[family] = [str(network) for network in networks]
    return result


def _install_packages(config: DeploymentConfig) -> None:
    environment = os.environ.copy()
    environment["DEBIAN_FRONTEND"] = "noninteractive"
    subprocess.run(["apt-get", "update"], check=True, env=environment)
    packages = ["ca-certificates", "curl", "unzip", "openssl", "ufw"]
    if config.profile.requires_certificate:
        packages.extend(["nginx", "certbot"])
    subprocess.run(["apt-get", "install", "-y", *packages],
        check=True,
        env=environment,
    )


def _ensure_identities() -> None:
    _run_if_missing(["getent", "group", "sparklink-cert"], ["groupadd", "--system", "sparklink-cert"])
    for name in ("xray", "sing-box"):
        _run_if_missing(["getent", "group", name], ["groupadd", "--system", name])
        _run_if_missing(
            ["id", "-u", name],
            ["useradd", "--system", "--gid", name, "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name],
        )
    subprocess.run(["usermod", "-a", "-G", "sparklink-cert", "sing-box"], check=True)


def _run_if_missing(probe: list[str], create: list[str]) -> None:
    if subprocess.run(probe, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode != 0:
        subprocess.run(create, check=True)


def _obtain_certificate(config: DeploymentConfig, transaction: Transaction) -> None:
    transaction.add_note("Certbot state under /etc/letsencrypt is retained for manual audit after rollback")
    Path("/var/www/html").mkdir(parents=True, exist_ok=True)
    subprocess.run(["systemctl", "enable", "--now", "nginx.service"], check=True)
    domains = [config.host.direct_domain]
    if config.profile.has("cdn-vless-ws"):
        domains.append(config.host.cdn_domain)
    subprocess.run(
        [
            "certbot",
            "certonly",
            "--webroot",
            "--webroot-path",
            "/var/www/html",
            "--non-interactive",
            "--agree-tos",
            "--email",
            config.host.acme_email,
            "--cert-name",
            config.host.direct_domain,
            *sum((["-d", domain] for domain in domains), []),
        ],
        check=True,
    )


def _prepare_directories() -> None:
    directories = {
        "/etc/xray": (0o750, "xray"),
        "/etc/sing-box": (0o750, "sing-box"),
        "/etc/sparklink/tls": (0o750, "sparklink-cert"),
        "/etc/wireguard": (0o700, None),
        "/var/lib/sparklink/secure": (0o700, None),
        "/var/lib/sparklink/private": (0o700, None),
        "/var/lib/sparklink/private/delivery": (0o700, None),
        "/var/lib/sparklink/public": (0o755, None),
        "/usr/local/libexec/sparklink": (0o755, None),
        "/usr/local/libexec/sparklink/deployer": (0o755, None),
        "/usr/local/libexec/sparklink/deployer/sparklink_deployer": (0o755, None),
    }
    for raw, (mode, group_name) in directories.items():
        path = Path(raw)
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
        if group_name is not None:
            os.chown(path, 0, grp.getgrnam(group_name).gr_gid)


def _install_deployer_runtime(project_root: Path, transaction: Transaction) -> None:
    package_root = project_root / "src" / "sparklink_deployer"
    for source in sorted(package_root.glob("*.py")):
        transaction.install_file(
            source,
            f"/usr/local/libexec/sparklink/deployer/sparklink_deployer/{source.name}",
            0o644,
            0,
            0,
        )
    transaction.install_file(project_root / "versions.lock.json", "/usr/local/libexec/sparklink/deployer/versions.lock.json", 0o644, 0, 0)
    wrapper = """#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH=/usr/local/libexec/sparklink/deployer
exec python3 -m sparklink_deployer.cli "$@"
"""
    transaction.install_text(wrapper, "/usr/local/bin/sparklinkctl", 0o755, 0, 0)


def _install_rendered(rendered: Path, transaction: Transaction) -> None:
    xray = pwd.getpwnam("xray")
    sing_box = pwd.getpwnam("sing-box")
    ownership = {
        "/etc/xray/config.json": (0o640, 0, xray.pw_gid),
        "/etc/sing-box/config.json": (0o640, 0, sing_box.pw_gid),
    }
    for source in sorted(path for path in rendered.rglob("*") if path.is_file() and path.name != "MANIFEST.sha256"):
        logical = "/" + source.relative_to(rendered).as_posix()
        mode, uid, gid = ownership.get(logical, (source.stat().st_mode & 0o777, 0, 0))
        if logical.startswith("/var/lib/sparklink/private/"):
            mode = 0o600
        transaction.install_file(source, logical, mode, uid, gid)


def _install_certificates(source: Path, transaction: Transaction) -> None:
    cert_group = grp.getgrnam("sparklink-cert").gr_gid
    transaction.install_file(source / "fullchain.pem", "/etc/sparklink/tls/fullchain.pem", 0o640, 0, cert_group)
    transaction.install_file(source / "privkey.pem", "/etc/sparklink/tls/privkey.pem", 0o640, 0, cert_group)


def _apply_firewall(config: DeploymentConfig, ranges: dict[str, list[str]], transaction: Transaction) -> None:
    for path in ("/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/ufw.conf"):
        transaction.capture(path)
    rules = [["ufw", "allow", f"{config.host.ssh_port}/tcp", "comment", "SparkLink SSH preserve"]]
    if config.profile.has("xray-reality-vision"):
        rules.append(["ufw", "allow", f"{config.ports.reality}/tcp", "comment", "SparkLink REALITY"])
    if config.profile.has("singbox-anytls"):
        rules.append(["ufw", "allow", f"{config.ports.anytls}/tcp", "comment", "SparkLink AnyTLS"])
    if config.profile.has("hysteria2"):
        rules.append(["ufw", "allow", f"{config.ports.hysteria2}/udp", "comment", "SparkLink Hysteria2"])
    subprocess.run(["ufw", "default", "deny", "incoming"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["ufw", "default", "allow", "outgoing"], check=True, stdout=subprocess.DEVNULL)
    if config.profile.requires_certificate and config.firewall.allow_http_for_acme:
        rules.append(["ufw", "allow", "80/tcp", "comment", "SparkLink ACME"])
    for command in rules:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    if config.profile.has("cdn-vless-ws"):
        for family in ("ipv4", "ipv6"):
            for network in ranges[family]:
                subprocess.run(
                    [
                        "ufw",
                        "allow",
                        "from",
                        network,
                        "to",
                        "any",
                        "port",
                        str(config.ports.cdn_origin),
                        "proto",
                        "tcp",
                        "comment",
                        "SparkLink Cloudflare origin",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
    subprocess.run(["ufw", "--force", "enable"], check=True, stdout=subprocess.DEVNULL)


def _validate_before_activation(config: DeploymentConfig) -> None:
    if config.profile.requires_xray:
        subprocess.run(["/usr/local/bin/xray", "run", "-test", "-config", "/etc/xray/config.json"], check=True)
    if config.profile.active_singbox or "sing-box" in config.profile.standby_cores:
        subprocess.run(["/usr/local/bin/sing-box", "check", "-c", "/etc/sing-box/config.json"], check=True)
    if config.profile.requires_warp:
        subprocess.run(["/usr/local/libexec/sparklink/wireproxy", "-n", "-c", "/etc/wireguard/sparklink-hytru.conf"], check=True)
    if config.profile.has("cdn-vless-ws"):
        subprocess.run(["nginx", "-t"], check=True)


def _activate_services(config: DeploymentConfig) -> None:
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    if config.profile.requires_warp:
        subprocess.run(["systemctl", "enable", "--now", "sparklink-wireproxy.service"], check=True)
        for _ in range(30):
            if subprocess.run(
                ["curl", "-fsS", "--max-time", "2", f"http://127.0.0.1:{config.ports.warp_health}/readyz"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("WireProxy readiness did not become healthy")
    services = []
    if config.profile.requires_xray:
        services.append("xray.service")
    if config.profile.active_singbox:
        services.append("sing-box.service")
    if config.profile.has("cdn-vless-ws"):
        services.append("nginx.service")
    if config.profile.requires_warp:
        services.append("sparklink-wireproxy-watchdog.timer")
    if config.profile.requires_certificate:
        services.append("certbot.timer")
    if "nginx.service" in services:
        services.remove("nginx.service")
        subprocess.run(["systemctl", "enable", "--now", "nginx.service"], check=True)
    if services:
        subprocess.run(["systemctl", "enable", "--now", *services], check=True)
    if config.profile.has("cdn-vless-ws"):
        subprocess.run(["systemctl", "reload", "nginx.service"], check=True)
    if not config.profile.active_singbox and "sing-box" in config.profile.standby_cores:
        subprocess.run(["systemctl", "disable", "--now", "sing-box.service"], check=False)


def _stop_managed_services() -> None:
    for service in MANAGED_SERVICES:
        subprocess.run(["systemctl", "disable", "--now", service], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _record_packages(path: Path) -> None:
    completed = subprocess.run(
        ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"],
        capture_output=True,
        text=True,
        check=True,
    )
    path.write_text(completed.stdout, encoding="utf-8")
    os.chmod(path, 0o600)


def _ufw_is_active() -> bool:
    completed = subprocess.run(["ufw", "status"], capture_output=True, text=True, check=False)
    return completed.returncode == 0 and any(
        line.strip().lower() == "status: active" for line in completed.stdout.splitlines()
    )


def _restore_ufw_state(was_active: bool) -> None:
    command = ["ufw", "--force", "enable"] if was_active else ["ufw", "disable"]
    subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
