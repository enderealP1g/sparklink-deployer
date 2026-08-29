from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote, urlencode

from .descriptor import build_node_descriptor
from .model import DeploymentConfig
from .secrets_store import DeploymentSecrets


ORIGIN_REALITY_USER = "origin-reality"
HYTRU_REALITY_USER = "hytru-reality"
ORIGIN_CDN_USER = "origin-cdn"
HYTRU_CDN_USER = "hytru-cdn"


def build_xray(config: DeploymentConfig, secret: DeploymentSecrets) -> dict:
    inbounds: list[dict] = []
    if config.profile.has("xray-reality-vision"):
        clients = []
        if config.profile.has("egress-native"):
            clients.append({"id": secret.reality_origin_uuid, "email": ORIGIN_REALITY_USER, "flow": "xtls-rprx-vision"})
        if config.profile.has("egress-hytru-warp"):
            clients.append({"id": secret.reality_hytru_uuid, "email": HYTRU_REALITY_USER, "flow": "xtls-rprx-vision"})
        inbounds.append(
            {
                "tag": "reality-in",
                "listen": "::",
                "port": config.ports.reality,
                "protocol": "vless",
                "settings": {"clients": clients, "decryption": "none"},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": config.reality.target,
                        "xver": 0,
                        "serverNames": list(config.reality.server_names),
                        "privateKey": secret.reality_private_key,
                        "shortIds": [secret.reality_short_id],
                    },
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            }
        )
    if config.profile.has("cdn-vless-ws"):
        clients = []
        if config.profile.has("egress-native"):
            clients.append({"id": secret.cdn_origin_uuid, "email": ORIGIN_CDN_USER})
        if config.profile.has("egress-hytru-warp"):
            clients.append({"id": secret.cdn_hytru_uuid, "email": HYTRU_CDN_USER})
        inbounds.append(
            {
                "tag": "cdn-ws-in",
                "listen": "127.0.0.1",
                "port": config.ports.cdn_loopback,
                "protocol": "vless",
                "settings": {"clients": clients, "decryption": "none"},
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": secret.cdn_path},
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            }
        )

    outbounds = [{"tag": "direct", "protocol": "freedom", "settings": {}}]
    if config.profile.requires_warp:
        outbounds.append(
            {
                "tag": "warp",
                "protocol": "socks",
                "settings": {"servers": [{"address": "127.0.0.1", "port": config.ports.warp_socks}]},
            }
        )
    outbounds.append({"tag": "blocked", "protocol": "blackhole", "settings": {}})
    rules: list[dict] = []
    if config.profile.has("egress-hytru-warp"):
        users = []
        if config.profile.has("xray-reality-vision"):
            users.append(HYTRU_REALITY_USER)
        if config.profile.has("cdn-vless-ws"):
            users.append(HYTRU_CDN_USER)
        if users:
            rules.append({"type": "field", "user": users, "network": "tcp,udp", "outboundTag": "warp"})
    native_users = []
    if config.profile.has("xray-reality-vision"):
        native_users.append(ORIGIN_REALITY_USER)
    if config.profile.has("cdn-vless-ws"):
        native_users.append(ORIGIN_CDN_USER)
    if native_users:
        rules.append({"type": "field", "user": native_users, "network": "tcp,udp", "outboundTag": "direct"})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


def build_sing_box(config: DeploymentConfig, secret: DeploymentSecrets) -> dict:
    inbounds: list[dict] = []
    wants_anytls = config.profile.has("singbox-anytls") or "sing-box" in config.profile.standby_cores
    if wants_anytls:
        users = []
        if config.profile.has("egress-native"):
            users.append({"name": "origin-anytls", "password": secret.anytls_origin_password})
        if config.profile.has("egress-hytru-warp"):
            users.append({"name": "hytru-anytls", "password": secret.anytls_hytru_password})
        if users:
            inbounds.append(
                {
                    "type": "anytls",
                    "tag": "anytls-in",
                    "listen": "::",
                    "listen_port": config.ports.anytls,
                    "users": users,
                    "tls": {
                        "enabled": True,
                        "certificate_path": "/etc/sparklink/tls/fullchain.pem",
                        "key_path": "/etc/sparklink/tls/privkey.pem",
                    },
                }
            )
    if config.profile.has("hysteria2"):
        _require_hy2_secrets(secret)
        users = []
        if config.profile.has("egress-native"):
            users.append({"name": "origin-hy2", "password": secret.hy2_origin_password})
        if config.profile.has("egress-hytru-warp"):
            users.append({"name": "hytru-hy2", "password": secret.hy2_hytru_password})
        inbounds.append(
            {
                "type": "hysteria2",
                "tag": "hysteria2-in",
                "listen": "::",
                "listen_port": config.ports.hysteria2,
                "users": users,
                "obfs": {"type": "salamander", "password": secret.hy2_obfs_password},
                "tls": {
                    "enabled": True,
                    "certificate_path": "/etc/sparklink/tls/fullchain.pem",
                    "key_path": "/etc/sparklink/tls/privkey.pem",
                },
            }
        )
    outbounds = [{"type": "direct", "tag": "direct"}]
    rules: list[dict] = []
    if config.profile.requires_warp:
        outbounds.append(
            {
                "type": "socks",
                "tag": "warp",
                "server": "127.0.0.1",
                "server_port": config.ports.warp_socks,
                "version": "5",
            }
        )
        if config.profile.has("egress-hytru-warp"):
            rules.append({"inbound": ["anytls-in"], "auth_user": ["hytru-anytls"], "action": "route", "outbound": "warp"})
    if config.profile.has("hysteria2") and config.profile.has("egress-hytru-warp"):
        rules.append({"inbound": ["hysteria2-in"], "auth_user": ["hytru-hy2"], "action": "route", "outbound": "warp"})
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"auto_detect_interface": True, "rules": rules, "final": "direct"},
    }


def build_nginx(config: DeploymentConfig, secret: DeploymentSecrets) -> str:
    if not config.profile.has("cdn-vless-ws"):
        raise ValueError("CDN capability is disabled")
    return f"""server {{
    listen 80;
    listen [::]:80;
    server_name {config.host.direct_domain} {config.host.cdn_domain};
    location ^~ /.well-known/acme-challenge/ {{ root /var/www/html; }}
    location / {{ return 404; }}
}}

server {{
    listen {config.ports.cdn_origin} ssl;
    listen [::]:{config.ports.cdn_origin} ssl;
    server_name {config.host.cdn_domain};

    ssl_certificate /etc/sparklink/tls/fullchain.pem;
    ssl_certificate_key /etc/sparklink/tls/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log off;

    location = {secret.cdn_path} {{
        proxy_pass http://127.0.0.1:{config.ports.cdn_loopback};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }}

    location / {{ return 404; }}
}}
"""


def build_xray_service() -> str:
    return """[Unit]
Description=SparkLink Xray ingress
Wants=network-online.target sparklink-wireproxy.service
After=network-online.target

[Service]
Type=simple
User=xray
Group=xray
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
"""


def build_sing_box_service() -> str:
    return """[Unit]
Description=SparkLink sing-box standby/ingress
Wants=network-online.target sparklink-wireproxy.service
After=network-online.target

[Service]
Type=simple
User=sing-box
Group=sing-box
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
"""


def build_wireproxy_service(config: DeploymentConfig) -> str:
    return f"""[Unit]
Description=SparkLink HyTru WireProxy WARP egress
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStartPre=/usr/local/libexec/sparklink/wireproxy -n -c /etc/wireguard/sparklink-hytru.conf
ExecStart=/usr/local/libexec/sparklink/wireproxy -s -i 127.0.0.1:{config.ports.warp_health} -c /etc/wireguard/sparklink-hytru.conf
Restart=on-failure
RestartSec=5s
TimeoutStartSec=60s
TimeoutStopSec=15s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryMax=256M
TasksMax=64

[Install]
WantedBy=multi-user.target
"""


def build_watchdog_service() -> str:
    return """[Unit]
Description=SparkLink HyTru readiness watchdog
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/sparklink/watch-wireproxy.sh
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
"""


def build_watchdog_timer() -> str:
    return """[Unit]
Description=Periodically verify SparkLink HyTru readiness

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s
Unit=sparklink-wireproxy-watchdog.service

[Install]
WantedBy=timers.target
"""


def build_watchdog_script(config: DeploymentConfig) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
health=http://127.0.0.1:{config.ports.warp_health}/readyz
if curl -fsS --max-time 2 "$health" >/dev/null 2>&1; then exit 0; fi
sleep 5
if curl -fsS --max-time 2 "$health" >/dev/null 2>&1; then exit 0; fi
echo "WireProxy readiness failed twice; scheduling restart" >&2
systemctl --no-block restart sparklink-wireproxy.service
"""


def build_cert_renew_hook(config: DeploymentConfig) -> str:
    reloads = ["systemctl reload nginx"] if config.profile.has("cdn-vless-ws") else []
    if config.profile.active_singbox:
        reloads.append("systemctl restart sing-box")
    if not reloads:
        reloads.append(":")
    return """#!/usr/bin/env bash
set -euo pipefail
install -d -o root -g sparklink-cert -m 750 /etc/sparklink/tls
install -o root -g sparklink-cert -m 640 "$RENEWED_LINEAGE/fullchain.pem" /etc/sparklink/tls/fullchain.pem
install -o root -g sparklink-cert -m 640 "$RENEWED_LINEAGE/privkey.pem" /etc/sparklink/tls/privkey.pem
""" + "\n".join(reloads) + "\n"


def build_client_links(config: DeploymentConfig, secret: DeploymentSecrets) -> list[str]:
    links: list[str] = []
    if config.profile.has("xray-reality-vision"):
        reality_common = {
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": config.reality.server_names[0],
            "fp": "chrome",
            "pbk": secret.reality_public_key,
            "sid": secret.reality_short_id,
            "type": "tcp",
        }
        if config.profile.has("egress-native"):
            links.append(_vless_uri(secret.reality_origin_uuid, config.host.direct_domain, config.ports.reality, reality_common, f"{config.host.name}-Origin-Reality"))
        if config.profile.has("egress-hytru-warp"):
            links.append(_vless_uri(secret.reality_hytru_uuid, config.host.direct_domain, config.ports.reality, reality_common, f"{config.host.name}-HyTru-Reality"))
    if config.profile.has("singbox-anytls"):
        query = urlencode({"sni": config.host.direct_domain})
        if config.profile.has("egress-native"):
            links.append(_anytls_uri(secret.anytls_origin_password, config.host.direct_domain, config.ports.anytls, query, f"{config.host.name}-Origin-AnyTLS"))
        if config.profile.has("egress-hytru-warp"):
            links.append(_anytls_uri(secret.anytls_hytru_password, config.host.direct_domain, config.ports.anytls, query, f"{config.host.name}-HyTru-AnyTLS"))
    if config.profile.has("cdn-vless-ws"):
        cdn_common = {
            "encryption": "none",
            "security": "tls",
            "sni": config.host.cdn_domain,
            "fp": "chrome",
            "type": "ws",
            "host": config.host.cdn_domain,
            "path": secret.cdn_path,
        }
        if config.profile.has("egress-native"):
            links.append(_vless_uri(secret.cdn_origin_uuid, config.host.cdn_domain, 443, cdn_common, f"{config.host.name}-Origin-CDN"))
        if config.profile.has("egress-hytru-warp"):
            links.append(_vless_uri(secret.cdn_hytru_uuid, config.host.cdn_domain, 443, cdn_common, f"{config.host.name}-HyTru-CDN"))
    if config.profile.has("hysteria2"):
        _require_hy2_secrets(secret)
        query = {
            "sni": config.host.direct_domain,
            "obfs": "salamander",
            "obfs-password": secret.hy2_obfs_password,
        }
        if config.profile.has("egress-native"):
            links.append(_hy2_uri(secret.hy2_origin_password, config.host.direct_domain, config.ports.hysteria2, query, f"{config.host.name}-Origin-HY2"))
        if config.profile.has("egress-hytru-warp"):
            links.append(_hy2_uri(secret.hy2_hytru_password, config.host.direct_domain, config.ports.hysteria2, query, f"{config.host.name}-HyTru-HY2"))
    return links


def render_bundle(
    config: DeploymentConfig,
    secret: DeploymentSecrets,
    output: Path,
    include_private: bool = False,
    versions: dict | None = None,
) -> dict[str, str]:
    files: dict[str, tuple[str, int]] = {
        "var/lib/sparklink/public/deployment.json": (_json(config.public_summary()), 0o644),
        "var/lib/sparklink/public/node-descriptor.json": (_json(build_node_descriptor(config, versions=versions)), 0o644),
    }
    if config.profile.requires_xray:
        files["etc/xray/config.json"] = (_json(build_xray(config, secret)), 0o640)
        files["etc/systemd/system/xray.service"] = (build_xray_service(), 0o644)
    if config.profile.active_singbox or "sing-box" in config.profile.standby_cores:
        files["etc/sing-box/config.json"] = (_json(build_sing_box(config, secret)), 0o640)
        files["etc/systemd/system/sing-box.service"] = (build_sing_box_service(), 0o644)
    if config.profile.has("cdn-vless-ws"):
        files["etc/nginx/sites-available/sparklink"] = (build_nginx(config, secret), 0o644)
    if config.profile.requires_warp:
        files["etc/systemd/system/sparklink-wireproxy.service"] = (build_wireproxy_service(config), 0o644)
        files["etc/systemd/system/sparklink-wireproxy-watchdog.service"] = (build_watchdog_service(), 0o644)
        files["etc/systemd/system/sparklink-wireproxy-watchdog.timer"] = (build_watchdog_timer(), 0o644)
        files["usr/local/libexec/sparklink/watch-wireproxy.sh"] = (build_watchdog_script(config), 0o750)
    if config.profile.requires_certificate:
        files["etc/letsencrypt/renewal-hooks/deploy/sparklink-reload"] = (build_cert_renew_hook(config), 0o750)
    if include_private:
        links = build_client_links(config, secret)
        link_text = "\n".join(links) + ("\n" if links else "")
        files["var/lib/sparklink/private/delivery/client-links.txt"] = (link_text, 0o600)
        files["var/lib/sparklink/private/delivery/subscription.txt"] = (
            base64.b64encode(link_text.encode("utf-8")).decode("ascii") + "\n",
            0o600,
        )
    digests: dict[str, str] = {}
    for relative, (content, mode) in files.items():
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="\n")
        if os.name != "nt":
            os.chmod(destination, mode)
        digests[relative] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    manifest = "\n".join(f"{digest}  {name}" for name, digest in sorted(digests.items())) + "\n"
    manifest_path = output / "MANIFEST.sha256"
    manifest_path.write_text(manifest, encoding="utf-8", newline="\n")
    if os.name != "nt":
        os.chmod(manifest_path, 0o600 if include_private else 0o644)
    return digests


def _vless_uri(identity: str, host: str, port: int, query: dict[str, str], label: str) -> str:
    encoded = urlencode(query, quote_via=quote, safe="")
    return f"vless://{identity}@{host}:{port}?{encoded}#{quote(label, safe='')}"


def _anytls_uri(password: str, host: str, port: int, query: str, label: str) -> str:
    return f"anytls://{quote(password, safe='')}@{host}:{port}?{query}#{quote(label, safe='')}"


def _hy2_uri(password: str, host: str, port: int, query: dict[str, str], label: str) -> str:
    encoded = urlencode(query, quote_via=quote, safe="")
    return f"hysteria2://{quote(password, safe='')}@{host}:{port}/?{encoded}#{quote(label, safe='')}"


def _require_hy2_secrets(secret: DeploymentSecrets) -> None:
    values = (secret.hy2_origin_password, secret.hy2_hytru_password, secret.hy2_obfs_password)
    if not all(values) or min(len(value) for value in values) < 32:
        raise ValueError("Hysteria2 requires generated origin, HyTru, and obfuscation secrets")


def _json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=False) + "\n"
