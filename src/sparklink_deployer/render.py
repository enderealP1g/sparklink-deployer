from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote, urlencode

from .model import DeploymentConfig
from .secrets_store import DeploymentSecrets


ORIGIN_REALITY_USER = "origin-reality"
HYTRU_REALITY_USER = "hytru-reality"
ORIGIN_CDN_USER = "origin-cdn"
HYTRU_CDN_USER = "hytru-cdn"


def build_xray(config: DeploymentConfig, secret: DeploymentSecrets) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "reality-in",
                "listen": "::",
                "port": config.ports.reality,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": secret.reality_origin_uuid,
                            "email": ORIGIN_REALITY_USER,
                            "flow": "xtls-rprx-vision",
                        },
                        {
                            "id": secret.reality_hytru_uuid,
                            "email": HYTRU_REALITY_USER,
                            "flow": "xtls-rprx-vision",
                        },
                    ],
                    "decryption": "none",
                },
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
            },
            {
                "tag": "cdn-ws-in",
                "listen": "127.0.0.1",
                "port": config.ports.cdn_loopback,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {"id": secret.cdn_origin_uuid, "email": ORIGIN_CDN_USER},
                        {"id": secret.cdn_hytru_uuid, "email": HYTRU_CDN_USER},
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": secret.cdn_path},
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {
                "tag": "warp",
                "protocol": "socks",
                "settings": {
                    "servers": [
                        {
                            "address": "127.0.0.1",
                            "port": config.ports.warp_socks,
                        }
                    ]
                },
            },
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "user": [HYTRU_REALITY_USER, HYTRU_CDN_USER],
                    "network": "tcp,udp",
                    "outboundTag": "warp",
                },
                {
                    "type": "field",
                    "user": [ORIGIN_REALITY_USER, ORIGIN_CDN_USER],
                    "network": "tcp,udp",
                    "outboundTag": "direct",
                },
            ],
        },
    }


def build_sing_box(config: DeploymentConfig, secret: DeploymentSecrets) -> dict:
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "anytls",
                "tag": "anytls-in",
                "listen": "::",
                "listen_port": config.ports.anytls,
                "users": [
                    {"name": "origin-anytls", "password": secret.anytls_origin_password},
                    {"name": "hytru-anytls", "password": secret.anytls_hytru_password},
                ],
                "tls": {
                    "enabled": True,
                    "certificate_path": "/etc/sparklink/tls/fullchain.pem",
                    "key_path": "/etc/sparklink/tls/privkey.pem",
                },
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {
                "type": "socks",
                "tag": "warp",
                "server": "127.0.0.1",
                "server_port": config.ports.warp_socks,
                "version": "5",
            },
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {
                    "auth_user": ["hytru-anytls"],
                    "action": "route",
                    "outbound": "warp",
                }
            ],
            "final": "direct",
        },
    }


def build_nginx(config: DeploymentConfig, secret: DeploymentSecrets) -> str:
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
Description=SparkLink sing-box AnyTLS ingress
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


def build_cert_renew_hook() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail
install -d -o root -g sparklink-cert -m 750 /etc/sparklink/tls
install -o root -g sparklink-cert -m 640 "$RENEWED_LINEAGE/fullchain.pem" /etc/sparklink/tls/fullchain.pem
install -o root -g sparklink-cert -m 640 "$RENEWED_LINEAGE/privkey.pem" /etc/sparklink/tls/privkey.pem
systemctl reload nginx
systemctl restart sing-box
"""


def build_client_links(config: DeploymentConfig, secret: DeploymentSecrets) -> list[str]:
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
    cdn_common = {
        "encryption": "none",
        "security": "tls",
        "sni": config.host.cdn_domain,
        "fp": "chrome",
        "type": "ws",
        "host": config.host.cdn_domain,
        "path": secret.cdn_path,
    }
    anytls_query = urlencode({"sni": config.host.direct_domain})
    return [
        _vless_uri(secret.reality_origin_uuid, config.host.direct_domain, config.ports.reality, reality_common, f"{config.host.name}-Origin-Reality"),
        _anytls_uri(secret.anytls_origin_password, config.host.direct_domain, config.ports.anytls, anytls_query, f"{config.host.name}-Origin-AnyTLS"),
        _vless_uri(secret.cdn_origin_uuid, config.host.cdn_domain, 443, cdn_common, f"{config.host.name}-Origin-CDN"),
        _vless_uri(secret.reality_hytru_uuid, config.host.direct_domain, config.ports.reality, reality_common, f"{config.host.name}-HyTru-Reality"),
        _anytls_uri(secret.anytls_hytru_password, config.host.direct_domain, config.ports.anytls, anytls_query, f"{config.host.name}-HyTru-AnyTLS"),
        _vless_uri(secret.cdn_hytru_uuid, config.host.cdn_domain, 443, cdn_common, f"{config.host.name}-HyTru-CDN"),
    ]


def render_bundle(
    config: DeploymentConfig,
    secret: DeploymentSecrets,
    output: Path,
    include_private: bool = False,
) -> dict[str, str]:
    files: dict[str, tuple[str, int]] = {
        "etc/xray/config.json": (_json(build_xray(config, secret)), 0o640),
        "etc/sing-box/config.json": (_json(build_sing_box(config, secret)), 0o640),
        "etc/nginx/sites-available/sparklink": (build_nginx(config, secret), 0o644),
        "etc/systemd/system/xray.service": (build_xray_service(), 0o644),
        "etc/systemd/system/sing-box.service": (build_sing_box_service(), 0o644),
        "etc/systemd/system/sparklink-wireproxy.service": (build_wireproxy_service(config), 0o644),
        "etc/systemd/system/sparklink-wireproxy-watchdog.service": (build_watchdog_service(), 0o644),
        "etc/systemd/system/sparklink-wireproxy-watchdog.timer": (build_watchdog_timer(), 0o644),
        "usr/local/libexec/sparklink/watch-wireproxy.sh": (build_watchdog_script(config), 0o750),
        "etc/letsencrypt/renewal-hooks/deploy/sparklink-reload": (build_cert_renew_hook(), 0o750),
        "var/lib/sparklink/public/deployment.json": (_json(config.public_summary()), 0o644),
    }
    if include_private:
        links = build_client_links(config, secret)
        link_text = "\n".join(links) + "\n"
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


def _json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=False) + "\n"
