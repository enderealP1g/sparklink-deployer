from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .model import DeploymentConfig


def build_node_descriptor(config: DeploymentConfig, *, versions: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a public, credential-free description of the selected deployment."""
    capabilities = list(config.profile.capabilities)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": {
            "name": config.host.name,
            "direct_domain": config.host.direct_domain,
            "cdn_domain": config.host.cdn_domain if config.profile.has("cdn-vless-ws") else None,
        },
        "deployment": {
            "mode": config.profile.mode,
            "capabilities": capabilities,
            "primary_core": config.profile.primary_core,
            "standby_cores": list(config.profile.standby_cores),
            "singbox_state": "active" if config.profile.active_singbox else (
                "standby" if "sing-box" in config.profile.standby_cores else "disabled"
            ),
        },
        "egress": {
            "native": config.profile.has("egress-native"),
            "hytru_warp": config.profile.has("egress-hytru-warp"),
            "identity_semantics": "HyTru is a dynamic shared WARP egress; it is not a fixed exit IP",
        },
        "health": {
            "state": "planned",
            "runtime_verified": False,
            "reboot_verified": False,
        },
        "versions": versions or {},
        "metering": {
            "ready": False,
            "scope": "transport identity is available; usage accounting is not implemented",
        },
    }
