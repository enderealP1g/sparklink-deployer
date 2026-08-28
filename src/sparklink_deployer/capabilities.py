from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapabilitySpec:
    capability_id: str
    label: str
    core: str | None
    recommended: bool = False
    custom_only: bool = False
    render_status: str = "ready"


CAPABILITY_CATALOG = (
    CapabilitySpec("xray-reality-vision", "Xray VLESS REALITY", "xray", recommended=True),
    CapabilitySpec("egress-native", "Origin/Native egress", None, recommended=True),
    CapabilitySpec("egress-hytru-warp", "HyTru/WARP egress", None, recommended=True),
    CapabilitySpec("singbox-anytls", "sing-box AnyTLS", "sing-box"),
    CapabilitySpec("cdn-vless-ws", "VLESS CDN fallback", "xray"),
    CapabilitySpec(
        "hysteria2",
        "Hysteria2 weak-network capability",
        "sing-box",
        custom_only=True,
        render_status="planned-pr3",
    ),
    CapabilitySpec(
        "veilshift-edge",
        "VeilShift Cloudflare Edge entry",
        None,
        custom_only=True,
        render_status="planned-pr5",
    ),
)

CAPABILITY_IDS = frozenset(spec.capability_id for spec in CAPABILITY_CATALOG)
DEFAULT_RECOMMENDED_CAPABILITIES = tuple(
    spec.capability_id for spec in CAPABILITY_CATALOG if spec.recommended
)
