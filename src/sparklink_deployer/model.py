from __future__ import annotations

import dataclasses
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from .capabilities import CAPABILITY_IDS, DEFAULT_RECOMMENDED_CAPABILITIES

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


DEFAULT_LEGACY_CAPABILITIES = (
    "cdn-vless-ws",
    "egress-hytru-warp",
    "egress-native",
    "singbox-anytls",
    "xray-reality-vision",
)


class ConfigError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Host:
    name: str
    direct_domain: str
    cdn_domain: str
    acme_email: str
    ssh_port: int


@dataclasses.dataclass(frozen=True)
class Ports:
    reality: int = 443
    anytls: int = 9443
    cdn_origin: int = 2053
    cdn_loopback: int = 10080
    warp_socks: int = 40000
    warp_health: int = 40002
    hysteria2: int = 8443


@dataclasses.dataclass(frozen=True)
class Reality:
    target: str
    server_names: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Firewall:
    mode: str = "ufw"
    allow_http_for_acme: bool = True


@dataclasses.dataclass(frozen=True)
class Cloudflare:
    managed_externally: bool = True
    expected_origin_tls: str = "strict"
    expected_cache: str = "bypass"


@dataclasses.dataclass(frozen=True)
class DeploymentProfile:
    mode: str = "recommended"
    capabilities: tuple[str, ...] = DEFAULT_RECOMMENDED_CAPABILITIES
    primary_core: str = "xray"
    standby_cores: tuple[str, ...] = ("sing-box",)

    def has(self, capability: str) -> bool:
        return capability in self.capabilities

    @property
    def active_singbox(self) -> bool:
        return self.has("singbox-anytls") or self.has("hysteria2")

    @property
    def requires_xray(self) -> bool:
        return self.has("xray-reality-vision") or self.has("cdn-vless-ws")

    @property
    def requires_certificate(self) -> bool:
        return self.has("cdn-vless-ws") or self.active_singbox

    @property
    def requires_warp(self) -> bool:
        return self.has("egress-hytru-warp")


@dataclasses.dataclass(frozen=True)
class DeploymentConfig:
    schema_version: int
    host: Host
    ports: Ports
    reality: Reality
    firewall: Firewall
    cloudflare: Cloudflare
    profile: DeploymentProfile = dataclasses.field(default_factory=DeploymentProfile)

    @classmethod
    def load(cls, path: Path) -> "DeploymentConfig":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"configuration not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON at line {exc.lineno}: {exc.msg}") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DeploymentConfig":
        schema_version = raw.get("schema_version")
        if schema_version not in (1, 2):
            raise ConfigError("schema_version must be 1 or 2")
        root_keys = {"schema_version", "host", "ports", "reality", "firewall", "cloudflare"}
        if schema_version == 2:
            root_keys.add("profile")
        _only_keys(raw, root_keys, "root")
        host_raw = _object(raw, "host")
        ports_raw = _object(raw, "ports")
        reality_raw = _object(raw, "reality")
        firewall_raw = _object(raw, "firewall")
        cloudflare_raw = _object(raw, "cloudflare")
        profile_raw = raw.get("profile") if schema_version == 2 else None

        _only_keys(host_raw, {"name", "direct_domain", "cdn_domain", "acme_email", "ssh_port"}, "host")
        _only_keys(ports_raw, {field.name for field in dataclasses.fields(Ports)}, "ports")
        _only_keys(reality_raw, {"target", "server_names"}, "reality")
        _only_keys(firewall_raw, {"mode", "allow_http_for_acme"}, "firewall")
        _only_keys(
            cloudflare_raw,
            {"managed_externally", "expected_origin_tls", "expected_cache"},
            "cloudflare",
        )
        if schema_version == 2:
            profile_raw = _object(raw, "profile")
            _only_keys(profile_raw, {field.name for field in dataclasses.fields(DeploymentProfile)}, "profile")
            for key in ("capabilities", "standby_cores"):
                if not isinstance(profile_raw.get(key), list):
                    raise ConfigError(f"profile.{key} must be an array")

        try:
            if schema_version == 1:
                profile = DeploymentProfile(mode="custom", capabilities=DEFAULT_LEGACY_CAPABILITIES)
            else:
                profile = DeploymentProfile(
                    mode=str(profile_raw.get("mode", "recommended")).lower(),
                    capabilities=tuple(str(value).lower() for value in profile_raw.get("capabilities", [])),
                    primary_core=str(profile_raw.get("primary_core", "xray")).lower(),
                    standby_cores=tuple(str(value).lower() for value in profile_raw.get("standby_cores", [])),
                )
            cfg = cls(
                schema_version=2,
                host=Host(
                    name=str(host_raw["name"]).lower(),
                    direct_domain=str(host_raw["direct_domain"]).lower().rstrip("."),
                    cdn_domain=str(host_raw["cdn_domain"]).lower().rstrip("."),
                    acme_email=str(host_raw["acme_email"]),
                    ssh_port=int(host_raw["ssh_port"]),
                ),
                ports=Ports(**{key: int(value) for key, value in ports_raw.items()}),
                reality=Reality(
                    target=str(reality_raw["target"]),
                    server_names=tuple(str(value).lower() for value in reality_raw["server_names"]),
                ),
                firewall=Firewall(**firewall_raw),
                cloudflare=Cloudflare(**cloudflare_raw),
                profile=profile,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"invalid configuration shape: {exc}") from exc
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not NAME_RE.fullmatch(self.host.name):
            raise ConfigError("host.name must use lowercase letters, digits, and hyphens")
        if not DOMAIN_RE.fullmatch(self.host.direct_domain):
            raise ConfigError("host.direct_domain is not a valid DNS name")
        try:
            ipaddress.ip_address(self.host.direct_domain)
        except ValueError:
            pass
        else:
            raise ConfigError("host.direct_domain must be a DNS name, not an IP address")
        if self.profile.has("cdn-vless-ws"):
            if not DOMAIN_RE.fullmatch(self.host.cdn_domain):
                raise ConfigError("host.cdn_domain is not a valid DNS name")
            try:
                ipaddress.ip_address(self.host.cdn_domain)
            except ValueError:
                pass
            else:
                raise ConfigError("host.cdn_domain must be a DNS name, not an IP address")
        elif self.host.cdn_domain:
            if not DOMAIN_RE.fullmatch(self.host.cdn_domain):
                raise ConfigError("host.cdn_domain is not a valid DNS name")
        if self.host.cdn_domain and self.host.direct_domain == self.host.cdn_domain:
            raise ConfigError("direct and CDN domains must differ")
        if self.profile.requires_certificate and not EMAIL_RE.fullmatch(self.host.acme_email):
            raise ConfigError("host.acme_email is invalid")

        if self.profile.mode not in {"recommended", "custom"}:
            raise ConfigError("profile.mode must be recommended or custom")
        if not self.profile.capabilities:
            raise ConfigError("profile.capabilities must not be empty")
        if len(set(self.profile.capabilities)) != len(self.profile.capabilities):
            raise ConfigError("profile.capabilities must be unique")
        unknown = set(self.profile.capabilities).difference(CAPABILITY_IDS)
        if unknown:
            raise ConfigError(f"unknown capabilities: {sorted(unknown)}")
        if self.profile.primary_core != "xray":
            raise ConfigError("profile.primary_core must be xray")
        if any(core != "sing-box" for core in self.profile.standby_cores):
            raise ConfigError("profile.standby_cores supports sing-box only")
        if len(set(self.profile.standby_cores)) != len(self.profile.standby_cores):
            raise ConfigError("profile.standby_cores must be unique")
        if self.profile.mode == "recommended":
            expected = set(DEFAULT_RECOMMENDED_CAPABILITIES)
            actual = set(self.profile.capabilities)
            if actual != expected:
                raise ConfigError("recommended profile must be exactly Xray Reality + Native + HyTru/WARP")
            if self.profile.standby_cores != ("sing-box",):
                raise ConfigError("recommended profile must keep sing-box as standby")
        if self.profile.has("egress-hytru-warp") and not self.profile.requires_xray and not self.profile.active_singbox:
            raise ConfigError("HyTru/WARP requires an enabled ingress")
        if not self.profile.requires_xray and not self.profile.active_singbox:
            raise ConfigError("profile must enable at least one ingress capability")
        if (self.profile.requires_xray or self.profile.active_singbox) and not (
            self.profile.has("egress-native") or self.profile.has("egress-hytru-warp")
        ):
            raise ConfigError("an ingress requires at least one egress identity")
        if self.profile.has("hysteria2") and self.profile.mode != "custom":
            raise ConfigError("hysteria2 is Custom-only")
        if self.profile.has("hysteria2"):
            raise ConfigError("hysteria2 capability is reserved for the PR3 renderer")
        if self.profile.has("veilshift-edge"):
            raise ConfigError("veilshift-edge capability is reserved for the PR5 controller")

        port_values = dataclasses.asdict(self.ports)
        for name, value in port_values.items():
            if not 1 <= value <= 65535:
                raise ConfigError(f"ports.{name} is outside 1..65535")
        public_ports = {"ssh": self.host.ssh_port}
        if self.profile.has("xray-reality-vision"):
            public_ports["reality"] = self.ports.reality
        if self.profile.active_singbox and self.profile.has("singbox-anytls"):
            public_ports["anytls"] = self.ports.anytls
        if self.profile.has("cdn-vless-ws"):
            public_ports["cdn_origin"] = self.ports.cdn_origin
        if self.profile.has("hysteria2"):
            public_ports["hysteria2"] = self.ports.hysteria2
        if len(set(public_ports.values())) != len(public_ports):
            raise ConfigError("SSH and public service ports must be distinct")
        internal_ports = set()
        if self.profile.has("cdn-vless-ws"):
            internal_ports.add(self.ports.cdn_loopback)
        if self.profile.requires_warp:
            internal_ports.update({self.ports.warp_socks, self.ports.warp_health})
        expected_internal = (2 if self.profile.requires_warp else 0) + (1 if self.profile.has("cdn-vless-ws") else 0)
        if internal_ports.intersection(public_ports.values()) or len(internal_ports) != expected_internal:
            raise ConfigError("loopback service ports must be unique and not public ports")

        if self.profile.has("xray-reality-vision"):
            target_host, target_port = split_host_port(self.reality.target)
            if target_port != 443:
                raise ConfigError("reality.target must use TCP/443")
            if not DOMAIN_RE.fullmatch(target_host):
                raise ConfigError("reality.target host must be a DNS name")
            if not self.reality.server_names:
                raise ConfigError("reality.server_names must not be empty")
            if any(not DOMAIN_RE.fullmatch(value) for value in self.reality.server_names):
                raise ConfigError("reality.server_names contains an invalid DNS name")
            if target_host not in self.reality.server_names:
                raise ConfigError("reality.target host must be included in reality.server_names")

        if self.firewall.mode != "ufw":
            raise ConfigError("alpha supports firewall.mode=ufw only")
        if self.profile.has("cdn-vless-ws") and not self.cloudflare.managed_externally:
            raise ConfigError("Cloudflare must be managed externally in alpha")
        if self.profile.has("cdn-vless-ws") and self.cloudflare.expected_origin_tls != "strict":
            raise ConfigError("Cloudflare origin TLS must be strict")
        if self.profile.has("cdn-vless-ws") and self.cloudflare.expected_cache != "bypass":
            raise ConfigError("Cloudflare cache must be bypassed for the CDN hostname")

    def public_summary(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "profile": {
                "mode": self.profile.mode,
                "capabilities": list(self.profile.capabilities),
                "primary_core": self.profile.primary_core,
                "standby_cores": list(self.profile.standby_cores),
            },
            "host": dataclasses.asdict(self.host),
            "ports": dataclasses.asdict(self.ports),
            "reality": {
                "target": self.reality.target,
                "server_names": list(self.reality.server_names),
            },
            "firewall": dataclasses.asdict(self.firewall),
            "cloudflare": dataclasses.asdict(self.cloudflare),
        }


def split_host_port(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, raw_port = value.rsplit("]:", 1)
        return host[1:], int(raw_port)
    host, raw_port = value.rsplit(":", 1)
    return host, int(raw_port)


def _object(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be an object")
    return value


def _only_keys(raw: dict[str, Any], allowed: set[str], label: str) -> None:
    extra = set(raw).difference(allowed)
    if extra:
        raise ConfigError(f"unexpected {label} keys: {sorted(extra)}")
