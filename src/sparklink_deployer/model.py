from __future__ import annotations

import dataclasses
import ipaddress
import json
import re
from pathlib import Path
from typing import Any


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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
class DeploymentConfig:
    schema_version: int
    host: Host
    ports: Ports
    reality: Reality
    firewall: Firewall
    cloudflare: Cloudflare

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
        _only_keys(raw, {"schema_version", "host", "ports", "reality", "firewall", "cloudflare"}, "root")
        if raw.get("schema_version") != 1:
            raise ConfigError("schema_version must be 1")
        host_raw = _object(raw, "host")
        ports_raw = _object(raw, "ports")
        reality_raw = _object(raw, "reality")
        firewall_raw = _object(raw, "firewall")
        cloudflare_raw = _object(raw, "cloudflare")

        _only_keys(host_raw, {"name", "direct_domain", "cdn_domain", "acme_email", "ssh_port"}, "host")
        _only_keys(ports_raw, {field.name for field in dataclasses.fields(Ports)}, "ports")
        _only_keys(reality_raw, {"target", "server_names"}, "reality")
        _only_keys(firewall_raw, {"mode", "allow_http_for_acme"}, "firewall")
        _only_keys(
            cloudflare_raw,
            {"managed_externally", "expected_origin_tls", "expected_cache"},
            "cloudflare",
        )

        try:
            cfg = cls(
                schema_version=1,
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
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"invalid configuration shape: {exc}") from exc
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not NAME_RE.fullmatch(self.host.name):
            raise ConfigError("host.name must use lowercase letters, digits, and hyphens")
        for label, value in (
            ("host.direct_domain", self.host.direct_domain),
            ("host.cdn_domain", self.host.cdn_domain),
        ):
            if not DOMAIN_RE.fullmatch(value):
                raise ConfigError(f"{label} is not a valid DNS name")
            try:
                ipaddress.ip_address(value)
            except ValueError:
                pass
            else:
                raise ConfigError(f"{label} must be a DNS name, not an IP address")
        if self.host.direct_domain == self.host.cdn_domain:
            raise ConfigError("direct and CDN domains must differ")
        if not EMAIL_RE.fullmatch(self.host.acme_email):
            raise ConfigError("host.acme_email is invalid")

        port_values = dataclasses.asdict(self.ports)
        for name, value in port_values.items():
            if not 1 <= value <= 65535:
                raise ConfigError(f"ports.{name} is outside 1..65535")
        public_ports = {
            "ssh": self.host.ssh_port,
            "reality": self.ports.reality,
            "anytls": self.ports.anytls,
            "cdn_origin": self.ports.cdn_origin,
        }
        if len(set(public_ports.values())) != len(public_ports):
            raise ConfigError("SSH and public service ports must be distinct")
        internal_ports = {self.ports.cdn_loopback, self.ports.warp_socks, self.ports.warp_health}
        if internal_ports.intersection(public_ports.values()) or len(internal_ports) != 3:
            raise ConfigError("loopback service ports must be unique and not public ports")

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
        if not self.cloudflare.managed_externally:
            raise ConfigError("Cloudflare must be managed externally in alpha")
        if self.cloudflare.expected_origin_tls != "strict":
            raise ConfigError("Cloudflare origin TLS must be strict")
        if self.cloudflare.expected_cache != "bypass":
            raise ConfigError("Cloudflare cache must be bypassed for the CDN hostname")

    def public_summary(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
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
