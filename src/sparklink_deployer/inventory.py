from __future__ import annotations

import dataclasses
import datetime as dt
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .capabilities import DEFAULT_RECOMMENDED_CAPABILITIES


INVENTORY_SCHEMA_VERSION = 1
SENSITIVE_KEY_RE = re.compile(
    r"(?:pass(word)?|secret|token|private|credential|subscription|uuid|api.?key|cookie)",
    re.IGNORECASE,
)
KNOWN_FAMILIES = {
    "sparklink-managed",
    "known-xui-xray",
    "known-xui-xray-singbox",
    "known-systemd-xray-singbox",
    "known-systemd-xray",
}


@dataclasses.dataclass(frozen=True)
class ServiceObservation:
    name: str
    installed: bool
    version: str | None = None
    manager: str | None = None
    active: bool = False
    enabled: bool = False
    config_paths: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class ListenerObservation:
    protocol: str
    address: str
    port: int
    process: str | None = None


@dataclasses.dataclass(frozen=True)
class HostObservation:
    name: str
    provider: str | None
    endpoint: str | None
    os_id: str
    os_version: str
    architecture: str
    kernel: str | None
    services: tuple[ServiceObservation, ...]
    listeners: tuple[ListenerObservation, ...]
    markers: tuple[str, ...]
    config_fingerprints: dict[str, str]
    observed_capabilities: tuple[str, ...]
    collected_at: str
    source: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, name_override: str | None = None) -> "HostObservation":
        if not isinstance(raw, dict):
            raise ValueError("inventory must be a JSON object")
        if raw.get("schema_version", INVENTORY_SCHEMA_VERSION) != INVENTORY_SCHEMA_VERSION:
            raise ValueError("unsupported inventory schema_version")
        host = _object(raw, "host")
        system = _object(raw, "system")
        services_raw = raw.get("services", {})
        if not isinstance(services_raw, dict):
            raise ValueError("inventory.services must be an object")
        services = tuple(_service(name, value) for name, value in sorted(services_raw.items()))
        listeners_raw = raw.get("listeners", [])
        if not isinstance(listeners_raw, list):
            raise ValueError("inventory.listeners must be an array")
        listeners = tuple(_listener(value) for value in listeners_raw)
        markers_raw = raw.get("markers", [])
        if not isinstance(markers_raw, list) or any(not isinstance(value, str) for value in markers_raw):
            raise ValueError("inventory.markers must be an array of strings")
        fingerprints_raw = raw.get("config_fingerprints", {})
        if not isinstance(fingerprints_raw, dict):
            raise ValueError("inventory.config_fingerprints must be an object")
        observed_raw = raw.get("observed_capabilities", [])
        if not isinstance(observed_raw, list) or any(not isinstance(value, str) for value in observed_raw):
            raise ValueError("inventory.observed_capabilities must be an array of strings")
        name = name_override or str(host.get("name", "")).strip().lower()
        if not name or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", name):
            raise ValueError("inventory.host.name must be a safe host label")
        return cls(
            name=name,
            provider=_optional_text(host.get("provider")),
            endpoint=_optional_text(host.get("endpoint")),
            os_id=str(system.get("os_id", "unknown")),
            os_version=str(system.get("os_version", "unknown")),
            architecture=str(system.get("architecture", "unknown")),
            kernel=_optional_text(system.get("kernel")),
            services=services,
            listeners=listeners,
            markers=tuple(sorted(set(markers_raw))),
            config_fingerprints={str(key): str(value) for key, value in fingerprints_raw.items()},
            observed_capabilities=tuple(sorted(set(value.lower() for value in observed_raw))),
            collected_at=str(raw.get("collected_at") or dt.datetime.now(dt.timezone.utc).isoformat()),
            source=str(raw.get("source", "unknown")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "host": {
                "name": self.name,
                "provider": self.provider,
                "endpoint": self.endpoint,
            },
            "system": {
                "os_id": self.os_id,
                "os_version": self.os_version,
                "architecture": self.architecture,
                "kernel": self.kernel,
            },
            "services": {
                service.name: {
                    "installed": service.installed,
                    "version": service.version,
                    "manager": service.manager,
                    "active": service.active,
                    "enabled": service.enabled,
                    "config_paths": list(service.config_paths),
                }
                for service in self.services
            },
            "listeners": [dataclasses.asdict(listener) for listener in self.listeners],
            "markers": list(self.markers),
            "config_fingerprints": dict(sorted(self.config_fingerprints.items())),
            "observed_capabilities": list(self.capabilities()),
            "collected_at": self.collected_at,
            "source": self.source,
        }

    def service(self, name: str) -> ServiceObservation | None:
        return next((service for service in self.services if service.name == name), None)

    def has_service(self, name: str) -> bool:
        service = self.service(name)
        return bool(service and service.installed)

    def capabilities(self) -> tuple[str, ...]:
        """Infer only capability IDs supported by explicit markers or strong layout signals."""
        capabilities = set(self.observed_capabilities)
        if self.has_service("xray") or "xray_config" in self.markers:
            capabilities.add("egress-native")
        if "xray_reality_listener" in self.markers:
            capabilities.add("xray-reality-vision")
        if self.has_service("wireproxy") or "wireproxy_config" in self.markers or "warp" in self.markers:
            capabilities.add("egress-hytru-warp")
        if self.has_service("sing-box") or "sing_box_config" in self.markers:
            if "anytls_listener" in self.markers:
                capabilities.add("singbox-anytls")
            if "hysteria2_listener" in self.markers:
                capabilities.add("hysteria2")
        if "cdn_listener" in self.markers or "nginx_cdn" in self.markers:
            capabilities.add("cdn-vless-ws")
        return tuple(sorted(capabilities))

    def family(self) -> str:
        if "sparklink_descriptor" in self.markers:
            return "sparklink-managed"
        has_xui = "xui" in self.markers
        has_xray = self.has_service("xray") or "xray_config" in self.markers
        has_singbox = self.has_service("sing-box") or "sing_box_config" in self.markers
        if has_xui and has_xray and has_singbox:
            return "known-xui-xray-singbox"
        if has_xui and has_xray:
            return "known-xui-xray"
        if has_xray and has_singbox:
            return "known-systemd-xray-singbox"
        if has_xray:
            return "known-systemd-xray"
        return "unknown"


@dataclasses.dataclass(frozen=True)
class AdoptionPlan:
    host: str
    family: str
    status: str
    desired_capabilities: tuple[str, ...]
    detected_capabilities: tuple[str, ...]
    compatible_capabilities: tuple[str, ...]
    gaps: tuple[str, ...]
    unmanaged_capabilities: tuple[str, ...]
    risks: tuple[str, ...]
    backup_points: tuple[str, ...]
    actions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": "read-only-adopt-plan",
            "requires_explicit_approval": True,
            "host": self.host,
            "layout": {"family": self.family, "status": self.status},
            "capabilities": {
                "desired": list(self.desired_capabilities),
                "detected": list(self.detected_capabilities),
                "compatible": list(self.compatible_capabilities),
                "gaps": list(self.gaps),
                "unmanaged": list(self.unmanaged_capabilities),
            },
            "risks": list(self.risks),
            "backup_points": list(self.backup_points),
            "actions": list(self.actions),
        }


def build_adoption_plan(
    observation: HostObservation,
    desired_capabilities: Iterable[str] = DEFAULT_RECOMMENDED_CAPABILITIES,
) -> AdoptionPlan:
    desired = tuple(sorted(set(value.lower() for value in desired_capabilities)))
    detected = observation.capabilities()
    compatible = tuple(sorted(set(desired).intersection(detected)))
    gaps = tuple(sorted(set(desired).difference(detected)))
    unmanaged = tuple(sorted(set(detected).difference(desired)))
    risks: list[str] = []
    if observation.family() == "sparklink-managed":
        risks.append("host already exposes a SparkLink descriptor; verify state instead of migrating blindly")
    if observation.family() == "unknown":
        risks.append("host layout is not a known SparkLink family; adoption is blocked")
    if "xui" in observation.markers:
        risks.append("x-ui/3x-ui owns part of the live state; database and generated config can diverge")
    if observation.has_service("nginx") or "nginx_config" in observation.markers:
        risks.append("Nginx is already present; CDN and certificate ownership must be reviewed per host")
    if "xray_api" in observation.markers:
        risks.append("Xray API/stats are present; counters require per-host adapter validation")
    inactive = [service.name for service in observation.services if service.installed and not service.active]
    if inactive:
        risks.append("installed service(s) were inactive during collection: " + ", ".join(inactive))
    if "hysteria2" in detected:
        risks.append("HY2 was detected from host evidence; client and UDP behavior still require live acceptance")
    if not risks:
        risks.append("read-only observation only; no migration adapter has been approved")
    backup_points = [
        "capture a host-specific config and service manifest before any apply",
        "record the x-ui database or systemd config backup path in the transaction journal",
    ]
    actions = [
        "review the redacted inventory and capability gaps",
        "select a host-specific migration adapter; generic overwrite is not supported",
        "obtain explicit per-host approval before any adopt-apply implementation is used",
        "repeat service, listener, client, egress, and reboot acceptance after migration",
    ]
    if observation.family() == "sparklink-managed":
        status = "managed"
    elif observation.family() in KNOWN_FAMILIES:
        status = "review-required"
    else:
        status = "unsupported"
    return AdoptionPlan(
        host=observation.name,
        family=observation.family(),
        status=status,
        desired_capabilities=desired,
        detected_capabilities=detected,
        compatible_capabilities=compatible,
        gaps=gaps,
        unmanaged_capabilities=unmanaged,
        risks=tuple(risks),
        backup_points=tuple(backup_points),
        actions=tuple(actions),
    )


def load_inventory(path: Path, *, name_override: str | None = None) -> HostObservation:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"inventory not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid inventory JSON at line {exc.lineno}: {exc.msg}") from exc
    return HostObservation.from_dict(redact_secrets(raw), name_override=name_override)


def write_inventory(observation: HostObservation, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact_secrets(observation.to_dict()), indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def write_manager_inventory(observation: HostObservation, manager_root: Path) -> Path:
    destination = manager_root / ".sparklink" / "hosts" / observation.name / "inventory.json"
    write_inventory(observation, destination)
    return destination


def load_manager_inventories(manager_root: Path) -> tuple[HostObservation, ...]:
    root = manager_root / ".sparklink" / "hosts"
    if not root.is_dir():
        return ()
    observations: list[HostObservation] = []
    for path in sorted(root.glob("*/inventory.json")):
        observations.append(load_inventory(path))
    return tuple(observations)


def collect_remote_inventory(
    target: str,
    *,
    name: str | None = None,
    provider: str | None = None,
    port: int | None = None,
    ssh_binary: str = "ssh",
    timeout: int = 45,
) -> HostObservation:
    if not target or target.startswith("-"):
        raise ValueError("SSH target must be a non-empty alias or host")
    command = [ssh_binary, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    if port is not None:
        if not 1 <= port <= 65535:
            raise ValueError("SSH port is outside 1..65535")
        command.extend(["-p", str(port)])
    command.extend([target, "python3", "-"])
    try:
        completed = subprocess.run(
            command,
            input=REMOTE_COLLECTOR_SCRIPT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"read-only inventory collection timed out for {target}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "ssh failed"
        raise RuntimeError(f"read-only inventory collection failed for {target}: {detail}")
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"remote collector returned invalid JSON: {exc.msg}") from exc
    observation = HostObservation.from_dict(redact_secrets(raw), name_override=name or None)
    return dataclasses.replace(observation, provider=provider or observation.provider)


def redact_secrets(value: Any, *, key: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(key):
        return "[redacted]"
    if isinstance(value, dict):
        return {str(child_key): redact_secrets(child_value, key=str(child_key)) for child_key, child_value in value.items()}
    if isinstance(value, list):
        return [redact_secrets(child, key=key) for child in value]
    if isinstance(value, tuple):
        return [redact_secrets(child, key=key) for child in value]
    return value


def _object(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"inventory.{key} must be an object")
    return value


def _service(name: str, raw: Any) -> ServiceObservation:
    if not isinstance(raw, dict):
        raise ValueError(f"inventory.services.{name} must be an object")
    paths = raw.get("config_paths", [])
    if not isinstance(paths, list) or any(not isinstance(value, str) for value in paths):
        raise ValueError(f"inventory.services.{name}.config_paths must be an array")
    return ServiceObservation(
        name=str(name),
        installed=bool(raw.get("installed", False)),
        version=_optional_text(raw.get("version")),
        manager=_optional_text(raw.get("manager")),
        active=bool(raw.get("active", False)),
        enabled=bool(raw.get("enabled", False)),
        config_paths=tuple(paths),
    )


def _listener(raw: Any) -> ListenerObservation:
    if not isinstance(raw, dict):
        raise ValueError("inventory.listeners entries must be objects")
    try:
        port = int(raw["port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("inventory listener port is invalid") from exc
    if not 1 <= port <= 65535:
        raise ValueError("inventory listener port is outside 1..65535")
    return ListenerObservation(
        protocol=str(raw.get("protocol", "unknown")),
        address=str(raw.get("address", "unknown")),
        port=port,
        process=_optional_text(raw.get("process")),
    )


def _optional_text(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


REMOTE_COLLECTOR_SCRIPT = r'''import hashlib, json, os, platform, re, shutil, socket, subprocess

def run(command):
    for prefix in ([], ["sudo", "-n"]):
        try:
            result = subprocess.run(prefix + command, capture_output=True, text=True, timeout=8)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return result.stdout.strip()
    return ""

def exists(path):
    return os.path.exists(path) or os.path.islink(path)

def find_binary(binary):
    for candidate in (shutil.which(binary), "/usr/local/bin/" + binary, "/usr/local/x-ui/bin/" + binary):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

def version(binary):
    path = find_binary(binary)
    if not path:
        return None
    output = run([path, "--version"])
    return output.splitlines()[0][:160] if output else "installed"

def service(name, binary, paths, units=None):
    units = units or [name + ".service"]
    unit = next((candidate for candidate in units if run(["systemctl", "cat", candidate])), None)
    active = any(run(["systemctl", "is-active", candidate]) == "active" for candidate in units)
    enabled = any(run(["systemctl", "is-enabled", candidate]) in ("enabled", "static", "indirect") for candidate in units)
    return {
        "installed": bool(find_binary(binary)) or any(exists(path) for path in paths),
        "version": version(binary),
        "manager": "systemd" if unit else None,
        "active": active,
        "enabled": enabled,
        "config_paths": [path for path in paths if exists(path)],
    }

os_release = {}
try:
    for line in open("/etc/os-release", encoding="utf-8"):
        if "=" in line:
            key, value = line.rstrip().split("=", 1)
            os_release[key] = value.strip().strip('"')
except OSError:
    pass

listeners = []
ss = run(["ss", "-H", "-lntup"])
for line in ss.splitlines():
    fields = line.split()
    if len(fields) < 5:
        continue
    protocol = fields[0].lower()
    local = fields[4]
    match = re.search(r":(\d+)$", local)
    if not match:
        continue
    process = fields[-1] if fields[-1].startswith("users:") else None
    listeners.append({"protocol": protocol, "address": local.rsplit(":", 1)[0], "port": int(match.group(1)), "process": process})

markers = []
paths = {
    "xui": ["/etc/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db"],
    "xray_config": ["/etc/xray/config.json", "/usr/local/x-ui/bin/config.json"],
    "sing_box_config": ["/etc/sing-box/config.json"],
    "nginx_config": ["/etc/nginx/nginx.conf"],
    "wireproxy_config": ["/etc/wireguard/proxy.conf", "/etc/wireguard/sparklink-hytru.conf"],
    "sparklink_descriptor": ["/var/lib/sparklink/public/node-descriptor.json"],
}
for marker, candidates in paths.items():
    if any(exists(path) for path in candidates):
        markers.append(marker)
if any(listener["port"] in (443, 8443) and listener["protocol"].startswith("tcp") for listener in listeners) and "xray_config" in markers:
    markers.append("xray_reality_listener")
if any(listener["port"] in (9443, 2053) and listener["protocol"].startswith("tcp") for listener in listeners) and "sing_box_config" in markers:
    markers.append("anytls_listener")
if any(listener["port"] in (443, 8443) and listener["protocol"].startswith("udp") for listener in listeners) and "sing_box_config" in markers:
    markers.append("hysteria2_listener")
if "nginx_config" in markers and any(listener["port"] in (2053, 8443) and listener["protocol"].startswith("tcp") for listener in listeners):
    # An Nginx origin port is not enough to identify VLESS-WebSocket; it can also
    # front XHTTP, ShadowTLS, or an unrelated service. Keep this as a neutral marker.
    markers.append("nginx_listener_2053")
if "wireproxy_config" in markers:
    markers.append("warp")
if any(listener["port"] == 62789 for listener in listeners):
    markers.append("xray_api")

descriptor_capabilities = []
descriptor_path = "/var/lib/sparklink/public/node-descriptor.json"
if exists(descriptor_path):
    try:
        with open(descriptor_path, encoding="utf-8") as handle:
            descriptor = json.load(handle)
        deployment = descriptor.get("deployment", {})
        values = deployment.get("capabilities", [])
        if isinstance(values, list):
            descriptor_capabilities = [value for value in values if isinstance(value, str)]
    except (OSError, ValueError):
        pass

fingerprints = {}
for path in ("/etc/xray/config.json", "/usr/local/x-ui/bin/config.json", "/etc/sing-box/config.json", "/etc/nginx/nginx.conf", "/etc/wireguard/proxy.conf", "/var/lib/sparklink/public/node-descriptor.json"):
    if exists(path):
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            fingerprints[path] = digest.hexdigest()
        except OSError:
            fingerprints[path] = "unreadable"

print(json.dumps({
    "schema_version": 1,
    "host": {"name": socket.gethostname(), "provider": None, "endpoint": None},
    "system": {"os_id": os_release.get("ID", "unknown"), "os_version": os_release.get("VERSION_ID", "unknown"), "architecture": platform.machine(), "kernel": platform.release()},
    "services": {
        "xray": service("xray", "xray", ["/etc/xray/config.json", "/usr/local/x-ui/bin/config.json"], ["xray.service", "x-ui.service"]),
        "sing-box": service("sing-box", "sing-box", ["/etc/sing-box/config.json"], ["sing-box.service"]),
        "nginx": service("nginx", "nginx", ["/etc/nginx/nginx.conf"], ["nginx.service"]),
        "wireproxy": service("wireproxy", "wireproxy", ["/etc/wireguard/proxy.conf", "/etc/wireguard/sparklink-hytru.conf"], ["wireproxy.service", "sparklink-wireproxy.service"]),
    },
    "listeners": listeners,
    "markers": sorted(set(markers)),
    "config_fingerprints": fingerprints,
    "observed_capabilities": descriptor_capabilities,
    "collected_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    "source": "ssh-readonly-collector",
}))
'''
