from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import json
import os
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


API = "https://api.cloudflareclient.com/v0a2158/reg"
USER_AGENT = "okhttp/3.12.1"
CLIENT_VERSION = "a-6.10-2158"


@dataclasses.dataclass(frozen=True)
class WarpIdentity:
    private_key: str
    addresses: tuple[str, ...]
    peer_public_key: str
    endpoint: str
    keepalive: int = 25
    mtu: int = 1420

    def validate(self) -> None:
        if not self.private_key or not self.peer_public_key:
            raise ValueError("WARP key material is missing")
        if not self.addresses:
            raise ValueError("WARP addresses are missing")
        if ":" not in self.endpoint:
            raise ValueError("WARP endpoint is invalid")


def register_or_load(directory: Path) -> WarpIdentity:
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(directory, 0o700)
    account_path = directory / "warp-account.json"
    identity_path = directory / "warp-identity.json"
    if account_path.is_file() and identity_path.is_file():
        identity = _load_identity(identity_path)
        _require_private(identity_path)
        _require_private(account_path)
        return identity

    private_key, public_key = _make_keypair()
    last_error = "registration failed"
    for attempt in range(1, 4):
        try:
            account = _post_registration(public_key)
            identity = _build_identity(account, private_key)
            _secure_json(account_path, account)
            _secure_json(identity_path, dataclasses.asdict(identity))
            return identity
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, RuntimeError) as exc:
            last_error = f"attempt {attempt}: {type(exc).__name__}"
            if attempt < 3:
                time.sleep(10 if "1015" in str(exc) else 2)
    raise RuntimeError(last_error)


def render_wireproxy(identity: WarpIdentity, socks_port: int) -> str:
    identity.validate()
    return "\n".join(
        [
            "[Interface]",
            f"Address = {', '.join(identity.addresses)}",
            f"PrivateKey = {identity.private_key}",
            "DNS = 1.1.1.1",
            f"MTU = {identity.mtu}",
            "CheckAlive = 1.1.1.1",
            "CheckAliveInterval = 5",
            "",
            "[Peer]",
            f"PublicKey = {identity.peer_public_key}",
            f"Endpoint = {identity.endpoint}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"PersistentKeepalive = {identity.keepalive}",
            "",
            "[Socks5]",
            f"BindAddress = 127.0.0.1:{socks_port}",
            "",
            "[Resolve]",
            "ResolveStrategy = ipv4",
            "",
        ]
    )


def _make_keypair() -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="sparklink-warp-") as raw:
        work = Path(raw)
        private_der = work / "private.der"
        public_der = work / "public.der"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER", "-out", os.fspath(private_der)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-inform",
                "DER",
                "-in",
                os.fspath(private_der),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                os.fspath(public_der),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        private_blob = private_der.read_bytes()
        public_blob = public_der.read_bytes()
    if len(private_blob) != 48 or len(public_blob) != 44:
        raise RuntimeError("unexpected OpenSSL X25519 DER shape")
    return base64.b64encode(private_blob[-32:]).decode(), base64.b64encode(public_blob[-32:]).decode()


def _post_registration(public_key: str) -> dict:
    install_id = secrets.token_urlsafe(18)[:22]
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    suffix = "".join(secrets.choice(alphabet) for _ in range(134))
    payload = {
        "key": public_key,
        "install_id": install_id,
        "fcm_token": f"{install_id}:APA91b{suffix}",
        "tos": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "model": "PC",
        "serial_number": install_id,
        "locale": "zh_CN",
    }
    request = urllib.request.Request(
        API,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "User-Agent": USER_AGENT,
            "CF-Client-Version": CLIENT_VERSION,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
        if response.status not in (200, 201):
            raise RuntimeError(f"registration HTTP {response.status}")
        return json.loads(response.read().decode())


def _build_identity(account: dict, private_key: str) -> WarpIdentity:
    config = account.get("config") or {}
    interface = config.get("interface") or {}
    addresses = interface.get("addresses") or {}
    peers = config.get("peers") or []
    if len(peers) != 1:
        raise RuntimeError("registration response must contain one peer")
    peer = peers[0]
    endpoint_value = peer.get("endpoint") or {}
    endpoint = endpoint_value.get("v4") if isinstance(endpoint_value, dict) else endpoint_value
    if not endpoint or not peer.get("public_key"):
        raise RuntimeError("registration response has no IPv4 peer")
    normalized_addresses = []
    for family, suffix in (("v4", "/32"), ("v6", "/128")):
        value = addresses.get(family)
        if value:
            normalized_addresses.append(value if "/" in value else value + suffix)
    if not account.get("id") or not account.get("token") or not normalized_addresses:
        raise RuntimeError("registration response is incomplete")
    identity = WarpIdentity(
        private_key=private_key,
        addresses=tuple(normalized_addresses),
        peer_public_key=peer["public_key"],
        endpoint=endpoint,
    )
    identity.validate()
    return identity


def _load_identity(path: Path) -> WarpIdentity:
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["addresses"] = tuple(raw["addresses"])
    identity = WarpIdentity(**raw)
    identity.validate()
    return identity


def _secure_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    if os.name != "nt":
        os.chmod(path, 0o600)


def _require_private(path: Path) -> None:
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise PermissionError(f"permissions are broader than 600: {path}")
