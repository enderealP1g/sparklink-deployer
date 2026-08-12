from __future__ import annotations

import dataclasses
import json
import os
import secrets as random_secrets
import uuid
from pathlib import Path
from typing import Any


SECRET_FIELDS = {
    "reality_origin_uuid",
    "reality_hytru_uuid",
    "cdn_origin_uuid",
    "cdn_hytru_uuid",
    "anytls_origin_password",
    "anytls_hytru_password",
    "reality_private_key",
    "reality_public_key",
    "reality_short_id",
    "cdn_path",
}


@dataclasses.dataclass(frozen=True)
class DeploymentSecrets:
    reality_origin_uuid: str
    reality_hytru_uuid: str
    cdn_origin_uuid: str
    cdn_hytru_uuid: str
    anytls_origin_password: str
    anytls_hytru_password: str
    reality_private_key: str
    reality_public_key: str
    reality_short_id: str
    cdn_path: str

    @classmethod
    def generate(cls, reality_private_key: str, reality_public_key: str) -> "DeploymentSecrets":
        return cls(
            reality_origin_uuid=str(uuid.uuid4()),
            reality_hytru_uuid=str(uuid.uuid4()),
            cdn_origin_uuid=str(uuid.uuid4()),
            cdn_hytru_uuid=str(uuid.uuid4()),
            anytls_origin_password=random_secrets.token_urlsafe(32),
            anytls_hytru_password=random_secrets.token_urlsafe(32),
            reality_private_key=reality_private_key,
            reality_public_key=reality_public_key,
            reality_short_id=random_secrets.token_hex(8),
            cdn_path="/" + random_secrets.token_urlsafe(24),
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DeploymentSecrets":
        if set(raw) != SECRET_FIELDS:
            raise ValueError("secret file has an unexpected shape")
        value = cls(**{key: str(raw[key]) for key in SECRET_FIELDS})
        value.validate()
        return value

    @classmethod
    def load(cls, path: Path, require_private_mode: bool = True) -> "DeploymentSecrets":
        value = cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        if require_private_mode and os.name != "nt" and path.stat().st_mode & 0o077:
            raise PermissionError(f"secret file permissions are broader than 600: {path}")
        return value

    def validate(self) -> None:
        for field in (
            self.reality_origin_uuid,
            self.reality_hytru_uuid,
            self.cdn_origin_uuid,
            self.cdn_hytru_uuid,
        ):
            uuid.UUID(field)
        if len({self.reality_origin_uuid, self.reality_hytru_uuid, self.cdn_origin_uuid, self.cdn_hytru_uuid}) != 4:
            raise ValueError("VLESS identities must be unique")
        if min(len(self.anytls_origin_password), len(self.anytls_hytru_password)) < 32:
            raise ValueError("AnyTLS passwords are too short")
        if not self.cdn_path.startswith("/") or len(self.cdn_path) < 24:
            raise ValueError("CDN path is invalid")
        if len(self.reality_short_id) != 16:
            raise ValueError("REALITY short ID must contain 16 hex characters")
        int(self.reality_short_id, 16)
        if not self.reality_private_key or not self.reality_public_key:
            raise ValueError("REALITY keys are missing")

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(path.parent, 0o700)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(dataclasses.asdict(self), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)

    @classmethod
    def dummy(cls) -> "DeploymentSecrets":
        return cls(
            reality_origin_uuid="11111111-1111-4111-8111-111111111111",
            reality_hytru_uuid="22222222-2222-4222-8222-222222222222",
            cdn_origin_uuid="33333333-3333-4333-8333-333333333333",
            cdn_hytru_uuid="44444444-4444-4444-8444-444444444444",
            anytls_origin_password="origin-dummy-password-not-for-production",
            anytls_hytru_password="hytru-dummy-password-not-for-production-",
            reality_private_key="PRIVATE_KEY_PLACEHOLDER",
            reality_public_key="PUBLIC_KEY_PLACEHOLDER",
            reality_short_id="0123456789abcdef",
            cdn_path="/dummy-path-not-for-production",
        )
