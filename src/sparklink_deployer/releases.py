from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Release:
    name: str
    version: str
    archive: str
    sha256: str
    release_base: str

    @property
    def archive_url(self) -> str:
        return f"{self.release_base}/{self.archive}"

def load_releases(path: Path) -> dict[str, Release]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1:
        raise ValueError("release lock schema must be 1")
    result: dict[str, Release] = {}
    for name in ("xray", "sing_box", "wireproxy"):
        value = raw[name]
        release = Release(name=name, **value)
        if len(release.sha256) != 64 or any(character not in "0123456789abcdef" for character in release.sha256.lower()):
            raise ValueError(f"invalid SHA-256 for {name}")
        result[name] = release
    return result


def download_release(release: Release, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    archive_path = output / release.archive
    _download(release.archive_url, archive_path)
    actual = sha256_file(archive_path)
    if actual.lower() != release.sha256.lower():
        raise RuntimeError(f"checksum mismatch for {release.name} {release.version}")
    return archive_path


def extract_binary(archive: Path, binary_name: str, output: Path) -> Path:
    extract_dir = output / (archive.name + ".extract")
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True)
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as handle:
            _safe_zip_extract(handle, extract_dir)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive, "r:*") as handle:
            _safe_tar_extract(handle, extract_dir)
    else:
        raise ValueError(f"unsupported archive: {archive}")
    matches = [path for path in extract_dir.rglob(binary_name) if path.is_file()]
    if len(matches) != 1:
        raise RuntimeError(f"expected one {binary_name} binary, found {len(matches)}")
    destination = output / binary_name
    shutil.copy2(matches[0], destination)
    if os.name != "nt":
        os.chmod(destination, 0o755)
    return destination


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "SparkLink-Deployer/0.1"})
    temporary = destination.with_suffix(destination.suffix + ".part")
    with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as output:
        shutil.copyfileobj(response, output)
    os.replace(temporary, destination)


def _safe_zip_extract(handle: zipfile.ZipFile, destination: Path) -> None:
    root = destination.resolve()
    for info in handle.infolist():
        target = (destination / info.filename).resolve()
        if root not in target.parents and target != root:
            raise ValueError("zip archive contains path traversal")
    handle.extractall(destination)


def _safe_tar_extract(handle: tarfile.TarFile, destination: Path) -> None:
    root = destination.resolve()
    members = handle.getmembers()
    for member in members:
        target = (destination / member.name).resolve()
        if root not in target.parents and target != root:
            raise ValueError("tar archive contains path traversal")
        if member.issym() or member.islnk():
            raise ValueError("release archive contains a link")
    handle.extractall(destination, members=members, filter="data")
