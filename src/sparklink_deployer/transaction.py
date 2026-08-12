from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
import shutil
from pathlib import Path, PurePosixPath


@dataclasses.dataclass
class Record:
    path: str
    existed: bool
    kind: str
    backup: str | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    sha256: str | None = None


class Transaction:
    def __init__(self, backup_base: Path, root: Path = Path("/"), transaction_id: str | None = None):
        self.root = root.resolve()
        self.backup_base = backup_base.resolve()
        self.transaction_id = transaction_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.directory = self.backup_base / self.transaction_id
        self.files_directory = self.directory / "files"
        self.records: list[Record] = []
        self.notes: list[str] = []
        self.complete = False
        self.directory.mkdir(parents=True, exist_ok=False)
        self.files_directory.mkdir(mode=0o700)
        if os.name != "nt":
            os.chmod(self.directory, 0o700)
        self._write_manifest()

    def logical_to_real(self, logical: str | PurePosixPath) -> Path:
        value = PurePosixPath(logical)
        if not value.is_absolute():
            raise ValueError(f"transaction path must be absolute: {logical}")
        if ".." in value.parts:
            raise ValueError("transaction path contains parent traversal")
        relative = Path(*value.parts[1:])
        unresolved = self.root / relative
        parent = unresolved.parent.resolve()
        if self.root != Path("/").resolve() and self.root not in parent.parents and parent != self.root:
            raise ValueError("transaction path escaped its root")
        return parent / unresolved.name

    def capture(self, logical: str) -> None:
        if any(record.path == logical for record in self.records):
            return
        target = self.logical_to_real(logical)
        if target.is_symlink():
            record = Record(path=logical, existed=True, kind="symlink", backup=os.readlink(target))
        elif target.is_file():
            relative = Path(*PurePosixPath(logical).parts[1:])
            backup = self.files_directory / relative
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup)
            stat = target.stat()
            record = Record(
                path=logical,
                existed=True,
                kind="file",
                backup=os.fspath(backup.relative_to(self.directory)),
                mode=stat.st_mode & 0o7777,
                uid=getattr(stat, "st_uid", None),
                gid=getattr(stat, "st_gid", None),
                sha256=_sha256(target),
            )
        elif target.exists():
            raise ValueError(f"refusing to transactionally replace non-file path: {logical}")
        else:
            record = Record(path=logical, existed=False, kind="missing")
        self.records.append(record)
        self._write_manifest()

    def install_file(
        self,
        source: Path,
        logical: str,
        mode: int,
        uid: int | None = None,
        gid: int | None = None,
    ) -> None:
        self.capture(logical)
        target = self.logical_to_real(logical)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".sparklink-new")
        shutil.copyfile(source, temporary)
        os.chmod(temporary, mode)
        if os.name != "nt" and (uid is not None or gid is not None):
            os.chown(temporary, -1 if uid is None else uid, -1 if gid is None else gid)
        os.replace(temporary, target)

    def install_text(
        self,
        text: str,
        logical: str,
        mode: int,
        uid: int | None = None,
        gid: int | None = None,
    ) -> None:
        temporary = self.directory / "generated" / hashlib.sha256(logical.encode()).hexdigest()
        temporary.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(text, encoding="utf-8", newline="\n")
        self.install_file(temporary, logical, mode, uid, gid)

    def install_symlink(self, target_value: str, logical: str) -> None:
        self.capture(logical)
        target = self.logical_to_real(logical)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".sparklink-new")
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
        temporary.symlink_to(target_value)
        os.replace(temporary, target)

    def remove(self, logical: str) -> None:
        self.capture(logical)
        target = self.logical_to_real(logical)
        if target.is_file() or target.is_symlink():
            target.unlink()
        elif target.exists():
            raise ValueError(f"refusing to remove non-file path: {logical}")

    def add_note(self, note: str) -> None:
        self.notes.append(note)
        self._write_manifest()

    def finalize(self) -> None:
        self.complete = True
        self._write_manifest()

    def rollback(self) -> None:
        for record in reversed(self.records):
            target = self.logical_to_real(record.path)
            if target.is_file() or target.is_symlink():
                target.unlink()
            if not record.existed:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if record.kind == "symlink":
                target.symlink_to(record.backup or "")
            elif record.kind == "file":
                backup = self.directory / str(record.backup)
                shutil.copy2(backup, target)
                if record.mode is not None:
                    os.chmod(target, record.mode)
                if os.name != "nt" and record.uid is not None and record.gid is not None:
                    os.chown(target, record.uid, record.gid)
        self.complete = False
        self.notes.append("rollback applied")
        self._write_manifest()

    def _write_manifest(self) -> None:
        manifest = {
            "schema_version": 1,
            "transaction_id": self.transaction_id,
            "root": os.fspath(self.root),
            "complete": self.complete,
            "records": [dataclasses.asdict(record) for record in self.records],
            "notes": self.notes,
        }
        temporary = self.directory / "manifest.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, self.directory / "manifest.json")

    @classmethod
    def load(cls, backup_directory: Path) -> "Transaction":
        manifest_path = backup_directory / "manifest.json"
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != 1 or raw.get("transaction_id") != backup_directory.name:
            raise ValueError("invalid transaction manifest")
        instance = cls.__new__(cls)
        instance.root = Path(raw["root"]).resolve()
        instance.backup_base = backup_directory.parent.resolve()
        instance.transaction_id = raw["transaction_id"]
        instance.directory = backup_directory.resolve()
        instance.files_directory = instance.directory / "files"
        instance.records = [Record(**item) for item in raw["records"]]
        instance.notes = list(raw.get("notes", []))
        instance.complete = bool(raw.get("complete"))
        return instance


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
