"""Per-installation identity and heartbeat support for MonClub Access."""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
from typing import Callable

from app.core.secure_store import SecureStoreError, protect_bytes, unprotect_bytes


_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PcCredentials:
    pc_uuid: str
    pc_secret: str


class PcCredentialStore:
    """Store one PC credential pair as a single DPAPI-protected file."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        protect: Callable[[bytes], bytes] = protect_bytes,
        unprotect: Callable[[bytes], bytes] = unprotect_bytes,
    ) -> None:
        if path is None:
            from access.storage import get_access_storage_paths

            path = get_access_storage_paths().data_dir / "pc_identity.dat"
        self.path = Path(path)
        self._protect = protect
        self._unprotect = unprotect

    def load(self) -> PcCredentials | None:
        if not self.path.is_file():
            return None
        try:
            protected = self.path.read_bytes()
            plain = self._unprotect(protected)
            payload = json.loads(plain.decode("utf-8"))
            pc_uuid = str(payload.get("pcUuid") or "").strip()
            pc_secret = str(payload.get("pcSecret") or "").strip()
            if not pc_uuid or not pc_secret:
                return None
            return PcCredentials(pc_uuid=pc_uuid, pc_secret=pc_secret)
        except Exception as exc:
            _log.warning("PC credential store is unreadable; returning first-run state: %s", exc)
            return None

    def save(self, credentials: PcCredentials) -> None:
        if not credentials.pc_uuid.strip() or not credentials.pc_secret.strip():
            raise ValueError("Both pcUuid and pcSecret are required")

        plain = json.dumps(
            {"pcUuid": credentials.pc_uuid, "pcSecret": credentials.pc_secret},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        protected = self._protect(plain)
        if not protected or protected == plain:
            raise SecureStoreError("DPAPI did not produce a protected credential blob")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.path.with_name(f"{self.path.name}.tmp")
        try:
            temporary_path.write_bytes(protected)
            os.replace(temporary_path, self.path)
        finally:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


__all__ = ["PcCredentialStore", "PcCredentials", "SecureStoreError"]
