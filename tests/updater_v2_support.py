"""Helpers shared by the updater v2 client tests: test-key signing and offers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from shared import ed25519
from shared.release_keys import TEST_KEYS
from shared.release_manifest import canonical_manifest

TEST_KEY_ID = "test-l2-2026-10"
TEST_SEED = bytes.fromhex(
    (Path(__file__).parent / "fixtures" / "release_signing" / "test-l2-2026-10.seed").read_text(encoding="ascii").strip()
)
TEST_KEYRING = {TEST_KEY_ID: TEST_KEYS[TEST_KEY_ID]}

OTHER_SEED = hashlib.sha256(b"not-a-trusted-key").digest()


def installer_bytes(version: str, size: int = 4096) -> bytes:
    seed = f"MonClub fake installer {version}\n".encode("ascii")
    return (seed * (size // len(seed) + 1))[:size]


def manifest_fields(
    *,
    version: str = "1.5.1",
    target: str = "access",
    platform: str = "WINDOWS",
    channel: str = "stable",
    payload: Optional[bytes] = None,
    name: Optional[str] = None,
    rollback_from: Optional[str] = None,
    **overrides: Any,
) -> Dict[str, Any]:
    data = payload if payload is not None else installer_bytes(version)
    fields: Dict[str, Any] = {
        "allowDowngrade": rollback_from is not None,
        "channel": channel,
        "installerName": name or f"monclub_{target}_{version}.exe",
        "installerSha256": hashlib.sha256(data).hexdigest(),
        "installerSize": len(data),
        "issuedAt": "2026-10-10T08:00:00Z",
        "platform": platform,
        "rollbackFrom": rollback_from,
        "schema": 1,
        "target": target,
        "version": version,
    }
    fields.update(overrides)
    return fields


def make_offer(
    *,
    version: str = "1.5.1",
    target: str = "access",
    seed: bytes = TEST_SEED,
    key_id: str = TEST_KEY_ID,
    url: Optional[str] = None,
    fields: Optional[Dict[str, Any]] = None,
    manifest_text: Optional[str] = None,
    **field_kwargs: Any,
) -> Dict[str, Any]:
    f = fields if fields is not None else manifest_fields(version=version, target=target, **field_kwargs)
    text = manifest_text if manifest_text is not None else canonical_manifest(f)
    signature = ed25519.sign(seed, text.encode("ascii")).hex()
    return {
        "shouldUpdate": True,
        "version": f.get("version", version),
        "codename": "Test",
        "releaseNotes": "<p>Notes</p>",
        "installer": {
            "url": url or f"https://github.com/monclub/releases/{f.get('installerName')}",
            "name": f.get("installerName"),
            "size": f.get("installerSize"),
        },
        "signedManifest": text,
        "manifestSignature": signature,
        "signingKeyId": key_id,
        "installerSha256": f.get("installerSha256"),
        "rollback": bool(f.get("allowDowngrade")),
    }
