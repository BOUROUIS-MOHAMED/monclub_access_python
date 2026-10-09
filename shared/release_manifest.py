"""Accept or refuse a server update offer (design section 5.2; D3, D8, D29 client half).

The server's offer is untrusted. It is accepted only when its ``signedManifest`` string
verifies with a trusted Ed25519 key (shared/release_keys.py) and the manifest, parsed AFTER
verification, names this component, platform, channel and the offered version. The
download is then checked against the manifest's SHA-256 and size, never the server's.

Version rule: a normal manifest (``allowDowngrade=false``, ``rollbackFrom=null``) is
accepted only for a version above the installed one. A rollback manifest
(``allowDowngrade=true``) only when ``rollbackFrom`` equals the installed version, so an old
signed manifest replayed by a hacked server cannot downgrade a PC.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlsplit

from shared import ed25519
from shared.update_versions import compare_versions, parse_version

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-fA-F]{128}")
# monclub_<target>_<version...>.exe: the name the "Setup running" check knows
# (shared/update_files.py::SETUP_IMAGE_RE) and a plain file name inside downloads\.
_INSTALLER_NAME = re.compile(r"monclub_(access|tv)_[0-9][0-9A-Za-z._-]{0,120}\.exe", re.IGNORECASE)
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class OfferRefused(Exception):
    """The offer must not be downloaded or installed.

    ``code``: ``UNSIGNED`` (server sends no signed manifest -- today's backend),
    ``BAD_SIGNATURE``, ``UNKNOWN_KEY``, ``MISMATCH`` (manifest names another
    component / platform / channel / version), ``BAD_MANIFEST`` (unparseable or a field
    is invalid), ``NOT_NEWER`` (a normal manifest for a version not above the installed
    one -- not an attack, just nothing to do), ``ROLLBACK_NOT_FOR_US``.
    ``code`` other than NOT_NEWER is reported as VERIFY_FAILED.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    @property
    def is_verify_failure(self) -> bool:
        return self.code != "NOT_NEWER"


@dataclass(frozen=True)
class VerifiedOffer:
    version: str
    target: str
    platform: str
    channel: str
    installer_name: str
    installer_sha256: str
    installer_size: int
    installer_url: str
    rollback: bool
    rollback_from: Optional[str]
    manifest_text: str
    signature_hex: str
    key_id: str
    issued_at: str

    def to_json(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "target": self.target,
            "platform": self.platform,
            "channel": self.channel,
            "installerName": self.installer_name,
            "installerSha256": self.installer_sha256,
            "installerSize": self.installer_size,
            "installerUrl": self.installer_url,
            "rollback": self.rollback,
            "rollbackFrom": self.rollback_from,
            "signedManifest": self.manifest_text,
            "manifestSignature": self.signature_hex,
            "signingKeyId": self.key_id,
            "issuedAt": self.issued_at,
        }


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _url_allowed(url: str) -> bool:
    """https, or http to this PC only (the L4 end-to-end serves installers on 127.0.0.1).

    The signature + SHA-256 make the file safe whatever the URL; this only keeps the
    download off cleartext networks."""
    try:
        parts = urlsplit(url)
    except Exception:
        return False
    if parts.scheme == "https" and parts.hostname:
        return True
    return parts.scheme == "http" and (parts.hostname or "") in _LOOPBACK_HOSTS


def verify_offer(
    offer: Mapping[str, Any],
    *,
    target: str,
    platform: str,
    channel: str,
    installed_version: str,
    keys: Mapping[str, str],
) -> VerifiedOffer:
    """The verified offer, or raise OfferRefused. Never downloads anything."""
    if not isinstance(offer, Mapping):
        raise OfferRefused("BAD_MANIFEST", "offer is not a JSON object")
    offered_version = _text(offer.get("version"))
    manifest_text = offer.get("signedManifest")
    signature_hex = _text(offer.get("manifestSignature"))
    key_id = _text(offer.get("signingKeyId"))

    if not isinstance(manifest_text, str) or not manifest_text or not signature_hex or not key_id:
        raise OfferRefused("UNSIGNED", f"release {offered_version or '?'} has no signed manifest; refusing to install it")
    if not manifest_text.isascii():
        raise OfferRefused("BAD_MANIFEST", "signed manifest is not ASCII")
    if not _HEX128.fullmatch(signature_hex):
        raise OfferRefused("BAD_SIGNATURE", "manifest signature is not 128 hex characters")
    public_hex = keys.get(key_id)
    if not public_hex:
        raise OfferRefused("UNKNOWN_KEY", f"signing key {key_id!r} is not trusted by this build")
    try:
        public = bytes.fromhex(public_hex)
    except ValueError:
        raise OfferRefused("UNKNOWN_KEY", f"trusted key {key_id!r} is malformed")
    if not ed25519.verify(public, manifest_text.encode("ascii"), bytes.fromhex(signature_hex)):
        raise OfferRefused("BAD_SIGNATURE", "manifest signature does not verify")

    # Only now is the manifest trusted enough to parse.
    try:
        manifest = json.loads(manifest_text)
    except ValueError:
        raise OfferRefused("BAD_MANIFEST", "signed manifest is not JSON")
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise OfferRefused("BAD_MANIFEST", "signed manifest has an unknown schema")

    m_target = _text(manifest.get("target")).lower()
    m_platform = _text(manifest.get("platform")).upper()
    m_channel = _text(manifest.get("channel")).lower()
    m_version = manifest.get("version")
    if m_target != target.lower():
        raise OfferRefused("MISMATCH", f"manifest is for target {m_target!r}, not {target!r}")
    if m_platform != platform.upper():
        raise OfferRefused("MISMATCH", f"manifest is for platform {m_platform!r}, not {platform!r}")
    if m_channel != channel.lower():
        raise OfferRefused("MISMATCH", f"manifest is for channel {m_channel!r}, not {channel!r}")
    if not isinstance(m_version, str) or parse_version(m_version) is None:
        raise OfferRefused("BAD_MANIFEST", "manifest version is not a valid version")
    if m_version != offered_version:
        raise OfferRefused("MISMATCH", f"manifest version {m_version} differs from offered {offered_version or '?'}")

    name = manifest.get("installerName")
    sha = manifest.get("installerSha256")
    size = manifest.get("installerSize")
    name_match = _INSTALLER_NAME.fullmatch(name) if isinstance(name, str) else None
    if not name_match or name_match.group(1).lower() != m_target:
        raise OfferRefused("BAD_MANIFEST", "manifest installerName is not monclub_<target>_<version>.exe")
    if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
        raise OfferRefused("BAD_MANIFEST", "manifest installerSha256 is not 64 lowercase hex")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise OfferRefused("BAD_MANIFEST", "manifest installerSize is not a positive integer")

    allow_downgrade = manifest.get("allowDowngrade")
    rollback_from = manifest.get("rollbackFrom")
    if allow_downgrade is not True and allow_downgrade is not False:
        raise OfferRefused("BAD_MANIFEST", "manifest allowDowngrade is not a boolean")
    order = compare_versions(m_version, installed_version)
    if allow_downgrade:
        if not isinstance(rollback_from, str) or not rollback_from:
            raise OfferRefused("BAD_MANIFEST", "rollback manifest has no rollbackFrom")
        if rollback_from != installed_version or order != -1:
            raise OfferRefused(
                "ROLLBACK_NOT_FOR_US",
                f"rollback {rollback_from} -> {m_version} does not apply to installed {installed_version or '?'}",
            )
        rollback = True
    else:
        if rollback_from is not None:
            raise OfferRefused("BAD_MANIFEST", "normal manifest carries rollbackFrom")
        if order != 1:
            raise OfferRefused("NOT_NEWER", f"{m_version} is not newer than installed {installed_version or '?'}")
        rollback = False

    installer = offer.get("installer") if isinstance(offer.get("installer"), Mapping) else {}
    url = _text(installer.get("url"))
    if not _url_allowed(url):
        raise OfferRefused("BAD_MANIFEST", "installer URL is not https")

    return VerifiedOffer(
        version=m_version,
        target=m_target,
        platform=m_platform,
        channel=m_channel,
        installer_name=name,
        installer_sha256=sha,
        installer_size=size,
        installer_url=url,
        rollback=rollback,
        rollback_from=rollback_from if rollback else None,
        manifest_text=manifest_text,
        signature_hex=signature_hex.lower(),
        key_id=key_id,
        issued_at=_text(manifest.get("issuedAt")),
    )


def canonical_manifest(fields: Mapping[str, Any]) -> str:
    """The exact signed-bytes form of design section 5.2 (used by tests and tools)."""
    return json.dumps(dict(fields), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


__all__ = ["OfferRefused", "VerifiedOffer", "canonical_manifest", "verify_offer"]
