"""Public keys that may sign a MonClub Access / TV release (design section 5.1).

``PROD_KEYS`` maps keyId -> 64-hex Ed25519 public key. It is shipped inside every build;
the client installs a release only if its manifest verifies against one of these keys.
Add a new key in one release BEFORE signing with it, so PCs already trust it (rotation).

TODO(owner, before the 1.5.0 build): on the build PC run
    python tools/release_sign.py keygen
which keeps the private key in %USERPROFILE%\\.monclub\\release-signing\\<keyId>.key (never
in a repo, never printed) and prints the PUBLIC key. Paste that keyId + public key here and
into the backend prod config ``monclub.release-signing.public-keys``. Until then the list is
empty, every release fails verification (VERIFY_FAILED) and build_release.ps1 refuses to
produce a publishable build. A lane must never generate a production key.

``TEST_KEYS`` are trusted only when the app runs from source (never in a frozen build).
A frozen end-to-end test build trusts the test key only because build_release.ps1's
E2E switch rewrites the STAGED copy of this file with the test key inside PROD_KEYS; such
a build is refused for publishing (a ``test-`` keyId in PROD_KEYS).
The test seed is not secret: tests/fixtures/release_signing/test-l2-2026-10.seed
(SHA-256 of b"monclub-updater-v2-test-key-2026-10").
"""

from __future__ import annotations

import os
from typing import Dict

PROD_KEYS: Dict[str, str] = {}

TEST_KEYS: Dict[str, str] = {
    "test-l2-2026-10": "b7a32fb80368ee93dda0c920d0c577852159b16d2fc9a3d921a17fc2f28777b0",
}

TEST_KEYS_ENV = "MONCLUB_UPDATER_TEST_KEYS"


def _is_frozen() -> bool:
    import sys

    return bool(getattr(sys, "frozen", False))


def trusted_keys(*, frozen: bool | None = None) -> Dict[str, str]:
    """keyId -> public key hex this process accepts.

    PROD_KEYS always. TEST_KEYS only when not frozen (running from source; the
    ``MONCLUB_UPDATER_TEST_KEYS=1`` switch is accepted as an explicit opt-in there, and
    ``=0`` turns them off for a source run that must behave like production).
    """
    keys = {str(k): str(v).strip().lower() for k, v in PROD_KEYS.items()}
    is_frozen = _is_frozen() if frozen is None else bool(frozen)
    if not is_frozen and os.environ.get(TEST_KEYS_ENV, "1").strip() != "0":
        for key_id, public_hex in TEST_KEYS.items():
            keys.setdefault(str(key_id), str(public_hex).strip().lower())
    return keys


__all__ = ["PROD_KEYS", "TEST_KEYS", "TEST_KEYS_ENV", "trusted_keys"]
