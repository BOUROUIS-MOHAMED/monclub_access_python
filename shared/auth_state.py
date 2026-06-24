"""Shared auth token helpers used by Access and TV."""

from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass
class AuthTokenState:
    email: str
    token: str
    last_login_at: str
    # Refresh-token extension (two-token auth, Task 18)
    refresh_token: str = ""     # raw opaque refresh token (not stored here encrypted; db layer handles that)
    next_refresh_at: str = ""   # ISO UTC deadline: app proactively refreshes when past this


# ---------------------------------------------------------------------------
# DPAPI (Windows) setup — done ONCE at import, NOT per call.
#
# The previous code defined a ctypes.Structure subclass (DATA_BLOB), loaded the
# crypt32/kernel32 WinDLLs, and set .argtypes on EVERY call to protect/unprotect.
# Each new DATA_BLOB class seeds ctypes' internal type caches (POINTER(DATA_BLOB),
# c_byte*N, …) which are never freed → ~110 bytes leaked per call. These helpers
# are on the auth hot path (hundreds of thousands of calls), so the process grew
# ~37 MB/h and eventually hit the 32-bit address ceiling → "can't start new thread"
# (the Type-2 daily lockup). Defining everything once removes the leak entirely.
# ---------------------------------------------------------------------------
_DPAPI_READY = False
try:
    import ctypes as _ctypes
    from ctypes import wintypes as _wintypes

    class _DATA_BLOB(_ctypes.Structure):
        _fields_ = [("cbData", _wintypes.DWORD), ("pbData", _ctypes.POINTER(_ctypes.c_byte))]

    _crypt32 = _ctypes.WinDLL("crypt32.dll")
    _kernel32 = _ctypes.WinDLL("kernel32.dll")

    _crypt32.CryptProtectData.argtypes = [
        _ctypes.POINTER(_DATA_BLOB), _wintypes.LPCWSTR, _ctypes.POINTER(_DATA_BLOB),
        _wintypes.LPVOID, _wintypes.LPVOID, _wintypes.DWORD, _ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = _wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [
        _ctypes.POINTER(_DATA_BLOB), _ctypes.POINTER(_wintypes.LPWSTR), _ctypes.POINTER(_DATA_BLOB),
        _wintypes.LPVOID, _wintypes.LPVOID, _wintypes.DWORD, _ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = _wintypes.BOOL
    _DPAPI_READY = True
except Exception:
    _DPAPI_READY = False


def _bytes_to_blob(b: bytes):
    buf = (_ctypes.c_byte * len(b))(*b)
    return _DATA_BLOB(len(b), _ctypes.cast(buf, _ctypes.POINTER(_ctypes.c_byte)))


def _blob_to_bytes(blob) -> bytes:
    cb = int(blob.cbData)
    if cb <= 0:
        return b""
    data = _ctypes.string_at(blob.pbData, cb)
    _kernel32.LocalFree(blob.pbData)
    return data


def protect_auth_token(plain: str) -> str:
    """
    Best-effort encryption for auth tokens on Windows using DPAPI.
    Falls back to a raw prefix if DPAPI is unavailable.
    """
    if not _DPAPI_READY:
        import logging as _log
        _log.getLogger(__name__).error("DPAPI unavailable — refusing to store plaintext token")
        return ""
    try:
        in_blob = _bytes_to_blob(plain.encode("utf-8"))
        out_blob = _DATA_BLOB()
        ok = _crypt32.CryptProtectData(
            _ctypes.byref(in_blob), None, None, None, None, 0, _ctypes.byref(out_blob)
        )
        if not ok:
            import logging as _log
            _log.getLogger(__name__).error("DPAPI CryptProtectData failed — refusing to store plaintext token")
            return ""
        enc = _blob_to_bytes(out_blob)
        return "dpapi:" + base64.b64encode(enc).decode("ascii")
    except Exception as _exc:
        import logging as _log
        _log.getLogger(__name__).error("DPAPI unavailable (%s) — refusing to store plaintext token", _exc)
        return ""


def unprotect_auth_token(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith("raw:"):
        return stored[len("raw:") :]
    if not stored.startswith("dpapi:"):
        return stored
    if not _DPAPI_READY:
        return ""
    try:
        enc = base64.b64decode(stored[len("dpapi:") :].encode("ascii"))
        in_blob = _bytes_to_blob(enc)
        out_blob = _DATA_BLOB()
        ok = _crypt32.CryptUnprotectData(
            _ctypes.byref(in_blob), None, None, None, None, 0, _ctypes.byref(out_blob)
        )
        if not ok:
            return ""
        dec = _blob_to_bytes(out_blob)
        return dec.decode("utf-8", errors="replace")
    except Exception:
        return ""


def next_refresh_at_from_expires(expires_at_iso: str, *, lead_days: int = 3) -> str:
    """Compute the proactive-refresh deadline as an ISO UTC string.

    Returns empty string on any parse error so callers can treat it as
    "no deadline" without crashing.
    """
    if not expires_at_iso:
        return ""
    try:
        from datetime import datetime, timezone, timedelta
        exp = datetime.fromisoformat(expires_at_iso.replace("Z", "+00:00"))
        due = exp.astimezone(timezone.utc) - timedelta(days=lead_days)
        return due.isoformat()
    except Exception:
        return ""


def is_refresh_due(next_refresh_at: str) -> bool:
    """Return True if the proactive-refresh deadline has passed.

    An empty or unparseable deadline is treated as *not due* to be safe
    (callers fall back to the 401 safety-net path).
    """
    if not next_refresh_at:
        return False
    try:
        from datetime import datetime, timezone
        due = datetime.fromisoformat(next_refresh_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        return datetime.now(timezone.utc) >= due
    except Exception:
        return False


__all__ = [
    "AuthTokenState",
    "protect_auth_token",
    "unprotect_auth_token",
    "next_refresh_at_from_expires",
    "is_refresh_due",
]
