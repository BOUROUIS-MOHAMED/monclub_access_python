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


def protect_auth_token(plain: str) -> str:
    """
    Best-effort encryption for auth tokens on Windows using DPAPI.
    Falls back to a raw prefix if DPAPI is unavailable.
    """
    try:
        import ctypes
        from ctypes import wintypes

        crypt32 = ctypes.WinDLL("crypt32.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        def _bytes_to_blob(b: bytes) -> DATA_BLOB:
            buf = (ctypes.c_byte * len(b))(*b)
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

        def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
            cb = int(blob.cbData)
            if cb <= 0:
                return b""
            data = ctypes.string_at(blob.pbData, cb)
            kernel32.LocalFree(blob.pbData)
            return data

        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPCWSTR,
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptProtectData.restype = wintypes.BOOL

        plain_bytes = plain.encode("utf-8")
        in_blob = _bytes_to_blob(plain_bytes)
        out_blob = DATA_BLOB()

        ok = crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
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

    try:
        import ctypes
        from ctypes import wintypes

        crypt32 = ctypes.WinDLL("crypt32.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        def _bytes_to_blob_alloc(b: bytes) -> DATA_BLOB:
            buf = (ctypes.c_byte * len(b))(*b)
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

        def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
            cb = int(blob.cbData)
            if cb <= 0:
                return b""
            data = ctypes.string_at(blob.pbData, cb)
            kernel32.LocalFree(blob.pbData)
            return data

        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL

        enc = base64.b64decode(stored[len("dpapi:") :].encode("ascii"))
        in_blob = _bytes_to_blob_alloc(enc)
        out_blob = DATA_BLOB()

        ok = crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
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
