"""Shared auth token helpers used by Access and TV."""

from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass
class AuthTokenState:
    email: str
    token: str
    last_login_at: str


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
            return "raw:" + plain

        enc = _blob_to_bytes(out_blob)
        return "dpapi:" + base64.b64encode(enc).decode("ascii")
    except Exception:
        return "raw:" + plain


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


__all__ = ["AuthTokenState", "protect_auth_token", "unprotect_auth_token"]
