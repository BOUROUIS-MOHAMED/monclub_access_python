# monclub_access_python/app/core/secure_store.py
from __future__ import annotations

import sys

_IS_WIN = sys.platform.startswith("win")


class SecureStoreError(RuntimeError):
    """Raised when bytes cannot be protected or unprotected with Windows DPAPI."""


def protect_bytes(data: bytes) -> bytes:
    if not data:
        return b""
    if not _IS_WIN:
        raise SecureStoreError("Windows DPAPI is unavailable")
    try:
        import ctypes
        from ctypes import wintypes

        CRYPTPROTECT_UI_FORBIDDEN = 0x01

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_blob = DATA_BLOB()
        in_blob.cbData = len(data)
        in_blob.pbData = ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte))

        out_blob = DATA_BLOB()

        if not crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        ):
            raise SecureStoreError("CryptProtectData failed")

        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return out
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except SecureStoreError:
        raise
    except Exception as exc:
        raise SecureStoreError("Windows DPAPI protection failed") from exc


def unprotect_bytes(blob: bytes) -> bytes:
    if not blob:
        return b""
    if not _IS_WIN:
        raise SecureStoreError("Windows DPAPI is unavailable")
    try:
        import ctypes
        from ctypes import wintypes

        CRYPTPROTECT_UI_FORBIDDEN = 0x01

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        in_blob = DATA_BLOB()
        in_blob.cbData = len(blob)
        in_blob.pbData = ctypes.cast(ctypes.create_string_buffer(blob), ctypes.POINTER(ctypes.c_byte))

        out_blob = DATA_BLOB()

        if not crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        ):
            raise SecureStoreError("CryptUnprotectData failed")

        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return out
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except SecureStoreError:
        raise
    except Exception as exc:
        raise SecureStoreError("Windows DPAPI unprotection failed") from exc
