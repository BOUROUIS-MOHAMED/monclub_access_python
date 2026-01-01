from __future__ import annotations

import sys
from typing import Optional

_IS_WIN = sys.platform.startswith("win")


def protect_bytes(data: bytes) -> bytes:
    if not data:
        return b""
    if not _IS_WIN:
        return data  # fallback
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
            raise OSError("CryptProtectData failed")

        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return out
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except Exception:
        # fallback (not ideal, but avoids crashing)
        return data


def unprotect_bytes(blob: bytes) -> bytes:
    if not blob:
        return b""
    if not _IS_WIN:
        return blob  # fallback
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
            raise OSError("CryptUnprotectData failed")

        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return out
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except Exception:
        # fallback
        return blob
