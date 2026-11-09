"""The ZK9500 fingerprint chain must be loadable from app/sdk alone (2026-11-09).

fppswsk12.dll (the matching engine) imports libiomp5md.dll (Intel OpenMP). Access did not
ship it: on PCs that once had the ZKFinger driver it sat in SysWOW64, so enrolment worked;
on a fresh PC ZKFPM_Init returned -1 and the diagnostics said nothing was missing.

The guard below does not ask "can this PC load it" -- the dev PC has the file in SysWOW64 and
would pass anyway. It asks: is every DLL the chain imports either shipped in app/sdk or a
Windows system DLL that every PC has.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.sdk import zkfinger

SDK = Path(__file__).resolve().parents[1] / "app" / "sdk"

# The fingerprint chain (static imports + the runtime-loaded hops).
CHAIN = ("libzkfp.dll", "ZKFPCap.dll", "fpslib.dll", "zkfpslibLow.dll", "fppswsk12.dll", "libiomp5md.dll")

# DLLs that ship with every supported Windows (10+). Anything else must be in app/sdk.
WINDOWS = {
    "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll", "shlwapi.dll",
    "ole32.dll", "oleaut32.dll", "ws2_32.dll", "psapi.dll", "iphlpapi.dll", "winspool.drv",
    "setupapi.dll", "version.dll", "winmm.dll", "comctl32.dll", "comdlg32.dll", "ntdll.dll",
    "rpcrt4.dll", "crypt32.dll", "bcrypt.dll", "imm32.dll", "hid.dll", "cfgmgr32.dll",
}


def _machine(path: Path) -> int:
    b = path.read_bytes()
    e = struct.unpack_from("<I", b, 0x3C)[0]
    return struct.unpack_from("<H", b, e + 4)[0]


def test_libiomp5md_is_shipped_and_32_bit():
    p = SDK / "libiomp5md.dll"
    assert p.is_file(), "fppswsk12.dll imports libiomp5md.dll: it must ship in app/sdk"
    assert _machine(p) == 0x14C  # i386: the app is a 32-bit process


def test_the_engine_really_imports_it():
    """If a future SDK drops the dependency this test says so, instead of a stale claim."""
    imports = [n.lower() for n in zkfinger._pe_imports(SDK / "fppswsk12.dll")]
    assert "libiomp5md.dll" in imports


@pytest.mark.parametrize("dll", CHAIN)
def test_every_import_of_the_chain_is_shipped_or_windows(dll):
    shipped = {p.name.lower() for p in SDK.glob("*.dll")}
    for name in zkfinger._pe_imports(SDK / dll):
        n = name.lower()
        if n.startswith(("api-ms-win-", "ext-ms-")):
            continue
        assert n in shipped or n in WINDOWS, f"{dll} imports {name}: not in app/sdk and not a Windows DLL"


def test_libiomp5md_is_preloaded_before_the_engine():
    order = [n.lower() for n in zkfinger._RUNTIME_LOADED_VENDOR_DLLS]
    assert order.index("libiomp5md.dll") < order.index("fppswsk12.dll")


def test_a_present_dll_that_will_not_load_is_named_in_the_diagnostics(tmp_path):
    """The "MISSING: none" line hid the fresh-PC failure: the file was there, its load failed."""
    bogus = tmp_path / "fppswsk12.dll"
    bogus.write_bytes(b"not a PE file")
    zf = zkfinger.ZKFinger(dll_dir=str(tmp_path))
    zf._preload_from_dir(tmp_path, "fppswsk12.dll")
    assert "fppswsk12.dll" in zf._preload_errors
    assert "fppswsk12.dll" not in zf._preloaded
