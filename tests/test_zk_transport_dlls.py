"""zkemkeeper transport DLLs and ProgID (2026-10-26 outage: fresh gym PC, Connect_Net always False)."""

from pathlib import Path

import pytest

from app.sdk import zk_standalone as zks

SDK_DIR = Path(__file__).resolve().parents[1] / "app" / "sdk"


def _pe_machine(path: Path) -> int:
    data = path.read_bytes()
    assert data[:2] == b"MZ", path
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    assert data[pe_off:pe_off + 4] == b"PE\x00\x00", path
    return int.from_bytes(data[pe_off + 4:pe_off + 6], "little")


def test_shipped_zkemkeeper_registers_the_first_progid_tried():
    data = (SDK_DIR / "zkemkeeper.dll").read_bytes()
    first = zks.ZKEMKEEPER_PROG_IDS[0]
    assert first.encode("ascii") in data or first.encode("utf-16-le") in data
    # The DLL never writes the .NET interop name; a check keyed on it alone is always red.
    assert b"zkemkeeper.CZKEM" not in data and "zkemkeeper.CZKEM".encode("utf-16-le") not in data


@pytest.mark.parametrize("name", zks._TRANSPORT_DLLS)
def test_transport_dll_ships_in_sdk_as_32_bit(name):
    path = SDK_DIR / name
    assert path.is_file(), f"{name} must ship in app/sdk (MonClubAccess.spec globs *.dll)"
    assert _pe_machine(path) == 0x14C  # IMAGE_FILE_MACHINE_I386


def test_preload_loads_by_absolute_path_once_and_never_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(zks, "_transport_done", False)
    monkeypatch.setattr(zks, "_transport_handles", [])
    (tmp_path / "tcpcomm.dll").write_bytes(b"x")
    (tmp_path / "comms.dll").write_bytes(b"x")
    calls = []

    def loader(path):
        calls.append(path)
        if path.endswith("comms.dll"):
            raise OSError("bad image")
        return object()

    report = zks._preload_transport_dlls(sdk_dir=str(tmp_path), loader=loader)

    assert calls == [str(tmp_path / "tcpcomm.dll"), str(tmp_path / "comms.dll")]
    assert report["tcpcomm.dll"] == "loaded"
    assert report["comms.dll"].startswith("failed:")
    assert report["usbcomm.dll"] == report["rscomm.dll"] == report["usbstd.dll"] == "missing"
    assert len(zks._transport_handles) == 1  # the loaded module stays pinned

    assert zks._preload_transport_dlls(sdk_dir=str(tmp_path), loader=loader) == {}
    assert len(calls) == 2
