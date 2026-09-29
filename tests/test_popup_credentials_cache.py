"""The popup's credential flags are TTL-cached, the "nothing known" (None) result included.

/popup/poll runs every ~1.5 s while a popup window is open. Before this fix a None result
(a PC with no devices, or a failed read) was never cached, so every poll queried the DB.
"""
import time as _real_time

import pytest

import app.api.local_access_api_v2 as v2
import app.core.db as dbmod


@pytest.fixture(autouse=True)
def _fresh_cache():
    def _reset():
        with v2._popup_creds_lock:
            v2._popup_creds_cache.clear()
            v2._popup_creds_cache.update({"valid": False, "value": None, "at": 0.0})
    _reset()
    yield
    _reset()


class _Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class _TimeWithClock:
    """The real time module, except monotonic(): patched on v2 only, never process-wide."""

    def __init__(self, clock):
        self._clock = clock

    def monotonic(self):
        return self._clock()

    def __getattr__(self, name):
        return getattr(_real_time, name)


def _install(monkeypatch, devices_or_exc):
    calls = {"n": 0}

    def _list():
        calls["n"] += 1
        if isinstance(devices_or_exc, Exception):
            raise devices_or_exc
        return list(devices_or_exc)

    monkeypatch.setattr(dbmod, "list_sync_devices_payload", _list)
    clock = _Clock()
    monkeypatch.setattr(v2, "time", _TimeWithClock(clock))
    return calls, clock


def test_no_devices_is_cached_for_the_ttl_then_read_again(monkeypatch):
    calls, clock = _install(monkeypatch, [])
    assert v2._popup_enabled_credentials() is None
    assert calls["n"] == 1
    clock.t += 1.5
    assert v2._popup_enabled_credentials() is None
    clock.t += v2._POPUP_CREDS_TTL_SEC - 3.0  # still inside the TTL
    assert v2._popup_enabled_credentials() is None
    assert calls["n"] == 1
    clock.t += 1.6  # past the TTL since the first read
    assert v2._popup_enabled_credentials() is None
    assert calls["n"] == 2


def test_a_failed_read_is_cached_too(monkeypatch):
    calls, clock = _install(monkeypatch, RuntimeError("database is locked"))
    assert v2._popup_enabled_credentials() is None
    clock.t += 1.5
    assert v2._popup_enabled_credentials() is None
    assert calls["n"] == 1
    clock.t += v2._POPUP_CREDS_TTL_SEC
    assert v2._popup_enabled_credentials() is None
    assert calls["n"] == 2


def test_a_non_empty_result_is_still_cached_and_returned_as_a_copy(monkeypatch):
    calls, clock = _install(monkeypatch, [
        {"active": True, "accessDevice": True, "rfidEnabled": True, "fingerprintEnabled": False,
         "totpEnabled": True, "faceIdEnabled": False},
    ])
    first = v2._popup_enabled_credentials()
    assert first == {"rfid": True, "fingerprint": False, "qr": True, "face": False}
    first["rfid"] = False  # a caller's change must not reach the cache
    clock.t += 1.5
    second = v2._popup_enabled_credentials()
    assert second == {"rfid": True, "fingerprint": False, "qr": True, "face": False}
    assert second is not first
    assert calls["n"] == 1
    clock.t += v2._POPUP_CREDS_TTL_SEC
    v2._popup_enabled_credentials()
    assert calls["n"] == 2
