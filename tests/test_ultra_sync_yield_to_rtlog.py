"""Tests for the ULTRA "yield to RTLog during device sync" feature.

When ``ultra_sync_yield_to_rtlog`` (gym-level — dashboard /account → MonClub
Access tab) is enabled, a long inline device sync interleaves RTLog polling +
scan processing between push chunks so the entry popup doesn't freeze and
PC-verified QR/TOTP members still get in while the roster is being pushed.

The hook's contract — verified here — is:
  * default OFF (gym-level flag, read live via get_backend_global_settings),
  * throttled to ~1 poll/sec so a long push doesn't hammer the single SDK conn,
  * NEVER disconnects on a failed poll (that would corrupt the in-flight push),
  * dedups via the worker's normal _process_event path,
  * best-effort: an internal error never aborts the sync.
"""
from __future__ import annotations

import importlib
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


# --------------------------------------------------------------------------- #
# normalize_global_settings — camelCase backend flag -> snake_case internal key
# --------------------------------------------------------------------------- #

class TestNormalizeGlobalSettings:
    def _norm(self, raw):
        from app.core.settings_reader import normalize_global_settings
        return normalize_global_settings(raw)

    def test_default_false_when_absent(self):
        assert self._norm({})["ultra_sync_yield_to_rtlog"] is False

    def test_maps_camelcase_true(self):
        assert self._norm({"ultraSyncYieldToRtlog": True})["ultra_sync_yield_to_rtlog"] is True

    def test_snake_case_fallback(self):
        assert self._norm({"ultra_sync_yield_to_rtlog": True})["ultra_sync_yield_to_rtlog"] is True

    def test_falsey_stays_false(self):
        assert self._norm({"ultraSyncYieldToRtlog": False})["ultra_sync_yield_to_rtlog"] is False


# --------------------------------------------------------------------------- #
# db.py — row->payload coercion + a real save/load round-trip through the DDL
# --------------------------------------------------------------------------- #

class TestCoercePayload:
    def _coerce(self, row):
        from app.core.db import _coerce_sync_access_software_settings_row_to_payload
        return _coerce_sync_access_software_settings_row_to_payload(row)

    def test_row_one_is_true(self):
        assert self._coerce({"ultra_sync_yield_to_rtlog": 1})["ultraSyncYieldToRtlog"] is True

    def test_row_zero_is_false(self):
        assert self._coerce({"ultra_sync_yield_to_rtlog": 0})["ultraSyncYieldToRtlog"] is False

    def test_missing_key_defaults_false(self):
        # Older snapshot rows without the column must coerce to False, not raise.
        assert self._coerce({"gym_id": 1})["ultraSyncYieldToRtlog"] is False


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "yield.db"), raising=False)
    db_module.init_db()
    return db_module


class TestDbRoundTrip:
    """Exercises the full DDL column + upsert (29 cols/placeholders) + SELECT +
    coerce chain — a placeholder/column mismatch would surface here."""

    def test_save_then_load_true(self, db):
        with db.get_conn() as conn:
            db._upsert_sync_access_software_settings_row(
                conn.cursor(),
                {"gymId": 1, "ultraSyncYieldToRtlog": True},
                updated_at="2026-06-29T00:00:00Z",
            )
            conn.commit()
        loaded = db.load_sync_access_software_settings()
        assert loaded is not None
        assert loaded["ultraSyncYieldToRtlog"] is True

    def test_default_false_when_omitted(self, db):
        with db.get_conn() as conn:
            db._upsert_sync_access_software_settings_row(
                conn.cursor(), {"gymId": 1}, updated_at="2026-06-29T00:00:00Z",
            )
            conn.commit()
        assert db.load_sync_access_software_settings()["ultraSyncYieldToRtlog"] is False


# --------------------------------------------------------------------------- #
# UltraDeviceWorker._sync_yield_to_rtlog — gate, throttle, safety
# --------------------------------------------------------------------------- #

def _yield_worker(connected: bool = True):
    """Minimal worker carrying only what _sync_yield_to_rtlog touches."""
    from app.core.ultra_engine import UltraDeviceWorker
    w = UltraDeviceWorker.__new__(UltraDeviceWorker)
    w._sdk = object() if connected else None
    w._connected = connected
    w._tel_wid = "ULTRA:1"
    w._last_sync_rtlog_yield_mono = 0.0
    w._poll_with_watchdog = MagicMock(return_value=[])
    w._process_event = MagicMock()
    w._disconnect = MagicMock()
    return w


def _patch_gate(monkeypatch, enabled: bool):
    import app.core.settings_reader as sr
    monkeypatch.setattr(
        sr, "get_backend_global_settings",
        lambda: {"ultra_sync_yield_to_rtlog": enabled},
    )


class TestSyncYieldToRtlog:
    def test_disabled_does_not_poll(self, monkeypatch):
        _patch_gate(monkeypatch, False)
        w = _yield_worker()
        w._sync_yield_to_rtlog()
        w._poll_with_watchdog.assert_not_called()
        w._process_event.assert_not_called()

    def test_enabled_polls_and_processes_each_event(self, monkeypatch):
        _patch_gate(monkeypatch, True)
        w = _yield_worker()
        w._poll_with_watchdog.return_value = [{"eventId": "a"}, {"eventId": "b"}]
        w._sync_yield_to_rtlog()
        w._poll_with_watchdog.assert_called_once()
        assert w._process_event.call_count == 2

    def test_throttled_within_interval(self, monkeypatch):
        _patch_gate(monkeypatch, True)
        w = _yield_worker()
        w._poll_with_watchdog.return_value = [{"eventId": "a"}]
        w._sync_yield_to_rtlog()   # first call polls
        w._sync_yield_to_rtlog()   # immediate second call is throttled
        w._poll_with_watchdog.assert_called_once()

    def test_poll_none_never_disconnects_or_processes(self, monkeypatch):
        # A poll timeout/error mid-push returns None — we must NOT tear down the
        # connection (that would corrupt the in-flight SetDeviceData) and must
        # not process anything.
        _patch_gate(monkeypatch, True)
        w = _yield_worker()
        w._poll_with_watchdog.return_value = None
        w._sync_yield_to_rtlog()
        w._poll_with_watchdog.assert_called_once()
        w._process_event.assert_not_called()
        w._disconnect.assert_not_called()

    def test_not_connected_skips_poll(self, monkeypatch):
        _patch_gate(monkeypatch, True)
        w = _yield_worker(connected=False)
        w._sync_yield_to_rtlog()
        w._poll_with_watchdog.assert_not_called()

    def test_never_raises_on_internal_error(self, monkeypatch):
        _patch_gate(monkeypatch, True)
        w = _yield_worker()
        w._poll_with_watchdog.side_effect = RuntimeError("boom")
        # Must be swallowed — a yield poll must never abort the push.
        w._sync_yield_to_rtlog()
        w._process_event.assert_not_called()


# --------------------------------------------------------------------------- #
# DeviceSyncEngine._maybe_yield_rtlog — the engine-side hook
# --------------------------------------------------------------------------- #

class TestMaybeYieldRtlog:
    def _engine(self):
        import app.core.device_sync as device_sync_module
        return device_sync_module.DeviceSyncEngine(cfg=SimpleNamespace(), logger=MagicMock())

    def test_default_cb_is_none_and_noop(self):
        eng = self._engine()
        assert eng._rtlog_yield_cb is None
        eng._maybe_yield_rtlog()  # must not raise

    def test_calls_cb_when_set(self):
        eng = self._engine()
        cb = MagicMock()
        eng._rtlog_yield_cb = cb
        eng._maybe_yield_rtlog()
        cb.assert_called_once()

    def test_swallows_cb_exception(self):
        eng = self._engine()
        eng._rtlog_yield_cb = MagicMock(side_effect=RuntimeError("x"))
        eng._maybe_yield_rtlog()  # must not raise
