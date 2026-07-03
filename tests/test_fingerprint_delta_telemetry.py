"""Tests for the device-sync fingerprint delta telemetry.

This telemetry exposes WHICH user/field flips the ULTRA device-sync fingerprint
(forcing a full ~10s blocking live-worker read that stalls RTLog polling and
bursts popups). The capture must be purely additive — it must NEVER change the
fingerprint hash or sync behaviour.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock


def _engine():
    import app.core.device_sync as device_sync_module
    return device_sync_module.DeviceSyncEngine(cfg=SimpleNamespace(), logger=MagicMock())


class TestComputeDesiredHashFieldsOut:
    def test_fields_out_does_not_change_hash(self):
        engine = _engine()
        user = {"fullName": "Bob", "firstCardId": "100"}
        h_base = engine._compute_desired_hash(
            pin="1", user=user, door_bitmask=2, templates=[], authorize_timezone_id=1,
        )
        fo: dict = {}
        h_dup = engine._compute_desired_hash(
            pin="1", user=user, door_bitmask=2, templates=[], authorize_timezone_id=1, fields_out=fo,
        )
        # The diagnostic capture must be a no-op on the hash itself.
        assert h_base == h_dup
        # …and it must populate the per-field breakdown.
        assert fo["name"] == "Bob"
        for k in ("card", "doors", "tz", "tplh", "tpln"):
            assert k in fo
        assert fo["doors"] == "2"
        assert fo["tz"] == "1"

    def test_changed_field_changes_hash_and_capture(self):
        engine = _engine()
        fo_a: dict = {}
        h_a = engine._compute_desired_hash(
            pin="1", user={"fullName": "Bob", "firstCardId": "100"},
            door_bitmask=2, templates=[], authorize_timezone_id=1, fields_out=fo_a,
        )
        fo_b: dict = {}
        h_b = engine._compute_desired_hash(
            pin="1", user={"fullName": "Bobby", "firstCardId": "100"},
            door_bitmask=2, templates=[], authorize_timezone_id=1, fields_out=fo_b,
        )
        assert h_a != h_b
        assert fo_a["name"] == "Bob"
        assert fo_b["name"] == "Bobby"


class TestDeviceCardNormalization:
    """The device CardNo is a 4-byte int (<=10 digits). Card normalization must be
    identical in the push and the desired-hash so a '99999+' marker toggle only
    re-syncs when the value the DEVICE receives truly changes."""

    def test_normalize_device_card_cases(self):
        import app.core.device_sync as ds
        f = ds._normalize_device_card
        assert f("8192567") == "8192567"          # normal numeric, fits
        assert f("99+8192567") == "998192567"      # short marker stripped, fits (9 digits)
        assert f("99999+8192567") == ""            # 12 digits -> exceeds 4-byte limit -> dropped
        assert f("999998192567") == ""             # same, already digits
        assert f("4294967295") == "4294967295"     # exact 4-byte max
        assert f("4294967296") == ""               # one over the max
        assert f("") == "" and f(None) == ""
        assert f("abc") == "" and f("0") == ""
        assert f("0008192567") == "8192567"        # leading zeros canonicalised

    def test_hash_ignores_toolong_marker(self):
        # A too-long marker normalizes to "" — same as no card — so it adds no card
        # noise to the desired hash (toggling it vs an empty card is a no-op).
        engine = _engine()
        h_marked = engine._compute_desired_hash(
            pin="1", user={"fullName": "A", "firstCardId": "99999+8192567"},
            door_bitmask=2, templates=[], authorize_timezone_id=1,
        )
        h_nocard = engine._compute_desired_hash(
            pin="1", user={"fullName": "A", "firstCardId": ""},
            door_bitmask=2, templates=[], authorize_timezone_id=1,
        )
        assert h_marked == h_nocard

    def test_hash_transparent_to_plus_separator(self):
        # `99+8192567` and `998192567` are the same device card -> identical hash.
        engine = _engine()
        h_plus = engine._compute_desired_hash(
            pin="1", user={"fullName": "A", "firstCardId": "99+8192567"},
            door_bitmask=2, templates=[], authorize_timezone_id=1,
        )
        h_digits = engine._compute_desired_hash(
            pin="1", user={"fullName": "A", "firstCardId": "998192567"},
            door_bitmask=2, templates=[], authorize_timezone_id=1,
        )
        assert h_plus == h_digits


class TestFingerprintDeltaLogger:
    def _scheduler(self):
        from app.core.ultra_engine import UltraSyncScheduler
        return UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())

    def test_identifies_changed_field(self):
        sched = self._scheduler()
        prev = {"header": "H", "users": {
            "1": {"name": "Bob", "card": "100", "doors": "1", "tz": "1", "tplh": "", "h": "aaaaaa"},
        }}
        cur = {"header": "H", "users": {
            "1": {"name": "Bobby", "card": "100", "doors": "1", "tz": "1", "tplh": "", "h": "bbbbbb"},
        }}
        sched._log_fingerprint_delta("5", prev, cur)

        # The summary line carries field_change_counts as its last positional arg.
        summary = next(
            c for c in sched._logger.info.call_args_list
            if c.args and "FP_DELTA reason" in str(c.args[0])
        )
        field_counts = summary.args[-1]
        assert field_counts == {"name": 1}

        # And a per-user sample names the field with prev/cur values.
        user_line = next(
            c for c in sched._logger.info.call_args_list
            if c.args and "FP_DELTA_USER" in str(c.args[0])
        )
        assert "name" in user_line.args[3]  # diff_fields list positional
        sample = user_line.args[-1]
        assert sample["name"]["prev"] == "Bob"
        assert sample["name"]["cur"] == "Bobby"

    def test_no_previous_detail_is_safe(self):
        sched = self._scheduler()
        cur = {"header": "H", "users": {"1": {"h": "x", "name": "Bob"}}}
        # Must not raise when there's no prior snapshot to diff against.
        sched._log_fingerprint_delta("5", None, cur)
        assert any(
            c.args and "no_prev_detail" in str(c.args[0])
            for c in sched._logger.info.call_args_list
        )

    def test_added_and_removed_users(self):
        sched = self._scheduler()
        prev = {"header": "H", "users": {"1": {"h": "a"}, "2": {"h": "b"}}}
        cur = {"header": "H", "users": {"2": {"h": "b"}, "3": {"h": "c"}}}
        sched._log_fingerprint_delta("5", prev, cur)
        summary = next(
            c for c in sched._logger.info.call_args_list
            if c.args and "FP_DELTA reason" in str(c.args[0])
        )
        # args: (fmt, device_id, reason, header_changed, added, removed, changed, field_counts)
        _, _device, _reason, _hdr, added, removed, changed, _fc = summary.args
        assert added == 1 and removed == 1 and changed == 0

    def test_never_raises_on_garbage(self):
        sched = self._scheduler()
        # Malformed details must be swallowed (best-effort telemetry).
        sched._log_fingerprint_delta("5", {"users": None}, {"users": None})
        sched._log_fingerprint_delta("5", "notadict", {"users": {}})

    def test_header_change_is_logged(self):
        sched = self._scheduler()
        prev = {"header": "doorBitmask=2", "users": {"1": {"h": "a"}}}
        cur = {"header": "doorBitmask=6", "users": {"1": {"h": "a"}}}
        sched._log_fingerprint_delta("5", prev, cur)
        hdr_line = next(
            (c for c in sched._logger.info.call_args_list
             if c.args and "FP_DELTA_HEADER" in str(c.args[0])),
            None,
        )
        assert hdr_line is not None
        assert "doorBitmask=2" in str(hdr_line.args) and "doorBitmask=6" in str(hdr_line.args)


class TestSchedulerStatePruning:
    def _scheduler(self):
        from app.core.ultra_engine import UltraSyncScheduler
        return UltraSyncScheduler(cfg=SimpleNamespace(), logger_inst=MagicMock())

    def test_update_devices_prunes_removed_fp_detail(self):
        sched = self._scheduler()
        sched._last_fp_detail = {1: {"users": {}}, 2: {"users": {}}}
        sched.update_devices([{"id": 2}])
        assert 1 not in sched._last_fp_detail  # removed device pruned
        assert 2 in sched._last_fp_detail       # surviving device kept

    def test_force_resync_clears_fp_detail(self):
        sched = self._scheduler()
        sched._last_hash = {5: "abc"}
        sched._last_fp_detail = {5: {"users": {}}}
        sched.force_resync(5)
        assert 5 not in sched._last_fp_detail
        assert 5 not in sched._last_hash
