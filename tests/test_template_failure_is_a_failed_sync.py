"""A refused fingerprint template is a FAILED sync, on every PullSDK push path (F0 Part A).

THE BUG THIS PINS
-----------------
Template push errors were a `logger.warning` and nothing else. The three PullSDK
paths then recorded the pin as a success:

  * batch Phase C never wrote `pin_outcomes[pin]`, and Phase D derives the stored
    state from exactly that dict (`pin_ok = not pin_error`),
  * the per-pin path branched on `if auth_complete:` alone,
  * the targeted path did `ok=bool(auth_complete)` and never consulted templates
    at all.

So `device_sync_state.last_ok` was 1, `push_pin_history.status` was SUCCESS, and
`device_content_mirror.push_ok` was 1 -- the dashboard showed the member green --
while their finger did not open the door. And because the retry gate re-selects a
pin only when `prev_hash != dh OR not prev_ok`, and a SUCCESS also stores the
hash, the pin was never selected again. The failure was both invisible and
permanent.

The sibling standalone driver already had this right; its comment names the bug
exactly: "A refused template is a failed sync. Reporting ok=True here is what let
a non-working fingerprint be stamped as 'synced' and never retried."

WHAT THIS CHANGE DELIBERATELY DOES *NOT* DO
-------------------------------------------
It does not make a refused template land. If the cause is a v9/v10 algorithm
mismatch or a full fingerprint store, the member still cannot use their finger --
the change converts a silent failure into a reported one. Gyms whose terminals
have been quietly refusing templates will see amber the day they upgrade. That is
a discovery, not a regression.

Part B (tests/test_sync_retry_backoff.py) is what keeps the newly-failing pins
from being re-pushed on every cycle forever. Part A must never ship without it.
"""
from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest


def make_engine(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    from app.core.device_sync import DeviceSyncEngine
    return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test")), db_module


def make_device(dev_id=1):
    return {
        "id": dev_id, "name": "TestDevice", "ipAddress": "10.0.0.1", "portNumber": 4370,
        "password": "", "active": True, "accessDevice": True,
        "accessDataMode": "DEVICE", "fingerprintEnabled": True,
        "authorizeTimezoneId": 1, "doorIds": [15], "doorPresets": [],
        "pushingToDevicePolicy": "ALL",
    }


def make_user(am_id, with_finger=True):
    return {
        "activeMembershipId": am_id, "userId": am_id + 1000,
        "membershipId": am_id, "fullName": f"User {am_id}",
        "phone": "0600000000", "email": f"u{am_id}@example.com",
        "validFrom": "2026-01-01", "validTo": "2026-12-31",
        "firstCardId": str(am_id * 100), "secondCardId": None,
        "image": None, "faceId": None, "accountUsernameId": None,
        "qrCodePayload": None, "birthday": None, "imageSource": None,
        "userImageStatus": None,
        "fingerprints": ([{"fingerId": 6, "templateVersion": 10,
                           "templateSize": 512, "templateData": "QUJD",
                           "enabled": True}] if with_finger else []),
    }


def _patch_sdk():
    sdk_cls = MagicMock()
    inst = MagicMock()
    sdk_cls.return_value = inst
    inst.get_all_device_data.return_value = []
    inst.get_device_data_rows.return_value = []
    inst.supports_delete_device_data.return_value = True
    inst.set_device_data.return_value = None
    inst.delete_device_data.return_value = None
    inst.__enter__ = lambda s: s
    inst.__exit__ = MagicMock(return_value=False)
    return sdk_cls, inst


def _state(db_module, device_id, pin):
    return db_module.list_device_sync_retry_state(device_id=device_id).get(pin)


# ---------------------------------------------------------------------------
# _sync_one_device (batch Phase C / per-pin path)
# ---------------------------------------------------------------------------

class TestSyncOneDevice:
    def test_a_refused_template_marks_the_pin_failed(self, tmp_path, monkeypatch):
        svc, db_module = make_engine(tmp_path, monkeypatch)
        sdk_cls, _inst = _patch_sdk()

        # every finger refused, as a v9/v10 mismatch does
        monkeypatch.setattr(svc, "_push_templates",
                            lambda *a, **k: (0, ["FingerID=6: no compatible schema"]))

        with patch("app.core.device_sync.PullSDK", sdk_cls):
            svc._sync_one_device(device=make_device(), users=[make_user(1)],
                                 local_fp_index={}, default_door_id=15, changed_ids=None)

        st = _state(db_module, 1, "1")
        assert st is not None, "a state row must exist"
        _h, ok, streak, _attempt, _seen = st
        assert ok is False, "a refused template must NOT be recorded as a successful sync"
        assert streak == 1, "and it must count toward the bounded-retry streak"

    def test_a_successful_template_still_marks_the_pin_ok(self, tmp_path, monkeypatch):
        """The control. Without this, 'always fail' would also pass the test above."""
        svc, db_module = make_engine(tmp_path, monkeypatch)
        sdk_cls, _inst = _patch_sdk()

        monkeypatch.setattr(svc, "_push_templates", lambda *a, **k: (1, []))

        with patch("app.core.device_sync.PullSDK", sdk_cls):
            svc._sync_one_device(device=make_device(), users=[make_user(1)],
                                 local_fp_index={}, default_door_id=15, changed_ids=None)

        _h, ok, streak, _attempt, _seen = _state(db_module, 1, "1")
        assert ok is True
        assert streak == 0

    def test_a_member_with_no_fingerprints_is_unaffected(self, tmp_path, monkeypatch):
        """Most members have no template; their path must not change at all."""
        svc, db_module = make_engine(tmp_path, monkeypatch)
        sdk_cls, _inst = _patch_sdk()

        monkeypatch.setattr(svc, "_push_templates",
                            lambda *a, **k: (0, ["should never be called"]))

        with patch("app.core.device_sync.PullSDK", sdk_cls):
            svc._sync_one_device(device=make_device(), users=[make_user(1, with_finger=False)],
                                 local_fp_index={}, default_door_id=15, changed_ids=None)

        _h, ok, _streak, _attempt, _seen = _state(db_module, 1, "1")
        assert ok is True

    def test_the_failed_pin_is_re_selected_on_the_next_run(self, tmp_path, monkeypatch):
        """Part A + Part B together: the failure is retried (inside the free
        attempts), which is the whole point -- it was previously never retried."""
        svc, db_module = make_engine(tmp_path, monkeypatch)
        sdk_cls, inst = _patch_sdk()

        monkeypatch.setattr(svc, "_push_templates", lambda *a, **k: (0, ["refused"]))

        with patch("app.core.device_sync.PullSDK", sdk_cls):
            svc._sync_one_device(device=make_device(), users=[make_user(1)],
                                 local_fp_index={}, default_door_id=15, changed_ids=None)
            first = inst.set_device_data.call_count
            inst.set_device_data.reset_mock()
            svc._sync_one_device(device=make_device(), users=[make_user(1)],
                                 local_fp_index={}, default_door_id=15, changed_ids=None)
            second = inst.set_device_data.call_count

        assert first > 0
        assert second > 0, "a failed pin must be retried, not silently abandoned"
        assert _state(db_module, 1, "1")[2] == 2, "and the streak must keep counting"


# ---------------------------------------------------------------------------
# _push_pin_to_connected_sdk (targeted single-member path)
# ---------------------------------------------------------------------------

class TestTargetedMemberPush:
    def _call(self, svc, templates):
        return svc._push_pin_to_connected_sdk(
            sdk=MagicMock(), device_id=7, device_name="D", pin="700",
            user={"fullName": "Jane", "firstCardId": "123"},
            desired_hash="H", door_ids=[15], door_bitmask=1,
            authorize_timezone_id=1, templates=templates,
        )

    def test_returns_false_when_a_template_is_refused(self, tmp_path, monkeypatch):
        svc, db_module = make_engine(tmp_path, monkeypatch)
        monkeypatch.setattr(svc, "_push_templates", lambda *a, **k: (0, ["refused"]))
        monkeypatch.setattr(svc, "_delete_pin_unconditional", lambda **k: None)

        got = self._call(svc, [{"fingerId": 6, "templateVersion": 10,
                                "templateSize": 512, "templateData": "QUJD"}])

        assert got is False, "this path ignored templates entirely and returned True"
        _h, ok, _s, _a, _t = _state(db_module, 7, "700")
        assert ok is False

    def test_returns_true_when_templates_land(self, tmp_path, monkeypatch):
        svc, db_module = make_engine(tmp_path, monkeypatch)
        monkeypatch.setattr(svc, "_push_templates", lambda *a, **k: (1, []))
        monkeypatch.setattr(svc, "_delete_pin_unconditional", lambda **k: None)

        got = self._call(svc, [{"fingerId": 6, "templateVersion": 10,
                                "templateSize": 512, "templateData": "QUJD"}])

        assert got is True
        _h, ok, _s, _a, _t = _state(db_module, 7, "700")
        assert ok is True
