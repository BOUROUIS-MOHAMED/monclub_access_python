"""A gym must be able to SEE a fingerprint that never reached the door (F11).

WHAT WAS MISSING
----------------
``lastPushError`` was built end to end and never populated. The dashboard renders it
(red when set), the backend entity stores it and every outgoing DTO ships it -- but
the only three ``setLastPushError`` call sites all passed ``null``, and the Access
client never reported a push failure upstream at all. So a member whose fingerprint
was silently refused looked identical to one whose fingerprint worked.

THE TWO INVARIANTS THAT MATTER
------------------------------
1. **Only transitions are reported.** Every backend write bumps
   ``UserFingerprint.updatedAt``, and ``GymAccessController.buildDeltaChangedAmIds``
   selects members via ``findActiveMembershipIdsChangedAfter(...)``. So re-sending an
   unchanged state would put that member back in the next delta poll, re-push, fail
   again, report again -- forever, once per sync tick. The client diffs against what
   it last reported; the backend additionally no-ops an identical write. Two
   independent brakes on the same loop.

2. **Status aggregates ACROSS devices.** A gym has several. ``lastPushError`` is one
   field per finger, so "works on the front door, refused on the gym floor" must
   surface as a problem, not be averaged away.

Recording happens inside ``_push_templates`` because that is the only place ``fid``
is in scope -- ``device_sync_state`` is per-PIN, while this is per-FINGER.
"""
from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    return db_module


class TestPendingReports:
    def test_tables_exist(self, db):
        with db.get_conn() as conn:
            names = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "fingerprint_push_status" in names
        assert "fingerprint_push_reported" in names

    def test_a_failure_becomes_a_pending_report(self, db):
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="FAILED", error_message="no compatible schema")
        pending = db.get_pending_fingerprint_push_reports()
        assert pending == [{"pin": "1001", "pin_source": "MEMBERSHIP", "finger_id": 6,
                            "error_message": "no compatible schema"}]

    def test_reporting_it_clears_the_pending_set(self, db):
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="FAILED", error_message="boom")
        pending = db.get_pending_fingerprint_push_reports()
        db.mark_fingerprint_push_reported(pending)

        assert db.get_pending_fingerprint_push_reports() == [], (
            "an unchanged state must NOT be re-reported: every backend write re-flags "
            "the member in the next delta poll"
        )

    def test_an_unchanged_failure_is_never_re_reported(self, db):
        """The loop-breaker. The same failure recurring every sync tick must produce
        exactly ONE upstream report."""
        for _ in range(5):
            db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                              status="FAILED", error_message="boom")
            pending = db.get_pending_fingerprint_push_reports()
            db.mark_fingerprint_push_reported(pending)

        # first round reported once; the next four found nothing to send
        assert db.get_pending_fingerprint_push_reports() == []

    def test_a_recovery_is_reported_as_a_clear(self, db):
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="FAILED", error_message="boom")
        db.mark_fingerprint_push_reported(db.get_pending_fingerprint_push_reports())

        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="OK", error_message=None)

        assert db.get_pending_fingerprint_push_reports() == [
            {"pin": "1001", "pin_source": "MEMBERSHIP", "finger_id": 6, "error_message": None}
        ], "recovering must clear the dashboard's error, not just stop reporting"

    def test_a_success_on_a_never_reported_finger_is_still_a_transition(self, db):
        """Otherwise a finger that worked from the start would never confirm."""
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="OK", error_message=None)
        assert db.get_pending_fingerprint_push_reports() == [
            {"pin": "1001", "pin_source": "MEMBERSHIP", "finger_id": 6, "error_message": None}
        ]

    def test_failure_on_ANY_device_makes_the_finger_failed(self, db):
        """lastPushError is one field per finger. Working on one door and refused on
        another is still a problem the gym must see."""
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="OK", error_message=None)
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=2,
                                          status="FAILED", error_message="refused by gate 2")

        pending = db.get_pending_fingerprint_push_reports()
        assert len(pending) == 1
        assert pending[0]["error_message"] == "refused by gate 2"

    def test_ok_only_when_every_device_accepted(self, db):
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="OK", error_message=None)
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=2,
                                          status="OK", error_message=None)
        assert db.get_pending_fingerprint_push_reports()[0]["error_message"] is None

    def test_fingers_are_tracked_independently(self, db):
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="FAILED", error_message="boom")
        db.upsert_fingerprint_push_status(pin="1001", finger_id=2, device_id=1,
                                          status="OK", error_message=None)
        pending = {p["finger_id"]: p["error_message"]
                   for p in db.get_pending_fingerprint_push_reports()}
        assert pending == {6: "boom", 2: None}

    def test_pruning_drops_removed_pins(self, db):
        db.upsert_fingerprint_push_status(pin="1001", finger_id=6, device_id=1,
                                          status="FAILED", error_message="boom")
        db.upsert_fingerprint_push_status(pin="2002", finger_id=6, device_id=1,
                                          status="FAILED", error_message="boom")

        db.prune_fingerprint_push_status(device_id=1, keep_pins=["1001"])

        remaining = {p["pin"] for p in db.get_pending_fingerprint_push_reports()}
        assert remaining == {"1001"}, "a revoked member must not be reported forever"


class TestPushTemplatesRecordsOutcome:
    def _engine(self):
        from app.core.device_sync import DeviceSyncEngine
        return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))

    def test_a_successful_push_is_recorded_ok(self, db):
        sdk = MagicMock()
        sdk.set_device_data.return_value = None
        tpl = {"fingerId": 6, "templateVersion": 10, "templateSize": 5, "templateData": "AABB"}

        self._engine()._push_templates(sdk, pin="1001", templates=[tpl], device_id=40)

        assert db.get_pending_fingerprint_push_reports() == [
            {"pin": "1001", "pin_source": "MEMBERSHIP", "finger_id": 6, "error_message": None}
        ]

    def test_a_refused_push_is_recorded_failed(self, db):
        sdk = MagicMock()
        sdk.set_device_data.side_effect = Exception("nope")
        tpl = {"fingerId": 6, "templateVersion": 10, "templateSize": 5, "templateData": "AABB"}

        self._engine()._push_templates(sdk, pin="1001", templates=[tpl], device_id=41)

        pending = db.get_pending_fingerprint_push_reports()
        assert len(pending) == 1
        assert pending[0]["finger_id"] == 6
        assert pending[0]["error_message"] is not None

    def test_recording_never_breaks_the_push(self, db, monkeypatch):
        """Instrumentation on the live worker path must not turn a successful push
        into a failed one."""
        import app.core.device_sync as ds

        def _boom(**kw):
            raise RuntimeError("db is on fire")

        monkeypatch.setattr(ds, "upsert_fingerprint_push_status", _boom)

        sdk = MagicMock()
        sdk.set_device_data.return_value = None
        tpl = {"fingerId": 6, "templateVersion": 10, "templateSize": 5, "templateData": "AABB"}

        ok, errs = self._engine()._push_templates(sdk, pin="1001", templates=[tpl], device_id=42)

        assert ok == 1
        assert errs == []


class TestApiPayload:
    def _api(self, endpoints_url="https://x/api/v1/manager/userFingerprint/reportPushResult"):
        from app.api.monclub_api import MonClubApi
        api = MonClubApi.__new__(MonClubApi)
        api.logger = logging.getLogger("test")
        api.endpoints = MagicMock()
        api.endpoints.report_fingerprint_push_result_url = endpoints_url
        api._session = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        api._session.post.return_value = resp
        return api

    def test_payload_shape(self):
        api = self._api()
        ok = api.report_fingerprint_push_result(token="T", items=[
            {"pin": "1001", "finger_id": 6, "error_message": "boom"},
            {"pin": "2002", "finger_id": 2, "error_message": None},
        ])
        assert ok is True
        body = api._session.post.call_args.kwargs["json"]
        assert body == {"items": [
            {"activeMembershipId": 1001, "fingerId": 6, "error": "boom"},
            {"activeMembershipId": 2002, "fingerId": 2, "error": None},
        ]}

    def test_a_non_numeric_pin_is_dropped_not_sent_as_garbage(self):
        """A member with no activeMembershipId is keyed by userId. They cannot have a
        UserFingerprint row anyway, so there is nothing to report."""
        api = self._api()
        ok = api.report_fingerprint_push_result(token="T", items=[
            {"pin": "not-a-number", "finger_id": 6, "error_message": "boom"},
        ])
        assert ok is True
        api._session.post.assert_not_called()

    def test_no_configured_url_is_a_soft_false(self):
        api = self._api(endpoints_url="")
        assert api.report_fingerprint_push_result(token="T", items=[
            {"pin": "1", "finger_id": 6, "error_message": None}]) is False

    def test_a_network_failure_never_raises(self):
        api = self._api()
        api._session.post.side_effect = Exception("connection reset")
        assert api.report_fingerprint_push_result(token="T", items=[
            {"pin": "1", "finger_id": 6, "error_message": None}]) is False
