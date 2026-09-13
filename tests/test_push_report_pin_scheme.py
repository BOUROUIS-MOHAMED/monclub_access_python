"""The fingerprint push report names the id the pin actually IS.

WHY
---
``report_fingerprint_push_result`` used to post every pin as ``activeMembershipId``. Under
pinScheme=ACCOUNT the pin is a main_account.id, and on the 2026-09-12 production data 110 of
those equal an existing active_membership.id -- 99 belonging to a DIFFERENT person. The backend
does ``findByActiveMembershipIdAndFingerId(<that number>, fingerId)``, so the report would
write a push error onto a stranger's fingerprint, or clear one.

The report cannot infer the scheme from the digits; the push records which field produced the
pin, and the report sends ``mainAccountId`` for ACCOUNT, ``activeMembershipId`` for MEMBERSHIP,
and nothing for userId-derived pins.
"""
from __future__ import annotations

import logging
import sqlite3
from unittest.mock import MagicMock

import pytest

from tests.test_standalone_incremental_sync import _tpl


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "report.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


def _api():
    from app.api.monclub_api import MonClubApi

    api = MonClubApi.__new__(MonClubApi)
    api.logger = logging.getLogger("test")
    api.endpoints = MagicMock()
    api.endpoints.report_fingerprint_push_result_url = "https://x/reportPushResult"
    api._session = MagicMock()
    api._session.post.return_value = MagicMock(status_code=200)
    return api


def _posted(api):
    return api._session.post.call_args.kwargs["json"]["items"]


class TestPayload:

    def test_account_pins_are_sent_as_main_account_id_and_never_as_membership(self):
        api = _api()
        api.report_fingerprint_push_result(token="T", items=[
            {"pin": "5", "pin_source": "ACCOUNT", "finger_id": 1, "error_message": "refused"},
        ])
        assert _posted(api) == [{"mainAccountId": 5, "fingerId": 1, "error": "refused"}]

    def test_membership_pins_are_sent_as_active_membership_id(self):
        api = _api()
        api.report_fingerprint_push_result(token="T", items=[
            {"pin": "5", "pin_source": "MEMBERSHIP", "finger_id": 1, "error_message": None},
            {"pin": "31000", "finger_id": 2, "error_message": None},        # pre-field item
        ])
        assert _posted(api) == [
            {"activeMembershipId": 5, "fingerId": 1, "error": None},
            {"activeMembershipId": 31000, "fingerId": 2, "error": None},
        ]

    def test_user_id_pins_are_not_reported(self):
        api = _api()
        assert api.report_fingerprint_push_result(token="T", items=[
            {"pin": "900", "pin_source": "USER", "finger_id": 1, "error_message": "x"},
        ]) is True
        api._session.post.assert_not_called()


class TestPendingReports:

    def test_the_same_digits_under_two_schemes_are_two_people(self, db):
        db.upsert_fingerprint_push_status(pin="5", finger_id=1, device_id=8, status="FAILED",
                                          error_message="Ali refused", pin_source="ACCOUNT")
        db.upsert_fingerprint_push_status(pin="5", finger_id=1, device_id=3, status="OK",
                                          error_message=None, pin_source="MEMBERSHIP")

        pending = sorted(db.get_pending_fingerprint_push_reports(), key=lambda p: p["pin_source"])

        assert pending == [
            {"pin": "5", "pin_source": "ACCOUNT", "finger_id": 1, "error_message": "Ali refused"},
            {"pin": "5", "pin_source": "MEMBERSHIP", "finger_id": 1, "error_message": None},
        ], "Sonia's OK on device 3 must not be averaged with Ali's refusal on device 8"

        db.mark_fingerprint_push_reported(pending)
        assert db.get_pending_fingerprint_push_reports() == []

    def test_a_row_written_before_the_column_reads_as_membership(self, db):
        with db.get_conn() as conn:
            conn.execute(
                "INSERT INTO fingerprint_push_status (pin, finger_id, device_id, status, "
                "error_message, updated_at) VALUES ('31000', 6, 1, 'FAILED', 'old', '2026-09-01 10:00:00')"
            )
            conn.commit()
        assert db.get_pending_fingerprint_push_reports() == [
            {"pin": "31000", "pin_source": "MEMBERSHIP", "finger_id": 6, "error_message": "old"}
        ]

    def test_an_already_reported_transition_is_not_re_sent_after_the_upgrade(self, tmp_path, monkeypatch):
        import app.core.db as db_module

        path = tmp_path / "old.db"
        conn = sqlite3.connect(str(path))
        conn.execute("""CREATE TABLE fingerprint_push_status (pin TEXT NOT NULL, finger_id INTEGER NOT NULL,
                        device_id INTEGER NOT NULL, status TEXT NOT NULL, error_message TEXT,
                        updated_at TEXT NOT NULL, PRIMARY KEY (pin, finger_id, device_id))""")
        conn.execute("""CREATE TABLE fingerprint_push_reported (pin TEXT NOT NULL, finger_id INTEGER NOT NULL,
                        last_reported TEXT, reported_at TEXT NOT NULL, PRIMARY KEY (pin, finger_id))""")
        conn.execute("INSERT INTO fingerprint_push_status VALUES ('31000', 6, 1, 'FAILED', 'boom', '2026-09-01 10:00:00')")
        conn.execute("INSERT INTO fingerprint_push_reported VALUES ('31000', 6, 'boom', '2026-09-01 10:00:05')")
        conn.commit()
        conn.close()

        monkeypatch.setattr(db_module, "_DB_PATH", str(path), raising=False)
        db_module.init_db()
        try:
            assert db_module.get_pending_fingerprint_push_reports() == []
            db_module.init_db()          # the copy is one-shot: no duplicate, no error
            assert db_module.get_pending_fingerprint_push_reports() == []
        finally:
            if hasattr(db_module, "_shutdown_db_writer_for_tests"):
                db_module._shutdown_db_writer_for_tests()


class TestThePushRecordsTheScheme:
    """End to end on the production collision: Ali's account id 5 is Sonia's membership 5."""

    def _cache(self, db):
        from tests.test_account_pin_device_sites import _member

        ali = _member(31000, 900, 5, "Ali", card="1900", fps=[_tpl(1, "AAAA")])
        sonia = _member(5, 901, 777, "Sonia", card="1901")
        db.save_sync_cache_delta(
            {"users": [ali, sonia], "membersDeltaMode": True, "validMemberIds": [31000, 5]},
            {"members": True, "devices": False, "credentials": False, "settings": False},
        )

    def _sync(self, scheme):
        from app.core.device_sync import DeviceSyncEngine
        from tests.test_account_pin_device_sites import _pullsdk_device, _sdk

        device = _pullsdk_device(fingerprintEnabled=True)
        if scheme:
            device["pinScheme"] = scheme
        DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("t")).sync_member_on_connected_sdk(
            sdk=_sdk(), device=device, member_id=31000)

    def test_an_account_push_is_reported_as_the_person(self, db):
        self._cache(db)
        self._sync("ACCOUNT")

        pending = db.get_pending_fingerprint_push_reports()
        assert pending == [{"pin": "5", "pin_source": "ACCOUNT", "finger_id": 1, "error_message": None}]

        api = _api()
        api.report_fingerprint_push_result(token="T", items=pending)
        assert _posted(api) == [{"mainAccountId": 5, "fingerId": 1, "error": None}], (
            "activeMembershipId 5 is Sonia -- the report must not name her"
        )

    @pytest.mark.parametrize("extra_people", [0, 6], ids=["per-pin-push", "batch-phase-c"])
    def test_a_full_sync_account_push_is_reported_as_the_person(self, db, extra_people):
        """Review #15. The full sync's _push_templates call sites pass pin_source too; dropping
        it stores NULL, which reads as MEMBERSHIP and reports Ali's finger against Sonia's
        membership 5. More than 5 pins to push takes the batch branch (Phase C templates);
        fewer takes the per-pin branch -- each has its own call site."""
        from app.core.device_sync import DeviceSyncEngine
        from tests.test_account_pin_device_sites import _member, _pullsdk_device, _sdk
        from unittest.mock import patch

        self._cache(db)
        extra = [_member(40000 + i, 1000 + i, 6000 + i, f"P{i}", card=str(2000 + i),
                         fps=[_tpl(1, "CCCC")]) for i in range(extra_people)]
        if extra:
            db.save_sync_cache_delta(
                {"users": extra, "membersDeltaMode": True,
                 "validMemberIds": [31000, 5] + [u["activeMembershipId"] for u in extra]},
                {"members": True, "devices": False, "credentials": False, "settings": False},
            )
        db.invalidate_sync_cache(clear_cached=True)   # the cache is process-wide
        users = list(db.load_sync_cache().users)
        sdk = _sdk()
        with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
            DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("t"))._sync_one_device(
                device=_pullsdk_device(pinScheme="ACCOUNT", fingerprintEnabled=True),
                users=users, local_fp_index={}, default_door_id=1, changed_ids=None)

        pending = {(r["pin"], r["pin_source"]) for r in db.get_pending_fingerprint_push_reports()}
        assert ("5", "ACCOUNT") in pending and ("5", "MEMBERSHIP") not in pending
        assert all(source == "ACCOUNT" for _pin, source in pending)

    def test_a_membership_push_is_reported_as_the_membership(self, db):
        self._cache(db)
        self._sync(None)

        pending = db.get_pending_fingerprint_push_reports()
        assert pending == [{"pin": "31000", "pin_source": "MEMBERSHIP", "finger_id": 1, "error_message": None}]
        api = _api()
        api.report_fingerprint_push_result(token="T", items=pending)
        assert _posted(api) == [{"activeMembershipId": 31000, "fingerId": 1, "error": None}]


class TestTheAdminRawPushRecordsTheDevicesScheme:
    """POST /api/v2/devices/{id}/users/push names the pin directly. Its outcome is recorded
    under the scheme the device runs, so the report names mainAccountId on an ACCOUNT device."""

    @pytest.mark.parametrize("scheme,expected", [("ACCOUNT", "ACCOUNT"), (None, "MEMBERSHIP")])
    def test_recorded_source_follows_the_device(self, db, monkeypatch, scheme, expected):
        from tests.test_admin_push_delegates_to_engine import _run, _tpl as _admin_tpl

        device = {"id": 77, "name": "Panel", "accessDataMode": "DEVICE"}
        if scheme:
            device["pinScheme"] = scheme
        with db.get_conn() as conn:
            db._insert_device_row(conn.cursor(), device)
            conn.commit()

        sent, _sdk = _run(monkeypatch, db, [_admin_tpl()])

        assert sent["payload"]["ok"] is True
        assert db.get_pending_fingerprint_push_reports() == [
            {"pin": "1001", "pin_source": expected, "finger_id": 6, "error_message": None}
        ]

    def test_an_unreadable_device_scheme_is_never_reported_as_a_membership(self, db, monkeypatch):
        """Review #10. If the device row cannot be read, the pin's id space is unknown. A NULL
        pin_source reads back as MEMBERSHIP and posts activeMembershipId=<pin> -- on an
        ACCOUNT device, the person whose membership has that number."""
        from tests.test_admin_push_delegates_to_engine import _run, _tpl as _admin_tpl

        real = db.get_sync_device_payload

        def _unreadable(device_id):
            import traceback
            if any("_handle_device_users_push" in f.name and "device_pin_scheme" in (f.line or "")
                   for f in traceback.extract_stack()):
                raise RuntimeError("database is locked")
            return real(device_id)

        monkeypatch.setattr(db, "get_sync_device_payload", _unreadable)
        sent, _sdk = _run(monkeypatch, db, [_admin_tpl()])

        pending = db.get_pending_fingerprint_push_reports()
        assert [(p["pin"], p["pin_source"]) for p in pending] == [("1001", "UNKNOWN")]
        api = _api()
        assert api.report_fingerprint_push_result(token="T", items=pending) is True
        api._session.post.assert_not_called()
