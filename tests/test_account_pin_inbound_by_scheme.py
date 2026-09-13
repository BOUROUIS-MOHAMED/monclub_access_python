"""A door event's pin is read under the scheme its DEVICE ran when the event happened.

WHY
---
A terminal reports "pin 5". On the 2026-09-12 production data 110 main_account.id values equal
an existing active_membership.id, 99 of them a different person, so pin 5 is Ali's ACCOUNT pin
and Sonia's MEMBERSHIP pin at the same time. Nothing in the event says which. What does say is
the device: it runs one scheme at a time, and every change is recorded with its time
(device_pin_scheme_switch). So:

  * an event on a device that switched to ACCOUNT at 10:00, stamped 11:00 -> Ali;
  * the same pin on the same device stamped 09:00 -> Sonia;
  * a device that never switched -> MEMBERSHIP, always -> Sonia;
  * only when the scheme cannot be known (switched device, unparseable time) does the old
    "unambiguous, else prefer membership" rule apply.

The upload must also stop posting an unresolvable ACCOUNT pin as ``activeMembership`` -- the
backend would file it against the person holding that membership id.
"""
from __future__ import annotations

import dataclasses
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.core.device_attendance import DeviceAttendanceMaintenanceEngine, HistoryPinResolver
from tests.test_access_history_sync import _make_row


def _member(am, user_id, account, name, membership_id=7, valid_to="2026-12-31T00:00:00"):
    return {"activeMembershipId": am, "userId": user_id, "mainAccountId": account,
            "membershipId": membership_id, "fullName": name, "validTo": valid_to,
            "firstCardId": f"{1000 + user_id}", "fingerprints": []}


ALI_GYM = _member(31000, 900, 5, "Ali", membership_id=7)
ALI_SPA = _member(31001, 900, 5, "Ali", membership_id=8, valid_to="2027-06-30T00:00:00")
SONIA = _member(5, 901, 777, "Sonia", membership_id=7)
USERS = [ALI_GYM, ALI_SPA, SONIA]

DEVICES = {
    8: {"id": 8, "name": "Sortie", "allowedMemberships": [7], "pinScheme": "ACCOUNT"},
    3: {"id": 3, "name": "Entree"},
}
SWITCHES = {8: [{"previous_scheme": "MEMBERSHIP", "scheme": "ACCOUNT",
                 "switched_at": "2026-09-12 10:00:00"}]}


def _row(device_id, event_time, pin, card=""):
    return dataclasses.replace(
        _make_row(), device_id=device_id, event_time=event_time, card_no=card,
        raw_json=json.dumps({"pin": str(pin)}),
    )


def _resolver():
    return HistoryPinResolver(users=USERS, devices_by_id=DEVICES, switches_by_device=SWITCHES)


def _resolve(row):
    return _resolver().resolve(row, json.loads(row.raw_json))


class TestResolution:

    def test_after_the_switch_pin_5_is_ali(self):
        user, scheme = _resolve(_row(8, "2026-09-12 11:00:00", 5))
        assert scheme == "ACCOUNT"
        assert user["fullName"] == "Ali"

    def test_before_the_switch_pin_5_is_sonia(self):
        user, scheme = _resolve(_row(8, "2026-09-12 09:00:00", 5))
        assert scheme == "MEMBERSHIP"
        assert user["fullName"] == "Sonia"

    def test_a_device_that_never_switched_is_membership_at_any_time(self):
        for when in ("2026-09-12 09:00:00", "2026-09-12 11:00:00", "garbage"):
            user, scheme = _resolve(_row(3, when, 5))
            assert (scheme, user["fullName"]) == ("MEMBERSHIP", "Sonia")

    def test_the_account_index_applies_the_devices_filters_like_the_push(self):
        """Device 8 accepts only plan 7. Ali's spa plan (8) reaches further, but the device row
        represents his gym plan -- so must the event."""
        user, _ = _resolve(_row(8, "2026-09-12 11:00:00", 5))
        assert user["activeMembershipId"] == 31000

    def test_an_unknown_scheme_falls_back_to_the_membership_preference(self):
        user, scheme = _resolve(_row(8, "not-a-time", 5))
        assert scheme is None
        assert user["fullName"] == "Sonia"

    def test_a_known_scheme_never_consults_the_other_index(self):
        """Pin 31000 is Ali's membership id, not anyone's account id: on an ACCOUNT device it
        names nobody."""
        user, scheme = _resolve(_row(8, "2026-09-12 11:00:00", 31000))
        assert scheme == "ACCOUNT" and user is None


def test_an_account_window_event_on_a_device_switched_back_is_still_ali():
    """Review #20. account_index_for forces the ACCOUNT reading for an event from an ACCOUNT
    window even when the device has since switched back to MEMBERSHIP; without it the index is
    keyed by membership id and pin 5 names Sonia."""
    devices = {8: {"id": 8, "name": "Sortie", "allowedMemberships": [7], "pinScheme": "MEMBERSHIP"}}
    switches = {8: [
        {"previous_scheme": "MEMBERSHIP", "scheme": "ACCOUNT", "switched_at": "2026-09-12 10:00:00"},
        {"previous_scheme": "ACCOUNT", "scheme": "MEMBERSHIP", "switched_at": "2026-09-20 18:30:00"},
    ]}
    resolver = HistoryPinResolver(users=USERS, devices_by_id=devices, switches_by_device=switches)

    in_window = _row(8, "2026-09-15 08:00:00", 5)
    user, scheme = resolver.resolve(in_window, json.loads(in_window.raw_json))
    assert scheme == "ACCOUNT"
    assert user is not None and user["fullName"] == "Ali" and user["activeMembershipId"] == 31000

    after = _row(8, "2026-09-21 08:00:00", 5)
    user, scheme = resolver.resolve(after, json.loads(after.raw_json))
    assert (scheme, user["fullName"]) == ("MEMBERSHIP", "Sonia")


class TestUploadItems:

    def _item(self, row):
        engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
        r = _resolver()
        return engine._serialize_row_for_backend(
            row=row, users_by_am=r.users_by_am, users_by_card=r.users_by_card,
            devices_by_id=DEVICES, users_by_account=r.users_by_account, resolver=r,
        )

    def test_a_resolved_account_event_is_filed_against_the_person(self):
        item = self._item(_row(8, "2026-09-12 11:00:00", 5))
        assert item["userId"] == 900
        assert item["activeMembershipId"] == 31000

    def test_a_pre_switch_event_on_the_same_pin_is_sonia(self):
        item = self._item(_row(8, "2026-09-12 09:00:00", 5))
        assert item["userId"] == 901
        assert item["activeMembershipId"] == 5

    def test_an_unresolvable_account_pin_is_sent_as_the_person_never_as_a_membership(self):
        item = self._item(_row(8, "2026-09-12 11:00:00", 424242))
        assert item["mainAccountId"] == 424242
        assert item["activeMembership"] is None
        assert "userId" not in item or item["userId"] is None

    def test_an_unresolvable_membership_pin_is_unchanged(self):
        item = self._item(_row(3, "2026-09-12 11:00:00", 424242))
        assert item["activeMembership"] == 424242
        assert "mainAccountId" not in item

    def test_an_unresolvable_pin_of_unknown_scheme_names_no_one(self):
        item = self._item(_row(8, "not-a-time", 424242))
        assert item["activeMembership"] is None
        assert "mainAccountId" not in item


class TestUploader:

    def _run(self, rows, switches):
        engine = DeviceAttendanceMaintenanceEngine(cfg=SimpleNamespace(), logger=MagicMock())
        api = MagicMock()
        api.sync_access_history.return_value = {"ok": True}
        switch_patch = (
            patch("app.core.device_attendance.list_device_pin_scheme_switches", side_effect=RuntimeError("locked"))
            if switches is RuntimeError else
            patch("app.core.device_attendance.list_device_pin_scheme_switches", return_value=switches)
        )
        with (
            patch("app.core.device_attendance.build_access_api_endpoints", return_value=SimpleNamespace()),
            patch("app.core.device_attendance.list_pending_access_history_for_sync", return_value=rows),
            patch("app.core.device_attendance.list_sync_devices_payload", return_value=list(DEVICES.values())),
            patch("app.core.device_attendance.MonClubApi", return_value=api),
            patch("app.core.device_attendance.mark_access_history_synced", return_value=len(rows)),
            patch("access.store.load_sync_cache", return_value=SimpleNamespace(users=USERS)),
            switch_patch,
        ):
            result = engine._sync_pending_history(token="t", sync_online=True)
        return result, api

    def test_the_upload_reads_each_row_under_its_devices_scheme_at_its_time(self):
        before = dataclasses.replace(_row(8, "2026-09-12 09:00:00", 5), id=1, event_id="before")
        after = dataclasses.replace(_row(8, "2026-09-12 11:00:00", 5), id=2, event_id="after")

        result, api = self._run([before, after], SWITCHES)

        payload = {i["eventId"]: i for i in api.sync_access_history.call_args.kwargs["payload"]}
        assert payload["before"]["userId"] == 901, "09:00 on device 8 was a membership pin: Sonia"
        assert payload["after"]["userId"] == 900, "11:00 on device 8 was an account pin: Ali"
        assert result["uploaded"] == 2

    def test_unreadable_switch_history_uploads_nothing(self):
        result, api = self._run([_row(8, "2026-09-12 11:00:00", 5)], RuntimeError)
        api.sync_access_history.assert_not_called()
        assert result == {"uploaded": 0, "failed": 0}


def test_the_dashboard_feed_uses_the_same_resolution(monkeypatch):
    import access.store as store
    import app.core.db as dbmod
    import app.api.local_access_api_v2 as m

    rows = [
        SimpleNamespace(id=1, event_id="after", created_at="2026-09-12 11:00:00",
                        event_time="2026-09-12 11:00:00", device_id=8, door_id=1, card_no="",
                        event_type="", allowed=1, reason="DEVICE_ALLOWED",
                        raw_json=json.dumps({"pin": "5"}), history_source="ULTRA"),
        SimpleNamespace(id=2, event_id="before", created_at="2026-09-12 09:00:00",
                        event_time="2026-09-12 09:00:00", device_id=8, door_id=1, card_no="",
                        event_type="", allowed=1, reason="DEVICE_ALLOWED",
                        raw_json=json.dumps({"pin": "5"}), history_source="ULTRA"),
    ]
    monkeypatch.setattr(store, "get_recent_access_history", lambda limit=50: rows, raising=False)
    monkeypatch.setattr(store, "load_sync_cache", lambda: SimpleNamespace(users=USERS), raising=False)
    monkeypatch.setattr(store, "list_sync_devices_payload", lambda: list(DEVICES.values()), raising=False)
    monkeypatch.setattr(dbmod, "list_device_pin_scheme_switches", lambda **kw: SWITCHES, raising=False)
    monkeypatch.setattr(dbmod, "get_membership_brief_index_cached", lambda: {}, raising=False)
    monkeypatch.setattr(m, "_dash_today", lambda: {})
    m._dash_users_cache.update({"at": 0.0, "by_am": {}, "by_card": {}, "devices": {}, "resolver": None})

    sent = {}
    ctx = SimpleNamespace(q_int=lambda *k, default=0: 10,
                          send_json=lambda status, payload: sent.update(status=status, payload=payload))
    m._handle_dashboard_overview(ctx)

    names = {i["eventId"]: i["userFullName"] for i in sent["payload"]["feed"]}
    assert names == {"after": "Ali", "before": "Sonia"}
    m._dash_users_cache.update({"at": 0.0, "by_am": {}, "by_card": {}, "devices": {}, "resolver": None})
