"""Every site that turns a MEMBERSHIP id into a device pin -- or a pin back into a member --
goes through the device's pinScheme.

THE FAILURE THESE PIN
---------------------
Sync requests, delta hints, fast-patch impacts and revocations all name MEMBERSHIPS
(activeMembershipId). Under pinScheme=ACCOUNT the device row is keyed by the PERSON
(mainAccountId). On the 2026-09-12 production data 110 main_account.id values equal an existing
active_membership.id and 99 of those are a DIFFERENT person. So a site that keeps using the
membership number as a pin does not merely miss: it names a stranger's device user.

The members below are that collision: Ali's main_account.id is 5 and Sonia's
active_membership.id is 5.

  * targeted PullSDK member sync for Sonia (membership 5) used `pin = 5`, missed Ali's
    account-keyed roster entry and DELETED device user 5 -- Ali;
  * the standalone revoke of Sonia's membership used `pin = str(5)` and removed Ali;
  * revoking one of Ali's two memberships would have removed his pin although his other plan
    still admits him; it must re-push the collapsed row, and remove only when nothing is left;
  * an ACCOUNT roster with rows lacking mainAccountId must never drive a removal;
  * a fingerprint scan reporting pin 5 on an ACCOUNT terminal is Ali, not Sonia.
"""
from __future__ import annotations

import logging
import re
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

import app.core.db as dbmod
import app.core.ultra_engine as ue
from tests.test_standalone_finger_removal_state import FingerState, fstate  # noqa: F401
from tests.test_standalone_incremental_sync import _tpl, _worker
from tests.test_standalone_revoked_pin_removal import RevokeDriver


# ── people ─────────────────────────────────────────────────────────────────────────────

def _member(am, user_id, account, name, *, card, membership_id=7, fps=None, valid_to="2026-12-31T00:00:00"):
    return {
        "activeMembershipId": am, "userId": user_id, "mainAccountId": account,
        "membershipId": membership_id, "fullName": name, "phone": None, "email": None,
        "validFrom": "2026-01-01T00:00:00", "validTo": valid_to,
        "firstCardId": card, "secondCardId": None, "image": None,
        "fingerprints": list(fps or []), "faceId": None, "accountUsernameId": None,
        "qrCodePayload": None, "birthday": None, "imageSource": None,
        "userImageStatus": None, "userProfileImage": None,
    }


def _ali_gym(**kw):
    return _member(31000, 900, 5, "Ali", card="1900", fps=[_tpl(1, "AAAA")], **kw)


def _ali_spa(**kw):
    return _member(31001, 900, 5, "Ali", card="1900", fps=[_tpl(2, "BBBB")],
                   valid_to="2026-10-01T00:00:00", **kw)


def _sonia(**kw):
    return _member(5, 901, 777, "Sonia", card="1901", **kw)


def _nadia_unfilled(**kw):
    """A deliverable row still carrying no mainAccountId (the upgrade trap)."""
    return _member(50, 950, None, "Nadia", card="1950", **kw)


_PIN = re.compile(r"Pin=(\d+)")


def _pins_in(calls) -> List[str]:
    out: List[str] = []
    for c in calls:
        out.extend(_PIN.findall(str(c)))
    return out


# ═════════════════════════════ PullSDK: real SQLite, mock SDK ═════════════════════════════

@pytest.fixture
def sqlite_db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "sites.db"), raising=False)
    dbmod.init_db()
    yield dbmod
    if hasattr(dbmod, "_shutdown_db_writer_for_tests"):
        dbmod._shutdown_db_writer_for_tests()


_MEMBERS = {"members": True, "devices": False, "credentials": False, "settings": False}


def _cache(db, users, *, valid_ids=None):
    ids = [u["activeMembershipId"] for u in users] if valid_ids is None else valid_ids
    db.save_sync_cache_delta(
        {"users": users, "membersDeltaMode": True, "validMemberIds": ids}, _MEMBERS,
    )


def _pullsdk_device(**kw):
    d = {"id": 1, "name": "Panel", "ipAddress": "10.0.0.1", "portNumber": 4370, "password": "",
         "active": True, "accessDevice": True, "accessDataMode": "ULTRA",
         "fingerprintEnabled": False, "authorizeTimezoneId": 1, "doorIds": [1],
         "doorPresets": [], "pushingToDevicePolicy": "ALL"}
    d.update(kw)
    return d


def _engine():
    from app.core.device_sync import DeviceSyncEngine

    return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test.sites"))


def _sdk(device_pins=()):
    sdk = MagicMock()
    rows = [{"Pin": p} for p in device_pins]
    sdk.get_device_data_rows.return_value = rows
    sdk.get_all_device_data.return_value = rows
    sdk.supports_delete_device_data.return_value = True
    return sdk


def _deleted_pins(sdk) -> List[str]:
    return _pins_in([c for c in sdk.mock_calls if "delete" in c[0]])


def _written_pins(sdk) -> List[str]:
    return _pins_in([c for c in sdk.mock_calls if "set_device_data" in c[0]])


def _removed_pins(sdk) -> set:
    """Pins deleted and NOT written back. A push clears a pin's authorize/template rows
    before re-writing them, so a bare delete call is not a removal."""
    return set(_deleted_pins(sdk)) - set(_written_pins(sdk))


class TestTargetedPullSdkMemberSync:

    def test_account_sync_of_sonias_membership_5_never_touches_ali_who_is_pin_5(self, sqlite_db):
        _cache(sqlite_db, [_ali_gym(), _sonia()])
        sdk = _sdk()

        _engine().sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(pinScheme="ACCOUNT"), member_id=5)

        assert "777" in _written_pins(sdk), "Sonia is pushed under HER account pin"
        assert "5" not in _written_pins(sdk) + _deleted_pins(sdk), (
            "membership id 5 is Ali's account pin on this terminal: it must not be written or "
            "deleted on Sonia's behalf"
        )

    def test_membership_device_is_unchanged(self, sqlite_db):
        _cache(sqlite_db, [_ali_gym(), _sonia()])
        sdk = _sdk()

        _engine().sync_member_on_connected_sdk(sdk=sdk, device=_pullsdk_device(), member_id=5)

        assert set(_written_pins(sdk)) == {"5"}
        assert _removed_pins(sdk) == set()

    def test_account_revoke_deletes_the_persons_pin_not_the_membership_number(self, sqlite_db):
        _cache(sqlite_db, [_ali_gym(), _sonia()])
        _cache(sqlite_db, [], valid_ids=[31000])          # Sonia's membership revoked
        assert sqlite_db.list_sync_users_by_active_membership_ids([5]) == []
        sdk = _sdk()

        _engine().sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(pinScheme="ACCOUNT"), member_id=5)

        assert _removed_pins(sdk) == {"777"}
        assert "5" not in _written_pins(sdk) + _deleted_pins(sdk)

    def test_a_person_with_two_memberships_is_pushed_as_one_collapsed_row(self, sqlite_db):
        _cache(sqlite_db, [_ali_gym(), _ali_spa(), _sonia()])
        sdk = _sdk()

        _engine().sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(pinScheme="ACCOUNT"), member_id=31001)

        assert set(_written_pins(sdk)) == {"5"}
        assert _removed_pins(sdk) == set()
        assert sqlite_db.get_device_sync_hash_for_pin(device_id=1, pin="5")[0], "state keyed by the person"

    def test_an_unmappable_membership_is_neither_pushed_nor_deleted(self, sqlite_db):
        _cache(sqlite_db, [_ali_gym()])
        sdk = _sdk()

        assert _engine().sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(pinScheme="ACCOUNT"), member_id=424242) is False
        assert _written_pins(sdk) == [] and _deleted_pins(sdk) == []

    def test_no_delete_while_a_deliverable_row_has_no_main_account_id(self, sqlite_db):
        _cache(sqlite_db, [_sonia(), _nadia_unfilled()])
        _cache(sqlite_db, [], valid_ids=[50])             # Sonia revoked, Nadia unfilled
        sdk = _sdk()

        _engine().sync_member_on_connected_sdk(
            sdk=sdk, device=_pullsdk_device(pinScheme="ACCOUNT"), member_id=5)

        assert _deleted_pins(sdk) == []


class TestFullPullSdkSync:

    def _run(self, sqlite_db, users, device, device_pins):
        sdk = _sdk(device_pins)
        with patch("app.core.device_sync.PullSDK", MagicMock(return_value=sdk)):
            _engine()._sync_one_device(device=device, users=users, local_fp_index={},
                                       default_door_id=1, changed_ids=None)
        return sdk

    def test_account_stale_pins_are_account_pins_and_old_membership_pins_are_untouched(self, sqlite_db):
        karim = _member(40, 902, 888, "Karim", card="1902", membership_id=99)   # not accepted
        users = [_ali_gym(), _sonia(), karim]

        sdk = self._run(sqlite_db, users, _pullsdk_device(pinScheme="ACCOUNT", allowedMemberships=[7]),
                        device_pins=["5", "777", "888", "31000"])

        assert _removed_pins(sdk) == {"888"}, (
            "Karim left this door: his ACCOUNT pin is stale. 31000 is an old membership pin "
            "Access does not track under ACCOUNT, so it is not touched"
        )

    def test_membership_stale_pins_are_unchanged(self, sqlite_db):
        karim = _member(40, 902, 888, "Karim", card="1902", membership_id=99)
        sdk = self._run(sqlite_db, [_ali_gym(), _sonia(), karim],
                        _pullsdk_device(allowedMemberships=[7]),
                        device_pins=["31000", "5", "40", "888"])
        assert _removed_pins(sdk) == {"40"}

    def test_an_incomplete_account_roster_removes_and_prunes_nothing(self, sqlite_db):
        sqlite_db.save_device_sync_state(device_id=1, pin="888", desired_hash="h", ok=True, error=None)
        users = [_ali_gym(), _sonia(), _nadia_unfilled()]

        sdk = self._run(sqlite_db, users, _pullsdk_device(pinScheme="ACCOUNT"),
                        device_pins=["5", "777", "888"])

        assert _removed_pins(sdk) == set()
        assert "888" not in _deleted_pins(sdk)
        assert "888" in sqlite_db.list_device_sync_pins(device_id=1), (
            "pruning would forget a pin that may belong to the withheld member"
        )

    def test_a_queued_offline_creation_does_not_freeze_removals(self, sqlite_db):
        """Review #12. load_sync_cache().users always carries a synthetic row for each queued
        offline creation; it never has mainAccountId and no roster refresh can give it one
        (it is not a sync_users row). Counted as withheld, it made every ACCOUNT roster
        'incomplete' for as long as the item stayed queued (blocked_auth waits on an
        operator), so a departed member's pin stayed on the terminal."""
        ali = {**_ali_gym(), "accountUsernameId": "ali"}
        _cache(sqlite_db, [ali, _sonia()])
        sqlite_db.insert_offline_creation(
            creation_kind="membership_only", state="failed_retryable",
            payload={"accountUsernameId": "ali", "membershipId": 8,
                     "startDate": "2026-09-01", "endDate": "2026-12-31"},
        )
        sqlite_db.save_device_sync_state(device_id=1, pin="888", desired_hash="h", ok=True, error=None)
        users = list(sqlite_db.load_sync_cache().users)
        assert any(u.get("offlinePending") for u in users), "the projection is in the roster"

        device = _pullsdk_device(pinScheme="ACCOUNT")
        stats: Dict[str, Any] = {}
        by_pin = _engine()._filter_users_for_device(
            users=users, device=dict(device), default_door_id=1, stats_out=stats)
        assert stats["withheld_missing_account"] == 0
        assert set(by_pin) == {"5", "777"}, "the projection is never emitted, under any pin"

        sdk = self._run(sqlite_db, users, device, device_pins=["5", "777", "888"])
        assert _removed_pins(sdk) == {"888"}, "Karim departed: his account pin is removed"


# ═════════════════════════════ ZK_STANDALONE worker ═════════════════════════════

class _People:
    """The four sync_users readers the worker uses, over an in-memory roster + durable link."""

    def __init__(self, monkeypatch, users):
        self.users = list(users)
        self.links = {int(u["activeMembershipId"]): int(u["mainAccountId"])
                      for u in users if u.get("mainAccountId") is not None}
        monkeypatch.setattr(dbmod, "list_sync_users_by_active_membership_ids", self.by_am, raising=False)
        monkeypatch.setattr(dbmod, "list_sync_users_by_main_account_ids", self.by_account, raising=False)
        monkeypatch.setattr(dbmod, "get_main_account_ids_for_memberships", self.link, raising=False)
        monkeypatch.setattr(dbmod, "list_sync_users_missing_main_account", self.missing, raising=False)

    def by_am(self, ids):
        wanted = {int(i) for i in ids}
        return [dict(u) for u in self.users if int(u["activeMembershipId"]) in wanted]

    def by_account(self, ids):
        wanted = {int(i) for i in ids}
        return [dict(u) for u in self.users
                if u.get("mainAccountId") is not None and int(u["mainAccountId"]) in wanted]

    def link(self, ids):
        return {int(i): self.links[int(i)] for i in ids if int(i) in self.links}

    def missing(self):
        return [dict(u) for u in self.users if u.get("mainAccountId") is None]

    def revoke(self, am):
        self.users = [u for u in self.users if int(u["activeMembershipId"]) != am]


def _account_worker(monkeypatch, *, users, driver=None):
    w, cache = _worker(monkeypatch, driver=driver or RevokeDriver(), users=users)
    w._device = {"id": 9, "name": "Entree 1", "pinScheme": "ACCOUNT"}
    w.request_full_sync = MagicMock(return_value=True)
    return w, cache


class TestStandaloneTargetedSites:

    def test_member_sync_pushes_the_persons_collapsed_row(self, monkeypatch, fstate):
        people = _People(monkeypatch, [_ali_gym(), _ali_spa(), _sonia()])
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=people.users, driver=drv)

        w._run_standalone_member_sync(31001)

        [call] = drv.push_calls
        assert [u["pin"] for u in call["users"]] == ["5"]
        assert sorted(t["fingerId"] for t in call["templates"]["5"]) == [1, 2], (
            "the gym plan's finger must not vanish because the spa plan changed"
        )

    def test_revoking_one_of_two_memberships_repushes_and_keeps_the_pin(self, monkeypatch, fstate):
        people = _People(monkeypatch, [_ali_gym(), _ali_spa()])
        fstate.rows["5"] = ("old", True, {1, 2})
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=people.users, driver=drv)
        people.revoke(31001)

        assert w._run_standalone_member_revoke(31001) is True

        assert drv.delete_calls == [], "Ali still holds the gym plan this device accepts"
        [call] = drv.push_calls
        assert [u["pin"] for u in call["users"]] == ["5"]
        assert [t["fingerId"] for t in call["templates"]["5"]] == [1]
        assert call["removals"] == {"5": [2]}, "the spa plan's finger is cleared off the terminal"
        assert "5" in fstate.rows
        w.request_full_sync.assert_not_called()

    def test_revoking_the_last_membership_removes_the_account_pin(self, monkeypatch, fstate):
        people = _People(monkeypatch, [_ali_gym(), _ali_spa()])
        fstate.rows["5"] = ("old", True, {1, 2})
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=people.users, driver=drv)
        people.revoke(31000)
        people.revoke(31001)

        assert w._run_standalone_member_revoke(31001) is True

        assert drv.delete_calls == [["5"]]
        assert "5" not in fstate.rows

    def test_revoking_sonias_membership_5_removes_sonia_not_ali(self, monkeypatch, fstate):
        people = _People(monkeypatch, [_ali_gym(), _sonia()])
        fstate.rows["5"] = ("ali", True, {1})
        fstate.rows["777"] = ("sonia", True, set())
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=people.users, driver=drv)
        people.revoke(5)

        assert w._run_standalone_member_revoke(5) is True

        assert drv.delete_calls == [["777"]]
        assert "5" in fstate.rows, "Ali's pin 5 must survive Sonia's revocation"

    def test_a_membership_device_still_revokes_by_membership_id(self, monkeypatch, fstate):
        _People(monkeypatch, [_ali_gym()])
        fstate.rows["31000"] = ("h", True, set())
        drv = RevokeDriver()
        w, _c = _worker(monkeypatch, driver=drv, users=[])

        assert w._run_standalone_member_revoke(31000) is True
        assert drv.delete_calls == [["31000"]]

    def test_an_unmappable_revocation_touches_nothing_and_defers(self, monkeypatch, fstate):
        _People(monkeypatch, [_ali_gym()])
        fstate.rows["5"] = ("ali", True, {1})
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=[_ali_gym()], driver=drv)

        assert w._run_standalone_member_revoke(424242) is False

        assert drv.delete_calls == [] and drv.push_calls == []
        assert w.request_full_sync.call_args.kwargs["revoked_ids"] == {424242}

    def test_no_removal_while_a_deliverable_row_has_no_main_account_id(self, monkeypatch, fstate):
        people = _People(monkeypatch, [_sonia(), _nadia_unfilled()])
        fstate.rows["777"] = ("sonia", True, set())
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=people.users, driver=drv)
        people.revoke(5)

        assert w._run_standalone_member_revoke(5) is False

        assert drv.delete_calls == []
        assert "777" in fstate.rows

    def test_a_deferred_member_sync_flags_the_persons_pin(self, monkeypatch, fstate):
        _People(monkeypatch, [_ali_gym(), _sonia()])
        fstate.rows["5"] = ("ali", True, {1})
        fstate.rows["777"] = ("sonia", True, set())
        w, _c = _account_worker(monkeypatch, users=[])

        w._defer_member_sync(5, reason="test")

        assert [row[0] for row in fstate.save_calls[-1]] == ["777"]

    def test_only_member_ids_are_translated_to_person_pins(self, monkeypatch, fstate):
        _People(monkeypatch, [_ali_gym(), _ali_spa(), _sonia()])
        w, _c = _account_worker(monkeypatch, users=[])

        users, _t, _h = w._build_standalone_roster(
            SimpleNamespace(users=[_ali_gym(), _ali_spa(), _sonia()]), only_member_ids={31001})

        assert [u["pin"] for u in users] == ["5"]


class TestStandaloneFullSyncSites:

    def test_a_revoked_membership_whose_person_remains_does_not_fail_the_sync(self, monkeypatch, fstate):
        """Requiring removal of a pin that is still desired would fail every full sync."""
        people = _People(monkeypatch, [_ali_gym(), _ali_spa()])
        fstate.rows["5"] = ("old", True, {1, 2})
        people.revoke(31001)
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=list(people.users), driver=drv)
        del w.request_full_sync                    # the real one, for the drain

        w.request_full_sync(reason="timer", fingerprint_hash="h1", revoked_ids={31001})
        assert w._drain_full_sync_commands(limit=1) == 1

        assert w._on_full_sync_finished.call_args.kwargs["ok"] is True
        assert drv.delete_calls == []

    def test_an_incomplete_roster_skips_the_revoke_pass_and_the_prune(self, monkeypatch, fstate):
        _People(monkeypatch, [_ali_gym(), _nadia_unfilled()])
        fstate.rows["5"] = ("old", True, {1})
        fstate.rows["999"] = ("departed?", True, set())
        drv = RevokeDriver()
        w, _c = _account_worker(monkeypatch, users=[_ali_gym(), _nadia_unfilled()], driver=drv)
        del w.request_full_sync
        warn = MagicMock()
        monkeypatch.setattr(ue._tel, "warn", warn)

        w.request_full_sync(reason="timer", fingerprint_hash="h1")
        assert w._drain_full_sync_commands(limit=1) == 1

        assert drv.delete_calls == []
        assert "999" in fstate.rows, "999 may be Nadia; its ownership evidence must survive"
        assert any(c.args and c.args[0] == "REVOKE_SKIP_INCOMPLETE_ROSTER" for c in warn.call_args_list)
        pushed = [u["pin"] for call in drv.push_calls for u in call["users"]]
        assert "50" not in pushed and "950" not in pushed, "never under a membership/user pin"


class TestInboundScanOnTheWorker:

    def _users_by_am(self):
        ali, sonia = _ali_gym(), _sonia()
        return {31000: ali, 5: sonia}

    def test_an_account_terminal_reporting_pin_5_is_ali(self, monkeypatch):
        w, _c = _account_worker(monkeypatch, users=[])
        assert w._user_for_device_pin("5", self._users_by_am())["fullName"] == "Ali"
        assert w._user_for_device_pin("777", self._users_by_am())["fullName"] == "Sonia"

    def test_a_membership_terminal_reporting_pin_5_is_sonia(self, monkeypatch):
        w, _c = _worker(monkeypatch, users=[])
        assert w._user_for_device_pin("5", self._users_by_am())["fullName"] == "Sonia"


# ═════════════════════════════ ZK_STANDALONE driver: pin -> card ═════════════════════════════

def test_the_standalone_pin_card_map_follows_the_devices_scheme(sqlite_db, monkeypatch):
    sqlite_db.save_sync_cache_delta(
        {"users": [_ali_gym(), _sonia()], "membersDeltaMode": True, "validMemberIds": [31000, 5],
         "devices": [
             {"id": 8, "name": "Sortie", "accessDataMode": "ULTRA", "deviceProtocol": "ZK_STANDALONE",
              "pinScheme": "ACCOUNT"},
             {"id": 10, "name": "Entree", "accessDataMode": "ULTRA", "deviceProtocol": "ZK_STANDALONE"},
         ]},
        {"members": True, "devices": True, "credentials": False, "settings": False},
    )
    from app.sdk import zk_standalone as zks

    warn = MagicMock()
    monkeypatch.setattr(zks._tel, "warn", warn)

    account = zks.ZKStandaloneDevice({"id": 8, "name": "Sortie", "deviceProtocol": "ZK_STANDALONE"},
                                     logger=MagicMock())
    account._refresh_pin_card_map()
    assert account._pin_card_snapshot() == {"5": "1900", "777": "1901"}

    membership = zks.ZKStandaloneDevice({"id": 10, "name": "Entree", "deviceProtocol": "ZK_STANDALONE"},
                                        logger=MagicMock())
    membership._refresh_pin_card_map()
    assert membership._pin_card_snapshot() == {"31000": "1900", "5": "1901"}

    account._on_att_event("5", 0, 0, 1, 2026, 9, 12, 10, 0, 0)
    evt = account._evt_queue.get_nowait()
    assert evt["cardNo"] == "1900", "a scan of pin 5 on the ACCOUNT terminal carries Ali's card"
    assert not any(c.args and c.args[0] == "ZKEM_PIN_UNMAPPED" for c in warn.call_args_list)
