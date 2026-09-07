"""Tests for the ZK_STANDALONE (MB2000/zkemkeeper) driver + its engine seams.

Everything here runs WITHOUT COM/hardware: the driver takes an injectable
``_com_factory`` (returns a fake zkemkeeper object) and a no-op COM runtime, so
the STA thread, command funnel, event normalization, push sequences, and the
UltraDeviceWorker sync branches are all exercised with fakes.

The two invariants that must never regress:
  * a ZK_STANDALONE device NEVER reaches DeviceSyncEngine's PullSDK push path
    (run_one_device_on_connected_sdk / sync_member_on_connected_sdk);
  * a queued full/member sync ALWAYS terminates (the old code re-queued forever
    when the raw PullSDK handle was None — the livelock).
"""
from __future__ import annotations

import queue
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from app.sdk.zk_standalone import (
    ZKStandaloneDevice,
    normalize_att_event,
    verify_method_to_scan_mode,
)


# --------------------------------------------------------------------------- #
# Fake zkemkeeper COM object
# --------------------------------------------------------------------------- #

class FakeZkem:
    """Records calls; GetRTLog replays queued punches into the driver's sink."""

    def __init__(self):
        self.calls: List[tuple] = []
        self.pending_punches: List[tuple] = []
        self.sink = None  # set to driver._on_att_event by the test factory
        self.connect_ok = True
        self.unlock_ok = True
        self.setuserinfo_ok = True
        self.settmp_ok = True
        # The real SSR_DelUserTmpExt returns a bool. Modelling it as None hid the
        # fact that the driver discarded the result of every slot clear.
        self.delusertmp_ok = True
        # device-user enumeration (list_device_users / MIRROR)
        self.device_users: List[Dict[str, Any]] = []  # {pin,name,card,enabled}
        self.readall_ok = True
        self._enum_idx = 0
        self._cur_card = ""
        self.raise_on_enum_index = None  # set to an int to raise mid-enumeration
        self.deleted: List[tuple] = []

    def _rec(self, name, *args):
        self.calls.append((name, *args))

    # connection / events
    def SetCommPassword(self, key):
        self._rec("SetCommPassword", key); return True

    def Connect_Net(self, ip, port):
        self._rec("Connect_Net", ip, port); return self.connect_ok

    def RegEvent(self, machine, mask):
        self._rec("RegEvent", machine, mask); return True

    def Disconnect(self):
        self._rec("Disconnect")

    def ReadRTLog(self, machine):
        self._rec("ReadRTLog", machine); return bool(self.pending_punches)

    def GetRTLog(self, machine):
        if not self.pending_punches:
            return False
        punch = self.pending_punches.pop(0)
        if self.sink is not None:
            self.sink(*punch)
        return True

    # door / time
    def ACUnlock(self, machine, delay):
        self._rec("ACUnlock", machine, delay); return self.unlock_ok

    # roster push
    def EnableDevice(self, machine, flag):
        self._rec("EnableDevice", machine, flag); return True

    def SetStrCardNumber(self, card):
        self._rec("SetStrCardNumber", card); return True

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        self._rec("SSR_SetUserInfo", machine, pin, name, pw, priv, enabled)
        return self.setuserinfo_ok

    def SSR_DelUserTmpExt(self, machine, pin, finger_id):
        # Clears ONE finger slot. This is what tools/mb2000_scripts/
        # 5_push_member_to_device.ps1 -- the push sequence proven on the real
        # MB2000 -- uses. SSR_DeleteEnrollData never returns for finger >= 1 on
        # that firmware (12 of 19 field STA wedges had it as the last call).
        self._rec("SSR_DelUserTmpExt", machine, pin, finger_id)
        self.deleted.append((str(pin), int(finger_id)))
        return self.delusertmp_ok

    def SSR_DeleteEnrollData(self, machine, pin, backup):
        # 3-arg SSR_ form (mn, pin, backupNumber). Retained ONLY for the
        # whole-user delete (12), which is script 7's proven usage.
        self._rec("SSR_DeleteEnrollData", machine, pin, backup)
        self.deleted.append((str(pin), int(backup)))
        return True

    def SetUserTmpExStr(self, machine, pin, finger, flag, tmp):
        self._rec("SetUserTmpExStr", machine, pin, finger, flag, tmp)
        return self.settmp_ok

    def RefreshData(self, machine):
        self._rec("RefreshData", machine); return True

    # device-user enumeration (ports script 2)
    def ReadAllUserID(self, machine):
        self._rec("ReadAllUserID", machine)
        self._enum_idx = 0
        return self.readall_ok

    def SSR_GetAllUserInfo(self, machine, *placeholders):
        # win32com "pass placeholders" convention -> returns
        # (ok, pin, name, password, privilege, enabled); ok False ends the table.
        if self.raise_on_enum_index is not None and self._enum_idx == self.raise_on_enum_index:
            raise RuntimeError("simulated mid-enumeration COM error")
        if self._enum_idx >= len(self.device_users):
            return (False, "", "", "", 0, 0)
        u = self.device_users[self._enum_idx]
        self._enum_idx += 1
        self._cur_card = str(u.get("card", ""))
        return (True, str(u["pin"]), str(u.get("name", "")), "", 0,
                1 if u.get("enabled", True) else 0)

    def GetStrCardNumber(self, *placeholders):
        return (True, self._cur_card)


def _make_driver(payload_extra: Dict[str, Any] | None = None,
                 fake: FakeZkem | None = None) -> tuple[ZKStandaloneDevice, FakeZkem]:
    payload = {
        "id": 9, "name": "Entree 1", "ipAddress": "192.168.9.10", "portNumber": 4370,
        "doorPresets": [{"doorNumber": 1, "direction": "IN"}],
    }
    payload.update(payload_extra or {})
    drv = ZKStandaloneDevice(payload, logger=MagicMock())
    zk = fake or FakeZkem()
    zk.sink = drv._on_att_event
    drv._com_factory = lambda: zk
    drv._co_init = lambda: None
    drv._co_uninit = lambda: None
    drv._pump = lambda: None
    # avoid touching the real sqlite DB in unit tests
    drv._refresh_pin_card_map = lambda: None  # type: ignore[method-assign]
    return drv, zk


@pytest.fixture
def driver():
    drv, zk = _make_driver()
    yield drv, zk
    drv.disconnect()


# --------------------------------------------------------------------------- #
# Pure normalization
# --------------------------------------------------------------------------- #

class TestNormalizeAttEvent:
    def test_valid_punch_is_allow_with_mapped_card(self):
        evt = normalize_att_event(
            enroll_number="117", is_invalid=0, att_state=0, verify_method=1,
            y=2026, mo=7, d=8, h=10, mi=30, s=5, seq=3,
            pin_to_card={"117": "8192567"}, direction="IN", device_id=9,
        )
        assert evt["eventType"] == "0"           # ALLOW for _process_event
        assert evt["cardNo"] == "8192567"        # pin -> card identity mapping
        assert evt["eventTime"] == "2026-07-08 10:30:05"
        assert evt["doorId"] == 1
        assert evt["table"] == "zkem"
        assert evt["rawRow"]["direction"] == "IN"
        assert evt["rawRow"]["scan_mode_hint"] == "FINGERPRINT"

    def test_unknown_pin_gets_zkpin_marker(self):
        evt = normalize_att_event(
            enroll_number="424242", is_invalid=0, att_state=0, verify_method=2,
            y=2026, mo=7, d=8, h=10, mi=0, s=0, pin_to_card={},
        )
        assert evt["cardNo"] == "ZKPIN:424242"   # never dropped silently

    def test_invalid_punch_lands_on_deny_branch(self):
        evt = normalize_att_event(
            enroll_number="117", is_invalid=1, att_state=0, verify_method=1,
            y=2026, mo=7, d=8, h=10, mi=0, s=0, pin_to_card={"117": "1"},
        )
        assert evt["eventType"] != "0"           # fail-safe: unknown -> DENY path

    def test_verify_method_both_value_spaces(self):
        assert verify_method_to_scan_mode(1) == "FINGERPRINT"   # normal mode
        assert verify_method_to_scan_mode(2) == "RFID_CARD"     # normal mode card
        assert verify_method_to_scan_mode(3) == "RFID_CARD"     # multi-verify RF
        assert verify_method_to_scan_mode(0) == "PASSWORD"
        assert verify_method_to_scan_mode(99) == "UNKNOWN"
        assert verify_method_to_scan_mode(None) == "UNKNOWN"

    def test_direction_absent_not_stamped(self):
        evt = normalize_att_event(
            enroll_number="117", is_invalid=0, att_state=1, verify_method=1,
            y=2026, mo=7, d=8, h=10, mi=0, s=0, pin_to_card={},
        )
        assert "direction" not in evt["rawRow"]


# --------------------------------------------------------------------------- #
# Driver lifecycle + events through the STA thread
# --------------------------------------------------------------------------- #

def _wait_until(pred, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return False


class TestDriverLifecycle:
    def test_connect_registers_events_and_sets_flag(self, driver):
        drv, zk = driver
        assert drv.connect() is True
        assert drv.is_connected is True
        names = [c[0] for c in zk.calls]
        assert "Connect_Net" in names
        assert "RegEvent" in names

    def test_connect_failure_returns_false(self):
        zk = FakeZkem(); zk.connect_ok = False
        drv, _ = _make_driver(fake=zk)
        try:
            assert drv.connect() is False
            assert drv.is_connected is False
        finally:
            drv.disconnect()

    def test_comm_key_set_before_connect(self):
        drv, zk = _make_driver({"password": "1234"})
        try:
            assert drv.connect() is True
            names = [c[0] for c in zk.calls]
            assert names.index("SetCommPassword") < names.index("Connect_Net")
        finally:
            drv.disconnect()

    def test_disconnect_joins_sta_thread(self, driver):
        drv, zk = driver
        drv.connect()
        t = drv._sta_thread
        drv.disconnect()
        assert t is not None and not t.is_alive()
        assert drv.is_connected is False

    def test_events_flow_to_poll_rtlog_once(self, driver):
        drv, zk = driver
        with drv._pin_map_lock:
            drv._pin_to_card = {"117": "8192567"}
        drv.connect()
        zk.pending_punches.append(("117", 0, 0, 1, 2026, 7, 8, 11, 0, 0, 0))
        assert _wait_until(lambda: drv._evt_queue.qsize() > 0)
        events = drv.poll_rtlog_once()
        assert len(events) == 1
        assert events[0]["cardNo"] == "8192567"
        assert events[0]["eventType"] == "0"
        assert events[0]["rawRow"]["direction"] == "IN"
        # queue drained; second poll is empty and non-blocking
        assert drv.poll_rtlog_once() == []

    def test_open_door_default_on_for_the_family(self, driver, monkeypatch):
        """Operator decision 2026-09-04: ON unless switched off per device or by env.
        Whether the MB2000 relay releases on ACUnlock is still UNVERIFIED (script 12/9)."""
        monkeypatch.delenv("MONCLUB_ZK_STANDALONE_OPEN_DOOR", raising=False)
        drv, zk = driver
        drv.connect()
        assert drv.supports_open_door is True
        assert drv._open_door_source == "default"
        assert drv.open_door(door_id=1, pulse_time_ms=3000) is True
        assert [c for c in zk.calls if c[0] == "ACUnlock"] == [("ACUnlock", 1, 30)]

    def test_open_door_switched_off_per_device_never_touches_com(self, monkeypatch):
        monkeypatch.delenv("MONCLUB_ZK_STANDALONE_OPEN_DOOR", raising=False)
        drv, zk = _make_driver({"openDoorEnabled": False})
        drv.connect()
        try:
            assert drv.supports_open_door is False
            assert drv._open_door_source == "local"
            assert drv.open_door(door_id=1, pulse_time_ms=3000) is False
            assert all(c[0] != "ACUnlock" for c in zk.calls)
        finally:
            drv.disconnect()

    def test_open_door_when_capability_enabled(self, driver):
        drv, zk = driver
        drv.connect()
        drv.supports_open_door = True
        assert drv.open_door(door_id=1, pulse_time_ms=3000) is True
        unlocks = [c for c in zk.calls if c[0] == "ACUnlock"]
        assert unlocks == [("ACUnlock", 1, 30)]  # 3000ms -> 30 deciseconds

    def test_inert_pullsdk_shaped_methods_never_raise(self, driver):
        drv, _ = driver
        assert drv.get_device_param(items="Door1Intertime") is None
        assert drv.set_device_param(items="X=1") == 0
        assert drv.get_table_count(table="user") == 0
        assert drv.delete_table_rows(table="user") == 0
        assert drv.read_transaction_rows() == []

    def test_satisfies_device_driver_protocol(self, driver):
        from app.sdk.device_driver import DeviceDriver
        drv, _ = driver
        assert isinstance(drv, DeviceDriver)


class TestPushRoster:
    def test_push_sequence_card_before_userinfo_and_delete_before_template(self, driver):
        drv, zk = driver
        drv.connect()
        res = drv.push_roster(
            [{"pin": "117", "name": "Bob", "card": "8192567"}],
            {"117": [{"fingerId": 6, "templateVersion": 10,
                      "templateData": "QUJD", "templateSize": 3}]},
        )
        assert res["ok"] is True and res["pushed"] == 1
        names = [c[0] for c in zk.calls]
        assert names.index("SetStrCardNumber") < names.index("SSR_SetUserInfo")
        # The slot is cleared with SSR_DelUserTmpExt, never SSR_DeleteEnrollData:
        # the latter hangs forever on this firmware for finger >= 1.
        assert names.index("SSR_DelUserTmpExt") < names.index("SetUserTmpExStr")
        assert "SSR_DeleteEnrollData" not in names
        tmp_calls = [c for c in zk.calls if c[0] == "SetUserTmpExStr"]
        assert tmp_calls == [("SetUserTmpExStr", 1, "117", 6, 1, "QUJD")]
        # daytime push: NEVER EnableDevice-locks the terminal
        assert all(c[0] != "EnableDevice" for c in zk.calls)

    def test_bracketed_push_enables_around_batch(self, driver):
        drv, zk = driver
        drv.connect()
        drv.push_roster([{"pin": "117", "name": "Bob", "card": "1"}],
                        {}, bracket_enable_device=True)
        enables = [c for c in zk.calls if c[0] == "EnableDevice"]
        assert enables[0] == ("EnableDevice", 1, False)
        assert enables[-1] == ("EnableDevice", 1, True)

    def test_pin_over_9_digits_is_skipped(self, driver):
        drv, zk = driver
        drv.connect()
        res = drv.push_roster(
            [{"pin": "1234567890", "name": "TooLong", "card": "1"},   # 10 digits
             {"pin": "117", "name": "Ok", "card": "2"}], {},
        )
        assert res["pushed"] == 1
        assert res["skipped_pin"] == 1
        pushed_pins = [c[2] for c in zk.calls if c[0] == "SSR_SetUserInfo"]
        assert pushed_pins == ["117"]

    def test_failed_userinfo_reported_not_raised(self, driver):
        drv, zk = driver
        zk.setuserinfo_ok = False
        drv.connect()
        res = drv.push_roster([{"pin": "117", "name": "Bob", "card": "1"}], {})
        assert res["ok"] is False and res["failed"] == 1


# --------------------------------------------------------------------------- #
# Device-user enumerate + delete (MIRROR pushing-policy primitives)
# --------------------------------------------------------------------------- #

class TestDeviceUserListAndDelete:
    def test_list_users_happy(self):
        drv, zk = _make_driver()
        zk.device_users = [
            {"pin": "40000", "name": "LAJNEF", "card": "1419213", "enabled": True},
            {"pin": "95503411", "name": "malek", "card": "27114027", "enabled": True},
            {"pin": "117", "name": "Bob", "card": "", "enabled": False},
        ]
        res = drv._do_list_users(zk)
        assert res["ok"] is True
        assert [u["pin"] for u in res["users"]] == ["40000", "95503411", "117"]
        assert res["users"][0]["card"] == "1419213"
        assert res["users"][2]["enabled"] is False

    def test_list_users_readall_false_is_not_empty(self):
        """The load-bearing distinction: a FAILED list must be ok=False, NOT an empty device."""
        drv, zk = _make_driver()
        zk.readall_ok = False
        zk.device_users = [{"pin": "1"}]
        res = drv._do_list_users(zk)
        assert res["ok"] is False and res["users"] == []

    def test_list_users_midloop_raise_fails_closed(self):
        drv, zk = _make_driver()
        zk.device_users = [{"pin": "1"}, {"pin": "2"}, {"pin": "3"}]
        zk.raise_on_enum_index = 1  # blow up on the 2nd row
        res = drv._do_list_users(zk)
        assert res["ok"] is False  # never a partial delete set

    def test_list_users_unexpected_shape_fails_closed(self):
        drv, zk = _make_driver()
        zk.SSR_GetAllUserInfo = lambda *a: True  # bare bool, not a tuple
        res = drv._do_list_users(zk)
        assert res["ok"] is False and "unexpected shape" in (res.get("error") or "")

    def test_delete_users_skips_invalid_and_deletes_whole_user(self):
        drv, zk = _make_driver()
        res = drv._do_delete_users(zk, ["40000", "abc", "1234567890", "117"])
        assert res["deleted"] == 2 and res["failed"] == 2
        assert ("40000", 12) in zk.deleted and ("117", 12) in zk.deleted  # 12 = whole user
        assert sum(1 for c in zk.calls if c[0] == "RefreshData") == 1     # once at the end


# --------------------------------------------------------------------------- #
# Engine seams: full-sync + member-sync branches on the worker
# --------------------------------------------------------------------------- #

class _FakeStandaloneDriver:
    """Just enough driver surface for the worker's sync drains."""
    owns_event_source = True

    def __init__(self, ok: bool = True):
        self.ok = ok
        self.push_calls: List[tuple] = []

    def push_roster(self, users, templates_by_pin=None, *, bracket_enable_device=False, **kw):
        self.push_calls.append((list(users), dict(templates_by_pin or {}), bracket_enable_device))
        return {"ok": self.ok, "pushed": len(users), "failed": 0 if self.ok else len(users),
                "errors": [] if self.ok else ["boom"]}


def _make_sync_worker(monkeypatch, driver=None, users=None):
    """Minimal UltraDeviceWorker carrying only what the sync drains touch."""
    import app.core.ultra_engine as ue

    w = ue.UltraDeviceWorker.__new__(ue.UltraDeviceWorker)
    w._device = {"id": 9, "name": "Entree 1"}
    w._device_id = 9
    w._device_name = "Entree 1"
    w._settings = {}
    w._cfg = None
    w._prefix = "[ULTRA:9]"
    w._tel_wid = "ULTRA:9"
    w._sdk = driver if driver is not None else _FakeStandaloneDriver()
    w._connected = True
    w._full_sync_lock = threading.Lock()
    w._pending_full_sync_request = None
    w._member_sync_lock = threading.Lock()
    from collections import deque
    w._pending_member_syncs = deque()
    w._pending_member_sync_ids = set()
    w._pending_member_revoke_ids = set()
    w._wake_evt = threading.Event()
    w._active_sync_lock = threading.Lock()
    w._active_sync_engine = None
    w._on_full_sync_started = MagicMock()
    w._on_full_sync_finished = MagicMock()

    cache = SimpleNamespace(users=users if users is not None else [
        {"activeMembershipId": 117, "userId": 5, "membershipId": 3,
         "fullName": "Bob", "firstCardId": "8192567"},
        {"activeMembershipId": 118, "userId": 6, "membershipId": 3,
         "fullName": "Alice", "firstCardId": "999"},
    ])
    monkeypatch.setattr(ue, "load_sync_cache", lambda: cache)

    # The incremental full sync reads/writes per-pin state in device_sync_state.
    # Keep these drains hermetic: no stored state (=> everything is pushed, the
    # behaviour these tests were written against) and no writes to a real DB.
    import app.core.db as _db
    monkeypatch.setattr(_db, "list_device_sync_hashes_and_status", lambda **kw: {})
    monkeypatch.setattr(_db, "save_device_sync_state_batch", lambda **kw: 0)
    monkeypatch.setattr(_db, "prune_device_sync_state", lambda **kw: 0)
    monkeypatch.setattr(_db, "delete_device_sync_state", lambda **kw: None)
    import app.core.device_sync as _ds
    monkeypatch.setattr(_ds.DeviceSyncEngine, "_build_local_fp_index_for_pins",
                        lambda self, *, pins, fingerprint_enabled: {}, raising=True)

    # sentinel: the PullSDK push path must NEVER be reached for this driver
    import app.core.device_sync as ds
    def _forbidden(*a, **k):
        raise AssertionError("ZK_STANDALONE device reached the PullSDK push path")
    monkeypatch.setattr(ds.DeviceSyncEngine, "run_one_device_on_connected_sdk",
                        _forbidden, raising=True)
    monkeypatch.setattr(ds.DeviceSyncEngine, "sync_member_on_connected_sdk",
                        _forbidden, raising=True)
    return w


class TestStandaloneFullSyncBranch:
    def test_full_sync_pushes_roster_and_terminates(self, monkeypatch):
        w = _make_sync_worker(monkeypatch)
        w.request_full_sync(reason="timer", fingerprint_hash="abc123")
        drained = w._drain_full_sync_commands(limit=1)
        assert drained == 1
        drv = w._sdk
        assert len(drv.push_calls) == 1
        users, templates, bracket = drv.push_calls[0]
        assert {u["pin"] for u in users} == {"117", "118"}
        assert bracket is False                      # timer = daytime, no UI lock
        # the request TERMINATED (livelock regression guard)
        assert w._pending_full_sync_request is None
        # finished bookkeeping fired with the fingerprint hash
        w._on_full_sync_finished.assert_called_once()
        kwargs = w._on_full_sync_finished.call_args.kwargs
        assert kwargs["ok"] is True
        assert kwargs["fingerprint_hash"] == "abc123"

    def test_manual_user_sync_brackets_enable_device(self, monkeypatch):
        w = _make_sync_worker(monkeypatch)
        w.request_full_sync(reason="user-sync", fingerprint_hash=None)
        w._drain_full_sync_commands(limit=1)
        assert w._sdk.push_calls[0][2] is True       # bracket_enable_device

    def test_failed_push_still_terminates_and_reports(self, monkeypatch):
        w = _make_sync_worker(monkeypatch, driver=_FakeStandaloneDriver(ok=False))
        w.request_full_sync(reason="timer", fingerprint_hash="abc123")
        w._drain_full_sync_commands(limit=1)
        assert w._pending_full_sync_request is None  # no re-queue on failure either
        kwargs = w._on_full_sync_finished.call_args.kwargs
        assert kwargs["ok"] is False
        assert kwargs["fingerprint_hash"] is None    # scheduler must NOT record it

    def test_allowed_memberships_filter_applies(self, monkeypatch):
        w = _make_sync_worker(monkeypatch)
        w._device["allowedMemberships"] = [3]
        users = [
            {"activeMembershipId": 117, "userId": 5, "membershipId": 3,
             "fullName": "Bob", "firstCardId": "1"},
            {"activeMembershipId": 200, "userId": 7, "membershipId": 4,   # filtered
             "fullName": "Eve", "firstCardId": "2"},
        ]
        import app.core.ultra_engine as ue
        monkeypatch.setattr(ue, "load_sync_cache",
                            lambda: SimpleNamespace(users=users))
        w.request_full_sync(reason="timer")
        w._drain_full_sync_commands(limit=1)
        pushed = w._sdk.push_calls[0][0]
        assert {u["pin"] for u in pushed} == {"117"}


class TestStandaloneMemberSyncBranch:
    def test_member_sync_pushes_only_that_member(self, monkeypatch):
        w = _make_sync_worker(monkeypatch)
        w.request_member_sync(117)
        drained = w._drain_member_sync_commands(limit=1)
        assert drained == 1
        drv = w._sdk
        assert len(drv.push_calls) == 1
        users = drv.push_calls[0][0]
        assert [u["pin"] for u in users] == ["117"]
        # queue drained — no endless re-queue
        assert len(w._pending_member_syncs) == 0

    def test_unknown_member_terminates_without_push(self, monkeypatch):
        w = _make_sync_worker(monkeypatch)
        w.request_member_sync(99999)
        w._drain_member_sync_commands(limit=1)
        assert len(w._sdk.push_calls) == 0
        assert len(w._pending_member_syncs) == 0
