"""DeviceSyncEngine must drive PullSDK devices ONLY.

Field incident (OXYGENE_FIT, 2026-08-27): a ZKTeco MB2000 talking the standalone
zkemkeeper SDK was handed a plcommpro.dll socket by DeviceSyncEngine, because the
engine filtered devices on accessDataMode and never on protocol. The client log
showed::

    [DeviceSync] Device id=8 name='Sortie' connecting: ip=192.168.1.247 port=4370
    Loading PullSDK DLL: ...\\sdk\\plcommpro.dll
    PullSDK Connect: protocol=TCP,ipaddress=192.168.1.247,...
    [T] FULL_SYNC_DEVICE device_id=8 ... connect_ms=5110

i.e. the full connect timeout burned on a perfectly healthy terminal, looking
exactly like a cabling fault.

The subtle part -- and the reason this file exists -- is that the OBVIOUS fix is
silently inert. ``_normalize_device()`` returns a fixed allowlist dict, and every
caller normalizes before ``_sync_one_device`` sees the payload. While that
allowlist omitted ``deviceProtocol``, ``resolve_device_protocol()`` answered
ZK_PULLSDK/"default" for the MB2000, so a guard placed downstream could never
fire while appearing to be in place.

These tests pin BOTH halves: the key survives normalization, AND the guard
refuses a standalone device without ever constructing a PullSDK object.
"""

from __future__ import annotations

import logging
import threading
from typing import Protocol

import pytest

from app.core.device_sync import DeviceSyncEngine
from app.sdk.device_driver import DeviceProtocol, resolve_device_protocol


def _declared_protocol_members(protocol: type[Protocol]) -> set[str]:
    """Return the public structural contract on supported Python versions."""
    try:
        from typing import get_protocol_members
    except ImportError:  # Python 3.10/3.11, which this application supports.
        get_protocol_members = None

    if get_protocol_members is not None:
        return set(get_protocol_members(protocol))
    return {name for name in vars(protocol) if not name.startswith("_")}


def _missing_protocol_members(protocol: type[Protocol], implementation: type) -> list[str]:
    return sorted(
        name for name in _declared_protocol_members(protocol) if not hasattr(implementation, name)
    )


def _engine() -> DeviceSyncEngine:
    return DeviceSyncEngine(cfg=None, logger=logging.getLogger("test-protocol-guard"))


def _raw_device(**overrides):
    base = {
        "id": 8,
        "name": "Sortie",
        "active": True,
        "accessDevice": True,
        "accessDataMode": "DEVICE",
        "ipAddress": "192.168.1.247",
        "portNumber": 4370,
        "password": "",
        "model": "UNKNOWN",
    }
    base.update(overrides)
    return base


class TestNormalizationCarriesProtocol:
    """The allowlist must not drop the key the guard depends on."""

    def test_standalone_protocol_survives_normalization(self):
        norm = _engine()._normalize_device(_raw_device(deviceProtocol="ZK_STANDALONE"))
        assert norm.get("deviceProtocol") == "ZK_STANDALONE"

    def test_snake_case_alias_survives_normalization(self):
        norm = _engine()._normalize_device(_raw_device(device_protocol="ZK_STANDALONE"))
        assert norm.get("deviceProtocol") == "ZK_STANDALONE"

    def test_resolver_sees_standalone_through_normalization(self):
        # The end-to-end property the guard actually relies on. If _normalize_device
        # ever drops the key again, this fails loudly instead of the guard going inert.
        norm = _engine()._normalize_device(_raw_device(deviceProtocol="ZK_STANDALONE"))
        assert resolve_device_protocol(norm) is DeviceProtocol.ZK_STANDALONE

    def test_pullsdk_device_is_unaffected(self):
        norm = _engine()._normalize_device(_raw_device(deviceProtocol="ZK_PULLSDK"))
        assert resolve_device_protocol(norm) is DeviceProtocol.ZK_PULLSDK

    def test_device_without_protocol_key_still_resolves_to_pullsdk(self):
        # Every gym onboarded before deviceProtocol existed must keep working.
        norm = _engine()._normalize_device(_raw_device())
        assert resolve_device_protocol(norm) is DeviceProtocol.ZK_PULLSDK


class TestSyncOneDeviceRefusesNonPullSDK:
    """The guard must return BEFORE any PullSDK object is constructed."""

    def test_standalone_device_never_constructs_pullsdk(self, monkeypatch):
        import app.core.device_sync as ds

        def _explode(*a, **kw):  # pragma: no cover - fails the test if reached
            raise AssertionError(
                "PullSDK was constructed for a ZK_STANDALONE device - the protocol "
                "guard did not fire"
            )

        monkeypatch.setattr(ds, "PullSDK", _explode)

        engine = _engine()
        device = engine._normalize_device(_raw_device(deviceProtocol="ZK_STANDALONE"))
        # Must return quietly rather than raise; the engine logs an explicit error.
        engine._sync_one_device(
            device=device,
            users=[],
            local_fp_index={},
            default_door_id=1,
            report_progress=False,
        )

    def test_pullsdk_device_is_not_refused(self, caplog):
        """Complement: the guard must NOT block a normal PullSDK panel.

        Asserted on the guard's own log line rather than on reaching the SDK,
        because with cfg=None execution stops later for unrelated reasons - that
        would make the test pass for the wrong reason.
        """
        engine = _engine()
        device = engine._normalize_device(_raw_device(deviceProtocol="ZK_PULLSDK"))
        with caplog.at_level(logging.ERROR, logger="test-protocol-guard"):
            try:
                engine._sync_one_device(
                    device=device,
                    users=[],
                    local_fp_index={},
                    default_door_id=1,
                    report_progress=False,
                )
            except Exception:
                # Irrelevant here: the engine needs a real cfg/DB to finish. All
                # this test cares about is that the PROTOCOL guard stayed quiet.
                pass
        assert "NOT synced: protocol=" not in caplog.text, (
            "the protocol guard refused a PullSDK panel"
        )

    def test_standalone_refusal_is_logged_explicitly(self, caplog):
        """A silent skip would look like a successful sync. It must be loud.

        A ZK_STANDALONE device left in DEVICE mode gets its roster from NO engine
        (the standalone push lives only on the ULTRA worker), so the operator has
        to be told, not quietly ignored.
        """
        engine = _engine()
        device = engine._normalize_device(_raw_device(deviceProtocol="ZK_STANDALONE"))
        with caplog.at_level(logging.ERROR, logger="test-protocol-guard"):
            engine._sync_one_device(
                device=device,
                users=[],
                local_fp_index={},
                default_door_id=1,
                report_progress=False,
            )
        assert "NOT synced: protocol=ZK_STANDALONE" in caplog.text
        assert "accessDataMode=ULTRA" in caplog.text, (
            "the refusal must tell the operator how to fix it"
        )


class TestTransactionTableCapability:
    """DeviceAttendance gates on this flag instead of calling and crashing."""

    def test_standalone_declares_no_transaction_table(self):
        from app.sdk.zk_standalone import ZKStandaloneDevice

        assert ZKStandaloneDevice.supports_transaction_table is False

    def test_pullsdk_declares_a_transaction_table(self):
        from app.sdk.pullsdk import PullSDKDevice

        assert PullSDKDevice.supports_transaction_table is True

    def test_standalone_implements_delete_all_transaction_rows(self):
        # The field AttributeError: 'ZKStandaloneDevice' object has no attribute
        # 'delete_all_transaction_rows'. It must exist AND be inert - clearing the
        # terminal's own log would destroy records never persisted to SQLite.
        from app.sdk.zk_standalone import ZKStandaloneDevice

        assert hasattr(ZKStandaloneDevice, "delete_all_transaction_rows")
        drv = ZKStandaloneDevice.__new__(ZKStandaloneDevice)
        assert drv.delete_all_transaction_rows() == 0

    def test_protocol_member_discovery_finds_the_declared_public_contract(self):
        class _Contract(Protocol):
            @property
            def is_connected(self) -> bool: ...

            def connect(self) -> bool: ...

        assert _declared_protocol_members(_Contract) == {"connect", "is_connected"}

    def test_missing_member_check_detects_each_incomplete_driver(self):
        class _Contract(Protocol):
            def connect(self) -> bool: ...

            def disconnect(self) -> None: ...

        class _ConnectOnly:
            def connect(self) -> bool:
                return True

        class _DisconnectOnly:
            def disconnect(self) -> None:
                return None

        assert _missing_protocol_members(_Contract, _ConnectOnly) == ["disconnect"]
        assert _missing_protocol_members(_Contract, _DisconnectOnly) == ["connect"]

    def test_both_drivers_satisfy_the_declared_protocol(self):
        from app.sdk.device_driver import DeviceDriver
        from app.sdk.pullsdk import PullSDKDevice
        from app.sdk.zk_standalone import ZKStandaloneDevice

        members = sorted(_declared_protocol_members(DeviceDriver))
        assert members, "DeviceDriver exposes no protocol members to check"
        for cls in (PullSDKDevice, ZKStandaloneDevice):
            missing = _missing_protocol_members(DeviceDriver, cls)
            assert not missing, f"{cls.__name__} is missing {missing}"


class TestCredentialTypeFromModalityTag:
    """Door-history / dashboard must not call MB2000 fingerprints "cards"."""

    def test_standalone_fingerprint_is_finger_print(self):
        from app.core.device_attendance import _credential_type_from_raw

        assert _credential_type_from_raw({"scan_mode_hint": "FINGERPRINT"}) == "FINGER_PRINT"

    def test_standalone_card_is_card(self):
        from app.core.device_attendance import _credential_type_from_raw

        assert _credential_type_from_raw({"scan_mode_hint": "RFID_CARD"}) == "CARD"

    def test_zkem_verify_digit_is_never_fed_to_the_pullsdk_digit_table(self):
        # The trap: in the PullSDK namespace "2" means fingerprint, but in the zkem
        # namespace 2 means CARD. A zkem card scan must stay CARD.
        from app.core.device_attendance import _credential_type_from_raw

        row = {"scan_mode_hint": "RFID_CARD", "verifymethod": "2"}
        assert _credential_type_from_raw(row) == "CARD"

    def test_pullsdk_rows_are_unchanged(self):
        from app.core.device_attendance import _credential_type_from_raw

        assert _credential_type_from_raw({"verifytype": "1"}) == "FINGER_PRINT"
        assert _credential_type_from_raw({"verifytype": "4"}) == "CARD"
        assert _credential_type_from_raw({}) == "CARD"

    def test_qr_still_wins(self):
        from app.core.device_attendance import _credential_type_from_raw

        assert _credential_type_from_raw({"scanmode": "QR_TOTP"}) == "QR_CODE"


class TestOpenDoorGate:
    """The door switch on the standalone family: env override > persisted local
    switch > family default (ON, operator decision 2026-09-04). Whether ACUnlock
    releases the MB2000 turnstile stays UNVERIFIED until script 12/9 passes on site."""

    def test_family_default_is_on(self, monkeypatch):
        from app.sdk import zk_standalone as zs

        monkeypatch.delenv("MONCLUB_ZK_STANDALONE_OPEN_DOOR", raising=False)
        assert zs.ZKStandaloneDevice.supports_open_door is True
        assert zs.resolve_open_door_switch(8, {}) == (True, "default")

    def test_env_forces_on(self, monkeypatch):
        from app.sdk.zk_standalone import _open_door_env_override, resolve_open_door_switch

        for val in ("1", "true", "yes", "on", "all"):
            monkeypatch.setenv("MONCLUB_ZK_STANDALONE_OPEN_DOOR", val)
            assert _open_door_env_override(8) is True, val
            assert resolve_open_door_switch(8, {"openDoorEnabled": False}) == (True, "env"), val

    def test_env_forces_off(self, monkeypatch):
        from app.sdk.zk_standalone import _open_door_env_override, resolve_open_door_switch

        for val in ("0", "false", "no", "off", "none"):
            monkeypatch.setenv("MONCLUB_ZK_STANDALONE_OPEN_DOOR", val)
            assert _open_door_env_override(8) is False, val
            assert resolve_open_door_switch(8, {"openDoorEnabled": True}) == (False, "env"), val

    def test_env_id_list_is_an_allowlist(self, monkeypatch):
        from app.sdk.zk_standalone import _open_door_env_override

        monkeypatch.setenv("MONCLUB_ZK_STANDALONE_OPEN_DOOR", "8,12")
        assert _open_door_env_override(8) is True
        assert _open_door_env_override(12) is True
        assert _open_door_env_override(9) is False

    def test_garbage_env_is_ignored(self, monkeypatch):
        from app.sdk.zk_standalone import _open_door_env_override, resolve_open_door_switch

        monkeypatch.setenv("MONCLUB_ZK_STANDALONE_OPEN_DOOR", "nope")
        assert _open_door_env_override(8) is None
        assert resolve_open_door_switch(8, {"openDoorEnabled": False}) == (False, "local")

    def test_open_door_refuses_while_switched_off(self, monkeypatch):
        """The refusal must be loud (log + DOOR_OPEN result=unsupported), not a silent False."""
        from unittest.mock import MagicMock

        from app.sdk import zk_standalone as zs

        tel = MagicMock()
        monkeypatch.setattr(zs, "_tel", tel)
        drv = zs.ZKStandaloneDevice.__new__(zs.ZKStandaloneDevice)
        drv.logger = MagicMock()
        drv._prefix = "[ZKEM:8]"
        drv._tel_wid = "ZKEM:8"
        drv.supports_open_door = False
        drv._open_door_source = "local"
        assert drv.open_door(door_id=1, pulse_time_ms=3000) is False
        assert drv.logger.warning.called
        assert tel.warn.call_args.args[0] == "DOOR_OPEN"
        assert tel.warn.call_args.kwargs["result"] == "unsupported"


class TestRosterPushIsBoundedAndRecoverable:
    """A wedged terminal must cost one chunk, not the whole gym.

    Field incident (OXYGENE_FIT, 2026-08-27, v1.4.23): push_roster ran as ONE
    600s command over 950 members. zkemkeeper has no call timeout, so when the
    terminal stopped answering, the STA thread blocked forever. `_call` raised
    after 600s but left the thread ALIVE, so `_ensure_sta_thread` saw a live
    thread and never replaced it -- the device stayed dead until the app was
    restarted. Meanwhile the STA loop never reached its event-pump step, so
    RTLog was never polled and the day's timeline stayed empty while members
    were badging.
    """

    @staticmethod
    def _driver():
        from app.sdk.zk_standalone import ZKStandaloneDevice

        drv = ZKStandaloneDevice(
            {"id": 8, "name": "Sortie", "ipAddress": "10.0.0.9", "portNumber": 4370, "password": ""},
            logger=logging.getLogger("zk-test"),
        )
        drv._refresh_pin_card_map = lambda: None  # type: ignore[method-assign]
        return drv

    def test_push_is_split_into_bounded_chunks(self):
        from app.sdk.zk_standalone import _PUSH_CHUNK_MEMBERS

        drv = self._driver()
        seen = []

        def fake_call(op, args=None, timeout=None):
            seen.append((len(args["users"]), timeout))
            return {"ok": True, "pushed": len(args["users"]), "failed": 0, "skipped_pin": 0}

        drv._call = fake_call  # type: ignore[method-assign]
        res = drv.push_roster([{"pin": str(i), "name": "x", "card": ""} for i in range(95)], {})

        expected = -(-95 // _PUSH_CHUNK_MEMBERS)  # ceil
        assert res["pushed"] == 95
        assert len(seen) == expected, f"expected {expected} chunks, got {len(seen)}"
        assert all(n <= _PUSH_CHUNK_MEMBERS for n, _ in seen)
        # Every chunk must carry a bounded timeout - an unbounded one is the bug.
        assert all(t is not None and t <= 600.0 for _, t in seen)

    def test_trace_budget_is_carried_across_chunks(self):
        """The trace must reach the calls that actually fail.

        Field incident (2026-08-27): tracing was enabled for the FIRST chunk only.
        Chunk 1 succeeded every time and chunk 2 wedged every time, so the trace
        covered only the working chunk. Worse, the first members of that roster had
        no fingerprints at all, so a member-only budget was exhausted before a
        single template upload was ever reached -- and the template calls are the
        prime suspect. Budgets must therefore span the whole roster.
        """
        from app.sdk.zk_standalone import _PUSH_TRACE_MEMBERS, _PUSH_TRACE_TEMPLATES

        drv = self._driver()
        seen = []

        def fake_call(op, args=None, timeout=None):
            seen.append((args.get("trace_members"), args.get("trace_templates")))
            # Pretend this chunk consumed one of each budget.
            return {
                "ok": True, "pushed": len(args["users"]), "failed": 0, "skipped_pin": 0,
                "trace_members_left": max(0, int(args.get("trace_members") or 0) - 1),
                "trace_templates_left": max(0, int(args.get("trace_templates") or 0) - 1),
            }

        drv._call = fake_call  # type: ignore[method-assign]
        drv.push_roster([{"pin": str(i), "name": "x", "card": ""} for i in range(50)], {})

        assert seen[0] == (_PUSH_TRACE_MEMBERS, _PUSH_TRACE_TEMPLATES), "first chunk starts with the full budget"
        # The budget must DECREASE across chunks rather than reset -- a reset is the
        # bug (every chunk would re-trace) and a constant is the old bug (only
        # chunk 1 traced).
        assert seen[1][0] == _PUSH_TRACE_MEMBERS - 1
        assert seen[1][1] == _PUSH_TRACE_TEMPLATES - 1
        assert seen[-1][1] < seen[0][1], "template budget must survive into later chunks"

    def test_a_wedged_chunk_does_not_abort_the_whole_roster(self):
        """One bad member must not block the other 940.

        Before this, a wedge broke out of the loop and the retry restarted at
        chunk 1, wedged at the same chunk, and the gym never received more than
        the first 10 of 950 members.
        """
        drv = self._driver()
        drv.connect = lambda: True  # type: ignore[method-assign]
        calls = {"n": 0}

        def fake_call(op, args=None, timeout=None):
            calls["n"] += 1
            if calls["n"] == 2:
                raise TimeoutError("zkemkeeper command 'push_roster' timed out")
            return {"ok": True, "pushed": len(args["users"]), "failed": 0, "skipped_pin": 0}

        drv._call = fake_call  # type: ignore[method-assign]
        res = drv.push_roster([{"pin": str(i), "name": "x", "card": ""} for i in range(50)], {})

        assert res["pushed"] == 40, "chunks after the wedged one must still be pushed"
        assert res["chunks_wedged"] == 1
        assert res["ok"] is False, "a skipped chunk is still not a clean sync"
        assert any("pins" in e for e in res["errors"]), "the wedged chunk must be identified"

    def test_repeated_wedges_are_abandoned_not_hammered(self):
        """A terminal that wedges on everything must not be retried 95 times.

        Each wedge abandons an unkillable STA thread, so an unbounded loop leaks
        one thread per chunk.
        """
        from app.sdk.zk_standalone import _PUSH_MAX_CONSECUTIVE_WEDGES

        drv = self._driver()
        drv.connect = lambda: True  # type: ignore[method-assign]
        calls = {"n": 0}

        def always_wedge(op, args=None, timeout=None):
            calls["n"] += 1
            raise TimeoutError("timed out")

        drv._call = always_wedge  # type: ignore[method-assign]
        res = drv.push_roster([{"pin": str(i), "name": "x", "card": ""} for i in range(950)], {})

        assert calls["n"] == _PUSH_MAX_CONSECUTIVE_WEDGES, "must stop at the cap, not run every chunk"
        assert res["chunks_wedged"] == _PUSH_MAX_CONSECUTIVE_WEDGES
        assert res["ok"] is False

    def test_bracketed_reconcile_stays_a_single_command(self):
        """EnableDevice(False) must span the WHOLE roster, so it is not chunked."""
        drv = self._driver()
        calls = []

        def fake_call(op, args=None, timeout=None):
            calls.append(len(args["users"]))
            return {"ok": True, "pushed": len(args["users"]), "failed": 0, "skipped_pin": 0}

        drv._call = fake_call  # type: ignore[method-assign]
        drv.push_roster(
            [{"pin": str(i), "name": "x", "card": ""} for i in range(50)],
            {}, bracket_enable_device=True,
        )
        assert calls == [50], "a bracketed reconcile must issue exactly one command"

    def test_abort_reports_what_actually_landed(self):
        drv = self._driver()
        n = {"i": 0}

        def fake_call(op, args=None, timeout=None):
            n["i"] += 1
            if n["i"] > 2:
                raise TimeoutError("zkemkeeper command 'push_roster' timed out")
            return {"ok": True, "pushed": len(args["users"]), "failed": 0, "skipped_pin": 0}

        drv._call = fake_call  # type: ignore[method-assign]
        res = drv.push_roster([{"pin": str(i), "name": "x", "card": ""} for i in range(95)], {})
        assert res["ok"] is False
        assert res["pushed"] == 20, "partial progress must be reported, not discarded"
        assert "timed out" in str(res.get("error", ""))

    def test_wedged_sta_thread_is_abandoned_so_a_new_one_can_start(self):
        drv = self._driver()
        drv._sta_thread = threading.Thread(target=lambda: threading.Event().wait(), daemon=True)
        drv._sta_thread.start()
        drv._connected_flag.set()
        gen_before = drv._sta_gen

        drv._abandon_sta_thread("simulated wedge")

        assert drv._sta_gen == gen_before + 1, "generation must advance to fence the zombie"
        assert drv._sta_thread is None, "a live-but-wedged thread must be dropped"
        assert not drv._connected_flag.is_set(), "the worker must see the device as down"

    def test_call_abandons_the_thread_on_timeout(self):
        """The whole point: a timeout must not leave the device dead forever."""
        drv = self._driver()
        drv._sta_thread = threading.Thread(target=lambda: threading.Event().wait(), daemon=True)
        drv._sta_thread.start()
        gen_before = drv._sta_gen

        with pytest.raises(TimeoutError):
            drv._call("push_roster", args={"users": []}, timeout=0.05)

        assert drv._sta_gen == gen_before + 1
        assert drv._sta_thread is None


class TestRefusedTemplateFailsTheSync:
    """A fingerprint the terminal refused must never be reported as synced.

    Found by audit (2026-08-28). SetUserTmpExStr returning False only appended a
    string to errors[]; `failed` was untouched, `pushed += 1` still ran, and
    `ok = failed == 0` stayed True. So: the member was reported synced, the roster
    fingerprint hash was stamped, and the scheduler then skipped every later cycle
    as "fingerprint unchanged" -- while that member's finger was refused at the
    turnstile and Access said it worked.
    """

    @staticmethod
    def _driver():
        from app.sdk.zk_standalone import ZKStandaloneDevice

        drv = ZKStandaloneDevice.__new__(ZKStandaloneDevice)
        drv.logger = logging.getLogger("zk-tpl")
        drv._prefix = "[ZKEM:8]"
        drv._tel_wid = "ZKEM:8"
        drv._pump = lambda: None  # type: ignore[method-assign]
        return drv

    class _ZK:
        def __init__(self, template_ok=True, user_ok=True):
            self.template_ok = template_ok
            self.user_ok = user_ok

        def SetStrCardNumber(self, c): pass
        def SSR_SetUserInfo(self, *a): return self.user_ok
        def SSR_DeleteEnrollData(self, *a): pass
        def SetUserTmpExStr(self, *a): return self.template_ok
        def RefreshData(self, mn): pass
        def EnableDevice(self, mn, on): pass

    def _push(self, zk):
        return self._driver()._do_push_roster(
            zk,
            users=[{"pin": "1000", "name": "Ahmed", "card": "5001"}],
            templates_by_pin={"1000": [{"fingerId": 0, "templateData": "x" * 400}]},
            bracket=False,
        )

    def test_refused_template_makes_the_push_not_ok(self):
        res = self._push(self._ZK(template_ok=False))
        assert res["ok"] is False, "a refused fingerprint was reported as a successful sync"
        assert res["templates_failed"] == 1

    def test_refused_template_is_reported_in_errors(self):
        res = self._push(self._ZK(template_ok=False))
        assert any("SetUserTmpExStr" in e for e in res["errors"])

    def test_successful_template_still_reports_ok(self):
        res = self._push(self._ZK(template_ok=True))
        assert res["ok"] is True
        assert res["templates_failed"] == 0
        assert res["pushed"] == 1

    def test_chunked_caller_aggregates_template_failures(self):
        drv = self._driver()

        def fake_call(op, args=None, timeout=None):
            return {"ok": False, "pushed": len(args["users"]), "failed": 0,
                    "templates_failed": len(args["users"]), "skipped_pin": 0, "errors": []}

        drv._call = fake_call  # type: ignore[method-assign]
        drv._refresh_pin_card_map = lambda: None  # type: ignore[method-assign]
        res = drv.push_roster([{"pin": str(i), "name": "x", "card": ""} for i in range(25)], {})
        assert res["ok"] is False
        assert res["templates_failed"] == 25, "per-chunk template failures must aggregate"


class TestUnsupportedForProtocolContract:
    """PullSDK-only endpoints must refuse with 409, not report a server fault."""

    def test_pullsdk_device_is_not_refused(self, monkeypatch):
        from app.api import local_access_api_v2 as v2

        monkeypatch.setattr(v2, "_device_protocol_of", lambda did: "ZK_PULLSDK")
        sent = []

        class _Ctx:
            def send_json(self, code, payload): sent.append((code, payload))

        assert v2._unsupported_for_protocol(_Ctx(), 7, "test") is False
        assert sent == [], "a PullSDK panel must not be refused"

    def test_standalone_device_gets_409_not_500(self, monkeypatch):
        from app.api import local_access_api_v2 as v2

        monkeypatch.setattr(v2, "_device_protocol_of", lambda did: "ZK_STANDALONE")
        sent = []

        class _Ctx:
            def send_json(self, code, payload): sent.append((code, payload))

        assert v2._unsupported_for_protocol(_Ctx(), 8, "la liste des utilisateurs") is True
        assert len(sent) == 1
        code, payload = sent[0]
        assert code == 409, "500 tells the operator the server broke; this is a policy refusal"
        assert payload["unsupported"] is True
        assert payload["protocol"] == "ZK_STANDALONE"
        assert payload["ok"] is False


class TestUltraPopulatesBirthday:
    """The popup's birthday screen must be reachable on an ULTRA gym.

    Found by audit: only realtime_agent (AGENT mode) ever set user_birthday, so
    on an ULTRA gym -- which is the only mode a standalone terminal can run in --
    the gold birthday screen was unreachable dead code. The value was already in
    the local cache (sync_users.birthday); it simply never reached the event.
    """

    def test_notification_request_carries_birthday_to_the_popup(self):
        from app.core.access_types import NotificationRequest
        from app.core.realtime_agent import _popup_payload_from_request

        req = NotificationRequest(
            event_id="e1", title="t", message="m",
            user_full_name="Ahmed", user_birthday="1990-08-28",
        )
        payload = _popup_payload_from_request(req)
        # The popup reads e.userBirthday (PopupWindow.tsx).
        assert payload["userBirthday"] == "1990-08-28"

    def test_ultra_enqueue_notification_accepts_birthday(self):
        """The ULTRA engine must accept and forward the field, not drop it."""
        import inspect

        from app.core.ultra_engine import UltraDeviceWorker

        sig = inspect.signature(UltraDeviceWorker._enqueue_notification)
        assert "user_birthday" in sig.parameters, (
            "ULTRA cannot populate the birthday screen without this parameter"
        )

    def test_ultra_call_sites_pass_the_birthday(self):
        """A parameter nothing passes is the same bug in a new place."""
        import inspect

        from app.core import ultra_engine

        src = inspect.getsource(ultra_engine)
        # Every notification built from a resolved user must forward it.
        assert src.count("user_birthday=(str(user.get(\"birthday\")") >= 3, (
            "expected the resolved-user notification call sites to pass birthday"
        )


class TestMirrorDeleteIsRecorded:
    """A destructive reconcile must leave a durable record.

    MIRROR is the only place the app deletes members off a terminal. It used to
    leave nothing but a log line and a telemetry event, so "who removed these
    users, and when?" was unanswerable from any screen.
    """

    def test_mirror_records_a_push_batch_row(self):
        import inspect

        from app.core import ultra_engine

        src = inspect.getsource(ultra_engine)
        armed = src[src.index("# 10) armed"):]
        assert "insert_push_batch(" in armed, "the armed delete must open a batch row"
        assert 'policy="MIRROR"' in armed, "the row must be identifiable as a MIRROR reconcile"
        assert "update_push_batch(" in armed, "the batch row must be finalised"

    def test_mirror_record_names_the_deleted_pins(self):
        """A row saying '12 users removed' that cannot say WHICH is not an audit trail."""
        import inspect

        from app.core import ultra_engine

        src = inspect.getsource(ultra_engine)
        armed = src[src.index("# 10) armed"):]
        assert "deleted pins: " in armed


class TestSlotClearUsesTheProvenApi:
    """The finger slot must be cleared with SSR_DelUserTmpExt, not SSR_DeleteEnrollData.

    Field trace (OXYGENE_FIT, v1.4.25): 12 of 19 STA thread wedges had
    `SSR_DeleteEnrollData(f=1)` as the last call made, plus 2 more on f=2, while
    finger 0 always returned normally -- i.e. on this firmware that call never
    returns for backupNumber >= 1, and it stalled the whole roster.

    tools/mb2000_scripts/5_push_member_to_device.ps1 -- the push sequence proven on
    this hardware -- uses SSR_DelUserTmpExt(mn, pin, fingerId). A code comment used
    to claim SSR_DeleteEnrollData was "proven by scripts 5/7"; that is false for
    script 5, which is the one that pushes. Script 7 uses SSR_DeleteEnrollData for
    WHOLE-USER / face / password backup numbers (11/12/13) -- a different operation,
    and that usage is retained.
    """

    class _ZK:
        def __init__(self): self.cleared = []
        def SetStrCardNumber(self, c): pass
        def SSR_SetUserInfo(self, *a): return True
        def SSR_DelUserTmpExt(self, mn, pin, fid): self.cleared.append(("DelUserTmpExt", fid))
        def SSR_DeleteEnrollData(self, *a):
            raise AssertionError(
                "SSR_DeleteEnrollData was used to clear a finger slot -- that call "
                "never returns for finger >= 1 on the MB2000 firmware"
            )
        def SetUserTmpExStr(self, *a): return True
        def RefreshData(self, mn): pass
        def EnableDevice(self, mn, on): pass

    @staticmethod
    def _driver():
        from app.sdk.zk_standalone import ZKStandaloneDevice

        drv = ZKStandaloneDevice.__new__(ZKStandaloneDevice)
        drv.logger = logging.getLogger("zk-slot")
        drv._prefix = "[ZKEM:8]"
        drv._tel_wid = "ZKEM:8"
        drv._pump = lambda: None  # type: ignore[method-assign]
        drv._device_fp_version = ""
        return drv

    def test_multi_finger_push_never_calls_the_hanging_api(self):
        zk = self._ZK()
        res = self._driver()._do_push_roster(
            zk,
            users=[{"pin": "30519", "name": "M", "card": ""}],
            templates_by_pin={"30519": [
                {"fingerId": 0, "templateVersion": 10, "templateData": "x" * 960},
                {"fingerId": 1, "templateVersion": 10, "templateData": "y" * 1400},
                {"fingerId": 2, "templateVersion": 10, "templateData": "z" * 1400},
            ]},
            bracket=False,
        )
        assert res["ok"] is True
        # Every finger, including the ones that used to wedge, cleared via the proven API.
        assert zk.cleared == [("DelUserTmpExt", 0), ("DelUserTmpExt", 1), ("DelUserTmpExt", 2)]

    def test_whole_user_delete_still_uses_delete_enroll_data(self):
        """MIRROR's whole-user delete (backupNumber 12) is script 7's proven usage."""
        import inspect

        from app.sdk import zk_standalone

        src = inspect.getsource(zk_standalone)
        assert "SSR_DeleteEnrollData(1, pin, 12)" in src, (
            "the whole-user delete must keep the API script 7 proved"
        )

    def test_refusal_names_the_version_gap(self, caplog):
        """339 silent refusals taught us nothing. The message must name both versions."""
        class _Refusing(TestSlotClearUsesTheProvenApi._ZK):
            def SetUserTmpExStr(self, *a): return False

        drv = self._driver()
        drv._device_fp_version = "9"
        with caplog.at_level(logging.WARNING, logger="zk-slot"):
            drv._do_push_roster(
                _Refusing(),
                users=[{"pin": "30519", "name": "M", "card": ""}],
                templates_by_pin={"30519": [
                    {"fingerId": 0, "templateVersion": 10, "templateData": "x" * 960},
                ]},
                bracket=False,
            )
        assert "deviceFpVersion=9" in caplog.text
        assert "templateVersion=10" in caplog.text


class TestDeviceOccupancyIsReported:
    """A terminal carried over from previous software arrives FULL.

    The gym kept the old system's fingerprints on the MB2000. A ZKTeco terminal
    has a finite fingerprint store, and when it is full SetUserTmpExStr returns
    False for every upload with no reason given -- which is exactly what the field
    showed (339 identical refusals, zero successes). Members WITHOUT fingerprints
    keep pushing fine, so the roster looks partly successful and the real cause
    hides. Nothing in the driver used to ask the device how full it was.
    """

    @staticmethod
    def _driver(status):
        from app.sdk.zk_standalone import ZKStandaloneDevice

        drv = ZKStandaloneDevice.__new__(ZKStandaloneDevice)
        drv.logger = logging.getLogger("zk-cap")
        drv._prefix = "[ZKEM:8]"
        drv._tel_wid = "ZKEM:8"
        drv._pump = lambda: None  # type: ignore[method-assign]
        drv._device_fp_version = "10"
        drv._device_status = status
        return drv

    def test_full_store_is_an_error_naming_the_carried_over_enrolments(self, caplog):
        drv = self._driver({"fingerprints": 3000, "fingerprint_capacity": 3000, "fingerprints_free": 0})
        with caplog.at_level(logging.ERROR, logger="zk-cap"):
            drv._warn_if_device_full()
        assert "FINGERPRINT STORE IS FULL" in caplog.text
        assert "3000/3000" in caplog.text
        assert "previous software" in caplog.text

    def test_nearly_full_store_warns_before_it_bites(self, caplog):
        drv = self._driver({"fingerprints": 2800, "fingerprint_capacity": 3000, "fingerprints_free": 200})
        with caplog.at_level(logging.WARNING, logger="zk-cap"):
            drv._warn_if_device_full()
        assert "93% full" in caplog.text

    def test_healthy_store_says_nothing(self, caplog):
        drv = self._driver({"fingerprints": 200, "fingerprint_capacity": 3000, "fingerprints_free": 2800})
        with caplog.at_level(logging.WARNING, logger="zk-cap"):
            drv._warn_if_device_full()
        assert caplog.text.strip() == ""

    def test_unreadable_status_never_invents_a_capacity(self, caplog):
        """If the device would not answer, say nothing — do not guess a number."""
        drv = self._driver({})
        with caplog.at_level(logging.WARNING, logger="zk-cap"):
            drv._warn_if_device_full()
        assert caplog.text.strip() == ""

    def test_refusal_reports_the_store_state(self, caplog):
        class _ZK:
            def SetStrCardNumber(self, c): pass
            def SSR_SetUserInfo(self, *a): return True
            def SSR_DelUserTmpExt(self, *a): pass
            def SetUserTmpExStr(self, *a): return False
            def RefreshData(self, mn): pass
            def EnableDevice(self, mn, on): pass

        drv = self._driver({"fingerprints": 3000, "fingerprint_capacity": 3000, "fingerprints_free": 0})
        with caplog.at_level(logging.WARNING, logger="zk-cap"):
            drv._do_push_roster(
                _ZK(),
                users=[{"pin": "30519", "name": "M", "card": ""}],
                templates_by_pin={"30519": [
                    {"fingerId": 0, "templateVersion": 10, "templateData": "x" * 960},
                ]},
                bracket=False, trace_templates=1,
            )
        assert "fpStore=3000/3000" in caplog.text
        # Both plausible causes must be named — we have not proven which one it is.
        assert "FULL" in caplog.text and "versions disagree" in caplog.text
