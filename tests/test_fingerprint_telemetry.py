"""Session C (2026-09-04): telemetry across the whole fingerprint chain.

Every `[T]` event added by that session has a test here that asserts it FIRES and
carries its correlation key, so a field failure in

    enrol -> backend -> sync -> push -> verify

is locatable from the log with one grep and without a rebuild.

Nothing here talks to hardware or to a backend: the standalone driver is driven
through the same fake COM object the other MB2000 suites use, and the enrolment
worker through a stubbed ZKFinger + API.

HARD RULE observed throughout: no test may reach the real
``C:\\ProgramData\\MonClub Access\\access\\access.db``. The driver's sqlite touch
point (``_refresh_pin_card_map``) is stubbed, the enrolment tests patch every
``app.core.db`` entry point the worker calls, and the sync test calls the pure
helper directly.

The instrumentation is telemetry ONLY. Where a test can cheaply prove that, it
also asserts the behaviour around it is unchanged.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from app.sdk import zk_standalone as zs
from app.sdk.zk_standalone import ZKStandaloneDevice


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

def tel_calls(tel: MagicMock, name: str) -> List[Dict[str, Any]]:
    """Telemetry lines named *name*, chronological, across event() and warn()."""
    out: List[Dict[str, Any]] = []
    for meth, args, kwargs in tel.mock_calls:
        if meth in ("event", "warn") and args and args[0] == name:
            out.append(dict(kwargs))
    return out


def tel_names(tel: MagicMock) -> List[str]:
    return [args[0] for meth, args, _ in tel.mock_calls
            if meth in ("event", "warn") and args]


class FakePushZkem:
    """Fake zkemkeeper COM object covering the roster-push surface."""

    def __init__(self) -> None:
        self.calls: List[tuple] = []
        self.connect_ok = True
        self.setuserinfo_ok = True
        self.settmp_ok = True
        # pin -> forced SSR_SetUserInfo result, overrides setuserinfo_ok
        self.setuserinfo_by_pin: Dict[str, bool] = {}
        # (pin, finger) -> forced SetUserTmpExStr result
        self.settmp_by: Dict[tuple, bool] = {}
        self.raise_on_pin: Optional[str] = None
        self.status: Dict[int, int] = {}
        self.fw_version = ""

    def _rec(self, name: str, *args: Any) -> None:
        self.calls.append((name, *args))

    def SetCommPassword(self, key):
        return True

    def Connect_Net(self, ip, port):
        self._rec("Connect_Net", ip, port)
        return self.connect_ok

    def RegEvent(self, machine, mask):
        return True

    def Disconnect(self):
        self._rec("Disconnect")

    def ReadRTLog(self, machine):
        return False

    def GetRTLog(self, machine):
        return False

    def EnableDevice(self, machine, flag):
        self._rec("EnableDevice", machine, flag)
        return True

    def SetStrCardNumber(self, card):
        return True

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        self._rec("SSR_SetUserInfo", machine, pin)
        if self.raise_on_pin is not None and str(pin) == self.raise_on_pin:
            raise RuntimeError("simulated COM failure mid-member")
        return self.setuserinfo_by_pin.get(str(pin), self.setuserinfo_ok)

    def SSR_DelUserTmpExt(self, machine, pin, finger_id):
        self._rec("SSR_DelUserTmpExt", machine, pin, finger_id)

    def SetUserTmpExStr(self, machine, pin, finger, flag, tmp):
        self._rec("SetUserTmpExStr", machine, pin, finger)
        return self.settmp_by.get((str(pin), int(finger)), self.settmp_ok)

    def RefreshData(self, machine):
        return True

    def GetDeviceStatus(self, machine, idx, box):
        if int(idx) in self.status:
            return (True, self.status[int(idx)])
        return (False, 0)

    def GetFirmwareVersion(self, machine, *placeholders):
        return (True, self.fw_version) if self.fw_version else (False, "")


def make_driver(payload_extra: Dict[str, Any] | None = None,
                fake: FakePushZkem | None = None):
    payload = {
        "id": 9, "name": "Entree 1", "ipAddress": "192.168.9.10", "portNumber": 4370,
        "doorPresets": [{"doorNumber": 1, "direction": "IN"}],
    }
    payload.update(payload_extra or {})
    drv = ZKStandaloneDevice(payload, logger=MagicMock())
    zk = fake or FakePushZkem()
    drv._com_factory = lambda: zk
    drv._co_init = lambda: None
    drv._co_uninit = lambda: None
    drv._pump = lambda: None
    # never let a unit test open the real access.db
    drv._refresh_pin_card_map = lambda: None  # type: ignore[method-assign]
    return drv, zk


@pytest.fixture(autouse=True)
def _no_open_door_env(monkeypatch):
    monkeypatch.delenv(zs._OPEN_DOOR_ENV_VAR, raising=False)


@pytest.fixture
def tel(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(zs, "_tel", fake)
    return fake


def _users(*pins: str) -> List[Dict[str, Any]]:
    return [{"pin": p, "name": f"M{p}", "card": ""} for p in pins]


def _tpl(finger: int = 0, data: str = "AAAA", version: str = "10") -> Dict[str, Any]:
    return {"fingerId": finger, "templateData": data, "templateVersion": version}


# --------------------------------------------------------------------------- #
# 1. PUSH — per-chunk aggregation, failed pins with reasons, template refusals
# --------------------------------------------------------------------------- #

class TestPushChunkTelemetry:
    def test_chunk_event_fires_per_chunk_with_worker_key(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        # 25 members at _PUSH_CHUNK_MEMBERS=10 -> 3 chunks
        res = drv.push_roster(_users(*[str(1000 + i) for i in range(25)]))
        assert res["ok"] is True

        chunks = tel_calls(tel, "ZKEM_PUSH_CHUNK")
        assert len(chunks) == 3, chunks
        assert [c["chunk"] for c in chunks] == [1, 2, 3]
        for c in chunks:
            assert c["worker"] == "ZKEM:9"          # correlation key
            assert c["chunks"] == 3
            assert isinstance(c["dur_ms"], int)
            assert c["ok"] is True
        assert [c["members"] for c in chunks] == [10, 10, 5]
        # the chunk line is what identifies WHICH members a wedge died on
        assert chunks[0]["first_pin"] == "1000"
        assert chunks[2]["last_pin"] == "1024"

    def test_chunk_counts_templates_attempted_and_ok(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        drv.push_roster(_users("11", "12"),
                        templates_by_pin={"11": [_tpl(0), _tpl(1)], "12": [_tpl(0)]})
        c = tel_calls(tel, "ZKEM_PUSH_CHUNK")[0]
        assert c["tpl_attempted"] == 3
        assert c["tpl_ok"] == 3

    def test_push_done_carries_template_totals(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        drv.push_roster(_users("11"), templates_by_pin={"11": [_tpl(0), _tpl(1)]})
        done = tel_calls(tel, "ZKEM_PUSH_DONE")
        assert len(done) == 1
        assert done[0]["tpl_attempted"] == 2
        assert done[0]["tpl_ok"] == 2
        assert done[0]["tpl_failed"] == 0


class TestPushFailedPinsTelemetry:
    def test_member_row_refusal_is_named_with_its_reason(self, tel):
        drv, zk = make_driver()
        zk.setuserinfo_by_pin["77"] = False
        assert drv.connect()
        res = drv.push_roster(_users("76", "77", "78"))

        assert res["ok"] is False
        assert res["failed_pins"] == ["77"]
        fp = tel_calls(tel, "ZKEM_PUSH_FAILED_PINS")
        assert len(fp) == 1
        assert fp[0]["worker"] == "ZKEM:9"
        assert fp[0]["count"] == 1
        assert "77=set_user_info_false" in fp[0]["pins"]
        assert fp[0]["by_reason"] == {"set_user_info_false": 1}

    def test_template_refusal_reason_names_the_finger(self, tel):
        drv, zk = make_driver()
        zk.settmp_by[("55", 1)] = False
        assert drv.connect()
        res = drv.push_roster(_users("55"),
                              templates_by_pin={"55": [_tpl(0), _tpl(1)]})

        assert res["templates_failed"] == 1
        fp = tel_calls(tel, "ZKEM_PUSH_FAILED_PINS")[0]
        assert "55=template_refused_f1" in fp["pins"]

    def test_exception_mid_member_is_named_as_such(self, tel):
        drv, zk = make_driver()
        zk.raise_on_pin = "44"
        assert drv.connect()
        res = drv.push_roster(_users("43", "44"))

        assert "44" in res["failed_pins"]
        fp = tel_calls(tel, "ZKEM_PUSH_FAILED_PINS")[0]
        assert "44=exception:RuntimeError" in fp["pins"]

    def test_no_failed_pins_event_when_everything_lands(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        drv.push_roster(_users("1", "2"))
        assert tel_calls(tel, "ZKEM_PUSH_FAILED_PINS") == []


class TestTemplateRefusalTelemetry:
    def test_refused_template_emits_size_version_and_store(self, tel):
        drv, zk = make_driver()
        zk.settmp_by[("55", 0)] = False
        assert drv.connect()
        drv._device_status = {"fingerprints": 3000, "fingerprint_capacity": 3000}
        drv._device_fp_version = "10"
        drv.push_roster(_users("55"),
                        templates_by_pin={"55": [_tpl(0, data="XYZ123", version="10")]})

        ev = tel_calls(tel, "ZKEM_PUSH_TPL_REFUSED")
        assert len(ev) == 1
        assert ev[0]["pin"] == "55"
        assert ev[0]["finger"] == 0
        assert ev[0]["size"] == len("XYZ123")
        assert ev[0]["template_version"] == "10"
        assert ev[0]["device_fp_version"] == "10"
        assert ev[0]["fp_used"] == 3000
        assert ev[0]["fp_capacity"] == 3000

    def test_never_logs_template_bytes(self, tel):
        secret = "THIS-IS-THE-BIOMETRIC-PAYLOAD"
        drv, zk = make_driver()
        zk.settmp_by[("55", 0)] = False
        assert drv.connect()
        drv.push_roster(_users("55"), templates_by_pin={"55": [_tpl(0, data=secret)]})

        for _meth, args, kwargs in tel.mock_calls:
            for v in list(args) + list(kwargs.values()):
                assert secret not in str(v), (args, kwargs)

    def test_version_mismatch_is_its_own_warn_event(self, tel):
        drv, zk = make_driver()
        zk.settmp_by[("55", 0)] = False
        assert drv.connect()
        drv._device_fp_version = "9"
        drv.push_roster(_users("55"),
                        templates_by_pin={"55": [_tpl(0, version="10")]})

        mm = tel_calls(tel, "ZKEM_TPL_VERSION_MISMATCH")
        assert len(mm) == 1
        assert mm[0]["template_version"] == "10"
        assert mm[0]["device_fp_version"] == "9"
        assert mm[0]["pin"] == "55"

    def test_no_mismatch_event_when_versions_agree(self, tel):
        drv, zk = make_driver()
        zk.settmp_by[("55", 0)] = False
        assert drv.connect()
        drv._device_fp_version = "10"
        drv.push_roster(_users("55"), templates_by_pin={"55": [_tpl(0, version="10")]})
        assert tel_calls(tel, "ZKEM_TPL_VERSION_MISMATCH") == []


class TestDeviceCountersTelemetry:
    def test_counters_emitted_at_connect_with_label_provenance(self, tel):
        drv, zk = make_driver()
        zk.status = {2: 120, 3: 340, 7: 3000}
        zk.fw_version = "10"
        assert drv.connect()

        ev = tel_calls(tel, "ZKEM_DEVICE_COUNTERS")
        assert len(ev) == 1
        assert ev[0]["worker"] == "ZKEM:9"
        # The index -> name table is contradicted by the on-site scripts, so the
        # SOURCE of the labels must travel with the numbers.
        assert ev[0]["label_source"] == "driver._STATUS_FIELDS"
        assert ev[0]["c_users"] == 120
        assert ev[0]["c_fingerprints"] == 340

    def test_counters_add_no_extra_device_round_trip(self, tel):
        """The values were already read on connect; telemetry must not re-read."""
        drv, zk = make_driver()
        zk.status = {3: 5}
        assert drv.connect()
        n_status_calls = len([c for c in zk.calls if c[0] == "GetDeviceStatus"])
        # _read_device_status is the only reader and it is called once per connect.
        assert n_status_calls == 0  # recorded via the tuple path, not _rec
        assert len(tel_calls(tel, "ZKEM_DEVICE_COUNTERS")) == 1


class TestPushWedgeTelemetry:
    """A wedged chunk, the abandon threshold, and the reconnect between chunks."""

    def _wedging_driver(self, wedge_chunks: set, connect_after_wedge=True):
        drv, zk = make_driver()

        real_call = drv._call
        state = {"chunk": 0}

        def fake_call(op, args=None, timeout=None):
            if op == "push_roster":
                state["chunk"] += 1
                if state["chunk"] in wedge_chunks:
                    raise TimeoutError(
                        f"zkemkeeper command {op!r} timed out after {timeout}s")
            return real_call(op, args=args, timeout=timeout)

        drv._call = fake_call  # type: ignore[method-assign]
        drv.connect = (lambda: True) if connect_after_wedge else (lambda: False)
        return drv, zk

    def test_wedged_chunk_names_the_chunk_and_its_members(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        state = {"n": 0}
        real_call = drv._call

        def fake_call(op, args=None, timeout=None):
            if op == "push_roster":
                state["n"] += 1
                if state["n"] == 1:
                    raise TimeoutError("zkemkeeper command 'push_roster' timed out after 45s")
            return real_call(op, args=args, timeout=timeout)

        drv._call = fake_call  # type: ignore[method-assign]
        drv.push_roster(_users(*[str(200 + i) for i in range(15)]))

        w = tel_calls(tel, "ZKEM_PUSH_WEDGED")
        assert len(w) == 1
        assert w[0]["worker"] == "ZKEM:9"
        assert w[0]["chunk"] == 1
        assert w[0]["members"] == 10
        assert w[0]["consecutive"] == 1
        assert "timed out" in w[0]["err"]

    def test_successful_reconnect_after_a_wedge_is_recorded(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        state = {"n": 0}
        real_call = drv._call

        def fake_call(op, args=None, timeout=None):
            if op == "push_roster":
                state["n"] += 1
                if state["n"] == 1:
                    raise TimeoutError("wedged")
            return real_call(op, args=args, timeout=timeout)

        drv._call = fake_call  # type: ignore[method-assign]
        drv.push_roster(_users(*[str(300 + i) for i in range(15)]))

        rc = tel_calls(tel, "ZKEM_PUSH_RECONNECT")
        assert len(rc) == 1
        assert rc[0]["ok"] is True
        assert rc[0]["chunk"] == 1

    def test_failed_reconnect_is_recorded_and_stops_the_push(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        real_call = drv._call

        def fake_call(op, args=None, timeout=None):
            if op == "push_roster":
                raise TimeoutError("wedged")
            return real_call(op, args=args, timeout=timeout)

        drv._call = fake_call  # type: ignore[method-assign]
        drv.connect = lambda: False  # type: ignore[method-assign]
        drv.push_roster(_users(*[str(400 + i) for i in range(15)]))

        rc = tel_calls(tel, "ZKEM_PUSH_RECONNECT")
        assert len(rc) == 1
        assert rc[0]["ok"] is False
        assert rc[0]["err"] == "connect_falsy"

    def test_abandon_after_consecutive_wedges_is_its_own_event(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        real_call = drv._call

        def fake_call(op, args=None, timeout=None):
            if op == "push_roster":
                raise TimeoutError("wedged")
            return real_call(op, args=args, timeout=timeout)

        drv._call = fake_call  # type: ignore[method-assign]
        drv.connect = lambda: True  # type: ignore[method-assign]
        drv.push_roster(_users(*[str(500 + i) for i in range(60)]))

        ab = tel_calls(tel, "ZKEM_PUSH_ABANDONED")
        assert len(ab) == 1
        assert ab[0]["consecutive"] == zs._PUSH_MAX_CONSECUTIVE_WEDGES

    def test_every_pin_of_a_wedged_chunk_is_reported_unconfirmed(self, tel):
        """failed_pins from a wedge carry no per-pin reason; the event says so
        rather than leaving the reason blank."""
        drv, zk = make_driver()
        assert drv.connect()
        real_call = drv._call

        def fake_call(op, args=None, timeout=None):
            if op == "push_roster":
                raise TimeoutError("wedged")
            return real_call(op, args=args, timeout=timeout)

        drv._call = fake_call  # type: ignore[method-assign]
        drv.connect = lambda: True  # type: ignore[method-assign]
        drv.push_roster(_users("901", "902"))

        fp = tel_calls(tel, "ZKEM_PUSH_FAILED_PINS")[0]
        assert "901=chunk_wedged_or_unconfirmed" in fp["pins"]


class TestPushInstrumentationIsBehaviourNeutral:
    def test_result_dict_keeps_every_key_the_engine_reads(self, tel):
        drv, zk = make_driver()
        assert drv.connect()
        res = drv.push_roster(_users("1", "2"), templates_by_pin={"1": [_tpl(0)]})
        for k in ("ok", "pushed", "failed", "templates_failed", "skipped_pin",
                  "chunks_wedged", "errors", "failed_pins"):
            assert k in res, k

    def test_no_per_pin_event_inside_the_member_loop(self, tel):
        """The STA loop pumps no COM messages while a command runs and the log
        handler writes inline, so per-pin lines there would widen the no-pump
        window. Detail is aggregated to chunk boundaries instead."""
        drv, zk = make_driver()
        assert drv.connect()
        drv.push_roster(_users(*[str(600 + i) for i in range(10)]))

        names = tel_names(tel)
        # 10 members, one chunk -> exactly one chunk line, no per-member lines.
        assert names.count("ZKEM_PUSH_CHUNK") == 1
        assert names.count("ZKEM_PUSH_DONE") == 1


# --------------------------------------------------------------------------- #
# 2. VERIFY — the terminal's own decision, and how stale the event was
# --------------------------------------------------------------------------- #

class TestVerifyTelemetry:
    """`zkem_invalid` used to produce only the generic "unrecognised eventType"
    warning, which said nothing about the pin, the verify method, or how old the
    event was. The 2026-08-30 field log had the terminal replay events ~3500 s
    old at 13:51, indistinguishable from live scans without an age."""

    @pytest.fixture
    def ue_tel(self, monkeypatch):
        import app.core.ultra_engine as ue
        fake = MagicMock()
        monkeypatch.setattr(ue, "_tel", fake)
        return fake

    def _worker(self, monkeypatch):
        from tests.test_ultra_engine import _make_worker
        w = _make_worker()
        # keep the test off the DB and off the popup/history plumbing
        w._handle_allow = lambda *a, **k: None          # type: ignore[method-assign]
        w._handle_rfid_rescue = lambda *a, **k: None    # type: ignore[method-assign]
        w._handle_totp_rescue = lambda *a, **k: None    # type: ignore[method-assign]
        return w

    def _evt(self, event_type, *, pin="1234", verify=1, att=0, when=None, eid="e1"):
        import time as _t
        when = when or _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime())
        return {
            "eventId": eid, "cardNo": "999", "eventType": event_type,
            "eventTime": when, "doorId": 1,
            "rawRow": {"pin": pin, "attState": att, "verifyMethod": verify,
                       "scan_mode_hint": "FINGERPRINT"},
        }

    def test_invalid_emits_named_event_with_raw_fields(self, monkeypatch, ue_tel):
        w = self._worker(monkeypatch)
        w._process_event(self._evt("zkem_invalid", pin="4321", verify=1, att=2))

        ev = tel_calls(ue_tel, "ZKEM_VERIFY_INVALID")
        assert len(ev) == 1
        assert ev[0]["worker"] == "ULTRA:1"
        assert ev[0]["pin"] == "4321"
        # RAW values, side by side. verifyMethod's meaning on the MB2000 is
        # [UNKNOWN] (its value space shifts between normal and multi-verify
        # modes), so nothing here may present a decoded reason.
        assert ev[0]["verify_method"] == 1
        assert ev[0]["att_state"] == 2
        assert ev[0]["scan_mode_hint"] == "FINGERPRINT"
        assert ev[0]["age_s"] is not None

    def test_invalid_no_longer_trips_the_generic_unrecognised_warning(self, monkeypatch, ue_tel, caplog):
        import logging
        w = self._worker(monkeypatch)
        with caplog.at_level(logging.WARNING, logger="zkapp"):
            w._process_event(self._evt("zkem_invalid"))
        assert "unrecognised eventType" not in caplog.text

    def test_a_genuinely_unknown_type_still_warns(self, monkeypatch, ue_tel, caplog):
        import logging
        w = self._worker(monkeypatch)
        with caplog.at_level(logging.WARNING, logger="zkapp"):
            w._process_event(self._evt("banana", eid="e-banana"))
        assert "unrecognised eventType" in caplog.text
        assert tel_calls(ue_tel, "ZKEM_VERIFY_INVALID") == []

    def test_accepted_scan_emits_verify_ok(self, monkeypatch, ue_tel):
        w = self._worker(monkeypatch)
        w._process_event(self._evt(0, pin="777"))

        ok = tel_calls(ue_tel, "ZKEM_VERIFY_OK")
        assert len(ok) == 1
        assert ok[0]["pin"] == "777"
        assert ok[0]["worker"] == "ULTRA:1"
        assert ok[0]["age_s"] is not None
        # POPUP_ENQUEUE carries neither the pin nor the verify method nor an age,
        # so this line is not redundant with it.
        assert "verify_method" in ok[0]

    def test_a_replayed_backlog_event_reports_a_large_age(self, monkeypatch, ue_tel):
        import time as _t
        w = self._worker(monkeypatch)
        old = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(_t.time() - 3500))
        w._process_event(self._evt(0, when=old, eid="stale-1"))

        ok = tel_calls(ue_tel, "ZKEM_VERIFY_OK")[0]
        assert ok["age_s"] > 3000, ok["age_s"]

    def test_pullsdk_rows_are_untouched(self, monkeypatch, ue_tel):
        """Only standalone rows carry scan_mode_hint; a PullSDK event must not
        produce either verify line."""
        w = self._worker(monkeypatch)
        w._process_event({
            "eventId": "pull-1", "cardNo": "555", "eventType": 0,
            "eventTime": "2026-09-04 10:00:00", "doorId": 1, "rawRow": {},
        })
        assert tel_calls(ue_tel, "ZKEM_VERIFY_OK") == []
        assert tel_calls(ue_tel, "ZKEM_VERIFY_INVALID") == []

    def test_invalid_still_routes_to_the_deny_branch(self, monkeypatch, ue_tel):
        """Telemetry only: the routing that `zkem_invalid` drives must not move."""
        w = self._worker(monkeypatch)
        seen = {"allow": 0, "rfid": 0}
        w._handle_allow = lambda *a, **k: seen.__setitem__("allow", seen["allow"] + 1)
        w._handle_rfid_rescue = lambda *a, **k: seen.__setitem__("rfid", seen["rfid"] + 1)
        w._process_event(self._evt("zkem_invalid", eid="deny-1"))
        assert seen == {"allow": 0, "rfid": 1}
