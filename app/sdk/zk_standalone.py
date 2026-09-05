"""ZK_STANDALONE driver — ZKTeco standalone terminals (MB2000-class) via zkemkeeper COM.

Implements the ``DeviceDriver`` contract (app/sdk/device_driver.py) for standalone
multi-bio terminals that plcommpro/PullSDK CANNOT drive. Design decisions D1-D8 of
docs/plans/mb2000_zk_standalone_driver_plan.md, in short:

* Transport: zkemkeeper.dll (32-bit COM) hosted IN-PROCESS — the production Access
  build is 32-bit Python by hard build gate, and pywin32 already ships. A 32-bit
  subprocess sidecar remains the designed fallback if in-process COM fails on real
  hardware (on-site GATE 1); only ``_com_factory`` would change.
* ONE STA thread per device owns EVERY COM call (connect, event pump, door unlock,
  roster/template writes, clock). COM interfaces must not be used cross-apartment,
  and the worker calls driver methods from ITS thread — so every public method posts
  a command onto an internal queue serviced by the STA thread and blocks with a
  deadline (the zkemkeeper PoC proved calls can hang; the deadline is the watchdog).
* Events: RegEvent(1, 1) registers OnAttTransactionEx on a COM sink; the STA loop
  drives delivery via ReadRTLog/GetRTLog polling (+ PumpWaitingMessages as
  belt-and-braces), normalizes each event to the exact dict shape PullSDK emits
  ({eventId, doorId, eventType, cardNo, eventTime, table, rawRow}) and enqueues it.
  ``poll_rtlog_once()`` is a NON-BLOCKING drain of that queue, so UltraDeviceWorker's
  loop, watchdog, dedupe, cooldown, popup/history plumbing run UNCHANGED.
* Identity: the terminal reports the user PIN (EnrollNumber) for BOTH fingerprint
  and card verifies. Downstream (cooldown, member resolution, history, popup photo)
  keys on the RFID card number, so the driver keeps a pin->card map (refreshed from
  the local sync DB on connect and at every roster push) and emits cardNo. Unknown
  pins emit "ZKPIN:<pin>" plus a telemetry warn — never dropped silently.
* Direction: this gym runs whole-device lanes (2 entry + 1 exit). The device's door
  preset direction (synced from the backend) is stamped into rawRow["direction"] so
  the existing attendance uploader carries it with zero changes.

HARDWARE-GATED (unverified until on-site day — see the plan's GATE table): in-process
COM viability, event field semantics, ACUnlock support (the door command IS issued —
the switch is ON for the family by operator decision, 2026-09-04 — but whether the
MB2000's relay physically releases the turnstile stays UNVERIFIED until script 12/9
passes on site), template portability, card number space.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("zkapp")

try:  # optional import so unit tests / non-Windows tooling can import this module
    from app.core import telemetry as _tel
except Exception:  # pragma: no cover
    class _TelStub:
        def event(self, *a, **k): ...
        def warn(self, *a, **k): ...
    _tel = _TelStub()  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# zkemkeeper RegEvent bitmask: bit 1 = OnAttTransaction(Ex) (TFT SDK manual).
_REGEVENT_ATT_TRANSACTION = 1

# VerifyMethod -> scan-mode hint. The value space SHIFTS between the terminal's
# normal mode (0=password, 1=fingerprint, 2=card) and multi-verify modes
# (0=FP, 1=PIN, 2=PW, 3=RF/card, ...). Both tables are mapped defensively and the
# raw value is always kept in rawRow for the on-site GATE 2 fidelity table.
_VERIFY_METHOD_SCAN_MODE: Dict[int, str] = {
    0: "PASSWORD",       # normal: password | multi-verify: FP (ambiguous — raw kept)
    1: "FINGERPRINT",    # normal: fingerprint
    2: "RFID_CARD",      # normal: card
    3: "RFID_CARD",      # multi-verify: RF card
}

_DEFAULT_CMD_TIMEOUT_SEC = 10.0
_CONNECT_TIMEOUT_SEC = 20.0
_EVENT_QUEUE_MAX = 4096
_STA_LOOP_IDLE_SLEEP_SEC = 0.25
# How many members to trace call-by-call at the start of a roster push.
_PUSH_TRACE_MEMBERS = 3
# Template uploads to trace, counted SEPARATELY and carried across chunks. The
# first members of a roster often have no fingerprints at all, so a member-only
# budget can be exhausted before a single SetUserTmpExStr is ever reached -- which
# is exactly how the wedging call stayed invisible in the field.
_PUSH_TRACE_TEMPLATES = 5
# Give up on the roster after this many chunks wedge back to back. One bad member
# must not block the other 940; a terminal that wedges on everything must not be
# hammered for 95 chunks (each wedge leaks an unkillable STA thread).
_PUSH_MAX_CONSECUTIVE_WEDGES = 3
# Members per STA command during a roster push. The STA loop is strictly
# sequential, so ONE command == a window where no COM message is pumped and no
# device event is drained. Chunking bounds that window, lets live events keep
# flowing during a multi-minute push, and caps what a wedged call can cost.
_PUSH_CHUNK_MEMBERS = 10

# MB2000 user-ID space is 9 digits (vendor datasheet). Longer pins would be
# silently truncated/rejected by the terminal — guard at push time.
_MAX_PIN_DIGITS = 9


def _digits_only(v: Any) -> str:
    return "".join(ch for ch in str(v or "") if ch.isdigit())


_OPEN_DOOR_ENV_VAR = "MONCLUB_ZK_STANDALONE_OPEN_DOOR"
# Key under which the persisted per-device switch (db.device_local_settings, projected
# by db.list_sync_devices_payload / get_sync_device_payload) travels in the device
# payload. None/absent = "not set" -> family default.
_OPEN_DOOR_PAYLOAD_KEY = "openDoorEnabled"
# Operator decision 2026-09-04: the door command is ON for the whole standalone
# family unless switched OFF per device (Devices page control panel) or forced by
# the env var. Field 2026-08-30: the desk pressed "open" 13x in ten seconds and was
# refused every time (DOOR_OPEN result=409_unsupported) while this shipped OFF.
# Whether ACUnlock physically releases THIS turnstile is still UNVERIFIED -- the
# software must be correct and loud; the proof stays on site (script 12/9).
_OPEN_DOOR_FAMILY_DEFAULT = True
# ACUnlock takes DECISECONDS. 1..600 ds == 0.1..60 s is the app's own ceiling -- the
# same 1-60 s the local API clamps pulseSeconds to and PullSDKDevice clamps its
# seconds to. The firmware's true maximum is UNKNOWN (not in the guide, not in any
# vendor document in this repo); nothing here claims one.
_ACUNLOCK_DELAY_DS_MIN = 1
_ACUNLOCK_DELAY_DS_MAX = 600
# Closed vocabulary of the DOOR_OPEN telemetry results this driver emits.
_DOOR_OPEN_RESULTS = frozenset({"ok", "false", "exception", "timeout", "unsupported"})
_ENV_TRUE_WORDS = ("1", "true", "yes", "on", "all")
_ENV_FALSE_WORDS = ("0", "false", "no", "off", "none")


def _open_door_env_override(device_id: int) -> Optional[bool]:
    """Per-machine override of the door switch, or None when the env var is unset.

    MONCLUB_ZK_STANDALONE_OPEN_DOOR accepts:
      "1" / "true" / "yes" / "on" / "all"   -> force ON for every standalone terminal
      "0" / "false" / "no" / "off" / "none" -> force OFF for every standalone terminal
      "8" or "8,12"                         -> allowlist: ON for those ids, OFF for the rest
    Unset/blank -> no override. Anything else is logged and IGNORED (never read as
    ON or OFF). Parsed per call so an operator can flip it without restarting.
    """
    raw = str(os.environ.get(_OPEN_DOOR_ENV_VAR, "") or "").strip().lower()
    if not raw:
        return None
    if raw in _ENV_TRUE_WORDS:
        return True
    if raw in _ENV_FALSE_WORDS:
        return False
    parts = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
    if parts and all(p.isdigit() for p in parts):
        return any(int(p) == int(device_id) for p in parts)
    logger.warning(
        "%s=%r not understood -- ignored (expected on/off or a device-id list)",
        _OPEN_DOOR_ENV_VAR, raw,
    )
    return None


def _coerce_switch(v: Any) -> Optional[bool]:
    """Persisted switch value (bool / 0-1 / 'true'-'false') -> bool, or None when unset."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(int(v))
    s = str(v).strip().lower()
    if s in _ENV_TRUE_WORDS:
        return True
    if s in _ENV_FALSE_WORDS:
        return False
    return None


def resolve_open_door_switch(device_id: int, payload: Dict[str, Any] | None) -> tuple[bool, str]:
    """Effective door switch for one device -> (enabled, source).

    source: "env"     -> MONCLUB_ZK_STANDALONE_OPEN_DOOR decided (wins over everything)
            "local"   -> the persisted per-device switch (payload["openDoorEnabled"])
            "default" -> nothing set: _OPEN_DOOR_FAMILY_DEFAULT
    """
    env = _open_door_env_override(device_id)
    if env is not None:
        return bool(env), "env"
    local = _coerce_switch((payload or {}).get(_OPEN_DOOR_PAYLOAD_KEY))
    if local is not None:
        return bool(local), "local"
    return bool(_OPEN_DOOR_FAMILY_DEFAULT), "default"


def _pulse_ms_to_delay_ds(pulse_time_ms: Any) -> tuple[int, bool]:
    """Pulse (ms) -> ACUnlock deciseconds clamped to the app ceiling; (ds, clamped)."""
    try:
        raw = int(round(int(pulse_time_ms) / 100.0))
    except (TypeError, ValueError):
        raw = 0
    ds = max(_ACUNLOCK_DELAY_DS_MIN, min(_ACUNLOCK_DELAY_DS_MAX, raw))
    return ds, ds != raw


def verify_method_to_scan_mode(verify_method: Any) -> str:
    try:
        vm = int(verify_method)
    except (TypeError, ValueError):
        return "UNKNOWN"
    return _VERIFY_METHOD_SCAN_MODE.get(vm, "UNKNOWN")


def normalize_att_event(
    *,
    enroll_number: Any,
    is_invalid: Any,
    att_state: Any,
    verify_method: Any,
    y: int, mo: int, d: int, h: int, mi: int, s: int,
    work_code: Any = 0,
    seq: int = 0,
    pin_to_card: Optional[Dict[str, str]] = None,
    direction: Optional[str] = None,
    device_id: Any = None,
) -> Dict[str, Any]:
    """Map one OnAttTransactionEx into the NormalizedEvent dict PullSDK emits.

    eventType "0" == ALLOW for UltraDeviceWorker._process_event; any other value
    lands on its DENY branch (fail-safe for unknown semantics until GATE 2).
    """
    pin = str(enroll_number or "").strip()
    try:
        invalid = int(is_invalid or 0) != 0
    except (TypeError, ValueError):
        invalid = True

    card = (pin_to_card or {}).get(pin, "")
    if not card:
        card = f"ZKPIN:{pin}" if pin else ""

    event_time = f"{int(y):04d}-{int(mo):02d}-{int(d):02d} {int(h):02d}:{int(mi):02d}:{int(s):02d}"
    evtype = "0" if not invalid else "zkem_invalid"
    raw: Dict[str, Any] = {
        "pin": pin,
        "attState": att_state,
        "verifyMethod": verify_method,
        "workCode": work_code,
        "scan_mode_hint": verify_method_to_scan_mode(verify_method),
    }
    if direction:
        # Consumed by device_attendance._direction_from_raw (reads "direction" first),
        # so entry-vs-exit reaches the backend with zero uploader changes.
        raw["direction"] = str(direction).strip().upper()
    return {
        "eventId": f"{event_time}|{card}|{evtype}|1|{pin}|zkem|{seq}",
        "doorId": 1,  # one door per standalone terminal
        "eventType": evtype,
        "cardNo": card,
        "eventTime": event_time,
        "table": "zkem",
        "rawRow": raw,
        # device_id only for logging context; _process_event doesn't read it
        "_deviceId": device_id,
    }


class _Cmd:
    __slots__ = ("op", "args", "done", "result", "error")

    def __init__(self, op: str, args: Dict[str, Any] | None = None):
        self.op = op
        self.args = args or {}
        self.done = threading.Event()
        self.result: Any = None
        self.error: Optional[BaseException] = None


def _make_default_com_factory(driver: "ZKStandaloneDevice") -> Callable[[], Any]:
    """Build the real-COM factory for one driver. MUST be invoked on the STA thread.

    Uses DispatchWithEvents so the terminal's real-time OnAttTransactionEx lands in
    a sink bound (via closure) to this driver's _on_att_event — a plain Dispatch
    would register no sink and events would silently never arrive. Lazy-imports
    pywin32 so this module stays importable in tests/CI without COM. Tries the
    ProgIDs seen in the wild ('zkemkeeper.ZKEM' / 'zkemkeeper.CZKEM').
    """

    def _factory() -> Any:  # pragma: no cover - real COM only
        import win32com.client as w32

        class _AttEvents:
            # Signature per the TFT SDK manual; called by COM on the STA thread.
            def OnAttTransactionEx(self, EnrollNumber, IsInValid, AttState, VerifyMethod,
                                   Year, Month, Day, Hour, Minute, Second, WorkCode=0):
                try:
                    driver._on_att_event(EnrollNumber, IsInValid, AttState, VerifyMethod,
                                         Year, Month, Day, Hour, Minute, Second, WorkCode)
                except Exception:
                    logger.exception("%s sink handler error", driver._prefix)

        last_exc: Optional[Exception] = None
        for prog_id in ("zkemkeeper.ZKEM", "zkemkeeper.CZKEM", "zkemkeeper.ZKEM.1"):
            try:
                return w32.DispatchWithEvents(prog_id, _AttEvents)
            except Exception as exc:
                last_exc = exc
        raise RuntimeError(f"zkemkeeper COM object could not be created: {last_exc}")

    return _factory


class ZKStandaloneDevice:
    """DeviceDriver implementation for zkemkeeper-family standalone terminals."""

    # ---- capability flags (D8) ----
    owns_event_source = True
    supports_device_params = False
    # Whether this driver may issue ACUnlock. _do_open_door implements the real
    # call; the flag only decides whether the app is ALLOWED to make it. The class
    # default is the family default (operator decision 2026-09-04: ON). Every
    # instance re-resolves it in __init__ via resolve_open_door_switch():
    #   env MONCLUB_ZK_STANDALONE_OPEN_DOOR  >  persisted per-device switch
    #   (payload["openDoorEnabled"], Devices page control panel)  >  this default
    # and the operator can flip it live through apply_open_door_switch(). Whether
    # the MB2000's relay physically releases the turnstile on ACUnlock stays
    # UNVERIFIED until tools/mb2000_scripts 12/9 pass on site -- so every call is
    # logged and emits a DOOR_OPEN telemetry result; a silent no-op is impossible.
    supports_open_door = _OPEN_DOOR_FAMILY_DEFAULT
    # The PullSDK "transaction" table has no analogue here: this driver reads
    # events through the COM event sink, not a table. read_transaction_rows /
    # get_table_count / delete_all_transaction_rows are all inert, so callers
    # must SKIP this device rather than act on their return values.
    supports_transaction_table = False

    def __init__(self, device_payload: Dict[str, Any], logger_inst: Any = None, *, logger: Any = None):
        # accept both kw spellings so get_driver(logger=...) works
        self.logger = logger or logger_inst or logging.getLogger("ZKStandaloneDevice")
        self.payload = device_payload or {}

        def _pick(keys: List[str], default: Any = "") -> Any:
            for k in keys:
                v = self.payload.get(k)
                if v not in (None, ""):
                    return v
            return default

        self.device_id = int(_pick(["id"], 0) or 0)
        self.name = str(_pick(["name"], f"device-{self.device_id}"))
        self.ip = str(_pick(["ip", "ipAddress", "ip_address", "host"], ""))
        self.port = int(_pick(["port", "portNumber", "port_number"], 4370) or 4370)
        # zkemkeeper comm key ("SetCommPassword") — reuse the device password field.
        self.comm_key = str(_pick(["password", "commKey", "comm_key"], "") or "")

        # Generation fence for the STA thread. zkemkeeper has no call timeout, so a
        # terminal that stops answering wedges the thread forever. We cannot
        # interrupt a blocked COM call, but we CAN abandon the thread and build a
        # fresh one; the generation stops the zombie from ever servicing commands
        # again if it later unblocks.
        self._sta_gen = 0
        # Terminal fingerprint algorithm version, filled on connect (see _read_fp_version).
        self._device_fp_version = ""
        # Terminal occupancy (users / fingerprints / capacities), filled on connect.
        self._device_status: Dict[str, int] = {}
        self._prefix = f"[ZKEM:{self.device_id}]"
        self._tel_wid = f"ZKEM:{self.device_id}"

        # Effective door switch for THIS device (env > persisted local > family
        # default), announced at construction -- i.e. at every worker connect -- so
        # the log always shows which value was in force and what decided it.
        self._open_door_source = "default"
        self.apply_open_door_switch(self.payload.get(_OPEN_DOOR_PAYLOAD_KEY))

        # Whole-device lane direction from the synced door preset (D7).
        self._direction = self._direction_from_presets(self.payload)

        # pin -> RFID card map (D4). Refreshed on connect + at every push_roster.
        self._pin_to_card: Dict[str, str] = {}
        self._pin_map_lock = threading.Lock()

        self._evt_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=_EVENT_QUEUE_MAX)
        self._cmd_queue: "queue.Queue[_Cmd]" = queue.Queue()
        self._stop_evt = threading.Event()
        self._sta_thread: Optional[threading.Thread] = None
        self._connected_flag = threading.Event()
        self._event_seq = 0
        self._unmapped_pins_warned: set[str] = set()

        # Injection point for tests / the sidecar fallback: a callable returning
        # an object exposing the zkemkeeper method surface. Real COM (with the
        # event sink bound to this driver) by default.
        self._com_factory: Callable[[], Any] = _make_default_com_factory(self)
        # pythoncom shim (real by default; tests replace with a no-op)
        self._co_init, self._co_uninit, self._pump = self._default_com_runtime()

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _default_com_runtime():
        def _co_init():
            import pythoncom
            pythoncom.CoInitialize()

        def _co_uninit():
            import pythoncom
            pythoncom.CoUninitialize()

        def _pump():
            import pythoncom
            pythoncom.PumpWaitingMessages()

        return _co_init, _co_uninit, _pump

    @staticmethod
    def _direction_from_presets(payload: Dict[str, Any]) -> Optional[str]:
        presets = payload.get("doorPresets") or payload.get("door_presets") or []
        if isinstance(presets, list):
            for p in presets:
                if isinstance(p, dict):
                    d = str(p.get("direction") or "").strip().upper()
                    if d in ("IN", "OUT"):
                        return d
        return None

    def _refresh_pin_card_map(self) -> None:
        """Rebuild pin->card from the local sync DB (best-effort, never raises).

        Pin convention mirrors device_sync._filter_users_for_device: prefer
        activeMembershipId, fall back to userId. Card = digits of firstCardId.
        """
        try:
            from app.core.db import get_conn  # lazy: keeps sdk importable standalone

            mapping: Dict[str, str] = {}
            with get_conn() as conn:
                rows = conn.execute(
                    "SELECT user_id, active_membership_id, first_card_id FROM sync_users"
                ).fetchall()
            for r in rows:
                d = dict(r)
                pin = str(d.get("active_membership_id") or d.get("user_id") or "").strip()
                card = _digits_only(d.get("first_card_id"))
                if pin and card:
                    mapping[pin] = card
            with self._pin_map_lock:
                self._pin_to_card = mapping
            self.logger.info("%s pin->card map refreshed: %d entries", self._prefix, len(mapping))
        except Exception as exc:
            self.logger.warning("%s pin->card map refresh failed: %s", self._prefix, exc)

    def _pin_card_snapshot(self) -> Dict[str, str]:
        with self._pin_map_lock:
            return dict(self._pin_to_card)

    # ------------------------------------------------------------------ #
    # DeviceDriver surface — lifecycle
    # ------------------------------------------------------------------ #

    @property
    def is_connected(self) -> bool:
        return self._connected_flag.is_set()

    def ensure_connected(self) -> bool:
        return self.is_connected or self.connect()

    def connect(self) -> bool:
        """Start the STA thread (if needed) and connect, with a hard deadline."""
        self._refresh_pin_card_map()
        self._ensure_sta_thread()
        try:
            res = self._call("connect", timeout=_CONNECT_TIMEOUT_SEC)
            return bool(res)
        except Exception as exc:
            self.logger.warning("%s connect failed: %s", self._prefix, exc)
            return False

    def disconnect(self) -> None:
        """Stop pumping, disconnect, and join the STA thread (bounded)."""
        self._stop_evt.set()
        t = self._sta_thread
        if t is not None and t.is_alive():
            t.join(timeout=_DEFAULT_CMD_TIMEOUT_SEC)
            if t.is_alive():  # pragma: no cover - defensive
                self.logger.error("%s STA thread did not stop within deadline", self._prefix)
        self._sta_thread = None
        self._connected_flag.clear()

    # explicit event-source lifecycle (D3): connect() already starts the pump;
    # start/stop exist so engines can treat push drivers uniformly.
    def start(self) -> None:
        self.ensure_connected()

    def stop(self) -> None:
        self.disconnect()

    # ------------------------------------------------------------------ #
    # DeviceDriver surface — events
    # ------------------------------------------------------------------ #

    def poll_rtlog_once(self, max_events: int = 64) -> List[Dict[str, Any]]:
        """Non-blocking drain of events the STA thread has already normalized."""
        out: List[Dict[str, Any]] = []
        for _ in range(max_events):
            try:
                out.append(self._evt_queue.get_nowait())
            except queue.Empty:
                break
        return out

    # ------------------------------------------------------------------ #
    # DeviceDriver surface — commands (all funneled to the STA thread, D5)
    # ------------------------------------------------------------------ #

    def apply_open_door_switch(self, local_value: Any) -> tuple[bool, str]:
        """Re-resolve the door switch (env > local > default) and apply it live.

        Called at construction with the payload's persisted value, and by the
        local API when the operator flips the switch -- no reconnect needed.
        Returns (enabled, source); logs and emits DOOR_OPEN_SWITCH telemetry.
        """
        enabled, source = resolve_open_door_switch(
            self.device_id, {_OPEN_DOOR_PAYLOAD_KEY: local_value},
        )
        self.supports_open_door = bool(enabled)
        self._open_door_source = source
        self.logger.log(
            logging.WARNING if (enabled and source == "env") else logging.INFO,
            "%s open_door switch: enabled=%s source=%s -- ACUnlock(1, ds) %s; relay "
            "release on this hardware is UNVERIFIED until script 12/9 passes on site",
            self._prefix, enabled, source,
            "will be issued" if enabled else "will be refused (HTTP 409)",
        )
        try:
            _tel.event("DOOR_OPEN_SWITCH", worker=self._tel_wid, enabled=bool(enabled), source=source)
        except Exception:
            pass
        return bool(enabled), source

    def _door_open_event(self, result: str, *, door_id: Any, delay_ds: int, dur_ms: float,
                         clamped: bool, err: str | None = None) -> None:
        """One DOOR_OPEN telemetry line per attempt; result is from _DOOR_OPEN_RESULTS."""
        assert result in _DOOR_OPEN_RESULTS, result
        fields = dict(
            worker=self._tel_wid, door=door_id, result=result, delay_ds=int(delay_ds),
            dur_ms=round(float(dur_ms)), clamped=True if clamped else None,
            source=getattr(self, "_open_door_source", None), err=err,
        )
        try:
            (_tel.event if result == "ok" else _tel.warn)("DOOR_OPEN", **fields)
        except Exception:
            pass

    def open_door(self, *, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> bool:
        """ACUnlock(1, deciseconds) on the STA thread. Never raises; never silent.

        Every outcome is logged AND emitted as DOOR_OPEN telemetry with a result in
        _DOOR_OPEN_RESULTS plus delay_ds and dur_ms. The command goes through _call()
        like every other STA command, so the generation fence and wedge recovery
        apply unchanged: a COM call that never returns is abandoned after the
        deadline (result=timeout, ZKEM_STA_WEDGED) and the next connect rebuilds the
        thread. door_id is informational -- the MB2000 has one lock relay and the
        machine number is always 1.
        """
        delay_ds, clamped = _pulse_ms_to_delay_ds(pulse_time_ms)
        if clamped:
            self.logger.warning(
                "%s open_door: pulse %sms is outside %d..%d ds -> clamped to %d ds",
                self._prefix, pulse_time_ms,
                _ACUNLOCK_DELAY_DS_MIN, _ACUNLOCK_DELAY_DS_MAX, delay_ds,
            )
        if not self.supports_open_door:
            self.logger.warning(
                "%s open_door REFUSED: switch OFF (source=%s) -- no ACUnlock issued",
                self._prefix, getattr(self, "_open_door_source", "?"),
            )
            self._door_open_event("unsupported", door_id=door_id, delay_ds=delay_ds,
                                  dur_ms=0.0, clamped=clamped)
            return False
        t0 = time.monotonic()
        try:
            ok = bool(self._call(
                "open_door", args={"delay_ds": delay_ds},
                timeout=max(2.0, timeout_ms / 1000.0),
            ))
        except TimeoutError as exc:
            dur_ms = (time.monotonic() - t0) * 1000.0
            self.logger.error(
                "%s open_door TIMEOUT after %.0f ms: %s -- STA thread abandoned (gen=%d), "
                "the next connect rebuilds it", self._prefix, dur_ms, exc, self._sta_gen,
            )
            self._door_open_event("timeout", door_id=door_id, delay_ds=delay_ds,
                                  dur_ms=dur_ms, clamped=clamped, err=type(exc).__name__)
            return False
        except Exception as exc:
            dur_ms = (time.monotonic() - t0) * 1000.0
            self.logger.warning("%s open_door EXCEPTION after %.0f ms: %s", self._prefix, dur_ms, exc)
            self._door_open_event("exception", door_id=door_id, delay_ds=delay_ds,
                                  dur_ms=dur_ms, clamped=clamped, err=type(exc).__name__)
            return False
        dur_ms = (time.monotonic() - t0) * 1000.0
        if ok:
            self.logger.info("%s ACUnlock(1, %d) -> True in %.0f ms (door=%s)",
                             self._prefix, delay_ds, dur_ms, door_id)
            self._door_open_event("ok", door_id=door_id, delay_ds=delay_ds,
                                  dur_ms=dur_ms, clamped=clamped)
        else:
            self.logger.warning(
                "%s ACUnlock(1, %d) -> False in %.0f ms (door=%s) -- the terminal refused "
                "the door command, or the driver is not connected",
                self._prefix, delay_ds, dur_ms, door_id,
            )
            self._door_open_event("false", door_id=door_id, delay_ds=delay_ds,
                                  dur_ms=dur_ms, clamped=clamped)
        return ok

    def get_device_time(self) -> Optional[float]:
        try:
            return self._call("get_time", timeout=_DEFAULT_CMD_TIMEOUT_SEC)
        except Exception:
            return None

    def set_device_time(self, epoch: float) -> bool:
        try:
            return bool(self._call("set_time", args={"epoch": float(epoch)},
                                   timeout=_DEFAULT_CMD_TIMEOUT_SEC))
        except Exception:
            return False

    def push_roster(
        self,
        users: List[Dict[str, Any]],
        templates_by_pin: Dict[str, List[Dict[str, Any]]] | None = None,
        *,
        remove_fingers_by_pin: Dict[str, List[int]] | None = None,
        bracket_enable_device: bool = False,
        timeout_sec: float = 600.0,
    ) -> Dict[str, Any]:
        """Push users (+ fingerprint templates) to the terminal (D6).

        users: [{"pin": str, "name": str, "card": str}] — pins must be numeric,
        <= 9 digits (MB2000 user-ID space); violations are skipped + counted.
        templates_by_pin: pin -> [{fingerId, templateVersion, templateData, templateSize}]
        (the protocol-neutral output of DeviceSyncEngine._collect_templates_for_pin).
        bracket_enable_device: ONLY the 22:00/manual full reconcile may set this —
        EnableDevice(False) locks the terminal UI and it is the gym's sole verifier.
        """
        users = list(users or [])
        templates_by_pin = templates_by_pin or {}
        remove_fingers_by_pin = remove_fingers_by_pin or {}

        # The bracketed full reconcile must hold EnableDevice(False) across the
        # WHOLE roster, so it stays a single command (its own deliberate window).
        # Everything else is chunked.
        if bracket_enable_device:
            chunks = [users] if users else []
        else:
            chunks = [users[i:i + _PUSH_CHUNK_MEMBERS]
                      for i in range(0, len(users), _PUSH_CHUNK_MEMBERS)] or [[]]

        def chunk_pins(part: List[Dict[str, Any]]) -> str:
            if not part:
                return "?"
            return f"{part[0].get('pin')}..{part[-1].get('pin')}"

        agg: Dict[str, Any] = {"ok": True, "pushed": 0, "failed": 0,
                               "templates_failed": 0, "skipped_pin": 0,
                               # Slot clears issued vs confirmed by the terminal.
                               # A revocation that did not land shows up here as a
                               # gap, and nowhere else.
                               "del_attempted": 0, "del_ok": 0,
                               "chunks_wedged": 0, "errors": [],
                               # Every pin NOT confirmed on the terminal: per-member
                               # failures reported by the chunk, plus every member of
                               # a chunk that wedged (none of those were confirmed).
                               "failed_pins": []}
        # Telemetry-only accumulators (never read by the engine).
        agg_failed_reasons: Dict[str, str] = {}
        agg_tpl_attempted = 0
        agg_tpl_ok = 0
        agg_del_attempted = 0
        agg_del_ok = 0
        consecutive_wedges = 0
        total = len(users)
        # Trace budgets span the WHOLE roster, not one chunk.
        trace_members_left = _PUSH_TRACE_MEMBERS
        trace_templates_left = _PUSH_TRACE_TEMPLATES
        t_start = time.monotonic()
        t_last_log = t_start
        self.logger.info(
            "%s push_roster START users=%d templates_for=%d chunks=%d bracket=%s",
            self._prefix, total, len(templates_by_pin), len(chunks), bool(bracket_enable_device),
        )
        for idx, part in enumerate(chunks, 1):
            # Bound each command. A wedged terminal now costs ONE chunk and is
            # detected in seconds, instead of hanging the worker for the full
            # timeout and leaving the device dead until the app restarts.
            if bracket_enable_device:
                chunk_timeout = timeout_sec
            else:
                # ~1-2s per member on real hardware, so 5s each is ~3x headroom;
                # the 45s floor protects a small final chunk. The caller's
                # timeout_sec is a HARD cap so this can never exceed it.
                chunk_timeout = min(timeout_sec, max(45.0, len(part) * 5.0))
            try:
                res = self._call(
                    "push_roster",
                    args={
                        "users": part,
                        "templates_by_pin": templates_by_pin,
                        "remove_fingers_by_pin": remove_fingers_by_pin,
                        "bracket": bool(bracket_enable_device),
                        "trace_members": trace_members_left,
                        "trace_templates": trace_templates_left,
                    },
                    timeout=chunk_timeout,
                ) or {}
            except Exception as exc:
                # A chunk wedged. _call has already abandoned the STA thread, so
                # rebuild the connection and CARRY ON with the next chunk.
                #
                # Aborting the whole roster here meant one bad member blocked all
                # 950: the retry restarted at chunk 1, wedged at the same chunk,
                # and the gym never got more than the first 10 members. Skipping
                # the bad chunk delivers the other ~940 and names the ones missed.
                agg["ok"] = False
                agg["error"] = str(exc)
                agg["chunks_wedged"] += 1
                consecutive_wedges += 1
                # Nothing in a wedged chunk is confirmed -- the STA thread died mid-way
                # and no per-member result came back. Every one of its pins must be
                # retried by the next sync.
                for _u in part:
                    _p = str(_u.get("pin") or "").strip()
                    if _p and _p not in agg["failed_pins"]:
                        agg["failed_pins"].append(_p)
                if len(agg["errors"]) < 5:
                    agg["errors"].append(f"chunk {idx}/{len(chunks)} (pins {chunk_pins(part)}): {exc}")
                self.logger.warning(
                    "%s push_roster chunk %d/%d WEDGED (pins %s) after %d pushed: %s",
                    self._prefix, idx, len(chunks), chunk_pins(part), agg["pushed"], exc,
                )
                # Named twin of the warning above. _abandon_sta_thread already emits
                # ZKEM_STA_WEDGED with the abandon reason; this one names the CHUNK
                # and the members lost with it, which that event cannot know.
                try:
                    _tel.warn(
                        "ZKEM_PUSH_WEDGED", worker=self._tel_wid, chunk=idx,
                        chunks=len(chunks), members=len(part),
                        consecutive=consecutive_wedges,
                        pushed_before=agg["pushed"], err=str(exc)[:120],
                    )
                except Exception:
                    pass
                if consecutive_wedges >= _PUSH_MAX_CONSECUTIVE_WEDGES:
                    self.logger.error(
                        "%s push_roster ABANDONED after %d consecutive wedged chunks "
                        "-- the terminal is not accepting this roster",
                        self._prefix, consecutive_wedges,
                    )
                    agg["errors"].append(
                        f"abandoned after {consecutive_wedges} consecutive wedged chunks")
                    try:
                        _tel.warn("ZKEM_PUSH_ABANDONED", worker=self._tel_wid,
                                  consecutive=consecutive_wedges, chunk=idx,
                                  chunks=len(chunks), pushed=agg["pushed"])
                    except Exception:
                        pass
                    break
                # Rebuild the link before the next chunk; without this every
                # remaining _call raises "STA thread not running".
                try:
                    if not self.connect():
                        self.logger.warning(
                            "%s push_roster: reconnect failed after a wedge -- stopping",
                            self._prefix,
                        )
                        try:
                            _tel.warn("ZKEM_PUSH_RECONNECT", worker=self._tel_wid,
                                      chunk=idx, ok=False, err="connect_falsy")
                        except Exception:
                            pass
                        break
                except Exception:
                    self.logger.warning(
                        "%s push_roster: reconnect raised after a wedge -- stopping",
                        self._prefix, exc_info=True,
                    )
                    try:
                        _tel.warn("ZKEM_PUSH_RECONNECT", worker=self._tel_wid,
                                  chunk=idx, ok=False, err="connect_raised")
                    except Exception:
                        pass
                    break
                try:
                    _tel.event("ZKEM_PUSH_RECONNECT", worker=self._tel_wid,
                               chunk=idx, ok=True)
                except Exception:
                    pass
                continue
            consecutive_wedges = 0
            agg["pushed"] += int(res.get("pushed") or 0)
            agg["failed"] += int(res.get("failed") or 0)
            agg["skipped_pin"] += int(res.get("skipped_pin") or 0)
            agg["templates_failed"] += int(res.get("templates_failed") or 0)
            agg["del_attempted"] += int(res.get("del_attempted") or 0)
            agg["del_ok"] += int(res.get("del_ok") or 0)
            _chunk_failed = res.get("failed_pins")
            if _chunk_failed is None and not res.get("ok", True):
                # A failed chunk that cannot say WHICH pins failed confirmed none of
                # them. Anything less would let the engine record unpushed pins as
                # synced and never retry them.
                _chunk_failed = [str(u.get("pin") or "").strip() for u in part]
            for _p in (_chunk_failed or []):
                _p = str(_p or "").strip()
                if _p and _p not in agg["failed_pins"]:
                    agg["failed_pins"].append(_p)
            # One telemetry line per chunk (~93 for a full 928-member roster), which
            # is where per-pin detail is aggregated to. Per-pin lines are deliberately
            # NOT emitted inside the member loop: see the note in _do_push_roster.
            try:
                for _fp, _fr in (res.get("failed_reasons") or {}).items():
                    agg_failed_reasons.setdefault(str(_fp), str(_fr))
                agg_tpl_attempted += int(res.get("tpl_attempted") or 0)
                agg_tpl_ok += int(res.get("tpl_ok") or 0)
                agg_del_attempted += int(res.get("del_attempted") or 0)
                agg_del_ok += int(res.get("del_ok") or 0)
                _tel.event(
                    "ZKEM_PUSH_CHUNK", worker=self._tel_wid, chunk=idx, chunks=len(chunks),
                    members=len(part),
                    first_pin=str((part or [{}])[0].get("pin") or "") or None,
                    last_pin=str((part or [{}])[-1].get("pin") or "") or None,
                    pushed=res.get("pushed"), failed=res.get("failed"),
                    templates_failed=res.get("templates_failed"),
                    tpl_attempted=res.get("tpl_attempted"), tpl_ok=res.get("tpl_ok"),
                    # op= spelling, never the literal SDK symbol: §10.4 mandates
                    # greps with expected match counts and a literal in a log value
                    # would inflate them into a false MUST-NOT-CALL alarm.
                    op="del_user_tmp_ext",
                    del_attempted=res.get("del_attempted"), del_ok=res.get("del_ok"),
                    dur_ms=res.get("chunk_ms"), ok=bool(res.get("ok", True)),
                )
            except Exception:
                pass
            trace_members_left = int(res.get("trace_members_left", trace_members_left) or 0)
            trace_templates_left = int(res.get("trace_templates_left", trace_templates_left) or 0)
            for e in (res.get("errors") or [])[:5]:
                if len(agg["errors"]) < 5:
                    agg["errors"].append(e)
            if not res.get("ok", True):
                agg["ok"] = False

            # Cumulative progress, throttled. This is the line that tells an
            # operator "moving" vs "wedged" -- the whole reason the first field
            # incident was unreadable.
            done = agg["pushed"] + agg["failed"] + agg["skipped_pin"]
            now = time.monotonic()
            if (now - t_last_log >= 10.0 or idx == len(chunks)) and done:
                t_last_log = now
                elapsed = now - t_start
                rate = done / elapsed if elapsed > 0 else 0.0
                eta = (max(total - done, 0) / rate) if rate > 0 else float("nan")
                self.logger.info(
                    "%s push_roster progress %d/%d (%.0f%%) ok=%d failed=%d skipped=%d "
                    "%.1f users/s elapsed=%.0fs eta=%.0fs",
                    self._prefix, done, total, (100.0 * done / total) if total else 100.0,
                    agg["pushed"], agg["failed"], agg["skipped_pin"], rate, elapsed, eta,
                )

        self.logger.info(
            "%s push_roster DONE ok=%s pushed=%d failed=%d templates_failed=%d "
            "skipped_pin=%d chunks_wedged=%d in %.0fs%s",
            self._prefix, agg["ok"], agg["pushed"], agg["failed"],
            agg["templates_failed"], agg["skipped_pin"], agg["chunks_wedged"],
            time.monotonic() - t_start,
            (" errors=" + "; ".join(agg["errors"][:5])) if agg["errors"] else "",
        )
        # One telemetry event for the whole roster, not one per chunk.
        try:
            _tel.event("ZKEM_PUSH_DONE", worker=self._tel_wid, pushed=agg["pushed"],
                       failed=agg["failed"], skipped_pin=agg["skipped_pin"],
                       ok=bool(agg["ok"]), chunks=len(chunks),
                       tpl_attempted=agg_tpl_attempted, tpl_ok=agg_tpl_ok,
                       tpl_failed=agg["templates_failed"],
                       op="del_user_tmp_ext",
                       del_attempted=agg_del_attempted, del_ok=agg_del_ok)
            # WHICH pins did not land, and WHY. One line, so "was pin X pushed?"
            # is a single grep. A pin with no recorded reason came from a WEDGED
            # chunk -- nothing in that chunk was confirmed -- which is itself the
            # answer, so it is reported as such rather than left blank.
            if agg["failed_pins"]:
                _reasons = {
                    str(p): agg_failed_reasons.get(str(p), "chunk_wedged_or_unconfirmed")
                    for p in agg["failed_pins"]
                }
                _by_reason: Dict[str, int] = {}
                for _r in _reasons.values():
                    _by_reason[_r] = _by_reason.get(_r, 0) + 1
                _tel.warn(
                    "ZKEM_PUSH_FAILED_PINS", worker=self._tel_wid,
                    count=len(agg["failed_pins"]), by_reason=_by_reason,
                    pins=";".join(f"{p}={r}" for p, r in list(_reasons.items())[:40]),
                    truncated=(len(_reasons) > 40) or None,
                )
        except Exception:
            pass
        # keep the event-side identity map in step with what the device now holds
        self._refresh_pin_card_map()
        return agg

    def list_device_users(self, *, timeout_sec: float = 60.0) -> Dict[str, Any]:
        """Enumerate ALL users currently on the terminal (for the MIRROR policy).

        Returns {'ok': bool, 'users': [{'pin','name','card','enabled'}], 'error'?: str}.
        ok=False means the enumeration FAILED or was incomplete — the MIRROR reconcile
        MUST treat ok=False as "unknown", NEVER as "empty device" (that would delete
        every member).
        """
        try:
            return self._call("list_users", timeout=timeout_sec)
        except Exception as exc:
            self.logger.warning("%s list_device_users failed: %s", self._prefix, exc)
            return {"ok": False, "users": [], "error": str(exc)}

    def delete_users(self, pins: List[str], *, timeout_sec: float = 300.0) -> Dict[str, Any]:
        """Delete whole users (fingers+card+password) from the terminal (MIRROR policy).

        Returns {'ok': bool, 'deleted': int, 'failed': int, 'errors': [str]}.
        Does NOT bracket EnableDevice — MIRROR runs inside push_roster's bracket window.
        """
        try:
            return self._call("delete_users", args={"pins": list(pins or [])}, timeout=timeout_sec)
        except Exception as exc:
            self.logger.warning("%s delete_users failed: %s", self._prefix, exc)
            return {"ok": False, "deleted": 0, "failed": len(pins or []), "errors": [str(exc)]}

    # ------------------------------------------------------------------ #
    # DeviceDriver surface — PullSDK-shaped members: INERT, never raise (D8)
    # ------------------------------------------------------------------ #

    def supports_get_device_param(self) -> bool:
        return False

    def supports_set_device_param(self) -> bool:
        return False

    def get_device_param(self, *, items: str, initial_size: int | None = None) -> Optional[str]:
        return None

    def set_device_param(self, *, items: str) -> int:
        return 0

    def get_table_count(self, *, table: str, filter_expr: str = "", options: str = "") -> int:
        return 0

    def delete_table_rows(self, *, table: str, data: str = "", options: str = "") -> int:
        return 0

    def read_transaction_rows(self, *, options: str = "new record", initial_size: int | None = None) -> List[Dict[str, str]]:
        return []

    def delete_all_transaction_rows(self) -> int:
        """INERT -- and deliberately so.

        The terminal's attendance log (GLog) is NOT the PullSDK 'transaction'
        table, and this driver does not READ it yet. Clearing it would destroy
        records that were never persisted to SQLite. Call sites must gate on
        ``supports_transaction_table``, never on this return value.
        """
        return 0

    # ------------------------------------------------------------------ #
    # Command funnel internals
    # ------------------------------------------------------------------ #

    def _ensure_sta_thread(self) -> None:
        t = self._sta_thread
        if t is not None and t.is_alive():
            return
        self._stop_evt.clear()
        self._connected_flag.clear()
        gen = self._sta_gen
        t = threading.Thread(target=self._sta_main, args=(gen,), daemon=True,
                             name=f"ZKemSTA-{self.device_id}-g{gen}")
        self._sta_thread = t
        try:
            t.start()
        except RuntimeError:
            try:
                _tel.thread_spawn_failure("zk_standalone._ensure_sta_thread", worker=self._tel_wid)  # type: ignore[attr-defined]
            except Exception:
                pass
            raise

    def _abandon_sta_thread(self, reason: str) -> None:
        """Fence off a wedged STA thread so a fresh one can take over.

        The old thread is NOT killable -- Python cannot interrupt a blocked COM
        call -- so it leaks until the process exits or the call finally returns.
        Bumping the generation guarantees that if it ever does return, it exits
        its loop instead of racing the new thread for commands.
        """
        with self._pin_map_lock:
            self._sta_gen += 1
            gen = self._sta_gen
        self._sta_thread = None
        self._connected_flag.clear()
        self.logger.error(
            "%s STA thread WEDGED (%s) - abandoning it and rebuilding (gen=%d). "
            "The stuck thread leaks until the call returns or the app restarts.",
            self._prefix, reason, gen,
        )
        try:
            _tel.warn("ZKEM_STA_WEDGED", worker=self._tel_wid, reason=str(reason)[:120], gen=gen)
        except Exception:
            pass

    def _call(self, op: str, args: Dict[str, Any] | None = None,
              timeout: float = _DEFAULT_CMD_TIMEOUT_SEC) -> Any:
        if self._sta_thread is None or not self._sta_thread.is_alive():
            raise RuntimeError("STA thread not running")
        cmd = _Cmd(op, args)
        self._cmd_queue.put(cmd)
        if not cmd.done.wait(timeout=timeout):
            # The STA thread is stuck inside a COM call that will never return.
            # Previously we raised and left it alive, so _ensure_sta_thread saw a
            # live thread, never replaced it, and the terminal stayed dead until
            # the app was restarted. Abandon it so the worker can rebuild.
            self._abandon_sta_thread(f"command {op!r} timed out after {timeout}s")
            raise TimeoutError(f"zkemkeeper command {op!r} timed out after {timeout}s")
        if cmd.error is not None:
            raise cmd.error
        return cmd.result

    # ------------------------------------------------------------------ #
    # STA thread — the ONLY code allowed to touch the COM object
    # ------------------------------------------------------------------ #

    def _sta_main(self, gen: int = 0) -> None:  # noqa: C901 - one linear device loop, kept together
        zk = None
        connected = False
        try:
            self._co_init()
        except Exception as exc:
            self.logger.error("%s CoInitialize failed: %s", self._prefix, exc)
            return
        try:
            while not self._stop_evt.is_set():
                if gen != self._sta_gen:
                    # We were abandoned as wedged and a newer thread owns the
                    # device now. Exit rather than race it for commands.
                    self.logger.warning("%s STA gen=%d superseded by gen=%d - exiting",
                                        self._prefix, gen, self._sta_gen)
                    break
                # 1) service pending commands (each with its own error capture)
                try:
                    cmd = self._cmd_queue.get(timeout=_STA_LOOP_IDLE_SLEEP_SEC)
                except queue.Empty:
                    cmd = None
                if cmd is not None and gen != self._sta_gen:
                    # Superseded BETWEEN the top-of-loop check and this dequeue. The
                    # command belongs to the successor thread that _abandon_sta_thread
                    # made room for -- a thread that was merely SLOW (not stuck in COM)
                    # would otherwise steal the successor's reconnect, service it on
                    # its own COM object, then exit and tear that state down, leaving
                    # connect() returning True with is_connected False and every later
                    # command answered "not connected". Hand it back and go.
                    self._cmd_queue.put(cmd)
                    self.logger.warning("%s STA gen=%d handed %r back to gen=%d and exited",
                                        self._prefix, gen, cmd.op, self._sta_gen)
                    break
                if cmd is not None:
                    try:
                        if cmd.op == "connect":
                            if zk is None:
                                zk = self._com_factory()
                            connected = self._do_connect(zk)
                            self._connected_flag.set() if connected else self._connected_flag.clear()
                            cmd.result = connected
                        elif cmd.op == "open_door":
                            cmd.result = bool(zk is not None and connected
                                              and self._do_open_door(zk, cmd.args["delay_ds"]))
                        elif cmd.op == "get_time":
                            cmd.result = self._do_get_time(zk) if (zk is not None and connected) else None
                        elif cmd.op == "set_time":
                            cmd.result = (zk is not None and connected
                                          and self._do_set_time(zk, cmd.args["epoch"]))
                        elif cmd.op == "push_roster":
                            if zk is None or not connected:
                                # Nothing was attempted, so nothing is confirmed: name
                                # every pin so the caller retries all of them rather
                                # than recording them as synced.
                                cmd.result = {"ok": False, "pushed": 0, "failed": 0,
                                              "error": "not connected",
                                              "failed_pins": [
                                                  str(u.get("pin") or "").strip()
                                                  for u in (cmd.args.get("users") or [])
                                                  if str(u.get("pin") or "").strip()
                                              ]}
                            else:
                                cmd.result = self._do_push_roster(
                                    zk,
                                    users=cmd.args["users"],
                                    templates_by_pin=cmd.args["templates_by_pin"],
                                    remove_fingers_by_pin=cmd.args.get("remove_fingers_by_pin"),
                                    bracket=cmd.args["bracket"],
                                    trace_members=int(cmd.args.get("trace_members") or 0),
                                    trace_templates=int(cmd.args.get("trace_templates") or 0),
                                )
                        elif cmd.op == "list_users":
                            if zk is None or not connected:
                                cmd.result = {"ok": False, "users": [], "error": "not connected"}
                            else:
                                cmd.result = self._do_list_users(zk)
                        elif cmd.op == "delete_users":
                            if zk is None or not connected:
                                cmd.result = {"ok": False, "deleted": 0, "failed": 0,
                                              "error": "not connected"}
                            else:
                                cmd.result = self._do_delete_users(zk, cmd.args["pins"])
                        else:
                            cmd.error = ValueError(f"unknown op {cmd.op!r}")
                    except BaseException as exc:  # noqa: BLE001 - captured for the caller
                        cmd.error = exc
                    finally:
                        cmd.done.set()

                # 2) pump real-time events
                if zk is not None and connected:
                    try:
                        self._pump_events_once(zk)
                    except Exception as exc:
                        # A dying pump is a disconnect, not a crash: flag it so the
                        # worker's normal reconnect logic drives recovery.
                        self.logger.warning("%s event pump error: %s", self._prefix, exc)
                        try:
                            _tel.warn("ZKEM_EVT_SINK_DOWN", worker=self._tel_wid, err=type(exc).__name__)
                        except Exception:
                            pass
                        connected = False
                        # Only the CURRENT owner may touch the shared flag: a thread
                        # superseded mid-iteration must not report the successor's
                        # live connection as down.
                        if gen == self._sta_gen:
                            self._connected_flag.clear()

                # 3) COM message pump (belt-and-braces for sink delivery)
                try:
                    self._pump()
                except Exception:
                    pass
        finally:
            try:
                if zk is not None:
                    try:
                        zk.Disconnect()
                    except Exception:
                        pass
            finally:
                # Disconnecting our OWN COM object above is local. Clearing the
                # SHARED connected flag is not: a superseded thread exiting here
                # while the successor is connected would flip is_connected to False
                # and send the worker into a needless reconnect loop.
                if gen == self._sta_gen:
                    self._connected_flag.clear()
                try:
                    self._co_uninit()
                except Exception:
                    pass

    # ---- STA-side operations (zk = the COM object; never called elsewhere) ----

    # GetDeviceStatus indices, standard ZKTeco standalone SDK. Reported raw as well
    # as named, because index meanings vary a little across firmware -- never state
    # a capacity we did not actually read.
    _STATUS_FIELDS = {
        1: "admins", 2: "users", 3: "fingerprints", 4: "attendance_records",
        5: "passwords", 7: "fingerprint_capacity", 8: "user_capacity",
        9: "attendance_capacity", 10: "fingerprints_free", 11: "users_free",
        12: "attendance_free",
    }

    def _read_device_status(self, zk: Any) -> Dict[str, int]:
        """How full the terminal actually is.

        NOTHING in this driver used to ask. We pushed a 900-member roster into a
        terminal that may already be full of another system's enrolments and had
        no way to see it -- SetUserTmpExStr just returns False, with no reason, for
        every single template. A gym migrating from older software keeps those old
        fingerprints until someone removes them, so "device full" is the NORMAL
        first-install state, not an edge case.

        Best-effort: any index that will not read is simply omitted.
        """
        out: Dict[str, int] = {}
        for idx, name in self._STATUS_FIELDS.items():
            for attempt in ("byref", "tuple"):
                try:
                    if attempt == "byref":
                        from win32com.client import VARIANT  # type: ignore
                        import pywintypes  # type: ignore
                        box = VARIANT(pywintypes.VT_BYREF | pywintypes.VT_I4, 0)
                        if bool(zk.GetDeviceStatus(1, int(idx), box)):
                            out[name] = int(box.value)
                            break
                    else:
                        res = zk.GetDeviceStatus(1, int(idx), 0)
                        if isinstance(res, (tuple, list)) and len(res) >= 2 and res[0]:
                            out[name] = int(res[1])
                            break
                except Exception:
                    continue
        return out

    def _read_fp_version(self, zk: Any) -> str:
        """The terminal's fingerprint ALGORITHM version (~ZKFPVersion), e.g. "9"/"10".

        This is the single most useful number when templates are refused. A ZK9500
        desk scanner captures v10; a terminal running v9 rejects every one of them,
        and SetUserTmpExStr just returns False with no reason -- which in the field
        looked like 339 silent refusals and no clue why. Log it once per connect so
        the mismatch is visible without running the on-site script pack.

        Best-effort: this is a diagnostic, never a gate. win32com maps the ByRef
        out-param differently across builds, so try both shapes and give up quietly.
        """
        for attempt in ("byref", "tuple"):
            try:
                if attempt == "byref":
                    import pythoncom  # noqa: F401  (win32com is already in use here)
                    from win32com.client import VARIANT  # type: ignore
                    import pywintypes  # type: ignore
                    out = VARIANT(pywintypes.VT_BYREF | pywintypes.VT_BSTR, "")
                    if bool(zk.GetSysOption(1, "~ZKFPVersion", out)):
                        return str(out.value or "").strip()
                else:
                    res = zk.GetSysOption(1, "~ZKFPVersion", "")
                    if isinstance(res, (tuple, list)) and len(res) >= 2 and res[0]:
                        return str(res[1] or "").strip()
            except Exception:
                continue
        return ""

    def _warn_if_device_full(self) -> None:
        """Say it plainly when the terminal has no room for more fingerprints.

        A full store makes EVERY SetUserTmpExStr return False -- which in the field
        looked like 339 identical refusals with no cause. Members WITHOUT
        fingerprints keep pushing fine, so the roster looks partly successful and
        the real problem hides.
        """
        st = getattr(self, "_device_status", None) or {}
        used = st.get("fingerprints")
        cap = st.get("fingerprint_capacity")
        free = st.get("fingerprints_free")

        if free is not None and free <= 0:
            self.logger.error(
                "%s DEVICE FINGERPRINT STORE IS FULL (%s/%s used, 0 free). No template "
                "can be uploaded until space is freed. A terminal carried over from "
                "previous software keeps its old enrolments -- those occupy this space.",
                self._prefix, used if used is not None else "?", cap or "?",
            )
            return
        if used is not None and cap:
            pct = (100.0 * used / cap) if cap else 0.0
            if pct >= 90.0:
                self.logger.warning(
                    "%s device fingerprint store %.0f%% full (%s/%s) - uploads will "
                    "start failing soon.", self._prefix, pct, used, cap,
                )

    def _do_connect(self, zk: Any) -> bool:
        if self.comm_key:
            try:
                # Must precede Connect_Net when the terminal has a comm key set.
                zk.SetCommPassword(int(self.comm_key) if self.comm_key.isdigit() else self.comm_key)
            except Exception as exc:
                self.logger.warning("%s SetCommPassword failed: %s", self._prefix, exc)
        ok = bool(zk.Connect_Net(self.ip, self.port))
        if ok:
            try:
                zk.RegEvent(1, _REGEVENT_ATT_TRANSACTION)
            except Exception as exc:
                self.logger.warning("%s RegEvent failed: %s", self._prefix, exc)
            self._device_fp_version = self._read_fp_version(zk)
            self._device_status = self._read_device_status(zk)
            self.logger.info(
                "%s connected ip=%s port=%s deviceFpVersion=%s status=%s",
                self._prefix, self.ip, self.port,
                self._device_fp_version or "unknown",
                self._device_status or "unreadable",
            )
            # Structured twin of the connect line above. Adds NO device round-trip:
            # both values were just read. This is the "device counters" record a
            # field test compares before and after a push -- a push is bracketed by
            # connects, so two consecutive lines answer "did the terminal's
            # fingerprint count actually go up?".
            #
            # label_source names WHERE the names come from on purpose: the index ->
            # name table below is CONTRADICTED by tools/mb2000_scripts (3 and 12
            # label index 6 as attendance logs and 8 as face templates). Nothing in
            # the repo settles it, so the provenance travels with the numbers rather
            # than the labels being presented as fact. [UNVERIFIED]
            try:
                _tel.event(
                    "ZKEM_DEVICE_COUNTERS", worker=self._tel_wid,
                    device_fp_version=self._device_fp_version or None,
                    label_source="driver._STATUS_FIELDS",
                    **{f"c_{_k}": _v for _k, _v in (self._device_status or {}).items()},
                )
            except Exception:
                pass
            self._warn_if_device_full()
        else:
            self.logger.warning("%s Connect_Net returned False (ip=%s port=%s)",
                                self._prefix, self.ip, self.port)
        return ok

    def _pump_events_once(self, zk: Any) -> None:
        """ReadRTLog/GetRTLog polling: transfers device events into the PC buffer,
        then drains it. On zkemkeeper, GetRTLog fires the registered sink
        synchronously; our sink (or a fake in tests) must call _on_att_event().
        """
        try:
            zk.ReadRTLog(1)
        except Exception:
            raise
        # Drain buffered events; GetRTLog returns falsy when the buffer is empty.
        for _ in range(256):
            try:
                if not zk.GetRTLog(1):
                    break
            except Exception:
                raise

    def _on_att_event(self, enroll_number, is_invalid, att_state, verify_method,
                      y, mo, d, h, mi, s, work_code=0) -> None:
        """Sink entry point — normalize + enqueue. Called on the STA thread."""
        self._event_seq += 1
        pin_map = self._pin_card_snapshot()
        evt = normalize_att_event(
            enroll_number=enroll_number, is_invalid=is_invalid,
            att_state=att_state, verify_method=verify_method,
            y=y, mo=mo, d=d, h=h, mi=mi, s=s, work_code=work_code,
            seq=self._event_seq, pin_to_card=pin_map,
            direction=self._direction, device_id=self.device_id,
        )
        card = str(evt.get("cardNo") or "")
        if card.startswith("ZKPIN:") and card not in self._unmapped_pins_warned:
            self._unmapped_pins_warned.add(card)
            try:
                _tel.warn("ZKEM_PIN_UNMAPPED", worker=self._tel_wid, pin=card[6:])
            except Exception:
                pass
        try:
            self._evt_queue.put_nowait(evt)
        except queue.Full:
            self.logger.warning("%s event queue full — dropping oldest", self._prefix)
            try:
                self._evt_queue.get_nowait()
                self._evt_queue.put_nowait(evt)
            except Exception:
                pass

    def _do_open_door(self, zk: Any, delay_ds: int) -> bool:
        return bool(zk.ACUnlock(1, int(delay_ds)))

    def _do_get_time(self, zk: Any) -> Optional[float]:
        try:
            # win32com maps the 6 ByRef out-params to a returned tuple:
            # (ok, year, month, day, hour, minute, second)
            res = zk.GetDeviceTime(1)
            if isinstance(res, (tuple, list)) and len(res) >= 7 and res[0]:
                import datetime as _dt
                return _dt.datetime(int(res[1]), int(res[2]), int(res[3]),
                                    int(res[4]), int(res[5]), int(res[6])).timestamp()
        except Exception as exc:
            self.logger.debug("%s GetDeviceTime unsupported/failed: %s", self._prefix, exc)
        return None

    def _do_set_time(self, zk: Any, epoch: float) -> bool:
        try:
            import datetime as _dt
            t = _dt.datetime.fromtimestamp(float(epoch))
            return bool(zk.SetDeviceTime2(1, t.year, t.month, t.day, t.hour, t.minute, t.second))
        except Exception as exc:
            self.logger.debug("%s SetDeviceTime2 unsupported/failed: %s", self._prefix, exc)
            return False

    def _do_push_roster(self, zk: Any, *, users: List[Dict[str, Any]],
                        templates_by_pin: Dict[str, List[Dict[str, Any]]],
                        bracket: bool,
                        remove_fingers_by_pin: Dict[str, List[int]] | None = None,
                        trace_members: int = 0, trace_templates: int = 0) -> Dict[str, Any]:
        """Per-member: SetStrCardNumber -> SSR_SetUserInfo -> clear vacated slots ->
        per desired finger (delete-if-occupied -> SetUserTmpExStr Flag=1). See plan D6.

        remove_fingers_by_pin: finger slots this member USED to have and no longer
        does. Supplied by the engine from persisted per-pin state; omitting it keeps
        the old additive behaviour exactly (no extra COM calls).
        """
        pushed = 0
        failed = 0
        skipped_pin = 0
        # Fingerprint templates that the terminal REFUSED. Counted separately from
        # `failed` (which is per-member) because a member row can be written fine
        # while its finger upload is rejected -- and that member then cannot get
        # through the turnstile. It must NOT be reported as a successful sync.
        templates_failed = 0
        errors: List[str] = []
        # WHICH pins did not land completely (member row refused, a template refused,
        # or an exception mid-member). The aggregate counts above cannot say which;
        # without this the engine had to treat a single refused finger as "re-push
        # all 928 next time". Deduplicated: a member with two refused fingers is one
        # failed pin.
        failed_pins: List[str] = []
        _failed_seen: set = set()
        # WHY each pin failed. failed_pins alone says a member did not land but not
        # whether the member ROW was refused (SSR_SetUserInfo False), a FINGER was
        # refused (SetUserTmpExStr False) or the member raised mid-push -- three
        # different faults with three different remedies. Telemetry only: this is
        # reported through ZKEM_PUSH_FAILED_PINS, never used to decide anything.
        failed_reasons: Dict[str, str] = {}
        # Template counters, accumulated in memory and reported at chunk boundaries.
        # They are deliberately NOT emitted per finger: the STA loop services one
        # command with no event pump for its whole duration, and the logging handler
        # writes synchronously inline, so a per-finger line on a 928-member push
        # widens the no-pump window -- a behaviour change, not instrumentation.
        tpl_attempted = 0
        tpl_ok = 0
        # Slot-clear counters, same chunk-boundary rule as the template ones above.
        # `del_attempted` counts every SSR_DelUserTmpExt issued (delete-before-write
        # AND vacated-slot removal); `del_ok` counts the ones the terminal confirmed.
        # A gap between them is the only signal that a revocation did not land.
        del_attempted = 0
        del_ok = 0

        def _mark_failed(p: str, reason: str = "") -> None:
            if p and p not in _failed_seen:
                _failed_seen.add(p)
                failed_pins.append(p)
            # First reason wins: it is the one that broke this member.
            if p and reason and p not in failed_reasons:
                failed_reasons[p] = reason

        # Progress instrumentation.
        #
        # A full roster is ~1000 members and each one costs several COM round
        # trips (SetStrCardNumber + SSR_SetUserInfo, then per finger
        # SSR_DeleteEnrollData + SetUserTmpExStr), so a first sync legitimately
        # runs for MINUTES. Previously this loop logged nothing until it
        # finished, which made "slow" and "hung" indistinguishable from the
        # outside -- the worker only emitted WORKER_STALL warnings. Emit a
        # heartbeat with a real rate and ETA so the operator can see it moving.
        total_users = len(users or [])
        t_start = time.monotonic()
        # Progress for the WHOLE roster is reported by push_roster() (the caller),
        # which is the only place that knows the totals. This is one chunk.
        # Which members this chunk covers. One line per chunk, and it is the only
        # thing that identifies the member a wedge died on -- the field incident
        # showed chunk 1 always succeeding and chunk 2 always hanging, with no way
        # to tell WHICH member chunk 2 started at.
        _first_pin = str((users or [{}])[0].get("pin") or "?")
        _last_pin = str((users or [{}])[-1].get("pin") or "?")
        self.logger.info(
            "%s push chunk pins %s..%s (n=%d)", self._prefix, _first_pin, _last_pin, total_users,
        )
        members_left = int(trace_members or 0)
        templates_left = int(trace_templates or 0)

        if bracket:
            try:
                zk.EnableDevice(1, False)
            except Exception as exc:
                errors.append(f"EnableDevice(False): {exc}")

        try:
            for u in users or []:
                done_so_far = pushed + failed + skipped_pin
                # Trace the first few members call-by-call, BEFORE each call.
                # zkemkeeper has no call timeout: if the terminal stops answering,
                # the COM call blocks forever and this thread never returns, so a
                # post-hoc timing log would never be written. Only a PRE-call line
                # survives a hang -- the last line in the log names the culprit.
                # Budgets are carried ACROSS chunks by the caller. Tracing only the
                # first chunk hid the failure: the first members had no fingerprints,
                # so the template calls -- the ones that actually wedge -- were never
                # traced at all.
                traced = members_left > 0
                if traced:
                    members_left -= 1
                pin = str(u.get("pin") or "").strip()
                name = str(u.get("name") or "")[:24]
                card = _digits_only(u.get("card"))
                if not pin.isdigit() or len(pin) > _MAX_PIN_DIGITS:
                    skipped_pin += 1
                    continue
                try:
                    if card:
                        if traced:
                            self.logger.info("%s push trace pin=%s -> SetStrCardNumber(%s)", self._prefix, pin, card)
                        zk.SetStrCardNumber(card)  # must precede SSR_SetUserInfo
                    else:
                        if traced:
                            self.logger.info("%s push trace pin=%s -> SetStrCardNumber('')", self._prefix, pin)
                        zk.SetStrCardNumber("")
                    if traced:
                        self.logger.info("%s push trace pin=%s -> SSR_SetUserInfo", self._prefix, pin)
                    ok = bool(zk.SSR_SetUserInfo(1, pin, name, "", 0, True))
                    if not ok:
                        failed += 1
                        _mark_failed(pin, "set_user_info_false")
                        if len(errors) < 5:
                            errors.append(f"SSR_SetUserInfo pin={pin}")
                        continue
                    # Slots this member USED to have and no longer does.
                    #
                    # The field bug this closes: the clear below used to exist ONLY
                    # inside the template loop, so a member whose fingerprints were
                    # all deleted had an empty desired set, the loop body never ran,
                    # and no COM call was ever issued for the vacated slot. The
                    # terminal kept verifying a revoked finger (Oxyfit, 2026-09-05).
                    #
                    # Done BEFORE the template loop on purpose: if a caller ever
                    # hands us a removal set that contradicts the desired set, the
                    # write below wins and the member keeps working. The opposite
                    # order would delete a template we had just installed.
                    desired_fingers = {
                        int(t.get("fingerId") or 0)
                        for t in ((templates_by_pin or {}).get(pin, []) or [])
                        if str(t.get("templateData") or "")
                    }
                    for finger_idx in sorted(
                        {int(f) for f in ((remove_fingers_by_pin or {}).get(pin, []) or [])}
                        - desired_fingers
                    ):
                        # USE SSR_DelUserTmpExt, NOT SSR_DeleteEnrollData -- see the
                        # note in the template loop below.
                        del_attempted += 1
                        try:
                            if bool(zk.SSR_DelUserTmpExt(1, pin, int(finger_idx))):
                                del_ok += 1
                        except Exception:
                            pass

                    for tpl in (templates_by_pin or {}).get(pin, []) or []:
                        finger_idx = int(tpl.get("fingerId") or 0)
                        tmp = str(tpl.get("templateData") or "")
                        if not tmp:
                            continue
                        try:
                            # ZKTeco FAQ: upload requires the slot to be EMPTY --
                            # delete-first makes re-enrollment deterministic.
                            #
                            # USE SSR_DelUserTmpExt, NOT SSR_DeleteEnrollData.
                            # tools/mb2000_scripts/5_push_member_to_device.ps1 -- the
                            # push sequence proven on this hardware -- clears the slot
                            # with SSR_DelUserTmpExt(mn, pin, fingerId). A previous
                            # comment here claimed SSR_DeleteEnrollData was "proven by
                            # scripts 5/7"; that is wrong for script 5. Script 7 uses
                            # SSR_DeleteEnrollData for WHOLE-USER / face / password
                            # backup numbers (11/12/13), which is a different operation.
                            #
                            # It matters: on this firmware SSR_DeleteEnrollData with
                            # backupNumber >= 1 NEVER RETURNS. Field trace, v1.4.25 --
                            # 12 of 19 STA wedges had SSR_DeleteEnrollData(f=1) as the
                            # last call made, 2 more had f=2, and finger 0 always
                            # returned normally. That hang is what stalled the roster.
                            if traced or templates_left > 0:
                                self.logger.info("%s push trace pin=%s -> SSR_DelUserTmpExt(f=%s)", self._prefix, pin, finger_idx)
                            # The result used to be discarded here, so the driver
                            # could not tell "slot cleared" from "firmware refused"
                            # from "call threw" -- which made every removal claim
                            # unverifiable. Counted, never decided on: a refused
                            # clear is immediately followed by the write, whose own
                            # result still drives ok/failed.
                            del_attempted += 1
                            if bool(zk.SSR_DelUserTmpExt(1, pin, int(finger_idx))):
                                del_ok += 1
                        except Exception:
                            pass
                        if traced or templates_left > 0:
                            if templates_left > 0:
                                templates_left -= 1
                            self.logger.info("%s push trace pin=%s -> SetUserTmpExStr(f=%s len=%d)", self._prefix, pin, finger_idx, len(tmp))
                        tpl_attempted += 1
                        okt = bool(zk.SetUserTmpExStr(1, pin, finger_idx, 1, tmp))
                        if okt:
                            tpl_ok += 1
                        if not okt:
                            # Previously this only appended a string to errors[] and
                            # left `failed` untouched, so ok stayed True: the member
                            # was reported synced, the roster hash was stamped, and
                            # the scheduler then skipped every later cycle as
                            # "fingerprint unchanged". The member's finger was
                            # refused at the turnstile while Access said it worked.
                            templates_failed += 1
                            _mark_failed(pin, f"template_refused_f{finger_idx}")
                            _st = getattr(self, "_device_status", None) or {}
                            _store = (
                                f"{_st.get('fingerprints')}/{_st.get('fingerprint_capacity')}"
                                if _st.get("fingerprint_capacity") else "unknown"
                            )
                            self.logger.warning(
                                "%s template REFUSED pin=%s finger=%s (%d bytes) "
                                "deviceFpVersion=%s templateVersion=%s fpStore=%s - this "
                                "member cannot verify on the device. If EVERY template is "
                                "refused, the two usual causes are (1) the terminal's "
                                "fingerprint store is FULL -- old enrolments from previous "
                                "software still occupy it -- or (2) the algorithm versions "
                                "disagree (a ZK9500 desk capture is v10).",
                                self._prefix, pin, finger_idx, len(tmp),
                                getattr(self, "_device_fp_version", "") or "unknown",
                                tpl.get("templateVersion") or "?", _store,
                            )
                            # Structured twin of the warning above. Emitted only on
                            # the REFUSAL path, which is rare, so the extra inline
                            # write cannot widen the no-pump window on a healthy push.
                            # Sizes and versions only -- never template bytes.
                            try:
                                _dev_ver = getattr(self, "_device_fp_version", "") or ""
                                _tpl_ver = str(tpl.get("templateVersion") or "")
                                _tel.warn(
                                    "ZKEM_PUSH_TPL_REFUSED", worker=self._tel_wid,
                                    pin=pin, finger=finger_idx, size=len(tmp),
                                    template_version=_tpl_ver or None,
                                    device_fp_version=_dev_ver or None,
                                    fp_used=_st.get("fingerprints"),
                                    fp_capacity=_st.get("fingerprint_capacity"),
                                )
                                # Version disagreement is one of the two documented
                                # causes of a blanket refusal (the other is a full
                                # store). Name it explicitly when both are known and
                                # differ -- otherwise it stays buried in two fields.
                                if _dev_ver and _tpl_ver and _dev_ver != _tpl_ver:
                                    _tel.warn(
                                        "ZKEM_TPL_VERSION_MISMATCH", worker=self._tel_wid,
                                        pin=pin, finger=finger_idx,
                                        template_version=_tpl_ver,
                                        device_fp_version=_dev_ver,
                                    )
                            except Exception:
                                pass
                            if len(errors) < 5:
                                errors.append(f"SetUserTmpExStr pin={pin} finger={finger_idx}")
                    pushed += 1
                except Exception as exc:
                    failed += 1
                    _mark_failed(pin, f"exception:{type(exc).__name__}")
                    if len(errors) < 5:
                        errors.append(f"pin={pin}: {exc}")

                # Let COM deliver anything queued for this apartment.
                #
                # The STA loop is strictly sequential (service ONE command -> pump
                # events -> PumpWaitingMessages), so for the entire duration of this
                # push nothing is pumped. An event sink IS registered on this
                # connection (RegEvent in _do_connect) and the proven-working script
                # pack never registers one -- the app is the only caller that pushes
                # a roster while a sink is live. Pump here so a device-initiated
                # callback cannot starve behind this loop.
                try:
                    self._pump()
                except Exception:
                    pass


        finally:
            if bracket:
                try:
                    zk.EnableDevice(1, True)
                except Exception as exc:
                    errors.append(f"EnableDevice(True): {exc}")
            try:
                zk.RefreshData(1)
            except Exception:
                pass

        # A refused template is a failed sync. Reporting ok=True here is what let a
        # non-working fingerprint be stamped as "synced" and never retried.
        ok = failed == 0 and templates_failed == 0
        self.logger.debug(
            "%s push chunk done pushed=%d failed=%d templates_failed=%d skipped_pin=%d in %.1fs",
            self._prefix, pushed, failed, templates_failed, skipped_pin,
            time.monotonic() - t_start,
        )
        if skipped_pin:
            self.logger.warning("%s push_roster skipped %d users with non-numeric/>%d-digit pins",
                                self._prefix, skipped_pin, _MAX_PIN_DIGITS)
        return {"ok": ok, "pushed": pushed, "failed": failed,
                "templates_failed": templates_failed,
                "skipped_pin": skipped_pin, "errors": errors,
                "failed_pins": failed_pins,
                # Telemetry-only additions. Nothing decides on these; push_roster
                # folds them into ZKEM_PUSH_CHUNK / ZKEM_PUSH_FAILED_PINS.
                "failed_reasons": failed_reasons,
                "tpl_attempted": tpl_attempted,
                "tpl_ok": tpl_ok,
                "del_attempted": del_attempted,
                "del_ok": del_ok,
                "chunk_ms": round((time.monotonic() - t_start) * 1000.0),
                "trace_members_left": members_left,
                "trace_templates_left": templates_left}

    def _do_list_users(self, zk: Any) -> Dict[str, Any]:
        """Enumerate every user on the device. Ports 2_get_member_templates.ps1.

        Returns {'ok': bool, 'users': [{'pin','name','card','enabled'}]}. ok=False
        distinguishes "listed OK, 0 users" from "list FAILED / incomplete" — the
        MIRROR reconcile hinges on this: a failed enumeration must NEVER be read as an
        empty device (that would delete every member). Any read failure fails CLOSED.

        NB: the win32com marshalling of SSR_GetAllUserInfo's [out] params is
        firmware/typelib-dependent. This handles both the "pass placeholders" and the
        "auto-alloc" conventions and fails closed on any unexpected shape. Confirming
        the exact tuple order on the real MB2000 is an on-hardware GATE.
        """
        try:
            if not zk.ReadAllUserID(1):
                return {"ok": False, "users": [], "error": "ReadAllUserID returned False"}
        except Exception as exc:
            return {"ok": False, "users": [], "error": f"ReadAllUserID: {exc}"}

        users: List[Dict[str, Any]] = []
        try:
            while True:
                try:
                    # (ok, pin, name, password, privilege, enabled)
                    res = zk.SSR_GetAllUserInfo(1, "", "", "", 0, 0)
                except TypeError:
                    res = zk.SSR_GetAllUserInfo(1)
                if not (isinstance(res, (tuple, list)) and len(res) >= 6):
                    return {"ok": False, "users": [],
                            "error": f"SSR_GetAllUserInfo unexpected shape: {type(res).__name__}"}
                if not res[0]:
                    break  # clean end of the user table
                pin = str(res[1] or "").strip()
                name = str(res[2] or "")
                enabled = bool(res[5])
                card = ""
                try:
                    cres = zk.GetStrCardNumber("")
                    if isinstance(cres, (tuple, list)) and len(cres) >= 2:
                        card = _digits_only(cres[1])
                    elif isinstance(cres, str):
                        card = _digits_only(cres)
                except Exception:
                    card = ""
                if pin:
                    users.append({"pin": pin, "name": name, "card": card, "enabled": enabled})
        except Exception as exc:
            # a mid-enumeration failure => the list is INCOMPLETE => fail closed
            return {"ok": False, "users": [], "error": f"SSR_GetAllUserInfo: {exc}"}
        return {"ok": True, "users": users}

    def _do_delete_users(self, zk: Any, pins: List[str]) -> Dict[str, Any]:
        """Delete whole users from the device. Ports 7_delete_device_fingerprint.ps1.

        backupNumber 12 == the WHOLE user (fingerprints + card + password). Skips
        non-numeric / over-length pins with the SAME guard push_roster uses, so a
        garbage device row can never be deleted by accident.
        """
        deleted = 0
        failed = 0
        errors: List[str] = []
        for raw in pins or []:
            pin = str(raw or "").strip()
            if not pin.isdigit() or len(pin) > _MAX_PIN_DIGITS:
                failed += 1
                if len(errors) < 5:
                    errors.append(f"skip invalid pin={pin!r}")
                continue
            try:
                if bool(zk.SSR_DeleteEnrollData(1, pin, 12)):  # 12 = whole user
                    deleted += 1
                else:
                    failed += 1
                    if len(errors) < 5:
                        errors.append(f"SSR_DeleteEnrollData(pin={pin}) returned False")
            except Exception as exc:
                failed += 1
                if len(errors) < 5:
                    errors.append(f"pin={pin}: {exc}")
        try:
            zk.RefreshData(1)
        except Exception:
            pass
        try:
            self._refresh_pin_card_map()
        except Exception:
            pass
        ok = failed == 0
        try:
            _tel.event("ZKEM_DELETE_DONE", worker=self._tel_wid,
                       deleted=deleted, failed=failed, ok=ok)
        except Exception:
            pass
        return {"ok": ok, "deleted": deleted, "failed": failed, "errors": errors}
