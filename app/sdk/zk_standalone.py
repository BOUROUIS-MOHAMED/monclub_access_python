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
COM viability, event field semantics, ACUnlock support (supports_open_door stays False
until GATE 4), template portability, card number space.
"""

from __future__ import annotations

import logging
import queue
import threading
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

# MB2000 user-ID space is 9 digits (vendor datasheet). Longer pins would be
# silently truncated/rejected by the terminal — guard at push time.
_MAX_PIN_DIGITS = 9


def _digits_only(v: Any) -> str:
    return "".join(ch for ch in str(v or "") if ch.isdigit())


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
    # ACUnlock is documented SDK-wide but UNVERIFIED on MB2000 (GATE 4). Until a
    # positive on-site test flips this (config/env), open_door returns False and
    # the worker's existing "open_door returned False" handling reports it.
    supports_open_door = False

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

        self._prefix = f"[ZKEM:{self.device_id}]"
        self._tel_wid = f"ZKEM:{self.device_id}"

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

    def open_door(self, *, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> bool:
        if not self.supports_open_door:
            # UNVERIFIED on MB2000 until GATE 4; the worker already surfaces
            # "open_door returned False" so this fails loud, not silent.
            self.logger.warning("%s open_door unsupported (GATE 4 pending)", self._prefix)
            return False
        try:
            delay_ds = max(1, int(round(pulse_time_ms / 100.0)))  # ACUnlock takes deciseconds
            return bool(self._call(
                "open_door", args={"delay_ds": delay_ds},
                timeout=max(2.0, timeout_ms / 1000.0),
            ))
        except Exception as exc:
            self.logger.warning("%s open_door failed: %s", self._prefix, exc)
            return False

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
        try:
            result = self._call(
                "push_roster",
                args={
                    "users": users or [],
                    "templates_by_pin": templates_by_pin or {},
                    "bracket": bool(bracket_enable_device),
                },
                timeout=timeout_sec,
            )
        except Exception as exc:
            self.logger.warning("%s push_roster failed: %s", self._prefix, exc)
            return {"ok": False, "pushed": 0, "failed": 0, "error": str(exc)}
        # keep the event-side identity map in step with what the device now holds
        self._refresh_pin_card_map()
        return result

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

    # ------------------------------------------------------------------ #
    # Command funnel internals
    # ------------------------------------------------------------------ #

    def _ensure_sta_thread(self) -> None:
        t = self._sta_thread
        if t is not None and t.is_alive():
            return
        self._stop_evt.clear()
        self._connected_flag.clear()
        t = threading.Thread(target=self._sta_main, daemon=True,
                             name=f"ZKemSTA-{self.device_id}")
        self._sta_thread = t
        try:
            t.start()
        except RuntimeError:
            try:
                _tel.thread_spawn_failure("zk_standalone._ensure_sta_thread", worker=self._tel_wid)  # type: ignore[attr-defined]
            except Exception:
                pass
            raise

    def _call(self, op: str, args: Dict[str, Any] | None = None,
              timeout: float = _DEFAULT_CMD_TIMEOUT_SEC) -> Any:
        if self._sta_thread is None or not self._sta_thread.is_alive():
            raise RuntimeError("STA thread not running")
        cmd = _Cmd(op, args)
        self._cmd_queue.put(cmd)
        if not cmd.done.wait(timeout=timeout):
            raise TimeoutError(f"zkemkeeper command {op!r} timed out after {timeout}s")
        if cmd.error is not None:
            raise cmd.error
        return cmd.result

    # ------------------------------------------------------------------ #
    # STA thread — the ONLY code allowed to touch the COM object
    # ------------------------------------------------------------------ #

    def _sta_main(self) -> None:  # noqa: C901 - one linear device loop, kept together
        zk = None
        connected = False
        try:
            self._co_init()
        except Exception as exc:
            self.logger.error("%s CoInitialize failed: %s", self._prefix, exc)
            return
        try:
            while not self._stop_evt.is_set():
                # 1) service pending commands (each with its own error capture)
                try:
                    cmd = self._cmd_queue.get(timeout=_STA_LOOP_IDLE_SLEEP_SEC)
                except queue.Empty:
                    cmd = None
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
                                cmd.result = {"ok": False, "pushed": 0, "failed": 0,
                                              "error": "not connected"}
                            else:
                                cmd.result = self._do_push_roster(
                                    zk,
                                    users=cmd.args["users"],
                                    templates_by_pin=cmd.args["templates_by_pin"],
                                    bracket=cmd.args["bracket"],
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
                self._connected_flag.clear()
                try:
                    self._co_uninit()
                except Exception:
                    pass

    # ---- STA-side operations (zk = the COM object; never called elsewhere) ----

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
            self.logger.info("%s connected ip=%s port=%s", self._prefix, self.ip, self.port)
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
                        bracket: bool) -> Dict[str, Any]:
        """Per-member: SetStrCardNumber -> SSR_SetUserInfo -> per finger
        (delete-if-occupied -> SetUserTmpExStr Flag=1). See plan D6.
        """
        pushed = 0
        failed = 0
        skipped_pin = 0
        errors: List[str] = []

        if bracket:
            try:
                zk.EnableDevice(1, False)
            except Exception as exc:
                errors.append(f"EnableDevice(False): {exc}")

        try:
            for u in users or []:
                pin = str(u.get("pin") or "").strip()
                name = str(u.get("name") or "")[:24]
                card = _digits_only(u.get("card"))
                if not pin.isdigit() or len(pin) > _MAX_PIN_DIGITS:
                    skipped_pin += 1
                    continue
                try:
                    if card:
                        zk.SetStrCardNumber(card)  # must precede SSR_SetUserInfo
                    else:
                        zk.SetStrCardNumber("")
                    ok = bool(zk.SSR_SetUserInfo(1, pin, name, "", 0, True))
                    if not ok:
                        failed += 1
                        if len(errors) < 5:
                            errors.append(f"SSR_SetUserInfo pin={pin}")
                        continue
                    for tpl in (templates_by_pin or {}).get(pin, []) or []:
                        finger_idx = int(tpl.get("fingerId") or 0)
                        tmp = str(tpl.get("templateData") or "")
                        if not tmp:
                            continue
                        try:
                            # ZKTeco FAQ: upload requires the slot to be EMPTY —
                            # delete-first makes re-enrollment deterministic.
                            # SSR_DeleteEnrollData is 3-arg (mn, pin, backupNumber);
                            # backupNumber 0..9 == that finger (proven by the .ps1 pack,
                            # scripts 5/7). The earlier 4-arg call silently raised here
                            # (swallowed) so the slot was never actually cleared.
                            zk.SSR_DeleteEnrollData(1, pin, int(finger_idx))
                        except Exception:
                            pass
                        okt = bool(zk.SetUserTmpExStr(1, pin, finger_idx, 1, tmp))
                        if not okt and len(errors) < 5:
                            errors.append(f"SetUserTmpExStr pin={pin} finger={finger_idx}")
                    pushed += 1
                except Exception as exc:
                    failed += 1
                    if len(errors) < 5:
                        errors.append(f"pin={pin}: {exc}")
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

        ok = failed == 0
        try:
            _tel.event("ZKEM_PUSH_DONE", worker=self._tel_wid, pushed=pushed,
                       failed=failed, skipped_pin=skipped_pin, ok=ok)
        except Exception:
            pass
        if skipped_pin:
            self.logger.warning("%s push_roster skipped %d users with non-numeric/>%d-digit pins",
                                self._prefix, skipped_pin, _MAX_PIN_DIGITS)
        return {"ok": ok, "pushed": pushed, "failed": failed,
                "skipped_pin": skipped_pin, "errors": errors}

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
