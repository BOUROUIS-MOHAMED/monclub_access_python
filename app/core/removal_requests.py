"""One-shot removal requests: run each once on the PC that drives the turnstile, then acknowledge it
(ULTRA merge D11 fingerprint erase, D13 card removal; backend plan 1 Task 9; plan 3).

The server records a request when a confirmed dashboard save switches fingerprints ON -> OFF (D11)
or moves cards away from TURNSTILE with "MonClub removes them" (D13), and sends its id in the device
payload until a PC acknowledges it or a save cancels it: ``fingerprintEraseRequestId``,
``cardRemovalRequestId`` (stored by sync_device_store, read by settings_reader as
``fingerprint_erase_request_id`` / ``card_removal_request_id``, lower-cased).

One runner per running ULTRA engine (``start_runner``, called by UltraEngine.start) looks at its
workers every ``POLL_SEC``. For each pending id, in ``ORDER``:
- Not before ``GRACE_SEC`` after this runner first saw it: a save undone at once (fingerprints back
  ON, cards back to TURNSTILE) cancels the request on the server, and the cancellation reaches this
  PC with the next device refresh. D11 erases fingers enrolled by hand, which nothing restores.
- Never run twice: a run that ended is recorded durably here (``removal_request_runs``) before the
  acknowledgement, so a power cut between the two only repeats the acknowledgement.
- Runs only when every condition of ``refusal`` holds: this PC drives the turnstile (driver lease),
  no handover freeze, no add-only state, no Erase-wizard hold, the latest stored payload still names
  the same id under the same key (else it was cancelled), the switch still says what the request
  is for, the worker is connected to the address MonClub records, and no pass is running. Every
  write re-checks ``write_refusal`` (with the stored payload) before it is queued, and
  ``thread_refusal`` (in memory only: lease, hold, the worker's settings, its address) on the worker
  thread just before it runs (removal_executors.Runway).
- Then the device work (removal_executors.py); after any run that queued a write, done or not,
  every per-pin hash of the device is cleared and a pass requested (removal_executors.py explains
  why); then the durable record and the ack.
- Acknowledgement outcomes (MonClubApi.ack_removal_request): DONE and GONE stop; RETRY is tried
  again every ``ACK_RETRY_SEC`` while the payload still names the id.
- A run that fails waits ``FAIL_RETRY_SEC`` before the next try; a refusal is re-checked next poll.

A request whose device has no running worker on this PC never runs here: a device out of service,
one this PC does not drive, or one not (yet) in ULTRA mode.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.core import device_hold as _device_hold
from app.core import removal_executors as _rx
from app.core import telemetry as _tel
from app.core.settings_reader import CARDS_TURNSTILE, effective_card_decision, removal_request_id
from app.core.v2 import lease_gate as _lease_gate

_log = logging.getLogger("zkapp.removal")

KIND_FINGERPRINTS = "FINGERPRINTS"
KIND_CARDS = "CARDS"
# Fingerprints first: the D11 erase is whole-table and needs no ownership record; the D13 removal
# then deletes the owned users and asks for the pass that writes members back (plan 3 SD-3).
ORDER = (KIND_FINGERPRINTS, KIND_CARDS)
_KEYS = {
    KIND_FINGERPRINTS: ("fingerprint_erase_request_id", "fingerprintEraseRequestId"),
    KIND_CARDS: ("card_removal_request_id", "cardRemovalRequestId"),
}
RESULT_CODES = {KIND_FINGERPRINTS: "ERASED", KIND_CARDS: "REMOVED"}

POLL_SEC = 30.0
GRACE_SEC = 120.0
ACK_RETRY_SEC = 300.0
FAIL_RETRY_SEC = 600.0
REFUSAL_LOG_SEC = 600.0

_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS removal_request_runs ("
    " request_id TEXT PRIMARY KEY, device_id INTEGER NOT NULL, kind TEXT NOT NULL,"
    " ran_at TEXT NOT NULL, result_code TEXT, result_detail TEXT,"
    " ack_outcome TEXT, acked_at TEXT, ack_attempts INTEGER NOT NULL DEFAULT 0, last_ack_error TEXT)"
)
_ensured_for: Optional[str] = None


# ------------------------------------------------------------------ the local record
def _ensure_table() -> None:
    """Create the table once per database file, through the DbWriter (the one writer)."""
    global _ensured_for
    from app.core import db as _db

    path = str(_db._resolve_db_path())
    if _ensured_for == path:
        return
    _db._run_db_write_sync("removal_request_runs_table", lambda conn, profile: conn.execute(_TABLE_SQL))
    _ensured_for = path


def _select_run(request_id: str) -> Any:
    from app.core import db as _db

    with _db.get_conn() as conn:
        return conn.execute(
            "SELECT request_id, device_id, kind, ran_at, result_code, result_detail, ack_outcome,"
            " acked_at, ack_attempts, last_ack_error FROM removal_request_runs WHERE request_id=?",
            (str(request_id),),
        ).fetchone()


def get_run(request_id: str) -> Optional[Dict[str, Any]]:
    global _ensured_for
    _ensure_table()
    try:
        row = _select_run(request_id)
    except sqlite3.OperationalError:
        _ensured_for = None             # the database file was replaced (a restore): create again
        _ensure_table()
        row = _select_run(request_id)
    if row is None:
        return None
    keys = ("request_id", "device_id", "kind", "ran_at", "result_code", "result_detail",
            "ack_outcome", "acked_at", "ack_attempts", "last_ack_error")
    return dict(zip(keys, tuple(row)))


def record_ran(request_id: str, *, device_id: int, kind: str, result_code: str, detail: str) -> None:
    """A run ended on the turnstile: recorded durably BEFORE the acknowledgement is sent."""
    _ensure_table()
    from app.core import db as _db
    from app.core.utils import now_iso

    def _write(conn: Any, profile: Dict[str, Any]) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO removal_request_runs (request_id, device_id, kind, ran_at,"
            " result_code, result_detail) VALUES (?, ?, ?, ?, ?, ?)",
            (str(request_id), int(device_id), str(kind), now_iso(), str(result_code), str(detail)[:255]),
        )

    _db._run_db_write_sync("removal_request_ran", _write, durable=True)


def record_ack(request_id: str, *, outcome: str, error: str = "") -> None:
    _ensure_table()
    from app.api.monclub_api import ACK_DONE, ACK_GONE
    from app.core import db as _db
    from app.core.utils import now_iso

    final = outcome in (ACK_DONE, ACK_GONE)

    def _write(conn: Any, profile: Dict[str, Any]) -> None:
        conn.execute(
            "UPDATE removal_request_runs SET ack_outcome=?, ack_attempts=ack_attempts+1,"
            " last_ack_error=?, acked_at=CASE WHEN ? THEN ? ELSE acked_at END WHERE request_id=?",
            (str(outcome), str(error or "")[:255] or None, 1 if final else 0, now_iso(), str(request_id)),
        )

    _db._run_db_write_sync("removal_request_ack", _write)


# ------------------------------------------------------------------ the conditions
def pending(settings: Dict[str, Any]) -> List[Tuple[str, str]]:
    """[(kind, request id)] a worker's settings carry, in ORDER."""
    out: List[Tuple[str, str]] = []
    for kind in ORDER:
        rid = (settings or {}).get(_KEYS[kind][0])
        if rid:
            out.append((kind, str(rid).strip().lower()))
    return out


def still_named(device_id: int, kind: str, request_id: str) -> bool:
    """The latest stored payload still carries the same id under the same key, compared through
    settings_reader.removal_request_id's normalisation (the store keeps the id as received)."""
    from app.core import db as _db

    payload = _db.get_sync_device_payload(int(device_id)) or {}
    return removal_request_id(payload, _KEYS[kind][1]) == str(request_id).strip().lower()


def _norm_addr(ip: Any, port: Any) -> Tuple[str, str]:
    text = str(port if port is not None else "").strip()
    try:
        text = str(int(text)) if text else "4370"      # both drivers default to 4370
    except ValueError:
        pass
    return str(ip or "").strip(), text


def address_refusal(worker: Any, device: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """The worker must be connected to the address MonClub records (erase_wizard._address_refusal):
    after an IP edit the old socket may reach another turnstile."""
    addr = getattr(worker, "_connected_addr", None)
    if not addr:
        return "ADDRESS_UNKNOWN", "the worker does not report the address it is connected to"
    have = _norm_addr(addr[0], addr[1] if len(addr) > 1 else None)
    want = _norm_addr(device.get("ipAddress") or device.get("ip_address"),
                      device.get("portNumber") or device.get("port_number"))
    if have != want:
        return "ADDRESS_CHANGED", f"connected to {have[0]}:{have[1]}, MonClub records {want[0]}:{want[1]}"
    return None


def write_refusal(device_id: int, kind: str, request_id: str) -> Optional[Tuple[str, str]]:
    """What every write re-checks, on the worker thread too."""
    if not _lease_gate.device_allowed(device_id):
        return "NOT_DRIVER", "this PC does not drive this turnstile"
    if _lease_gate.writes_frozen(device_id):
        return "HANDOVER_IN_PROGRESS", "this turnstile is being handed over to another PC"
    blocked = _lease_gate.removals_blocked(device_id)
    if blocked:
        return "ADD_ONLY", f"removals are not allowed on this turnstile ({blocked})"
    if _device_hold.is_held(device_id):
        return "ON_HOLD", "the Erase wizard holds this turnstile"
    if not still_named(device_id, kind, request_id):
        return "CANCELLED", "the request is no longer in the device payload"
    return None


def thread_refusal(device_id: int, kind: str, request_id: str, worker: Any,
                   device: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """What every write re-checks ON THE WORKER THREAD, between door polls: in-memory reads only (the
    lease snapshot, the hold set, the worker's own settings -- refreshed in place by
    ultra_worker_pool.refresh_copies when a cancellation arrives -- and its connected address). No
    database read there: the door loop would wait on it. The AUTHORITATIVE cancellation check is
    ``write_refusal`` (``still_named``, the stored payload), run on the runner thread before every
    write is queued; this one only catches a cancellation refresh_copies has already applied. Never
    drop the database check as redundant."""
    if not _lease_gate.device_allowed(device_id):
        return "NOT_DRIVER", "this PC does not drive this turnstile"
    if _lease_gate.writes_frozen(device_id):
        return "HANDOVER_IN_PROGRESS", "this turnstile is being handed over to another PC"
    blocked = _lease_gate.removals_blocked(device_id)
    if blocked:
        return "ADD_ONLY", f"removals are not allowed on this turnstile ({blocked})"
    if _device_hold.is_held(device_id):
        return "ON_HOLD", "the Erase wizard holds this turnstile"
    if (kind, str(request_id).strip().lower()) not in pending(getattr(worker, "_settings", None) or {}):
        return "CANCELLED", "the request is no longer in the worker's device settings"
    return address_refusal(worker, device)


def refusal(worker: Any, kind: str, request_id: str) -> Optional[Tuple[str, str]]:
    """Every condition a run needs, checked before it starts. None = go."""
    device = dict(getattr(worker, "_device", None) or {})
    settings = dict(getattr(worker, "_settings", None) or {})
    did = int(getattr(worker, "_device_id", 0) or device.get("id") or 0)
    why = write_refusal(did, kind, request_id)
    if why:
        return why
    if kind == KIND_FINGERPRINTS and bool(settings.get("fingerprint_enabled", False)):
        return "FINGERPRINTS_ON", "the device's fingerprints are on: an erase would remove pushed fingers"
    if kind == KIND_CARDS and effective_card_decision(device) == CARDS_TURNSTILE:
        return "CARDS_ON_TURNSTILE", "the device's cards are on the turnstile again"
    if not getattr(worker, "_connected", False):
        return "NOT_CONNECTED", "turnstile not connected"
    why = address_refusal(worker, device)
    if why:
        return why
    if getattr(worker, "_full_sync_running", False):
        return "BUSY", "a sync pass is running on this turnstile"
    return None


def _protocol(device: Dict[str, Any]) -> Optional[str]:
    from app.sdk.device_driver import DeviceProtocol, resolve_device_protocol

    try:
        proto = resolve_device_protocol(device)
    except Exception:
        return None
    if proto == DeviceProtocol.ZK_PULLSDK:
        return _rx.PROTO_PULLSDK
    if proto == DeviceProtocol.ZK_STANDALONE:
        return _rx.PROTO_STANDALONE
    return None


# ------------------------------------------------------------------ the runner
def _default_ack(device_id: int, request_id: str, code: str, detail: str) -> Dict[str, Any]:
    from access.config import build_access_api_endpoints
    from app.api.monclub_api import ACK_RETRY, MonClubApi
    from app.core.db import load_auth_token

    auth = load_auth_token()
    token = str(getattr(auth, "token", "") or "").strip() if auth else ""
    if not token:
        return {"outcome": ACK_RETRY, "detail": "not signed in"}
    api = MonClubApi(endpoints=build_access_api_endpoints(), logger=_log)
    return api.ack_removal_request(token=token, device_id=int(device_id), request_id=request_id,
                                   result_code=code, result_detail=detail)


class RemovalRequestRunner:
    """The pending requests of one UltraEngine's workers. ``tick`` is one pass (tests call it)."""

    def __init__(self, engine: Any, *,
                 ack: Optional[Callable[[int, str, str, str], Dict[str, Any]]] = None,
                 mono: Callable[[], float] = time.monotonic, grace_sec: float = GRACE_SEC) -> None:
        self.engine = engine
        self._ack = ack or _default_ack
        self._mono = mono
        self._grace = float(grace_sec)
        self._first_seen: Dict[str, float] = {}
        self._not_before: Dict[str, float] = {}       # request id -> next try (failures, ack retries)
        self._logged: Dict[Tuple[str, str], float] = {}

    def tick(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for did, worker in list((getattr(self.engine, "_workers", None) or {}).items()):
            for kind, rid in pending(getattr(worker, "_settings", None) or {}):
                if self._mono() < self._not_before.get(rid, float("-inf")):
                    continue
                try:
                    out.append(self._one(int(did), worker, kind, rid))
                except Exception as exc:          # pragma: no cover - never let one stop the rest
                    _log.exception("[REMOVAL] request %s on turnstile %s: %s", rid, did, exc)
        return out

    def _one(self, did: int, worker: Any, kind: str, rid: str) -> Dict[str, Any]:
        run = get_run(rid)
        if run is not None:
            if run.get("acked_at"):
                return {"requestId": rid, "state": "ACKED"}
            return self._send_ack(did, rid, run["result_code"] or RESULT_CODES[kind],
                                  run["result_detail"] or "")
        first = self._first_seen.setdefault(rid, self._mono())
        if self._mono() - first < self._grace:
            return {"requestId": rid, "state": "WAITING"}
        why = refusal(worker, kind, rid)
        if why:
            self._log_refusal(did, rid, why)
            return {"requestId": rid, "state": "REFUSED", "code": why[0]}
        device = dict(getattr(worker, "_device", None) or {})
        proto = _protocol(device)
        runway = _rx.Runway(worker, lambda: write_refusal(did, kind, rid) or address_refusal(worker, device),
                            lambda: thread_refusal(did, kind, rid, worker, device))
        _log.warning("[REMOVAL] turnstile %s: running %s request %s (%s)", did, kind, rid, proto)
        try:
            if kind == KIND_FINGERPRINTS:
                code, detail = _rx.erase_fingerprints(runway, proto or "", device_id=did)
            else:
                code, detail = _rx.remove_cards(runway, proto or "", device_id=did)
        except _rx.StepFailed as exc:
            if runway.wrote:
                self._after_writes(did, worker)
            self._not_before[rid] = self._mono() + FAIL_RETRY_SEC
            _log.error("[REMOVAL] turnstile %s: %s request %s FAILED %s: %s", did, kind, rid,
                       exc.code, exc.message)
            _tel.warn("REMOVAL_REQUEST_FAILED", device=did, kind=kind, code=exc.code)
            return {"requestId": rid, "state": "FAILED", "code": exc.code}
        if runway.wrote:
            self._after_writes(did, worker)
        record_ran(rid, device_id=did, kind=kind, result_code=code, detail=detail)
        _log.warning("[REMOVAL] turnstile %s: %s request %s done: %s %s", did, kind, rid, code, detail)
        _tel.event("REMOVAL_REQUEST_DONE", device=did, kind=kind, code=code)
        return self._send_ack(did, rid, code, detail)

    def _after_writes(self, did: int, worker: Any) -> None:
        """The turnstile may have changed: every per-pin hash cleared, then a pass requested (the
        scheduler's own device stamp dropped too, as the Erase wizard does after a release), so the
        next pass writes every member by the device's switches as they are then."""
        try:
            _rx.invalidate_hashes(did)
        except Exception:
            _log.error("[REMOVAL] hashes of turnstile %s NOT cleared", did, exc_info=True)
        sched = getattr(self.engine, "_sync_scheduler", None)
        try:
            if sched is not None and hasattr(sched, "force_resync"):
                sched.force_resync(did)
            worker.request_full_sync(reason="removal-request")
        except Exception:
            _log.warning("[REMOVAL] pass not requested after a removal request on turnstile %s", did,
                         exc_info=True)

    def _send_ack(self, did: int, rid: str, code: str, detail: str) -> Dict[str, Any]:
        from app.api.monclub_api import ACK_GONE, ACK_RETRY

        try:
            res = self._ack(did, rid, code, detail) or {}
        except Exception as exc:
            res = {"outcome": ACK_RETRY, "detail": str(exc)[:200]}
        outcome = str(res.get("outcome") or ACK_RETRY)
        record_ack(rid, outcome=outcome, error=str(res.get("detail") or ""))
        if outcome == ACK_RETRY:
            self._not_before[rid] = self._mono() + ACK_RETRY_SEC
            _log.warning("[REMOVAL] request %s: acknowledgement not accepted yet (%s); retried later",
                         rid, res.get("detail"))
        elif outcome == ACK_GONE:
            _log.warning("[REMOVAL] request %s: the server does not know it for turnstile %s (404); "
                         "stopped", rid, did)
        _tel.event("REMOVAL_REQUEST_ACK", device=did, outcome=outcome)
        return {"requestId": rid, "state": "ACK_" + outcome}

    def _log_refusal(self, did: int, rid: str, why: Tuple[str, str]) -> None:
        key = (rid, why[0])
        now = self._mono()
        if now - self._logged.get(key, float("-inf")) >= REFUSAL_LOG_SEC:
            self._logged[key] = now
            _log.info("[REMOVAL] turnstile %s: request %s waits (%s: %s)", did, rid, why[0], why[1])


def start_runner(engine: Any) -> Optional[threading.Thread]:
    """Start the engine's runner thread unless one is alive. It ends when the engine stops."""
    current = getattr(engine, "_removal_runner_thread", None)
    if current is not None and current.is_alive():
        return current
    runner = RemovalRequestRunner(engine)
    stop = engine._stop_event

    def _loop() -> None:
        while not stop.wait(POLL_SEC):
            if not getattr(engine, "_running", False):
                return
            runner.tick()

    thread = threading.Thread(target=_loop, name="removal-requests", daemon=True)
    engine._removal_runner_thread = thread
    thread.start()
    return thread
