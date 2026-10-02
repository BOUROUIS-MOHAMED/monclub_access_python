"""What a removal request does on ONE turnstile (ULTRA merge D11, D13; plan 3). The lifecycle --
which PC runs it, the re-check of the payload, the local record, the acknowledgement -- is
removal_requests.py; this module only talks to the turnstile and fixes MonClub's records after.

D11, fingerprints switched ON -> OFF: every template on the turnstile goes, MonClub's and
hand-enrolled alike.
- C3 (PullSDK): ``templatev10`` then ``template``, each erased whole (``PullSDKDevice.erase_table``,
  the Erase wizard's call). ``templatev10`` must answer a count; a ``template`` table that does not
  answer is read as absent (a C3 without the v9 table, erase_wizard.py ``_erase``). Verified by a
  recount of 0.
- MB2000 (zkemkeeper): every finger slot 0-9 of every NON-ADMIN user is swept
  (``sweep_finger_slots``: ``SSR_DelUserTmpExt``, never the finger-index ``SSR_DeleteEnrollData``
  that hangs the firmware). Administrators (privilege > 0) keep their fingers, as in the Erase wizard
  (plan 3 OD-3). Verified by the terminal's own fingerprint counter equal to the administrators'
  templates. Then every non-admin pin's resident finger set is recorded EMPTY and swept, so a later
  push never clears a slot that is already empty (db.invalidate_device_records' rule).

D13, cards moved away from TURNSTILE with "MonClub removes them": ONLY the pins MonClub wrote
(``device_sync_state.ownership_confirmed = 1``) are deleted; a user added by hand is never touched,
and an MB2000 administrator never.
- C3: ``DeleteDeviceData`` on ``templatev10``, ``template``, ``userauthorize`` then ``user``, 100
  pins per call (``PullSDKDevice.delete_table_rows``). A refused call on the first three is logged
  (the row may not exist, device_sync.py ``_bulk_delete_pins``); on ``user`` it fails the run.
- MB2000: ``delete_users`` (``SSR_DeleteEnrollData(1, pin, 12)``), 20 pins per call.
- Both: verified by re-reading the turnstile's users. Then the state rows of the pins that are gone
  are deleted, each logged in ``v2_removal_log`` (the ownership backup's REMOVED fact) -- but only a
  row unchanged since the run read it: a pass that rewrote a pin during the run keeps its row.

After ANY run that queued a write -- done or stopped halfway, either kind -- the runner clears every
per-pin hash of the device (``invalidate_hashes``) and asks for a pass (removal_requests.py). The
next pass then writes every member by the device's switches as they are THEN: members without cards
when fingerprints are on (device_push_rules.roster_for_card_mode), everyone back if staff switched
back to TURNSTILE or fingerprints back ON meanwhile. Without it, a stopped D13 leaves user rows
without their door rights and a reverted D11 leaves erased fingers recorded as present: both are
skipped by every later pass, whose per-pin hash did not change.

Every device call goes through the ULTRA worker's own connection (``request_run_sdk``), one command
at a time: the worker serves the door and the scans between commands. Every WRITE re-checks its
guard twice: before it is queued and again on the worker thread just before it runs.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from app.core.erase_wizard import (
    MB_DELETE_PINS_PER_CALL,
    MB_SWEEP_SLOTS_PER_CALL,
    MB_TEMPLATE_PINS_PER_CALL,
    PROTO_PULLSDK,
    PROTO_STANDALONE,
    T_COUNT,
    T_ERASE,
    T_READ,
    TD_DELETE,
    TD_LIST,
    TD_STATUS,
    TD_SWEEP,
    TD_TEMPLATES,
    terminal_people,
)

_log = logging.getLogger("zkapp.removal")

C3_TEMPLATE_TABLES = ("templatev10", "template")
C3_DELETE_ORDER = ("templatev10", "template", "userauthorize", "user")
C3_PINS_PER_DELETE = 100        # device_sync.py _bulk_delete_pins' chunk
MB_SLOTS = tuple(range(10))

Guard = Callable[[], Optional[Tuple[str, str]]]


class StepFailed(Exception):
    """The run stopped. Nothing is acknowledged; the request is tried again later."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _chunks(items: List[Any], n: int) -> List[List[Any]]:
    return [items[i:i + n] for i in range(0, len(items), max(1, n))]


class Runway:
    """The worker connection a run uses: ``read`` and guarded ``write`` (erase_wizard's _call and
    _write_call, without a wizard). ``guard`` runs before a write is queued; ``thread_guard`` (default:
    ``guard``) runs on the worker thread just before it -- inside the door loop's command drain, so
    the runner gives it in-memory checks only (removal_requests.thread_refusal)."""

    def __init__(self, worker: Any, guard: Guard, thread_guard: Optional[Guard] = None) -> None:
        self.worker = worker
        self.guard = guard
        self.thread_guard = thread_guard or guard
        self.wrote = False        # a write was queued: the turnstile may have changed

    def read(self, fn: Callable[[Any], Any], *, label: str, timeout: float) -> Any:
        res = self.worker.request_run_sdk(fn, label=f"removal_{label}", timeout=timeout) or {}
        if res.get("ok"):
            return res.get("result")
        raise StepFailed("DEVICE_ERROR", f"{label}: {res.get('error') or 'device command failed'}")

    def write(self, fn: Callable[[Any], Any], *, label: str, timeout: float) -> Any:
        refused = self.guard()
        if refused:
            raise StepFailed(*refused)
        seen: Dict[str, Tuple[str, str]] = {}
        self.wrote = True

        def _guarded(drv: Any) -> Any:
            why = self.thread_guard()
            if why:
                seen["refused"] = why
                return None
            return fn(drv)

        out = self.read(_guarded, label=label, timeout=timeout)
        if "refused" in seen:
            raise StepFailed(*seen["refused"])
        return out


# ------------------------------------------------------------------ records
def owned_rows(device_id: int) -> Dict[str, Optional[str]]:
    """{pin: updated_at} of every pin MonClub wrote to this turnstile (ownership_confirmed = 1)."""
    from app.core import db as _db

    with _db.get_conn() as conn:
        rows = conn.execute(
            "SELECT pin, updated_at FROM device_sync_state WHERE device_id=? AND ownership_confirmed=1",
            (int(device_id),),
        ).fetchall()
    return {str(r[0]).strip(): (None if r[1] is None else str(r[1])) for r in rows if str(r[0] or "").strip()}


def forget_removed_pins(device_id: int, snapshot: Dict[str, Optional[str]], on_device: Set[str]) -> int:
    """Delete the state, mirror and intent rows of each snapshot pin that is no longer on the
    turnstile and whose row is unchanged since the snapshot; log each in v2_removal_log. One
    durable transaction. ``updated_at`` has one-second precision (utils.now_iso): a rewrite in the
    very second the snapshot's stamp was written would pass for unchanged; the re-read of the
    turnstile before this call is what catches a pin a pass put back."""
    from app.core import db as _db

    did = int(device_id)
    gone = [(p, stamp) for p, stamp in sorted(snapshot.items()) if p not in on_device]

    def _write(conn: Any, profile: Dict[str, Any]) -> int:
        n = 0
        for pin, stamp in gone:
            cur = conn.execute(
                "DELETE FROM device_sync_state WHERE device_id=? AND pin=? AND ownership_confirmed=1 "
                "AND updated_at IS ?",
                (did, pin, stamp),
            )
            if int(cur.rowcount or 0) == 0:
                continue                      # rewritten by a pass during the run: keep it
            conn.execute("DELETE FROM device_content_mirror WHERE device_id=? AND pin=?", (did, pin))
            conn.execute("DELETE FROM device_push_intent WHERE device_id=? AND pin=?", (did, pin))
            _db._log_v2_removal(conn, did, pin)
            n += 1
        profile["forgotten"] = n
        return n

    return int(_db._run_db_write_sync("removal_forget_pins", _write, durable=True))


def invalidate_hashes(device_id: int) -> int:
    """Every per-pin hash of the device cleared AND the retry backoff reset, ownership, removal
    evidence and ``updated_at`` kept: ``db.invalidate_device_records(fingers_erased=False)``, the
    Erase wizard's keep-records reset (without the backoff reset a pin with a failure streak would be
    held back for hours, its review R2-2). Durable. The next pass writes every member again."""
    from app.core import db as _db

    return int(_db.invalidate_device_records(device_id=int(device_id), fingers_erased=False))


def mark_fingers_erased(device_id: int, *, keep_pins: Iterable[str] = ()) -> int:
    """After a verified MB2000 finger erase: every pin's resident finger set is known EMPTY and
    swept, except ``keep_pins`` (the administrators). One durable transaction."""
    from app.core import db as _db

    did = int(device_id)
    keep = sorted({str(p) for p in keep_pins})
    spare = f" AND pin NOT IN ({','.join(['?'] * len(keep))})" if keep else ""

    def _write(conn: Any, profile: Dict[str, Any]) -> int:
        cur = conn.execute(
            "UPDATE device_sync_state SET pushed_finger_ids='', finger_slots_swept=1 "
            f"WHERE device_id=?{spare}",
            (did, *keep),
        )
        return int(cur.rowcount or 0)

    return int(_db._run_db_write_sync("removal_mark_fingers_erased", _write, durable=True))


# ------------------------------------------------------------------ D11: fingerprints
def _count(run: Runway, table: str) -> Optional[int]:
    try:
        return int(run.read(lambda drv: drv.count_table_strict(table=table),
                            label=f"count_{table}", timeout=T_COUNT))
    except StepFailed:
        return None


def _erase_fingers_c3(run: Runway) -> Tuple[str, str]:
    before = {t: _count(run, t) for t in C3_TEMPLATE_TABLES}
    if before["templatev10"] is None:
        raise StepFailed("UNREADABLE", "the templatev10 table did not answer a count")
    for table in C3_TEMPLATE_TABLES:
        if before[table]:
            run.write(lambda drv, _t=table: drv.erase_table(table=_t), label=f"erase_{table}",
                      timeout=T_ERASE)
    left = {t: _count(run, t) for t in C3_TEMPLATE_TABLES if before[t]}
    left = {t: n for t, n in left.items() if n != 0}
    if left:
        raise StepFailed("NOT_ERASED", f"rows left or unreadable after the erase: {left}")
    detail = " ".join(f"{t}={'absent' if before[t] is None else before[t]}" for t in C3_TEMPLATE_TABLES)
    return "ERASED", detail


def _people(run: Runway, label: str) -> List[Dict[str, Any]]:
    res = run.read(lambda drv: drv.list_device_users(timeout_sec=TD_LIST), label=label,
                   timeout=T_READ) or {}
    if not res.get("ok"):
        raise StepFailed("LIST_FAILED", f"the terminal's user list did not read: {res.get('error')}")
    return terminal_people(PROTO_STANDALONE, list(res.get("users") or []))


def _fingerprint_counter(run: Runway, label: str) -> int:
    res = run.read(lambda drv: drv.read_device_status(timeout_sec=TD_STATUS), label=label,
                   timeout=T_COUNT) or {}
    value = (res.get("status") or {}).get("fingerprints") if res.get("ok") else None
    if not isinstance(value, int) or isinstance(value, bool):
        raise StepFailed("STATUS_UNREADABLE", "the terminal's fingerprint counter did not read")
    return value


def _erase_fingers_mb(run: Runway, device_id: int) -> Tuple[str, str]:
    people = _people(run, "list_users")
    admins = [p["pin"] for p in people if p["admin"]]
    members = [p["pin"] for p in people if not p["admin"]]
    before = _fingerprint_counter(run, "status_before")
    admin_fps = 0
    for part in _chunks(admins, MB_TEMPLATE_PINS_PER_CALL):
        res = run.read(lambda drv, _p=part: drv.read_user_templates(_p, timeout_sec=TD_TEMPLATES),
                       label="admin_templates", timeout=T_READ) or {}
        if not res.get("ok"):
            raise StepFailed("TEMPLATES_UNREADABLE", f"administrator templates: {res.get('error')}")
        admin_fps += sum(len(v or []) for v in (res.get("templates") or {}).values())
    swept = 0
    if before != admin_fps:
        for pin in members:
            parts = _chunks(list(MB_SLOTS), MB_SWEEP_SLOTS_PER_CALL)
            for j, slots in enumerate(parts):
                res = run.write(
                    lambda drv, _pin=pin, _s=slots, _last=(j == len(parts) - 1):
                    drv.sweep_finger_slots(_pin, _s, refresh=_last, timeout_sec=TD_SWEEP),
                    label="sweep_fingers", timeout=T_ERASE) or {}
                if not res.get("ok"):
                    raise StepFailed("SWEEP_FAILED", f"pin {pin}: {res.get('error')}")
            swept += 1
        after = _fingerprint_counter(run, "status_after")
        if after != admin_fps:
            raise StepFailed("NOT_ERASED", f"the terminal counts {after} template(s), the "
                                           f"administrators had {admin_fps}")
    mark_fingers_erased(device_id, keep_pins=admins)
    return "ERASED", f"fingerprints={before - admin_fps} swept={swept} admins_kept={len(admins)}"


def erase_fingerprints(run: Runway, proto: str, *, device_id: int) -> Tuple[str, str]:
    """D11 on one turnstile. Returns ("ERASED", detail) or raises StepFailed."""
    if proto == PROTO_PULLSDK:
        return _erase_fingers_c3(run)
    if proto == PROTO_STANDALONE:
        return _erase_fingers_mb(run, device_id)
    raise StepFailed("UNKNOWN_DRIVER", f"no fingerprint erase for protocol {proto!r}")


# ------------------------------------------------------------------ D13: cards
def _delete_one_user(run: Runway, pin: str) -> int:
    rc = run.write(lambda drv: drv.delete_table_rows(table="user", data=f"Pin={pin}\r\n"),
                   label="delete_user_pin", timeout=T_ERASE)
    return -1 if rc is None else int(rc)


def _remove_c3(run: Runway, pins: List[str]) -> Set[str]:
    for table in C3_DELETE_ORDER:
        for part in _chunks(pins, C3_PINS_PER_DELETE):
            data = "".join(f"Pin={p}\r\n" for p in part)
            rc = run.write(lambda drv, _t=table, _d=data: drv.delete_table_rows(table=_t, data=_d),
                           label=f"delete_{table}", timeout=T_ERASE)
            if rc is not None and int(rc) >= 0:
                continue
            if table != "user":
                _log.warning("[REMOVAL] delete from %s refused for %d pin(s) (the rows may not exist)",
                             table, len(part))
                continue
            # A refused chunk: one pin at a time, as device_sync.py _bulk_delete_pins falls back.
            failed = [p for p in part if _delete_one_user(run, p) < 0]
            if failed:
                raise StepFailed("DELETE_FAILED", f"user rows of {len(failed)} pin(s) not deleted "
                                                  f"(e.g. {failed[:5]})")
    rows = run.read(lambda drv: drv.read_table_strict(table="user"), label="read_users",
                    timeout=T_READ)
    return {p["pin"] for p in terminal_people(PROTO_PULLSDK, list(rows or []))}


def _remove_mb(run: Runway, pins: List[str]) -> Set[str]:
    for part in _chunks(pins, MB_DELETE_PINS_PER_CALL):
        res = run.write(lambda drv, _p=part: drv.delete_users(_p, timeout_sec=TD_DELETE),
                        label="delete_users", timeout=T_ERASE) or {}
        if not res.get("ok") or res.get("failed_pins"):
            raise StepFailed("DELETE_FAILED", f"{len(res.get('failed_pins') or part)} pin(s) not "
                                              f"deleted: {res.get('errors') or res.get('error')}")
    return {p["pin"] for p in _people(run, "list_users_after")}


def remove_cards(run: Runway, proto: str, *, device_id: int) -> Tuple[str, str]:
    """D13 on one turnstile. Returns ("REMOVED", detail) or raises StepFailed."""
    snapshot = owned_rows(device_id)
    if proto == PROTO_STANDALONE:
        # Only pins the terminal lists are deleted (a delete of an absent pin is not known to
        # answer True on this firmware); an administrator never, even one MonClub recorded.
        people = _people(run, "list_users")
        admins = {p["pin"] for p in people if p["admin"]}
        present = {p["pin"] for p in people}
        pins = [p for p in sorted(snapshot) if p not in admins]
        targets = [p for p in pins if p in present]
        on_device = _remove_mb(run, targets) if targets else present
    elif proto == PROTO_PULLSDK:
        pins = targets = sorted(snapshot)     # DeleteDeviceData of an absent pin succeeds (device_sync.py)
        on_device = _remove_c3(run, targets) if targets else set()
    else:
        raise StepFailed("UNKNOWN_DRIVER", f"no card removal for protocol {proto!r}")
    if not pins:
        return "REMOVED", "users=0 records=0"
    left = [p for p in targets if p in on_device]
    if left:
        raise StepFailed("NOT_REMOVED", f"{len(left)} pin(s) still on the turnstile (e.g. {left[:5]})")
    forgotten = forget_removed_pins(device_id, {p: snapshot[p] for p in pins}, on_device)
    return "REMOVED", f"users={len(targets)} records={forgotten}"
