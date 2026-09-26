"""The ownership backup on the PC (P2c-2 §1; owner decisions 1, 5a, 8).

Which pins MonClub put on each turnstile lives in this PC's SQLite (``device_sync_state``
with ``ownership_confirmed``, the write-ahead ``device_push_intent``). A new or reinstalled
driver has none of it, and without it every departed member reads as "not provably MonClub's"
and stays on the turnstile. The server keeps a copy; this module feeds and reads it.

Upload (every ``UPLOAD_EVERY_SEC`` for the turnstiles this PC drives, and a FULL final upload
before a release):
* ``APPLIED``  — ``device_sync_state.ownership_confirmed = 1`` (hash, recorded fingers);
* ``FAILED``   — a row with ``ownership_confirmed = 0`` (a write not proven);
* ``INTENT``   — a ``device_push_intent`` row with no confirmed state;
* ``REMOVED``  — ONLY from ``v2_removal_log`` (written in the removal's own transaction). A row
  that vanished from ``device_sync_state`` (a prune, a hash clear) is NEVER uploaded as removed.
Rows older than the device's latest pin-scheme switch belong to the old scheme and are not
uploaded under the new one.

``observedAt`` is the FACT time on the server's clock (owner decision 5a): the row's
``updated_at`` (local PC time) plus the measured offset, or the corrected removal time; bumped
past this PC's last upload of that pin when the state changed; capped at the corrected "now"
(the server refuses a fact later than ``sentAt``) and the capped value is what is recorded.

Restore (a DRIVE lease this PC has not restored for its generation): every page of the
current generation; an ``APPLIED`` row this PC has no confirmed state for becomes
``device_sync_state(ownership_confirmed=1, desired_hash=pushedHash, last_ok=1,
pushed_finger_ids=pushedFingerIds, finger_slots_swept=1)`` — the engine's own hash comparison
then skips a member already in sync (no ~900-member re-push after a handover) and pushes one
that is not. Local ownership is never lowered; ``REMOVED``/absent rows prove nothing about a
pin on the turnstile (the server's clock-window caveat, P2c-2 report) and are not used.

Release (a ``release[]`` entry): writes are frozen by the lease gate; once no full pass is
running the whole record is uploaded with ``finalPage=true`` (the server records the release
upload), then ``POST /assignment/release``.

Read-back (a DRIVE lease with ``handoverForced``, once restored): one listing of the turnstile
through its worker, then ``POST /assignment/read-back`` — the only way the flag clears; until
then the turnstile stays add-only.

Wipe: a PullSDK table clear posts ``/ownership/wiped`` (``note_wipe``); the next uploads go to
the new generation.
"""
from __future__ import annotations

import datetime as _dt
import logging
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.core.v2 import lease_gate, timefmt
from app.core.v2.api import V2ApiError

_log = logging.getLogger("zkapp.v2.ownership")

UPLOAD_EVERY_SEC = 300.0
META_TTL_SEC = 600.0
PAGE_ROWS = 1000
RETRY_SEC = 60.0
RELEASE_IDLE_GRACE_SEC = 2.0
WIPE_KEY_PREFIX = "wipe:"


def note_wipe(device_id: int) -> None:
    """Called where a PullSDK panel's user tables were cleared (device_sync)."""
    from app.core.v2 import store
    from app.core.v2.server_clock import corrected_now

    at, corrected = corrected_now()
    store.kv_put(f"{WIPE_KEY_PREFIX}{int(device_id)}", {"wipedAt": at, "corrected": corrected})


def _local_to_epoch(text: Any) -> Optional[float]:
    if not text:
        return None
    try:
        moment = _dt.datetime.strptime(str(text)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            moment = _dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
            if moment.tzinfo is not None:
                return moment.timestamp()
        except ValueError:
            return None
    return time.mktime(moment.timetuple())


def local_facts(device_id: int) -> Dict[str, Dict[str, Any]]:
    """pin -> {state, pushedHash, pushedFingerIds, pc_epoch, corrected} for one turnstile."""
    from app.core.db import get_conn, list_device_pin_scheme_switches

    did = int(device_id)
    try:
        switches = (list_device_pin_scheme_switches(device_id=did) or {}).get(did) or []
    except Exception:
        switches = []
    cutoff = _local_to_epoch(switches[-1].get("switched_at")) if switches else None
    facts: Dict[str, Dict[str, Any]] = {}
    with get_conn() as conn:
        for pin, h, fingers, owned, updated in conn.execute(
                "SELECT pin, desired_hash, pushed_finger_ids, ownership_confirmed, updated_at "
                "FROM device_sync_state WHERE device_id = ?", (did,)).fetchall():
            at = _local_to_epoch(updated)
            if at is None or (cutoff is not None and at < cutoff):
                continue
            facts[str(pin)] = {"state": "APPLIED" if int(owned or 0) == 1 else "FAILED",
                               "pushedHash": h or None, "pushedFingerIds": fingers,
                               "at": at, "corrected": False}
        for pin, updated in conn.execute(
                "SELECT pin, updated_at FROM device_push_intent WHERE device_id = ?", (did,)).fetchall():
            if str(pin) in facts and facts[str(pin)]["state"] == "APPLIED":
                continue
            at = _local_to_epoch(updated)
            if at is None or (cutoff is not None and at < cutoff):
                continue
            facts[str(pin)] = {"state": "INTENT", "pushedHash": None, "pushedFingerIds": None,
                               "at": at, "corrected": False}
        for pin, removed_at, corrected in conn.execute(
                "SELECT pin, removed_at, corrected FROM v2_removal_log WHERE device_id = ?", (did,)).fetchall():
            if str(pin) in facts:
                continue          # written again after the removal: the current state wins
            facts[str(pin)] = {"state": "REMOVED", "pushedHash": None, "pushedFingerIds": None,
                               "at": float(removed_at), "corrected": bool(corrected)}
    return facts


def _canon_fingers(value: Any) -> Optional[str]:
    if value is None:
        return None
    parts = sorted({int(p) for p in str(value).replace(" ", "").split(",") if p.isdigit() and 0 <= int(p) <= 9})
    return ",".join(str(p) for p in parts)


class OwnershipSync:
    """A runtime extension: ``tick(runtime)`` from the v2 control thread."""

    def __init__(self, runtime: Any) -> None:
        self.rt = runtime
        self._meta: Dict[int, Tuple[float, Dict[str, Any]]] = {}
        self._next_upload: Dict[int, float] = {}
        self._lost_done: set = set()      # not-driven turnstiles with nothing (more) to upload
        self._next_restore: Dict[int, float] = {}
        self._next_readback: Dict[int, float] = {}
        self._release_since: Dict[int, float] = {}
        self._next_release: Dict[int, float] = {}
        self._lock = threading.Lock()
        self.last: Dict[str, Any] = {}

    # ------------------------------------------------------------------ helpers
    @property
    def api(self):
        return self.rt.api

    def _mono(self) -> float:
        return time.monotonic()

    def _device_scheme(self, did: int) -> Optional[str]:
        try:
            from app.core.db import get_sync_device_payload
            from app.core.pin_scheme import device_pin_scheme
            payload = get_sync_device_payload(int(did))
            return device_pin_scheme(payload) if payload else None
        except Exception:
            return None

    def meta(self, did: int, *, fresh: bool = False) -> Dict[str, Any]:
        """The server's current generation + scheme for a turnstile (GET page of 1)."""
        cached = self._meta.get(did)
        if cached and not fresh and self._mono() - cached[0] < META_TTL_SEC:
            return cached[1]
        page = self.api.ownership_page(did, 0, 1)
        meta = {k: page.get(k) for k in ("generation", "pinScheme", "bumpReason", "wipedAt",
                                         "handoverForced", "forcedReason")}
        self._meta[did] = (self._mono(), meta)
        return meta

    def _forget(self, did: int) -> None:
        self._meta.pop(did, None)

    # ------------------------------------------------------------------ upload
    def _uploaded(self, did: int, scheme: str, generation: int) -> Dict[str, Tuple]:
        from app.core.db import get_conn
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT pin, state, pushed_hash, pushed_finger_ids, observed_at FROM v2_ownership_uploaded "
                "WHERE device_id = ? AND pin_scheme = ? AND generation = ?", (did, scheme, generation)).fetchall()
        return {str(r[0]): (r[1], r[2], r[3], float(r[4])) for r in rows}

    def _record_uploaded(self, did: int, scheme: str, generation: int, rows: List[Dict[str, Any]],
                         epochs: Dict[str, float]) -> None:
        from app.core.db import _run_db_write_sync

        def op(conn, _p):
            for r in rows:
                conn.execute(
                    "INSERT OR REPLACE INTO v2_ownership_uploaded (device_id, pin_scheme, generation, pin, state, "
                    "pushed_hash, pushed_finger_ids, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (did, scheme, generation, r["pin"], r["state"], r.get("pushedHash"), r.get("pushedFingerIds"),
                     epochs[r["pin"]]))
        _run_db_write_sync("v2_ownership_uploaded", op)

    def build_rows(self, did: int, scheme: str, generation: int, *, full: bool) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
        clock = self.rt.clock
        offset = clock.offset() or 0.0
        now = clock.now()
        prev = self._uploaded(did, scheme, generation)
        rows: List[Dict[str, Any]] = []
        epochs: Dict[str, float] = {}
        for pin, f in sorted(local_facts(did).items()):
            if not pin.isdigit() or len(pin) > 24:
                continue
            fingers = _canon_fingers(f.get("pushedFingerIds"))
            h = f.get("pushedHash")
            if h is not None and not (str(h).isalnum() and len(str(h)) <= 64):
                h = None
            before = prev.get(pin)
            if (f["state"] == "REMOVED" and before is not None and before[0] != "REMOVED"
                    and (f["at"] if f["corrected"] else f["at"] + offset) <= before[3]):
                # A removal logged BEFORE the state this PC already uploaded (the pin was written
                # again, then its state row went without a device removal -- a prune): not a
                # newer fact. Bumping it past the upload would claim a removal that never happened.
                continue
            same = before is not None and before[:3] == (f["state"], h, fingers)
            if same and not full:
                continue
            at = f["at"] if f["corrected"] else f["at"] + offset
            if before is not None:
                if same:
                    at = before[3]                    # a re-send keeps its recorded time
                elif at <= before[3]:
                    at = before[3] + 0.001            # a changed state must be strictly newer
            at = min(at, now)                          # never later than sentAt
            epochs[pin] = at
            rows.append({"pin": pin, "state": f["state"], "pushedHash": h, "pushedFingerIds": fingers,
                         "observedAt": timefmt.format_utc(at)})
        return rows, epochs

    def _last_uploaded_meta(self, did: int) -> Optional[Dict[str, Any]]:
        """The (scheme, generation) of this PC's own latest upload for a turnstile, if any."""
        from app.core.db import get_conn
        with get_conn() as conn:
            row = conn.execute(
                "SELECT pin_scheme, generation FROM v2_ownership_uploaded WHERE device_id = ? "
                "ORDER BY generation DESC LIMIT 1", (did,)).fetchone()
        return {"pinScheme": row[0], "generation": int(row[1])} if row else None

    def upload(self, did: int, *, final: bool = False,
               known_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Upload what changed (or everything, ``final``). Returns a summary; raises V2ApiError.
        ``known_meta``: a turnstile this PC does not drive -- the server's GET (the restore
        route) refuses it NOT_DEVICE_DRIVER, so the scheme and generation of this PC's own last
        upload are used; the POST itself is open to any ACTIVE PC of the gym."""
        if known_meta is None:
            if not self.rt.clock.has_sample():
                self.meta(did, fresh=True)             # a GET gives the first clock sample
            meta = self.meta(did)
        else:
            meta = known_meta
        scheme, generation = str(meta.get("pinScheme") or ""), int(meta.get("generation") or 0)
        local_scheme = self._device_scheme(did)
        if not generation or not scheme or (local_scheme and local_scheme != scheme):
            self._forget(did)
            return {"skipped": "scheme_or_generation_unknown", "server": scheme, "local": local_scheme}
        rows, epochs = self.build_rows(did, scheme, generation, full=final)
        pages = [rows[i:i + PAGE_ROWS] for i in range(0, len(rows), PAGE_ROWS)] or [[]]
        if not final and not rows:
            return {"rows": 0}
        summary = {"rows": len(rows), "stored": 0, "ignoredNotNewer": 0, "ignoredOutdated": 0,
                   "releaseRecorded": False}
        for i, page in enumerate(pages):
            body = {"gymDeviceId": did, "pinScheme": scheme, "generation": generation,
                    "finalPage": bool(final and i == len(pages) - 1), "totalRows": len(rows), "rows": page}
            try:
                ans = self.api.ownership_upload(body)
            except V2ApiError as exc:
                if exc.backend and exc.code in ("STALE_OWNERSHIP_GENERATION", "PIN_SCHEME_MISMATCH"):
                    self._forget(did)
                raise
            for k in ("stored", "ignoredNotNewer", "ignoredOutdated"):
                summary[k] += int(ans.get(k) or 0)
            summary["releaseRecorded"] = summary["releaseRecorded"] or bool(ans.get("releaseRecorded"))
            # Record the times as SENT (capped at that attempt's sentAt) -- the server's rule:
            # a capped time is written back, or each re-send would look newer.
            sent_rows = (getattr(self.api, "last_body", None) or {}).get("rows") or page
            for r in sent_rows:
                t = timefmt.to_epoch(r.get("observedAt")) if isinstance(r, dict) else None
                if t is not None and r.get("pin") in epochs:
                    epochs[r["pin"]] = t
            self._record_uploaded(did, scheme, generation, sent_rows, epochs)
        return summary

    # ------------------------------------------------------------------ restore
    def restore(self, did: int, lease_generation: int) -> int:
        """Adopt the server's APPLIED rows this PC lacks. Returns rows adopted; raises V2ApiError."""
        from app.core.db import _run_db_write_sync
        from app.core.utils import now_iso

        after, adopted = 0, 0
        local_scheme = self._device_scheme(did)
        while True:
            page = self.api.ownership_page(did, after, 1000)
            if local_scheme and page.get("pinScheme") and page.get("pinScheme") != local_scheme:
                # The server's record is of another pin scheme than this PC pushes: adopting
                # it would claim pins of the other numbering. Retried once the schemes agree.
                raise V2ApiError(409, "PIN_SCHEME_MISMATCH", "restore: pin scheme differs", backend=False)
            rows = [r for r in page.get("rows") or [] if isinstance(r, dict) and r.get("state") == "APPLIED"]
            if rows:
                def op(conn, _p, rows=rows):
                    n = 0
                    stamp = now_iso()
                    for r in rows:
                        pin = str(r.get("pin") or "").strip()
                        if not pin.isdigit():
                            continue
                        cur = conn.execute("SELECT ownership_confirmed FROM device_sync_state "
                                           "WHERE device_id = ? AND pin = ?", (did, pin)).fetchone()
                        if cur is not None and int(cur[0] or 0) == 1:
                            continue          # this PC's own proof wins
                        conn.execute(
                            "INSERT INTO device_sync_state (device_id, pin, desired_hash, last_ok, last_error, "
                            "updated_at, pushed_finger_ids, ownership_confirmed, finger_slots_swept) "
                            "VALUES (?, ?, ?, 1, NULL, ?, ?, 1, 1) "
                            "ON CONFLICT(device_id, pin) DO UPDATE SET ownership_confirmed = 1, "
                            "desired_hash = excluded.desired_hash, last_ok = 1, "
                            "pushed_finger_ids = excluded.pushed_finger_ids, finger_slots_swept = 1, "
                            "updated_at = excluded.updated_at",
                            (did, pin, r.get("pushedHash"), stamp, r.get("pushedFingerIds")))
                        n += 1
                    return n
                adopted += int(_run_db_write_sync("v2_ownership_restore", op) or 0)
            nxt = page.get("nextAfterId")
            if not nxt:
                break
            after = int(nxt)
        self.rt.leases.mark_restored(did, lease_generation, adopted=adopted)
        _log.info("[V2] ownership restored for turnstile %s (lease generation %s): %d pin(s) adopted",
                  did, lease_generation, adopted)
        return adopted

    # ------------------------------------------------------------------ read-back
    def read_back(self, did: int, lease_generation: int) -> bool:
        pins = self.rt.handlers._list_device_pins(did, timeout=90.0)
        if pins is None:
            return False
        ans = self.api.read_back(did, lease_generation)
        _log.info("[V2] read-back confirmed for turnstile %s: %d user(s) listed, cleared=%s",
                  did, len(pins), ans.get("clearedReason"))
        self.rt.refresh_assignment()
        return True

    # ------------------------------------------------------------------ release
    def _worker_idle(self, did: int) -> bool:
        """No pass is writing to the turnstile: the ULTRA worker's full sync (either SDK: its
        private DeviceSync engine included) and the DEVICE-mode DeviceSync engine (review R3)."""
        app = self.rt.app
        eng = getattr(app, "_ultra_engine", None)
        worker = (getattr(eng, "_workers", None) or {}).get(did) if eng is not None else None
        if worker is not None and (bool(getattr(worker, "_full_sync_running", False))
                                   or getattr(worker, "_active_sync_engine", None) is not None):
            return False
        dev_engine = getattr(app, "_device_sync_engine", None)
        if dev_engine is not None and bool(getattr(dev_engine, "_running", False)):
            return False
        sched = getattr(eng, "_sync_scheduler", None) if eng is not None else None
        if sched is not None and getattr(sched, "_active_sync_engine", None) is not None:
            return False                # the scheduler's PullSDK fallback pass (worker not usable)
        return True

    def release(self, did: int, generation: int) -> Optional[str]:
        now = self._mono()
        since = self._release_since.setdefault(did, now)
        if now - since < RELEASE_IDLE_GRACE_SEC or not self._worker_idle(did):
            return None                                   # let a write in flight finish first
        summary = self.upload(did, final=True)
        if not summary.get("releaseRecorded"):
            self.rt.refresh_assignment()                  # no longer releasing (or not us)
            return "NOT_RECORDED"
        ans = self.api.release(did, generation)
        outcome = str(ans.get("outcome") or "")
        _log.info("[V2] turnstile %s released (generation %s): %s", did, generation, outcome)
        self._release_since.pop(did, None)
        self.rt.refresh_assignment()
        return outcome

    # ------------------------------------------------------------------ wipes
    def report_wipes(self, drivable: Iterable[int]) -> None:
        from app.core.v2 import store
        for did in drivable:
            rec = store.kv_get(f"{WIPE_KEY_PREFIX}{did}")
            if not isinstance(rec, dict):
                continue
            at = float(rec.get("wipedAt") or 0.0)
            if not rec.get("corrected"):
                at += self.rt.clock.offset() or 0.0
            at = min(at, self.rt.clock.now())
            meta = self.meta(did, fresh=True)
            try:
                self.api.ownership_wiped(did, int(meta.get("generation") or 0), at)
            except V2ApiError as exc:
                if not (exc.backend and exc.code == "STALE_OWNERSHIP_GENERATION"):
                    raise
                cur = (exc.details or {}).get("currentGeneration")
                if cur:
                    self.api.ownership_wiped(did, int(cur), at)
            store.kv_delete(f"{WIPE_KEY_PREFIX}{did}")
            self._forget(did)

    # ------------------------------------------------------------------ the tick
    def _drivable(self) -> List[int]:
        snap = lease_gate.current()
        if snap.mode == lease_gate.MODE_LEASED:
            # Only once restored: before that this PC's record of a turnstile it drove long ago
            # is not what it will act on.
            return sorted(d for d, e in snap.drive.items()
                          if e.state == "DRIVE" and self.rt.leases.restored_generation(d) == e.generation)
        eng = getattr(self.rt.app, "_ultra_engine", None)
        ids = set(getattr(eng, "_workers", {}) or {}) if eng is not None and getattr(eng, "running", False) else set()
        try:
            from app.core.db import get_conn
            with get_conn() as conn:
                ids |= {int(r[0]) for r in conn.execute("SELECT DISTINCT device_id FROM device_sync_state").fetchall()}
        except Exception:
            pass
        return sorted(d for d in ids if d > 0)

    def _lost_with_facts(self, snap: "lease_gate.LeaseSnapshot") -> List[int]:
        """Turnstiles this PC holds ownership facts for but does not drive (a forced move, or
        a move while it was offline or revoked: no release, so no final upload; or pins it
        pushed before the gym used leases). Their facts are still uploaded, changes only,
        under the server's current generation: the server keeps the newer fact per pin, so
        nothing the new driver wrote is overwritten, and the members this PC pushed stay
        provably MonClub's (review R7). No wipe is reported for them and nothing connects to
        the turnstile: this is the local record only."""
        if snap.mode != lease_gate.MODE_LEASED:
            return []
        try:
            from app.core.db import get_conn
            with get_conn() as conn:
                ids = {int(r[0]) for r in conn.execute(
                    "SELECT DISTINCT device_id FROM device_sync_state").fetchall()}
        except Exception:
            return []
        return sorted(d for d in ids
                      if d > 0 and d not in snap.drive and d not in snap.release)

    def tick(self, runtime: Any) -> None:
        snap = lease_gate.current()
        now = self._mono()
        for did, rel in sorted(snap.release.items()):
            if now < self._next_release.get(did, 0.0):
                continue
            try:
                outcome = self.release(did, rel.generation)
                if outcome is not None and outcome not in ("RELEASED", "HANDOVER_CANCELLED"):
                    self._next_release[did] = now + RETRY_SEC
            except V2ApiError as exc:
                self._next_release[did] = now + RETRY_SEC
                self.last["release"] = f"{did}: {exc.code}"
                if exc.backend and exc.code in ("STALE_GENERATION", "NO_PENDING_RELEASE"):
                    self.rt.refresh_assignment()
        if snap.mode == lease_gate.MODE_LEASED:
            for did, entry in sorted(snap.drive.items()):
                if entry.state != "DRIVE":
                    continue
                if self.rt.leases.restored_generation(did) != entry.generation:
                    if now >= self._next_restore.get(did, 0.0):
                        try:
                            self.restore(did, entry.generation)
                        except V2ApiError as exc:
                            self._next_restore[did] = now + RETRY_SEC
                            self.last["restore"] = f"{did}: {exc.code}"
                    continue
                if entry.handover_forced and now >= self._next_readback.get(did, 0.0):
                    self._next_readback[did] = now + 3600.0
                    try:
                        if not self.read_back(did, entry.generation):
                            self._next_readback[did] = now + 600.0
                    except V2ApiError as exc:
                        self.last["readBack"] = f"{did}: {exc.code}"
                        if exc.backend and exc.code in ("STALE_GENERATION", "NOT_DEVICE_DRIVER"):
                            self.rt.refresh_assignment()
        drivable = [d for d in self._drivable() if d not in snap.release]
        try:
            self.report_wipes(drivable)
        except V2ApiError as exc:
            self.last["wipe"] = exc.code
        for did in drivable:
            self._lost_done.discard(did)
            if now < self._next_upload.get(did, 0.0):
                continue
            self._next_upload[did] = now + UPLOAD_EVERY_SEC
            try:
                self.last[f"upload:{did}"] = self.upload(did)
            except V2ApiError as exc:
                self._next_upload[did] = now + RETRY_SEC
                self.last[f"upload:{did}"] = {"error": exc.code}
        if not self.rt.clock.has_sample():
            return                                   # no sentAt the server would accept yet
        for did in self._lost_with_facts(snap):
            if did in self._lost_done or now < self._next_upload.get(did, 0.0):
                continue
            self._next_upload[did] = now + UPLOAD_EVERY_SEC
            try:
                known = self._last_uploaded_meta(did)
                local_scheme = self._device_scheme(did)
                if known is None or (local_scheme and local_scheme != known["pinScheme"]):
                    # Never uploaded by this PC (e.g. pins pushed only before the gym used
                    # leases): no generation to post under, and the GET is refused -- nothing
                    # to send (guide §3.9 residual).
                    self._lost_done.add(did)
                    continue
                try:
                    self.last[f"upload:{did}"] = self.upload(did, known_meta=known)
                except V2ApiError as exc:
                    cur = (exc.details or {}).get("currentGeneration") if isinstance(exc.details, dict) else None
                    if not (exc.backend and exc.code == "STALE_OWNERSHIP_GENERATION"
                            and isinstance(cur, int) and cur > known["generation"]
                            and exc.details.get("pinScheme") == known["pinScheme"]):
                        raise
                    # A generation bumped after this PC's last upload -- its own wipe report
                    # (DEVICE_WIPED; the refusal's pinScheme must still be ours): the server refuses any
                    # fact older than the wipe, so posting under the current one cannot plant a
                    # stale fact (review round 3).
                    self.last[f"upload:{did}"] = self.upload(
                        did, known_meta={"pinScheme": known["pinScheme"], "generation": cur})
            except V2ApiError as exc:
                self.last[f"upload:{did}"] = {"error": exc.code}
                if exc.code == "CLOCK_SKEW" or not exc.backend or exc.status >= 429:
                    self._next_upload[did] = now + RETRY_SEC          # transient
                elif exc.status in (403, 404, 409, 400):
                    # STALE_OWNERSHIP_GENERATION, PIN_SCHEME_MISMATCH, a refusal: never retried
                    # every minute; tried again after a restart or once this PC drives it.
                    self._lost_done.add(did)
                else:
                    self._next_upload[did] = now + RETRY_SEC

    def status(self) -> Dict[str, Any]:
        return {"ownership": dict(self.last)}
