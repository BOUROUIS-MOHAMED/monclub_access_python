"""Remote commands on the PC (P2b §5, payloads locked by P2c-2 §5).

At most once, never late:
1. A command id seen (socket notice or the pending poll) gets a journal row with a fresh claim
   token BEFORE the claim, so a lost claim answer can be re-claimed with the same token.
2. ``claim``: a 404/409 (finished, expired, claimed by someone else, not this PC's) is final —
   nothing runs.
3. The journal row turns ``STARTED`` in a DURABLE write (``synchronous=FULL``, like the push
   intents) BEFORE the command acts. A row found ``STARTED`` without an outcome after a restart
   is never run again: it is reported ``FAILED INTERRUPTED``.
4. The deadline is the claim answer's ``finishBy - serverTime`` (both the server's Tunis local
   clock, so no offset is needed) counted from the moment the answer arrived. A command whose
   remaining time is below its type's margin is not started (``FAILED EXPIRED``).
5. The result is posted until the server acknowledges it (a late result is accepted while the
   row is CLAIMED and flagged ``late``), for up to ``REPORT_GIVE_UP_SEC``.

Handlers run on their own thread per command (an enrolment may wait minutes); the executor
thread only claims and dispatches, so a DOOR_OPEN is never queued behind an enrolment.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from app.core.v2 import timefmt
from app.core.v2.api import V2Api, V2ApiError

_log = logging.getLogger("zkapp.v2.commands")

SEEN, STARTED, DONE = "SEEN", "STARTED", "DONE"
REPORT_GIVE_UP_SEC = 3600.0
# Minimum time left (s) for a command to start: a door must open within the window, an
# enrolment needs time for three finger presses.
CLAIM_RETRY_MAX = 6
START_MARGIN_SEC = {"DOOR_OPEN": 10.0, "CARD_SCAN": 5.0, "ENROLL_START": 30.0}
# DOOR_OPEN, 10 s (review R6): the desk handler it reuses can take the ULTRA queue's 2 s + 5 s,
# or the AGENT bus's 4 s followed by a direct PullSDK connect and pulse; with 10 s left the open
# lands inside the command's 20 s window in every path measured here (the PullSDK connect is
# bounded by the device's own timeout, not by this code -- guide §3.9).
DEFAULT_START_MARGIN_SEC = 2.0

Outcome = Tuple[str, Optional[str], Optional[Dict[str, Any]]]     # (SUCCEEDED|FAILED, code, detail)


@dataclass
class CommandRun:
    id: str
    type: str
    gym_device_id: Optional[int]
    payload: Optional[Dict[str, Any]]
    deadline_mono: float
    claim_token: str
    cancel: threading.Event = field(default_factory=threading.Event)
    progress: Callable[[Dict[str, Any]], None] = lambda _p: None

    def remaining(self, mono: Callable[[], float] = time.monotonic) -> float:
        return self.deadline_mono - mono()


class Journal:
    """``v2_command_journal`` access (tests pass an in-memory one)."""

    def get(self, cid: str) -> Optional[Dict[str, Any]]:
        from app.core.db import get_conn
        with get_conn() as conn:
            conn.row_factory = None
            cur = conn.execute(
                "SELECT id, type, claim_token, state, gym_device_id, payload_json, finish_by, started_at, "
                "outcome, result_code, result_json, reported, created_at FROM v2_command_journal WHERE id = ?",
                (cid,))
            row = cur.fetchone()
            if not row:
                return None
            keys = [d[0] for d in cur.description]
        return dict(zip(keys, row))

    def _write(self, label, sql, args, durable=False):
        from app.core.db import _run_db_write_sync
        _run_db_write_sync(label, lambda conn, _p: conn.execute(sql, args), durable=durable)

    def insert_seen(self, cid: str, ctype: str, token: str) -> None:
        now = time.time()
        self._write("v2_cmd_seen",
                    "INSERT OR IGNORE INTO v2_command_journal (id, type, claim_token, state, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)", (cid, ctype, token, SEEN, now, now))

    def mark_started(self, cid: str, ctype: str, device_id, payload, finish_by) -> None:
        now = time.time()
        self._write("v2_cmd_started",
                    "UPDATE v2_command_journal SET state = ?, type = ?, gym_device_id = ?, payload_json = ?, "
                    "finish_by = ?, started_at = ?, updated_at = ? WHERE id = ?",
                    (STARTED, ctype, device_id, json.dumps(payload) if payload is not None else None,
                     finish_by, now, now, cid), durable=True)

    def set_outcome(self, cid: str, outcome: str, code: Optional[str], detail: Optional[Dict[str, Any]],
                    *, state: str = STARTED) -> None:
        self._write("v2_cmd_outcome",
                    "UPDATE v2_command_journal SET state = ?, outcome = ?, result_code = ?, result_json = ?, "
                    "updated_at = ? WHERE id = ?",
                    (state, outcome, code, json.dumps(detail) if detail is not None else None, time.time(), cid))

    def mark_done(self, cid: str, *, reported: bool, code: Optional[str] = None) -> None:
        self._write("v2_cmd_done",
                    "UPDATE v2_command_journal SET state = ?, reported = ?, "
                    "result_code = COALESCE(result_code, ?), updated_at = ? WHERE id = ?",
                    (DONE, 1 if reported else 0, code, time.time(), cid))

    def unreported(self) -> list:
        from app.core.db import get_conn
        with get_conn() as conn:
            cur = conn.execute(
                "SELECT id, claim_token, state, outcome, result_code, result_json, started_at "
                "FROM v2_command_journal WHERE reported = 0 AND state = ? ", (STARTED,))
            keys = [d[0] for d in cur.description]
            return [dict(zip(keys, r)) for r in cur.fetchall()]

    def recent(self, limit: int = 20) -> list:
        from app.core.db import get_conn
        with get_conn() as conn:
            cur = conn.execute(
                "SELECT id, type, state, gym_device_id, outcome, result_code, reported, created_at, updated_at "
                "FROM v2_command_journal ORDER BY created_at DESC LIMIT ?", (int(limit),))
            keys = [d[0] for d in cur.description]
            return [dict(zip(keys, r)) for r in cur.fetchall()]


class CommandExecutor(threading.Thread):
    def __init__(self, *, api: V2Api, handlers: Dict[str, Callable[[CommandRun], Outcome]],
                 journal: Optional[Journal] = None, mono: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time,
                 token_factory: Callable[[], str] = lambda: os.urandom(16).hex()) -> None:
        super().__init__(name="v2-commands", daemon=True)
        self._api = api
        self._handlers = handlers
        self._journal = journal or Journal()
        self._mono = mono
        self._wall = wall
        self._token_factory = token_factory
        self._q: "queue.Queue[str]" = queue.Queue()
        self._queued: set = set()
        self._running: Dict[str, CommandRun] = {}
        self._started_here: set = set()
        self._tokens: Dict[str, str] = {}       # cid -> the claim token first chosen in this process
        self._retry_at: Dict[str, tuple] = {}   # cid -> (due monotonic, attempts): transient claim failures      # ids this process started: never "interrupted"
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._last_report_sweep = 0.0
        self.last_error: Optional[str] = None
        self.stats = {"claimed": 0, "refused": 0, "succeeded": 0, "failed": 0, "interrupted": 0}

    # ------------------------------------------------------------------ intake
    def offer(self, command_id: str, command_type: str = "") -> None:
        cid = str(command_id or "").strip().lower()
        if not cid:
            return
        with self._lock:
            if cid in self._queued or cid in self._running:
                return
            self._queued.add(cid)
        self._q.put(cid)

    def poll_pending(self) -> int:
        """GET pending and offer each; returns the count offered. Raises V2ApiError."""
        body = self._api.pending()
        n = 0
        for c in body.get("commands") or []:
            if isinstance(c, dict) and c.get("id"):
                self.offer(str(c["id"]), str(c.get("type") or ""))
                n += 1
        return n

    def running(self) -> Dict[str, CommandRun]:
        with self._lock:
            return dict(self._running)

    def stop(self, timeout: float = 3.0) -> None:
        self._stop_event.set()
        self._q.put("")
        if self.is_alive():
            self.join(timeout)

    # ------------------------------------------------------------------ loop
    def run(self) -> None:
        self._recover_interrupted()
        while not self._stop_event.is_set():
            try:
                cid = self._q.get(timeout=1.0 if self._retry_at else 5.0)
            except queue.Empty:
                cid = None
            if cid:
                with self._lock:
                    self._queued.discard(cid)
                try:
                    self.process(cid)
                    self._retry_at.pop(cid, None)
                except Exception as exc:
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    _log.warning("[V2] command %s failed to process: %s", cid, self.last_error)
                    self._schedule_retry(cid)
            self._offer_due_retries()
            if self._mono() - self._last_report_sweep > 30.0:
                self._last_report_sweep = self._mono()
                self._report_sweep()

    def _schedule_retry(self, cid: str) -> None:
        """A claim that failed for a transient reason (timeout, proxy 5xx, local 429 backoff) is
        tried again: the server notifies a command once, so while the socket stays up nothing
        else would re-offer it (review round 3). 2, 4, 8, 16, 30, 30 s -- then the pending poll
        (after a reconnect, or every pollIntervalSec while the socket is down) is the backstop.
        A re-claim reuses the journal's claim token, so it is idempotent on the server."""
        due, attempts = self._retry_at.get(cid, (0.0, 0))
        if attempts >= CLAIM_RETRY_MAX:
            self._retry_at.pop(cid, None)
            return
        self._retry_at[cid] = (self._mono() + min(30.0, 2.0 * (2 ** attempts)), attempts + 1)

    def _offer_due_retries(self) -> None:
        now = self._mono()
        for cid, (due, _n) in list(self._retry_at.items()):
            if due <= now:
                self._retry_at[cid] = (float("inf"), _n)      # until process() settles it
                self.offer(cid)

    def _recover_interrupted(self) -> None:
        """A row STARTED without an outcome belongs to a process that died mid-command."""
        try:
            rows = self._journal.unreported()
        except Exception:
            return
        for row in rows:
            if row.get("outcome") is None and row["id"] not in self._running:
                self._journal.set_outcome(row["id"], "FAILED", "INTERRUPTED",
                                          {"message": "the PC restarted while this command ran; not run again"})
                self.stats["interrupted"] += 1

    # ------------------------------------------------------------------ one command
    def process(self, cid: str) -> None:
        row = self._journal.get(cid)
        if row is not None:
            if row["state"] == DONE:
                return
            if row["state"] == STARTED:
                if cid in self.running() or cid in self._started_here:
                    return
                if row.get("outcome") is None:
                    self._journal.set_outcome(cid, "FAILED", "INTERRUPTED",
                                              {"message": "the PC restarted while this command ran; not run again"})
                self._report(cid)
                return
            token = row["claim_token"]
        else:
            # One token per command for this process's life: an insert_seen that timed out
            # (DbWriter stall > 60 s) still commits later, so a retry must claim with the SAME
            # token or the result would be refused (review round 4).
            if cid not in self._tokens:
                self._tokens[cid] = self._token_factory()
            token = self._tokens[cid]
            self._journal.insert_seen(cid, "", token)
        sent = self._mono()
        try:
            answer = self._api.claim(cid, token)
        except V2ApiError as exc:
            if exc.backend and exc.status in (404, 409) and exc.code in (
                    "COMMAND_NOT_FOUND", "COMMAND_FINISHED", "COMMAND_ALREADY_CLAIMED", "COMMAND_EXPIRED",
                    "NOT_DEVICE_DRIVER"):
                self.stats["refused"] += 1
                self._journal.mark_done(cid, reported=False, code=exc.code)
                _log.info("[V2] command %s not run: %s", cid, exc.code)
                return
            raise                                          # retried at the next poll / notice
        recv = self._mono()
        view = answer.get("command") or {}
        remaining = timefmt.local_seconds_between(view.get("serverTime"), view.get("finishBy"))
        if remaining is None:
            self._journal.mark_done(cid, reported=False, code="BAD_CLAIM_ANSWER")
            return
        run = CommandRun(id=cid, type=str(view.get("type") or ""),
                         gym_device_id=_int_or_none(view.get("gymDeviceId")),
                         payload=view.get("payload") if isinstance(view.get("payload"), dict) else None,
                         deadline_mono=recv + remaining - (recv - sent) / 2.0, claim_token=token)
        self.stats["claimed"] += 1
        handler = self._handlers.get(run.type)
        margin = START_MARGIN_SEC.get(run.type, DEFAULT_START_MARGIN_SEC)
        # The at-most-once point: durable BEFORE anything acts.
        self._journal.mark_started(cid, run.type, run.gym_device_id, run.payload, view.get("finishBy"))
        self._started_here.add(cid)
        if handler is None:
            self._finish(run, ("FAILED", "UNSUPPORTED_TYPE", {"type": run.type}))
            return
        if run.remaining(self._mono) < margin:
            self._finish(run, ("FAILED", "EXPIRED", {"remainingSec": round(run.remaining(self._mono), 2)}))
            return
        run.progress = self._progress_fn(run)
        with self._lock:
            self._running[cid] = run
        t = threading.Thread(target=self._run_handler, args=(run, handler), name=f"v2-cmd-{run.type}",
                             daemon=True)
        try:
            t.start()
        except RuntimeError as exc:
            with self._lock:
                self._running.pop(cid, None)
            self._finish(run, ("FAILED", "NO_THREAD", {"message": str(exc)}))

    def _run_handler(self, run: CommandRun, handler) -> None:
        try:
            try:
                outcome = handler(run)
            except Exception as exc:
                outcome = ("FAILED", "ERROR", {"message": f"{type(exc).__name__}: {exc}"[:300]})
            # The outcome is journaled while the command is still "running" in this process:
            # a duplicate offer in between must not read STARTED-without-outcome as a crash
            # (review R1 -- it reported a door that opened as FAILED INTERRUPTED).
            self._finish(run, outcome)
        finally:
            with self._lock:
                self._running.pop(run.id, None)

    def _finish(self, run: CommandRun, outcome: Outcome) -> None:
        status, code, detail = outcome
        self.stats["succeeded" if status == "SUCCEEDED" else "failed"] += 1
        self._journal.set_outcome(run.id, status, code, detail)
        _log.info("[V2] command %s %s -> %s %s", run.id, run.type, status, code)
        self._report(run.id)

    def _report(self, cid: str) -> bool:
        row = self._journal.get(cid)
        if not row or row.get("outcome") is None:
            return False
        detail = None
        if row.get("result_json"):
            try:
                detail = json.loads(row["result_json"])
            except Exception:
                detail = None
        try:
            self._api.result(cid, row["claim_token"], row["outcome"], row.get("result_code"), detail)
        except V2ApiError as exc:
            if exc.backend and exc.status in (404, 409):
                self._journal.mark_done(cid, reported=False)       # the server will not take it
                return False
            started = float(row.get("started_at") or 0.0)
            if started and self._wall() - started > REPORT_GIVE_UP_SEC:
                self._journal.mark_done(cid, reported=False)
            return False
        self._journal.mark_done(cid, reported=True)
        return True

    def _report_sweep(self) -> None:
        try:
            rows = self._journal.unreported()
        except Exception:
            return
        for row in rows:
            if row.get("outcome") is not None and row["id"] not in self.running():
                self._report(row["id"])

    def _progress_fn(self, run: CommandRun) -> Callable[[Dict[str, Any]], None]:
        last = {"at": 0.0, "value": None}

        def progress(value: Dict[str, Any]) -> None:
            if value == last["value"] or self._mono() - last["at"] < 1.0:
                return
            last.update(at=self._mono(), value=value)
            try:
                self._api.progress(run.id, run.claim_token, value)
            except V2ApiError:
                pass

        return progress


def _int_or_none(v) -> Optional[int]:
    try:
        i = int(v)
    except (TypeError, ValueError):
        return None
    return i if i > 0 else None
