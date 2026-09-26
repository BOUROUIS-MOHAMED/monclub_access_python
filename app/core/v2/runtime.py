"""The P3b-2 runtime: one object owned by the app that wires the v2 pieces together.

Threads (all daemon, none on the door path, none holding an engine lock):
* ``v2-control`` — a 1 s loop: the assignment refresh, the pending-command poll while the
  socket is down, the notice-driven syncs (debounced), releases, ownership uploads, restores,
  read-backs and problem reports.
* ``v2-notice`` — the notice socket (notice.py).
* ``v2-commands`` — claims and dispatches remote commands (commands.py).

Dormant: until the server answers ``GET /pc/assignment`` with 2xx the socket is not opened and
nothing is uploaded; a backend 404 ``NOT_FOUND`` (the switch off) re-probes every 30 min.

Start-up order (owner decision 8, power-on without internet): ``load_cached_roles`` runs
synchronously in ``MainApp.__init__`` before the first sync tick can start any worker, so a
reader stays a reader from the first second, online or not.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Dict, Optional

from app.core.v2 import lease_gate, timefmt
from app.core.v2.api import V2Api, V2ApiError
from app.core.v2.commands import CommandExecutor
from app.core.v2.handlers import CommandHandlers
from app.core.v2.leases import LeaseManager, OFF, ON, UNREACHABLE
from app.core.v2.notice import NoticeCallbacks, NoticeLoop
from app.core.v2.server_clock import ServerClock

_log = logging.getLogger("zkapp.v2")

ASSIGNMENT_REFRESH_SEC = 600.0
OFF_REPROBE_SEC = 1800.0
UNKNOWN_REPROBE_SEC = 120.0
NOTICE_SYNC_MIN_GAP_SEC = 60.0

def default_clock() -> Optional[ServerClock]:
    """The process's server clock, once the runtime exists (None before)."""
    from app.core.v2 import server_clock
    return server_clock.get_default()


def _pc_uuid(app: Any) -> Optional[str]:
    try:
        from access.pc_identity import get_pc_identity_service
        return (get_pc_identity_service(app).status() or {}).get("pcUuid")
    except Exception:
        return None


def _identity_state(app: Any) -> Optional[str]:
    try:
        from access.pc_identity import get_pc_identity_service
        return (get_pc_identity_service(app).status() or {}).get("state")
    except Exception:
        return None


def load_cached_roles(app: Any) -> bool:
    """Synchronous, local only: install the cached assignment before any worker starts."""
    try:
        mgr = LeaseManager(api=None, pc_uuid_provider=lambda: _pc_uuid(app))  # type: ignore[arg-type]
        loaded = mgr.load_cache()
        if loaded:
            from app.core.v2 import loss
            loss.set_enabled(True)      # roles cached from a v2 server: the server has v2
        return loaded
    except Exception as exc:
        _log.warning("[V2] cached roles not loaded: %s", exc)
        return False


def _ws_url(base_url: str) -> str:
    base = str(base_url).rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    return base + "/api/v1/public/access/v2/pc/ws"


class V2Runtime(NoticeCallbacks):
    def __init__(self, app: Any, *, base_url: Optional[str] = None, token_provider=None,
                 app_version: Optional[str] = None, rand=random.random) -> None:
        from app.core.v2 import server_clock as _sc
        from app.core.v2 import store
        if base_url is None:
            from app.core.app_const import MONCLUB_BASE_URL
            base_url = MONCLUB_BASE_URL
        self.app = app
        self._rand = rand
        self.clock = ServerClock(persist=lambda row: store.kv_put("server_clock", row),
                                 load=lambda: store.kv_get("server_clock"))
        _sc.set_default(self.clock)
        try:
            v2 = store.kv_get("server_clock") or {}
            if v2.get("utc_offset_sec") is None:
                from app.core.db import get_access_v2_state
                self.clock.set_utc_offset((get_access_v2_state() or {}).get("utc_offset_sec"))
        except Exception:
            pass
        self._token_provider = token_provider or self._identity_token
        self.api = V2Api(base_url=base_url, token_provider=self._token_provider, clock=self.clock,
                         app_version=app_version or self._app_version())
        self.leases = LeaseManager(api=self.api, pc_uuid_provider=lambda: _pc_uuid(app),
                                   identity_state_provider=lambda: _identity_state(app),
                                   on_change=self._on_lease_change)
        self.executor: Optional[CommandExecutor] = None
        self.handlers = CommandHandlers(app, running_commands=lambda: self.executor.running() if self.executor else {})
        self.executor = CommandExecutor(api=self.api, handlers=self.handlers.table())
        self.notice = NoticeLoop(url=_ws_url(base_url), headers_provider=self._ws_headers, callbacks=self,
                                 enabled=lambda: self.availability == ON)
        self.availability = "UNKNOWN"
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._next_refresh = 0.0
        self._next_poll = 0.0
        self._sync_due: Optional[float] = None
        self._last_notice_sync = 0.0
        self._lock = threading.Lock()
        self.extensions: list = []           # ownership, problems (each: tick(runtime)) -- server ON only
        self.local_extensions: list = []     # local steps that run whatever the server (loss watch)
        self._unknown_streak = 0
        self.last_error: Optional[str] = None

    # ------------------------------------------------------------------ identity
    def _identity_token(self) -> Optional[str]:
        from access.pc_identity import get_pc_identity_service
        return get_pc_identity_service(self.app).ensure_token()

    def _app_version(self) -> str:
        try:
            return str(self.app._update_manager.get_current_version() or "")
        except Exception:
            return ""

    def _ws_headers(self) -> Optional[Dict[str, str]]:
        try:
            token = self._token_provider()
        except Exception:
            return None
        if not token:
            return None
        h = {"Authorization": f"Bearer {token}", "User-Agent": "MonClubAccess"}
        v = self._app_version()
        if v:
            h["X-MonClub-Access-Version"] = v[:64]
        return h

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="v2-control", daemon=True)
        self._thread.start()
        self.executor.start()
        self.notice.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        for part in (self.notice, self.executor):
            try:
                part.stop(timeout=2.0)
            except Exception:
                pass
        try:
            self.clock.flush()
        except Exception:
            pass

    def wake(self) -> None:
        self._wake.set()

    # ------------------------------------------------------------------ control loop
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                _log.warning("[V2] control tick failed: %s", self.last_error)
            self._wake.wait(1.0)
            self._wake.clear()

    def tick(self) -> None:
        now = time.monotonic()
        for ext in list(self.local_extensions):
            try:
                ext.tick(self)
            except Exception as exc:
                _log.warning("[V2] %s tick failed: %s", type(ext).__name__, exc)
        if now >= self._next_refresh:
            self.refresh_assignment()
        if self.availability != ON:
            return
        if getattr(self, "_force_poll", False) or (not self.notice.connected and now >= self._next_poll):
            self._force_poll = False
            self._next_poll = now + float(self.notice.poll_interval_sec or 120)
            try:
                self.executor.poll_pending()
            except V2ApiError as exc:
                if exc.switched_off:
                    self._set_availability(OFF)
        due = self._sync_due
        if due is not None and now >= due:
            self._sync_due = None
            self._last_notice_sync = now
            self._request_sync("REALTIME_NOTICE")
        for ext in list(self.extensions):
            try:
                ext.tick(self)
            except Exception as exc:
                _log.warning("[V2] %s tick failed: %s", type(ext).__name__, exc)

    def refresh_assignment(self) -> str:
        result = self.leases.refresh()
        self._set_availability(result)
        now = time.monotonic()
        if result == ON:
            waiting = any(e.state != "DRIVE" for e in lease_gate.current().drive.values())
            # A PC waiting for a turnstile (WAIT_FOR_RELEASE) re-reads every minute, so an AGENT
            # door is not left without a driver for 10 min when the socket is down.
            self._next_refresh = now + (60.0 if waiting else ASSIGNMENT_REFRESH_SEC)
        elif result == OFF:
            self._next_refresh = now + OFF_REPROBE_SEC
        else:
            # Offline, a proxy page, no token: 2 min, doubling to 30 min while it lasts.
            self._next_refresh = now + min(OFF_REPROBE_SEC, UNKNOWN_REPROBE_SEC * (2 ** min(self._unknown_streak, 4)))
        self._unknown_streak = self._unknown_streak + 1 if result == UNREACHABLE else 0
        return result

    def _set_availability(self, result: str) -> None:
        if result == UNREACHABLE:
            return                      # keep what we knew: offline is not "switched off"
        if result != self.availability:
            _log.info("[V2] server v2 availability: %s -> %s", self.availability, result)
        self.availability = result
        from app.core.v2 import loss
        loss.set_enabled(result == ON)

    # ------------------------------------------------------------------ syncs
    def _request_sync(self, trigger_source: str) -> None:
        app = self.app
        try:
            app.after(0, lambda: app.request_sync_now(trigger_source=trigger_source,
                                                     trigger_hint={"reason": trigger_source.lower()}))
        except Exception as exc:
            _log.warning("[V2] sync request failed: %s", exc)

    def schedule_sync(self, low: float, high: float) -> None:
        now = time.monotonic()
        at = max(now + low + (high - low) * self._rand(), self._last_notice_sync + NOTICE_SYNC_MIN_GAP_SEC)
        with self._lock:
            if self._sync_due is None or at < self._sync_due:
                self._sync_due = at

    def _on_lease_change(self, previous, current) -> None:
        _log.info("[V2] roles changed: %s/%s -> %s/%s drive=%s release=%s add_only=%s",
                  previous.role, previous.mode, current.role, current.mode,
                  sorted(current.drive), sorted(current.release), sorted(current.add_only))
        # Engines pick the new set up in the sync tick's work() (starts/stops workers).
        self._request_sync("LEASE_CHANGE")

    # ------------------------------------------------------------------ notice callbacks
    def on_welcome(self, msg, sent_wall, recv_wall) -> None:
        st = msg.get("serverTime")
        off = timefmt.utc_offset_of(st)
        if off is not None:
            self.clock.set_utc_offset(off)
        epoch = timefmt.to_epoch(st)
        if epoch is not None:
            self.clock.add_sample(epoch, sent_wall, recv_wall, source="welcome")
        self._next_refresh = 0.0                 # re-read the roles
        self._force_poll = True                  # jobs filed while we were away (control thread)
        self.schedule_sync(0.0, 5.0)
        self.wake()

    def on_changed(self, scopes, msg) -> None:
        if "assignment" in scopes:
            self._next_refresh = 0.0
            self.wake()
        if any(s != "assignment" for s in scopes):
            self.schedule_sync(1.0, 10.0)

    def on_rollover(self, msg) -> None:
        try:
            spread = max(0.0, float(msg.get("spreadSec") or 90))
        except (TypeError, ValueError):
            spread = 90.0
        self.schedule_sync(0.0, spread)

    def on_command(self, command_id, command_type, msg) -> None:
        self.executor.offer(command_id, command_type)

    def on_disconnected(self, reason) -> None:
        self._next_poll = time.monotonic() + 5.0

    def on_switched_off(self) -> None:
        self._next_refresh = 0.0
        self.wake()

    def on_token_expired(self) -> None:
        try:
            from access.pc_identity import get_pc_identity_service
            get_pc_identity_service(self.app).invalidate_token()
        except Exception:
            pass

    # ------------------------------------------------------------------ status
    def status(self) -> Dict[str, Any]:
        snap = lease_gate.current()
        out: Dict[str, Any] = {
            "availability": self.availability,
            "role": snap.role,
            "mode": snap.mode,
            "source": snap.source,
            "drive": [{"gymDeviceId": d, "name": e.name, "generation": e.generation, "state": e.state,
                       "handoverForced": e.handover_forced, "addOnly": d in snap.add_only}
                      for d, e in sorted(snap.drive.items())],
            "release": [{"gymDeviceId": d, "name": e.name, "generation": e.generation}
                        for d, e in sorted(snap.release.items())],
            "readerOf": [{"pcId": p, "name": n} for p, n in snap.reader_of],
            "socket": {"connected": self.notice.connected, "sessions": self.notice.sessions,
                       "lastClose": self.notice.last_close, "lastError": self.notice.last_error,
                       "pollIntervalSec": self.notice.poll_interval_sec},
            "clock": self.clock.report(),
            "commands": {"running": sorted(self.executor.running()), **self.executor.stats},
            "lastError": self.last_error or self.leases.last_error,
        }
        for ext in self.extensions:
            try:
                out.update(ext.status())
            except Exception:
                pass
        return out


def start_v2_runtime(app: Any) -> Optional[V2Runtime]:
    existing = getattr(app, "_v2_runtime", None)
    if isinstance(existing, V2Runtime):
        return existing
    try:
        rt = V2Runtime(app)
        for factory in _extension_factories():
            try:
                rt.extensions.append(factory(rt))
            except Exception as exc:
                _log.warning("[V2] extension not started: %s", exc)
        from app.core.v2.loss import LossWatch
        rt.local_extensions.append(LossWatch(rt))
        app._v2_runtime = rt
        rt.start()
        return rt
    except Exception as exc:
        _log.warning("[V2] runtime did not start; access is unaffected: %s", exc)
        return None


def _extension_factories() -> list:
    from app.core.v2.ownership import OwnershipSync
    from app.core.v2.reports import ProblemReporter
    return [OwnershipSync, ProblemReporter]
