"""What each remote command does on this PC (payloads: P2c-2 §5, AccessPcCommandPayloads).

Every handler reuses the code path the desk already uses, so a remote command behaves exactly
like the button: DOOR_OPEN and the device reads go through the same local API handlers (the
lease gate included), ENROLL_START through ``_handle_enroll_start`` (the payload IS the local
enrol body), CARD_SCAN through ``/scan/quick``'s handler. Each returns
``(SUCCEEDED|FAILED, code, detail)``; codes are short and stable, details small (≤ 4000 chars).
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

from app.core.v2 import lease_gate
from app.core.v2.commands import CommandRun, Outcome

_log = logging.getLogger("zkapp.v2.handlers")


class LocalCtx:
    """The local API handler context, in process (no HTTP)."""

    def __init__(self, app: Any, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None):
        self.app = app
        self._params = dict(params or {})
        self._body = dict(body or {})
        self.status: Optional[int] = None
        self.payload: Dict[str, Any] = {}
        self.path = "/in-process/v2-command"
        self.method = "POST"

    def param_int(self, name: str, default: int = 0) -> int:
        try:
            return int(self._params.get(name, default))
        except (TypeError, ValueError):
            return default

    def param(self, name: str, default: str = "") -> str:
        return str(self._params.get(name, default))

    def q(self, name: str, default: Any = None) -> Any:
        return self._params.get(name, default)

    def body(self) -> Dict[str, Any]:
        return dict(self._body)

    def send_json(self, status: int, payload: Dict[str, Any]) -> None:
        self.status = int(status)
        self.payload = dict(payload or {})


def _la2():
    from app.api import local_access_api_v2 as la2
    return la2


def _gated(name: str):
    from access.local_api_routes import gated_handler
    return gated_handler(getattr(_la2(), name))


class CommandHandlers:
    def __init__(self, app: Any, *, running_commands: Callable[[], Dict[str, CommandRun]] = dict,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.app = app
        self._running = running_commands
        self._sleep = sleep
        self._enroll_by_command: Dict[str, str] = {}

    def table(self) -> Dict[str, Callable[[CommandRun], Outcome]]:
        return {
            "DOOR_OPEN": self.door_open,
            "CARD_SCAN": self.card_scan,
            "ENROLL_START": self.enroll_start,
            "ENROLL_CANCEL": self.enroll_cancel,
            "MEMBERS_RESYNC": self.members_resync,
            "DEVICE_RECONCILE": self.device_reconcile,
            "DEVICE_AUDIT": self.device_audit,
            "LOGS_FLUSH": self.logs_flush,
            "REMOVAL_CONFIRM": self.removal_confirm,
        }

    # ------------------------------------------------------------------ door
    def door_open(self, run: CommandRun) -> Outcome:
        did = run.gym_device_id
        if not did:
            return ("FAILED", "DEVICE_REQUIRED", None)
        if not lease_gate.device_allowed(did):
            return ("FAILED", "NOT_DRIVER", {"gymDeviceId": did})
        door = int((run.payload or {}).get("doorNumber") or 1)
        ctx = LocalCtx(self.app, {"deviceId": did}, {"doorNumber": door, "pulseSeconds": 3})
        _gated("_handle_device_door_open")(ctx)
        status, p = ctx.status, ctx.payload
        detail = {"gymDeviceId": did, "door": door, "source": p.get("source")}
        if status == 200 and p.get("ok"):
            return ("SUCCEEDED", "OPENED", detail)
        if status == 409 and p.get("notDriver"):
            return ("FAILED", "NOT_DRIVER", detail)
        if status == 409 and p.get("unsupported"):
            return ("FAILED", "DOOR_OPEN_DISABLED", detail)
        if status == 429:
            return ("FAILED", "RATE_LIMITED", detail)
        if status == 503:
            return ("FAILED", "DEVICE_UNREACHABLE", detail)
        if status == 500 and p.get("detail") == "sent, no answer":
            detail["message"] = "sent to the turnstile, no answer in time: it may have opened"
            return ("FAILED", "SENT_NO_ANSWER", detail)
        detail["message"] = str(p.get("detail") or p.get("error") or "")[:200]
        return ("FAILED", "REFUSED", detail)

    # ------------------------------------------------------------------ card scan
    def card_scan(self, run: CommandRun) -> Outcome:
        la2 = _la2()
        try:
            cfg = la2._get_runtime_access_config(LocalCtx(self.app))
            scanner_ip = str(getattr(cfg, "scanner_network_ip", "") or "").strip()
            scanner_mode = str(getattr(cfg, "scanner_mode", "") or "").strip().lower()
        except Exception:
            scanner_ip, scanner_mode = "", ""
        from app.core.v2.device_ips import ip_is_undriven_turnstile
        if scanner_ip and scanner_mode != "usb" and ip_is_undriven_turnstile(scanner_ip):
            # A reader never connects to a turnstile: a scanner configured on a turnstile's
            # address is that turnstile.
            return ("FAILED", "SCANNER_IS_A_TURNSTILE", {"ip": scanner_ip})
        timeout_ms = int(max(1.0, min(30.0, run.remaining() - 3.0)) * 1000)
        ctx = LocalCtx(self.app, body={"timeout_ms": timeout_ms})
        la2._handle_scan_quick(ctx)
        if ctx.status == 200 and ctx.payload.get("ok"):
            return ("SUCCEEDED", "CARD_READ", {"card": str(ctx.payload.get("card") or "")})
        if ctx.status == 408:
            return ("FAILED", "NO_CARD", None)
        if ctx.status == 409:
            return ("FAILED", "SCANNER_BUSY", None)
        return ("FAILED", "SCANNER_ERROR", {"message": str(ctx.payload.get("error") or "")[:200]})

    # ------------------------------------------------------------------ enrolment
    def enroll_start(self, run: CommandRun) -> Outcome:
        payload = dict(run.payload or {})
        body = {"type": payload.get("type") or "BACKEND", "userId": payload.get("userId"),
                "activeMembershipId": payload.get("activeMembershipId"), "fingerId": payload.get("fingerId"),
                "fullName": payload.get("fullName") or "", "device": "zk9500"}
        ctx = LocalCtx(self.app, body=body)
        _la2()._handle_enroll_start(ctx)
        if ctx.status != 202:
            code = "ENROLL_BUSY" if ctx.status == 409 else ("NO_THREAD" if ctx.status == 503 else "BAD_REQUEST")
            return ("FAILED", code, {"message": str(ctx.payload.get("error") or "")[:200]})
        enroll_id = str(ctx.payload.get("enrollId") or "")
        self._enroll_by_command[run.id] = enroll_id
        cancelled_for_deadline = False
        try:
            while getattr(self.app, "_enroll_running", False):
                if run.cancel.is_set() or (run.remaining() < 3.0 and not cancelled_for_deadline):
                    cancelled_for_deadline = not run.cancel.is_set()
                    try:
                        self.app.cancel_enroll()
                    except Exception:
                        pass
                run.progress({"step": str(getattr(_la2(), "_enroll_step", "") or "")[:120],
                              "enrollId": enroll_id})
                self._sleep(0.5)
        finally:
            self._enroll_by_command.pop(run.id, None)
        last = getattr(self.app, "_last_enroll_outcome", None) or {}
        outcome = str(last.get("outcome") or "unknown") if last.get("enrollId") in (enroll_id, None) else "unknown"
        detail = {"enrollId": enroll_id, "outcome": outcome}
        if outcome in ("ok", "ok_deferred_offline"):
            return ("SUCCEEDED", "SAVED" if outcome == "ok" else "SAVED_OFFLINE", detail)
        if outcome == "cancelled":
            return ("FAILED", "EXPIRED" if cancelled_for_deadline else "CANCELLED", detail)
        return ("FAILED", outcome.upper()[:64], detail)

    def enroll_cancel(self, run: CommandRun) -> Outcome:
        target = str((run.payload or {}).get("enrollCommandId") or "").lower()
        running = self._running().get(target)
        if running is not None and running.type == "ENROLL_START":
            running.cancel.set()
            return ("SUCCEEDED", "CANCEL_REQUESTED", {"enrollCommandId": target})
        if getattr(self.app, "_enroll_running", False):
            # An enrolment started at this desk, not by that command: never cancelled remotely.
            return ("FAILED", "NOT_THAT_ENROLMENT", {"enrollCommandId": target})
        return ("FAILED", "NOT_RUNNING", {"enrollCommandId": target})

    # ------------------------------------------------------------------ sync / reconcile
    def _request_sync(self, *, explicit: bool, trigger_source: str) -> None:
        hint = {"reason": "user-sync"} if explicit else {"reason": "remote-command"}
        src = "SYNC_NOW_API" if explicit else trigger_source
        self.app.after(0, lambda: self.app.request_sync_now(trigger_source=src, trigger_hint=hint))

    def _wait_sync(self, run: CommandRun, *, start_wait: float = 30.0) -> Optional[bool]:
        """None when no sync was seen starting; else the sync's success."""
        saw = False
        started = time.monotonic()
        while run.remaining() > 1.0:
            running = bool(getattr(self.app, "_sync_work_running", False))
            if running:
                saw = True
            elif saw:
                return bool(getattr(self.app, "_last_sync_ok", False))
            elif time.monotonic() - started > start_wait:
                return None
            self._sleep(0.5)
        return None

    def members_resync(self, run: CommandRun) -> Outcome:
        explicit = (run.payload or {}).get("reason") == "user-sync"
        self._request_sync(explicit=explicit, trigger_source="REMOTE_COMMAND")
        ok = self._wait_sync(run)
        if ok is None:
            return ("SUCCEEDED", "SYNC_REQUESTED", {"explicit": explicit})
        return ("SUCCEEDED", "SYNC_DONE", {"explicit": explicit}) if ok else ("FAILED", "SYNC_FAILED", None)

    def device_reconcile(self, run: CommandRun) -> Outcome:
        did = run.gym_device_id
        if not did:
            return ("FAILED", "DEVICE_REQUIRED", None)
        if not lease_gate.device_allowed(did):
            return ("FAILED", "NOT_DRIVER", {"gymDeviceId": did})
        if lease_gate.writes_frozen(did):
            return ("FAILED", "HANDOVER_IN_PROGRESS", {"gymDeviceId": did})
        requested = False
        try:
            requested = bool(self.app._request_running_ultra_sync(
                refresh={"members": True, "devices": False, "credentials": False, "settings": False},
                changed_ids=None, device_ids={int(did)}, reason="REMOTE_RECONCILE", full_reconcile=True))
        except Exception as exc:
            _log.warning("[V2] reconcile request failed: %s", exc)
        if not requested:
            # Not a running ULTRA turnstile (DEVICE mode): an explicit sync reconciles it.
            self._request_sync(explicit=True, trigger_source="REMOTE_COMMAND")
        return ("SUCCEEDED", "RECONCILE_REQUESTED", {"gymDeviceId": did, "ultra": requested})

    # ------------------------------------------------------------------ audit
    def device_audit(self, run: CommandRun) -> Outcome:
        did = run.gym_device_id
        if not did:
            return ("FAILED", "DEVICE_REQUIRED", None)
        if not lease_gate.device_allowed(did):
            return ("FAILED", "NOT_DRIVER", {"gymDeviceId": did})
        listed = self._list_device_pins(int(did), timeout=min(90.0, max(5.0, run.remaining() - 5.0)))
        if listed is None:
            return ("FAILED", "LIST_FAILED", {"gymDeviceId": did})
        from app.core.db import list_confirmed_device_sync_pins
        try:
            owned = set(list_confirmed_device_sync_pins(device_id=int(did)))
        except Exception:
            return ("FAILED", "OWNERSHIP_UNREADABLE", {"gymDeviceId": did})
        on_device = set(listed)
        detail = {
            "gymDeviceId": did,
            "onDevice": len(on_device),
            "owned": len(owned),
            "ownedOnDevice": len(owned & on_device),
            "ownedMissing": len(owned - on_device),
            "notMonClub": len(on_device - owned),
            "ownedMissingSample": sorted(owned - on_device)[:20],
            "notMonClubSample": sorted(on_device - owned)[:20],
        }
        return ("SUCCEEDED", "AUDITED", detail)

    def _list_device_pins(self, did: int, *, timeout: float) -> Optional[list]:
        eng = getattr(self.app, "_ultra_engine", None)
        worker = eng._workers.get(did) if eng is not None and getattr(eng, "running", False) else None
        if worker is not None:
            def fn(sdk):
                if hasattr(sdk, "list_device_users"):
                    res = sdk.list_device_users(timeout_sec=timeout)
                    if not res.get("ok"):
                        raise RuntimeError(res.get("error") or "listing failed")
                    return [str(u.get("pin")) for u in res.get("users") or [] if u.get("pin")]
                rows = sdk.read_table_rows(table="user", fields="Pin") if hasattr(sdk, "read_table_rows") else None
                if rows is None:
                    raise RuntimeError("driver cannot list users")
                return [str(r.get("Pin") or r.get("pin")) for r in rows if (r.get("Pin") or r.get("pin"))]

            res = worker.request_run_sdk(fn, label="v2_audit", timeout=timeout + 5.0)
            if res.get("ok"):
                return list(res.get("result") or [])
            return None
        ctx = LocalCtx(self.app, {"deviceId": did})
        _gated("_handle_device_users_list")(ctx)
        if ctx.status == 200 and ctx.payload.get("ok"):
            return [str(u.get("pin")) for u in ctx.payload.get("users") or [] if u.get("pin")]
        return None

    # ------------------------------------------------------------------ confirm removal
    def removal_confirm(self, run: CommandRun) -> Outcome:
        """Owner decision 7: run the refused removal only while its bound list is unchanged.

        The payload binds the list the owner saw (``expectedCount``, ``pinSetHash``). This PC
        recomputes its CURRENT refused list; a different count or hash is
        ``REMOVAL_LIST_CHANGED`` (and the fresh list goes out with the next problem report).
        Otherwise a one-shot approval for exactly that pin set is armed (push_safety consumes it
        on the standalone revoke pass or the PullSDK stale step, never on a table clear or an
        empty roster) and a pass of that turnstile is requested; SUCCEEDED once the approved
        step removed them.
        """
        from app.core.v2 import problems as pr

        did = run.gym_device_id
        payload = run.payload or {}
        try:
            expected_count = int(payload.get("expectedCount"))
        except (TypeError, ValueError):
            return ("FAILED", "PAYLOAD_INVALID", None)
        expected_hash = str(payload.get("pinSetHash") or "").strip().lower()
        if not did:
            return ("FAILED", "DEVICE_REQUIRED", None)
        if not lease_gate.device_allowed(did):
            return ("FAILED", "NOT_DRIVER", {"gymDeviceId": did})
        blocked = lease_gate.removals_blocked(did)
        if blocked:
            return ("FAILED", "REMOVALS_DEFERRED", {"gymDeviceId": did, "reason": blocked})
        current = pr.registry.current_removal_list(did)
        if current is None:
            return ("FAILED", "NO_REMOVAL_PENDING", {"gymDeviceId": did})
        pins, reason = current
        if reason != "above_ceiling":
            return ("FAILED", "REMOVAL_NOT_CONFIRMABLE", {"gymDeviceId": did, "reason": reason})
        current_hash = pr.canonical_hash(pins)
        if len(pins) != expected_count or current_hash != expected_hash:
            return ("FAILED", "REMOVAL_LIST_CHANGED",
                    {"gymDeviceId": did, "currentCount": len(pins), "currentPinSetHash": current_hash})
        pr.registry.approve_removal(did, current_hash, len(pins), expires_wall=time.time() + max(1.0, run.remaining()))
        used_before = len(pr.registry.approvals_used)
        if not self._request_device_pass(did):
            pr.registry.withdraw_approval(did)
            return ("FAILED", "NO_PASS_POSSIBLE", {"gymDeviceId": did})
        while run.remaining() > 1.0:
            if any(h == current_hash and d == did for d, h in pr.registry.approvals_used[used_before:]):
                return ("SUCCEEDED", "REMOVAL_RAN", {"gymDeviceId": did, "count": len(pins)})
            if not pr.registry.approval_pending(did):
                break
            now_list = pr.registry.current_removal_list(did)
            if now_list is not None and pr.canonical_hash(now_list[0]) != current_hash:
                pr.registry.withdraw_approval(did)
                return ("FAILED", "REMOVAL_LIST_CHANGED",
                        {"gymDeviceId": did, "currentCount": len(now_list[0]),
                         "currentPinSetHash": pr.canonical_hash(now_list[0])})
            self._sleep(1.0)
        pr.registry.withdraw_approval(did)
        return ("FAILED", "NOT_RUN_IN_TIME", {"gymDeviceId": did})

    def _request_device_pass(self, did: int) -> bool:
        eng = getattr(self.app, "_ultra_engine", None)
        worker = eng._workers.get(int(did)) if eng is not None and getattr(eng, "running", False) else None
        if worker is not None:
            # A worker pass, whatever the roster hash says (like the removal retry).
            return bool(worker.request_full_sync(reason="removal-confirm"))
        # A DEVICE-mode panel: an explicit sync runs its reconcile.
        self._request_sync(explicit=True, trigger_source="REMOTE_COMMAND")
        return True

    # ------------------------------------------------------------------ logs
    def logs_flush(self, run: CommandRun) -> Outcome:
        q = getattr(self.app, "_log_upload_queue", None)
        if q is None:
            return ("FAILED", "NO_LOG_UPLOADER", None)
        res = q.flush_now() or {}
        return ("SUCCEEDED", "FLUSHED", {k: res.get(k) for k in ("rotated", "activeBefore", "pendingNow")})


