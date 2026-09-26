"""Local API routes of the P3b-2 realtime layer (driver/reader roles, reader screens).

All under ``/api/v2/realtime/...`` and behind the local token like every other route. None of
them touches a turnstile: a reader's door or resync request is FILED on the server, which routes
it to the turnstile's driver PC (owner decision 2); the reader cannot read its outcome (no PC
route returns a command's state -- a P3c-2/backend gap, said in the UI).
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from app.core.v2 import lease_gate


def _runtime(ctx):
    return getattr(ctx.app, "_v2_runtime", None)


def _err(ctx, exc) -> None:
    code = getattr(exc, "code", "") or type(exc).__name__
    ctx.send_json(502 if getattr(exc, "status", 0) in (0, 500, 502, 503, 504) else 409,
                  {"ok": False, "code": code, "error": str(exc)[:300]})


def _handle_v2_status(ctx) -> None:
    rt = _runtime(ctx)
    if rt is None:
        snap = lease_gate.current()
        ctx.send_json(200, {"availability": "NOT_STARTED", "role": snap.role, "mode": snap.mode,
                            "source": snap.source, "drive": [], "release": [], "readerOf": []})
        return
    ctx.send_json(200, rt.status())


def _handle_v2_reader_history(ctx) -> None:
    rt = _runtime(ctx)
    if rt is None or rt.availability != "ON":
        ctx.send_json(200, {"available": False, "turnstiles": [], "items": [], "nextBeforeId": None})
        return
    before = ctx.q("beforeId")
    try:
        before_id = int(before) if before not in (None, "") else None
        limit = max(1, min(200, int(ctx.q("limit") or 50)))
    except (TypeError, ValueError):
        ctx.send_json(400, {"ok": False, "error": "beforeId/limit invalid"})
        return
    try:
        page = rt.api.reader_door_history(before_id, limit)
    except Exception as exc:
        _err(ctx, exc)
        return
    page["available"] = True
    ctx.send_json(200, page)


def _file_request(ctx, body: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> None:
    rt = _runtime(ctx)
    if rt is None or rt.availability != "ON":
        ctx.send_json(409, {"ok": False, "code": "REALTIME_OFF",
                            "error": "Les demandes au PC pilote ne sont pas disponibles (serveur sans v2)."})
        return
    try:
        ans = rt.api.request_command(body)
    except Exception as exc:
        _err(ctx, exc)
        return
    cmd = ans.get("command") or {}
    out = {"ok": True, "commandId": cmd.get("id"), "targetPcId": cmd.get("targetPcId"),
           "targetConnected": bool(ans.get("targetConnected")), "created": bool(ans.get("created"))}
    out.update(extra or {})
    ctx.send_json(202, out)


def _handle_v2_request_door(ctx, extra: Optional[Dict[str, Any]] = None) -> None:
    did = ctx.param_int("deviceId")
    if did <= 0:
        ctx.send_json(400, {"ok": False, "error": "invalid deviceId"})
        return
    door = 1
    try:
        door = max(1, int((ctx.body() or {}).get("doorNumber") or 1))
    except (TypeError, ValueError):
        pass
    _file_request(ctx, {"id": str(uuid.uuid4()), "type": "DOOR_OPEN", "gymDeviceId": did,
                        "payload": {"doorNumber": door}}, extra)


def _handle_v2_request_resync(ctx) -> None:
    did = ctx.param_int("deviceId")
    if did <= 0:
        ctx.send_json(400, {"ok": False, "error": "invalid deviceId"})
        return
    _file_request(ctx, {"id": str(uuid.uuid4()), "type": "MEMBERS_RESYNC", "gymDeviceId": did,
                        "payload": {"reason": "user-sync"}})


def _handle_v2_enroll_turnstiles(ctx) -> None:
    """After an enrolment: every turnstile, and which PC will put the finger on it.

    The finger is saved once on the server; each driver pushes it to the turnstiles the member
    may use (owner decision 3). No PC route reports a driver's push per turnstile, so a turnstile
    another PC drives reads "en attente du PC pilote" -- never "fait"."""
    snap = lease_gate.current()
    out: List[Dict[str, Any]] = []
    rt = _runtime(ctx)
    if snap.mode == lease_gate.MODE_LEASED and snap.role == "READER" and rt is not None and rt.availability == "ON":
        try:
            page = rt.api.reader_door_history(None, 1)
            for t in page.get("turnstiles") or []:
                out.append({"gymDeviceId": t.get("gymDeviceId"), "name": t.get("name"),
                            "driverPcName": t.get("driverPcName"), "status": "PENDING_DRIVER"})
        except Exception:
            pass
    else:
        try:
            from app.core.db import list_sync_devices_payload
            for d in list_sync_devices_payload():
                did = d.get("id")
                mine = lease_gate.device_allowed(did)
                out.append({"gymDeviceId": did, "name": d.get("name"),
                            "driverPcName": "ce PC" if mine else None,
                            "status": "THIS_PC" if mine else "PENDING_DRIVER"})
        except Exception:
            pass
    ctx.send_json(200, {"role": snap.role, "turnstiles": out})


ROUTES = (
    ("GET", "/api/v2/realtime/status", "_handle_v2_status"),
    ("GET", "/api/v2/realtime/reader/door-history", "_handle_v2_reader_history"),
    ("GET", "/api/v2/realtime/enroll/turnstiles", "_handle_v2_enroll_turnstiles"),
    ("POST", "/api/v2/realtime/devices/{deviceId}/door/request", "_handle_v2_request_door"),
    ("POST", "/api/v2/realtime/devices/{deviceId}/resync/request", "_handle_v2_request_resync"),
)
