"""Targeted off-hours delivery; never asks for a full device pass."""
from app.core import db


def still_on_devices(ids, limit=50):
    from app.core.device_sync import derive_member_pin, device_pin_scheme
    requested = set(ids)
    if not requested:
        return set()
    rows = {int(r["activeMembershipId"]): r for r in db.list_off_hours_held_rows()}
    live = db.list_sync_users()
    result = set()
    for device in db.list_sync_devices():
        if str(device.get("accessDataMode") or "").upper() != "ULTRA":
            continue
        scheme = device_pin_scheme(device)
        owned = db.list_confirmed_device_sync_pins(device_id=int(device["id"]))
        live_pins = {derive_member_pin(r, scheme)[0] for r in live}
        for am in sorted(requested & rows.keys()):
            pin, _ = derive_member_pin(rows[am], scheme)
            if pin and pin in owned and pin not in live_pins:
                result.add(am)
                if len(result) >= limit:
                    return result
    return result


def dispatch_off_hours(app, off, source):
    pending = getattr(app, "_off_hours_pending", {"hold": set(), "release": set()})
    # Empty result means no new decision (or a failed pass): never send an old revoke.
    if not off:
        hold = set()
        release = set(pending["release"])
    else:
        target = set(off.get("newly_held") or ()) | set(off.get("retry") or ())
        hold = still_on_devices(set(off.get("newly_held") or ()), limit=len(target) or 50)
        hold |= still_on_devices(set(off.get("retry") or ()), limit=50)
        hold |= set(pending["hold"]) & target
        release = (set(off.get("released") or ()) | set(pending["release"])) - target
        release -= set(off.get("released_to_date") or ())
    # Store before the call too, so a raised enqueue does not lose releases.
    app._off_hours_pending = {"hold": hold, "release": release}
    if not hold and not release:
        return
    ok = app._request_running_ultra_sync(refresh={"members": True, "devices": False},
                                        changed_ids=release, revoked_ids=hold, reason="off_hours")
    if ok:
        app._off_hours_pending = {"hold": set(), "release": set()}
