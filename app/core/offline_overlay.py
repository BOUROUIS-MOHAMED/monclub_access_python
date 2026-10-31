"""Local door changes, applied by the shared device roster filter."""
from __future__ import annotations

import sqlite3
import threading
import logging
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.core import db


def _template(row):
    return {"fingerId": row["finger_id"], "templateVersion": row["template_version"],
            "templateEncoding": row["template_encoding"], "templateData": row["template_data"],
            "enabled": True}


class OverlaySnapshot:
    def __init__(self, rows=()):
        self.rows = tuple(rows)
        awaiting = {r["real_active_membership_id"] for r in self.rows if r["state"] == "AWAITING_REAL_PIN" and r["real_active_membership_id"]}
        self.cached_real_ids = {u["activeMembershipId"] for u in db.list_sync_users_by_active_membership_ids(awaiting)} if awaiting else set()
        self.patches_by_membership = {}
        for row in self.rows:
            if row["kind"] != "TEMP_MEMBER" and row["state"] != "DROPPED":
                self.patches_by_membership.setdefault(row["target_active_membership_id"], []).append(row)
        for parent in self.rows:
            if parent["kind"] == "TEMP_MEMBER" and parent["state"] == "AWAITING_REAL_PIN" and parent["real_active_membership_id"]:
                target = db._synthetic_negative_id(parent["local_id"], "offline_approval")
                self.patches_by_membership.setdefault(parent["real_active_membership_id"], []).extend(
                    self.patches_by_membership.get(target, []))

    def temp_rows_for(self, device):
        out = []
        for row in self.rows:
            if row["kind"] != "TEMP_MEMBER" or row["state"] == "DROPPED" or device.get("id") not in row["device_ids"]:
                continue
            amid = db._synthetic_negative_id(row["local_id"], "offline_approval")
            user = {"activeMembershipId": int(row["temp_pin"]), "mainAccountId": int(row["temp_pin"]),
                    "fullName": row["full_name"], "membershipId": row["membership_id"],
                    "firstCardId": None if row["real_active_membership_id"] in self.cached_real_ids else row["card"],
                    "fingerprints": [], "offlineLocalId": row["local_id"]}
            out.append(self.patch(user, self.patches_by_membership.get(amid, []), device))
            if row["real_active_membership_id"] in self.cached_real_ids:
                out[-1] = {**out[-1], "firstCardId": None}
        return out

    def patch(self, user, patches, device):
        patches = [p for p in patches if device.get("id") in p["device_ids"]]
        if not patches:
            return user
        result = dict(user)
        fingers = list(user.get("fingerprints") or [])
        for patch in patches:
            if patch["kind"] == "FINGER_ADD":
                fingers = [f for f in fingers if f.get("fingerId") != patch["finger_id"]]
                fingers.append(_template(patch))
            elif patch["kind"] == "FINGER_DISABLE":
                fingers = [f for f in fingers if not (
                    patch["fingerprint_id"] is not None and f.get("id") == patch["fingerprint_id"] or
                    patch["finger_id"] is not None and f.get("fingerId") == patch["finger_id"])]
            elif patch["kind"] == "CARD_SET":
                result["firstCardId"] = patch["card"]
        result["fingerprints"] = fingers
        return result

    def patch_roster(self, out, users, device):
        from app.core.device_sync import derive_member_pin, device_pin_scheme, membership_allowed, allowed_membership_ids
        by_pin = {}
        for user in users or []:
            if not isinstance(user, dict):
                continue
            if not membership_allowed(user, allowed_membership_ids(device)):
                continue
            patches = self.patches_by_membership.get(user.get("activeMembershipId"))
            if patches:
                pin, _ = derive_member_pin(user, device_pin_scheme(device))
                by_pin.setdefault(pin, []).extend(patches)
        for pin, patches in by_pin.items():
            if pin in out:
                out[pin] = self.patch(out[pin], sorted(patches, key=lambda p: p["created_at"]), device)

    def user_for_pin(self, pin, device):
        for row in self.rows:
            if row["temp_pin"] == str(pin) and device.get("id") in row["device_ids"]:
                return {"fullName": row["full_name"], "membershipId": row["membership_id"],
                        "offlineLocalId": row["local_id"]}
        return None


_lock = threading.Lock()
_cached = (None, None, OverlaySnapshot())


def snapshot():
    global _cached
    generation = db.get_local_state_generation()
    path = db._DB_PATH
    with _lock:
        if _cached[:2] != (path, generation):
            try:
                rows = db.list_offline_overlay()
            except sqlite3.OperationalError as exc:
                if "no such table" not in str(exc):
                    raise
                rows = []  # Pre-migration/test databases have no overlay.
            _cached = (path, generation, OverlaySnapshot(rows))
        return _cached[2]


def action_overlay_factory(app, action):
    from app.core.v2 import lease_gate
    from app.core.v2.server_clock import get_default
    from app.core.v2.store import kv_get
    from app.core.device_service_gate import device_in_service
    if lease_gate.current().role not in ("DRIVER", "ALL_TURNSTILES"):
        return None
    devices = [d for d in lease_gate.filter_devices(db.list_sync_devices_payload())
               if device_in_service(d) and not lease_gate.writes_frozen(d.get("id"))]
    if not devices:
        return None
    from shared.auth_state import read_jwt_claims
    service = getattr(app, "_pc_identity_service", None)
    claims = read_jwt_claims(getattr(service, "_pc_token", None) or "") or {}
    pc_id = int(claims.get("gymAccessPcId") or kv_get("offline_pc_id") or 0)
    clock = get_default()
    offset = clock.utc_offset if clock and clock.utc_offset is not None else None
    now = clock.now() if clock else datetime.now().timestamp()
    local_now = datetime.fromtimestamp(now, timezone(timedelta(seconds=offset))) if offset is not None else datetime.fromtimestamp(now)
    expires = (local_now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).timestamp()
    date_status = db.gym_date_status(pc_now_epoch=time.time()) if action["kind"] == "CREATE" else {}

    def build(conn):
        from app.core.device_sync import device_pin_scheme, PIN_SCHEME_ACCOUNT, membership_allowed, allowed_membership_ids
        kind, payload = action["kind"], action["payload"]
        target = action["target_active_membership_id"]
        parent_id = action.get("depends_on_local_id")
        if parent_id:
            parent = conn.execute("SELECT state FROM offline_turnstile_overlay WHERE local_id = ? AND kind = 'TEMP_MEMBER'",
                                  (parent_id,)).fetchone()
            if not parent or parent[0] == "DROPPED":
                return None
            target = db._synthetic_negative_id(parent_id, "offline_approval")
        row = {"local_id": action["local_id"], "target_active_membership_id": target,
               "device_ids": [d["id"] for d in devices], "created_at": action["created_at"],
               "local_day": action["local_day"]}
        if kind == "CREATE":
            body = payload.get("body") or {}
            plan = {"membershipId": body.get("membershipId", body.get("membership_id"))}
            targets = [d for d in devices if membership_allowed(plan, allowed_membership_ids(d))]
            if payload.get("creationKind") == "membership_only":
                account = conn.execute("SELECT main_account_id FROM sync_users WHERE account_username_id = ? LIMIT 1",
                                       (body.get("accountUsernameId"),)).fetchone()
                if account and account[0]:
                    targets = [d for d in targets if not (device_pin_scheme(d) == PIN_SCHEME_ACCOUNT and conn.execute(
                        "SELECT 1 FROM device_sync_state WHERE device_id = ? AND pin = ?", (d["id"], str(account[0]))).fetchone())]
            if not targets:
                return None
            row.update(kind="TEMP_MEMBER", device_ids=[d["id"] for d in targets],
                       card=body.get("cardId"), full_name=action["member_label"],
                       membership_id=body.get("membershipId", body.get("membership_id")), expires_at_epoch=expires)
            row["temp_pin"] = db.allocate_offline_temp_pin(conn, pc_id=pc_id, device_ids=row["device_ids"])
            if (date_status.get("suspect") or (date_status.get("gym_date") and date_status["gym_date"] != row["local_day"])):
                row.update(state="DROPPED", dropped_reason="EXPIRED")
            if pc_id:
                conn.execute("INSERT INTO v2_kv (key, value_json, updated_at) VALUES ('offline_pc_id', ?, ?) "
                             "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                             (str(pc_id), now))
        elif kind == "FINGERPRINT":
            row.update(kind="FINGER_ADD", finger_id=payload.get("fingerId"), template_version=payload.get("templateVersion", 10),
                       template_encoding=payload.get("templateEncoding", "BASE64"), template_data=payload.get("templateData"))
        elif kind == "FINGERPRINT_DISABLE":
            row.update(kind="FINGER_DISABLE", fingerprint_id=payload["fingerprintId"])
            member = conn.execute("SELECT fingerprints_json FROM sync_users WHERE active_membership_id = ?", (target,)).fetchone()
            if member:
                import json
                fp = next((f for f in json.loads(member[0] or "[]") if f.get("id") == row["fingerprint_id"]), None)
                if fp:
                    row["finger_id"] = fp.get("fingerId")
        elif kind == "EDIT" and "cardId" in payload:
            row.update(kind="CARD_SET", card=payload["cardId"])
        else:
            return None
        return row
    return build


def dispatch_action(app, action):
    row = next((r for r in snapshot().rows if r["local_id"] == action["local_id"] and r["state"] != "DROPPED"), None)
    if row is None:
        return
    try:
        target = row["target_active_membership_id"]
        full = row["kind"] == "TEMP_MEMBER" or target is None or target < 0
        app._request_running_ultra_sync(refresh={"members": True}, changed_ids=None if full else {target},
                                        device_ids=set(row["device_ids"]), reason="offline_overlay")
    except Exception:
        logging.getLogger("zkapp").warning("Offline door delivery queued for retry", exc_info=True)


def expire_overlay(now):
    current = snapshot().rows
    if any(r["state"] == "DROPPED" for r in current):
        # Finished entries would otherwise be re-read (and their templates decrypted) on every
        # snapshot rebuild for ever; a week covers late door events of a removed pin.
        from app.core.utils import format_ts
        db.purge_offline_overlay(older_than=format_ts(datetime.fromtimestamp(now) - timedelta(days=7)))
    rows = [r for r in snapshot().rows if r["kind"] == "TEMP_MEMBER" and r["state"] == "ACTIVE"]
    if not rows:
        return
    status = db.gym_date_status(pc_now_epoch=now)
    from app.core.v2.server_clock import get_default
    from app.core.access_dates import gym_local_date
    clock = get_default()
    day = status.get("gym_date") or (gym_local_date(now, clock.utc_offset).isoformat()
        if clock and clock.utc_offset is not None else datetime.fromtimestamp(now).date().isoformat())
    for row in rows:
        try:
            expired = (status["suspect"] or now >= float(row["expires_at_epoch"]) or
                       row["local_day"] != day or datetime.fromisoformat(row["created_at"]).timestamp() > now)
        except (ValueError, TypeError, KeyError):
            expired = True
        if expired:
            db.drop_offline_overlay(row["local_id"], "EXPIRED")
            # A child's approval is still polled, but no finger/card may revive an expired pass.


def planned_pins_for_device(device):
    rows = [r for r in snapshot().rows if r["state"] == "DROPPED" and device.get("id") in r["device_ids"]]
    # Patches remove individual credentials through the ordinary slot/card diff. They
    # cannot exempt this member's whole pin from the ceiling on a later departure.
    return {r["temp_pin"] for r in rows if r["kind"] == "TEMP_MEMBER" and r["temp_pin"]}


def offline_owned_removals(device, pins):
    temporary = {r["temp_pin"] for r in snapshot().rows if r["kind"] == "TEMP_MEMBER" and device.get("id") in r["device_ids"]}
    if not temporary.intersection(pins):
        return pins
    owned = db.list_confirmed_device_sync_pins(device_id=device["id"])
    return [pin for pin in pins if pin not in temporary or pin in owned]


def expiry_pending():
    from app.core.v2 import lease_gate
    return any(r["state"] == "DROPPED" and r["kind"] == "TEMP_MEMBER" and
               lease_gate.removals_blocked(did) == "add_only" and
               (db.get_pin_sync_status(device_id=did, pin=r["temp_pin"]) is not None or
                db.get_push_intent(device_id=did, pin=r["temp_pin"]) is not None)
               for r in snapshot().rows for did in r["device_ids"])


def _prove_offline_temp_intents(worker, pins, owned):
    intents = {pin: intent for pin in set(pins) - owned
               if (intent := db.get_push_intent(device_id=worker._device_id, pin=pin))}
    if not intents:
        return owned
    if not getattr(worker._sdk, "owns_event_source", False):
        from app.core.device_sync import DeviceSyncEngine
        engine = DeviceSyncEngine(cfg=worker._cfg or SimpleNamespace(), logger=logging.getLogger("zkapp"))
        raw = getattr(worker._sdk, "_sdk", None)
        if raw is not None:
            for pin in intents:
                if engine._prove_pullsdk_intent(sdk=raw, did=worker._device_id, pin=pin) is True:
                    owned.add(pin)
        return owned
    listing = worker._sdk.list_device_users()
    if not isinstance(listing, dict) or listing.get("ok") is not True or not isinstance(listing.get("users"), list):
        return owned
    from app.core.ultra_engine import _standalone_wire_identity
    users = {str(u.get("pin") or ""): u for u in listing["users"] if isinstance(u, dict)}
    if owned and not owned.intersection(users):
        return owned  # Same read-back trust check as the existing daily maintenance path.
    proven = [pin for pin, intent in intents.items() if pin in users and
              str(intent.get("protocol") or "") in ("", "ZK_STANDALONE") and
              (intent.get("name") or intent.get("card")) and
              _standalone_wire_identity(users[pin]) == _standalone_wire_identity(intent)]
    if proven:
        db.promote_push_intents(device_id=worker._device_id, pins=proven)
        owned.update(proven)
    return owned


def drain_worker(worker):
    """Replay durable obligations on the worker thread, including a manual-mode boot."""
    rows = snapshot().rows
    if not rows or not getattr(worker, "_connected", False) or getattr(worker, "_sdk", None) is None:
        return
    generation = db.get_local_state_generation()
    stamp = (generation, db._DB_PATH)
    now = time.monotonic()
    if getattr(worker, "_offline_overlay_stamp", None) == stamp and now < getattr(worker, "_offline_overlay_due", 0):
        return
    worker._offline_overlay_stamp, worker._offline_overlay_due = stamp, now + 60
    from app.core.v2 import lease_gate
    from app.core import device_hold
    did = worker._device_id
    if (not lease_gate.device_allowed(did) or lease_gate.writes_frozen(did) or device_hold.is_held(did)):
        return
    rows = [r for r in rows if did in r["device_ids"]]
    owned = db.list_confirmed_device_sync_pins(device_id=did)
    candidates = {r["temp_pin"] for r in rows if r["kind"] == "TEMP_MEMBER" and r["state"] == "DROPPED"}
    if candidates and not lease_gate.removals_blocked(did):
        owned = _prove_offline_temp_intents(worker, candidates, owned)
    dropped = sorted(candidates & owned)
    if dropped and not lease_gate.removals_blocked(did):
        if not lease_gate.device_allowed(did) or device_hold.is_held(did):
            return  # Read-back may have outlived a lease or an erase hold change.
        if getattr(worker._sdk, "owns_event_source", False):
            worker._remove_departed_pins(dropped)
        else:
            from app.core.device_sync import DeviceSyncEngine
            raw = getattr(worker._sdk, "_sdk", None)
            if raw is not None:
                engine = DeviceSyncEngine(cfg=worker._cfg or SimpleNamespace(), logger=logging.getLogger("zkapp"))
                _, failed = engine._bulk_delete_pins(sdk=raw, pins=dropped, device_id=did,
                    fingerprint_enabled=bool(worker._settings.get("fingerprint_enabled")))
                for pin in set(dropped) - set(failed):
                    db.clear_device_revocation_state(device_id=did, pin=pin)
    # Replay active updates too: an HTTP request may have arrived before workers existed.
    # Once per entry and worker: every later pass already reads the overlay through the filter,
    # so repeating this each minute would only queue a full pass per device until midnight.
    replayed = getattr(worker, "_offline_overlay_replayed", None)
    if replayed is None:
        replayed = worker._offline_overlay_replayed = set()
    fresh = [r for r in rows if r["state"] != "DROPPED" and r["local_id"] not in replayed]
    targets = {r["target_active_membership_id"] for r in fresh if r["kind"] != "TEMP_MEMBER" and
               r["target_active_membership_id"] and r["target_active_membership_id"] > 0}
    for target in targets:
        worker.request_member_sync(target)
    if any(r["kind"] == "TEMP_MEMBER" for r in fresh):
        worker.request_full_sync(reason="offline_overlay")
    replayed.update(r["local_id"] for r in fresh)


def real_pin_hash(device, users, amid):
    from app.core.device_sync import DeviceSyncEngine, derive_member_pin, device_pin_scheme
    from app.sdk.device_driver import DeviceProtocol, resolve_device_protocol
    engine = DeviceSyncEngine(cfg=SimpleNamespace(), logger=logging.getLogger("zkapp"))
    normalized = engine._normalize_device(device)
    default_door = engine._default_authorize_door_id()
    roster = engine._filter_users_for_device(users=users, device=normalized, default_door_id=default_door, apply_card_mode=True)
    member = next((u for u in users if u.get("activeMembershipId") == amid), None)
    if not member:
        return None
    pin, _ = derive_member_pin(member, device_pin_scheme(device))
    if pin not in roster:
        return None
    user = roster[pin]
    _, doors, auth_tz, fp_enabled = engine._resolve_push_context(device=normalized, default_door_id=default_door)
    local = engine._build_local_fp_index_for_pins(pins={pin}, fingerprint_enabled=fp_enabled)
    templates = engine._collect_templates_for_pin(user=user, pin=pin, local_fp_index=local, fingerprint_enabled=fp_enabled)
    if resolve_device_protocol(device) == DeviceProtocol.ZK_STANDALONE:
        from app.core.ultra_engine import _standalone_pin_hash
        desired = _standalone_pin_hash({"pin": pin, "name": user.get("fullName") or "", "card": user.get("firstCardId") or ""}, templates)
    else:
        desired = engine._compute_desired_hash(pin=pin, user=user, door_bitmask=doors, templates=templates,
            authorize_timezone_id=auth_tz, template_version_override=engine._resolve_template_version_override(normalized))
    return pin, desired


def _server_has_patch(row, users):
    user = next((u for u in users if u.get("activeMembershipId") == row["target_active_membership_id"]), None)
    if not user:
        return False
    fingers = user.get("fingerprints") or []
    if row["kind"] == "CARD_SET":
        return str(user.get("firstCardId") or "") == str(row["card"] or "")
    if row["kind"] == "FINGER_ADD":
        return any(f.get("fingerId") == row["finger_id"] and f.get("enabled", True) for f in fingers)
    if row["kind"] == "FINGER_DISABLE":
        return not any((f.get("id") == row["fingerprint_id"] if row["fingerprint_id"] is not None else
                        f.get("fingerId") == row["finger_id"]) and f.get("enabled", True) for f in fingers)
    return False


def reconcile_decisions(decisions, *, now=None):
    from app.core.v2.store import kv_get, kv_put
    now = time.time() if now is None else now
    receipts = kv_get("offline_action_receipts") or {}
    uploaded = kv_get("offline_overlay_uploaded") or {}
    metadata = kv_get("offline_overlay_decisions") or {}
    old_metadata = {k: dict(v) for k, v in metadata.items()}
    by_id = {d["localId"]: d for d in decisions if isinstance(d, dict) and d.get("localId")}
    users = db.list_sync_users()
    completed = kv_get("offline_overlay_roster_completed")
    for row in db.list_offline_overlay(active_only=True):
        response = by_id.get(row["local_id"])
        if not response:
            continue
        status = response.get("status")
        if status not in ("PENDING", "APPLIED", "REFUSED", "APPLY_FAILED", "UNKNOWN"):
            continue
        if row["decision"] != status:
            db.update_offline_overlay(row["local_id"], decision=status)
        meta = metadata.setdefault(row["local_id"], {})
        if status != "UNKNOWN":
            meta.pop("firstUnknownAt", None)
        if status == "REFUSED":
            db.drop_offline_overlay(row["local_id"], "REFUSED")
        elif status == "UNKNOWN" and (row["local_id"] in receipts or row["local_id"] in uploaded):
            since = meta.setdefault("firstUnknownAt", now)
            if now - since > 86400:
                db.drop_offline_overlay(row["local_id"], "UNKNOWN")
        elif status == "APPLIED":
            meta.pop("firstUnknownAt", None)
            meta["decidedAt"] = response.get("decidedAt")
            if row["kind"] == "TEMP_MEMBER":
                ids = {k: response.get(v) for k, v in (("real_active_membership_id", "activeMembershipId"),
                    ("real_user_id", "userId"), ("real_main_account_id", "mainAccountId"))}
                ids = {k: v if type(v) is int and v > 0 else None for k, v in ids.items()}
                if row["state"] != "AWAITING_REAL_PIN" or any(row[k] != v for k, v in ids.items()):
                    db.update_offline_overlay(row["local_id"], state="AWAITING_REAL_PIN", **ids)
                if ids["real_active_membership_id"] is None:
                    continue
                ready = bool(row["device_ids"])
                for did in row["device_ids"]:
                    device = db.get_sync_device_payload(did)
                    expected = real_pin_hash(device, users, ids["real_active_membership_id"]) if device else None
                    if not expected or db.get_pin_sync_status(device_id=did, pin=expected[0]) != (expected[1], True):
                        ready = False
                        break
                if ready:
                    db.swap_offline_overlay(row["local_id"], ids["real_active_membership_id"])
            elif row["target_active_membership_id"] and row["target_active_membership_id"] > 0:
                after_decision = False
                try:
                    after_decision = completed is not None and float(completed) > datetime.fromisoformat(meta["decidedAt"]).timestamp()
                except (ValueError, TypeError):
                    pass
                if _server_has_patch(row, users) or after_decision:
                    db.drop_offline_overlay(row["local_id"], "APPLIED")
    if metadata != old_metadata:
        kv_put("offline_overlay_decisions", metadata, durable=True)


def poll_decisions(app, token):
    from app.core.offline_actions import staff_enabled
    if not staff_enabled(app):
        return
    ids = [r["local_id"] for r in snapshot().rows if r["state"] != "DROPPED"]
    for start in range(0, len(ids), 200):
        decisions = app._api().offline_action_decisions(token=token, local_ids=ids[start:start + 200])
        reconcile_decisions(decisions)
