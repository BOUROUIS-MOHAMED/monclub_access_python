"""Approval-only offline actions. No roster write, SDK call or legacy queue here."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import threading
import uuid

from app.core import db
from app.core.offline_session import local_day
from app.core.v2 import lease_gate
from app.core.v2.server_clock import get_default
from app.core.v2.store import kv_get


PERMISSIONS = {
    "CREATE": ("ACTIVE_MEMBERSHIP_CREATION",), "RENEW": ("ACTIVE_MEMBERSHIP_RENEWAL",),
    "PAY_REST": ("ACTIVE_MEMBERSHIP_PAY_REMAINING",), "EDIT": ("ACTIVE_MEMBERSHIP_UPDATE",),
    "FREEZE": ("ACTIVE_MEMBERSHIP_FREEZING",),
    "FREEZE_CANCEL": ("ACTIVE_MEMBERSHIP_FREEZING", "ACTIVE_MEMBERSHIP_FREEZE_CANCEL"),
    "DELETE": ("ACTIVE_MEMBERSHIP_DELETION",), "FINGERPRINT": ("ACTIVE_MEMBERSHIP_FINGERPRINTS",),
}
SUMMARIES = {"CREATE": "Nouveau membre", "RENEW": "Renouvellement", "PAY_REST": "Paiement du reste",
             "EDIT": "Modification du membre", "FREEZE": "Gel de l'abonnement", "FREEZE_CANCEL": "Annulation du gel",
             "DELETE": "Suppression du membre", "FINGERPRINT": "Enrôlement d'empreinte"}
MUTATION_KINDS = {"edit": "EDIT", "freeze_create": "FREEZE", "freeze_cancel": "FREEZE_CANCEL", "delete": "DELETE"}


def staff_enabled(app) -> bool:
    staff = getattr(app, "staff_session", None)
    return bool(staff and callable(getattr(staff, "snapshot", None)) and staff.snapshot()["enabled"])


def locked_result() -> dict:
    return {"ok": False, "code": "OFFLINE_LOCKED", "error": "Internet indisponible – passez en mode hors ligne"}


def check_offline(app, kind: str) -> dict | None:
    if not staff_enabled(app) or not app.staff_session.offline_detector.state()["offline"]:
        return None
    if lease_gate.current().role not in ("DRIVER", "ALL_TURNSTILES"):
        return {"ok": False, "code": "READER_OFFLINE"}
    if kind not in PERMISSIONS:
        return {"ok": False, "code": "OFFLINE_UNSUPPORTED", "error": "Cette action nécessite internet"}
    allowed, code = app.staff_session.offline_session.require("ACTIVE_MEMBERSHIP_MANAGEMENT", *PERMISSIONS[kind])
    if not allowed:
        return locked_result() if code == "OFFLINE_LOCKED" else {"ok": False, "code": code}
    return {"ok": True}


def _create_projection(row: dict) -> dict:
    body = row["payload"].get("body") or {}
    amid = db._synthetic_negative_id(row["local_id"], "offline_approval")
    return {"id": amid, "userId": amid, "activeMembershipId": amid,
                    "fullName": row["member_label"], "membershipId": body.get("membershipId", body.get("membership_id")),
                    "email": body.get("email", ""), "phone": body.get("phone", ""),
                    "accountUsernameId": body.get("accountUsernameId", ""),
                    "validFrom": None, "validTo": None, "status": "pending", "fingerprints": [],
                    "offlinePending": True, "offlineApproval": True,
                    "offlinePendingLocalId": row["local_id"], "offlinePendingState": "pending_approval",
                    "approvalPending": True, "approvalCreated": True}


def uploaded_receipts() -> list[dict]:
    return list((kv_get("offline_action_receipts") or {}).values())


def pending_members() -> list[dict]:
    members = [_create_projection(row) for row in db.list_offline_pending_actions(limit=100000) if row["kind"] == "CREATE"]
    return members + [row["projection"] for row in uploaded_receipts() if row.get("projection")]


def record_if_offline(app, kind: str, payload: dict, *, target_id=None, depends_on=None, member_label="") -> dict | None:
    check = check_offline(app, kind)
    if check is None or not check["ok"]:
        return check
    session = app.staff_session.offline_session
    # Serializes operator requests; the DB writer checks the limit again atomically.
    with session._lock:
        check = check_offline(app, kind)
        if check is None or not check["ok"]:
            return check or locked_result()
        body = deepcopy(payload)
        request_body = body.get("body", {}) if kind == "CREATE" else body
        local_id = str(request_body.get("clientRequestId") or uuid.uuid4())
        if kind == "CREATE":
            request_body["clientRequestId"] = local_id
            member_label = member_label or " ".join(str(request_body.get(k) or request_body.get(k.lower()) or "")
                                                    for k in ("firstName", "lastName")).strip()
        if target_id is not None:
            target_id = int(target_id)
            if target_id < 0:
                parent = next((m for m in pending_members() if m["activeMembershipId"] == target_id), None)
                if not parent:
                    return {"ok": False, "code": "UNKNOWN_PENDING_MEMBER"}
                depends_on = parent["offlinePendingLocalId"]
                member_label = member_label or parent["fullName"]
                target_id = None
        if target_id and not member_label:
            with db.get_conn() as conn:
                member, _hold = db._member_row_for_card(conn, target_id)
            member_label = (member or {}).get("full_name") or f"Membre {target_id}"
        if kind == "CREATE" and not member_label and request_body.get("accountUsernameId"):
            with db.get_conn() as conn:
                member = conn.execute("SELECT full_name FROM sync_users WHERE account_username_id = ? LIMIT 1",
                                      (request_body["accountUsernameId"],)).fetchone()
            member_label = member[0] if member else str(request_body["accountUsernameId"])
        if depends_on:
            body.pop("id", None)
            body.pop("activeMembershipId", None)
        if kind == "RENEW":
            body = {k: v for k, v in body.items() if k in (
                "activeMembershipId", "membership_id", "price", "payedPrice", "paymentMethod", "cheque", "bankTransfer", "note")}
        elif kind == "PAY_REST":
            body = {k: v for k, v in body.items() if k in (
                "activeMembershipId", "amount", "paymentMethod", "termId", "cheque", "bankTransfer", "note")}
        elif kind == "DELETE":
            body = {}
        category = "DOOR" if kind == "FINGERPRINT" else "MONEY"
        # Same classification as the backend: a card-only edit consumes the door limit.
        if kind == "EDIT" and ("cardId" in body or "secondCardId" in body) and all(body.get(k) is None for k in ("startDate", "endDate", "note")):
            category = "DOOR"
        money_body = request_body if kind == "CREATE" else body
        amount = money_body.get("amount" if kind == "PAY_REST" else "payedPrice") if kind in ("CREATE", "RENEW", "PAY_REST") else None
        clock = get_default()
        at = datetime.now().isoformat(timespec="microseconds")
        row = {"local_id": local_id, "kind": kind, "category": category,
               "target_active_membership_id": target_id, "depends_on_local_id": depends_on,
               "member_label": member_label or "Nouveau membre", "summary": SUMMARIES[kind],
               "amount": str(amount) if amount is not None else None, "payload": body,
               "act_as_agent_id": session.selected()["id"], "unlocked_with_code": 1,
               "manual_offline": int(app.staff_session.offline_detector.state()["manual"]),
               "occurred_at_pc": at, "clock_offset_sec": round(clock.offset()) if clock and clock.offset() is not None else None,
               "created_at": at, "local_day": local_day()}
        result = db.insert_offline_pending_action(row, daily_limit=session.limits()[category.lower()]["max"])
    if result["ok"]:
        from app.api.local_access_api_v2 import invalidate_staff_status
        invalidate_staff_status()
        if row["manual_offline"]:
            try:
                upload_soon(app)
            except RuntimeError:
                pass  # The durable action is saved; the staff tick will retry the upload.
    return result


def upload_soon(app):
    def run():
        from access.store import load_auth_token
        auth = load_auth_token()
        if auth and auth.token:
            upload_pending(app, auth.token)
    threading.Thread(target=run, name="offline-upload", daemon=True).start()


def upload_pending(app, token: str, *, pc_uuid=None):
    if not staff_enabled(app):
        return
    session = app.staff_session.offline_session
    if not session.upload_lock.acquire(blocking=False):
        return
    try:
        rows = db.list_offline_pending_actions()
        if not rows:
            return
        ids = [r["local_id"] for r in rows]
        try:
            if not pc_uuid:
                from access.pc_identity import get_pc_identity_service
                pc_uuid = get_pc_identity_service(app).status().get("pcUuid")
            if not pc_uuid:
                return
            clock = get_default()
            offset = round(clock.offset()) if clock and clock.offset() is not None else None
            events = [{"localId": r["local_id"], "pcUuid": pc_uuid, "kind": r["kind"],
                       "targetActiveMembershipId": r["target_active_membership_id"], "dependsOnLocalId": r["depends_on_local_id"],
                       "memberLabel": r["member_label"], "summary": r["summary"], "amount": r["amount"],
                       "payload": r["payload"], "actAsAgentId": r["act_as_agent_id"], "unlockedWithCode": bool(r["unlocked_with_code"]),
                       "manualOffline": bool(r["manual_offline"]), "occurredAtPc": r["occurred_at_pc"],
                       "clockOffsetSec": r["clock_offset_sec"] if r["clock_offset_sec"] is not None else offset} for r in rows]
            result = app._api().upload_offline_actions(token=token, events=events)
            rejected = {r["localId"]: str(r["reason"]) for r in result["rejected"]}
            accepted = [lid for lid in ids if lid not in rejected]
            if int(result["stored"]) + int(result["duplicates"]) != len(accepted) or not set(rejected).issubset(ids):
                raise ValueError("Réponse d'envoi hors ligne incomplète")
        except Exception:
            # Never persist backend bodies: they might echo a password or template.
            db.finish_offline_pending_upload([], {lid: "Envoi impossible – nouvelle tentative au prochain contrôle" for lid in ids})
            return
        receipts = {r["local_id"]: {"local_id": r["local_id"], "kind": r["kind"],
                    "target_active_membership_id": r["target_active_membership_id"],
                    "projection": _create_projection(r) if r["kind"] == "CREATE" else None} for r in rows}
        db.finish_offline_pending_upload(accepted, rejected, receipts=receipts)
        if accepted and session.recovery_pending:
            count = (session.last_upload or {}).get("count", 0) if session.recovery_upload_started else 0
            session.last_upload = {"count": count + len(accepted), "at": datetime.now().isoformat(timespec="microseconds")}
            session.recovery_upload_started = True
            if not db.offline_pending_status()["count"]:
                session.recovery_pending = False
        from app.api.local_access_api_v2 import invalidate_staff_status
        invalidate_staff_status()
    finally:
        session.upload_lock.release()


def reconcile_uploaded(app, token: str):
    if not staff_enabled(app) or not app.staff_session.snapshot().get("agent") or not uploaded_receipts():
        return
    session = app.staff_session.offline_session
    try:
        result = app._api().list_offline_actions(token=token, page=session.receipt_page)
        decided = [r["localId"] for r in result["items"] if r["status"] in ("APPLIED", "REFUSED")]
        if decided:
            db.retire_offline_action_receipts(decided)
        session.receipt_page = session.receipt_page + 1 if result["hasNext"] else 0
    except Exception:
        pass  # A missing dashboard staff cookie cannot discard a dependency reference.
