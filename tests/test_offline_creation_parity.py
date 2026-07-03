"""Tests for the full-fidelity offline member-creation parity work:

  * server-id capture on reconcile (enabler for deferred sub-resource push)
  * the local-first member roster (search / status filter / pagination), including
    projected offline-pending members.

Uses the documented `_DB_PATH` temp-database override so nothing touches the real
runtime store.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    return db_module


def _make_user(*, am_id, user_id, full_name, card, valid_to, email=None, username=None):
    return {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": 50,
        "fullName": full_name,
        "phone": "0600000000",
        "email": email or f"user{user_id}@example.com",
        "validFrom": "2026-01-01",
        "validTo": valid_to,
        "firstCardId": card,
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": username,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
    }


# --------------------------------------------------------------------------- #
# server-id capture
# --------------------------------------------------------------------------- #

def test_extract_server_ids_parses_backend_response():
    from app.core.db import _extract_server_ids

    am, uid, acc, accu = _extract_server_ids({
        "activeMembershipId": 555,
        "userId": 222,
        "mainAccountId": 111,
        "accountUsernameId": "u-abc",
    })
    assert (am, uid, acc, accu) == (555, 222, 111, "u-abc")


def test_extract_server_ids_is_defensive_on_empty_or_bad_body():
    from app.core.db import _extract_server_ids

    assert _extract_server_ids(None) == (None, None, None, None)
    assert _extract_server_ids({}) == (None, None, None, None)
    # non-numeric ids must not raise — they are simply dropped
    assert _extract_server_ids({"activeMembershipId": "not-a-number"}) == (None, None, None, None)


def test_mark_success_captures_server_ids(db):
    row = db.insert_offline_creation(
        creation_kind="account_plus_membership",
        payload={"membershipId": 50, "email": "a@b.com"},
        client_request_id="rid-capture-1",
    )
    lid = row["local_id"]

    updated = db.mark_offline_creation_success(
        lid,
        reconciled=False,
        result={
            "activeMembershipId": 9001,
            "userId": 7002,
            "mainAccountId": 5003,
            "accountUsernameId": "user-9001",
        },
    )
    assert updated is not None
    assert updated["state"] == "succeeded"
    assert updated["created"] is True
    assert updated["server_active_membership_id"] == 9001
    assert updated["server_user_id"] == 7002
    assert updated["server_account_id"] == 5003
    assert updated["server_account_username_id"] == "user-9001"


def test_mark_success_coalesces_ids_on_empty_replay(db):
    """A later replay that returns an empty body must NOT wipe ids already captured."""
    row = db.insert_offline_creation(
        creation_kind="account_plus_membership",
        payload={"membershipId": 50},
        client_request_id="rid-capture-2",
    )
    lid = row["local_id"]

    db.mark_offline_creation_success(lid, reconciled=False, result={"activeMembershipId": 4242})
    again = db.mark_offline_creation_success(lid, reconciled=True, result={})

    assert again["state"] == "reconciled"
    assert again["server_active_membership_id"] == 4242  # preserved by COALESCE


# --------------------------------------------------------------------------- #
# local-first member roster
# --------------------------------------------------------------------------- #

def test_roster_derives_status_and_counts(db):
    db.upsert_delta_users([
        _make_user(am_id=1, user_id=101, full_name="Active Annie", card="1001", valid_to="2999-12-31"),
        _make_user(am_id=2, user_id=102, full_name="Expired Eddie", card="1002", valid_to="2000-01-01"),
    ])

    rows, total, counts = db.list_members_roster()
    by_name = {r["fullName"]: r for r in rows}

    assert by_name["Active Annie"]["status"] == "active"
    assert by_name["Expired Eddie"]["status"] == "expired"
    assert counts["active"] >= 1
    assert counts["expired"] >= 1
    assert total == counts["all"]


def test_roster_includes_projected_offline_pending(db):
    # one synced base user so the projection has a non-colliding context
    db.upsert_delta_users([
        _make_user(am_id=1, user_id=101, full_name="Synced Sam", card="1001",
                   valid_to="2999-12-31", email="sam@example.com"),
    ])
    db.insert_offline_creation(
        creation_kind="account_plus_membership",
        payload={
            "membershipId": 50,
            "firstname": "Pending",
            "lastname": "Pat",
            "email": "pending.pat@example.com",
            "phone": "0612345678",
            "password": "secret123",
            "startDate": "2026-01-01",
            "endDate": "2999-12-31",
            "cardId": "2002",
        },
        client_request_id="rid-pending-1",
    )

    rows, _total, counts = db.list_members_roster(status="pending")
    names = {r["fullName"] for r in rows}
    assert "Pending Pat" in names
    assert all(r["status"] == "pending" for r in rows)
    assert counts["pending"] >= 1
    pending_row = next(r for r in rows if r["fullName"] == "Pending Pat")
    assert pending_row.get("offlinePending") is True


def test_roster_search_and_pagination(db):
    db.upsert_delta_users([
        _make_user(am_id=1, user_id=101, full_name="Karim Bensalah", card="1001", valid_to="2999-12-31"),
        _make_user(am_id=2, user_id=102, full_name="Sara Lahmar", card="1002", valid_to="2999-12-31"),
        _make_user(am_id=3, user_id=103, full_name="Karim Othmani", card="1003", valid_to="2999-12-31"),
    ])

    rows, total, _counts = db.list_members_roster(q="karim")
    assert total == 2
    assert {r["fullName"] for r in rows} == {"Karim Bensalah", "Karim Othmani"}

    page1, total1, _ = db.list_members_roster(limit=1, offset=0, sort_by="name", sort_dir="asc")
    page2, total2, _ = db.list_members_roster(limit=1, offset=1, sort_by="name", sort_dir="asc")
    assert total1 == total2 == 3
    assert len(page1) == 1 and len(page2) == 1
    assert page1[0]["fullName"] != page2[0]["fullName"]


# --------------------------------------------------------------------------- #
# deferred sub-resource queue (fingerprint/photo for offline members)
# --------------------------------------------------------------------------- #

def _creation(db, rid):
    return db.insert_offline_creation(
        creation_kind="account_plus_membership",
        payload={"membershipId": 50},
        client_request_id=rid,
    )["local_id"]


def test_subresource_basic_lifecycle(db):
    cid = _creation(db, "rid-sub-1")
    sub = db.insert_offline_subresource(
        creation_local_id=cid, kind="fingerprint",
        payload={"finger_id": 1, "tpl_text": "AA", "tpl_ver": 1, "enc_backend": "BASE64"},
    )
    sid = sub["id"]
    assert sub["state"] == "pending"
    assert sub["payload"]["finger_id"] == 1

    assert any(r["id"] == sid for r in db.list_due_offline_subresources(limit=10))
    forc = db.list_offline_subresources_for(cid)
    assert len(forc) == 1 and forc[0]["id"] == sid

    done = db.mark_offline_subresource_done(sid, server_ref="fp-9")
    assert done["state"] == "done"
    assert done["server_ref"] == "fp-9"
    assert all(r["id"] != sid for r in db.list_due_offline_subresources(limit=10))


def test_subresource_unsupported_kind_rejected(db):
    cid = _creation(db, "rid-sub-2")
    with pytest.raises(ValueError):
        db.insert_offline_subresource(creation_local_id=cid, kind="banana", payload={})


def test_subresource_gate_on_parent_reconcile(db):
    """The parent creation must carry server_active_membership_id before a deferred
    sub-resource can be pushed — this is exactly the app-level gate."""
    cid = _creation(db, "rid-sub-3")
    db.insert_offline_subresource(creation_local_id=cid, kind="fingerprint", payload={"finger_id": 0})

    assert not db.get_offline_creation(cid).get("server_active_membership_id")
    db.mark_offline_creation_success(cid, reconciled=False, result={"activeMembershipId": 7777})
    assert db.get_offline_creation(cid)["server_active_membership_id"] == 7777


def test_subresource_failed_retry_then_terminal(db):
    cid = _creation(db, "rid-sub-4")
    sid = db.insert_offline_subresource(creation_local_id=cid, kind="fingerprint", payload={})["id"]
    r1 = db.mark_offline_subresource_failed(sid, message="boom", retry_delay_min=5, max_attempts=2)
    assert r1["state"] == "failed_retryable" and r1["attempt_count"] == 1
    r2 = db.mark_offline_subresource_failed(sid, message="boom2", retry_delay_min=5, max_attempts=2)
    assert r2["state"] == "failed_terminal" and r2["attempt_count"] == 2
    assert all(r["id"] != sid for r in db.list_due_offline_subresources(limit=10))


def test_cancel_subresources_for(db):
    cid = _creation(db, "rid-sub-5")
    db.insert_offline_subresource(creation_local_id=cid, kind="fingerprint", payload={})
    assert db.cancel_offline_subresources_for(cid) == 1
    assert db.list_offline_subresources_for(cid)[0]["state"] == "cancelled"


def test_app_pushes_fingerprint_only_after_reconcile(db):
    """End-to-end of the app glue: process_due_offline_subresources skips while the
    parent is unreconciled, then pushes the template with the real activeMembershipId
    once it reconciles. Skips if the desktop app module can't import headlessly."""
    try:
        from app.ui.app import MainApp
    except Exception as e:  # heavy module (Tkinter/scanner) — fine to skip in CI
        pytest.skip(f"MainApp import unavailable: {e}")

    from types import SimpleNamespace
    from unittest.mock import MagicMock
    import logging

    cid = _creation(db, "rid-app-1")
    db.insert_offline_subresource(
        creation_local_id=cid, kind="fingerprint",
        payload={"finger_id": 2, "tpl_text": "DEAD", "tpl_ver": 1, "enc_backend": "HEX"},
    )

    fake_api = MagicMock()
    fake_api.create_user_fingerprint.return_value = {"id": 555}
    self_obj = SimpleNamespace(logger=logging.getLogger("test"), _auth_token_value=lambda: "tok", _api=lambda: fake_api)
    self_obj._push_offline_subresource = lambda sub, *, creation, token: MainApp._push_offline_subresource(
        self_obj, sub, creation=creation, token=token
    )

    res = MainApp.process_due_offline_subresources(self_obj, limit=50)
    assert res["pushed"] == 0 and res["skipped"] == 1
    fake_api.create_user_fingerprint.assert_not_called()

    db.mark_offline_creation_success(cid, reconciled=False, result={"activeMembershipId": 8888})
    res2 = MainApp.process_due_offline_subresources(self_obj, limit=50)
    assert res2["pushed"] == 1
    body = fake_api.create_user_fingerprint.call_args.kwargs["payload"]
    assert body["activeMembershipId"] == 8888
    assert body["fingerId"] == 2
    assert body["templateData"] == "DEAD"
    assert body["templateEncoding"] == "HEX"

    rows = db.list_offline_subresources_for(cid)
    assert rows[0]["state"] == "done" and rows[0]["server_ref"] == "555"


# --------------------------------------------------------------------------- #
# deferred member photo (managed-media presign)
# --------------------------------------------------------------------------- #

def _main_app_or_skip():
    try:
        from app.ui.app import MainApp
        return MainApp
    except Exception as e:  # heavy desktop module — fine to skip in CI
        pytest.skip(f"MainApp import unavailable: {e}")


def test_upload_member_photo_bytes_orchestration():
    MainApp = _main_app_or_skip()
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    api = MagicMock()
    api.media_create_upload_session.return_value = {
        "sessionId": 12, "uploadUrl": "https://store/put", "uploadMethod": "PUT",
        "uploadHeaders": {}, "uploadFields": None,
    }
    api.media_finalize_upload.return_value = {"fileId": 99}
    self_obj = SimpleNamespace(_api=lambda: api)

    ref = MainApp._upload_member_photo_bytes(
        self_obj, active_membership_id=8888, data=b"JPEGDATA",
        content_type="image/jpeg", file_name="m.jpg", token="tok",
    )
    assert ref == "99"
    cs = api.media_create_upload_session.call_args.kwargs
    assert cs["active_membership_id"] == 8888 and cs["size_bytes"] == len(b"JPEGDATA")
    po = api.media_put_object.call_args.kwargs
    assert po["upload_url"] == "https://store/put" and po["data"] == b"JPEGDATA"
    fin = api.media_finalize_upload.call_args.kwargs
    assert fin["session_id"] == 12 and fin["active_membership_id"] == 8888


def test_photo_deferred_store_then_push(db, tmp_path):
    MainApp = _main_app_or_skip()
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    import base64
    import logging
    import os

    cid = _creation(db, "rid-photo-1")

    api = MagicMock()
    api.media_create_upload_session.return_value = {
        "sessionId": 5, "uploadUrl": "u", "uploadMethod": "PUT", "uploadHeaders": {}, "uploadFields": None,
    }
    api.media_finalize_upload.return_value = {"fileId": 4242}

    self_obj = SimpleNamespace(
        logger=logging.getLogger("t"),
        _auth_token_value=lambda: "tok",
        _api=lambda: api,
        _offline_media_dir=lambda: str(tmp_path),
        _photo_ext_for=MainApp._photo_ext_for,
    )
    self_obj._upload_member_photo_bytes = lambda **kw: MainApp._upload_member_photo_bytes(self_obj, **kw)
    self_obj._push_member_photo = lambda **kw: MainApp._push_member_photo(self_obj, **kw)
    self_obj._push_offline_subresource = lambda sub, *, creation, token: MainApp._push_offline_subresource(
        self_obj, sub, creation=creation, token=token
    )
    self_obj.process_due_offline_subresources = lambda **kw: MainApp.process_due_offline_subresources(self_obj, **kw)

    img_b64 = base64.b64encode(b"PHOTOBYTES").decode()
    res = MainApp.store_member_photo_pending(
        self_obj, creation_local_id=cid, image_base64=img_b64, content_type="image/jpeg", file_name="m.jpg",
    )
    assert res["ok"] is True and res["deferred"] is True

    subs = db.list_offline_subresources_for(cid)
    assert len(subs) == 1 and subs[0]["kind"] == "photo"
    fpath = subs[0]["payload"]["file_path"]
    assert os.path.exists(fpath)

    # parent not reconciled yet -> skipped, no upload
    r1 = MainApp.process_due_offline_subresources(self_obj, limit=50)
    assert r1["pushed"] == 0
    api.media_create_upload_session.assert_not_called()

    # reconcile -> push with the real id, file cleaned up
    db.mark_offline_creation_success(cid, reconciled=False, result={"activeMembershipId": 8888})
    r2 = MainApp.process_due_offline_subresources(self_obj, limit=50)
    assert r2["pushed"] == 1
    assert api.media_create_upload_session.call_args.kwargs["active_membership_id"] == 8888
    done = db.list_offline_subresources_for(cid)[0]
    assert done["state"] == "done" and done["server_ref"] == "4242"
    assert not os.path.exists(fpath)
