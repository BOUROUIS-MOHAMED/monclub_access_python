"""Tests for the offline_mutation_queue foundation — the local queue for lifecycle
edits (edit/renew/freeze/balance/delete/taxes) on already-synced members.

Focus: the safety-critical invariants — real-id-only target, client_request_id
idempotency, per-target FIFO dependency gate, @Version chaining, and the distinct
'conflict' state for stale-version 409s.
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


def _edit(db, target_id=100, rid=None, depends_on=None, expected_version=None):
    return db.insert_offline_mutation(
        op_kind="edit", target_kind="active_membership", target_id=target_id,
        payload={"cardId": "1001", "endDate": "2999-12-31"},
        client_request_id=rid, depends_on_local_id=depends_on, expected_version=expected_version,
    )


# --------------------------------------------------------------------------- #
# invariants
# --------------------------------------------------------------------------- #

def test_insert_rejects_synthetic_negative_target(db):
    with pytest.raises(ValueError):
        db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=-7, payload={})
    with pytest.raises(ValueError):
        db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=0, payload={})


def test_insert_rejects_bad_kinds(db):
    with pytest.raises(ValueError):
        db.insert_offline_mutation(op_kind="frobnicate", target_kind="active_membership", target_id=1, payload={})
    with pytest.raises(ValueError):
        db.insert_offline_mutation(op_kind="edit", target_kind="banana", target_id=1, payload={})


def test_money_flag_defaults_by_op_kind(db):
    assert _edit(db, rid="r-edit")["money"] is False
    bal = db.insert_offline_mutation(op_kind="balance_adjust", target_kind="active_membership", target_id=100, payload={"balance": 50, "update": True}, client_request_id="r-bal")
    assert bal["money"] is True
    renew = db.insert_offline_mutation(op_kind="renew", target_kind="active_membership", target_id=100, payload={}, client_request_id="r-ren")
    assert renew["money"] is True
    # explicit override
    forced = db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=101, payload={}, money=True, client_request_id="r-forced")
    assert forced["money"] is True


def test_client_request_id_is_idempotent(db):
    a = _edit(db, rid="rid-dup")
    b = _edit(db, rid="rid-dup")
    assert a["local_id"] == b["local_id"]
    assert db.count_offline_mutations() == 1


# --------------------------------------------------------------------------- #
# per-target FIFO + version chaining
# --------------------------------------------------------------------------- #

def test_fifo_dependency_gate_and_version_chaining(db):
    a = _edit(db, target_id=100, rid="rid-a", expected_version=3)
    b = _edit(db, target_id=100, rid="rid-b", depends_on=a["local_id"])

    due_ids = {r["local_id"] for r in db.list_offline_mutations_due_for_retry(limit=50)}
    assert a["local_id"] in due_ids
    assert b["local_id"] not in due_ids  # blocked behind A

    # A succeeds and reports a new server version -> B becomes due, version chained
    db.mark_offline_mutation_success(a["local_id"], reconciled=False, result={"version": 7})
    due2 = {r["local_id"] for r in db.list_offline_mutations_due_for_retry(limit=50)}
    assert b["local_id"] in due2
    assert db.get_offline_mutation(b["local_id"])["expected_version"] == 7


def test_claim_locks_row(db):
    a = _edit(db, rid="rid-claim")
    claimed = db.claim_offline_mutation_for_processing(a["local_id"])
    assert claimed is not None and claimed["state"] == "processing"
    assert db.claim_offline_mutation_for_processing(a["local_id"]) is None  # already locked
    # locked rows are not offered as due
    assert all(r["local_id"] != a["local_id"] for r in db.list_offline_mutations_due_for_retry(limit=50))


def test_reset_stale_locks(db):
    a = _edit(db, rid="rid-stale")
    db.claim_offline_mutation_for_processing(a["local_id"], lock_ttl_sec=30)
    # force-expire the lock
    import app.core.db as dbm
    with dbm.get_conn() as conn:
        conn.execute("UPDATE offline_mutation_queue SET processing_lock_expires_at='2000-01-01T00:00:00Z' WHERE local_id=?", (a["local_id"],))
        conn.commit()
    assert db.reset_stale_offline_mutation_locks() == 1
    assert db.get_offline_mutation(a["local_id"])["state"] == "pending"


# --------------------------------------------------------------------------- #
# failure / conflict / lifecycle
# --------------------------------------------------------------------------- #

def test_failure_retry_then_terminal(db):
    a = _edit(db, rid="rid-fail")
    r1 = db.mark_offline_mutation_failure(a["local_id"], failure_type="validation", failure_code="X", http_status=400, message="bad", max_countable_failures=2)
    assert r1["state"] == "failed_retryable" and r1["failure_count"] == 1
    r2 = db.mark_offline_mutation_failure(a["local_id"], failure_type="validation", failure_code="X", http_status=400, message="bad", max_countable_failures=2)
    assert r2["state"] == "failed_terminal" and r2["try_to_apply"] is False


def test_auth_failure_blocks(db):
    a = _edit(db, rid="rid-auth")
    r = db.mark_offline_mutation_failure(a["local_id"], failure_type="auth", failure_code="AUTH", http_status=401, message="login")
    assert r["state"] == "blocked_auth"


def test_conflict_state_is_not_due(db):
    a = _edit(db, rid="rid-conf")
    r = db.mark_offline_mutation_conflict(a["local_id"], http_status=409, message="stale", server_state={"version": 9, "endDate": "2030-01-01"})
    assert r["state"] == "conflict"
    assert r["server_result_json"] and "2030-01-01" in r["server_result_json"]
    assert all(x["local_id"] != a["local_id"] for x in db.list_offline_mutations_due_for_retry(limit=50))


def test_cancel_and_archive(db):
    a = _edit(db, rid="rid-cxl")
    assert db.cancel_offline_mutation(a["local_id"], reason="oops")["state"] == "cancelled"
    assert db.archive_offline_mutation(a["local_id"])["state"] == "archived"


def test_success_marks_reconciled_on_replay(db):
    a = _edit(db, rid="rid-recon")
    r = db.mark_offline_mutation_success(a["local_id"], reconciled=True, result={"idempotentReplay": True, "version": 4})
    assert r["state"] == "reconciled"
    assert r["server_new_version"] == 4


# --------------------------------------------------------------------------- #
# drain engine (app.py) — online-first attempt + money gate + conflict
# --------------------------------------------------------------------------- #

def _drain_self(db, *, money_enabled=False, api=None):
    try:
        from app.ui.app import MainApp
    except Exception as e:
        pytest.skip(f"MainApp import unavailable: {e}")
    from types import SimpleNamespace
    import logging
    import threading

    s = SimpleNamespace(
        logger=logging.getLogger("t"),
        _auth_token_value=lambda: "tok",
        _api=lambda: api,
        _offline_money_mutations_enabled=money_enabled,
        _offline_mutation_lock=threading.Lock(),
        _last_mutation_retry_epoch=0.0,
    )
    s.attempt_offline_mutation = lambda **kw: MainApp.attempt_offline_mutation(s, **kw)
    s.process_offline_mutation_row = lambda lid, **kw: MainApp.process_offline_mutation_row(s, lid, **kw)
    s.process_due_offline_mutations = lambda **kw: MainApp.process_due_offline_mutations(s, **kw)
    s.submit_offline_mutation = lambda **kw: MainApp.submit_offline_mutation(s, **kw)
    s.resolve_offline_mutation_conflict = lambda lid, **kw: MainApp.resolve_offline_mutation_conflict(s, lid, **kw)
    return s, MainApp


# --------------------------------------------------------------------------- #
# online-first submit + conflict resolution + roster overlay
# --------------------------------------------------------------------------- #

def test_submit_online_success_leaves_no_queue_row(db):
    from unittest.mock import MagicMock
    api = MagicMock()
    api.apply_lifecycle_mutation.return_value = {"version": 3}
    s, MainApp = _drain_self(db, api=api)
    res = MainApp.submit_offline_mutation(s, op_kind="edit", target_kind="active_membership", target_id=100, payload={"cardId": "1"})
    assert res["ok"] and res["state"] == "succeeded"
    assert db.count_offline_mutations() == 0


def test_submit_offline_queues_for_retry(db):
    from unittest.mock import MagicMock
    api = MagicMock()
    api.apply_lifecycle_mutation.side_effect = ConnectionError("no network connection")
    s, MainApp = _drain_self(db, api=api)
    res = MainApp.submit_offline_mutation(s, op_kind="edit", target_kind="active_membership", target_id=100, payload={})
    assert res.get("queued") is True
    assert db.get_offline_mutation(res["localId"])["state"] == "failed_retryable"


def test_submit_conflict_is_surfaced_not_queued(db):
    from unittest.mock import MagicMock
    from app.api.monclub_api import MonClubApiConflictError
    api = MagicMock()
    api.apply_lifecycle_mutation.side_effect = MonClubApiConflictError("stale", status_code=409, body="{}", server_state={"version": 5})
    s, MainApp = _drain_self(db, api=api)
    res = MainApp.submit_offline_mutation(s, op_kind="edit", target_kind="active_membership", target_id=100, payload={})
    assert res.get("conflict") is True
    assert db.count_offline_mutations() == 0  # never silently queued


def test_submit_validation_surfaces_for_fix(db):
    from unittest.mock import MagicMock
    from app.api.monclub_api import MonClubApiHttpError
    api = MagicMock()
    api.apply_lifecycle_mutation.side_effect = MonClubApiHttpError("bad field", status_code=400, body="bad")
    s, MainApp = _drain_self(db, api=api)
    res = MainApp.submit_offline_mutation(s, op_kind="edit", target_kind="active_membership", target_id=100, payload={})
    assert res.get("needsFix") is True
    assert db.count_offline_mutations() == 0


def test_submit_money_gated_queues_without_attempt(db):
    from unittest.mock import MagicMock
    api = MagicMock()
    s, MainApp = _drain_self(db, money_enabled=False, api=api)
    res = MainApp.submit_offline_mutation(s, op_kind="balance_adjust", target_kind="active_membership", target_id=100, payload={"balance": 10, "update": True})
    assert res.get("queued") is True and res.get("gated") is True
    api.apply_lifecycle_mutation.assert_not_called()
    assert db.get_offline_mutation(res["localId"])["state"] == "pending"


def test_resolve_abort_cancels(db):
    s, MainApp = _drain_self(db)
    row = db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=100, payload={}, client_request_id="rcfa")
    db.mark_offline_mutation_conflict(row["local_id"], server_state={"version": 9})
    res = MainApp.resolve_offline_mutation_conflict(s, row["local_id"], action="abort")
    assert res["ok"] and res["action"] == "abort"
    assert db.get_offline_mutation(row["local_id"])["state"] == "cancelled"


def test_resolve_rebase_archives_and_reenqueues(db):
    s, MainApp = _drain_self(db)
    row = db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=100, payload={"cardId": "old"}, client_request_id="rcfr")
    db.mark_offline_mutation_conflict(row["local_id"], server_state={"version": 9})
    res = MainApp.resolve_offline_mutation_conflict(s, row["local_id"], action="rebase", new_payload={"cardId": "new"}, new_expected_version=9)
    assert res["ok"] and res["action"] == "rebase"
    assert db.get_offline_mutation(row["local_id"])["state"] == "archived"
    new = db.get_offline_mutation(res["localId"])
    assert new["payload"]["cardId"] == "new" and new["expected_version"] == 9 and new["state"] == "pending"


def test_roster_overlays_pending_delete(db):
    db.upsert_delta_users([{
        "activeMembershipId": 555, "userId": 101, "membershipId": 50, "fullName": "Edit Eddie",
        "phone": "0", "email": "e@e.com", "validFrom": "2026-01-01", "validTo": "2999-12-31",
        "firstCardId": "1", "secondCardId": None, "image": None, "fingerprints": [], "faceId": None,
        "accountUsernameId": None, "qrCodePayload": None, "birthday": None, "imageSource": None, "userImageStatus": None,
    }])
    db.insert_offline_mutation(op_kind="delete", target_kind="active_membership", target_id=555, payload={}, client_request_id="rm1")
    rows, _t, _c = db.list_members_roster()
    eddie = next(r for r in rows if r["fullName"] == "Edit Eddie")
    assert eddie.get("pendingDelete") is True
    assert any(m["opKind"] == "delete" for m in eddie.get("pendingMutations", []))


def test_drain_edit_success_sends_idempotency_key(db):
    from unittest.mock import MagicMock
    api = MagicMock()
    api.apply_lifecycle_mutation.return_value = {"version": 8}
    s, MainApp = _drain_self(db, api=api)
    row = db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=100, payload={"cardId": "1"}, client_request_id="r1", expected_version=2)
    res = MainApp.process_offline_mutation_row(s, row["local_id"])
    assert res["ok"] and res["state"] == "succeeded"
    kw = api.apply_lifecycle_mutation.call_args.kwargs
    assert kw["idempotency_key"] == "r1" and kw["op_kind"] == "edit" and kw["target_id"] == 100 and kw["expected_version"] == 2
    assert db.get_offline_mutation(row["local_id"])["server_new_version"] == 8


def test_drain_money_is_gated_until_enabled(db):
    from unittest.mock import MagicMock
    api = MagicMock()
    s, MainApp = _drain_self(db, money_enabled=False, api=api)
    row = db.insert_offline_mutation(op_kind="balance_adjust", target_kind="active_membership", target_id=100, payload={"balance": 50, "update": True}, client_request_id="rb")
    res = MainApp.process_offline_mutation_row(s, row["local_id"])
    assert res["error"] == "money-gated"
    api.apply_lifecycle_mutation.assert_not_called()
    assert db.get_offline_mutation(row["local_id"])["state"] == "pending"  # untouched, not even claimed

    # once the backend idempotency layer is live, the operator flips the gate
    s._offline_money_mutations_enabled = True
    api.apply_lifecycle_mutation.return_value = {"ok": True}
    res2 = MainApp.process_offline_mutation_row(s, row["local_id"])
    assert res2["ok"]
    api.apply_lifecycle_mutation.assert_called_once()
    # absolute mode must be what we send for balance
    assert api.apply_lifecycle_mutation.call_args.kwargs["payload"]["update"] is True


def test_drain_conflict_goes_to_conflict_state(db):
    from unittest.mock import MagicMock
    from app.api.monclub_api import MonClubApiConflictError
    api = MagicMock()
    api.apply_lifecycle_mutation.side_effect = MonClubApiConflictError("stale", status_code=409, body="{}", server_state={"version": 12, "endDate": "2031-01-01"})
    s, MainApp = _drain_self(db, api=api)
    row = db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=100, payload={}, client_request_id="rc")
    res = MainApp.process_offline_mutation_row(s, row["local_id"])
    assert res["state"] == "conflict"
    r = db.get_offline_mutation(row["local_id"])
    assert r["state"] == "conflict" and "2031-01-01" in (r["server_result_json"] or "")


def test_drain_due_skips_money_counts_gated(db):
    from unittest.mock import MagicMock
    api = MagicMock()
    api.apply_lifecycle_mutation.return_value = {"version": 2}
    s, MainApp = _drain_self(db, money_enabled=False, api=api)
    db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=100, payload={}, client_request_id="e1")
    db.insert_offline_mutation(op_kind="balance_adjust", target_kind="active_membership", target_id=101, payload={"balance": 1, "update": True}, client_request_id="b1")
    summary = MainApp.process_due_offline_mutations(s, limit=50)
    assert summary["processed"] == 1 and summary["succeeded"] == 1 and summary["gated"] == 1


def test_drain_replay_reconciles(db):
    from unittest.mock import MagicMock
    api = MagicMock()
    api.apply_lifecycle_mutation.return_value = {"idempotentReplay": True, "version": 5}
    s, MainApp = _drain_self(db, api=api)
    row = db.insert_offline_mutation(op_kind="edit", target_kind="active_membership", target_id=100, payload={}, client_request_id="rr")
    res = MainApp.process_offline_mutation_row(s, row["local_id"])
    assert res["state"] == "reconciled"
