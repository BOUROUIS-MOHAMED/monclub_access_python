"""
A8 Proof Sending -- verification test script.
Tests proof creation, idempotency, countability, outbox state machine,
retry logic, startup recovery, and terminal transition hooks.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tempfile, shutil, pathlib, json
_tmp = tempfile.mkdtemp()
os.environ["MONCLUB_ACCESS_DATA_ROOT"] = _tmp

from app.core.tv_local_cache import (
    ensure_tv_local_schema,
    create_tv_screen_binding,
    upsert_tv_ad_task_cache,
    create_tv_ad_proof,
    list_tv_ad_proof_outbox,
    load_tv_ad_proof,
    process_tv_ad_proof_outbox,
    retry_tv_ad_proof,
    startup_recover_proof_outbox,
    complete_tv_ad_display,
    abort_tv_ad_display,
    reconcile_all_active_gyms,
    AD_FILE_STATE_VALID, AD_LAYOUT_FULL_SCREEN,
    PROOF_STATUS_COMPLETED, PROOF_STATUS_ABORTED,
    PROOF_STATUS_FAILED_TO_START, PROOF_STATUS_CANCELLED_REMOTE,
    PROOF_OUTBOX_QUEUED, PROOF_OUTBOX_SENT,
    PROOF_OUTBOX_FAILED_RETRYABLE, PROOF_OUTBOX_FAILED_TERMINAL,
    PROOF_OUTBOX_SENDING,
    PROOF_COUNTABLE_TOLERANCE_SEC,
    GYM_COORD_DISPLAYING,
)
from app.core.db import get_conn
from app.core.utils import now_iso
from datetime import datetime, timedelta

PASS = 0
FAIL = 0

def check(label, condition, got=None):
    global PASS, FAIL
    if condition:
        print(f"  [OK] {label}")
        PASS += 1
    else:
        print(f"  [FAIL] {label} | got: {got}")
        FAIL += 1

ensure_tv_local_schema()

media_dir = pathlib.Path(_tmp) / "tv" / "media"
media_dir.mkdir(parents=True, exist_ok=True)

def make_ad_file(name="ad-a8.mp4") -> str:
    p = media_dir / name
    p.write_bytes(b"FAKE_AD")
    return str(p)

GYM_ID = 701
b1 = create_tv_screen_binding(screen_id=3001, screen_label="gym701-s1", gym_id=GYM_ID)
b2 = create_tv_screen_binding(screen_id=3002, screen_label="gym701-s2", gym_id=GYM_ID)
BID1, BID2 = b1["id"], b2["id"]

ad_path = make_ad_file("ad-a8-001.mp4")
TASK_ID = "task-a8-001"

# -----------------------------------------------------------------------
# Case 0: Direct create_tv_ad_proof for COMPLETED (countable)
# -----------------------------------------------------------------------
print("\n[Case 0] Countable completed proof")
exp = 30
disp = 30
proof = create_tv_ad_proof(
    campaign_task_id=TASK_ID,
    gym_id=GYM_ID,
    result_status=PROOF_STATUS_COMPLETED,
    started_at="2026-03-18T10:00:00Z",
    finished_at="2026-03-18T10:00:30Z",
    displayed_duration_sec=disp,
    expected_duration_sec=exp,
    correlation_id="corr-a8-001",
)
check("proof created", bool(proof.get("local_proof_id")), proof.get("local_proof_id"))
check("result_status=COMPLETED", proof.get("result_status") == PROOF_STATUS_COMPLETED, proof.get("result_status"))
check("countable=1", proof.get("countable") == 1, proof.get("countable"))
check("completed_fully=1", proof.get("completed_fully") == 1, proof.get("completed_fully"))
check("outbox_state=QUEUED", proof.get("outbox_state") == PROOF_OUTBOX_QUEUED, proof.get("outbox_state"))
check("reason_if_not_countable=None", proof.get("reason_if_not_countable") is None, proof.get("reason_if_not_countable"))

# -----------------------------------------------------------------------
# Case 1: Idempotency -- same call returns existing row, does NOT create new one
# -----------------------------------------------------------------------
print("\n[Case 1] Idempotent creation -- same idempotency_key")
proof2 = create_tv_ad_proof(
    campaign_task_id=TASK_ID,
    gym_id=GYM_ID,
    result_status=PROOF_STATUS_COMPLETED,
    started_at="2026-03-18T10:00:00Z",
    finished_at="2026-03-18T10:00:30Z",
    displayed_duration_sec=30,
    expected_duration_sec=30,
    correlation_id="corr-a8-001",  # same key
)
check("same local_proof_id", proof2.get("local_proof_id") == proof.get("local_proof_id"), proof2.get("local_proof_id"))

total = list_tv_ad_proof_outbox(campaign_task_id=TASK_ID).get("total", 0)
check("only one row in outbox", total == 1, total)

# -----------------------------------------------------------------------
# Case 2: Non-countable proof (ABORTED)
# -----------------------------------------------------------------------
print("\n[Case 2] Non-countable aborted proof")
proof_abort = create_tv_ad_proof(
    campaign_task_id="task-a8-abort",
    gym_id=GYM_ID,
    result_status=PROOF_STATUS_ABORTED,
    started_at="2026-03-18T10:01:00Z",
    finished_at="2026-03-18T10:01:05Z",
    displayed_duration_sec=5,
    expected_duration_sec=30,
    correlation_id="corr-abort-001",
)
check("aborted proof created", bool(proof_abort.get("local_proof_id")), proof_abort)
check("countable=0", proof_abort.get("countable") == 0, proof_abort.get("countable"))
check("reason=ABORTED", proof_abort.get("reason_if_not_countable") == "ABORTED", proof_abort.get("reason_if_not_countable"))

# -----------------------------------------------------------------------
# Case 3: FAILED_TO_START proof
# -----------------------------------------------------------------------
print("\n[Case 3] FAILED_TO_START proof")
proof_skip = create_tv_ad_proof(
    campaign_task_id="task-a8-skip",
    gym_id=GYM_ID,
    result_status=PROOF_STATUS_FAILED_TO_START,
    displayed_duration_sec=0,
    expected_duration_sec=30,
    correlation_id="corr-skip-001",
)
check("skip proof created", bool(proof_skip.get("local_proof_id")), proof_skip)
check("countable=0", proof_skip.get("countable") == 0, proof_skip.get("countable"))
check("reason=FAILED_TO_START", proof_skip.get("reason_if_not_countable") == "FAILED_TO_START", proof_skip.get("reason_if_not_countable"))

# -----------------------------------------------------------------------
# Case 4: Duration tolerance -- just barely countable (tolerance=2)
# -----------------------------------------------------------------------
print(f"\n[Case 4] Duration tolerance ({PROOF_COUNTABLE_TOLERANCE_SEC}s)")
proof_tol = create_tv_ad_proof(
    campaign_task_id="task-a8-tol",
    gym_id=GYM_ID,
    result_status=PROOF_STATUS_COMPLETED,
    displayed_duration_sec=28,   # 30 - 2 = 28, exactly at boundary
    expected_duration_sec=30,
    correlation_id="corr-tol-001",
)
check("28s of 30s is countable (tolerance=2)", proof_tol.get("countable") == 1, proof_tol.get("countable"))

proof_short = create_tv_ad_proof(
    campaign_task_id="task-a8-short",
    gym_id=GYM_ID,
    result_status=PROOF_STATUS_COMPLETED,
    displayed_duration_sec=27,   # 27 < 28, NOT countable
    expected_duration_sec=30,
    correlation_id="corr-short-001",
)
check("27s of 30s is NOT countable", proof_short.get("countable") == 0, proof_short.get("countable"))
check("reason=DURATION_SHORT", proof_short.get("reason_if_not_countable") == "DURATION_SHORT", proof_short.get("reason_if_not_countable"))

# -----------------------------------------------------------------------
# Case 5: list_tv_ad_proof_outbox filters
# -----------------------------------------------------------------------
print("\n[Case 5] list_tv_ad_proof_outbox filters")
all_proofs = list_tv_ad_proof_outbox(gym_id=GYM_ID)
check("list returns rows", isinstance(all_proofs.get("rows"), list), type(all_proofs.get("rows")))
check("total > 0", all_proofs.get("total", 0) > 0, all_proofs.get("total"))

queued = list_tv_ad_proof_outbox(gym_id=GYM_ID, outbox_states=[PROOF_OUTBOX_QUEUED])
check("queued filter works", queued.get("total", 0) > 0, queued.get("total"))

countable_only = list_tv_ad_proof_outbox(gym_id=GYM_ID, countable=True)
check("countable filter returns rows", countable_only.get("total", 0) > 0, countable_only.get("total"))

# -----------------------------------------------------------------------
# Case 6: load_tv_ad_proof by id
# -----------------------------------------------------------------------
print("\n[Case 6] load_tv_ad_proof")
pid = proof.get("local_proof_id")
loaded = load_tv_ad_proof(local_proof_id=pid)
check("loaded proof not None", loaded is not None, loaded)
check("loaded proof id matches", (loaded or {}).get("local_proof_id") == pid, loaded)

missing = load_tv_ad_proof(local_proof_id=99999)
check("missing proof returns None", missing is None, missing)

# -----------------------------------------------------------------------
# Case 7: process_tv_ad_proof_outbox with no backend (should FAILED_RETRYABLE)
# -----------------------------------------------------------------------
print("\n[Case 7] process_tv_ad_proof_outbox -- no backend available")
result = process_tv_ad_proof_outbox(limit=10)
check("process returns ok=True", bool(result.get("ok")), result)
check("processed >= 1", result.get("processed", 0) >= 1, result)
# All should fail retryable (no real backend)
check("sent=0 (no backend)", result.get("sent", 0) == 0, result.get("sent"))
check("failed_retryable >= 1", result.get("failed_retryable", 0) >= 1, result.get("failed_retryable"))

# Verify state updated
loaded_after = load_tv_ad_proof(local_proof_id=pid)
check("outbox_state=FAILED_RETRYABLE", (loaded_after or {}).get("outbox_state") == PROOF_OUTBOX_FAILED_RETRYABLE, (loaded_after or {}).get("outbox_state"))
check("attempt_count=1", (loaded_after or {}).get("attempt_count") == 1, (loaded_after or {}).get("attempt_count"))
check("next_attempt_at set", (loaded_after or {}).get("next_attempt_at") is not None, loaded_after)

# -----------------------------------------------------------------------
# Case 8: retry_tv_ad_proof -- already sent: rejected
# -----------------------------------------------------------------------
print("\n[Case 8] retry_tv_ad_proof on edge cases")
# Mark a row as SENT manually
with get_conn() as conn:
    conn.execute("UPDATE tv_ad_proof_outbox SET outbox_state='SENT' WHERE local_proof_id=?", (pid,))
    conn.commit()
retry_sent = retry_tv_ad_proof(local_proof_id=pid)
check("retry of SENT row rejected", not bool(retry_sent.get("ok")), retry_sent)
check("error says already sent", "already sent" in str(retry_sent.get("error", "")).lower(), retry_sent.get("error"))

# Restore to QUEUED for further testing
with get_conn() as conn:
    conn.execute("UPDATE tv_ad_proof_outbox SET outbox_state='QUEUED', attempt_count=0, next_attempt_at=NULL WHERE local_proof_id=?", (pid,))
    conn.commit()

# retry while SENDING should be rejected
with get_conn() as conn:
    conn.execute("UPDATE tv_ad_proof_outbox SET outbox_state='SENDING' WHERE local_proof_id=?", (pid,))
    conn.commit()
retry_sending = retry_tv_ad_proof(local_proof_id=pid)
check("retry of SENDING row rejected", not bool(retry_sending.get("ok")), retry_sending)
check("error says currently being sent", "being sent" in str(retry_sending.get("error", "")).lower(), retry_sending.get("error"))

# -----------------------------------------------------------------------
# Case 9: startup_recover_proof_outbox -- SENDING -> FAILED_RETRYABLE
# -----------------------------------------------------------------------
print("\n[Case 9] startup_recover_proof_outbox")
# pid is currently SENDING from case 8
recover = startup_recover_proof_outbox()
check("recovery ok", bool(recover.get("ok")), recover)
check("recovered >= 1", recover.get("recovered", 0) >= 1, recover)

recovered_row = load_tv_ad_proof(local_proof_id=pid)
check("SENDING->FAILED_RETRYABLE", (recovered_row or {}).get("outbox_state") == PROOF_OUTBOX_FAILED_RETRYABLE, recovered_row)
check("last_error=RECOVERED_FROM_SENDING_CRASH",
      "RECOVERED" in str((recovered_row or {}).get("last_error", "")),
      (recovered_row or {}).get("last_error"))

# -----------------------------------------------------------------------
# Case 10: process_outbox respects next_attempt_at (no re-send before due)
# -----------------------------------------------------------------------
print("\n[Case 10] process_outbox respects next_attempt_at")
future = (datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
with get_conn() as conn:
    conn.execute("UPDATE tv_ad_proof_outbox SET outbox_state='FAILED_RETRYABLE', next_attempt_at=? WHERE local_proof_id=?", (future, pid))
    conn.commit()
result2 = process_tv_ad_proof_outbox(limit=100)
# The row with future next_attempt_at should NOT be processed
loaded_after2 = load_tv_ad_proof(local_proof_id=pid)
check("row not processed when next_attempt_at is future",
      (loaded_after2 or {}).get("outbox_state") == PROOF_OUTBOX_FAILED_RETRYABLE,
      (loaded_after2 or {}).get("outbox_state"))

# -----------------------------------------------------------------------
# Case 11: complete_tv_ad_display hooks proof creation
# -----------------------------------------------------------------------
print("\n[Case 11] complete_tv_ad_display hooks proof")
TASK_COMPLETE = "task-a8-complete"
due_ts = (datetime.utcnow() - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id=TASK_COMPLETE,
    gym_id=GYM_ID,
    ad_media_id="adm-a8-complete",
    scheduled_at=due_ts,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=10,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
reconcile_all_active_gyms()  # inject it

# Verify it's DISPLAYING
from app.core.tv_local_cache import load_tv_gym_ad_runtime, load_tv_ad_task_runtime
gym_before = load_tv_gym_ad_runtime(gym_id=GYM_ID)
check("gym DISPLAYING before complete", (gym_before or {}).get("coordination_state") == GYM_COORD_DISPLAYING, gym_before)

before_count = list_tv_ad_proof_outbox(campaign_task_id=TASK_COMPLETE).get("total", 0)
complete_result = complete_tv_ad_display(campaign_task_id=TASK_COMPLETE)
check("complete ok", bool(complete_result.get("ok")), complete_result)

after_count = list_tv_ad_proof_outbox(campaign_task_id=TASK_COMPLETE).get("total", 0)
check("proof created on complete", after_count == before_count + 1, after_count)

proofs_for_task = list_tv_ad_proof_outbox(campaign_task_id=TASK_COMPLETE)
row = (proofs_for_task.get("rows") or [None])[0]
check("proof result_status=COMPLETED", (row or {}).get("result_status") == PROOF_STATUS_COMPLETED, row)
check("proof countable check (depends on timing)", isinstance((row or {}).get("countable"), int), row)

# -----------------------------------------------------------------------
# Case 12: abort_tv_ad_display hooks proof creation
# -----------------------------------------------------------------------
print("\n[Case 12] abort_tv_ad_display hooks proof")
TASK_ABORT = "task-a8-abort2"
due_ts2 = (datetime.utcnow() - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id=TASK_ABORT,
    gym_id=GYM_ID,
    ad_media_id="adm-a8-abort",
    scheduled_at=due_ts2,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=60,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
reconcile_all_active_gyms()

before_count2 = list_tv_ad_proof_outbox(campaign_task_id=TASK_ABORT).get("total", 0)
abort_result = abort_tv_ad_display(campaign_task_id=TASK_ABORT, reason="TEST_ABORT_A8")
check("abort ok", bool(abort_result.get("ok")), abort_result)

after_count2 = list_tv_ad_proof_outbox(campaign_task_id=TASK_ABORT).get("total", 0)
check("proof created on abort", after_count2 == before_count2 + 1, after_count2)

abort_proof_rows = list_tv_ad_proof_outbox(campaign_task_id=TASK_ABORT).get("rows") or []
abort_proof = abort_proof_rows[0] if abort_proof_rows else {}
check("abort proof result_status=ABORTED", abort_proof.get("result_status") == PROOF_STATUS_ABORTED, abort_proof.get("result_status"))
check("abort proof countable=0", abort_proof.get("countable") == 0, abort_proof.get("countable"))

# -----------------------------------------------------------------------
# Case 13: overdue task (grace window) hooks FAILED_TO_START proof
# -----------------------------------------------------------------------
print("\n[Case 13] _expire_overdue hooks FAILED_TO_START proof")
TASK_OVERDUE = "task-a8-overdue"
overdue_ts = (datetime.utcnow() - timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id=TASK_OVERDUE,
    gym_id=GYM_ID,
    ad_media_id="adm-a8-overdue",
    scheduled_at=overdue_ts,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=30,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
before_overdue = list_tv_ad_proof_outbox(campaign_task_id=TASK_OVERDUE).get("total", 0)
reconcile_all_active_gyms()  # should expire it
after_overdue = list_tv_ad_proof_outbox(campaign_task_id=TASK_OVERDUE).get("total", 0)
check("proof created on overdue expiry", after_overdue == before_overdue + 1, after_overdue)

overdue_proof_rows = list_tv_ad_proof_outbox(campaign_task_id=TASK_OVERDUE).get("rows") or []
overdue_proof = overdue_proof_rows[0] if overdue_proof_rows else {}
check("overdue proof result_status=FAILED_TO_START", overdue_proof.get("result_status") == PROOF_STATUS_FAILED_TO_START, overdue_proof.get("result_status"))
check("overdue proof countable=0", overdue_proof.get("countable") == 0, overdue_proof.get("countable"))

# -----------------------------------------------------------------------
# Case 14: CANCELLED_REMOTE proof (not countable)
# -----------------------------------------------------------------------
print("\n[Case 14] CANCELLED_REMOTE proof")
proof_cancel = create_tv_ad_proof(
    campaign_task_id="task-a8-cancel",
    gym_id=GYM_ID,
    result_status=PROOF_STATUS_CANCELLED_REMOTE,
    displayed_duration_sec=0,
    expected_duration_sec=30,
    correlation_id="corr-cancel-001",
)
check("cancel proof countable=0", proof_cancel.get("countable") == 0, proof_cancel.get("countable"))
check("cancel reason=CANCELLED_REMOTE", proof_cancel.get("reason_if_not_countable") == "CANCELLED_REMOTE", proof_cancel.get("reason_if_not_countable"))

# -----------------------------------------------------------------------
print(f"\n=== A8 Results: {PASS} passed, {FAIL} failed ===")
shutil.rmtree(_tmp, ignore_errors=True)
sys.exit(0 if FAIL == 0 else 1)
