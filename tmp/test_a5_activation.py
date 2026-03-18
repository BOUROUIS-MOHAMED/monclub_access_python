import sqlite3
import time
import os
from typing import Any, Dict

# Apply test overrides so we don't clobber the dev db
os.environ["MONCLUB_DB_PATH"] = "test_a5.db"
import app.core.utils
app.core.utils.DB_PATH = "test_a5.db"
import app.core.db
app.core.db.DB_PATH = "test_a5.db"

from app.core.tv_local_cache import (
    ensure_tv_local_schema,
    create_tv_screen_binding,
    upsert_tv_snapshot_cache,
    upsert_tv_snapshot_readiness,
    load_tv_activation_state,
    evaluate_tv_activation,
    activate_tv_ready_snapshot,
    list_tv_activation_attempts,
    READINESS_READY,
    READINESS_NOT_READY,
    MANIFEST_STATUS_COMPLETE,
    MANIFEST_STATUS_INCOMPLETE,
    ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT,
    ACTIVATION_STATE_ACTIVE_CURRENT,
    ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST,
    ACTIVATION_STATE_BLOCKED_WAITING_FOR_READY,
    ATTEMPT_RESULT_ACTIVATED,
    ATTEMPT_RESULT_SKIPPED_NOT_READY,
    ATTEMPT_RESULT_SKIPPED_ALREADY_ACTIVE
)

def drop_test_db():
    if os.path.exists("test_a5.db"):
        os.remove("test_a5.db")

def run_tests():
    drop_test_db()
    ensure_tv_local_schema()
    
    print("=== Testing A5 Tv Activation Engine ===")
    
    # 1. Setup Screen
    screen_id = 501
    create_tv_screen_binding(screen_id=screen_id, screen_label="Lobby A5")
    print("  [OK] Screen created")
    
    # 2. Test empty states
    st = evaluate_tv_activation(screen_id=screen_id)
    assert st["activation_state"] == ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT, st["activation_state"]
    print("  [OK] Initial baseline is NO_ACTIVE_SNAPSHOT")
    
    # 3. Simulate a snapshot landing, but missing readiness (or NOT_READY)
    upsert_tv_snapshot_cache(
        screen_id=screen_id, snapshot_id="snap1", snapshot_version=1,
        manifest_status=MANIFEST_STATUS_COMPLETE, is_latest=True
    )
    upsert_tv_snapshot_readiness(
        screen_id=screen_id, snapshot_id="snap1", snapshot_version=1,
        readiness_state=READINESS_NOT_READY, is_latest=True, is_fully_ready=False,
        total_required_assets=1, ready_asset_count=0
    )
    st = evaluate_tv_activation(screen_id=screen_id)
    assert st["activation_state"] == ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT, st["activation_state"]
    assert st["blocked_reason"] == "NO_READY_SNAPSHOT"
    print("  [OK] Not Ready snapshot correctly blocked (NO_ACTIVE_SNAPSHOT/NO_READY_SNAPSHOT)")
    
    # 4. Make it READY
    upsert_tv_snapshot_readiness(
        screen_id=screen_id, snapshot_id="snap1", snapshot_version=1,
        readiness_state=READINESS_READY, is_latest=True, is_fully_ready=True,
        total_required_assets=1, ready_asset_count=1
    )
    st = evaluate_tv_activation(screen_id=screen_id)
    # The evaluation alone doesn't flip active state!
    assert st["activation_state"] == ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT
    assert st["latest_ready_snapshot_id"] == "snap1"
    
    # Attempt activation
    res = activate_tv_ready_snapshot(screen_id=screen_id)
    print("RES1:", res)
    assert res["result"] == ATTEMPT_RESULT_ACTIVATED
    
    st = evaluate_tv_activation(screen_id=screen_id)
    assert st["activation_state"] == ACTIVATION_STATE_ACTIVE_CURRENT
    assert st["active_snapshot_id"] == "snap1"
    print("  [OK] Clean Activation success -> ACTIVE_CURRENT")
    
    # 5. Idempotency test (Alread Active)
    res2 = activate_tv_ready_snapshot(screen_id=screen_id)
    assert res2["result"] == ATTEMPT_RESULT_SKIPPED_ALREADY_ACTIVE
    print("  [OK] Already Active -> Skips gracefully")
    
    # 6. New Snapshot Arrives (Not Ready yet)
    upsert_tv_snapshot_cache(
        screen_id=screen_id, snapshot_id="snap2", snapshot_version=2,
        manifest_status=MANIFEST_STATUS_COMPLETE, is_latest=True
    )
    # the readiness engine un-flags previous latest
    upsert_tv_snapshot_readiness(
        screen_id=screen_id, snapshot_id="snap1", snapshot_version=1,
        readiness_state=READINESS_READY, is_latest=False, is_fully_ready=True,
        total_required_assets=1, ready_asset_count=1
    )
    upsert_tv_snapshot_readiness(
        screen_id=screen_id, snapshot_id="snap2", snapshot_version=2,
        readiness_state=READINESS_NOT_READY, is_latest=True, is_fully_ready=False,
        total_required_assets=2, ready_asset_count=1
    )
    st = evaluate_tv_activation(screen_id=screen_id)
    assert st["activation_state"] == ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST
    assert st["blocked_reason"] == "LATEST_NEWER_NOT_READY"
    assert st["active_snapshot_id"] == "snap1"
    res3 = activate_tv_ready_snapshot(screen_id=screen_id)
    print("RES3:", res3)
    assert res3["result"] == "SKIPPED_NO_SNAPSHOT"  # There is no latest ready snapshot to upgrade to, so it skips
    print("  [OK] New Unready Snapshot -> ACTIVE_OLDER_THAN_LATEST (active maintained)")
    
    # 7. Snap2 becomes ready
    upsert_tv_snapshot_readiness(
        screen_id=screen_id, snapshot_id="snap2", snapshot_version=2,
        readiness_state=READINESS_READY, is_latest=True, is_fully_ready=True,
        total_required_assets=2, ready_asset_count=2
    )
    st = evaluate_tv_activation(screen_id=screen_id)
    # The evaluation says older than latest because it derived candidate but hasn't switched yet.
    assert st["activation_state"] == ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST
    
    # 8. Activate Snap2
    res4 = activate_tv_ready_snapshot(screen_id=screen_id)
    print("RES4:", res4)
    assert res4["result"] == ATTEMPT_RESULT_ACTIVATED

    st = evaluate_tv_activation(screen_id=screen_id)
    assert st["activation_state"] == ACTIVATION_STATE_ACTIVE_CURRENT
    assert st["active_snapshot_id"] == "snap2"
    assert st["previous_active_snapshot_id"] == "snap1"
    print("  [OK] Snap2 Activated -> ACTIVE_CURRENT (snap1 correctly demoted to previous)")
    
    # 9. Safety Rollback: Try activating a forced broken row
    # We lie to the attempt function by saying we have a latest ready candidate (snap3),
    # but the native safety check will see it is actually NOT_READY, forcing an abort.
    upsert_tv_snapshot_cache(
        screen_id=screen_id, snapshot_id="snap3", snapshot_version=3,
        manifest_status=MANIFEST_STATUS_COMPLETE, is_latest=True
    )
    upsert_tv_snapshot_readiness(
        screen_id=screen_id, snapshot_id="snap3", snapshot_version=3,
        readiness_state=READINESS_READY, is_latest=True, is_fully_ready=True,
        total_required_assets=3, ready_asset_count=3
    )
    # evaluate picks up snap3 as candidate!
    evaluate_tv_activation(screen_id=screen_id)
    # Oops, background process trashes readiness right before activation!
    upsert_tv_snapshot_readiness(
        screen_id=screen_id, snapshot_id="snap3", snapshot_version=3,
        readiness_state=READINESS_NOT_READY, is_latest=True, is_fully_ready=False, # Now it's NOT READY!
        total_required_assets=3, ready_asset_count=0
    )
    
    res5 = activate_tv_ready_snapshot(screen_id=screen_id)
    print("RES5:", res5)
    assert res5["result"] == "SKIPPED_NO_SNAPSHOT"
    
    st = evaluate_tv_activation(screen_id=screen_id)
    assert st["active_snapshot_id"] == "snap2" # Should NOT be snap3
    assert st["previous_active_snapshot_id"] == "snap1"
    print("  [OK] Aborted unsafe activation -> Active state safely maintained")
    
    attempts = list_tv_activation_attempts(screen_id=screen_id)
    assert len(attempts) == 5
    
    print("=== FINISHED: ALL TASKS PASSED ===")

if __name__ == "__main__":
    run_tests()
