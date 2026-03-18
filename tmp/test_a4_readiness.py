"""
Test script for Functionality A4: Tv Readiness Computation Engine.
Verifies:
 1) EMPTY state (no snapshot, or snapshot with 0 assets)
 2) ERROR state (inconsistent manifest)
 3) NOT_READY state (no valid assets)
 4) PARTIALLY_READY state (some valid, some missing)
 5) READY state (all valid)
 6) Idempotency of run_tv_readiness_computation
"""
import os
import sys

# Setup paths so we can import app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Ensure we use a clean local DB instead of the production DB
TEST_DB_PATH = os.path.join(os.path.dirname(__file__), "test_a4.db")
if os.path.exists(TEST_DB_PATH):
    os.remove(TEST_DB_PATH)

import app.core.utils as utils
utils.DB_PATH = TEST_DB_PATH

import app.core.db as db
db.DB_PATH = TEST_DB_PATH

from app.core.tv_local_cache import (
    ensure_tv_local_schema,
    get_conn,
    create_tv_screen_binding,
    upsert_tv_snapshot_cache,
    upsert_tv_snapshot_required_asset,
    upsert_tv_local_asset_state,
    compute_tv_screen_readiness,
    run_tv_readiness_computation,
    list_tv_snapshot_readiness,
    load_tv_latest_readiness,
    READINESS_EMPTY,
    READINESS_ERROR,
    READINESS_NOT_READY,
    READINESS_PARTIALLY_READY,
    READINESS_READY,
    ASSET_STATE_VALID,
    ASSET_STATE_NOT_PRESENT,
    ASSET_STATE_INVALID_SIZE,
    ASSET_STATE_PRESENT_UNCHECKED
)

checks_total = 0
checks_passed = 0

def assert_msg(condition, msg):
    global checks_total, checks_passed
    checks_total += 1
    if condition:
        checks_passed += 1
        print(f"  [OK] {msg}")
    else:
        print(f"  [FAIL] {msg}")

def run_tests():
    print("=== Testing A4 Tv Readiness Computation Engine ===")
    
    # 1. Reset pristine schema in memory DB (or test DB)
    ensure_tv_local_schema()

    # Create dummy screen
    b1 = create_tv_screen_binding(screen_id=101, screen_name="Screen A4")
    assert_msg(b1["screen_id"] == 101, "Screen created")

    print("\n--- Test 1: No snapshot -> EMPTY")
    r1 = compute_tv_screen_readiness(screen_id=101)
    assert_msg(r1["readiness_state"] == READINESS_EMPTY, f"State should be EMPTY, got {r1.get('readiness_state')}")
    assert_msg(r1["total_required_assets"] == 0, "0 required assets")
    assert_msg(r1["is_fully_ready"] == 0, "Not fully ready")
    assert_msg(r1["is_latest"] == 1, "Is latest")

    print("\n--- Test 2: Snapshot exists, asset_count=0, no rows -> EMPTY")
    upsert_tv_snapshot_cache(screen_id=101, snapshot_id="snap0", snapshot_version=1, asset_count=0)
    r2 = compute_tv_screen_readiness(screen_id=101)
    assert_msg(r2["readiness_state"] == READINESS_EMPTY, "State EMPTY")
    assert_msg(r2["snapshot_id"] == "snap0", "Correct snapshot")

    print("\n--- Test 3: Snapshot exists, asset_count=3, but 0 required asset rows -> ERROR")
    upsert_tv_snapshot_cache(screen_id=101, snapshot_id="snap_err", snapshot_version=2, asset_count=3)
    r3 = compute_tv_screen_readiness(screen_id=101)
    assert_msg(r3["readiness_state"] == READINESS_ERROR, "State ERROR due to inconsistency")
    assert_msg(r3["missing_asset_count"] == 3, "All 3 counted as missing")

    print("\n--- Test 4: Setup proper snapshot with 3 assets")
    upsert_tv_snapshot_cache(screen_id=101, snapshot_id="snap1", snapshot_version=3, asset_count=3)
    upsert_tv_snapshot_required_asset(snapshot_id="snap1", media_asset_id="asset1")
    upsert_tv_snapshot_required_asset(snapshot_id="snap1", media_asset_id="asset2")
    upsert_tv_snapshot_required_asset(snapshot_id="snap1", media_asset_id="asset3")
    
    # None of them exist locally yet
    r4 = compute_tv_screen_readiness(screen_id=101)
    assert_msg(r4["readiness_state"] == READINESS_NOT_READY, "0/3 valid -> NOT_READY")
    assert_msg(r4["invalid_asset_count"] == 3, "All 3 unknown/invalid since no local state row exists yet")
    
    print("\n--- Test 5: Local asset states - PARTIALLY_READY")
    upsert_tv_local_asset_state(media_asset_id="asset1", asset_state=ASSET_STATE_VALID)
    upsert_tv_local_asset_state(media_asset_id="asset2", asset_state=ASSET_STATE_NOT_PRESENT)
    upsert_tv_local_asset_state(media_asset_id="asset3", asset_state=ASSET_STATE_INVALID_SIZE)
    r5 = compute_tv_screen_readiness(screen_id=101)
    assert_msg(r5["readiness_state"] == READINESS_PARTIALLY_READY, "1/3 valid -> PARTIALLY_READY")
    assert_msg(r5["ready_asset_count"] == 1, "1 ready")
    assert_msg(r5["missing_asset_count"] == 1, "1 missing")
    assert_msg(r5["invalid_asset_count"] == 1, "1 invalid")
    
    # What if one is PRESENT_UNCHECKED?
    upsert_tv_local_asset_state(media_asset_id="asset2", asset_state=ASSET_STATE_PRESENT_UNCHECKED)
    r5b = compute_tv_screen_readiness(screen_id=101)
    assert_msg(r5b["readiness_state"] == READINESS_PARTIALLY_READY, "Unchecked still means partially ready")
    assert_msg(r5b["invalid_asset_count"] == 2, "Unchecked counts as invalid/not-ready until validated")

    print("\n--- Test 6: All valid -> READY")
    upsert_tv_local_asset_state(media_asset_id="asset2", asset_state=ASSET_STATE_VALID)
    upsert_tv_local_asset_state(media_asset_id="asset3", asset_state=ASSET_STATE_VALID)
    r6 = compute_tv_screen_readiness(screen_id=101)
    assert_msg(r6["readiness_state"] == READINESS_READY, "3/3 valid -> READY")
    assert_msg(r6["is_fully_ready"] == 1, "is_fully_ready flipped to 1")

    print("\n--- Test 7: Batch runner idempotency")
    res = run_tv_readiness_computation(screen_id=0)  # should run for all enabled screens (just 101)
    assert_msg(res["ok"], "Runner ok")
    assert_msg(res["computed"] == 1, "Computed 1 screen")
    assert_msg(res["results"][0]["readiness_state"] == READINESS_READY, "Still READY")
    
    # Verify latest readiness fetch
    latest = load_tv_latest_readiness(screen_id=101)
    assert_msg(latest["readiness_state"] == READINESS_READY, "load_tv_latest_readiness works")
    
    all_rows = list_tv_snapshot_readiness(screen_id=101)
    assert_msg(all_rows["total"] > 1, f"There are multiple rows from state changes ({all_rows['total']})")
    
    # Ensure only 1 row has is_latest=1
    with get_conn() as conn:
        latest_c = conn.execute("SELECT COUNT(*) as c FROM tv_snapshot_readiness WHERE screen_id=101 AND is_latest=1").fetchone()["c"]
        assert_msg(latest_c == 1, "Only exact 1 row is flagged as latest")

    # 102 disabled screen
    b2 = create_tv_screen_binding(screen_id=102, enabled=False)
    res2 = run_tv_readiness_computation(screen_id=0)
    assert_msg(res2["computed"] == 1, "Disabled screen 102 was skipped in batch runner")

    print(f"\n=== FINISHED: {checks_passed}/{checks_total} PASSED ===")

if __name__ == "__main__":
    run_tests()
