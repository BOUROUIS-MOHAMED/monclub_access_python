"""
Test script for Functionality A2: Snapshot Fetch + Manifest Cache.
Verifies:
 1) New constants exist
 2) delete_tv_snapshot_required_assets_for_snapshot works
 3) _finalize_sync_run works
 4) run_tv_snapshot_sync handles no-bindings case
 5) run_tv_snapshot_sync handles no-auth case
"""
import os, sys, tempfile, sqlite3

# ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Use a temp DB to avoid touching real data
_tmp = tempfile.mkdtemp(prefix="test_a2_")
os.environ["MONCLUB_DATA_ROOT"] = _tmp

# Patch DATA_ROOT before import
import app.core.utils as utils
utils.DATA_ROOT = _tmp
utils.DB_PATH = os.path.join(_tmp, "test_a2.db")

from app.core import tv_local_cache as tvc

checks_passed = 0
checks_total = 0

def check(name, condition):
    global checks_total, checks_passed
    checks_total += 1
    if condition:
        checks_passed += 1
        print(f"  [OK] {name}")
    else:
        print(f"  [FAIL] {name}")

# --- 1) Constants ---
print("\n=== 1) New A2 Constants ===")
check("SYNC_STATUS_IDLE", tvc.SYNC_STATUS_IDLE == "IDLE")
check("SYNC_STATUS_FETCHING_SNAPSHOT", tvc.SYNC_STATUS_FETCHING_SNAPSHOT == "FETCHING_SNAPSHOT")
check("SYNC_STATUS_FETCHING_MANIFEST", tvc.SYNC_STATUS_FETCHING_MANIFEST == "FETCHING_MANIFEST")
check("SYNC_RUN_SUCCESS", tvc.SYNC_RUN_SUCCESS == "SUCCESS")
check("SYNC_RUN_NO_SNAPSHOT", tvc.SYNC_RUN_NO_SNAPSHOT == "NO_SNAPSHOT")
check("MANIFEST_STATUS_MISSING", tvc.MANIFEST_STATUS_MISSING == "MISSING")

# --- 2) Schema + CRUD ---
print("\n=== 2) Schema + delete_tv_snapshot_required_assets_for_snapshot ===")
tvc.ensure_tv_local_schema()
check("schema created", True)

# insert a snapshot + asset
tvc.upsert_tv_snapshot_cache(
    screen_id=42, snapshot_id="snap-001", snapshot_version=1,
    activation_state="", resolved_at="", resolved_day_of_week="",
    fetched_at=utils.now_iso(), sync_status="COMPLETED",
)
tvc.upsert_tv_snapshot_required_asset(
    snapshot_id="snap-001", media_asset_id="asset-A",
)
tvc.upsert_tv_snapshot_required_asset(
    snapshot_id="snap-001", media_asset_id="asset-B",
)
assets = tvc.list_tv_snapshot_required_assets(snapshot_id="snap-001")
check("2 assets inserted", len(assets) == 2)

deleted = tvc.delete_tv_snapshot_required_assets_for_snapshot(snapshot_id="snap-001")
check("delete returned 2", deleted == 2)
assets = tvc.list_tv_snapshot_required_assets(snapshot_id="snap-001")
check("0 assets after delete", len(assets) == 0)

# --- 3) _finalize_sync_run ---
print("\n=== 3) _finalize_sync_run ===")
log = tvc.insert_tv_sync_run_log(screen_id=42, started_at=utils.now_iso(), correlation_id="corr-1")
log_id = log.get("id")
check("sync log created", log_id is not None)
tvc._finalize_sync_run(log_id, result="SUCCESS", target_snapshot_version=5, warning_count=1)
# read back
from app.core.db import get_conn
with get_conn() as conn:
    row = conn.execute("SELECT * FROM tv_sync_run_log WHERE id=?", (log_id,)).fetchone()
check("finalized result", dict(row)["result"] == "SUCCESS")
check("finalized version", dict(row)["target_snapshot_version"] == 5)
check("finalized warning_count", dict(row)["warning_count"] == 1)
check("finalized finished_at set", dict(row)["finished_at"] is not None)

# --- 4) run_tv_snapshot_sync with no bindings ---
print("\n=== 4) run_tv_snapshot_sync — no bindings ===")
result = tvc.run_tv_snapshot_sync()
check("ok=True", result.get("ok") == True)
check("synced=0", result.get("synced") == 0)
check("skipped=True", result.get("skipped") == True)
check("correlation_id present", bool(result.get("correlation_id")))

# --- 5) run_tv_snapshot_sync with no auth ---
print("\n=== 5) run_tv_snapshot_sync — with binding but no auth ===")
tvc.create_tv_screen_binding(
    screen_id=42, screen_name="Test Screen",
    enabled=True,
)
result = tvc.run_tv_snapshot_sync()
check("ok=False", result.get("ok") == False)
check("error mentions auth/token", "auth" in result.get("error", "").lower() or "token" in result.get("error", "").lower())

# --- Summary ---
print(f"\n{'='*50}")
print(f"  PASSED: {checks_passed}/{checks_total}")
if checks_passed == checks_total:
    print("  ALL CHECKS PASSED ✓")
else:
    print(f"  {checks_total - checks_passed} CHECKS FAILED ✗")
print(f"{'='*50}")

# Cleanup
import shutil
shutil.rmtree(_tmp, ignore_errors=True)
