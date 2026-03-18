"""Quick verification: ensure TV local schema creates all 9 tables and CRUD works."""
import importlib
import os
import shutil
import tempfile

_TEST_ROOT = tempfile.mkdtemp(prefix='tv_a1_test_')
os.environ['MONCLUB_ACCESS_DATA_ROOT'] = _TEST_ROOT

import app.core.utils as _u
import app.core.db as _db
import app.core.tv_local_cache as _tv

utils = importlib.reload(_u)
db = importlib.reload(_db)
tv = importlib.reload(_tv)

EXPECTED_TABLES = [
    'tv_host_monitor', 'tv_screen_binding', 'tv_screen_binding_runtime',
    'tv_screen_binding_event', 'tv_snapshot_cache', 'tv_snapshot_required_asset',
    'tv_local_asset_state', 'tv_snapshot_readiness', 'tv_sync_run_log',
]

def main():
    errors = []

    # 1. Schema creation
    tv._schema_ready = False
    tv.ensure_tv_local_schema()
    with db.get_conn() as conn:
        existing = [r['name'] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    for t in EXPECTED_TABLES:
        if t not in existing:
            errors.append(f"MISSING TABLE: {t}")
    print(f"[1] Schema: {len(EXPECTED_TABLES)} expected, {len([t for t in EXPECTED_TABLES if t in existing])} found")

    # 2. Host monitor CRUD
    m = tv.upsert_tv_host_monitor(monitor_id="mon-1", monitor_label="Primary", width=1920, height=1080, is_primary=True)
    assert m.get("monitor_id") == "mon-1", f"monitor upsert failed: {m}"
    monitors = tv.list_tv_host_monitors()
    assert len(monitors) >= 1, "list monitors empty"
    print("[2] Host monitor CRUD: OK")

    # 3. Screen binding CRUD
    b = tv.create_tv_screen_binding(screen_id=1001, screen_name="Test Screen", monitor_id="mon-1", enabled=True)
    assert b.get("screen_id") == 1001, f"binding create failed: {b}"
    bid = b["id"]
    b2 = tv.load_tv_screen_binding_by_id(binding_id=bid)
    assert b2 is not None, "load binding by id returned None"
    bindings = tv.list_tv_screen_bindings()
    assert len(bindings) >= 1, "list bindings empty"
    tv.update_tv_screen_binding(binding_id=bid, screen_name="Updated Screen")
    b3 = tv.load_tv_screen_binding_by_id(binding_id=bid)
    assert b3["screen_label"] == "Updated Screen", f"update failed: {b3}"
    # Duplicate screen_id should raise
    try:
        tv.create_tv_screen_binding(screen_id=1001, screen_name="Dupe")
        errors.append("Duplicate screen_id should have raised ValueError")
    except ValueError:
        pass
    print("[3] Screen binding CRUD: OK")

    # 4. Binding runtime
    rt = tv.upsert_tv_screen_binding_runtime(binding_id=bid, runtime_state="RUNNING")
    assert rt.get("runtime_state") == "RUNNING", f"runtime upsert failed: {rt}"
    rt2 = tv.load_tv_screen_binding_runtime(binding_id=bid)
    assert rt2 is not None, "load runtime returned None"
    print("[4] Binding runtime CRUD: OK")

    # 5. Binding events
    ev = tv.record_tv_screen_binding_event(binding_id=bid, event_type="STARTED", severity="INFO", message="test")
    assert ev.get("ok"), f"event record failed: {ev}"
    evs = tv.list_tv_screen_binding_events(binding_id=bid)
    assert evs["total"] >= 1, "list events empty"
    print("[5] Binding events CRUD: OK")

    # 6. Snapshot cache
    sc = tv.upsert_tv_snapshot_cache(screen_id=1001, snapshot_id="snap-100", snapshot_version=1,
                                      manifest_status="COMPLETE", sync_status="COMPLETED")
    assert sc.get("snapshot_id") == "snap-100", f"snapshot cache upsert failed: {sc}"
    latest = tv.load_tv_latest_snapshot(screen_id=1001)
    assert latest is not None, "load latest snapshot returned None"
    print("[6] Snapshot cache CRUD: OK")

    # 7. Required assets
    ra = tv.upsert_tv_snapshot_required_asset(snapshot_id="snap-100", media_asset_id="asset-1",
                                               title="Video 1", media_type="VIDEO", size_bytes=1024)
    assert ra.get("media_asset_id") == "asset-1", f"required asset upsert failed: {ra}"
    ras = tv.list_tv_snapshot_required_assets(snapshot_id="snap-100")
    assert len(ras) >= 1, "list required assets empty"
    print("[7] Required assets CRUD: OK")

    # 8. Local asset state
    la = tv.upsert_tv_local_asset_state(media_asset_id="asset-1", asset_state="VALID",
                                         file_exists=True, local_size_bytes=1024)
    assert la.get("asset_state") == "VALID", f"local asset upsert failed: {la}"
    la2 = tv.load_tv_local_asset_state(media_asset_id="asset-1")
    assert la2 is not None, "load local asset returned None"
    print("[8] Local asset state CRUD: OK")

    # 9. Snapshot readiness
    sr = tv.upsert_tv_snapshot_readiness(screen_id=1001, snapshot_id="snap-100", snapshot_version=1,
                                          readiness_state="READY", is_fully_ready=True,
                                          total_required_assets=1, ready_asset_count=1)
    assert sr.get("readiness_state") == "READY", f"readiness upsert failed: {sr}"
    lr = tv.load_tv_latest_readiness(screen_id=1001)
    assert lr is not None, "load latest readiness returned None"
    print("[9] Snapshot readiness CRUD: OK")

    # 10. Sync run log
    sl = tv.insert_tv_sync_run_log(screen_id=1001, target_snapshot_version=1,
                                    result="COMPLETED", warning_count=0)
    assert sl.get("result") == "COMPLETED", f"sync log insert failed: {sl}"
    sls = tv.list_tv_sync_run_logs(screen_id=1001)
    assert sls["total"] >= 1, "list sync logs empty"
    print("[10] Sync run log CRUD: OK")

    # 11. Delete binding
    ok = tv.delete_tv_screen_binding(binding_id=bid)
    assert ok, "delete binding returned False"
    print("[11] Delete binding: OK")

    # 12. Expected local path
    p = tv.compute_expected_local_path(screen_id=1001, media_asset_id="asset-1",
                                        media_type="VIDEO", mime_type="video/mp4")
    assert "asset-1.mp4" in p, f"expected local path wrong: {p}"
    print("[12] Expected local path: OK")

    # Summary
    if errors:
        print(f"\n!!! ERRORS: {len(errors)}")
        for e in errors:
            print(f"  - {e}")
    else:
        print("\n=== ALL 12 CHECKS PASSED ===")

    shutil.rmtree(_TEST_ROOT, ignore_errors=True)
    return len(errors) == 0

if __name__ == '__main__':
    import sys
    sys.exit(0 if main() else 1)
