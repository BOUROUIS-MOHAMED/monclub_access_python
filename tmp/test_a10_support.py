"""
A10 Support / Recovery Actions -- verification script.
Exercises the Access-side support summary, dispatcher, single-flight guard,
and durable support log behavior against an isolated temp data root.
"""
import os
import shutil
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_tmp = tempfile.mkdtemp()
os.environ["MONCLUB_ACCESS_DATA_ROOT"] = _tmp

from app.core import tv_local_cache as tv  # noqa: E402
from app.core.db import get_conn  # noqa: E402

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


def cleanup():
    shutil.rmtree(_tmp, ignore_errors=True)


try:
    tv.ensure_tv_local_schema()

    tv.replace_tv_host_monitors(monitors=[
        {
            "monitor_id": "mon-1",
            "monitor_label": "Monitor 1",
            "monitor_index": 0,
            "is_connected": True,
            "width": 1920,
            "height": 1080,
            "offset_x": 0,
            "offset_y": 0,
            "scale_factor": 1.0,
            "is_primary": True,
        }
    ])

    binding = tv.create_tv_screen_binding(
        screen_id=401,
        screen_label="Support Screen",
        gym_id=77,
        monitor_id="mon-1",
        monitor_label="Monitor 1",
        enabled=True,
    )
    bid = binding["id"]

    tv.upsert_tv_snapshot_cache(
        screen_id=401,
        snapshot_id="snap-a10-1",
        snapshot_version=1,
        manifest_status=tv.MANIFEST_STATUS_COMPLETE,
        sync_status="COMPLETED",
        is_latest=True,
        asset_count=1,
    )
    tv.upsert_tv_snapshot_required_asset(
        snapshot_id="snap-a10-1",
        media_asset_id="asset-a10-1",
        checksum_sha256="abc123",
        size_bytes=5,
        mime_type="video/mp4",
        media_type="VIDEO",
        download_link="https://example.invalid/a.mp4",
    )
    tv.upsert_tv_local_asset_state(
        media_asset_id="asset-a10-1",
        expected_local_path=os.path.join(_tmp, "tv", "media", "asset-a10-1.mp4"),
        local_file_path=os.path.join(_tmp, "tv", "media", "asset-a10-1.mp4"),
        file_exists=True,
        local_size_bytes=5,
        local_checksum_sha256="abc123",
        asset_state=tv.ASSET_STATE_VALID,
        validation_mode=tv.VALIDATION_STRONG,
        state_reason="seeded",
        last_checked_at=tv.now_iso(),
    )
    tv.upsert_tv_snapshot_readiness(
        screen_id=401,
        snapshot_id="snap-a10-1",
        snapshot_version=1,
        readiness_state=tv.READINESS_READY,
        total_required_assets=1,
        ready_asset_count=1,
        missing_asset_count=0,
        invalid_asset_count=0,
        stale_asset_count=0,
        is_fully_ready=True,
        is_latest=True,
    )

    summary = tv.load_tv_binding_support_summary(binding_id=bid)
    check("support summary returns ok", summary.get("ok") is True, summary)
    check("initial health is STOPPED", summary.get("health") == tv.BINDING_HEALTH_STOPPED, summary.get("health"))

    start_result = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_START_BINDING,
        confirm=False,
        triggered_by="TEST",
    )
    check("START_BINDING succeeds", start_result.get("result") == tv.SUPPORT_RESULT_SUCCEEDED, start_result)
    tv.upsert_tv_screen_binding_runtime(binding_id=bid, runtime_state=tv.BINDING_RUNTIME_RUNNING)

    no_confirm_stop = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_STOP_BINDING,
        confirm=False,
        triggered_by="TEST",
    )
    check("STOP_BINDING without confirm is blocked", no_confirm_stop.get("result") == tv.SUPPORT_RESULT_BLOCKED, no_confirm_stop)

    stop_result = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_STOP_BINDING,
        confirm=True,
        triggered_by="TEST",
    )
    check("STOP_BINDING with confirm succeeds", stop_result.get("result") == tv.SUPPORT_RESULT_SUCCEEDED, stop_result)

    tv.start_tv_screen_binding(binding_id=bid)
    tv.upsert_tv_screen_binding_runtime(binding_id=bid, runtime_state=tv.BINDING_RUNTIME_RUNNING)
    reset_blocked = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE,
        confirm=True,
        triggered_by="TEST",
    )
    check("RESET_TRANSIENT_PLAYER_STATE blocked while running", reset_blocked.get("result") == tv.SUPPORT_RESULT_BLOCKED, reset_blocked)

    tv.upsert_tv_screen_binding_runtime(binding_id=bid, runtime_state=tv.BINDING_RUNTIME_STARTING)
    restart_blocked = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_RESTART_BINDING,
        confirm=True,
        triggered_by="TEST",
    )
    check("RESTART_BINDING blocked during transition", restart_blocked.get("result") == tv.SUPPORT_RESULT_BLOCKED, restart_blocked)

    tv.stop_tv_screen_binding(binding_id=bid)
    tv.upsert_tv_screen_binding_runtime(binding_id=bid, runtime_state=tv.BINDING_RUNTIME_STOPPED)

    retry_downloads = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS,
        triggered_by="TEST",
    )
    check("RETRY_FAILED_DOWNLOADS skips cleanly", retry_downloads.get("result") == tv.SUPPORT_RESULT_SKIPPED, retry_downloads)

    activation_eval = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_REEVALUATE_ACTIVATION,
        triggered_by="TEST",
    )
    check("REEVALUATE_ACTIVATION succeeds", activation_eval.get("result") == tv.SUPPORT_RESULT_SUCCEEDED, activation_eval)

    activate_ready = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_ACTIVATE_LATEST_READY,
        triggered_by="TEST",
    )
    activation_state = tv.load_tv_activation_state(screen_id=401) or {}
    check("ACTIVATE_LATEST_READY succeeds", activate_ready.get("result") == tv.SUPPORT_RESULT_SUCCEEDED, activate_ready)
    check("activation state now has active snapshot", activation_state.get("active_snapshot_id") == "snap-a10-1", activation_state)

    readiness_result = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_RECOMPUTE_READINESS,
        triggered_by="TEST",
    )
    latest_readiness = tv.load_tv_latest_readiness(screen_id=401) or {}
    check("RECOMPUTE_READINESS succeeds", readiness_result.get("result") == tv.SUPPORT_RESULT_SUCCEEDED, readiness_result)
    check("latest readiness remains READY", latest_readiness.get("readiness_state") == tv.READINESS_READY, latest_readiness)

    original_sync = tv._run_support_snapshot_sync

    def fake_sync(*, screen_id: int, correlation_id: str):
        return {
            "ok": True,
            "screen_id": screen_id,
            "result": tv.SYNC_RUN_SUCCESS,
            "correlation_id": correlation_id,
        }

    tv._run_support_snapshot_sync = fake_sync
    sync_result = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_RUN_SYNC,
        triggered_by="TEST",
    )
    check("RUN_SYNC succeeds", sync_result.get("result") == tv.SUPPORT_RESULT_SUCCEEDED, sync_result)
    check("RUN_SYNC returns correlation id", bool(sync_result.get("correlationId")), sync_result)

    gate = threading.Event()

    def slow_sync(*, screen_id: int, correlation_id: str):
        gate.wait(2.0)
        return {
            "ok": True,
            "screen_id": screen_id,
            "result": tv.SYNC_RUN_SUCCESS,
            "correlation_id": correlation_id,
        }

    tv._run_support_snapshot_sync = slow_sync
    thread_result = {}

    def worker():
        thread_result["value"] = tv.run_tv_binding_support_action(
            binding_id=bid,
            action_type=tv.SUPPORT_ACTION_RUN_SYNC,
            triggered_by="THREAD",
        )

    worker_thread = threading.Thread(target=worker, daemon=True)
    worker_thread.start()
    time.sleep(0.2)
    overlap_result = tv.run_tv_binding_support_action(
        binding_id=bid,
        action_type=tv.SUPPORT_ACTION_RECOMPUTE_READINESS,
        triggered_by="TEST",
    )
    gate.set()
    worker_thread.join(timeout=5.0)
    tv._run_support_snapshot_sync = original_sync

    check("single-flight blocks overlapping action", overlap_result.get("result") == tv.SUPPORT_RESULT_BLOCKED, overlap_result)
    check("blocked overlap returns already running code", overlap_result.get("errorCode") == "ALREADY_RUNNING", overlap_result)

    history = tv.list_tv_support_action_logs(binding_id=bid, limit=50, offset=0)
    rows = history.get("rows") or []
    check("support history returns rows", len(rows) >= 8, len(rows))
    check("history contains RUN_SYNC row", any(row.get("action_type") == tv.SUPPORT_ACTION_RUN_SYNC for row in rows), rows[:3])
    check("history rows include parsed metadata", any(isinstance(row.get("metadata"), dict) for row in rows), rows[:3])

    summary_after = tv.load_tv_binding_support_summary(binding_id=bid)
    check("support summary exposes action availability", isinstance(summary_after.get("actionAvailability"), dict), summary_after)
    check("support summary exposes last correlation id", bool(summary_after.get("lastCorrelationId")), summary_after)

finally:
    cleanup()

print(f"\n=== A10 Results: {PASS} passed, {FAIL} failed ===")
raise SystemExit(1 if FAIL else 0)
