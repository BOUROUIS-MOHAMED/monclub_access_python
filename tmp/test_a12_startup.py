"""
A12 Startup Reconciliation + Deployment Preflight verification script.
Builds an isolated Access data root, seeds startup-interrupted TV runtime state,
and verifies startup preflight, persisted reconciliation history, proof repair,
temp cleanup, and safe runtime reconciliation.
"""
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_tmp = tempfile.mkdtemp()
os.environ["MONCLUB_ACCESS_DATA_ROOT"] = _tmp

from app.core import tv_local_cache as tv  # noqa: E402
from app.core.db import get_conn, init_db, save_auth_token  # noqa: E402

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
    init_db()
    tv.ensure_tv_local_schema()
    now = tv.now_iso()
    save_auth_token(email="startup@test.local", token="seed-token", last_login_at=now)

    tv.replace_tv_host_monitors(
        monitors=[
            {
                "monitor_id": "startup-mon-1",
                "monitor_label": "Startup Monitor",
                "monitor_index": 0,
                "is_connected": True,
                "width": 1920,
                "height": 1080,
                "x": 0,
                "y": 0,
                "is_primary": True,
            },
            {
                "monitor_id": "startup-mon-2",
                "monitor_label": "Startup Monitor 2",
                "monitor_index": 1,
                "is_connected": True,
                "width": 1280,
                "height": 720,
                "x": 1920,
                "y": 0,
                "is_primary": False,
            },
        ]
    )

    binding_run = tv.create_tv_screen_binding(
        screen_id=801,
        screen_label="Startup Running",
        gym_id=301,
        monitor_id="startup-mon-1",
        monitor_label="Startup Monitor",
        enabled=True,
    )
    bid_run = binding_run["id"]
    tv.update_tv_screen_binding(binding_id=bid_run, desired_state=tv.DESIRED_RUNNING)
    tv.upsert_tv_screen_binding_runtime(
        binding_id=bid_run,
        runtime_state=tv.BINDING_RUNTIME_STARTING,
        window_id="tv-player-801",
        tauri_window_label="tv-player-801",
        last_error_code="",
        last_error_message="",
    )

    binding_stop = tv.create_tv_screen_binding(
        screen_id=802,
        screen_label="Startup Stopping",
        gym_id=302,
        monitor_id="startup-mon-2",
        monitor_label="Startup Monitor 2",
        enabled=True,
    )
    bid_stop = binding_stop["id"]
    tv.update_tv_screen_binding(binding_id=bid_stop, desired_state=tv.DESIRED_STOPPED)
    tv.upsert_tv_screen_binding_runtime(
        binding_id=bid_stop,
        runtime_state=tv.BINDING_RUNTIME_STOPPING,
        window_id="tv-player-802",
        tauri_window_label="tv-player-802",
    )

    expected_media = tv.compute_expected_local_path(
        media_asset_id="media-startup-1",
        checksum_sha256="abc123456789",
        mime_type="video/mp4",
        media_type="VIDEO",
    )
    os.makedirs(os.path.dirname(expected_media), exist_ok=True)
    with open(expected_media, "wb") as handle:
        handle.write(b"startup-media")

    tv.upsert_tv_snapshot_cache(
        screen_id=801,
        snapshot_id="startup-snap-1",
        snapshot_version=1,
        manifest_status=tv.MANIFEST_STATUS_COMPLETE,
        sync_status=tv.SYNC_STATUS_COMPLETED,
        is_latest=True,
        asset_count=1,
    )
    tv.upsert_tv_snapshot_required_asset(
        snapshot_id="startup-snap-1",
        media_asset_id="media-startup-1",
        checksum_sha256="abc123456789",
        size_bytes=len(b"startup-media"),
        mime_type="video/mp4",
        media_type="VIDEO",
        download_link="https://example.invalid/media-startup-1.mp4",
    )
    tv.upsert_tv_local_asset_state(
        media_asset_id="media-startup-1",
        expected_local_path=expected_media,
        local_file_path=expected_media,
        file_exists=True,
        local_size_bytes=len(b"startup-media"),
        local_checksum_sha256="abc123456789",
        asset_state=tv.ASSET_STATE_VALID,
        validation_mode=tv.VALIDATION_STRONG,
        state_reason="seeded",
        last_checked_at=now,
    )
    tv.upsert_tv_snapshot_readiness(
        screen_id=801,
        snapshot_id="startup-snap-1",
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
    tv.evaluate_tv_activation(screen_id=801)
    activation_before = tv.activate_tv_ready_snapshot(screen_id=801, trigger_source="TEST_A12")
    check("Seed activation succeeded", bool(activation_before.get("ok")), activation_before)

    tv.upsert_tv_player_state(
        binding_id=bid_run,
        state_updates={
            "screen_id": 801,
            "active_snapshot_id": "startup-snap-1",
            "active_snapshot_version": 1,
            "player_state": tv.PLAYER_STATE_LOADING_ACTIVE_SNAPSHOT,
            "render_mode": tv.RENDER_MODE_IDLE_FALLBACK,
            "last_tick_at": now,
            "last_state_change_at": now,
        },
    )

    tv.upsert_tv_ad_task_cache(
        campaign_task_id="task-startup-1",
        gym_id=301,
        campaign_id="campaign-startup",
        ad_media_id="ad-startup-1",
        scheduled_at=now,
        local_file_state=tv.AD_FILE_STATE_VALID,
        remote_status="READY",
    )
    tv.upsert_tv_gym_ad_runtime(
        gym_id=301,
        coordination_state=tv.GYM_COORD_DISPLAYING,
        current_campaign_task_id="task-startup-1",
        started_at=now,
        expected_finish_at=now,
        active_binding_count=1,
        failed_binding_count=0,
        audio_override_active=True,
    )

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tv_ad_task_runtime (
                campaign_task_id, gym_id, binding_scope_count, local_display_state, due_at,
                display_started_at, display_finished_at, display_aborted_at,
                display_abort_reason, display_abort_message, injected_layout,
                active_binding_ids_json, failed_binding_ids_json, correlation_id,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "task-startup-1",
                301,
                1,
                tv.AD_TASK_STATE_DISPLAYING,
                now,
                now,
                None,
                None,
                None,
                None,
                tv.AD_LAYOUT_FULL_SCREEN,
                f"[{bid_run}]",
                "[]",
                "corr-task-startup",
                now,
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO tv_ad_proof_outbox (
                campaign_task_id, campaign_id, gym_id, ad_media_id, idempotency_key,
                started_at, finished_at, displayed_duration_sec, expected_duration_sec,
                completed_fully, countable, result_status, reason_if_not_countable,
                correlation_id, participating_binding_count, failed_binding_count,
                outbox_state, attempt_count, next_attempt_at, last_error,
                backend_proof_id, backend_task_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "task-startup-1",
                "campaign-startup",
                301,
                "ad-startup-1",
                "idem-startup-proof",
                now,
                now,
                5,
                30,
                0,
                0,
                tv.PROOF_STATUS_ABORTED,
                "seeded sending row",
                "corr-proof-startup",
                1,
                0,
                tv.PROOF_OUTBOX_SENDING,
                0,
                None,
                None,
                None,
                None,
                now,
                now,
            ),
        )
        conn.commit()

    temp_file = os.path.join(_tmp, "tv", "media", "old-temp.mp4.downloading")
    os.makedirs(os.path.dirname(temp_file), exist_ok=True)
    with open(temp_file, "wb") as handle:
        handle.write(b"partial")
    old_epoch = time.time() - (8 * 3600)
    os.utime(temp_file, (old_epoch, old_epoch))

    bad_root_path = os.path.join(_tmp, "bad-root-file")
    with open(bad_root_path, "w", encoding="utf-8") as handle:
        handle.write("file blocks directory creation")

    preflight_bad_root = tv.run_tv_deployment_preflight(data_root_override=bad_root_path, include_query_checks=False)
    check("Preflight bad data root blocks startup", preflight_bad_root.get("ok") is False, preflight_bad_root)
    check(
        "Preflight bad data root emits blocker",
        any(item.get("code") == "DATA_ROOT_READY" and item.get("status") == tv.STARTUP_RESULT_FAILED for item in preflight_bad_root.get("checks") or []),
        preflight_bad_root.get("checks"),
    )

    preflight_bad_config = tv.run_tv_deployment_preflight(
        config_loader=lambda: (_ for _ in ()).throw(RuntimeError("CONFIG_BROKEN")),
        include_query_checks=False,
    )
    check("Preflight config failure blocks startup", preflight_bad_config.get("ok") is False, preflight_bad_config)
    check(
        "Preflight config failure emits blocker",
        any(item.get("code") == "CONFIG_LOAD" and item.get("status") == tv.STARTUP_RESULT_FAILED for item in preflight_bad_config.get("checks") or []),
        preflight_bad_config.get("checks"),
    )

    preflight_good = tv.run_tv_deployment_preflight(
        include_query_checks=False,
        monitors=[
            {
                "monitor_id": "startup-mon-1",
                "monitor_label": "Startup Monitor",
                "monitor_index": 0,
                "is_connected": True,
                "width": 1920,
                "height": 1080,
                "offset_x": 0,
                "offset_y": 0,
                "is_primary": True,
            }
        ],
    )
    check("Good preflight returns structured checks", isinstance(preflight_good.get("checks"), list), preflight_good)
    check("Good preflight includes info counts", (preflight_good.get("counts") or {}).get("infoCount", 0) >= 1, preflight_good.get("counts"))

    run = tv.run_tv_startup_reconciliation(
        trigger_source="TEST_A12",
        monitors=[
            {
                "monitor_id": "startup-mon-1",
                "monitor_label": "Startup Monitor",
                "monitor_index": 0,
                "is_connected": True,
                "width": 1920,
                "height": 1080,
                "offset_x": 0,
                "offset_y": 0,
                "is_primary": True,
            }
        ],
    )
    check("Startup run returns a run id", int(run.get("runId") or 0) > 0, run)
    check("Startup run did not block", run.get("result") != "BLOCKED", run)

    latest = tv.load_tv_startup_reconciliation_latest()
    check("Latest startup load returns ok", bool(latest.get("ok")), latest)
    check("Latest startup returns persisted phases", len(latest.get("phases") or []) == len(tv.STARTUP_PHASES), latest.get("phases"))
    check(
        "Latest startup phases keep required order",
        [phase.get("phaseName") for phase in latest.get("phases") or []] == list(tv.STARTUP_PHASES),
        [phase.get("phaseName") for phase in latest.get("phases") or []],
    )

    runs = tv.list_tv_startup_reconciliation_runs(limit=5, offset=0)
    check("Startup runs list returns rows", (runs.get("total") or 0) >= 1 and len(runs.get("rows") or []) >= 1, runs)

    proof_row = tv.list_tv_ad_proof_outbox(gym_id=301, campaign_task_id="task-startup-1", limit=5, offset=0)["rows"][0]
    check("SENDING proof recovered to FAILED_RETRYABLE", proof_row.get("outbox_state") == tv.PROOF_OUTBOX_FAILED_RETRYABLE, proof_row)

    gym_runtime = tv.load_tv_gym_ad_runtime(gym_id=301)
    check("Ad runtime recovered to IDLE", (gym_runtime or {}).get("coordination_state") == tv.GYM_COORD_IDLE, gym_runtime)

    runtime_run = tv.load_tv_screen_binding_runtime(binding_id=bid_run)
    runtime_stop = tv.load_tv_screen_binding_runtime(binding_id=bid_stop)
    check(
        "Desired running binding becomes safe non-running fact",
        (runtime_run or {}).get("runtime_state") in {tv.BINDING_RUNTIME_CRASHED, tv.BINDING_RUNTIME_ERROR},
        runtime_run,
    )
    check("Stopped binding reconciles to STOPPED", (runtime_stop or {}).get("runtime_state") == tv.BINDING_RUNTIME_STOPPED, runtime_stop)

    activation_after = tv.load_tv_activation_state(screen_id=801) or {}
    check("Activation active snapshot preserved", activation_after.get("active_snapshot_id") == "startup-snap-1", activation_after)

    check("Stale temp file removed", not os.path.exists(temp_file), temp_file)
    check("Valid media file preserved", os.path.exists(expected_media), expected_media)

    latest_phase_names = [phase.get("phaseName") for phase in latest.get("phases") or []]
    check("Monitor rescan phase present", "monitor_rescan" in latest_phase_names, latest_phase_names)
    check("Preflight phase present", "preflight" in latest_phase_names, latest_phase_names)
    check("Latest startup carries check list", isinstance(latest.get("checks"), list), latest)

finally:
    print(f"\nA12 startup verification: {PASS} passed, {FAIL} failed")
    cleanup()
    if FAIL:
        raise SystemExit(1)
