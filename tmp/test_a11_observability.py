"""
A11 Observability / Retention verification script.
Builds an isolated temp Access data root, seeds factual TV runtime state, and
verifies observability helpers plus safe retention cleanup.
"""
import json
import os
import shutil
import sys
import tempfile

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


def ts_days_ago(days: int) -> str:
    return tv._cutoff_ts_days(days)


def insert_support_log(*, binding_id: int, gym_id: int, action_type: str, result: str, created_at: str, message: str):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tv_support_action_log (
                binding_id, gym_id, correlation_id, action_type, result,
                message, error_code, error_message, metadata_json,
                started_at, finished_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?)
            """,
            (
                binding_id,
                gym_id,
                f"corr-{binding_id}-{action_type}-{result}",
                action_type,
                result,
                message,
                json.dumps({"seeded": True}),
                created_at,
                created_at,
                created_at,
                created_at,
            ),
        )
        conn.commit()


try:
    tv.ensure_tv_local_schema()
    now = tv.now_iso()
    old_40 = ts_days_ago(40)
    old_50 = ts_days_ago(50)
    old_70 = ts_days_ago(70)

    tv.replace_tv_host_monitors(
        monitors=[
            {
                "monitor_id": "mon-1",
                "monitor_label": "Monitor 1",
                "monitor_index": 0,
                "is_connected": True,
                "width": 1920,
                "height": 1080,
                "x": 0,
                "y": 0,
                "is_primary": True,
            }
        ]
    )
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tv_host_monitor (
                monitor_id, monitor_label, monitor_index, is_connected,
                width, height, x, y, is_primary, detected_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("mon-old", "Old Monitor", 9, 0, 1280, 720, 0, 0, 0, old_50, old_50),
        )
        conn.commit()

    # Healthy running binding on gym 91
    binding_ok = tv.create_tv_screen_binding(
        screen_id=501,
        screen_label="Healthy Screen",
        gym_id=91,
        monitor_id="mon-1",
        monitor_label="Monitor 1",
        enabled=True,
    )
    bid_ok = binding_ok["id"]
    tv.start_tv_screen_binding(binding_id=bid_ok)
    tv.upsert_tv_screen_binding_runtime(
        binding_id=bid_ok,
        runtime_state=tv.BINDING_RUNTIME_RUNNING,
        window_id="window-ok",
        tauri_window_label="tv-player-1",
        last_started_at=now,
        last_error_code="",
        last_error_message="",
    )
    tv.upsert_tv_snapshot_cache(
        screen_id=501,
        snapshot_id="snap-ok-1",
        snapshot_version=1,
        manifest_status=tv.MANIFEST_STATUS_COMPLETE,
        sync_status=tv.SYNC_STATUS_COMPLETED,
        is_latest=True,
        asset_count=1,
    )
    tv.upsert_tv_snapshot_required_asset(
        snapshot_id="snap-ok-1",
        media_asset_id="asset-ok-1",
        checksum_sha256="ok-hash",
        size_bytes=10,
        mime_type="video/mp4",
        media_type="VIDEO",
        download_link="https://example.invalid/ok.mp4",
    )
    tv.upsert_tv_local_asset_state(
        media_asset_id="asset-ok-1",
        expected_local_path=os.path.join(_tmp, "tv", "media", "asset-ok-1.mp4"),
        local_file_path=os.path.join(_tmp, "tv", "media", "asset-ok-1.mp4"),
        file_exists=True,
        local_size_bytes=10,
        local_checksum_sha256="ok-hash",
        asset_state=tv.ASSET_STATE_VALID,
        validation_mode=tv.VALIDATION_STRONG,
        state_reason="seeded",
        last_checked_at=now,
    )
    tv.upsert_tv_snapshot_readiness(
        screen_id=501,
        snapshot_id="snap-ok-1",
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
    tv.evaluate_tv_activation(screen_id=501)
    tv.activate_tv_ready_snapshot(screen_id=501, trigger_source="TEST")
    tv.upsert_tv_player_state(
        binding_id=bid_ok,
        state_updates={
            "screen_id": 501,
            "active_snapshot_id": "snap-ok-1",
            "active_snapshot_version": 1,
            "player_state": tv.PLAYER_STATE_RENDERING,
            "render_mode": tv.RENDER_MODE_VISUAL_ONLY,
            "last_tick_at": now,
            "last_snapshot_check_at": now,
            "last_state_change_at": now,
        },
    )
    tv.record_tv_screen_binding_event(
        binding_id=bid_ok,
        event_type="WINDOW_STARTED",
        message="Healthy binding started.",
    )
    tv.insert_tv_player_event(
        binding_id=bid_ok,
        event_type=tv.PLAYER_EVENT_STATE_CHANGED,
        message="Healthy player rendering.",
    )
    tv.insert_tv_sync_run_log(
        started_at=now,
        finished_at=now,
        screen_id=501,
        target_snapshot_version=1,
        result=tv.SYNC_RUN_SUCCESS,
        correlation_id="sync-ok",
    )
    insert_support_log(
        binding_id=bid_ok,
        gym_id=91,
        action_type=tv.SUPPORT_ACTION_RUN_SYNC,
        result=tv.SUPPORT_RESULT_SUCCEEDED,
        created_at=now,
        message="Seeded recent support action.",
    )
    tv.upsert_tv_ad_task_cache(
        campaign_task_id="task-live",
        gym_id=91,
        campaign_id="campaign-1",
        ad_media_id="ad-1",
        scheduled_at=now,
        local_file_state=tv.AD_FILE_STATE_VALID,
        remote_status="READY",
    )
    tv.upsert_tv_gym_ad_runtime(
        gym_id=91,
        coordination_state=tv.GYM_COORD_DISPLAYING,
        current_campaign_task_id="task-live",
        started_at=now,
        expected_finish_at=now,
        active_binding_count=1,
        failed_binding_count=0,
        audio_override_active=True,
    )

    # Problem binding on gym 92 with failed asset + retryable proof
    binding_bad = tv.create_tv_screen_binding(
        screen_id=502,
        screen_label="Problem Screen",
        gym_id=92,
        monitor_id="missing-monitor",
        monitor_label="Missing Monitor",
        enabled=True,
    )
    bid_bad = binding_bad["id"]
    tv.update_tv_screen_binding(binding_id=bid_bad, desired_state=tv.DESIRED_RUNNING)
    tv.upsert_tv_screen_binding_runtime(
        binding_id=bid_bad,
        runtime_state=tv.BINDING_RUNTIME_ERROR,
        last_crashed_at=now,
        crash_count=1,
        last_exit_reason="MONITOR_MISSING",
        last_error_code="MONITOR_MISSING",
        last_error_message="Monitor is not connected.",
    )
    tv.upsert_tv_snapshot_cache(
        screen_id=502,
        snapshot_id="snap-bad-1",
        snapshot_version=2,
        manifest_status=tv.MANIFEST_STATUS_COMPLETE,
        sync_status=tv.SYNC_STATUS_COMPLETED_WITH_WARNINGS,
        is_latest=True,
        asset_count=1,
    )
    tv.upsert_tv_snapshot_required_asset(
        snapshot_id="snap-bad-1",
        media_asset_id="asset-bad-1",
        checksum_sha256="bad-hash",
        size_bytes=10,
        mime_type="video/mp4",
        media_type="VIDEO",
        download_link="https://example.invalid/bad.mp4",
    )
    tv.upsert_tv_local_asset_state(
        media_asset_id="asset-bad-1",
        expected_local_path=os.path.join(_tmp, "tv", "media", "asset-bad-1.mp4"),
        local_file_path=os.path.join(_tmp, "tv", "media", "asset-bad-1.mp4"),
        file_exists=False,
        asset_state=tv.ASSET_STATE_ERROR,
        validation_mode=tv.VALIDATION_STRONG,
        state_reason="download failed",
        last_checked_at=now,
    )
    tv.upsert_tv_snapshot_readiness(
        screen_id=502,
        snapshot_id="snap-bad-1",
        snapshot_version=2,
        readiness_state=tv.READINESS_PARTIALLY_READY,
        total_required_assets=1,
        ready_asset_count=0,
        missing_asset_count=1,
        invalid_asset_count=0,
        stale_asset_count=0,
        is_fully_ready=False,
        is_latest=True,
    )
    tv.evaluate_tv_activation(screen_id=502)
    tv.upsert_tv_player_state(
        binding_id=bid_bad,
        state_updates={
            "screen_id": 502,
            "player_state": tv.PLAYER_STATE_ERROR,
            "render_mode": tv.RENDER_MODE_ERROR_FALLBACK,
            "fallback_reason": tv.FALLBACK_REASON_NO_ACTIVE_SNAPSHOT,
            "last_render_error_code": "ASSET_INVALID",
            "last_render_error_message": "Current render asset is invalid.",
            "last_tick_at": now,
            "last_state_change_at": now,
        },
    )
    tv.record_tv_screen_binding_event(
        binding_id=bid_bad,
        event_type="MONITOR_MISSING",
        severity=tv.SEVERITY_ERROR,
        message="Problem binding monitor is missing.",
    )
    tv.insert_tv_player_event(
        binding_id=bid_bad,
        event_type=tv.PLAYER_EVENT_ERROR,
        severity=tv.SEVERITY_ERROR,
        message="Problem player error.",
    )
    insert_support_log(
        binding_id=bid_bad,
        gym_id=92,
        action_type=tv.SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS,
        result=tv.SUPPORT_RESULT_BLOCKED,
        created_at=now,
        message="Seeded problem support action.",
    )

    with get_conn() as conn:
        # Proofs: one retryable live row, one old SENT row eligible for cleanup.
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
                "task-proof-live",
                "campaign-2",
                92,
                "ad-2",
                "idem-live",
                now,
                now,
                0,
                30,
                0,
                0,
                tv.PROOF_STATUS_ABORTED,
                "seeded retryable",
                "corr-proof-live",
                1,
                1,
                tv.PROOF_OUTBOX_FAILED_RETRYABLE,
                3,
                now,
                "temporary failure",
                None,
                None,
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
                "task-proof-old",
                "campaign-2",
                92,
                "ad-2",
                "idem-old",
                old_70,
                old_70,
                30,
                30,
                1,
                1,
                tv.PROOF_STATUS_COMPLETED,
                None,
                "corr-proof-old",
                1,
                0,
                tv.PROOF_OUTBOX_SENT,
                1,
                None,
                None,
                "backend-old",
                "COMPLETED",
                old_70,
                old_70,
            ),
        )

        # Old history eligible for retention.
        conn.execute(
            "INSERT INTO tv_screen_binding_event (binding_id, event_type, severity, message, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (bid_ok, "OLD_EVENT", tv.SEVERITY_INFO, "Old binding event", json.dumps({"seeded": True}), old_40),
        )
        conn.execute(
            "INSERT INTO tv_player_event (binding_id, event_type, severity, message, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (bid_ok, "OLD_PLAYER_EVENT", tv.SEVERITY_INFO, "Old player event", json.dumps({"seeded": True}), old_40),
        )
        conn.execute(
            "INSERT INTO tv_sync_run_log (started_at, finished_at, screen_id, target_snapshot_version, result, warning_count, error_message, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (old_40, old_40, 501, 1, tv.SYNC_RUN_SUCCESS, 0, None, "sync-old", old_40),
        )
        conn.execute(
            "INSERT INTO tv_activation_attempt (screen_id, trigger_source, target_snapshot_id, target_snapshot_version, result, failure_reason, message, precheck_readiness_state, precheck_manifest_status, started_at, finished_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (501, "TEST", "snap-ok-1", 1, tv.ATTEMPT_RESULT_ACTIVATED, None, "Old activation attempt", tv.READINESS_READY, tv.MANIFEST_STATUS_COMPLETE, old_40, old_40, old_40),
        )
        conn.execute(
            """
            INSERT INTO tv_ad_task_runtime (
                campaign_task_id, gym_id, binding_scope_count, local_display_state,
                due_at, display_started_at, display_finished_at, display_aborted_at,
                display_abort_reason, display_abort_message, injected_layout,
                active_binding_ids_json, failed_binding_ids_json, correlation_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "task-runtime-old",
                91,
                1,
                tv.AD_TASK_STATE_COMPLETED,
                old_40,
                old_40,
                old_40,
                None,
                None,
                None,
                tv.AD_LAYOUT_FULL_SCREEN,
                json.dumps([bid_ok]),
                json.dumps([]),
                "corr-task-old",
                old_40,
                old_40,
            ),
        )
        conn.commit()

    insert_support_log(
        binding_id=bid_ok,
        gym_id=91,
        action_type=tv.SUPPORT_ACTION_RELOAD_PLAYER,
        result=tv.SUPPORT_RESULT_SUCCEEDED,
        created_at=old_40,
        message="Old support log",
    )

    overview = tv.get_tv_observability_overview()
    check("overview returns ok", overview.get("ok") is True, overview)
    check("overview counts bindings", overview.get("totals", {}).get("totalBindings") == 2, overview.get("totals"))
    check("overview counts active ad runtimes", overview.get("totals", {}).get("activeGymAdRuntimes") == 1, overview.get("totals"))
    check("overview counts retryable proofs", overview.get("totals", {}).get("queuedOrRetryableProofCount") == 1, overview.get("totals"))
    check("overview counts failed downloads", overview.get("totals", {}).get("recentFailedDownloadsCount") >= 1, overview.get("totals"))
    check("overview counts stale/problem bindings", overview.get("totals", {}).get("staleProblemBindingsCount") >= 1, overview.get("totals"))

    binding_diag = tv.get_tv_observability_binding(binding_id=bid_bad)
    check("binding diagnostics returns ok", binding_diag.get("ok") is True, binding_diag)
    check("binding diagnostics includes failed assets", binding_diag.get("failedAssets", {}).get("count") == 1, binding_diag.get("failedAssets"))
    check("binding diagnostics includes recent events", binding_diag.get("recentEvents", {}).get("total", 0) >= 2, binding_diag.get("recentEvents"))
    check("binding diagnostics includes support summary", bool(binding_diag.get("supportSummary")), binding_diag)

    gym_diag = tv.get_tv_observability_gym(gym_id=91)
    check("gym diagnostics returns ok", gym_diag.get("ok") is True, gym_diag)
    check("gym diagnostics exposes coordination state", gym_diag.get("coordinationState") == tv.GYM_COORD_DISPLAYING, gym_diag)
    check("gym diagnostics exposes audio override", gym_diag.get("audioOverrideActive") is True, gym_diag)

    proofs = tv.list_tv_observability_proofs(limit=20, offset=0)
    states = {row.get("outbox_state") for row in (proofs.get("rows") or [])}
    check("proof diagnostics lists rows", proofs.get("total", 0) >= 2, proofs)
    check("proof diagnostics exposes retryable state", tv.PROOF_OUTBOX_FAILED_RETRYABLE in states, states)
    check("proof diagnostics exposes sent state", tv.PROOF_OUTBOX_SENT in states, states)

    retention = tv.get_tv_observability_retention()
    table_map = {row["table"]: row for row in retention.get("tables") or []}
    check("retention summary returns ok", retention.get("ok") is True, retention)
    check("retention summary finds old support logs", table_map.get("tv_support_action_log", {}).get("eligibleRows", 0) >= 1, table_map.get("tv_support_action_log"))
    check("retention summary finds old proofs", table_map.get("tv_ad_proof_outbox", {}).get("eligibleRows", 0) >= 1, table_map.get("tv_ad_proof_outbox"))
    check("retention summary finds old disconnected monitors", table_map.get("tv_host_monitor", {}).get("eligibleRows", 0) >= 1, table_map.get("tv_host_monitor"))

    run = tv.run_tv_retention_maintenance(dry_run=False)
    check("retention run returns ok", run.get("ok") is True, run)
    check("retention run deletes rows", run.get("deletedRows", 0) >= 6, run)

    with get_conn() as conn:
        runtime_row = conn.execute("SELECT * FROM tv_screen_binding_runtime WHERE binding_id=?", (bid_ok,)).fetchone()
        activation_state = conn.execute("SELECT * FROM tv_activation_state WHERE screen_id=501").fetchone()
        binding_count = conn.execute("SELECT COUNT(*) AS cnt FROM tv_screen_binding").fetchone()["cnt"]
        retryable_proof = conn.execute(
            "SELECT COUNT(*) AS cnt FROM tv_ad_proof_outbox WHERE outbox_state=?",
            (tv.PROOF_OUTBOX_FAILED_RETRYABLE,),
        ).fetchone()["cnt"]
        sent_proof = conn.execute(
            "SELECT COUNT(*) AS cnt FROM tv_ad_proof_outbox WHERE outbox_state=? AND campaign_task_id='task-proof-old'",
            (tv.PROOF_OUTBOX_SENT,),
        ).fetchone()["cnt"]
        old_monitor = conn.execute("SELECT COUNT(*) AS cnt FROM tv_host_monitor WHERE monitor_id='mon-old'").fetchone()["cnt"]

    check("binding runtime preserved after retention", runtime_row is not None, runtime_row)
    check("activation state preserved after retention", activation_state is not None, activation_state)
    check("bindings preserved after retention", binding_count == 2, binding_count)
    check("retryable proofs preserved after retention", retryable_proof == 1, retryable_proof)
    check("old sent proof removed by retention", sent_proof == 0, sent_proof)
    check("stale disconnected monitor removed", old_monitor == 0, old_monitor)

finally:
    cleanup()

print(f"\n=== A11 Results: {PASS} passed, {FAIL} failed ===")
raise SystemExit(1 if FAIL else 0)
