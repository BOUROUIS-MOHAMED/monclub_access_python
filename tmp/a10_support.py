
# ---------------------------------------------------------------------------
# A10: Support and Recovery Actions
# ---------------------------------------------------------------------------

def get_tv_binding_health_summary(*, binding_id: int) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    binding = get_tv_screen_binding(binding_id=bid)
    if not binding:
        return {"health": BINDING_HEALTH_ERROR, "reasons": ["Binding not found"]}

    enabled = _binding_bool(binding.get("enabled"))
    desired = _safe_str(binding.get("desired_state"), DESIRED_STOPPED)

    if not enabled or desired == DESIRED_STOPPED:
        return {"health": BINDING_HEALTH_STOPPED, "reasons": ["Binding is stopped or disabled"]}

    # Collect facts
    reasons = []
    is_error = False
    is_degraded = False
    is_warning = False

    runtime = get_tv_screen_binding_runtime(binding_id=bid) or {}
    run_state = _safe_str(runtime.get("runtime_state"), BINDING_RUNTIME_IDLE)
    crash_count = _safe_int(runtime.get("crash_count"), 0)

    if crash_count > 3:
        is_error = True
        reasons.append(f"High crash count ({crash_count})")
    elif crash_count > 0:
        is_warning = True
        reasons.append(f"Recent crashes ({crash_count})")

    if run_state in (BINDING_RUNTIME_ERROR, BINDING_RUNTIME_CRASHED):
        is_error = True
        reasons.append(f"Runtime state is {run_state}")

    if binding.get("last_error_message"):
        is_warning = True
        reasons.append(f"Binding error: {binding['last_error_message']}")

    # Player state facts
    player_state = load_tv_player_state(binding_id=bid) or {}
    p_state = _safe_str(player_state.get("player_state"), PLAYER_STATE_IDLE)
    p_fallback = _safe_str(player_state.get("fallback_reason"), "")

    if p_state == PLAYER_STATE_ERROR:
        is_error = True
        reasons.append("Player is in ERROR state")
    elif p_fallback:
        is_degraded = True
        reasons.append(f"Player fallback: {p_fallback}")

    if p_state.startswith("BLOCKED"):
        is_error = True
        reasons.append(f"Player blocked: {p_state}")

    # Monitor availability
    mid = _safe_str(binding.get("monitor_id"), "")
    if mid:
        monitors = list_tv_host_monitors()
        mon = next((m for m in monitors if m.get("monitor_id") == mid), None)
        if not mon or not _binding_bool(mon.get("is_connected")):
            is_error = True
            reasons.append(f"Assigned monitor disconnected or missing: {mid}")

    # Determine health enum
    health = BINDING_HEALTH_HEALTHY
    if is_error:
        health = BINDING_HEALTH_ERROR
    elif is_degraded:
        health = BINDING_HEALTH_DEGRADED
    elif is_warning:
        health = BINDING_HEALTH_WARNING

    if health == BINDING_HEALTH_HEALTHY and not reasons:
        reasons.append("Running normally")

    return {
        "health": health,
        "reasons": reasons,
        "summary": {
            "binding": dict(binding),
            "runtime": dict(runtime),
            "player": dict(player_state),
        }
    }


def _start_support_action(conn, binding_id: int, action_type: str) -> str:
    # Single flight check
    running = conn.execute(
        "SELECT id FROM tv_support_action_log WHERE binding_id=? AND result=? LIMIT 1",
        (binding_id, SUPPORT_RESULT_STARTED)
    ).fetchone()
    if running:
        raise ValueError(f"Support action already running for binding {binding_id}")

    corr_id = f"sa_{uuid.uuid4().hex[:12]}"
    ts = now_iso()
    gym_id = conn.execute("SELECT gym_id FROM tv_screen_binding WHERE id=?", (binding_id,)).fetchone()
    gid = _safe_int(gym_id[0]) if gym_id else 0

    curr_cur = conn.execute("""
        INSERT INTO tv_support_action_log (
            binding_id, gym_id, correlation_id, action_type, result, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (binding_id, gid, corr_id, action_type, SUPPORT_RESULT_STARTED, ts, ts, ts))
    return corr_id


def _finish_support_action(conn, correlation_id: str, result: str, message: str = None, error_code: str = None,
                           metadata: dict = None):
    ts = now_iso()
    meta_json = _json_dumps(metadata) if metadata else None
    conn.execute("""
        UPDATE tv_support_action_log
        SET result=?, message=?, error_code=?, error_message=?, metadata_json=?, finished_at=?, updated_at=?
        WHERE correlation_id=?
    """, (result, message, error_code, message if error_code else None, meta_json, ts, ts, correlation_id))


def run_tv_support_action(*, binding_id: int, action_type: str, options: Dict[str, Any] = None, confirm: bool = False) -> Dict[str, Any]:
    ensure_tv_local_schema()
    bid = int(binding_id)
    opts = options or {}

    destructive_actions = {
        SUPPORT_ACTION_STOP_BINDING,
        SUPPORT_ACTION_RESTART_BINDING,
        SUPPORT_ACTION_RESTART_PLAYER_WINDOW,
        SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE
    }

    if action_type in destructive_actions and not confirm:
        return {"ok": False, "result": SUPPORT_RESULT_BLOCKED, "error": "CONFIRMATION_REQUIRED", "message": f"{action_type} requires confirm=True"}

    with get_conn() as conn:
        try:
            corr_id = _start_support_action(conn, bid, action_type)
            conn.commit()
        except ValueError as e:
            return {"ok": False, "result": SUPPORT_RESULT_BLOCKED, "error": "ALREADY_RUNNING", "message": str(e)}
        except Exception as e:
            _log.error("Failed to start support action: %s", e)
            return {"ok": False, "result": SUPPORT_RESULT_FAILED, "error": "INTERNAL_ERROR", "message": str(e)}

    # Dispatch externally
    result = SUPPORT_RESULT_SUCCEEDED
    message = None
    err_code = None
    meta = {}

    try:
        # Resolve screen_id if needed
        binding = get_tv_screen_binding(binding_id=bid)
        if not binding:
            err_code = "BINDING_NOT_FOUND"
            result = SUPPORT_RESULT_BLOCKED
            raise ValueError(f"Binding {bid} not found")
        
        sid = _safe_int(binding.get("screen_id"), 0)

        if action_type == SUPPORT_ACTION_RUN_SYNC:
            if not sid:
                raise ValueError("Binding has no valid screen_id for sync")
            sync_res = sync_tv_screen_latest_snapshot(screen_id=sid, force_recheck=True, correlation_id=corr_id)
            meta["sync"] = sync_res
            if not sync_res.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "SYNC_FAILED"
                message = sync_res.get("error") or "Sync failed"

        elif action_type == SUPPORT_ACTION_RECOMPUTE_READINESS:
            if not sid:
                raise ValueError("Binding has no valid screen_id")
            # Force readiness recompute
            snap_res = get_tv_screen_active_snapshot(screen_id=sid)
            latest_id = snap_res.get("state", {}).get("latest_snapshot_id")
            if latest_id:
                read_res = get_or_compute_snapshot_readiness(screen_id=sid, snapshot_id=latest_id, force_recheck=True)
                meta["readiness"] = read_res
            else:
                result = SUPPORT_RESULT_SKIPPED
                message = "No latest snapshot to compute readiness for"

        elif action_type == SUPPORT_ACTION_REEVALUATE_ACTIVATION:
            if not sid:
                raise ValueError("Binding has no valid screen_id")
            act_res = evaluate_tv_screen_activation(screen_id=sid, reason="support_reevaluate", execute_if_ready=True)
            meta["activation"] = act_res
            if not act_res.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "ACTIVATION_REEVAL_FAILED"
                message = act_res.get("error")

        elif action_type == SUPPORT_ACTION_ACTIVATE_LATEST_READY:
            if not sid:
                raise ValueError("Binding has no valid screen_id")
            act_res = evaluate_tv_screen_activation(screen_id=sid, reason="support_activate_latest", execute_if_ready=True)
            meta["activation"] = act_res
            if not act_res.get("ok") and act_res.get("error") != "SKIPPED_ALREADY_ACTIVE":
                 result = SUPPORT_RESULT_FAILED
                 err_code = "ACTIVATION_FAILED"
                 message = act_res.get("error")

        elif action_type == SUPPORT_ACTION_REEVALUATE_PLAYER_CONTEXT:
            ctx = reevaluate_tv_player(binding_id=bid, persist=True)
            meta["context"] = ctx
            if not ctx.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "REEVALUATE_FAILED"
                message = ctx.get("error")

        elif action_type == SUPPORT_ACTION_RELOAD_PLAYER:
            ctx = reload_tv_player(binding_id=bid, persist=True)
            meta["context"] = ctx
            if not ctx.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "RELOAD_FAILED"
                message = ctx.get("error")

        elif action_type == SUPPORT_ACTION_RETRY_FAILED_DOWNLOADS:
            from app.core._tv_sync_helpers import retry_screen_failed_downloads
            if not sid:
                raise ValueError("Binding has no valid screen_id")
            res_retry = retry_screen_failed_downloads(screen_id=sid, force=True)
            meta["retry_results"] = res_retry
            if res_retry.get("retried_count", 0) == 0:
                result = SUPPORT_RESULT_SKIPPED
                message = "No failed downloads to retry"

        elif action_type == SUPPORT_ACTION_RETRY_ONE_DOWNLOAD:
            asset_id = opts.get("mediaAssetId")
            if not asset_id:
                err_code = "MISSING_ASSET_ID"
                result = SUPPORT_RESULT_BLOCKED
                raise ValueError("mediaAssetId option is required")
            
            from app.core._tv_sync_helpers import evaluate_local_asset
            res_eval = evaluate_local_asset(media_asset_id=asset_id, force_download_retry=True)
            meta["asset_eval"] = res_eval

        elif action_type == SUPPORT_ACTION_START_BINDING:
            db_res = update_tv_screen_binding(binding_id=bid, updates={"desired_state": DESIRED_RUNNING})
            meta["update"] = db_res
            if not db_res.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "START_FAILED"
                message = db_res.get("error")

        elif action_type == SUPPORT_ACTION_STOP_BINDING:
            db_res = update_tv_screen_binding(binding_id=bid, updates={"desired_state": DESIRED_STOPPED})
            meta["update"] = db_res
            if not db_res.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "STOP_FAILED"
                message = db_res.get("error")

        elif action_type == SUPPORT_ACTION_RESTART_BINDING:
            # Requires stopping then starting in quick succession
            res_stop = update_tv_screen_binding(binding_id=bid, updates={"desired_state": DESIRED_STOPPED})
            res_start = update_tv_screen_binding(binding_id=bid, updates={"desired_state": DESIRED_RUNNING})
            meta["stop"] = res_stop
            meta["start"] = res_start
            if not res_start.get("ok"):
                result = SUPPORT_RESULT_FAILED
                err_code = "RESTART_FAILED"
                message = res_start.get("error")
                
        elif action_type == SUPPORT_ACTION_RESTART_PLAYER_WINDOW:
            # We enforce restart by setting runtime to crashed, then supervisor restarts it if desired is running
            db_res = report_tv_screen_binding_runtime(binding_id=bid, runtime_state=BINDING_RUNTIME_CRASHED, last_exit_reason="support_restart")
            meta["runtime_update"] = db_res

        elif action_type == SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE:
            # Must be stopped
            run_state = get_tv_screen_binding_runtime(binding_id=bid) or {}
            rt = _safe_str(run_state.get("runtime_state"), BINDING_RUNTIME_IDLE)
            if rt in (BINDING_RUNTIME_RUNNING, BINDING_RUNTIME_STARTING):
                result = SUPPORT_RESULT_BLOCKED
                err_code = "MUST_STOP_FIRST"
                raise ValueError(f"Binding must be stopped to reset transient state. Current runtime = {rt}")
            
            with get_conn() as rconn:
                rconn.execute("DELETE FROM tv_player_state WHERE binding_id=?", (bid,))
                rconn.execute("DELETE FROM tv_screen_binding_runtime WHERE binding_id=?", (bid,))
                rconn.commit()
            message = "Transient player state cleared."

        else:
            result = SUPPORT_RESULT_FAILED
            err_code = "UNKNOWN_ACTION_TYPE"
            message = f"Unsupported action type: {action_type}"

    except Exception as e:
        _log.exception(f"Support action {action_type} failed: {e}")
        if result not in (SUPPORT_RESULT_BLOCKED, SUPPORT_RESULT_SKIPPED):
            result = SUPPORT_RESULT_FAILED
        if not err_code:
            err_code = "EXECUTION_ERROR"
        if not message:
            message = str(e)

    # Finally write result
    try:
        with get_conn() as conn:
            _finish_support_action(conn, corr_id, result, message, err_code, meta)
            conn.commit()
    except Exception as e2:
        _log.error("Failed to commit support finish: %s", e2)

    return {
        "ok": result in (SUPPORT_RESULT_SUCCEEDED, SUPPORT_RESULT_SKIPPED),
        "correlationId": corr_id,
        "result": result,
        "message": message,
        "errorCode": err_code,
        "metadata": meta
    }


def get_tv_support_action_history(*, binding_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    ensure_tv_local_schema()
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM tv_support_action_log
            WHERE binding_id=?
            ORDER BY created_at DESC
            LIMIT ?
        """, (int(binding_id), int(limit))).fetchall()
        
        hist = []
        for r in rows:
            d = _row_to_dict(r)
            d["metadata"] = _json_loads(d.pop("metadata_json", None))
            hist.append(d)
        return hist
