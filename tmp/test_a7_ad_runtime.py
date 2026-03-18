"""
A7 Ad Task Runtime -- verification test script.
Tests gym-level coordination, due-task selection, injection, completion, abort,
grace-window expiry, and startup recovery.
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
    load_tv_ad_task_cache_one,
    list_tv_ad_task_cache,
    upsert_tv_gym_ad_runtime,
    load_tv_gym_ad_runtime,
    upsert_tv_ad_task_runtime,
    load_tv_ad_task_runtime,
    list_tv_ad_task_runtime,
    inject_tv_ad_task_now,
    abort_tv_ad_task_now,
    complete_tv_ad_display,
    abort_tv_ad_display,
    reconcile_all_active_gyms,
    startup_recover_ad_runtime,
    get_tv_player_render_context,
    load_tv_player_state,
    AD_TASK_STATE_READY, AD_TASK_STATE_DISPLAYING, AD_TASK_STATE_COMPLETED,
    AD_TASK_STATE_ABORTED, AD_TASK_STATE_SKIPPED_WINDOW,
    AD_FILE_STATE_VALID, AD_FILE_STATE_PENDING,
    GYM_COORD_IDLE, GYM_COORD_DISPLAYING,
    AD_LAYOUT_FULL_SCREEN,
)
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

# Create temp media dir and fake ad file
media_dir = pathlib.Path(_tmp) / "tv" / "media"
media_dir.mkdir(parents=True, exist_ok=True)

def make_ad_file(name="ad-001.mp4") -> str:
    p = media_dir / name
    p.write_bytes(b"FAKE_AD_CONTENT_DATA")
    return str(p)

GYM_ID = 501

# Create two bindings in this gym
b1 = create_tv_screen_binding(screen_id=2001, screen_label="gym501-screen1", gym_id=GYM_ID)
b2 = create_tv_screen_binding(screen_id=2002, screen_label="gym501-screen2", gym_id=GYM_ID)
BID1 = b1["id"]
BID2 = b2["id"]

# Create a binding in a DIFFERENT gym (should be isolated)
GYM_ID2 = 502
b3 = create_tv_screen_binding(screen_id=2003, screen_label="gym502-screen1", gym_id=GYM_ID2)
BID3 = b3["id"]

TASK_ID_1 = "task-a7-001"
TASK_ID_2 = "task-a7-002"
TASK_ID_OTHER_GYM = "task-a7-gym2"

ad_path = make_ad_file("ad-001.mp4")

# -----------------------------------------------------------------------
# Case 0: No tasks -> reconcile is a no-op
# -----------------------------------------------------------------------
print("\n[Case 0] No due tasks -- reconcile is no-op")
result = reconcile_all_active_gyms()
check("reconcile ok", bool(result.get("ok")), result)
check("injected=0 when no tasks", result.get("injected") == 0, result.get("injected"))

# -----------------------------------------------------------------------
# Case 1: Task inserted but not yet due -> no injection
# -----------------------------------------------------------------------
print("\n[Case 1] Task not yet due")
future_ts = (datetime.utcnow() + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id=TASK_ID_1,
    gym_id=GYM_ID,
    ad_media_id="adm-001",
    scheduled_at=future_ts,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=10,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
result = reconcile_all_active_gyms()
check("no injection when future task", result.get("injected") == 0, result)

# -----------------------------------------------------------------------
# Case 2: Task is due -> injection
# -----------------------------------------------------------------------
print("\n[Case 2] Task is now due -> inject")
due_ts = (datetime.utcnow() - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id=TASK_ID_1,
    gym_id=GYM_ID,
    ad_media_id="adm-001",
    scheduled_at=due_ts,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=30,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
result = reconcile_all_active_gyms()
check("injection happened", result.get("injected") == 1, result)

gym_rt = load_tv_gym_ad_runtime(gym_id=GYM_ID)
check("gym state=DISPLAYING", (gym_rt or {}).get("coordination_state") == GYM_COORD_DISPLAYING, gym_rt)
check("gym audio_override_active=1", (gym_rt or {}).get("audio_override_active") == 1, gym_rt)

task_rt = load_tv_ad_task_runtime(campaign_task_id=TASK_ID_1)
check("task runtime state=DISPLAYING", (task_rt or {}).get("local_display_state") == AD_TASK_STATE_DISPLAYING, task_rt)

# -----------------------------------------------------------------------
# Case 3: Both bindings in the gym got ad_override_active=1
# -----------------------------------------------------------------------
print("\n[Case 3] Both bindings got ad override")
ps1 = load_tv_player_state(binding_id=BID1)
ps2 = load_tv_player_state(binding_id=BID2)
check("binding1 ad_override_active=1", (ps1 or {}).get("ad_override_active") == 1, ps1)
check("binding2 ad_override_active=1", (ps2 or {}).get("ad_override_active") == 1, ps2)
check("binding1 current_ad_task_id set", (ps1 or {}).get("current_ad_task_id") == TASK_ID_1, ps1)
check("binding1 layout=FULL_SCREEN", (ps1 or {}).get("current_ad_layout") == AD_LAYOUT_FULL_SCREEN, ps1)

# -----------------------------------------------------------------------
# Case 4: render context includes ad override fields
# -----------------------------------------------------------------------
print("\n[Case 4] Render context reflects ad override")
ctx = get_tv_player_render_context(binding_id=BID1)
check("adOverrideActive=True", ctx.get("adOverrideActive") == True, ctx.get("adOverrideActive"))
check("currentAdTaskId set", ctx.get("currentAdTaskId") == TASK_ID_1, ctx.get("currentAdTaskId"))
check("adAssetPath set", ctx.get("adAssetPath") == ad_path, ctx.get("adAssetPath"))
check("adAudioOverrideActive=True", ctx.get("adAudioOverrideActive") == True, ctx.get("adAudioOverrideActive"))

# -----------------------------------------------------------------------
# Case 5: Different gym (gym502) is not affected
# -----------------------------------------------------------------------
print("\n[Case 5] Different gym is isolated")
ps3 = load_tv_player_state(binding_id=BID3)
# BID3 has no player state row yet (never reported), so it's None or has no ad override
ad_override_3 = (ps3 or {}).get("ad_override_active", 0)
check("gym502 binding not affected", ad_override_3 != 1, ad_override_3)

# -----------------------------------------------------------------------
# Case 6: Second reconcile while DISPLAYING -> no new injection
# -----------------------------------------------------------------------
print("\n[Case 6] No double-injection during DISPLAYING")
result2 = reconcile_all_active_gyms()
check("no new injection during display", result2.get("injected") == 0, result2)

# -----------------------------------------------------------------------
# Case 7: Completion via complete_tv_ad_display
# -----------------------------------------------------------------------
print("\n[Case 7] Completion clears player overrides")
complete_result = complete_tv_ad_display(campaign_task_id=TASK_ID_1)
check("complete ok", bool(complete_result.get("ok")), complete_result)

gym_rt2 = load_tv_gym_ad_runtime(gym_id=GYM_ID)
check("gym back to IDLE after complete", (gym_rt2 or {}).get("coordination_state") == GYM_COORD_IDLE, gym_rt2)
check("gym audio_override_active=0", (gym_rt2 or {}).get("audio_override_active") == 0, gym_rt2)

ps1_after = load_tv_player_state(binding_id=BID1)
check("binding1 ad_override_active=0 after complete", (ps1_after or {}).get("ad_override_active") == 0, ps1_after)
ps2_after = load_tv_player_state(binding_id=BID2)
check("binding2 ad_override_active=0 after complete", (ps2_after or {}).get("ad_override_active") == 0, ps2_after)

task_rt2 = load_tv_ad_task_runtime(campaign_task_id=TASK_ID_1)
check("task state=COMPLETED", (task_rt2 or {}).get("local_display_state") == AD_TASK_STATE_COMPLETED, task_rt2)

# -----------------------------------------------------------------------
# Case 8: Two due tasks for same gym -> deterministic single winner
# -----------------------------------------------------------------------
print("\n[Case 8] Two due tasks -> single winner (earliest scheduledAt)")
ad_path2 = make_ad_file("ad-002.mp4")
t1_ts = (datetime.utcnow() - timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ")  # earlier
t2_ts = (datetime.utcnow() - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")  # later

upsert_tv_ad_task_cache(
    campaign_task_id="task-a7-w1",
    gym_id=GYM_ID,
    ad_media_id="adm-win1",
    scheduled_at=t2_ts,  # later = should lose
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=10,
    remote_status="APPROVED",
    local_file_path=ad_path2,
    local_file_state=AD_FILE_STATE_VALID,
)
upsert_tv_ad_task_cache(
    campaign_task_id="task-a7-w0",
    gym_id=GYM_ID,
    ad_media_id="adm-win0",
    scheduled_at=t1_ts,  # earlier = should win
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=10,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
result3 = reconcile_all_active_gyms()
check("only one injected for two due tasks", result3.get("injected") == 1, result3)

gym_rt3 = load_tv_gym_ad_runtime(gym_id=GYM_ID)
# The winner should be task-a7-w0 (earliest scheduled_at)
check("winner is task with earliest scheduledAt",
      (gym_rt3 or {}).get("current_campaign_task_id") == "task-a7-w0",
      (gym_rt3 or {}).get("current_campaign_task_id"))

# Clean up winner
abort_tv_ad_display(campaign_task_id="task-a7-w0", reason="TEST_CLEANUP")
# Push the loser's scheduled_at past the grace window so Case 9/10 reconcile won't inject it
old_ts_w1 = (datetime.utcnow() - timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id="task-a7-w1",
    gym_id=GYM_ID,
    ad_media_id="adm-win1",
    scheduled_at=old_ts_w1,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=10,
    remote_status="APPROVED",
    local_file_path=ad_path2,
    local_file_state=AD_FILE_STATE_VALID,
)

# -----------------------------------------------------------------------
# Case 9: Task past grace window -> SKIPPED_WINDOW_MISSED
# -----------------------------------------------------------------------
print("\n[Case 9] Overdue task past grace window -> SKIPPED_WINDOW_MISSED")
TASK_OVERDUE = "task-a7-overdue"
overdue_ts = (datetime.utcnow() - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id=TASK_OVERDUE,
    gym_id=GYM_ID,
    ad_media_id="adm-old",
    scheduled_at=overdue_ts,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=10,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
result4 = reconcile_all_active_gyms()
check("overdue task skipped", result4.get("skipped", 0) >= 1, result4)

overdue_rt = load_tv_ad_task_runtime(campaign_task_id=TASK_OVERDUE)
check("overdue task state=SKIPPED_WINDOW_MISSED",
      (overdue_rt or {}).get("local_display_state") == AD_TASK_STATE_SKIPPED_WINDOW,
      overdue_rt)

# -----------------------------------------------------------------------
# Case 10: Abort clears player overrides
# -----------------------------------------------------------------------
print("\n[Case 10] Abort clears player overrides")
TASK_ABORT = "task-a7-abort"
abort_ts = (datetime.utcnow() - timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id=TASK_ABORT,
    gym_id=GYM_ID,
    ad_media_id="adm-abort",
    scheduled_at=abort_ts,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=60,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
reconcile_all_active_gyms()
# Verify it's displaying
gym_before_abort = load_tv_gym_ad_runtime(gym_id=GYM_ID)
check("task is displaying before abort", (gym_before_abort or {}).get("coordination_state") == GYM_COORD_DISPLAYING, gym_before_abort)

abort_result = abort_tv_ad_display(campaign_task_id=TASK_ABORT, reason="TEST_ABORT", message="Manual test abort")
check("abort ok", bool(abort_result.get("ok")), abort_result)

gym_after_abort = load_tv_gym_ad_runtime(gym_id=GYM_ID)
check("gym back to IDLE after abort", (gym_after_abort or {}).get("coordination_state") == GYM_COORD_IDLE, gym_after_abort)

ps1_abort = load_tv_player_state(binding_id=BID1)
check("binding1 ad_override=0 after abort", (ps1_abort or {}).get("ad_override_active") == 0, ps1_abort)

abort_rt = load_tv_ad_task_runtime(campaign_task_id=TASK_ABORT)
check("task state=ABORTED", (abort_rt or {}).get("local_display_state") == AD_TASK_STATE_ABORTED, abort_rt)
check("abort_reason set", (abort_rt or {}).get("display_abort_reason") == "TEST_ABORT", abort_rt)

# -----------------------------------------------------------------------
# Case 11: startup_recover_ad_runtime resets stuck DISPLAYING state
# -----------------------------------------------------------------------
print("\n[Case 11] startup_recover_ad_runtime resets stuck DISPLAYING")
TASK_STUCK = "task-a7-stuck"
stuck_ts = (datetime.utcnow() - timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
upsert_tv_ad_task_cache(
    campaign_task_id=TASK_STUCK,
    gym_id=GYM_ID,
    ad_media_id="adm-stuck",
    scheduled_at=stuck_ts,
    layout=AD_LAYOUT_FULL_SCREEN,
    display_duration_sec=60,
    remote_status="APPROVED",
    local_file_path=ad_path,
    local_file_state=AD_FILE_STATE_VALID,
)
reconcile_all_active_gyms()
# Verify it's stuck in DISPLAYING
gym_stuck = load_tv_gym_ad_runtime(gym_id=GYM_ID)
check("gym is DISPLAYING (stuck)", (gym_stuck or {}).get("coordination_state") == GYM_COORD_DISPLAYING, gym_stuck)

recover_result = startup_recover_ad_runtime()
check("recovery ok", bool(recover_result.get("ok")), recover_result)
check("recovered >= 1", recover_result.get("recovered", 0) >= 1, recover_result)

gym_recovered = load_tv_gym_ad_runtime(gym_id=GYM_ID)
check("gym back to IDLE after recovery", (gym_recovered or {}).get("coordination_state") == GYM_COORD_IDLE, gym_recovered)
ps1_recovered = load_tv_player_state(binding_id=BID1)
check("binding1 ad_override=0 after recovery", (ps1_recovered or {}).get("ad_override_active") == 0, ps1_recovered)

# -----------------------------------------------------------------------
# Case 12: list_tv_ad_task_cache and list_tv_ad_task_runtime
# -----------------------------------------------------------------------
print("\n[Case 12] List functions")
tasks = list_tv_ad_task_cache(gym_id=GYM_ID)
check("list tasks returns dict", isinstance(tasks, dict) and "rows" in tasks, type(tasks))
check("list tasks has rows", tasks.get("total", 0) > 0, tasks.get("total"))

runtimes = list_tv_ad_task_runtime(gym_id=GYM_ID)
check("list runtime returns dict", isinstance(runtimes, dict) and "rows" in runtimes, type(runtimes))
check("list runtime has rows", runtimes.get("total", 0) > 0, runtimes.get("total"))

# -----------------------------------------------------------------------
print(f"\n=== A7 Results: {PASS} passed, {FAIL} failed ===")
shutil.rmtree(_tmp, ignore_errors=True)
sys.exit(0 if FAIL == 0 else 1)
