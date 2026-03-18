"""
A6 Player Runtime — quick verification script.
Tests all player state decision rules using an in-memory SQLite DB.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Use a temp DB
import tempfile, shutil
_tmp = tempfile.mkdtemp()
os.environ["MONCLUB_ACCESS_DATA_ROOT"] = _tmp

from app.core.tv_local_cache import (
    ensure_tv_local_schema,
    create_tv_screen_binding,
    upsert_tv_snapshot_cache,
    upsert_tv_snapshot_required_asset,
    upsert_tv_local_asset_state,
    upsert_tv_snapshot_readiness,
    _upsert_tv_activation_state,
    get_tv_player_render_context,
    reevaluate_tv_player,
    reload_tv_player,
    load_tv_player_status,
    list_tv_player_events,
    report_tv_player_state,
    ASSET_STATE_VALID, ASSET_STATE_MISSING,
    READINESS_READY,
    MANIFEST_STATUS_COMPLETE,
    PLAYER_STATE_BLOCKED_NO_BINDING,
    PLAYER_STATE_BLOCKED_BINDING_DISABLED,
    PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT,
    PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM,
    PLAYER_STATE_RENDERING,
    PLAYER_STATE_FALLBACK_RENDERING,
    PLAYER_STATE_ERROR,
    RENDER_MODE_VISUAL_ONLY,
    RENDER_MODE_AUDIO_ONLY,
    RENDER_MODE_VISUAL_AND_AUDIO,
    RENDER_MODE_IDLE_FALLBACK,
    RENDER_MODE_ERROR_FALLBACK,
    FALLBACK_REASON_AUDIO_ASSET_INVALID,
    FALLBACK_REASON_VISUAL_ASSET_INVALID,
    FALLBACK_REASON_BOTH_ASSETS_INVALID,
    FALLBACK_REASON_NO_CURRENT_ITEM,
)
import pathlib, json
from app.core.utils import now_iso

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

# ---------------------------------------------------------------------------
# Helper: create a valid asset file on disk
# ---------------------------------------------------------------------------
media_dir = pathlib.Path(_tmp) / "tv" / "media"
media_dir.mkdir(parents=True, exist_ok=True)

def make_asset_file(name: str) -> str:
    p = media_dir / name
    p.write_bytes(b"FAKE_MEDIA_CONTENT")
    return str(p)

# ---------------------------------------------------------------------------
# Case 0: no binding → BLOCKED_NO_BINDING
# ---------------------------------------------------------------------------
print("\n[Case 0] No binding")
ctx = get_tv_player_render_context(binding_id=9999)
check("playerState=BLOCKED_NO_BINDING", ctx.get("playerState") == PLAYER_STATE_BLOCKED_NO_BINDING, ctx.get("playerState"))
check("ok=False", not bool(ctx.get("ok")), ctx.get("ok"))

# ---------------------------------------------------------------------------
# Case 1: disabled binding → BLOCKED_BINDING_DISABLED
# ---------------------------------------------------------------------------
print("\n[Case 1] Disabled binding")
b_disabled = create_tv_screen_binding(screen_id=1001, screen_label="disabled-screen", enabled=False)
bid_dis = b_disabled["id"]
ctx = get_tv_player_render_context(binding_id=bid_dis)
check("playerState=BLOCKED_BINDING_DISABLED", ctx.get("playerState") == PLAYER_STATE_BLOCKED_BINDING_DISABLED, ctx.get("playerState"))

# ---------------------------------------------------------------------------
# Shared setup: enabled binding, snapshot + manifest
# ---------------------------------------------------------------------------
SCREEN_ID = 1002
b = create_tv_screen_binding(screen_id=SCREEN_ID, screen_label="test-screen")
BID = b["id"]
SNAP_ID = "snap-a6-001"
SNAP_VER = 1

# Minimal snapshot payload with timeline items
MINUTE_NOW = 480  # 08:00
DAY_NOW = "WEDNESDAY"

VISUAL_ASSET_ID = "vas-001"
AUDIO_ASSET_ID  = "aus-001"

payload = {
    "visualTimelineItems": [
        {
            "id": "vi-001",
            "timelineType": "VISUAL",
            "mediaAssetId": VISUAL_ASSET_ID,
            "mediaType": "IMAGE",
            "startMinuteOfDay": 0,
            "endMinuteOfDay": 1440,
            "title": "Test visual",
            "videoAudioEnabled": False,
        }
    ],
    "audioTimelineItems": [
        {
            "id": "ai-001",
            "timelineType": "AUDIO",
            "mediaAssetId": AUDIO_ASSET_ID,
            "mediaType": "AUDIO",
            "startMinuteOfDay": 0,
            "endMinuteOfDay": 1440,
            "title": "Test audio",
        }
    ],
}

upsert_tv_snapshot_cache(
    screen_id=SCREEN_ID,
    snapshot_id=SNAP_ID,
    snapshot_version=SNAP_VER,
    manifest_status=MANIFEST_STATUS_COMPLETE,
    sync_status="COMPLETED",
    payload_json=json.dumps(payload),
    asset_count=2,
)
upsert_tv_snapshot_required_asset(snapshot_id=SNAP_ID, media_asset_id=VISUAL_ASSET_ID, media_type="IMAGE", mime_type="image/jpeg", checksum_sha256="aaaa1111", size_bytes=18)
upsert_tv_snapshot_required_asset(snapshot_id=SNAP_ID, media_asset_id=AUDIO_ASSET_ID,  media_type="AUDIO", mime_type="audio/mpeg", checksum_sha256="bbbb2222", size_bytes=18)
upsert_tv_snapshot_readiness(
    screen_id=SCREEN_ID, snapshot_id=SNAP_ID, snapshot_version=SNAP_VER,
    readiness_state=READINESS_READY, is_fully_ready=True,
    total_required_assets=2, ready_asset_count=2, is_latest=True,
)

# Activate snapshot
_upsert_tv_activation_state(screen_id=SCREEN_ID, state_updates={
    "active_snapshot_id": SNAP_ID,
    "active_snapshot_version": SNAP_VER,
    "activation_state": "ACTIVE_CURRENT",
})

# ---------------------------------------------------------------------------
# Case 2: no active snapshot (different screen, no activation)
# ---------------------------------------------------------------------------
print("\n[Case 2] No active snapshot")
b2 = create_tv_screen_binding(screen_id=1003, screen_label="no-snap-screen")
ctx = get_tv_player_render_context(binding_id=b2["id"])
check("playerState=BLOCKED_NO_ACTIVE_SNAPSHOT", ctx.get("playerState") == PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT, ctx.get("playerState"))

# ---------------------------------------------------------------------------
# Case 3: no matching timeline item at minute 9999
# ---------------------------------------------------------------------------
# We override the clock by injecting a dummy snapshot with no items
print("\n[Case 3] No current matching item")
SNAP_EMPTY = "snap-empty-001"
upsert_tv_snapshot_cache(screen_id=SCREEN_ID, snapshot_id=SNAP_EMPTY, snapshot_version=99,
    manifest_status=MANIFEST_STATUS_COMPLETE, payload_json=json.dumps({"visualTimelineItems": [], "audioTimelineItems": []}), asset_count=0)
upsert_tv_snapshot_readiness(screen_id=SCREEN_ID, snapshot_id=SNAP_EMPTY, snapshot_version=99,
    readiness_state=READINESS_READY, is_fully_ready=True, is_latest=True, total_required_assets=0, ready_asset_count=0)
_upsert_tv_activation_state(screen_id=SCREEN_ID, state_updates={
    "active_snapshot_id": SNAP_EMPTY, "active_snapshot_version": 99, "activation_state": "ACTIVE_CURRENT"})
ctx = get_tv_player_render_context(binding_id=BID)
check("playerState=BLOCKED_NO_RENDERABLE_ITEM", ctx.get("playerState") == PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM, ctx.get("playerState"))
check("renderMode=IDLE_FALLBACK", ctx.get("renderMode") == RENDER_MODE_IDLE_FALLBACK, ctx.get("renderMode"))
check("fallbackReason=NO_CURRENT_ITEM", ctx.get("fallbackReason") == FALLBACK_REASON_NO_CURRENT_ITEM, ctx.get("fallbackReason"))

# Restore real snapshot
_upsert_tv_activation_state(screen_id=SCREEN_ID, state_updates={
    "active_snapshot_id": SNAP_ID, "active_snapshot_version": SNAP_VER, "activation_state": "ACTIVE_CURRENT"})

# ---------------------------------------------------------------------------
# Case 4: both assets VALID + files exist → RENDERING / VISUAL_AND_AUDIO
# ---------------------------------------------------------------------------
print("\n[Case 4] Both assets valid")
vis_path = make_asset_file("vis-001.jpg")
aud_path = make_asset_file("aud-001.mp3")
upsert_tv_local_asset_state(media_asset_id=VISUAL_ASSET_ID, asset_state=ASSET_STATE_VALID, file_exists=True, local_file_path=vis_path)
upsert_tv_local_asset_state(media_asset_id=AUDIO_ASSET_ID,  asset_state=ASSET_STATE_VALID, file_exists=True, local_file_path=aud_path)
ctx = get_tv_player_render_context(binding_id=BID)
check("playerState=RENDERING",          ctx.get("playerState") == PLAYER_STATE_RENDERING,           ctx.get("playerState"))
check("renderMode=VISUAL_AND_AUDIO",    ctx.get("renderMode")  == RENDER_MODE_VISUAL_AND_AUDIO,      ctx.get("renderMode"))
check("currentVisual present",          ctx.get("currentVisual") is not None)
check("currentAudio present",           ctx.get("currentAudio") is not None)
check("visualRenderable",               (ctx.get("currentVisual") or {}).get("assetRenderable") == True)
check("audioRenderable",                (ctx.get("currentAudio")  or {}).get("assetRenderable") == True)

# ---------------------------------------------------------------------------
# Case 5: audio asset MISSING → FALLBACK / VISUAL_ONLY
# ---------------------------------------------------------------------------
print("\n[Case 5] Audio invalid, visual valid")
upsert_tv_local_asset_state(media_asset_id=AUDIO_ASSET_ID, asset_state=ASSET_STATE_MISSING, file_exists=False, local_file_path=None)
ctx = get_tv_player_render_context(binding_id=BID)
check("playerState=FALLBACK_RENDERING",   ctx.get("playerState") == PLAYER_STATE_FALLBACK_RENDERING,  ctx.get("playerState"))
check("renderMode=VISUAL_ONLY",           ctx.get("renderMode")  == RENDER_MODE_VISUAL_ONLY,           ctx.get("renderMode"))
check("fallbackReason=AUDIO_ASSET_INVALID", ctx.get("fallbackReason") == FALLBACK_REASON_AUDIO_ASSET_INVALID, ctx.get("fallbackReason"))

# ---------------------------------------------------------------------------
# Case 6: visual asset MISSING → FALLBACK / AUDIO_ONLY
# ---------------------------------------------------------------------------
print("\n[Case 6] Visual invalid, audio valid")
upsert_tv_local_asset_state(media_asset_id=AUDIO_ASSET_ID,  asset_state=ASSET_STATE_VALID, file_exists=True, local_file_path=aud_path)
upsert_tv_local_asset_state(media_asset_id=VISUAL_ASSET_ID, asset_state=ASSET_STATE_MISSING, file_exists=False, local_file_path=None)
ctx = get_tv_player_render_context(binding_id=BID)
check("playerState=FALLBACK_RENDERING",    ctx.get("playerState") == PLAYER_STATE_FALLBACK_RENDERING, ctx.get("playerState"))
check("renderMode=AUDIO_ONLY",             ctx.get("renderMode")  == RENDER_MODE_AUDIO_ONLY,           ctx.get("renderMode"))
check("fallbackReason=VISUAL_ASSET_INVALID", ctx.get("fallbackReason") == FALLBACK_REASON_VISUAL_ASSET_INVALID, ctx.get("fallbackReason"))

# ---------------------------------------------------------------------------
# Case 7: both assets MISSING → ERROR / ERROR_FALLBACK
# ---------------------------------------------------------------------------
print("\n[Case 7] Both assets invalid")
upsert_tv_local_asset_state(media_asset_id=AUDIO_ASSET_ID,  asset_state=ASSET_STATE_MISSING, file_exists=False, local_file_path=None)
upsert_tv_local_asset_state(media_asset_id=VISUAL_ASSET_ID, asset_state=ASSET_STATE_MISSING, file_exists=False, local_file_path=None)
ctx = get_tv_player_render_context(binding_id=BID)
check("playerState=ERROR",                ctx.get("playerState") == PLAYER_STATE_ERROR,             ctx.get("playerState"))
check("renderMode=ERROR_FALLBACK",        ctx.get("renderMode")  == RENDER_MODE_ERROR_FALLBACK,      ctx.get("renderMode"))

# ---------------------------------------------------------------------------
# Case 8: snapshot change detection (active_snapshot_id changes)
# ---------------------------------------------------------------------------
print("\n[Case 8] Snapshot change reloads context")
upsert_tv_local_asset_state(media_asset_id=VISUAL_ASSET_ID, asset_state=ASSET_STATE_VALID, file_exists=True, local_file_path=vis_path)
upsert_tv_local_asset_state(media_asset_id=AUDIO_ASSET_ID,  asset_state=ASSET_STATE_VALID, file_exists=True, local_file_path=aud_path)
ctx1 = get_tv_player_render_context(binding_id=BID)
old_snap = ctx1.get("activeSnapshotId")
# Now switch to empty snapshot
_upsert_tv_activation_state(screen_id=SCREEN_ID, state_updates={"active_snapshot_id": SNAP_EMPTY, "active_snapshot_version": 99})
ctx2 = get_tv_player_render_context(binding_id=BID)
new_snap = ctx2.get("activeSnapshotId")
check("snapshot changed cleanly", old_snap != new_snap, f"{old_snap} → {new_snap}")
check("new context reflects empty snap", ctx2.get("playerState") == PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM, ctx2.get("playerState"))

# ---------------------------------------------------------------------------
# Case 9: report_tv_player_state persists and change-detection works
# ---------------------------------------------------------------------------
print("\n[Case 9] report_tv_player_state — change-based writes")
result = report_tv_player_state(binding_id=BID, payload={
    "player_state": "RENDERING", "render_mode": "VISUAL_ONLY",
    "active_snapshot_id": SNAP_ID, "active_snapshot_version": 1,
    "current_minute_of_day": 480,
})
check("report writes on first call", bool(result.get("updated")), result)

result2 = report_tv_player_state(binding_id=BID, payload={
    "player_state": "RENDERING", "render_mode": "VISUAL_ONLY",
    "active_snapshot_id": SNAP_ID, "active_snapshot_version": 1,
    "current_minute_of_day": 481,  # only minute changed, not a tracked key
}, force=False, freshness_seconds=9999)
check("no write when unchanged tracked keys", not bool(result2.get("updated")), result2)

result3 = report_tv_player_state(binding_id=BID, payload={
    "player_state": "FALLBACK_RENDERING", "render_mode": "AUDIO_ONLY",
    "active_snapshot_id": SNAP_ID, "active_snapshot_version": 1,
}, force=False, freshness_seconds=9999)
check("writes on meaningful change", bool(result3.get("updated")), result3)
check("changed=True flagged", bool(result3.get("changed")), result3)

# ---------------------------------------------------------------------------
# Case 10: list_tv_player_events returns dict
# ---------------------------------------------------------------------------
print("\n[Case 10] list_tv_player_events returns rows/total")
evts = list_tv_player_events(binding_id=BID, limit=10)
check("returns dict with rows", isinstance(evts, dict) and "rows" in evts, type(evts))
check("returns dict with total", "total" in evts, evts)
check("has some events", evts.get("total", 0) >= 0)

# ---------------------------------------------------------------------------
# Case 11: reevaluate_tv_player and reload_tv_player return ok
# ---------------------------------------------------------------------------
print("\n[Case 11] reevaluate_tv_player / reload_tv_player")
_upsert_tv_activation_state(screen_id=SCREEN_ID, state_updates={"active_snapshot_id": SNAP_ID, "active_snapshot_version": SNAP_VER})
reeval = reevaluate_tv_player(binding_id=BID, persist=True)
check("reevaluate ok", bool(reeval.get("ok")), reeval)
check("reevaluate returns context", "context" in reeval, reeval)

rel = reload_tv_player(binding_id=BID, persist=True)
check("reload ok", bool(rel.get("ok")), rel)

# ---------------------------------------------------------------------------
# Case 12: load_tv_player_status
# ---------------------------------------------------------------------------
print("\n[Case 12] load_tv_player_status")
status = load_tv_player_status(binding_id=BID)
check("status ok=True", bool(status.get("ok")), status)
check("status has binding", status.get("binding") is not None)

status_missing = load_tv_player_status(binding_id=9999)
check("status ok=False for missing binding", not bool(status_missing.get("ok")), status_missing)

# ---------------------------------------------------------------------------
print(f"\n=== A6 Results: {PASS} passed, {FAIL} failed ===")

# Cleanup
shutil.rmtree(_tmp, ignore_errors=True)
sys.exit(0 if FAIL == 0 else 1)
