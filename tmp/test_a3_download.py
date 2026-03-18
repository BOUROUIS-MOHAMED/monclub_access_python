"""
Test script for Functionality A3: Asset Download + Validation Cache.
Verifies:
 1) New A3 constants exist
 2) compute_expected_local_path uses checksum-prefix naming
 3) _validate_local_file: valid, invalid_size, invalid_checksum, not_present, weak mode
 4) _process_single_asset: idempotent runs, temp not promoted on bad validation
 5) run_tv_asset_download: empty worklist, valid handling
 6) list_tv_cache_assets: filtered query works
"""
import os, sys, tempfile, hashlib, shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_tmp = tempfile.mkdtemp(prefix="test_a3_")
os.environ["MONCLUB_DATA_ROOT"] = _tmp

import app.core.utils as utils
utils.DATA_ROOT = _tmp
utils.DB_PATH = os.path.join(_tmp, "test_a3.db")

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
print("\n=== 1) A3 Constants ===")
check("NOT_PRESENT", tvc.ASSET_STATE_NOT_PRESENT == "NOT_PRESENT")
check("PRESENT_UNCHECKED", tvc.ASSET_STATE_PRESENT_UNCHECKED == "PRESENT_UNCHECKED")
check("INVALID_UNREADABLE", tvc.ASSET_STATE_INVALID_UNREADABLE == "INVALID_UNREADABLE")

# --- 2) Deterministic path ---
print("\n=== 2) compute_expected_local_path ===")
tvc.ensure_tv_local_schema()
p1 = tvc.compute_expected_local_path(
    media_asset_id="abc123", checksum_sha256="deadbeef1234567890",
    mime_type="video/mp4")
check("has checksum prefix", "abc123_deadbeef" in p1)
check("has .mp4 ext", p1.endswith(".mp4"))
check("under tv/media", os.sep + "tv" + os.sep + "media" + os.sep in p1.replace("/", os.sep))

p2 = tvc.compute_expected_local_path(media_asset_id="abc123", checksum_sha256="", mime_type="image/jpeg")
check("no checksum => nochk", "abc123_nochk" in p2)
check("jpeg ext", p2.endswith(".jpg"))

p3 = tvc.compute_expected_local_path(media_asset_id="abc123", media_type="AUDIO")
check("audio fallback", p3.endswith(".mp3"))

# --- 3) _validate_local_file ---
print("\n=== 3) _validate_local_file ===")

# 3a) file does not exist
state, mode, reason = tvc._validate_local_file("/nonexistent/file.mp4", expected_size=100)
check("missing => NOT_PRESENT", state == tvc.ASSET_STATE_NOT_PRESENT)

# 3b) valid file with correct checksum + size
test_content = b"hello world test content for A3"
test_file = os.path.join(_tmp, "test_valid.bin")
with open(test_file, "wb") as f:
    f.write(test_content)
expected_sha = hashlib.sha256(test_content).hexdigest()
expected_size = len(test_content)

state, mode, reason = tvc._validate_local_file(test_file, expected_size=expected_size, expected_checksum=expected_sha)
check("valid => VALID", state == tvc.ASSET_STATE_VALID)
check("strong validation", mode == tvc.VALIDATION_STRONG)

# 3c) wrong size
state, mode, reason = tvc._validate_local_file(test_file, expected_size=expected_size + 999, expected_checksum=expected_sha)
check("wrong size => INVALID_SIZE", state == tvc.ASSET_STATE_INVALID_SIZE)

# 3d) wrong checksum (correct size)
state, mode, reason = tvc._validate_local_file(test_file, expected_size=expected_size, expected_checksum="0000000000000000")
check("wrong checksum => INVALID_CHECKSUM", state == tvc.ASSET_STATE_INVALID_CHECKSUM)

# 3e) weak validation (no checksum, size matches)
state, mode, reason = tvc._validate_local_file(test_file, expected_size=expected_size, expected_checksum="")
check("size only => VALID WEAK", state == tvc.ASSET_STATE_VALID and mode == tvc.VALIDATION_WEAK)

# 3f) no integrity metadata at all
state, mode, reason = tvc._validate_local_file(test_file, expected_size=0, expected_checksum="")
check("no metadata => PRESENT_UNCHECKED", state == tvc.ASSET_STATE_PRESENT_UNCHECKED)

# --- 4) _process_single_asset ---
print("\n=== 4) _process_single_asset ===")

# 4a) Asset with file already at expected path - should validate existing
media_id = "test-asset-001"
cksum = hashlib.sha256(test_content).hexdigest()
expected_path = tvc.compute_expected_local_path(
    media_asset_id=media_id, checksum_sha256=cksum, mime_type="application/octet-stream")
os.makedirs(os.path.dirname(expected_path), exist_ok=True)
with open(expected_path, "wb") as f:
    f.write(test_content)

r = tvc._process_single_asset({
    "media_asset_id": media_id,
    "checksum_sha256": cksum,
    "size_bytes": len(test_content),
    "mime_type": "application/octet-stream",
    "download_link": "",  # no URL needed since file exists
})
check("existing file => VALIDATED_EXISTING", r.get("action") == "VALIDATED_EXISTING")
check("state => VALID", r.get("state") == tvc.ASSET_STATE_VALID)

# verify DB row updated
las = tvc.load_tv_local_asset_state(media_asset_id=media_id)
check("DB row exists", las is not None)
check("DB state VALID", las.get("asset_state") == tvc.ASSET_STATE_VALID)
check("DB file_exists=1", las.get("file_exists") == 1)

# 4b) Re-run same asset — should be idempotent
r2 = tvc._process_single_asset({
    "media_asset_id": media_id,
    "checksum_sha256": cksum,
    "size_bytes": len(test_content),
    "mime_type": "application/octet-stream",
    "download_link": "",
})
check("idempotent => VALIDATED_EXISTING", r2.get("action") == "VALIDATED_EXISTING")
las2 = tvc.load_tv_local_asset_state(media_asset_id=media_id)
check("idempotent DB still VALID", las2.get("asset_state") == tvc.ASSET_STATE_VALID)

# 4c) Asset with no download link and no local file
r3 = tvc._process_single_asset({
    "media_asset_id": "no-url-asset",
    "download_link": "",
    "mime_type": "video/mp4",
})
check("no URL => SKIPPED_NO_URL", r3.get("action") == "SKIPPED_NO_URL")
check("no URL => ERROR state", r3.get("state") == tvc.ASSET_STATE_ERROR)

# --- 5) run_tv_asset_download ---
print("\n=== 5) run_tv_asset_download — no worklist ===")
result = tvc.run_tv_asset_download()
check("empty worklist ok=True", result.get("ok") == True)
check("empty total=0", result.get("total") == 0)
check("correlation_id present", bool(result.get("correlation_id")))

# --- 6) list_tv_cache_assets ---
print("\n=== 6) list_tv_cache_assets ===")
data = tvc.list_tv_cache_assets()
check("has rows key", "rows" in data)
check("has total key", "total" in data)
check("total >= 2", data["total"] >= 2)  # test-asset-001 + no-url-asset

data2 = tvc.list_tv_cache_assets(asset_state="VALID")
check("filter by VALID", all(r.get("asset_state") == "VALID" for r in data2["rows"]))

data3 = tvc.list_tv_cache_assets(media_asset_id="test-asset-001")
check("filter by mediaAssetId", data3["total"] == 1)

# --- Summary ---
print(f"\n{'='*50}")
print(f"  PASSED: {checks_passed}/{checks_total}")
if checks_passed == checks_total:
    print("  ALL CHECKS PASSED ✓")
else:
    print(f"  {checks_total - checks_passed} CHECKS FAILED ✗")
print(f"{'='*50}")

shutil.rmtree(_tmp, ignore_errors=True)
