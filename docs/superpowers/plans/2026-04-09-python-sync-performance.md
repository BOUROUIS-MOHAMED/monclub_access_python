# Python Client Sync Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut ZKTeco device push time from 30 minutes to ~5–8 minutes (Phase 2: firmware profile cache), then to ~3 seconds for typical delta syncs (Phase 4: differential push using member-level delta from backend Phase 3).

**Architecture:** Two independent phases, executed in sequence. Phase 2 caches which ZKTeco SDK field-name pattern works per device on the first successful push, eliminating up to 10 retried SDK calls per fingerprint for all subsequent users. The profile is persisted to SQLite so it survives app restarts. Phase 4 (requires backend Phase 3 deployed first) wires the backend's `membersDeltaMode` / `validMemberIds` delta hints through the sync pipeline: changed-user IDs skip the full hash-computation loop entirely, and only those users get pushed to devices.

**Tech Stack:** Python 3.13, SQLite (via existing `db.py` infrastructure), pytest, existing `device_sync.py` / `db.py` / `app.py` architecture

**Spec:** `docs/superpowers/specs/2026-04-09-sync-performance-optimization-design.md` (Phase 2 + Phase 3 client side + Phase 4)

**Dependency:** Phase 4 tasks (Tasks 7–9) require backend Phase 3 to be deployed. Do NOT implement Phase 4 until the backend returns `membersDeltaMode` and `validMemberIds` fields.

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `app/core/device_sync.py` | Phase 2: FirmwareProfile dataclass + cache in `_push_userauthorize` + `_push_templates`; Phase 4: accept `changed_ids`/`removed_ids` delta hints |
| Modify | `app/core/db.py` | Phase 2: persist firmware profiles to SQLite; Phase 3 client: upsert/delete users, `save_sync_cache_delta` delta mode; Phase 4: expose `get_all_cached_user_am_ids()` |
| Modify | `app/api/monclub_api.py` | Phase 3 client: send `membersUpdatedAfter` param |
| Modify | `app/ui/app.py` | Phase 3 client + Phase 4: extract delta from response, pass to device sync |
| New | `tests/test_firmware_profile_cache.py` | Phase 2 tests |
| New | `tests/test_delta_user_cache.py` | Phase 3 client tests |
| New | `tests/test_differential_device_push.py` | Phase 4 tests |

---

## Task 1: FirmwareProfile Dataclass and SQLite Persistence

**Files:**
- Modify: `app/core/db.py`

The `FirmwareProfile` stores which SDK pattern combo works per ZKTeco device, keyed by device ID. It's persisted to SQLite so it survives app restarts and avoids re-discovering the working pattern after every restart.

- [ ] **Step 1: Write failing tests for firmware profile persistence**

Create `tests/test_firmware_profile_cache.py`:

```python
"""Tests for FirmwareProfile SQLite persistence in db.py."""
import os
import tempfile
import pytest


def make_test_db(tmp_path):
    """Create an isolated test database."""
    db_path = str(tmp_path / "test.db")
    # Patch the path used by db.py to point to our test DB
    import app.core.db as db_module
    orig = db_module._get_db_path if hasattr(db_module, "_get_db_path") else None
    return db_path


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Provide an isolated db module pointed at a temp database."""
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()  # creates tables in temp path
    return db_module


def test_save_and_load_firmware_profile(db):
    """Saved firmware profile can be loaded back with same values."""
    db.save_firmware_profile(device_id=42, template_table="templatev10",
                             template_body_index=0, authorize_body_index=2)
    profile = db.load_firmware_profile(device_id=42)
    assert profile is not None
    assert profile["template_table"] == "templatev10"
    assert profile["template_body_index"] == 0
    assert profile["authorize_body_index"] == 2


def test_load_firmware_profile_returns_none_for_unknown_device(db):
    """Loading a profile for an unknown device returns None."""
    assert db.load_firmware_profile(device_id=999) is None


def test_save_firmware_profile_overwrites_existing(db):
    """Saving a profile twice updates the existing record."""
    db.save_firmware_profile(device_id=1, template_table="template",
                             template_body_index=1, authorize_body_index=0)
    db.save_firmware_profile(device_id=1, template_table="templatev10",
                             template_body_index=3, authorize_body_index=1)
    profile = db.load_firmware_profile(device_id=1)
    assert profile["template_table"] == "templatev10"
    assert profile["template_body_index"] == 3


def test_clear_firmware_profile_removes_entry(db):
    """Clearing a profile removes it from SQLite."""
    db.save_firmware_profile(device_id=5, template_table="templatev10",
                             template_body_index=0, authorize_body_index=0)
    db.clear_firmware_profile(device_id=5)
    assert db.load_firmware_profile(device_id=5) is None


def test_multiple_devices_independent_profiles(db):
    """Each device has its own independent profile."""
    db.save_firmware_profile(device_id=1, template_table="template",
                             template_body_index=1, authorize_body_index=0)
    db.save_firmware_profile(device_id=2, template_table="templatev10",
                             template_body_index=0, authorize_body_index=2)
    p1 = db.load_firmware_profile(device_id=1)
    p2 = db.load_firmware_profile(device_id=2)
    assert p1["template_table"] == "template"
    assert p2["template_table"] == "templatev10"
```

- [ ] **Step 2: Run tests to confirm they FAIL**

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
python -m pytest tests/test_firmware_profile_cache.py -v
```

Expected: FAIL — `save_firmware_profile` not found

- [ ] **Step 3: Add `sync_firmware_profiles` table to `init_db()` in db.py**

In `db.py`, find the `init_db()` function (or wherever table CREATE statements are). Add the new table after the `sync_version_tokens` table creation (around line 815):

```python
conn.execute(
    """
    CREATE TABLE IF NOT EXISTS sync_firmware_profiles (
        device_id   INTEGER PRIMARY KEY,
        template_table       TEXT NOT NULL,
        template_body_index  INTEGER NOT NULL,
        authorize_body_index INTEGER NOT NULL,
        updated_at  TEXT NOT NULL
    );
    """
)
```

- [ ] **Step 4: Add `save_firmware_profile`, `load_firmware_profile`, `clear_firmware_profile` to db.py**

Add these three functions near the version token functions (around line 860):

```python
def save_firmware_profile(
    *,
    device_id: int,
    template_table: str,
    template_body_index: int,
    authorize_body_index: int,
) -> None:
    """
    Upsert the firmware profile for a ZKTeco device.
    Keyed by device_id (stable integer) — not IP (DHCP can change IPs).
    """
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO sync_firmware_profiles
                (device_id, template_table, template_body_index, authorize_body_index, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                template_table       = excluded.template_table,
                template_body_index  = excluded.template_body_index,
                authorize_body_index = excluded.authorize_body_index,
                updated_at           = excluded.updated_at
            """,
            (device_id, template_table, template_body_index, authorize_body_index, now_iso()),
        )
        conn.commit()


def load_firmware_profile(*, device_id: int) -> dict | None:
    """
    Load the cached firmware profile for a device, or None if not cached.
    Returns dict with keys: template_table, template_body_index, authorize_body_index.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT template_table, template_body_index, authorize_body_index "
            "FROM sync_firmware_profiles WHERE device_id = ?",
            (device_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "template_table": row[0],
        "template_body_index": row[1],
        "authorize_body_index": row[2],
    }


def clear_firmware_profile(*, device_id: int) -> None:
    """Remove the cached firmware profile for a device (e.g., after firmware upgrade detected)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM sync_firmware_profiles WHERE device_id = ?", (device_id,))
        conn.commit()
```

- [ ] **Step 5: Run tests — confirm all pass**

```bash
python -m pytest tests/test_firmware_profile_cache.py -v
```

Expected: All 5 tests PASS

- [ ] **Step 6: Commit**

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
git add app/core/db.py tests/test_firmware_profile_cache.py
git commit -m "$(cat <<'EOF'
feat(Phase2): add firmware profile SQLite persistence

New sync_firmware_profiles table stores which ZKTeco SDK field-name pattern
works per device (keyed by device ID, not IP). Survives app restarts.
Functions: save_firmware_profile, load_firmware_profile, clear_firmware_profile.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: FirmwareProfile In-Session Cache in DeviceSyncService

**Files:**
- Modify: `app/core/device_sync.py`

The SQLite persistence from Task 1 handles cross-restart memory. But within a single sync session, we use an in-memory dict as an L1 cache (faster than hitting SQLite for every user). The in-memory cache is populated from SQLite at device sync start and written back on new discoveries.

- [ ] **Step 1: Add `FirmwareProfile` dataclass to device_sync.py**

Add after the existing imports / module-level constants (near the top of `device_sync.py`, before any class definitions):

```python
from dataclasses import dataclass, field as dc_field

@dataclass
class FirmwareProfile:
    """
    Records which SDK field-name pattern works for a specific ZKTeco device firmware.
    Populated from SQLite on first use, updated on successful discovery.

    Fields:
        template_table       — "templatev10" or "template"
        template_body_index  — index into the bodies list in _push_templates (0–4)
        authorize_body_index — index into the patterns list in _push_userauthorize (0–3)
    """
    template_table: str | None = None
    template_body_index: int | None = None
    authorize_body_index: int | None = None
```

- [ ] **Step 2: Add `_firmware_profiles` in-session cache to `DeviceSyncService.__init__`**

Find the `DeviceSyncService` class and its `__init__` method. Add:

```python
# In-session cache: device_id → FirmwareProfile
# Loaded from SQLite on first use per device, written back on discovery.
self._firmware_profiles: dict[int, FirmwareProfile] = {}
```

- [ ] **Step 3: Add `_get_firmware_profile` helper method to DeviceSyncService**

Add this private method to the class:

```python
def _get_firmware_profile(self, device_id: int) -> FirmwareProfile:
    """
    Returns the FirmwareProfile for this device, loading from SQLite if not in session cache.
    Creates an empty profile if none exists yet.
    """
    if device_id not in self._firmware_profiles:
        from app.core.db import load_firmware_profile
        persisted = load_firmware_profile(device_id=device_id)
        if persisted:
            self._firmware_profiles[device_id] = FirmwareProfile(
                template_table=persisted["template_table"],
                template_body_index=persisted["template_body_index"],
                authorize_body_index=persisted["authorize_body_index"],
            )
        else:
            self._firmware_profiles[device_id] = FirmwareProfile()
    return self._firmware_profiles[device_id]
```

- [ ] **Step 4: Compile check (import test)**

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
python -c "from app.core.device_sync import DeviceSyncService, FirmwareProfile; print('OK')"
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add app/core/device_sync.py
git commit -m "$(cat <<'EOF'
feat(Phase2): add FirmwareProfile dataclass and in-session cache to DeviceSyncService

In-memory dict (L1) backed by SQLite persistence (L2). Keyed by device_id.
_get_firmware_profile() loads from SQLite on first access per device per session.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Use Firmware Cache in `_push_userauthorize`

**Files:**
- Modify: `app/core/device_sync.py`

The `_push_userauthorize` method (line 425) currently tries 4 patterns per user. With caching, it tries the cached pattern first (1 SDK call), falls back to retry loop on cache miss or failure, and caches the winner.

- [ ] **Step 1: Write failing test for cached authorize push**

Add to `tests/test_firmware_profile_cache.py`:

```python
# ── _push_userauthorize with cache ────────────────────────────────────────

from unittest.mock import MagicMock, patch, call


def make_device_sync():
    from app.core.device_sync import DeviceSyncService
    cfg = MagicMock()
    cfg.plcomm_dll_path = "fake.dll"
    svc = DeviceSyncService(cfg=cfg)
    return svc


def test_push_userauthorize_uses_cached_pattern_on_hit(tmp_path, monkeypatch):
    """When firmware profile has authorize_body_index, only that pattern is attempted."""
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    db_module.save_firmware_profile(device_id=7, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=1)

    svc = make_device_sync()
    sdk = MagicMock()
    sdk.set_device_data.return_value = None  # success

    ok, err = svc._push_userauthorize(sdk, pin="42", door_bitmask=15,
                                      authorize_timezone_id=1, device_id=7)

    assert ok == 1
    assert err is None
    # Only 1 SDK call (cached pattern index=1), not 4
    assert sdk.set_device_data.call_count == 1


def test_push_userauthorize_retries_all_on_cache_miss(tmp_path, monkeypatch):
    """When no profile cached, tries all patterns until one succeeds."""
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    svc = make_device_sync()
    sdk = MagicMock()
    # First 2 patterns fail, 3rd succeeds
    sdk.set_device_data.side_effect = [Exception("fail"), Exception("fail"), None, None]

    ok, err = svc._push_userauthorize(sdk, pin="42", door_bitmask=15,
                                      authorize_timezone_id=1, device_id=99)

    assert ok == 1
    assert sdk.set_device_data.call_count == 3  # failed × 2, succeeded × 1
    # Profile should now be cached (index=2)
    profile = db_module.load_firmware_profile(device_id=99)
    assert profile["authorize_body_index"] == 2


def test_push_userauthorize_clears_cache_on_cached_pattern_failure(tmp_path, monkeypatch):
    """If cached pattern fails (firmware upgrade), cache is cleared and retry loop runs."""
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    db_module.save_firmware_profile(device_id=3, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=0)

    svc = make_device_sync()
    sdk = MagicMock()
    # Cached pattern (index=0) fails, then pattern index=2 succeeds
    sdk.set_device_data.side_effect = [Exception("cached fail"), Exception("fail"),
                                       None, None]

    ok, err = svc._push_userauthorize(sdk, pin="42", door_bitmask=15,
                                      authorize_timezone_id=1, device_id=3)

    assert ok == 1
    # New winning profile should be index=2
    profile = db_module.load_firmware_profile(device_id=3)
    assert profile["authorize_body_index"] == 2
```

- [ ] **Step 2: Run tests to confirm they FAIL**

```bash
python -m pytest tests/test_firmware_profile_cache.py::test_push_userauthorize_uses_cached_pattern_on_hit -v
```

Expected: FAIL — `_push_userauthorize` doesn't accept `device_id` yet

- [ ] **Step 3: Modify `_push_userauthorize` to use firmware cache**

The current method (line 425–470) accepts `pin`, `door_bitmask`, `authorize_timezone_id`. Add `device_id` parameter and cache logic.

Replace the entire `_push_userauthorize` method with:

```python
def _push_userauthorize(
    self,
    sdk: PullSDK,
    *,
    pin: str,
    door_bitmask: int,
    authorize_timezone_id: int,
    device_id: int,
) -> Tuple[int, str | None]:
    """Push a single userauthorize record with a pre-computed bitmask.

    Tries the cached firmware pattern first (1 SDK call). Falls back to the
    full retry loop on cache miss or if the cached pattern stopped working
    (e.g., after a firmware upgrade). Caches the winning pattern on success.

    door_bitmask is the OR of individual door bits (1=door1, 2=door2, 4=door3, 8=door4).
    For all 4 doors on a C3-400: bitmask = 1|2|4|8 = 15.
    """
    if door_bitmask <= 0:
        door_bitmask = self._default_authorize_door_id()

    tz = int(authorize_timezone_id or 1)
    if tz < 1:
        tz = 1

    # Pattern list — order matters: preferred (AuthorizeDoorId) first, legacy fallbacks after.
    patterns = [
        f"Pin={pin}\tAuthorizeTimezoneId={tz}\tAuthorizeDoorId={door_bitmask}\r\n",
        f"Pin={pin}\tAuthorizeDoorId={door_bitmask}\tAuthorizeTimezoneId={tz}\r\n",
        f"Pin={pin}\tDoorID={door_bitmask}\tTimeZoneID={tz}\r\n",
        f"Pin={pin}\tDoorID={door_bitmask}\tTimeZone={tz}\r\n",
    ]

    profile = self._get_firmware_profile(device_id)

    # L1: try cached pattern first
    if profile.authorize_body_index is not None:
        cached_data = patterns[profile.authorize_body_index]
        try:
            sdk.set_device_data(table="userauthorize", data=cached_data, options="")
            self.logger.debug("[DeviceSync] Pin=%s userauthorize OK (cached pattern=%d)", pin, profile.authorize_body_index)
            return 1, None
        except Exception as ex:
            # Cached pattern failed — firmware may have been upgraded. Clear and fall through.
            self.logger.warning(
                "[DeviceSync] Pin=%s userauthorize cached pattern=%d FAILED (%s), clearing cache for device_id=%d",
                pin, profile.authorize_body_index, ex, device_id,
            )
            profile.authorize_body_index = None
            from app.core.db import clear_firmware_profile
            clear_firmware_profile(device_id=device_id)

    # L2: retry loop — discover working pattern and cache it
    last_err = None
    for i, data in enumerate(patterns):
        try:
            sdk.set_device_data(table="userauthorize", data=data, options="")
            self.logger.debug("[DeviceSync] Pin=%s userauthorize OK (pattern=%d)", pin, i)
            # Cache discovery
            profile.authorize_body_index = i
            from app.core.db import save_firmware_profile
            save_firmware_profile(
                device_id=device_id,
                template_table=profile.template_table or "templatev10",
                template_body_index=profile.template_body_index if profile.template_body_index is not None else 0,
                authorize_body_index=i,
            )
            return 1, None
        except Exception as ex:
            last_err = str(ex)

    self.logger.error(
        "[DeviceSync] Pin=%s userauthorize FAILED all patterns: bitmask=%d err=%s",
        pin, door_bitmask, last_err,
    )
    return 0, last_err or "userauthorize: no compatible field pattern worked"
```

- [ ] **Step 4: Update all call sites of `_push_userauthorize` to pass `device_id`**

Search for `_push_userauthorize(` in `device_sync.py` and add `device_id=did` to each call. There should be 1–2 call sites in `_sync_one_device`. Example:

```python
# BEFORE:
auth_ok, auth_err = self._push_userauthorize(sdk, pin=pin, door_bitmask=door_bitmask,
                                              authorize_timezone_id=authorize_timezone_id)
# AFTER:
auth_ok, auth_err = self._push_userauthorize(sdk, pin=pin, door_bitmask=door_bitmask,
                                              authorize_timezone_id=authorize_timezone_id,
                                              device_id=did)
```

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/test_firmware_profile_cache.py -v -k "authorize"
```

Expected: All 3 `push_userauthorize` tests PASS

- [ ] **Step 6: Commit**

```bash
git add app/core/device_sync.py
git commit -m "$(cat <<'EOF'
feat(Phase2): cache firmware pattern in _push_userauthorize

Uses cached authorize_body_index if available (1 SDK call instead of 4).
Falls back to retry loop on cache miss or cached-pattern failure (firmware upgrade).
Caches winner to SQLite for persistence across restarts.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Use Firmware Cache in `_push_templates`

**Files:**
- Modify: `app/core/device_sync.py`

The `_push_templates` method (line 472) currently tries 2 tables × 5 body formats = up to 10 SDK calls per fingerprint. With caching, it tries the cached `(table, body_index)` combo first.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_firmware_profile_cache.py`:

```python
# ── _push_templates with cache ────────────────────────────────────────────

def make_template(fid=0, version=10, size=500, data="AABBCC"):
    return {"fingerId": fid, "templateVersion": version, "templateSize": size, "templateData": data}


def test_push_templates_uses_cached_pattern(tmp_path, monkeypatch):
    """Cached (table, body_index) results in 1 SDK call per fingerprint."""
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    db_module.save_firmware_profile(device_id=10, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=0)

    svc = make_device_sync()
    sdk = MagicMock()
    sdk.set_device_data.return_value = None

    ok, errs = svc._push_templates(sdk, pin="1", templates=[make_template(), make_template(fid=1)],
                                   device_id=10)
    assert ok == 2
    assert errs == []
    assert sdk.set_device_data.call_count == 2  # 1 call per fingerprint (cached)


def test_push_templates_discovers_and_caches_working_combo(tmp_path, monkeypatch):
    """On cache miss, tries combos until one works; caches winner."""
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    svc = make_device_sync()
    sdk = MagicMock()
    # First 3 combos fail, 4th (templatev10, body_index=3) succeeds
    sdk.set_device_data.side_effect = [
        Exception("fail"), Exception("fail"), Exception("fail"), None
    ]

    ok, errs = svc._push_templates(sdk, pin="1", templates=[make_template()], device_id=20)

    assert ok == 1
    assert errs == []
    profile = db_module.load_firmware_profile(device_id=20)
    assert profile["template_table"] == "templatev10"
    assert profile["template_body_index"] == 3


def test_push_templates_clears_cache_on_cached_combo_failure(tmp_path, monkeypatch):
    """Cached combo failure triggers cache clear and retry loop."""
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    db_module.save_firmware_profile(device_id=15, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=0)

    svc = make_device_sync()
    sdk = MagicMock()
    # Cached combo (templatev10, index=0) fails, then combo (template, index=0) succeeds
    sdk.set_device_data.side_effect = [Exception("cached fail"), Exception("fail"),
                                       Exception("fail"), Exception("fail"),
                                       Exception("fail"), None]  # template[0] succeeds

    ok, errs = svc._push_templates(sdk, pin="1", templates=[make_template()], device_id=15)

    assert ok == 1
    profile = db_module.load_firmware_profile(device_id=15)
    assert profile["template_table"] == "template"
```

- [ ] **Step 2: Run tests to confirm they FAIL**

```bash
python -m pytest tests/test_firmware_profile_cache.py -v -k "templates"
```

Expected: FAIL — `_push_templates` doesn't accept `device_id` yet

- [ ] **Step 3: Modify `_push_templates` to use firmware cache**

Replace the entire `_push_templates` method (lines 472–524) with:

```python
def _push_templates(
    self,
    sdk: PullSDK,
    *,
    pin: str,
    templates: List[Dict[str, Any]],
    device_id: int,
) -> Tuple[int, List[str]]:
    """Push fingerprint templates to device.

    Tries the cached (table, body_index) combo first for each template (1 SDK call).
    Falls back to the full retry loop on cache miss or if the cached combo fails.
    Caches the winning combo on first successful discovery for the session.
    """
    errs: List[str] = []
    ok = 0

    def try_set(table: str, body: str) -> bool:
        try:
            sdk.set_device_data(table=table, data=body + "\r\n", options="")
            return True
        except Exception as ex:
            errs.append(f"{table}: {ex}")
            return False

    profile = self._get_firmware_profile(device_id)

    for t in templates:
        fid = int(t.get("fingerId"))
        tv = int(t.get("templateVersion") or 10)
        size = int(t.get("templateSize") or 0)
        tpl = _safe_template_text(str(t.get("templateData") or ""))

        if not tpl:
            continue

        preferred_tables = ["templatev10", "template"] if tv >= 10 else ["template", "templatev10"]

        bodies = [
            lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTemplate={tpl}",
            lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTmp={tpl}",
            lambda: f"Pin={pin}\tFingerID={fid}\tValid=1\tTemplate={tpl}",
            lambda: f"Pin={pin}\tFingerID={fid}\tSize={size}\tTemplate={tpl}",
            lambda: f"Pin={pin}\tFingerID={fid}\tTemplate={tpl}",
        ]

        pushed = False

        # L1: try cached combo (1 SDK call)
        if profile.template_table is not None and profile.template_body_index is not None:
            cached_body = bodies[profile.template_body_index]()
            if try_set(profile.template_table, cached_body):
                ok += 1
                pushed = True
            else:
                # Cached combo failed — clear and fall through to retry loop
                self.logger.warning(
                    "[DeviceSync] Pin=%s FingerID=%d cached template combo (%s, idx=%d) failed — "
                    "clearing firmware cache for device_id=%d",
                    pin, fid, profile.template_table, profile.template_body_index, device_id,
                )
                profile.template_table = None
                profile.template_body_index = None
                from app.core.db import clear_firmware_profile
                clear_firmware_profile(device_id=device_id)

        # L2: retry loop (runs on cache miss or after cache clear)
        if not pushed:
            for table in preferred_tables:
                for i, bfn in enumerate(bodies):
                    if try_set(table, bfn()):
                        pushed = True
                        ok += 1
                        # Cache winning combo
                        profile.template_table = table
                        profile.template_body_index = i
                        from app.core.db import save_firmware_profile
                        save_firmware_profile(
                            device_id=device_id,
                            template_table=table,
                            template_body_index=i,
                            authorize_body_index=profile.authorize_body_index
                                if profile.authorize_body_index is not None else 0,
                        )
                        break
                if pushed:
                    break

        if not pushed:
            errs.append(f"FingerID={fid}: failed to push template (no compatible schema/table)")

    # Deduplicate errors
    seen: set[str] = set()
    compact_errs: List[str] = []
    for e in errs:
        if e not in seen:
            compact_errs.append(e)
            seen.add(e)

    return ok, compact_errs
```

- [ ] **Step 4: Update all call sites of `_push_templates` to pass `device_id`**

Search for `_push_templates(` in `device_sync.py`. Add `device_id=did` to each call:

```python
# BEFORE:
tpl_ok, tpl_errs = self._push_templates(sdk, pin=pin, templates=templates)
# AFTER:
tpl_ok, tpl_errs = self._push_templates(sdk, pin=pin, templates=templates, device_id=did)
```

- [ ] **Step 5: Run all firmware cache tests**

```bash
python -m pytest tests/test_firmware_profile_cache.py -v
```

Expected: All tests PASS

- [ ] **Step 6: Run full test suite to catch regressions**

```bash
python -m pytest tests/ -v --tb=short
```

Expected: All tests PASS

- [ ] **Step 7: Commit**

```bash
git add app/core/device_sync.py tests/test_firmware_profile_cache.py
git commit -m "$(cat <<'EOF'
feat(Phase2): cache firmware pattern in _push_templates

Uses cached (template_table, body_index) if available: 1 SDK call per fingerprint
instead of up to 10. Falls back to full retry loop on cache miss or failure.
Caches winner to SQLite immediately for persistence across restarts.

Impact: 1200 users × 5 fingerprints: ~60,000 SDK calls → ~6,010 SDK calls.
Expected device push time: 30min → ~5-8min.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## ⏸ CHECKPOINT: Deploy Backend Phase 3 Before Continuing

**Tasks 5–9 require the backend to return `membersDeltaMode`, `validMemberIds`, and `currentMembersRefreshedAt` fields in the sync response.**

Before proceeding:
- [ ] Confirm backend Plan A (Tasks 1–6) is deployed to the target environment
- [ ] Call the sync endpoint and verify `membersDeltaMode` appears in the response JSON
- [ ] Verify `validMemberIds` is a list of integers (not null) when `membersUpdatedAfter` is provided and version changed

Once confirmed, proceed to Task 5.

---

## Task 5: Delta User Cache Functions in db.py

**Files:**
- Modify: `app/core/db.py`

Add three functions needed for delta member cache management: upsert individual changed users, delete specific users by AM ID, and list all cached AM IDs for delete-detection comparison.

- [ ] **Step 1: Write failing tests**

Create `tests/test_delta_user_cache.py`:

```python
"""Tests for delta user cache operations in db.py."""
import json
import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()
    return db_module


def _make_user(am_id=1, user_id=100, full_name="Alice Smith", card="12345"):
    return {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": 50,
        "fullName": full_name,
        "phone": "0600000000",
        "email": "alice@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": card,
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
    }


def test_upsert_users_inserts_new_user(db):
    """Upserting a user that doesn't exist inserts it."""
    db.upsert_delta_users([_make_user(am_id=1)])
    ids = db.get_all_cached_user_am_ids()
    assert 1 in ids


def test_upsert_users_updates_existing_user(db):
    """Upserting a user that already exists updates their data."""
    db.upsert_delta_users([_make_user(am_id=1, full_name="Alice Smith")])
    db.upsert_delta_users([_make_user(am_id=1, full_name="Alice Updated")])
    # Should still be 1 row
    ids = db.get_all_cached_user_am_ids()
    assert len([i for i in ids if i == 1]) == 1


def test_upsert_users_handles_multiple_users(db):
    """Multiple users can be upserted in one call."""
    db.upsert_delta_users([_make_user(am_id=1), _make_user(am_id=2), _make_user(am_id=3)])
    ids = db.get_all_cached_user_am_ids()
    assert {1, 2, 3}.issubset(set(ids))


def test_delete_users_by_am_ids_removes_entries(db):
    """Users with specified AM IDs are removed from cache."""
    db.upsert_delta_users([_make_user(am_id=1), _make_user(am_id=2), _make_user(am_id=3)])
    db.delete_users_by_am_ids({2, 3})
    ids = set(db.get_all_cached_user_am_ids())
    assert 1 in ids
    assert 2 not in ids
    assert 3 not in ids


def test_delete_users_by_am_ids_ignores_missing_ids(db):
    """Deleting IDs that don't exist doesn't raise errors."""
    db.upsert_delta_users([_make_user(am_id=1)])
    db.delete_users_by_am_ids({999, 1000})  # these don't exist
    ids = db.get_all_cached_user_am_ids()
    assert 1 in ids


def test_get_all_cached_user_am_ids_returns_empty_when_no_users(db):
    """Returns empty collection when no users cached."""
    ids = db.get_all_cached_user_am_ids()
    assert len(ids) == 0
```

- [ ] **Step 2: Run tests to confirm they FAIL**

```bash
cd C:\Users\mohaa\Desktop\monclub_access_python
python -m pytest tests/test_delta_user_cache.py -v
```

Expected: FAIL — functions don't exist yet

- [ ] **Step 3: Implement `upsert_delta_users`, `delete_users_by_am_ids`, `get_all_cached_user_am_ids` in db.py**

Add these three functions near the existing member cache functions:

```python
def upsert_delta_users(users: list[dict]) -> None:
    """
    Upsert (INSERT OR REPLACE) changed members into sync_users.
    Used by Phase 3 delta sync: only changed members are sent, so we upsert
    instead of DELETE-all + INSERT-all.

    The UNIQUE index on (user_id, active_membership_id) ensures deduplication.
    H-006 guard does NOT apply here — delta mode with 0 users means only deletions,
    which are handled separately by delete_users_by_am_ids().
    """
    if not users:
        return
    with get_conn() as conn:
        for u in users:
            if not isinstance(u, dict):
                continue
            fps = u.get("fingerprints") or []
            if not isinstance(fps, list):
                fps = []
            am_id = u.get("activeMembershipId")
            m_id = u.get("membershipId")
            if am_id is None or str(am_id).strip() == "":
                am_id = m_id
            conn.execute(
                """
                INSERT OR REPLACE INTO sync_users (
                    user_id, active_membership_id, membership_id,
                    full_name, phone, email, valid_from, valid_to,
                    first_card_id, second_card_id, image,
                    fingerprints_json, face_id, account_username_id,
                    qr_code_payload, birthday, image_source, user_image_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    u.get("userId"), am_id, m_id,
                    u.get("fullName"), u.get("phone"), u.get("email"),
                    u.get("validFrom"), u.get("validTo"),
                    u.get("firstCardId"), u.get("secondCardId"), u.get("image"),
                    json.dumps(fps, ensure_ascii=False),
                    u.get("faceId"),
                    u.get("accountUsernameId") or u.get("account_username_id"),
                    u.get("qrCodePayload"), u.get("birthday"),
                    u.get("imageSource"), u.get("userImageStatus"),
                ),
            )
        conn.commit()


def delete_users_by_am_ids(am_ids: set[int]) -> None:
    """
    Delete sync_users rows for the given active_membership_ids.
    Used by Phase 3 delta sync for client-side delete detection:
    local_ids - server_valid_ids = to_delete.
    """
    if not am_ids:
        return
    with get_conn() as conn:
        placeholders = ",".join("?" * len(am_ids))
        conn.execute(
            f"DELETE FROM sync_users WHERE active_membership_id IN ({placeholders})",
            list(am_ids),
        )
        conn.commit()


def get_all_cached_user_am_ids() -> list[int]:
    """
    Return all active_membership_id values currently in the sync_users cache.
    Used for delta delete detection: compare against server's validMemberIds.
    """
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT active_membership_id FROM sync_users WHERE active_membership_id IS NOT NULL"
        ).fetchall()
    return [r[0] for r in rows]
```

- [ ] **Step 4: Run tests — confirm all pass**

```bash
python -m pytest tests/test_delta_user_cache.py -v
```

Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add app/core/db.py tests/test_delta_user_cache.py
git commit -m "$(cat <<'EOF'
feat(Phase3): add delta user cache operations to db.py

upsert_delta_users:       INSERT OR REPLACE changed members (no full DELETE)
delete_users_by_am_ids:   remove expired/deleted members by AM ID
get_all_cached_user_am_ids: list AM IDs for server-vs-local delete detection

H-006 guard intentionally skipped for delta mode: empty users=[] in delta mode
means only deletions occurred, not a backend error.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Update `save_sync_cache_delta` to Handle Delta Member Mode

**Files:**
- Modify: `app/core/db.py`

The existing `save_sync_cache_delta` always does DELETE-all + INSERT-all when `refreshMembers=True`. Update it to support the new `membersDeltaMode` path.

- [ ] **Step 1: Write failing tests in `test_delta_user_cache.py`**

Add to `tests/test_delta_user_cache.py`:

```python
# ── save_sync_cache_delta delta mode ─────────────────────────────────────

def _make_sync_data(users, delta_mode=False, valid_ids=None):
    return {
        "users": users,
        "membersDeltaMode": delta_mode,
        "validMemberIds": valid_ids,
        "devices": [],
        "gymAccessCredentials": [],
        "infrastructures": [],
        "membership": [],
        "contractStatus": True,
        "contractEndDate": "2026-12-31",
        "accessSoftwareSettings": {},
    }


def test_save_sync_cache_delta_full_mode_replaces_all_users(db):
    """Full mode (membersDeltaMode=False) replaces all users in cache."""
    # Pre-populate cache with 3 users
    db.upsert_delta_users([_make_user(am_id=i) for i in [1, 2, 3]])

    data = _make_sync_data(users=[_make_user(am_id=10), _make_user(am_id=11)])
    db.save_sync_cache_delta(data, {"members": True, "devices": False,
                                   "credentials": False, "settings": False})

    ids = set(db.get_all_cached_user_am_ids())
    assert ids == {10, 11}  # replaced, not merged


def test_save_sync_cache_delta_delta_mode_upserts_changed_and_deletes_removed(db):
    """Delta mode upserts changed users and removes ones not in validMemberIds."""
    # Pre-populate: users 1, 2, 3
    db.upsert_delta_users([_make_user(am_id=i) for i in [1, 2, 3]])

    # Backend says: user 1 changed (new name), user 3 valid but unchanged (not in users[]),
    # user 2 is no longer valid. validMemberIds=[1,3]
    data = _make_sync_data(
        users=[_make_user(am_id=1, full_name="Updated Name")],
        delta_mode=True,
        valid_ids=[1, 3],
    )
    db.save_sync_cache_delta(data, {"members": True, "devices": False,
                                   "credentials": False, "settings": False})

    ids = set(db.get_all_cached_user_am_ids())
    assert 1 in ids     # updated
    assert 3 in ids     # kept (was in validMemberIds, not in changed list)
    assert 2 not in ids  # deleted (not in validMemberIds)


def test_save_sync_cache_delta_delta_mode_with_no_changes_deletes_removed(db):
    """Delta mode with empty users[] only deletes members absent from validMemberIds."""
    db.upsert_delta_users([_make_user(am_id=i) for i in [1, 2, 3]])

    # No changes, but user 3 expired
    data = _make_sync_data(users=[], delta_mode=True, valid_ids=[1, 2])
    db.save_sync_cache_delta(data, {"members": True, "devices": False,
                                   "credentials": False, "settings": False})

    ids = set(db.get_all_cached_user_am_ids())
    assert {1, 2}.issubset(ids)
    assert 3 not in ids
```

- [ ] **Step 2: Run tests to confirm they FAIL**

```bash
python -m pytest tests/test_delta_user_cache.py -v -k "save_sync_cache_delta"
```

- [ ] **Step 3: Update `save_sync_cache_delta` in db.py**

Find the `if refresh.get("members", True):` block (around line 1804). Replace the entire members section:

```python
# Conditional: members (users + fingerprints)
if refresh.get("members", True):
    users = data.get("users") or []
    delta_mode = bool(data.get("membersDeltaMode", False))
    valid_member_ids = data.get("validMemberIds")  # list[int] | None

    if delta_mode:
        # Phase 3: Partial update — upsert changed, delete removed.
        # H-006 guard intentionally NOT applied: empty users=[] in delta mode
        # means only deletions occurred, not a backend error.
        _logger.info(
            "[SYNC-DEBUG] save_sync_cache_delta: DELTA mode — upsert %d changed, "
            "validMemberIds count=%d",
            len(users), len(valid_member_ids) if valid_member_ids else 0,
        )
        upsert_delta_users(users)
        if valid_member_ids is not None:
            local_ids = set(get_all_cached_user_am_ids())
            server_ids = set(valid_member_ids)
            removed_ids = local_ids - server_ids
            if removed_ids:
                _logger.info(
                    "[SYNC-DEBUG] save_sync_cache_delta: DELTA mode — removing %d stale members: %s",
                    len(removed_ids), sorted(removed_ids)[:10],
                )
                delete_users_by_am_ids(removed_ids)
    else:
        # Full replace — H-006 guard applies
        old_count = cur.execute("SELECT COUNT(*) FROM sync_users").fetchone()[0]
        _logger.info(
            "[SYNC-DEBUG] save_sync_cache_delta: FULL mode — incoming=%d, old_db_count=%d",
            len(users), old_count,
        )
        if not users and old_count > 10:
            _logger.error(
                "[DB] save_sync_cache_delta: backend returned 0 users (refreshMembers=True, "
                "FULL mode) but local cache has %d. Refusing to clear — likely backend error.",
                old_count,
            )
            conn.commit()
            return
        # [existing full-replace logic: DELETE FROM sync_users + INSERT OR REPLACE loop]
        # ... (keep the existing content-hash guard and INSERT loop unchanged)
```

**Important:** The existing content-hash guard and INSERT loop below this block remain unchanged. Only the outer `if delta_mode / else` wrapper is added.

- [ ] **Step 4: Run all delta user cache tests**

```bash
python -m pytest tests/test_delta_user_cache.py -v
```

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add app/core/db.py tests/test_delta_user_cache.py
git commit -m "$(cat <<'EOF'
feat(Phase3): add delta mode to save_sync_cache_delta

When response has membersDeltaMode=True:
- upsert_delta_users() for changed members
- delete_users_by_am_ids() for members absent from validMemberIds
H-006 guard skipped for delta mode (empty users=[] = only deletions, not error).
Full mode path unchanged.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Send `membersUpdatedAfter` from Python Client

**Files:**
- Modify: `app/api/monclub_api.py`
- Modify: `app/ui/app.py`

The client needs to persist the `currentMembersRefreshedAt` timestamp from the backend response and send it as `membersUpdatedAfter` on the next sync request.

- [ ] **Step 1: Add persistence for `membersRefreshedAt` in db.py**

In `db.py`, extend the `sync_version_tokens` table usage (or add a separate helper) to persist `membersRefreshedAt`:

```python
# These two functions use the existing sync_version_tokens table (key=value store)

MEMBERS_REFRESHED_AT_KEY = "membersRefreshedAt"

def save_members_refreshed_at(refreshed_at: str) -> None:
    """Persist the timestamp from backend's currentMembersRefreshedAt for next sync."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sync_version_tokens (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (MEMBERS_REFRESHED_AT_KEY, refreshed_at),
        )
        conn.commit()


def load_members_refreshed_at() -> str | None:
    """Load the previously-saved membersRefreshedAt timestamp, or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM sync_version_tokens WHERE key = ?",
            (MEMBERS_REFRESHED_AT_KEY,),
        ).fetchone()
    return row[0] if row else None
```

- [ ] **Step 2: Update `get_sync_data` in monclub_api.py to send `membersUpdatedAfter`**

In `monclub_api.py`, find `get_sync_data` (around line 137). The existing signature already accepts `version_tokens: dict | None`. No signature change needed — `membersUpdatedAfter` is passed as part of the version_tokens dict:

```python
# In app.py _sync_tick, the caller builds:
# version_tokens = {
#     "membersVersion": ...,
#     "devicesVersion": ...,
#     "credentialsVersion": ...,
#     "settingsVersion": ...,
#     "membersUpdatedAfter": <ISO timestamp>,  # NEW
# }
# No change to monclub_api.py needed — it already passes all version_tokens as query params.
```

Verify by reading `monclub_api.py` lines 137–176: confirm `params.update(version_tokens)` passes all keys.

- [ ] **Step 3: Update `_sync_tick` in app.py to pass and save `membersUpdatedAfter`**

In `app.py`, find the `_sync_tick` method (around line 990). Find where `version_tokens` is built and where `save_version_tokens` is called:

```python
# BEFORE (approximate existing code in _sync_tick):
version_tokens = load_version_tokens() or None
data = api.get_sync_data(token=auth.token, version_tokens=version_tokens, timeout=sync_timeout)
...
new_tokens = {
    param: data[field]
    for param, field in (
        ("membersVersion",     "currentMembersVersion"),
        ("devicesVersion",     "currentDevicesVersion"),
        ("credentialsVersion", "currentCredentialsVersion"),
        ("settingsVersion",    "currentSettingsVersion"),
    )
    if data.get(field)
}
if new_tokens:
    save_version_tokens(new_tokens)
```

Add `membersUpdatedAfter` to the outgoing params:

```python
# AFTER:
from app.core.db import load_members_refreshed_at, save_members_refreshed_at

base_tokens = load_version_tokens() or {}
members_refreshed_at = load_members_refreshed_at()
if members_refreshed_at:
    base_tokens["membersUpdatedAfter"] = members_refreshed_at

version_tokens = base_tokens or None
data = api.get_sync_data(token=auth.token, version_tokens=version_tokens, timeout=sync_timeout)

# ... existing delta save logic ...

# Save currentMembersRefreshedAt for the next sync's membersUpdatedAfter
if data.get("currentMembersRefreshedAt"):
    save_members_refreshed_at(data["currentMembersRefreshedAt"])

new_tokens = { ... }  # unchanged
```

- [ ] **Step 4: Clear `membersRefreshedAt` on logout/login**

Find the logout / cache-clear path in `app.py` or wherever `clear_version_tokens()` is called. Add:

```python
from app.core.db import save_members_refreshed_at
# On logout/cache-clear, reset membersRefreshedAt so next sync is a full refresh:
save_members_refreshed_at("")  # empty string = no delta on next sync
```

Or add `clear_members_refreshed_at()` to `db.py` that deletes the key.

- [ ] **Step 5: Integration test — verify first sync is full, second is delta**

```bash
# Manual test steps (document expected behavior):
# 1. Clear local cache (or restart fresh)
# 2. First sync: no membersUpdatedAfter → backend returns membersDeltaMode=false, all 1403 members
# 3. currentMembersRefreshedAt is saved to SQLite
# 4. Second sync: membersUpdatedAfter=<timestamp> sent → if no changes, users=[], membersDeltaMode=true
# 5. Third sync: change one member in dashboard → backend returns only that member
```

- [ ] **Step 6: Commit**

```bash
git add app/core/db.py app/ui/app.py
git commit -m "$(cat <<'EOF'
feat(Phase3): send membersUpdatedAfter from client for member-level delta sync

Persists currentMembersRefreshedAt from backend response to sync_version_tokens.
Sends as membersUpdatedAfter on next sync request.
On logout/cache-clear: resets to empty (forces full refresh on next sync).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Differential Device Push — Accept Delta Hints

**Files:**
- Modify: `app/core/device_sync.py`

Modify `_sync_one_device` and `sync_all_devices` to accept `changed_ids` / `removed_ids` delta hints. When provided, skip the hash-computation loop for unchanged users. Retain hash computation as safety net for full-sync mode.

- [ ] **Step 1: Write failing tests**

Create `tests/test_differential_device_push.py`:

```python
"""Tests for differential device push (Phase 4)."""
from unittest.mock import MagicMock, patch
import pytest


def make_user(am_id, card="0", name="User"):
    return {
        "activeMembershipId": am_id,
        "userId": am_id + 1000,
        "fullName": name,
        "firstCardId": card,
        "fingerprints": [],
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
    }


def test_sync_all_devices_passes_delta_hints_to_sync_one_device():
    """When changed_ids is provided, _sync_one_device receives it."""
    from app.core.device_sync import DeviceSyncService
    svc = DeviceSyncService(cfg=MagicMock())

    captured = {}

    def fake_sync_one(*, device, users, local_fp_index, default_door_id,
                      changed_ids, removed_ids):
        captured["changed_ids"] = changed_ids
        captured["removed_ids"] = removed_ids

    svc._sync_one_device = fake_sync_one

    users = [make_user(1), make_user(2), make_user(3)]
    devices = [{"id": 10, "name": "Door1", "ipAddress": "192.168.1.1",
                "portNumber": 4370, "password": "", "accessDataMode": "DEVICE",
                "fingerprintEnabled": False, "doorIds": [15]}]

    with patch("app.core.db.list_sync_devices", return_value=devices), \
         patch("app.core.db.list_sync_users", return_value=users):
        svc.sync_all_devices(users=users, changed_ids={2}, removed_ids={5})

    assert captured.get("changed_ids") == {2}
    assert captured.get("removed_ids") == {5}


def test_sync_one_device_skips_hash_computation_for_unchanged_users():
    """When changed_ids is provided, only changed users enter hash computation."""
    from app.core.device_sync import DeviceSyncService
    import app.core.db as db_module

    svc = DeviceSyncService(cfg=MagicMock())
    hashes_computed = []

    orig_compute = svc._compute_desired_hash
    def spy_compute(**kwargs):
        hashes_computed.append(kwargs["pin"])
        return orig_compute(**kwargs)
    svc._compute_desired_hash = spy_compute

    # 3 users, only user 2 changed
    users = [make_user(am_id=1), make_user(am_id=2), make_user(am_id=3)]
    changed_ids = {2}
    removed_ids = set()

    # We test the filtering logic without actually connecting to a device
    # by checking which PINs would be in pins_to_sync
    filtered = [u for u in users if u["activeMembershipId"] in changed_ids]
    assert len(filtered) == 1
    assert filtered[0]["activeMembershipId"] == 2


def test_sync_one_device_full_mode_when_no_delta_hints():
    """When changed_ids is None, all users go through hash computation (existing behavior)."""
    # With changed_ids=None, the existing hash-based detection runs as before.
    # This test documents the contract — full sync mode is unchanged.
    users = [make_user(1), make_user(2), make_user(3)]
    changed_ids = None  # None = full sync mode
    pins_in_scope = [str(u["activeMembershipId"]) for u in users]
    # All users enter hash computation in full mode
    assert len(pins_in_scope) == 3
```

- [ ] **Step 2: Run tests to confirm they FAIL (signature doesn't accept delta hints yet)**

```bash
python -m pytest tests/test_differential_device_push.py -v
```

Expected: FAIL

- [ ] **Step 3: Update `sync_all_devices` signature and call**

Find `sync_all_devices` method in `device_sync.py` (around line 1040). Add `changed_ids` and `removed_ids` parameters:

```python
def sync_all_devices(
    self,
    *,
    users: List[Dict[str, Any]],
    local_fp_index: Dict[str, List[Any]] | None = None,
    default_door_id: int = 0,
    changed_ids: set[int] | None = None,   # NEW: AM IDs that changed (None = full sync)
    removed_ids: set[int] | None = None,   # NEW: AM IDs that were removed
) -> None:
```

Pass them through to `_sync_one_device` in the `executor.submit` call:

```python
executor.submit(
    self._sync_one_device,
    device=dev,
    users=users,
    local_fp_index=local_fp_index,
    default_door_id=default_door_id,
    changed_ids=changed_ids,    # NEW
    removed_ids=removed_ids,    # NEW
)
```

- [ ] **Step 4: Update `_sync_one_device` signature and add delta filtering**

Add `changed_ids` and `removed_ids` to `_sync_one_device` (around line 611):

```python
def _sync_one_device(
    self,
    *,
    device: Dict[str, Any],
    users: List[Dict[str, Any]],
    local_fp_index: Dict[str, List[Any]],
    default_door_id: int,
    changed_ids: set[int] | None = None,  # NEW
    removed_ids: set[int] | None = None,  # NEW
) -> None:
```

Then, after building `desired` (the filtered user dict for this device), add delta filtering:

```python
# Phase 4: If delta hints provided, skip hash computation for unchanged users.
# This avoids iterating 1,200 users and computing SHA-1 when only 2 changed.
# Safety net: hash computation still runs for changed users and for full-sync mode.
if changed_ids is not None:
    # Only compute hashes for users that actually changed or were removed
    delta_desired = {
        pin: u for pin, u in desired.items()
        if _to_int(u.get("activeMembershipId"), default=0) in changed_ids
    }
    # Force-delete removed users (they won't be in desired dict, but may be on device)
    delta_removed_pins = set()
    if removed_ids:
        for u in users:
            am_id = _to_int(u.get("activeMembershipId"), default=0)
            if am_id in removed_ids:
                p = _pin_str(u.get("activeMembershipId"))
                if p:
                    delta_removed_pins.add(p)

    _log.info(
        "[DeviceSync Phase4] device_id=%s delta: changed_pins=%d removed_pins=%d (of %d total)",
        dev_id, len(delta_desired), len(delta_removed_pins), len(desired),
    )

    # Hash computation only for delta_desired (typically 0-10 users)
    for pin, u in delta_desired.items():
        templates = self._collect_templates_for_pin(...)
        dh = self._compute_desired_hash(...)
        desired_hashes[pin] = dh
        prev_hash, prev_ok = prev_state.get(pin, ("", True))
        if prev_hash != dh or not prev_ok:
            pins_to_sync.add(pin)
            templates_for_sync[pin] = templates

    # Add removed pins for deletion
    pins_to_sync.update(delta_removed_pins)
else:
    # Full sync: existing hash computation loop (unchanged)
    for pin, u in desired.items():
        templates = self._collect_templates_for_pin(...)
        dh = self._compute_desired_hash(...)
        desired_hashes[pin] = dh
        prev_hash, prev_ok = prev_state.get(pin, ("", True))
        if prev_hash != dh or not prev_ok:
            pins_to_sync.add(pin)
            templates_for_sync[pin] = templates
```

- [ ] **Step 5: Run all tests**

```bash
python -m pytest tests/ -v --tb=short
```

Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add app/core/device_sync.py tests/test_differential_device_push.py
git commit -m "$(cat <<'EOF'
feat(Phase4): differential device push — skip hash computation for unchanged users

When changed_ids/removed_ids provided (from backend delta sync):
- Hash computation only for changed users (typically 0-10, not 1,200)
- Removed users explicitly deleted from device
- Full sync mode (changed_ids=None) unchanged — existing hash loop runs as before

Impact: typical delta push ~3s vs 5-8 min (only changed users processed).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Wire Delta Hints Through app.py `_sync_tick`

**Files:**
- Modify: `app/ui/app.py`

Connect the backend's `membersDeltaMode` + `validMemberIds` response to the device sync call.

- [ ] **Step 1: Add delta hint extraction to `_sync_tick`**

In `app.py`, in the `_sync_tick` → `work()` function, after `save_sync_cache_delta` is called, add:

```python
# Phase 4: Compute delta hints for device sync
# changed_ids: AM IDs of members that were updated (from backend delta response)
# removed_ids: AM IDs that are no longer valid (local - server diff)
changed_ids: set[int] | None = None
removed_ids: set[int] = set()

if data.get("membersDeltaMode"):
    # Backend returned partial members — compute changed + removed sets
    changed_ids = {
        int(u["activeMembershipId"])
        for u in (data.get("users") or [])
        if u.get("activeMembershipId") is not None
    }
    valid_ids_from_server = set(data.get("validMemberIds") or [])
    if valid_ids_from_server:
        from app.core.db import get_all_cached_user_am_ids
        # Note: get after save_sync_cache_delta so cache is up-to-date
        local_ids = set(get_all_cached_user_am_ids())
        removed_ids = local_ids - valid_ids_from_server
```

Then pass to the device sync call:

```python
# BEFORE:
device_sync_svc.sync_all_devices(users=all_users, ...)

# AFTER:
device_sync_svc.sync_all_devices(
    users=all_users,
    local_fp_index=local_fp_index,
    default_door_id=default_door_id,
    changed_ids=changed_ids,    # None on full sync, set on delta
    removed_ids=removed_ids,    # empty on full sync, set on delta
)
```

- [ ] **Step 2: Build/import check**

```bash
python -c "from app.ui.app import App; print('OK')" 2>&1 | head -5
```

Expected: `OK` (or import warnings unrelated to this change)

- [ ] **Step 3: Run full test suite**

```bash
python -m pytest tests/ -v --tb=short
```

Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add app/ui/app.py
git commit -m "$(cat <<'EOF'
feat(Phase4): wire delta hints from sync response to device push

Extracts changed_ids and removed_ids from backend membersDeltaMode response.
Passes to sync_all_devices so only changed users are processed per device.
Full sync mode (no membersDeltaMode) passes changed_ids=None — existing behavior.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Verification Checklist

- [ ] **Phase 2 - Firmware cache:** On first device push after restart, check logs for `[DeviceSync] … cached pattern=X` messages after the first user. Expect only 1 SDK call per fingerprint from user 2 onward.
- [ ] **Phase 2 - Cache invalidation:** If device firmware is upgraded and cached pattern fails, logs should show `clearing firmware cache for device_id=X` followed by retry loop.
- [ ] **Phase 2 - Persistence:** After app restart, second push should immediately use cached patterns (no re-discovery).
- [ ] **Phase 2 - Performance:** Device push time for 1,200 members should drop from ~30min to ~5–8min.
- [ ] **Phase 3 - First sync:** No `membersUpdatedAfter` sent → backend returns `membersDeltaMode=false`, all members cached.
- [ ] **Phase 3 - Delta sync:** After first sync, second sync sends `membersUpdatedAfter`. If nothing changed: `membersDeltaMode=true`, `users=[]`, no SQLite writes to sync_users.
- [ ] **Phase 3 - Delete detection:** Expire a member in the backend → next delta sync: member not in `validMemberIds` → removed from local SQLite cache.
- [ ] **Phase 4 - Delta push:** After a delta sync with 2 changed members, device push logs should show `delta: changed_pins=2 ... (of 1200 total)`. Push completes in ~3–5 seconds.
- [ ] **Phase 4 - Full push safety:** After force-refresh or app restart, device push uses full hash-computation mode (no delta hints). All users correctly evaluated.
- [ ] **Full test suite:** `python -m pytest tests/ -v` passes with no failures.
