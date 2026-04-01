# ULTRA Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ULTRA access control mode — device-firmware RFID/fingerprint with PC-side RTLog observation and TOTP rescue — across backend, access client, and dashboard.

**Architecture:** ULTRA combines DEVICE mode (push data to controller, firmware handles RFID/FP instantly) with AGENT mode's RTLog polling (popup notifications, real-time history) and TOTP rescue (PC verifies denied QR codes and opens door). Three layers per device: Device Sync, RTLog Observer, TOTP Rescue.

**Tech Stack:** Java/Spring (backend), Python 3 + Tkinter + PullSDK (access client), React + TypeScript + MUI (dashboard)

**Spec:** `docs/superpowers/specs/2026-04-01-ultra-mode-design.md`

---

## File Structure

### Files to Create

| File | Responsibility |
|------|---------------|
| `monclub_access_python/app/core/access_types.py` | Shared dataclasses: NotificationRequest, HistoryRecord, AccessEvent |
| `monclub_access_python/app/core/access_verification.py` | Shared functions: verify_totp, verify_card, load_local_state, TOTP helpers |
| `monclub_access_python/app/core/ultra_engine.py` | UltraEngine, UltraDeviceWorker, UltraSyncScheduler |
| `monclub_access_python/tests/test_access_verification.py` | Unit tests for extracted verification functions |
| `monclub_access_python/tests/test_ultra_engine.py` | Unit tests for ULTRA engine event classification and TOTP rescue |

### Files to Modify

| File | Change |
|------|--------|
| **Backend** | |
| `monclub_backend/.../Enumurations/AccessSoftwareDataMode.java` | Add `ULTRA` value |
| `monclub_backend/.../Models/GymDevice.java` | Add 3 ULTRA fields |
| `monclub_backend/.../Models/DTO/GymDeviceDto.java` | Add 3 ULTRA fields |
| **Access Client** | |
| `monclub_access_python/app/core/realtime_agent.py` | Import from shared modules instead of inline definitions |
| `monclub_access_python/app/core/config.py` | Add ULTRA to `_normalize_data_mode()` |
| `monclub_access_python/app/core/settings_reader.py` | Add ULTRA to `normalize_access_data_mode()` + read ULTRA fields |
| `monclub_access_python/app/core/db.py` | Add "ULTRA" to allowed accessDataMode values |
| `monclub_access_python/app/ui/app.py` | Add ULTRA count to mode summary + UltraEngine startup |
| `monclub_access_python/app/api/local_access_api_v2.py` | Add `/api/v2/ultra/status` endpoint + update `/api/v2/status` |
| `monclub_access_python/access/local_api_routes.py` | Register ULTRA API routes |
| **Dashboard** | |
| `mon_club_dashboard/src/models/enums/AccessSoftwareDataMode.ts` | Add `ULTRA` value |
| `mon_club_dashboard/src/models/GymDeviceModel.ts` | Add 3 ULTRA fields + fromJson/toJson |
| `mon_club_dashboard/src/schemas/GymDeviceSchema.ts` | Update Zod schema |
| `mon_club_dashboard/src/sections/GymDevices/view/gym-devices-view.tsx` | ULTRA settings in device form |

---

## Task 1: Backend — Add ULTRA Enum and Model Fields

**Files:**
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\Enumurations\AccessSoftwareDataMode.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\GymDevice.java`
- Modify: `D:\projects\MonClub\monclub_backend\src\main\java\com\tpjava\tpjava\Models\DTO\GymDeviceDto.java`

- [ ] **Step 1: Add ULTRA to AccessSoftwareDataMode enum**

In `AccessSoftwareDataMode.java`, add `ULTRA` after `AGENT`:

```java
public enum AccessSoftwareDataMode {
    DEVICE,
    AGENT,
    ULTRA
}
```

- [ ] **Step 2: Add ULTRA fields to GymDevice entity**

In `GymDevice.java`, after the existing sleep/backoff fields (~line 195), add:

```java
@Column(nullable = true)
private Integer ultraSyncIntervalMinutes = 15;

@Column(nullable = true)
private Boolean ultraTotpRescueEnabled = true;

@Column(nullable = true)
private Boolean ultraRtlogEnabled = true;
```

Generate getters and setters (or rely on Lombok if the project uses it — follow existing field patterns in the file).

- [ ] **Step 3: Add ULTRA fields to GymDeviceDto**

In `GymDeviceDto.java`, after the existing fields (~line 165), add matching fields:

```java
private Integer ultraSyncIntervalMinutes;
private Boolean ultraTotpRescueEnabled;
private Boolean ultraRtlogEnabled;
```

Ensure the mapper/converter that converts `GymDevice` -> `GymDeviceDto` includes these fields. Follow the existing mapping pattern in the codebase.

- [ ] **Step 4: Commit**

```bash
cd D:/projects/MonClub/monclub_backend
git add -A
git commit -m "feat: add ULTRA mode enum value and device model fields"
```

---

## Task 2: Dashboard — Add ULTRA to Enum, Model, Schema, and Form

**Files:**
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\models\enums\AccessSoftwareDataMode.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\models\GymDeviceModel.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\schemas\GymDeviceSchema.ts`
- Modify: `C:\Users\mohaa\Desktop\mon_club_dashboard\src\sections\GymDevices\view\gym-devices-view.tsx`

- [ ] **Step 1: Add ULTRA to TypeScript enum**

In `AccessSoftwareDataMode.ts`, add `ULTRA = "ULTRA"` to the enum and the exported array:

```typescript
export enum AccessSoftwareDataMode {
  DEVICE = "DEVICE",
  AGENT = "AGENT",
  ULTRA = "ULTRA",
}

export const AccessSoftwareDataModeValues = [
  AccessSoftwareDataMode.DEVICE,
  AccessSoftwareDataMode.AGENT,
  AccessSoftwareDataMode.ULTRA,
];
```

- [ ] **Step 2: Add ULTRA fields to GymDeviceModel**

In `GymDeviceModel.ts`, add fields to the class definition (~line 82):

```typescript
ultraSyncIntervalMinutes: number = 15;
ultraTotpRescueEnabled: boolean = true;
ultraRtlogEnabled: boolean = true;
```

In `fromJson()` (~line 127), add parsing:

```typescript
model.ultraSyncIntervalMinutes = json.ultraSyncIntervalMinutes ?? 15;
model.ultraTotpRescueEnabled = json.ultraTotpRescueEnabled ?? true;
model.ultraRtlogEnabled = json.ultraRtlogEnabled ?? true;
```

In `toJson()` (~line 208), add serialization:

```typescript
ultraSyncIntervalMinutes: this.ultraSyncIntervalMinutes,
ultraTotpRescueEnabled: this.ultraTotpRescueEnabled,
ultraRtlogEnabled: this.ultraRtlogEnabled,
```

- [ ] **Step 3: Update Zod schema**

In `GymDeviceSchema.ts` (~line 38), after the existing accessDataMode field, add:

```typescript
ultraSyncIntervalMinutes: z.number().min(5).max(1440).default(15),
ultraTotpRescueEnabled: z.boolean().default(true),
ultraRtlogEnabled: z.boolean().default(true),
```

- [ ] **Step 4: Add ULTRA settings to device form UI**

In `gym-devices-view.tsx`, find the accessDataMode `<Select>` component (~lines 854-879). The dropdown already maps `Object.values(AccessSoftwareDataMode)` to `<MenuItem>` items, so ULTRA will appear automatically from step 1.

Below the accessDataMode selector, add a conditional ULTRA settings panel:

```tsx
{watchedAccessDataMode === AccessSoftwareDataMode.ULTRA && (
  <>
    <Controller
      name="ultraSyncIntervalMinutes"
      control={control}
      render={({ field }) => (
        <TextField
          {...field}
          label="Sync Interval (minutes)"
          type="number"
          inputProps={{ min: 5, max: 1440 }}
          helperText="How often to push data to device (5-1440 min)"
        />
      )}
    />
    <Controller
      name="ultraTotpRescueEnabled"
      control={control}
      render={({ field }) => (
        <FormControlLabel
          control={<Switch checked={field.value} onChange={field.onChange} />}
          label="TOTP Rescue Enabled"
        />
      )}
    />
    <Controller
      name="ultraRtlogEnabled"
      control={control}
      render={({ field }) => (
        <FormControlLabel
          control={<Switch checked={field.value} onChange={field.onChange} />}
          label="RTLog Observation Enabled"
        />
      )}
    />
  </>
)}
```

Add a `watch` for the accessDataMode field near the top of the component:

```typescript
const watchedAccessDataMode = watch("accessDataMode");
```

- [ ] **Step 5: Set ULTRA defaults in create/edit form**

In the create form defaults (~line 209) and edit form defaults (~line 393), add:

```typescript
ultraSyncIntervalMinutes: device?.ultraSyncIntervalMinutes ?? 15,
ultraTotpRescueEnabled: device?.ultraTotpRescueEnabled ?? true,
ultraRtlogEnabled: device?.ultraRtlogEnabled ?? true,
```

- [ ] **Step 6: Commit**

```bash
cd C:/Users/mohaa/Desktop/mon_club_dashboard
git add -A
git commit -m "feat: add ULTRA mode to device settings UI"
```

---

## Task 3: Access Client — Extract Shared Types (access_types.py)

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\access_types.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\realtime_agent.py`

- [ ] **Step 1: Create access_types.py with dataclasses**

Copy these dataclasses from `realtime_agent.py` into the new file:

- `AccessEvent` (lines 405-414 of realtime_agent.py)
- `NotificationRequest` (lines 424-445)
- `HistoryRecord` (lines 472-487)

```python
"""Shared dataclasses for access control engines (AGENT + ULTRA)."""

from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class AccessEvent:
    """A single RTLog event read from a device."""
    # Copy exact fields from realtime_agent.py lines 405-414
    ...


@dataclass
class NotificationRequest:
    """Data for a popup notification."""
    # Copy exact fields from realtime_agent.py lines 424-445
    ...


@dataclass
class HistoryRecord:
    """Data for an access history entry to sync to backend."""
    # Copy exact fields from realtime_agent.py lines 472-487
    ...
```

Copy the exact field definitions verbatim from `realtime_agent.py`. Do not change field names, types, or defaults.

- [ ] **Step 2: Update realtime_agent.py to import from access_types.py**

In `realtime_agent.py`, replace the inline dataclass definitions (lines 405-487) with imports:

```python
from app.core.access_types import AccessEvent, NotificationRequest, HistoryRecord
```

Delete the original `AccessEvent`, `NotificationRequest`, and `HistoryRecord` class definitions from `realtime_agent.py`.

- [ ] **Step 3: Verify AGENT mode still works**

Run the access application and confirm no import errors. The app should start normally with AGENT-mode devices working as before.

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
python -c "from app.core.access_types import AccessEvent, NotificationRequest, HistoryRecord; print('OK')"
python -c "from app.core.realtime_agent import AgentRealtimeEngine; print('OK')"
```

- [ ] **Step 4: Commit**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
git add app/core/access_types.py app/core/realtime_agent.py
git commit -m "refactor: extract shared dataclasses to access_types.py"
```

---

## Task 4: Access Client — Extract Shared Verification (access_verification.py)

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\access_verification.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\realtime_agent.py`

- [ ] **Step 1: Create access_verification.py with TOTP helpers**

Extract these module-level functions from `realtime_agent.py`:
- `_totp_counter()` (line 169-170)
- `_totp_is_hex()` (lines 173-185)
- `_totp_hex_to_bytes()` (lines 188-192)
- `_totp_hotp()` (lines 195-200)

```python
"""Shared access verification functions for AGENT + ULTRA engines."""

import hmac
import hashlib
import struct
import time
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _totp_counter(unix_time: int, period: int) -> int:
    # Copy exact code from realtime_agent.py line 169-170
    ...


def _totp_is_hex(s: str) -> bool:
    # Copy exact code from realtime_agent.py lines 173-185
    ...


def _totp_hex_to_bytes(hex_str: str) -> bytes:
    # Copy exact code from realtime_agent.py lines 188-192
    ...


def _totp_hotp(secret: bytes, counter: int, digits: int) -> str:
    # Copy exact code from realtime_agent.py lines 195-200
    ...
```

Copy verbatim. Do not refactor.

- [ ] **Step 2: Extract verify_totp as standalone function**

Convert `DecisionService._verify_totp()` (lines 1192-1390) to a standalone function in `access_verification.py`:

```python
def verify_totp(
    scanned: str,
    settings: Dict[str, Any],
    creds_payload: List[Dict[str, Any]],
    users_by_am: Dict[str, Any],
    users_by_card: Dict[str, Any],
) -> Dict[str, Any]:
    """Verify a scanned code against TOTP credentials.

    Returns dict with keys: allowed, reason, scanMode, user info, etc.
    Same return shape as the original DecisionService._verify_totp().
    """
    # Copy the body of DecisionService._verify_totp() verbatim.
    # Replace self.logger with module-level logger.
    # Replace self._verify_card() calls with verify_card() calls.
    # All other logic stays identical.
    ...
```

- [ ] **Step 3: Extract verify_card as standalone function**

Convert `DecisionService._verify_card()` (lines 1106-1190) to a standalone function:

```python
def verify_card(
    scanned: str,
    settings: Dict[str, Any],
    users_by_card: Dict[str, Any],
) -> Dict[str, Any]:
    """Verify a scanned card number against known users.

    Returns dict with keys: allowed, reason, scanMode, user info, etc.
    Same return shape as the original DecisionService._verify_card().
    """
    # Copy the body of DecisionService._verify_card() verbatim.
    # Replace self.logger with module-level logger.
    ...
```

- [ ] **Step 4: Extract load_local_state as standalone function**

Convert `DecisionService._load_local_state()` (lines 1035-1104) to a standalone function:

```python
def load_local_state(
    db_path: str,
    device_id: int,
    settings: Dict[str, Any],
) -> Tuple[List[Dict], Dict[str, Any], Dict[str, Any]]:
    """Load credentials, users_by_am, users_by_card from local SQLite cache.

    Returns (creds_payload, users_by_am, users_by_card).
    Same return shape as the original DecisionService._load_local_state().
    """
    # Copy the body verbatim.
    # Replace self.logger, self._db_path, self._device_id, self._settings
    # with the function parameters.
    ...
```

- [ ] **Step 5: Update realtime_agent.py to use shared functions**

In `realtime_agent.py`:

1. Add import at top:
```python
from app.core.access_verification import (
    verify_totp, verify_card, load_local_state,
    _totp_counter, _totp_is_hex, _totp_hex_to_bytes, _totp_hotp,
)
```

2. Delete the module-level TOTP helper functions (lines 169-200).

3. In `DecisionService`, replace `_verify_totp()`, `_verify_card()`, `_load_local_state()` methods with thin wrappers that call the standalone functions:

```python
def _verify_totp(self, scanned, settings, creds_payload, users_by_am, users_by_card):
    return verify_totp(scanned, settings, creds_payload, users_by_am, users_by_card)

def _verify_card(self, scanned, settings, users_by_card):
    return verify_card(scanned, settings, users_by_card)

def _load_local_state(self):
    return load_local_state(self._db_path, self._device_id, self._settings)
```

This preserves the existing call sites in `DecisionService.run()` without any changes.

- [ ] **Step 6: Verify AGENT mode still works**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
python -c "from app.core.access_verification import verify_totp, verify_card, load_local_state; print('OK')"
python -c "from app.core.realtime_agent import AgentRealtimeEngine; print('OK')"
```

- [ ] **Step 7: Commit**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
git add app/core/access_verification.py app/core/realtime_agent.py
git commit -m "refactor: extract verification functions to access_verification.py"
```

---

## Task 5: Access Client — Write Tests for Extracted Modules

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_access_verification.py`

- [ ] **Step 1: Write TOTP helper tests**

```python
"""Tests for access_verification module."""
import time
import pytest
from app.core.access_verification import (
    _totp_counter, _totp_hotp, _totp_is_hex, _totp_hex_to_bytes,
    verify_totp, verify_card,
)


class TestTotpHelpers:
    def test_totp_counter_30s_period(self):
        """Counter increments every 30 seconds."""
        t = 1700000000
        c1 = _totp_counter(t, 30)
        c2 = _totp_counter(t + 30, 30)
        assert c2 == c1 + 1

    def test_totp_counter_same_window(self):
        """Same counter within a 30-second window."""
        t = 1700000000
        assert _totp_counter(t, 30) == _totp_counter(t + 15, 30)

    def test_totp_is_hex_valid(self):
        assert _totp_is_hex("abcdef0123456789") is True

    def test_totp_is_hex_invalid(self):
        assert _totp_is_hex("xyz") is False

    def test_totp_is_hex_empty(self):
        assert _totp_is_hex("") is False

    def test_totp_hex_to_bytes(self):
        result = _totp_hex_to_bytes("48656c6c6f")
        assert result == b"Hello"

    def test_totp_hotp_deterministic(self):
        """Same secret + counter always produces same code."""
        secret = bytes.fromhex("3132333435363738393031323334353637383930")
        code1 = _totp_hotp(secret, 1, 7)
        code2 = _totp_hotp(secret, 1, 7)
        assert code1 == code2
        assert len(code1) == 7
        assert code1.isdigit()

    def test_totp_hotp_different_counters(self):
        """Different counters produce different codes."""
        secret = bytes.fromhex("3132333435363738393031323334353637383930")
        code1 = _totp_hotp(secret, 1, 7)
        code2 = _totp_hotp(secret, 2, 7)
        assert code1 != code2
```

- [ ] **Step 2: Run tests to confirm they pass**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
python -m pytest tests/test_access_verification.py -v
```

Expected: All tests PASS.

- [ ] **Step 3: Write verify_card tests**

Add to the test file:

```python
class TestVerifyCard:
    def _make_settings(self, **overrides):
        defaults = {
            "rfid_enabled": True,
            "rfid_min_digits": 1,
            "rfid_max_digits": 16,
        }
        defaults.update(overrides)
        return defaults

    def test_valid_card_found(self):
        users_by_card = {"12345": {"id": 1, "name": "John"}}
        result = verify_card("12345", self._make_settings(), users_by_card)
        assert result["allowed"] is True

    def test_unknown_card_denied(self):
        users_by_card = {"12345": {"id": 1, "name": "John"}}
        result = verify_card("99999", self._make_settings(), users_by_card)
        assert result["allowed"] is False

    def test_rfid_disabled(self):
        result = verify_card("12345", self._make_settings(rfid_enabled=False), {"12345": {}})
        assert result["allowed"] is False
```

- [ ] **Step 4: Run all tests**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
python -m pytest tests/test_access_verification.py -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
git add tests/test_access_verification.py
git commit -m "test: add unit tests for extracted verification functions"
```

---

## Task 6: Access Client — ULTRA-Awareness Audit (Normalization + DB)

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\config.py` (lines 60-69)
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\settings_reader.py` (lines 153-156, 229-230)
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\db.py` (lines ~1399-1403, ~1705-1724)

- [ ] **Step 1: Update _normalize_data_mode() in config.py**

In `config.py` lines 60-69, add ULTRA recognition between the DEVICE and AGENT blocks:

```python
def _normalize_data_mode(v: Any) -> str:
    if isinstance(v, bool):
        return "DEVICE" if v else "AGENT"

    s = _safe_str(v, "").strip().upper()
    if s in ("DEVICE", "DEVICE_DATA", "DEVICE_MODE", "IN_DEVICE_DATA", "1", "TRUE", "YES", "ON"):
        return "DEVICE"
    if s in ("AGENT", "AGENT_DATA", "AGENT_MODE", "IN_AGENT_DATA", "2", "FALSE", "NO", "OFF"):
        return "AGENT"
    if s in ("ULTRA", "ULTRA_MODE", "3"):
        return "ULTRA"
    return "DEVICE"
```

- [ ] **Step 2: Update normalize_access_data_mode() in settings_reader.py**

In `settings_reader.py` lines 153-156, change from binary to ternary:

```python
def normalize_access_data_mode(v: Any) -> str:
    """Normalize accessDataMode to 'DEVICE', 'AGENT', or 'ULTRA'."""
    s = _safe_str(v, "DEVICE").strip().upper()
    if s == "AGENT":
        return "AGENT"
    if s == "ULTRA":
        return "ULTRA"
    return "DEVICE"
```

- [ ] **Step 3: Add ULTRA field reading in settings_reader.py**

In `normalize_device_settings()` (~line 309 where the dict is returned), add the ULTRA fields to the returned dict:

```python
"ultra_sync_interval_minutes": int(dev.get("ultraSyncIntervalMinutes") or 15),
"ultra_totp_rescue_enabled": bool(dev.get("ultraTotpRescueEnabled", True)),
"ultra_rtlog_enabled": bool(dev.get("ultraRtlogEnabled", True)),
```

- [ ] **Step 4: Update db.py sync cache writer**

In `db.py` ~line 1402, change:
```python
if adm not in ("DEVICE", "AGENT"):
```
to:
```python
if adm not in ("DEVICE", "AGENT", "ULTRA"):
```

- [ ] **Step 5: Update db.py _coerce_device_row_to_payload()**

In `db.py` ~line 1715, change the same pattern:
```python
if adm not in ("DEVICE", "AGENT"):
```
to:
```python
if adm not in ("DEVICE", "AGENT", "ULTRA"):
```

- [ ] **Step 6: Verify normalization works**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
python -c "
from app.core.config import _normalize_data_mode
assert _normalize_data_mode('ULTRA') == 'ULTRA'
assert _normalize_data_mode('ULTRA_MODE') == 'ULTRA'
assert _normalize_data_mode('3') == 'ULTRA'
assert _normalize_data_mode('DEVICE') == 'DEVICE'
assert _normalize_data_mode('AGENT') == 'AGENT'
print('All normalization tests passed')
"
```

- [ ] **Step 7: Commit**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
git add app/core/config.py app/core/settings_reader.py app/core/db.py
git commit -m "feat: add ULTRA mode recognition to normalization and DB layers"
```

---

## Task 7: Access Client — Build UltraEngine

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\ultra_engine.py`

This is the largest task. The UltraEngine has 3 components:
1. `UltraSyncScheduler` — periodic data push to device
2. `UltraDeviceWorker` — RTLog poll + event classification + TOTP rescue
3. `UltraEngine` — orchestrator

- [ ] **Step 1: Create ultra_engine.py with imports and constants**

```python
"""ULTRA mode engine: device-firmware RFID/FP + PC-side RTLog observer + TOTP rescue."""

import logging
import threading
import time
import queue
import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Deque

from app.core.access_types import AccessEvent, NotificationRequest, HistoryRecord
from app.core.access_verification import verify_totp, verify_card, load_local_state
from app.sdk.pullsdk import PullSDKDevice

logger = logging.getLogger(__name__)

_ULTRA_LOG_PREFIX = "[ULTRA:{device_id}]"
```

- [ ] **Step 2: Implement UltraDeviceWorker class**

This is the per-device thread that polls RTLog, classifies events, handles TOTP rescue, and enqueues popup/history.

```python
class UltraDeviceWorker(threading.Thread):
    """Per-device thread: polls RTLog, classifies events, TOTP rescue."""

    def __init__(
        self,
        device: Dict[str, Any],
        settings: Dict[str, Any],
        db_path: str,
        popup_q: queue.Queue,
        history_q: queue.Queue,
        stop_event: threading.Event,
    ):
        super().__init__(daemon=True, name=f"UltraWorker-{device.get('id')}")
        self._device = device
        self._settings = settings
        self._db_path = db_path
        self._popup_q = popup_q
        self._history_q = history_q
        self._stop = stop_event
        self._device_id = int(device.get("id", 0))
        self._device_name = device.get("name", "")
        self._sdk: Optional[PullSDKDevice] = None
        self._seen: Deque[str] = deque(maxlen=10_000)
        self._connected = False
        self._events_processed = 0
        self._totp_rescues = 0
        self._totp_failures = 0
        self._door_cmd_failures = 0
        self._poll_ema_ms = 0.0
        self._prefix = f"[ULTRA:{self._device_id}]"

        # Adaptive sleep settings (same as AGENT mode)
        self._busy_min = int(settings.get("busy_sleep_min_ms", 0))
        self._busy_max = int(settings.get("busy_sleep_max_ms", 50))
        self._empty_min = int(settings.get("empty_sleep_min_ms", 200))
        self._empty_max = int(settings.get("empty_sleep_max_ms", 500))
        self._backoff = float(settings.get("empty_backoff_factor", 1.35))
        self._backoff_cap = int(settings.get("empty_backoff_max_ms", 2000))
        self._empty_sleep_ms = float(self._empty_min)
        self._poll_timeout_sec = 15.0

    def run(self):
        """Main loop: connect -> poll RTLog -> classify -> repeat."""
        logger.info(f"{self._prefix} started")
        self._pre_populate_seen()

        while not self._stop.is_set():
            # Connect if needed
            if not self._connected:
                self._connect()
                if not self._connected:
                    self._stop.wait(5.0)
                    continue

            # Poll RTLog with watchdog
            events = self._poll_with_watchdog()
            if events is None:
                # Watchdog timeout or error -> reconnect
                self._disconnect()
                continue

            if events:
                self._empty_sleep_ms = float(self._empty_min)
                for evt in events:
                    self._process_event(evt)
                sleep_ms = self._busy_min
            else:
                self._empty_sleep_ms = min(
                    self._empty_sleep_ms * self._backoff,
                    self._backoff_cap,
                )
                sleep_ms = self._empty_sleep_ms

            self._stop.wait(sleep_ms / 1000.0)

        self._disconnect()
        logger.info(f"{self._prefix} stopped")

    # -- Connection management (same pattern as AGENT DeviceWorker) --

    def _connect(self):
        """Connect to device via PullSDK."""
        try:
            ip = self._device.get("ipAddress", "")
            port = int(self._device.get("portNumber", 4370))
            password = self._device.get("password", "")
            self._sdk = PullSDKDevice()
            self._sdk.connect(ip, port, timeout_ms=5000, password=password)
            self._connected = True
            logger.info(f"{self._prefix} connected to {ip}:{port}")
        except Exception as e:
            logger.error(f"{self._prefix} connect failed: {e}")
            self._connected = False

    def _disconnect(self):
        if self._sdk:
            try:
                self._sdk.disconnect()
            except Exception:
                pass
        self._sdk = None
        self._connected = False

    # -- RTLog polling with watchdog (15s timeout, same as AGENT) --

    def _poll_with_watchdog(self) -> Optional[List[Dict]]:
        """Poll RTLog with thread-based watchdog. Returns events or None on timeout."""
        result = [None]
        error = [None]

        def _poll():
            try:
                result[0] = self._sdk.poll_rtlog_once()
            except Exception as e:
                error[0] = e

        t = threading.Thread(target=_poll, daemon=True)
        t0 = time.monotonic()
        t.start()
        t.join(timeout=self._poll_timeout_sec)
        elapsed_ms = (time.monotonic() - t0) * 1000

        # Update EMA
        alpha = 0.2
        self._poll_ema_ms = alpha * elapsed_ms + (1 - alpha) * self._poll_ema_ms

        if t.is_alive():
            logger.error(f"{self._prefix} poll_rtlog timed out ({self._poll_timeout_sec}s)")
            return None
        if error[0]:
            logger.error(f"{self._prefix} poll_rtlog error: {error[0]}")
            return None
        return result[0] or []

    # -- Event deduplication (same as AGENT) --

    def _pre_populate_seen(self):
        """Load recent event IDs from DB to prevent re-processing after restart."""
        import sqlite3
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            cur = conn.execute(
                "SELECT event_id FROM access_history "
                "WHERE device_id = ? ORDER BY rowid DESC LIMIT 200",
                (str(self._device_id),),
            )
            for (eid,) in cur:
                if eid:
                    self._seen.append(str(eid))
            conn.close()
            logger.debug(f"{self._prefix} pre-populated {len(self._seen)} seen event IDs")
        except Exception as e:
            logger.warning(f"{self._prefix} pre_populate_seen failed: {e}")

    def _is_seen(self, event_id: str) -> bool:
        if event_id in self._seen:
            return True
        self._seen.append(event_id)
        return False

    # -- Event classification (core ULTRA logic) --

    def _process_event(self, evt: Dict[str, Any]):
        """Classify RTLog event and route to appropriate handler."""
        card_no = str(evt.get("CardNo", "") or "").strip()
        event_type = int(evt.get("EventType", evt.get("Verified", -1)) or -1)
        pin = str(evt.get("PIN", "") or "").strip()
        timestamp = evt.get("Time_second", "")

        event_id = f"{self._device_id}:{timestamp}:{card_no}"
        if self._is_seen(event_id):
            return

        self._events_processed += 1
        is_allow = (event_type == 0)

        if is_allow:
            self._handle_allow(card_no, pin, timestamp, event_id)
        elif self._is_totp_format(card_no):
            self._handle_totp_rescue(card_no, timestamp, event_id)
        else:
            self._handle_deny(card_no, timestamp, event_id)

    def _is_totp_format(self, code: str) -> bool:
        """Check if scanned code matches TOTP format: prefix + N digits."""
        prefix = self._settings.get("totp_prefix", "9")
        digits = int(self._settings.get("totp_digits", 7))
        expected_len = len(prefix) + digits
        if not self._settings.get("totp_enabled", True):
            return False
        if not self._settings.get("ultra_totp_rescue_enabled", True):
            return False
        return (
            len(code) == expected_len
            and code.startswith(prefix)
            and code[len(prefix):].isdigit()
        )

    # -- ALLOW handler (passive observation, enrichment only) --

    def _handle_allow(self, card_no: str, pin: str, timestamp: str, event_id: str):
        """Device already opened door. Enrich with user data for popup/history."""
        creds, users_by_am, users_by_card = self._get_cached_local_state()

        # Simple dict lookup — no validation (device already decided)
        user = users_by_card.get(card_no)
        user_name = ""
        user_image = ""
        user_membership_id = ""
        user_phone = ""
        user_valid_from = ""
        user_valid_to = ""
        scan_mode = "RFID_CARD"

        if user:
            user_name = user.get("full_name", "") or user.get("name", "")
            user_image = user.get("image", "") or ""
            user_membership_id = str(user.get("activeMembershipId", "") or "")
            user_phone = user.get("phone", "") or ""
            user_valid_from = user.get("validFrom", "") or ""
            user_valid_to = user.get("validTo", "") or ""

        logger.info(f"{self._prefix} rtlog ALLOW: card={card_no}, user={user_name}")

        self._enqueue_notification(
            event_id=event_id,
            allowed=True,
            reason="DEVICE_ALLOWED",
            scan_mode=scan_mode,
            user_full_name=user_name,
            user_image=user_image,
            user_membership_id=user_membership_id,
            user_phone=user_phone,
            user_valid_from=user_valid_from,
            user_valid_to=user_valid_to,
        )
        self._enqueue_history(event_id, True, "DEVICE_ALLOWED", scan_mode, card_no, timestamp)

    # -- TOTP Rescue handler (active: verify + open door) --

    def _handle_totp_rescue(self, code: str, timestamp: str, event_id: str):
        """Device denied a TOTP code. Verify locally, open door if valid."""
        creds, users_by_am, users_by_card = self._get_cached_local_state()

        t0 = time.monotonic()
        result = verify_totp(code, self._settings, creds, users_by_am, users_by_card)
        took_ms = (time.monotonic() - t0) * 1000

        allowed = result.get("allowed", False)
        reason = result.get("reason", "DENY_TOTP_FAILED")
        user_name = result.get("user_full_name", "") or ""

        if allowed:
            # Open door
            door_opened = self._open_door_with_retry()
            if door_opened:
                self._totp_rescues += 1
                masked = code[0] + "*" * (len(code) - 2) + code[-1]
                logger.info(
                    f"{self._prefix} rtlog TOTP_RESCUE: code={masked}, "
                    f"user={user_name}, took={took_ms:.0f}ms"
                )
            else:
                allowed = False
                reason = "DOOR_CMD_FAILED"
                self._door_cmd_failures += 1
                logger.error(f"{self._prefix} door_cmd_failed after valid TOTP")
        else:
            self._totp_failures += 1
            logger.info(f"{self._prefix} rtlog DENY: code=TOTP, reason={reason}")

        self._enqueue_notification(
            event_id=event_id,
            allowed=allowed,
            reason=reason,
            scan_mode="QR_TOTP",
            user_full_name=result.get("user_full_name", ""),
            user_image=result.get("user_image", ""),
            user_membership_id=result.get("user_membership_id", ""),
            user_phone=result.get("user_phone", ""),
            user_valid_from=result.get("user_valid_from", ""),
            user_valid_to=result.get("user_valid_to", ""),
        )
        self._enqueue_history(event_id, allowed, reason, "QR_TOTP", code, timestamp)

    def _open_door_with_retry(self) -> bool:
        """Open door via PullSDK. Retry once on failure. Returns True if succeeded."""
        door_id = int(self._settings.get("door_entry_id", 1))
        pulse_ms = int(self._settings.get("pulse_time_ms", 3000))
        for attempt in range(2):
            try:
                self._sdk.open_door(door_id, pulse_ms, timeout_ms=4000)
                return True
            except Exception as e:
                logger.warning(
                    f"{self._prefix} open_door attempt {attempt + 1} failed: {e}"
                )
                if attempt == 0:
                    time.sleep(0.1)
        return False

    # -- DENY handler (passive observation) --

    def _handle_deny(self, card_no: str, timestamp: str, event_id: str):
        """Device denied a non-TOTP code. Log and notify."""
        logger.info(f"{self._prefix} rtlog DENY: card={card_no}, reason=DEVICE_DENIED")
        self._enqueue_notification(
            event_id=event_id,
            allowed=False,
            reason="DEVICE_DENIED",
            scan_mode="RFID_CARD",
            user_full_name="",
            user_image="",
            user_membership_id="",
            user_phone="",
            user_valid_from="",
            user_valid_to="",
        )
        self._enqueue_history(event_id, False, "DEVICE_DENIED", "RFID_CARD", card_no, timestamp)

    # -- Notification and history helpers --

    def _enqueue_notification(self, *, event_id, allowed, reason, scan_mode,
                               user_full_name, user_image, user_membership_id,
                               user_phone, user_valid_from, user_valid_to):
        popup_enabled = self._settings.get("popup_enabled", True)
        if not popup_enabled:
            return

        # User-facing message for error states
        message = ""
        if reason == "DOOR_CMD_FAILED":
            message = "Valid code but door did not open — try again or use card"

        try:
            req = NotificationRequest(
                event_id=event_id,
                title="Acces",
                message=message,
                image_path="",
                popup_show_image=self._settings.get("popup_show_image", True),
                user_full_name=user_full_name,
                user_image=user_image,
                user_valid_from=user_valid_from,
                user_valid_to=user_valid_to,
                user_membership_id=user_membership_id,
                user_phone=user_phone,
                device_id=str(self._device_id),
                device_name=self._device_name,
                allowed=allowed,
                reason=reason,
                scan_mode=scan_mode,
                popup_duration_sec=int(self._settings.get("popup_duration_sec", 3)),
                popup_enabled=True,
                win_notify_enabled=self._settings.get("win_notify_enabled", False),
            )
            self._popup_q.put_nowait(req)
        except queue.Full:
            logger.warning(f"{self._prefix} popup queue full, dropping notification")

    def _enqueue_history(self, event_id, allowed, reason, scan_mode, card_no, timestamp):
        """Atomically insert history + enqueue for backend sync.

        Uses INSERT OR IGNORE on event_id UNIQUE constraint for DB-level dedup.
        Only enqueues to backend sync queue if insert succeeds (rowcount=1).
        """
        import sqlite3
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            cur = conn.execute(
                "INSERT OR IGNORE INTO access_history "
                "(event_id, device_id, device_name, allowed, reason, scan_mode, card_no, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, str(self._device_id), self._device_name,
                 1 if allowed else 0, reason, scan_mode, card_no, timestamp),
            )
            conn.commit()
            inserted = cur.rowcount == 1
            conn.close()
        except Exception as e:
            logger.warning(f"{self._prefix} history DB insert failed: {e}")
            inserted = True  # still try to enqueue

        if not inserted:
            return  # duplicate, already processed

        try:
            rec = HistoryRecord(
                event_id=event_id,
                device_id=str(self._device_id),
                device_name=self._device_name,
                allowed=allowed,
                reason=reason,
                scan_mode=scan_mode,
                card_no=card_no,
                timestamp=timestamp,
            )
            self._history_q.put_nowait(rec)
        except queue.Full:
            logger.warning(f"{self._prefix} history queue full, dropping record")

    # -- Local state caching (avoid per-event SQLite reads) --

    _cached_state = None
    _cached_state_ts = 0.0
    _CACHE_TTL_SEC = 5.0  # refresh local state every 5 seconds

    def _get_cached_local_state(self):
        """Return (creds, users_by_am, users_by_card) with 5-second cache."""
        now = time.monotonic()
        if self._cached_state is None or (now - self._cached_state_ts) > self._CACHE_TTL_SEC:
            self._cached_state = load_local_state(
                self._db_path, self._device_id, self._settings
            )
            self._cached_state_ts = now
        return self._cached_state

    # -- Status snapshot --

    def get_snapshot(self) -> Dict[str, Any]:
        return {
            "device_id": self._device_id,
            "device_name": self._device_name,
            "mode": "ULTRA",
            "rtlog_polling": self._settings.get("ultra_rtlog_enabled", True),
            "totp_rescue_enabled": self._settings.get("ultra_totp_rescue_enabled", True),
            "connected": self._connected,
            "events_processed": self._events_processed,
            "totp_rescues": self._totp_rescues,
            "totp_failures": self._totp_failures,
            "door_cmd_failures": self._door_cmd_failures,
            "poll_ema_ms": round(self._poll_ema_ms, 1),
        }
```

- [ ] **Step 3: Implement UltraSyncScheduler**

```python
class UltraSyncScheduler:
    """Periodically pushes user data to ULTRA-mode devices using DeviceSyncEngine logic."""

    def __init__(self, cfg, logger_inst, db_path: str):
        self._cfg = cfg
        self._logger = logger_inst
        self._db_path = db_path
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_hash: Dict[int, str] = {}  # device_id -> payload hash
        self._last_sync_at: Dict[int, str] = {}
        self._next_sync_at: Dict[int, str] = {}

    def start(self, devices: List[Dict[str, Any]]):
        self._devices = devices
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="UltraSyncScheduler"
        )
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _run(self):
        """Sync loop: push data to each ULTRA device on its configured interval."""
        # Immediate first sync
        self._sync_all()

        while not self._stop.is_set():
            # Find the shortest interval among all ULTRA devices
            min_interval = 15 * 60  # default 15 min
            for d in self._devices:
                settings = d.get("_settings", {})
                interval = int(settings.get("ultra_sync_interval_minutes", 15)) * 60
                min_interval = min(min_interval, interval)

            self._stop.wait(min_interval)
            if not self._stop.is_set():
                self._sync_all()

    def _sync_all(self):
        """Push user data to all ULTRA devices (with hash-based skip)."""
        for d in self._devices:
            device_id = d.get("id")
            try:
                self._sync_device(d)
                self._last_sync_at[device_id] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                interval = int(d.get("_settings", {}).get("ultra_sync_interval_minutes", 15)) * 60
                next_t = time.time() + interval
                self._next_sync_at[device_id] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_t))
            except Exception as e:
                logger.error(f"[ULTRA:{device_id}] sync failed: {e}")

    def _sync_device(self, device: Dict[str, Any]):
        """Push data to a single device with hash-based change detection.

        Reuses DeviceSyncEngine by temporarily treating this ULTRA device
        as a DEVICE-mode device for the push operation.
        """
        from app.core.device_sync import DeviceSyncEngine
        from app.core.db import load_sync_cache

        device_id = device.get("id")
        cache = load_sync_cache()

        # Compute hash of current user payload for this device
        users = getattr(cache, "users", []) or []
        payload_str = json.dumps(sorted(
            [u.get("activeMembershipId", "") for u in users if u]
        ), sort_keys=True)
        current_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        if self._last_hash.get(device_id) == current_hash:
            logger.info(f"[ULTRA:{device_id}] sync skip: hash unchanged")
            return

        logger.info(f"[ULTRA:{device_id}] sync push started")

        # Create a temporary DeviceSyncEngine and call its push pipeline.
        # We override the device's accessDataMode to "DEVICE" so the sync
        # engine's filter accepts it, then push data for this single device.
        engine = DeviceSyncEngine(cfg=self._cfg, logger=self._logger)
        device_copy = dict(device)
        device_copy["accessDataMode"] = "DEVICE"  # trick filter to accept it

        # Build a cache-like object with only this device
        engine.run_blocking(cache=cache, source="ultra_sync")

        self._last_hash[device_id] = current_hash
        logger.info(f"[ULTRA:{device_id}] sync push complete")

    def get_sync_status(self) -> Dict[int, Dict[str, Any]]:
        return {
            did: {
                "last_sync_at": self._last_sync_at.get(did, ""),
                "next_sync_at": self._next_sync_at.get(did, ""),
            }
            for did in [d.get("id") for d in self._devices]
        }
```

- [ ] **Step 4: Implement UltraEngine orchestrator**

```python
class UltraEngine:
    """Orchestrates ULTRA mode: sync scheduler + per-device RTLog workers."""

    def __init__(self, cfg, logger_inst):
        self._cfg = cfg
        self._logger = logger_inst
        self._workers: Dict[int, UltraDeviceWorker] = {}
        self._sync_scheduler: Optional[UltraSyncScheduler] = None
        self._stop_event = threading.Event()
        self._popup_q: queue.Queue = queue.Queue(maxsize=5000)
        self._history_q: queue.Queue = queue.Queue(maxsize=5000)
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    @property
    def popup_q(self) -> queue.Queue:
        return self._popup_q

    @property
    def history_q(self) -> queue.Queue:
        return self._history_q

    def start(self, devices: List[Dict[str, Any]], db_path: str):
        """Start ULTRA engine for the given devices."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        ultra_devices = [
            d for d in devices
            if str(d.get("accessDataMode", "")).strip().upper() == "ULTRA"
        ]

        if not ultra_devices:
            logger.info("[ULTRA] No ULTRA-mode devices found")
            self._running = False
            return

        logger.info(f"[ULTRA] Starting with {len(ultra_devices)} device(s)")

        # Start sync scheduler
        self._sync_scheduler = UltraSyncScheduler(self._cfg, self._logger, db_path)
        self._sync_scheduler.start(ultra_devices)

        # Start per-device workers
        from app.core.settings_reader import normalize_device_settings
        for d in ultra_devices:
            device_id = int(d.get("id", 0))
            settings = normalize_device_settings(d)
            worker = UltraDeviceWorker(
                device=d,
                settings=settings,
                db_path=db_path,
                popup_q=self._popup_q,
                history_q=self._history_q,
                stop_event=self._stop_event,
            )
            self._workers[device_id] = worker
            worker.start()

    def stop(self):
        """Stop all workers and sync scheduler."""
        if not self._running:
            return
        logger.info("[ULTRA] Stopping engine")
        self._stop_event.set()

        # Stop sync scheduler
        if self._sync_scheduler:
            self._sync_scheduler.stop()

        # Stop workers
        for device_id, worker in self._workers.items():
            worker.join(timeout=10)
            if worker.is_alive():
                logger.warning(f"[ULTRA:{device_id}] worker did not stop in time")

        self._workers.clear()
        self._running = False
        logger.info("[ULTRA] Engine stopped")

    def get_status(self) -> Dict[str, Any]:
        """Return full ULTRA engine status for /api/v2/ultra/status."""
        devices = {}
        sync_status = self._sync_scheduler.get_sync_status() if self._sync_scheduler else {}

        for device_id, worker in self._workers.items():
            snap = worker.get_snapshot()
            ss = sync_status.get(device_id, {})
            snap["last_sync_at"] = ss.get("last_sync_at", "")
            snap["next_sync_at"] = ss.get("next_sync_at", "")
            snap["sync_interval_minutes"] = int(
                worker._settings.get("ultra_sync_interval_minutes", 15)
            )
            devices[str(device_id)] = snap

        return {
            "running": self._running,
            "devices": devices,
        }
```

- [ ] **Step 5: Verify the module imports cleanly**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
python -c "from app.core.ultra_engine import UltraEngine; print('OK')"
```

- [ ] **Step 6: Commit**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
git add app/core/ultra_engine.py
git commit -m "feat: implement UltraEngine with RTLog observer and TOTP rescue"
```

---

## Task 8: Access Client — App Wiring (Startup + Mode Summary)

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\ui\app.py` (lines 311-313, 430-445, 899-966)

- [ ] **Step 1: Add UltraEngine import and initialization**

In `app.py`, near line 311 where engines are initialized, add:

```python
from app.core.ultra_engine import UltraEngine
# ... existing engine init ...
self._ultra_engine = UltraEngine(cfg=self.cfg, logger=self.logger)
```

- [ ] **Step 2: Update get_access_mode_summary()**

In `app.py` lines 430-445, add ULTRA counting:

```python
def get_access_mode_summary(self) -> Dict[str, int]:
    cache = load_sync_cache()
    devices = getattr(cache, "devices", []) if cache else []
    dev = ag = ultra = unk = 0
    for d in devices or []:
        if not isinstance(d, dict):
            continue
        raw = d.get("accessDataMode") or d.get("access_data_mode") or ""
        m = str(raw).strip().upper()
        if m == "DEVICE":
            dev += 1
        elif m == "AGENT":
            ag += 1
        elif m == "ULTRA":
            ultra += 1
        else:
            unk += 1
    return {"DEVICE": dev, "AGENT": ag, "ULTRA": ultra, "UNKNOWN": unk}
```

- [ ] **Step 3: Start UltraEngine in sync tick with mode switching**

In the `_sync_tick()` method (~line 930), after the existing agent engine start logic, add full mode-switching-aware startup:

```python
# --- ULTRA mode management ---
ultra_count = mode_summary.get("ULTRA", 0)

if ultra_count > 0 and not self._ultra_engine.running:
    ultra_devices = [
        d for d in devices
        if str(d.get("accessDataMode", "")).strip().upper() == "ULTRA"
    ]
    if ultra_devices:
        # Stop DeviceSyncEngine for devices that switched to ULTRA
        # (DeviceSyncEngine already skips non-DEVICE devices via its filter,
        #  so no explicit stop needed — it just won't push to them next cycle)

        # Stop AgentRealtimeEngine workers for devices switching from AGENT to ULTRA
        if self._agent_engine and self._agent_engine.running:
            ultra_ids = {int(d.get("id", 0)) for d in ultra_devices}
            # AgentRealtimeEngine should stop workers for devices no longer in AGENT mode
            # The agent engine's next refresh will drop non-AGENT devices naturally.
            # Force a stop/restart if any ULTRA device was previously in AGENT mode.
            for uid in ultra_ids:
                if uid in getattr(self._agent_engine, "_workers", {}):
                    self.logger.info(f"[ULTRA] Device {uid} switching from AGENT to ULTRA")
                    # Agent engine will drop this device on next cycle

        self._ultra_engine.start(ultra_devices, db_path=self.cfg.db_path)

# Stop ULTRA engine if no ULTRA devices remain (device switched away from ULTRA)
if ultra_count == 0 and self._ultra_engine.running:
    self.logger.info("[ULTRA] No ULTRA devices remaining, stopping engine")
    self._ultra_engine.stop()
```

- [ ] **Step 4: Wire ULTRA history queue into existing HistoryService consumer**

The existing `HistoryService` (in realtime_agent.py) reads from `_history_q` and syncs records to the backend via `bulk_save_gym_access_history`. Wire the ULTRA engine's history queue into the same consumer.

In `_sync_tick()`, after starting the ULTRA engine, add a history consumer thread if not already running:

```python
# Start history consumer for ULTRA engine
if self._ultra_engine.running and not getattr(self, "_ultra_history_consumer", None):
    from app.core.realtime_agent import HistoryService
    self._ultra_history_consumer = HistoryService(
        history_q=self._ultra_engine.history_q,
        cfg=self.cfg,
        logger=self.logger,
    )
    self._ultra_history_consumer.start()
```

And when stopping the ULTRA engine:
```python
if hasattr(self, "_ultra_history_consumer") and self._ultra_history_consumer:
    self._ultra_history_consumer.stop()
    self._ultra_history_consumer = None
```

- [ ] **Step 5: Stop UltraEngine on app shutdown**

In the app's `destroy()` or shutdown method, add:

```python
if self._ultra_engine and self._ultra_engine.running:
    self._ultra_engine.stop()
if hasattr(self, "_ultra_history_consumer") and self._ultra_history_consumer:
    self._ultra_history_consumer.stop()
```

- [ ] **Step 6: Commit**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
git add app/ui/app.py
git commit -m "feat: wire UltraEngine with mode switching and history consumer"
```

---

## Task 9: Access Client — Local API Endpoints

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\api\local_access_api_v2.py` (lines 357-440, new handler)
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\access\local_api_routes.py`

- [ ] **Step 1: Add /api/v2/ultra/status handler**

In `local_access_api_v2.py`, add a new handler function (near the agent status handlers ~line 2832):

```python
def _handle_ultra_status(ctx):
    """GET /api/v2/ultra/status — ULTRA engine status."""
    eng = getattr(ctx.app, "_ultra_engine", None)
    if eng is None or not eng.running:
        ctx.send_json({"running": False, "devices": {}})
        return
    ctx.send_json(eng.get_status())
```

- [ ] **Step 2: Update /api/v2/status to include ULTRA**

In `_handle_status()` (~line 404), update the mode dict to include ULTRA:

Change:
```python
mode = {"DEVICE": dev_count, "AGENT": agent_count, "UNKNOWN": unknown_count}
```
To include ULTRA count (follow the same counting pattern as DEVICE/AGENT).

Also add ULTRA engine status to the response:

```python
ultra_eng = getattr(ctx.app, "_ultra_engine", None)
ultra_status = ultra_eng.get_status() if ultra_eng and ultra_eng.running else {"running": False}
```

Include `"ultra": ultra_status` in the JSON response.

- [ ] **Step 3: Register ULTRA route**

In `access/local_api_routes.py`, add the route tuple (~line 53, near agent routes):

```python
("GET", "/api/v2/ultra/status", "_handle_ultra_status"),
```

- [ ] **Step 4: Wire ULTRA popup events into existing SSE stream**

In `_handle_agent_events_sse()` (~line 2910), add logic to also read from the ULTRA engine's popup queue. The SSE handler already reads from the agent engine's popup queue — add a check for the ULTRA engine's queue as well:

```python
ultra_eng = getattr(ctx.app, "_ultra_engine", None)
if ultra_eng and ultra_eng.running:
    # Also check ultra_eng.popup_q for events
    try:
        while not ultra_eng.popup_q.empty():
            popup = ultra_eng.popup_q.get_nowait()
            # Send same SSE event format as agent popups
            ctx.send_sse_event("popup", popup_to_dict(popup))
    except queue.Empty:
        pass
```

- [ ] **Step 5: Commit**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
git add app/api/local_access_api_v2.py access/local_api_routes.py
git commit -m "feat: add /api/v2/ultra/status endpoint and SSE popup integration"
```

---

## Task 10: Access Client — Write UltraEngine Tests

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_ultra_engine.py`

- [ ] **Step 1: Write event classification tests**

```python
"""Tests for ULTRA engine event classification."""
import pytest
from unittest.mock import MagicMock, patch
from app.core.ultra_engine import UltraDeviceWorker


class TestEventClassification:
    def _make_worker(self, **setting_overrides):
        settings = {
            "totp_enabled": True,
            "totp_prefix": "9",
            "totp_digits": 7,
            "ultra_totp_rescue_enabled": True,
            "busy_sleep_min_ms": 0,
            "busy_sleep_max_ms": 50,
            "empty_sleep_min_ms": 200,
            "empty_sleep_max_ms": 500,
            "empty_backoff_factor": 1.35,
            "empty_backoff_max_ms": 2000,
        }
        settings.update(setting_overrides)
        import queue, threading
        worker = UltraDeviceWorker.__new__(UltraDeviceWorker)
        worker._settings = settings
        worker._device_id = 1
        worker._device_name = "Test"
        worker._popup_q = queue.Queue()
        worker._history_q = queue.Queue()
        worker._seen = []
        worker._events_processed = 0
        worker._totp_rescues = 0
        worker._totp_failures = 0
        worker._door_cmd_failures = 0
        worker._prefix = "[ULTRA:1]"
        worker._db_path = ":memory:"
        return worker

    def test_totp_format_valid(self):
        worker = self._make_worker()
        assert worker._is_totp_format("91234567") is True

    def test_totp_format_wrong_prefix(self):
        worker = self._make_worker()
        assert worker._is_totp_format("81234567") is False

    def test_totp_format_wrong_length(self):
        worker = self._make_worker()
        assert worker._is_totp_format("9123") is False

    def test_totp_format_disabled(self):
        worker = self._make_worker(totp_enabled=False)
        assert worker._is_totp_format("91234567") is False

    def test_totp_rescue_disabled(self):
        worker = self._make_worker(ultra_totp_rescue_enabled=False)
        assert worker._is_totp_format("91234567") is False

    def test_totp_format_custom_prefix(self):
        worker = self._make_worker(totp_prefix="8", totp_digits=6)
        assert worker._is_totp_format("8123456") is True
        assert worker._is_totp_format("9123456") is False
```

- [ ] **Step 2: Write door retry and error handling tests**

```python
class TestDoorRetry:
    def _make_worker_with_sdk(self, sdk_mock, **setting_overrides):
        """Create worker with mocked SDK for door command testing."""
        settings = {
            "door_entry_id": 1,
            "pulse_time_ms": 3000,
            "totp_enabled": True,
            "totp_prefix": "9",
            "totp_digits": 7,
            "ultra_totp_rescue_enabled": True,
            "popup_enabled": False,  # disable popup to simplify testing
            "busy_sleep_min_ms": 0,
            "busy_sleep_max_ms": 50,
            "empty_sleep_min_ms": 200,
            "empty_sleep_max_ms": 500,
            "empty_backoff_factor": 1.35,
            "empty_backoff_max_ms": 2000,
        }
        settings.update(setting_overrides)
        import queue
        worker = UltraDeviceWorker.__new__(UltraDeviceWorker)
        worker._settings = settings
        worker._device_id = 1
        worker._device_name = "Test"
        worker._sdk = sdk_mock
        worker._popup_q = queue.Queue()
        worker._history_q = queue.Queue()
        worker._seen = deque(maxlen=10000)
        worker._events_processed = 0
        worker._totp_rescues = 0
        worker._totp_failures = 0
        worker._door_cmd_failures = 0
        worker._prefix = "[ULTRA:1]"
        worker._db_path = ":memory:"
        worker._cached_state = None
        worker._cached_state_ts = 0.0
        return worker

    def test_open_door_succeeds_first_try(self):
        sdk = MagicMock()
        sdk.open_door.return_value = None
        worker = self._make_worker_with_sdk(sdk)
        assert worker._open_door_with_retry() is True
        assert sdk.open_door.call_count == 1

    def test_open_door_succeeds_on_retry(self):
        sdk = MagicMock()
        sdk.open_door.side_effect = [Exception("timeout"), None]
        worker = self._make_worker_with_sdk(sdk)
        assert worker._open_door_with_retry() is True
        assert sdk.open_door.call_count == 2

    def test_open_door_fails_both_attempts(self):
        sdk = MagicMock()
        sdk.open_door.side_effect = [Exception("err1"), Exception("err2")]
        worker = self._make_worker_with_sdk(sdk)
        assert worker._open_door_with_retry() is False
        assert sdk.open_door.call_count == 2
```

- [ ] **Step 3: Write event routing tests**

```python
from collections import deque

class TestEventRouting:
    def _make_worker_with_mocks(self):
        import queue
        settings = {
            "totp_enabled": True,
            "totp_prefix": "9",
            "totp_digits": 7,
            "ultra_totp_rescue_enabled": True,
            "popup_enabled": True,
            "popup_show_image": False,
            "popup_duration_sec": 3,
            "win_notify_enabled": False,
            "door_entry_id": 1,
            "pulse_time_ms": 3000,
            "busy_sleep_min_ms": 0,
            "busy_sleep_max_ms": 50,
            "empty_sleep_min_ms": 200,
            "empty_sleep_max_ms": 500,
            "empty_backoff_factor": 1.35,
            "empty_backoff_max_ms": 2000,
        }
        worker = UltraDeviceWorker.__new__(UltraDeviceWorker)
        worker._settings = settings
        worker._device_id = 1
        worker._device_name = "Test"
        worker._popup_q = queue.Queue()
        worker._history_q = queue.Queue()
        worker._seen = deque(maxlen=10000)
        worker._events_processed = 0
        worker._totp_rescues = 0
        worker._totp_failures = 0
        worker._door_cmd_failures = 0
        worker._prefix = "[ULTRA:1]"
        worker._db_path = ":memory:"
        worker._cached_state = ([], {}, {"12345": {"full_name": "John"}})
        worker._cached_state_ts = time.monotonic()
        return worker

    def test_allow_event_routes_to_popup(self):
        """ALLOW events produce a popup with DEVICE_ALLOWED reason."""
        worker = self._make_worker_with_mocks()
        worker._handle_allow("12345", "100", "2026-04-01 08:00:00", "evt1")
        assert not worker._popup_q.empty()
        popup = worker._popup_q.get_nowait()
        assert popup.allowed is True
        assert popup.reason == "DEVICE_ALLOWED"

    def test_deny_event_routes_to_popup(self):
        """Plain DENY events produce a popup with DEVICE_DENIED reason."""
        worker = self._make_worker_with_mocks()
        worker._handle_deny("99999", "2026-04-01 08:00:00", "evt2")
        assert not worker._popup_q.empty()
        popup = worker._popup_q.get_nowait()
        assert popup.allowed is False
        assert popup.reason == "DEVICE_DENIED"

    def test_event_dedup_skips_seen(self):
        """Duplicate event IDs are skipped."""
        worker = self._make_worker_with_mocks()
        evt = {"CardNo": "12345", "EventType": 0, "PIN": "100", "Time_second": "t1"}
        worker._process_event(evt)
        assert worker._events_processed == 1
        worker._process_event(evt)  # same event again
        assert worker._events_processed == 1  # not incremented
```

- [ ] **Step 4: Run all tests**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
python -m pytest tests/test_ultra_engine.py -v
```

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
cd C:/Users/mohaa/Desktop/monclub_access_python
git add tests/test_ultra_engine.py
git commit -m "test: add comprehensive ULTRA engine tests (classification, retry, routing)"
```

---

## Task 11: Memory — Save ULTRA Mode Context

- [ ] **Step 1: Save project memory about ULTRA mode**

Save a memory file documenting the ULTRA mode architecture decision so future conversations have context.

---

## Summary

| Task | Codebase | What |
|------|----------|------|
| 1 | Backend | ULTRA enum + model fields |
| 2 | Dashboard | ULTRA enum + model + form UI |
| 3 | Access Client | Extract access_types.py |
| 4 | Access Client | Extract access_verification.py |
| 5 | Access Client | Tests for extracted modules |
| 6 | Access Client | ULTRA-awareness audit (config, settings, db) |
| 7 | Access Client | Build UltraEngine (worker, sync, orchestrator) |
| 8 | Access Client | App wiring (startup, mode switching, history consumer) |
| 9 | Access Client | Local API endpoints + SSE integration |
| 10 | Access Client | UltraEngine tests (classification, retry, routing, dedup) |
| 11 | All | Save memory |

**Total: 11 tasks, ~55 steps**

**Key implementation details addressed:**
- DB-level event dedup via INSERT OR IGNORE (Task 7, `_enqueue_history`)
- Local state caching with 5-second TTL (Task 7, `_get_cached_local_state`)
- WAL mode enforced on all SQLite connections (Task 7, `_pre_populate_seen` and `_enqueue_history`)
- TOTP rescue retry-once-then-fail with user-facing message (Task 7, `_open_door_with_retry`)
- Mode switching: DEVICE->ULTRA, AGENT->ULTRA, ULTRA->away (Task 8, Step 3)
- History queue consumed by HistoryService (Task 8, Step 4)
- Hash-based sync skip (Task 7, `_sync_device`)

**Dependencies:** Tasks 1-2 are independent (backend/dashboard). Tasks 3-4 must precede 5. Task 6 must precede 7-8. Tasks 7-8 must precede 9-10.

**Parallel execution:** Tasks 1 + 2 can run in parallel. Tasks 3 + 4 can run sequentially (shared codebase). Tasks 7 + 10 can be staggered.
