# Anti-Fraud System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add configurable per-device anti-fraud that blocks card/QR reuse within a time window, enforced in software (all modes) and via ZKTeco hardware parameters (DEVICE/ULTRA mode), with dashboard controls.

**Architecture:** Three new settings (`antiFraudeCard`, `antiFraudeQrCode`, `antiFraudeDuration`) flow from backend DB → sync API → Python SQLite → `normalize_device_settings` → `DecisionService` and `device_sync`. A dedicated `AntiFraudGuard` module tracks in-memory blocks per `(device_id, token, kind)` composite key with monotonic-clock TTLs, replacing the existing hardcoded 10-second card cooldown.

**Tech Stack:** Python 3.11, `threading.Lock`, `time.monotonic()`, ZKTeco PullSDK `set_device_param`, Java Spring Boot JPA, React/TypeScript (dashboard, separate repo).

---

## File Structure

### `monclub_access_python`

| Action | Path | Responsibility |
|--------|------|----------------|
| **Create** | `app/core/anti_fraud.py` | `AntiFraudGuard` — thread-safe token block store |
| **Create** | `tests/test_anti_fraud.py` | Unit tests for `AntiFraudGuard` |
| **Create** | `tests/test_decision_service_anti_fraud.py` | Integration tests for DecisionService + guard |
| **Modify** | `app/core/db.py` | 3 new `sync_devices` columns + INSERT mapping + `_coerce_device_row_to_payload` |
| **Modify** | `app/core/settings_reader.py` | 3 new keys in `normalize_device_settings()` |
| **Modify** | `app/core/realtime_agent.py` | Remove old cooldown; wire guard into `DecisionService`; add pre/post checks |
| **Modify** | `app/core/device_sync.py` | 3 new fields in `_normalize_device()`; `SetDeviceParam` anti-passback push |

### `monclub_backend` (Java)

| Action | Path | Responsibility |
|--------|------|----------------|
| **Modify** | `src/main/java/.../GymDevice.java` | 3 new JPA columns |
| **Modify** | `src/main/java/.../GymDeviceDto.java` | 3 new DTO fields |
| **Modify** | `src/main/java/.../GymAccessController.java` | Map new fields in builder |
| **Create** | `src/main/resources/db/migration/V<next>__anti_fraude_columns.sql` | Flyway/Liquibase migration |

### `mon_club_dashboard` (React/TypeScript)

| Action | Path | Responsibility |
|--------|------|----------------|
| **Modify** | `src/models/GymDeviceModel.ts` | 3 new fields with defaults |
| **Modify** | `src/pages/DeviceEditPage.tsx` (or equivalent device form) | "Anti-Fraude" settings section |

---

## Task 1: `AntiFraudGuard` — create module with tests

**Files:**
- Create: `app/core/anti_fraud.py`
- Create: `tests/test_anti_fraud.py`

---

- [ ] **Step 1: Write the failing tests**

Create `tests/test_anti_fraud.py`:

```python
"""Tests for AntiFraudGuard."""
import time
import threading
import pytest
from app.core.anti_fraud import AntiFraudGuard


def make_guard() -> AntiFraudGuard:
    return AntiFraudGuard()


class TestCheckNotBlocked:
    def test_new_token_not_blocked(self):
        g = make_guard()
        blocked, remaining = g.check(1, "ABC123", "card")
        assert blocked is False
        assert remaining == 0.0

    def test_different_device_not_blocked(self):
        g = make_guard()
        g.record(1, "ABC", "card", 60.0)
        blocked, _ = g.check(2, "ABC", "card")
        assert blocked is False

    def test_different_kind_not_blocked(self):
        g = make_guard()
        g.record(1, "ABC", "card", 60.0)
        blocked, _ = g.check(1, "ABC", "qr")
        assert blocked is False

    def test_different_token_not_blocked(self):
        g = make_guard()
        g.record(1, "ABC", "card", 60.0)
        blocked, _ = g.check(1, "XYZ", "card")
        assert blocked is False


class TestCheckBlocked:
    def test_blocked_immediately_after_record(self):
        g = make_guard()
        g.record(1, "ABC", "card", 30.0)
        blocked, remaining = g.check(1, "ABC", "card")
        assert blocked is True
        assert 29.0 < remaining <= 30.0

    def test_not_blocked_after_expiry(self):
        g = make_guard()
        g.record(1, "ABC", "card", 0.05)
        time.sleep(0.1)
        blocked, remaining = g.check(1, "ABC", "card")
        assert blocked is False
        assert remaining == 0.0

    def test_record_extends_window(self):
        g = make_guard()
        g.record(1, "ABC", "card", 0.05)
        time.sleep(0.03)
        g.record(1, "ABC", "card", 30.0)  # extend
        blocked, remaining = g.check(1, "ABC", "card")
        assert blocked is True
        assert remaining > 29.0


class TestEviction:
    def test_stale_entries_evicted_on_record(self):
        g = make_guard()
        g.record(1, "OLD", "card", 0.02)
        time.sleep(0.05)
        g.record(1, "NEW", "card", 60.0)  # triggers eviction
        # OLD should be gone from internal dict
        with g._lock:
            assert (1, "OLD", "card") not in g._entries

    def test_active_entries_not_evicted(self):
        g = make_guard()
        g.record(1, "KEEP", "card", 60.0)
        g.record(1, "OTHER", "card", 60.0)  # triggers eviction
        with g._lock:
            assert (1, "KEEP", "card") in g._entries


class TestThreadSafety:
    def test_concurrent_record_and_check(self):
        g = make_guard()
        errors = []

        def worker(device_id: int):
            try:
                for i in range(50):
                    g.record(device_id, f"token{i}", "card", 0.5)
                    g.check(device_id, f"token{i}", "card")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
```

- [ ] **Step 2: Run tests to verify they fail**

```
cd C:\Users\mohaa\Desktop\monclub_access_python
python -m pytest tests/test_anti_fraud.py -v 2>&1 | head -20
```
Expected: `ERROR` — `ModuleNotFoundError: No module named 'app.core.anti_fraud'`

- [ ] **Step 3: Implement `AntiFraudGuard`**

Create `app/core/anti_fraud.py`:

```python
"""
Anti-fraud guard — in-memory per-device token block store.

Blocks reuse of a card number or QR credential ID on the same device
for a configurable duration after a successful access grant.

Thread-safe. State is intentionally ephemeral (lost on restart).
At gym scale (<100 doors, 30 s TTL) the internal dict stays small enough
that lazy eviction on every record() call is sufficient.
"""
from __future__ import annotations

import math
import threading
import time
from typing import Dict, Tuple


class AntiFraudGuard:
    """
    Key:   (device_id: int, token: str, kind: str)
    Value: expires_at — time.monotonic() float

    kind is "card" or "qr".
    For cards : token = card_no string from the ZKTeco event.
    For QR    : token = credential ID UUID string (stable across TOTP rotations).
    """

    def __init__(self) -> None:
        self._entries: Dict[Tuple[int, str, str], float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self, device_id: int, token: str, kind: str
    ) -> Tuple[bool, float]:
        """
        Returns (is_blocked, seconds_remaining).
        seconds_remaining is 0.0 when not blocked.
        """
        key = (device_id, token, kind)
        now = time.monotonic()
        with self._lock:
            expires_at = self._entries.get(key, 0.0)
            if expires_at > now:
                return True, expires_at - now
            return False, 0.0

    def record(
        self, device_id: int, token: str, kind: str, duration: float
    ) -> None:
        """
        Record a successful access grant and start the block window.

        Lazily evicts all stale entries on every call (O(n) but n is tiny).
        Overwrites any existing entry for the same key — extends the window
        if called again before the previous TTL expires.
        """
        key = (device_id, token, kind)
        now = time.monotonic()
        with self._lock:
            stale = [k for k, exp in self._entries.items() if exp <= now]
            for k in stale:
                del self._entries[k]
            self._entries[key] = now + duration

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def format_remaining(seconds: float) -> str:
        """Human-readable remaining time, e.g. '28s'."""
        return f"{math.ceil(seconds)}s"
```

- [ ] **Step 4: Run tests to verify they pass**

```
python -m pytest tests/test_anti_fraud.py -v
```
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app/core/anti_fraud.py tests/test_anti_fraud.py
git commit -m "feat: add AntiFraudGuard in-memory token block store"
```

---

## Task 2: DB schema — add 3 columns to `sync_devices`

**Files:**
- Modify: `app/core/db.py` (CREATE TABLE ~line 404, `_insert_device_row` ~line 1204, `_coerce_device_row_to_payload` ~line 2165)

---

- [ ] **Step 1: Write the failing test**

Add to a new file `tests/test_db_anti_fraud_columns.py`:

```python
"""Verify anti-fraud columns exist in sync_devices and round-trip correctly."""
import sqlite3
import pytest
from app.core.db import get_conn


def test_sync_devices_has_anti_fraud_columns():
    with get_conn() as conn:
        cursor = conn.execute("PRAGMA table_info(sync_devices)")
        columns = {row["name"] for row in cursor.fetchall()}
    assert "anti_fraude_card" in columns
    assert "anti_fraude_qr_code" in columns
    assert "anti_fraude_duration" in columns


def test_anti_fraud_column_defaults():
    """A freshly inserted device should have default anti-fraud values."""
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO sync_devices (id, name) VALUES (99999, 'test-af')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT anti_fraude_card, anti_fraude_qr_code, anti_fraude_duration "
            "FROM sync_devices WHERE id = 99999"
        ).fetchone()
        conn.execute("DELETE FROM sync_devices WHERE id = 99999")
        conn.commit()
    assert row["anti_fraude_card"] == 1
    assert row["anti_fraude_qr_code"] == 1
    assert row["anti_fraude_duration"] == 30
```

- [ ] **Step 2: Run test to verify it fails**

```
python -m pytest tests/test_db_anti_fraud_columns.py -v
```
Expected: FAIL — columns missing.

- [ ] **Step 3: Add columns to CREATE TABLE in `db.py`**

In `app/core/db.py` around line 395-403 (the end of the `CREATE TABLE IF NOT EXISTS sync_devices` statement, just before the closing `)`), add the three new columns.

Find the last existing column in the CREATE TABLE block (it ends with the `updated_at TEXT` line). Add **before** the closing `);`:

```sql
    anti_fraude_card     INTEGER NOT NULL DEFAULT 1,
    anti_fraude_qr_code  INTEGER NOT NULL DEFAULT 1,
    anti_fraude_duration INTEGER NOT NULL DEFAULT 30,
```

Also add a migration block. Search for the pattern where existing ALTER TABLE migrations are applied (look for `"ALTER TABLE sync_devices ADD COLUMN"` in `db.py`). Add alongside existing migrations:

```python
_run_if_missing(conn, "sync_devices", "anti_fraude_card",
                "ALTER TABLE sync_devices ADD COLUMN anti_fraude_card INTEGER NOT NULL DEFAULT 1")
_run_if_missing(conn, "sync_devices", "anti_fraude_qr_code",
                "ALTER TABLE sync_devices ADD COLUMN anti_fraude_qr_code INTEGER NOT NULL DEFAULT 1")
_run_if_missing(conn, "sync_devices", "anti_fraude_duration",
                "ALTER TABLE sync_devices ADD COLUMN anti_fraude_duration INTEGER NOT NULL DEFAULT 30")
```

> **Note:** `_run_if_missing(conn, table, column, sql)` is the helper already used throughout `db.py` for safe schema migrations. Search for its definition if you need its exact signature.

- [ ] **Step 4: Add columns to `_insert_device_row`** (~line 1204)

Locate `_insert_device_row`. In the INSERT column list, add after the last existing column:

```python
    # ... existing columns ...
    anti_fraude_card,
    anti_fraude_qr_code,
    anti_fraude_duration
```

In the VALUES section (immediately after the column list), add the corresponding values using the `_bool_to_i()` and `_to_int_or_none()` helpers that are already used throughout:

```python
    # ... existing values ...
    _bool_to_i(d.get("antiFraudeCard"),    default=1),   # anti_fraude_card
    _bool_to_i(d.get("antiFraudeQrCode"),  default=1),   # anti_fraude_qr_code
    _to_int_or_none(d.get("antiFraudeDuration")) or 30,  # anti_fraude_duration
```

- [ ] **Step 5: Add to `_coerce_device_row_to_payload`** (~line 2165)

Locate `_coerce_device_row_to_payload` (~line 2075). After the `"rfidEnabled"` and `"totpEnabled"` lines, add:

```python
"antiFraudeCard":     _boolish(g("anti_fraude_card",    default=1), True),
"antiFraudeQrCode":   _boolish(g("anti_fraude_qr_code", default=1), True),
"antiFraudeDuration": _to_int_or_none(g("anti_fraude_duration", default=30)) or 30,
```

> **Note:** `_boolish` and `_to_int_or_none` are defined locally inside `_coerce_device_row_to_payload` (around lines 2089-2101 and used throughout). Use the same local helpers as the existing boolean columns.

- [ ] **Step 6: Run tests to verify they pass**

```
python -m pytest tests/test_db_anti_fraud_columns.py -v
```
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add app/core/db.py tests/test_db_anti_fraud_columns.py
git commit -m "feat: add anti_fraude columns to sync_devices schema and coerce payload"
```

---

## Task 3: Settings normalisation — expose 3 new keys

**Files:**
- Modify: `app/core/settings_reader.py` (~line 276)

---

- [ ] **Step 1: Write the failing test**

Add to a new file `tests/test_settings_anti_fraud.py`:

```python
"""Verify anti-fraud keys are returned by normalize_device_settings."""
from app.core.settings_reader import normalize_device_settings


def _norm(overrides: dict) -> dict:
    base = {
        "id": 1,
        "name": "test",
        "active": True,
        "accessDevice": True,
        "accessDataMode": "AGENT",
        "ipAddress": "192.168.1.1",
        "portNumber": "4370",
        "totpEnabled": True,
        "rfidEnabled": True,
    }
    return normalize_device_settings({**base, **overrides})


class TestAntiFraudDefaults:
    def test_default_card_enabled(self):
        s = _norm({})
        assert s["anti_fraude_card"] is True

    def test_default_qr_enabled(self):
        s = _norm({})
        assert s["anti_fraude_qr_code"] is True

    def test_default_duration(self):
        s = _norm({})
        assert s["anti_fraude_duration"] == 30


class TestAntiFraudOverrides:
    def test_card_disabled(self):
        s = _norm({"antiFraudeCard": False})
        assert s["anti_fraude_card"] is False

    def test_card_disabled_integer_zero(self):
        s = _norm({"antiFraudeCard": 0})
        assert s["anti_fraude_card"] is False

    def test_qr_disabled(self):
        s = _norm({"antiFraudeQrCode": False})
        assert s["anti_fraude_qr_code"] is False

    def test_custom_duration(self):
        s = _norm({"antiFraudeDuration": 60})
        assert s["anti_fraude_duration"] == 60

    def test_duration_clamped_low(self):
        s = _norm({"antiFraudeDuration": 1})
        assert s["anti_fraude_duration"] == 5  # lo=5

    def test_duration_clamped_high(self):
        s = _norm({"antiFraudeDuration": 9999})
        assert s["anti_fraude_duration"] == 300  # hi=300

    def test_duration_none_uses_default(self):
        s = _norm({"antiFraudeDuration": None})
        assert s["anti_fraude_duration"] == 30
```

- [ ] **Step 2: Run tests to verify they fail**

```
python -m pytest tests/test_settings_anti_fraud.py -v
```
Expected: FAIL — `KeyError: 'anti_fraude_card'`

- [ ] **Step 3: Add 3 keys to `normalize_device_settings`**

In `app/core/settings_reader.py`, locate `normalize_device_settings()` (~line 211). Find the section where RFID settings are returned (around lines 276-279 — `"rfid_min_digits"`, `"rfid_max_digits"`). After those lines, add:

```python
        "anti_fraude_card":     _boolish(raw.get("antiFraudeCard"), True),
        "anti_fraude_qr_code":  _boolish(raw.get("antiFraudeQrCode"), True),
        "anti_fraude_duration": _clamp_int(raw.get("antiFraudeDuration"), default=30, lo=5, hi=300),
```

`_boolish` and `_clamp_int` are already defined in `settings_reader.py` (lines 56-75). No new imports needed.

- [ ] **Step 4: Run tests to verify they pass**

```
python -m pytest tests/test_settings_anti_fraud.py -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add app/core/settings_reader.py tests/test_settings_anti_fraud.py
git commit -m "feat: expose anti_fraude settings keys in normalize_device_settings"
```

---

## Task 4: Wire `AntiFraudGuard` into `DecisionService`

**Files:**
- Modify: `app/core/realtime_agent.py` (~lines 933–980 init, ~lines 1028–1268 run)

This task replaces the hardcoded 10-second card cooldown with the proper `AntiFraudGuard`.

---

- [ ] **Step 1: Write integration tests**

Create `tests/test_decision_service_anti_fraud.py`:

```python
"""
Integration tests for AntiFraudGuard inside DecisionService.

These tests use the existing _make_decision_service pattern from
test_launch_safety_regressions.py — a minimal stub DecisionService
wired with in-memory queues and mock dependencies.
"""
import queue
import threading
import time
from unittest.mock import MagicMock, patch
import pytest

from app.core.anti_fraud import AntiFraudGuard
from app.core.realtime_agent import DecisionService, EMA, NotificationGate, DeviceCommandBus


DEVICE_ID = 42
CARD_NO = "ABC123"
CRED_ID = "cred-uuid-001"

AF_SETTINGS = {
    "enabled": True,
    "totp_enabled": False,
    "rfid_enabled": True,
    "anti_fraude_card": True,
    "anti_fraude_qr_code": True,
    "anti_fraude_duration": 30,
    "save_history": False,  # skip DB writes in unit tests
    "show_notifications": False,
    "win_notify_enabled": False,
    "popup_enabled": False,
    "door_ids": [1],
    "pulse_time_ms": 200,
    "cmd_timeout_ms": 5000,
    "timeout_ms": 5000,
}


class _DummyLogger:
    def debug(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass
    def exception(self, *a, **k): pass


def _make_ds(settings_override=None, guard=None):
    settings = {**AF_SETTINGS, **(settings_override or {})}
    ev_q: queue.Queue = queue.Queue()
    cmd_bus = MagicMock(spec=DeviceCommandBus)
    cmd_bus.open_door.return_value = MagicMock(success=True)
    ds = DecisionService(
        logger=_DummyLogger(),
        event_queue=ev_q,
        command_bus=cmd_bus,
        notify_q=queue.Queue(),
        popup_q=queue.Queue(),
        history_q=queue.Queue(),
        settings_provider=lambda _: settings,
        global_settings=lambda: {},
        notify_gate=MagicMock(spec=NotificationGate),
        decision_ema=EMA(alpha=0.1),
        guard=guard or AntiFraudGuard(),
    )
    return ds, ev_q, cmd_bus


def _run_event(ds, ev):
    """Run DecisionService for one event then stop."""
    ds.stop_event = threading.Event()
    ds.event_queue.put(ev)

    def _stop_after_drain():
        time.sleep(0.3)
        ds.stop_event.set()

    t_stop = threading.Thread(target=_stop_after_drain, daemon=True)
    t_stop.start()
    ds.run()


class TestCardAntiFraud:
    @patch("app.core.realtime_agent.access_history_exists", return_value=False)
    @patch("app.core.realtime_agent.insert_access_history", return_value=0)
    def test_card_blocked_returns_deny_reason(self, mock_hist, mock_dedup):
        guard = AntiFraudGuard()
        guard.record(DEVICE_ID, CARD_NO, "card", 30.0)  # pre-block the card

        ds, ev_q, cmd_bus = _make_ds(guard=guard)
        ev = MagicMock(device_id=DEVICE_ID, card_no=CARD_NO, event_id="evt-001")

        with patch.object(ds, "_verify_totp") as mock_verify:
            _run_event(ds, ev)
            # verify_totp should NOT be called when card is pre-blocked
            mock_verify.assert_not_called()

        cmd_bus.open_door.assert_not_called()

    @patch("app.core.realtime_agent.access_history_exists", return_value=False)
    @patch("app.core.realtime_agent.insert_access_history", return_value=0)
    def test_card_not_blocked_when_disabled(self, mock_hist, mock_dedup):
        guard = AntiFraudGuard()
        guard.record(DEVICE_ID, CARD_NO, "card", 30.0)

        ds, ev_q, cmd_bus = _make_ds(
            settings_override={"anti_fraude_card": False},
            guard=guard,
        )
        ev = MagicMock(device_id=DEVICE_ID, card_no=CARD_NO, event_id="evt-002")

        with patch.object(ds, "_verify_totp", return_value={"allowed": False, "reason": "DENY_UNKNOWN_CARD"}) as mock_verify:
            _run_event(ds, ev)
            # verify_totp IS called because anti_fraude_card is disabled
            mock_verify.assert_called_once()


class TestGuardRecord:
    @patch("app.core.realtime_agent.access_history_exists", return_value=False)
    @patch("app.core.realtime_agent.insert_access_history", return_value=1)
    def test_guard_record_called_after_allowed_grant(self, mock_hist, mock_dedup):
        guard = AntiFraudGuard()
        ds, ev_q, cmd_bus = _make_ds(guard=guard)
        ev = MagicMock(device_id=DEVICE_ID, card_no=CARD_NO, event_id="evt-010")

        with patch.object(ds, "_verify_totp", return_value={"allowed": True, "reason": "GRANT"}):
            _run_event(ds, ev)

        blocked, _ = guard.check(DEVICE_ID, CARD_NO, "card")
        assert blocked is True

    @patch("app.core.realtime_agent.access_history_exists", return_value=False)
    @patch("app.core.realtime_agent.insert_access_history", return_value=0)
    def test_guard_record_not_called_when_history_not_claimed(self, mock_hist, mock_dedup):
        guard = AntiFraudGuard()
        ds, ev_q, cmd_bus = _make_ds(guard=guard)
        ev = MagicMock(device_id=DEVICE_ID, card_no=CARD_NO, event_id="evt-011")

        with patch.object(ds, "_verify_totp", return_value={"allowed": True, "reason": "GRANT"}):
            _run_event(ds, ev)

        blocked, _ = guard.check(DEVICE_ID, CARD_NO, "card")
        assert blocked is False  # not recorded because rowcount was 0

    @patch("app.core.realtime_agent.access_history_exists", return_value=False)
    @patch("app.core.realtime_agent.insert_access_history", return_value=1)
    def test_guard_record_not_called_when_denied(self, mock_hist, mock_dedup):
        guard = AntiFraudGuard()
        ds, ev_q, cmd_bus = _make_ds(guard=guard)
        ev = MagicMock(device_id=DEVICE_ID, card_no=CARD_NO, event_id="evt-012")

        with patch.object(ds, "_verify_totp", return_value={"allowed": False, "reason": "DENY_UNKNOWN_CARD"}):
            _run_event(ds, ev)

        blocked, _ = guard.check(DEVICE_ID, CARD_NO, "card")
        assert blocked is False  # not recorded because allowed=False
```

- [ ] **Step 2: Run tests to verify they fail**

```
python -m pytest tests/test_decision_service_anti_fraud.py -v 2>&1 | head -30
```
Expected: FAIL — `TypeError: DecisionService.__init__() got unexpected keyword argument 'guard'`

- [ ] **Step 3: Add `guard` parameter to `DecisionService.__init__`**

In `app/core/realtime_agent.py`, at the top of the file add the import:

```python
from app.core.anti_fraud import AntiFraudGuard
```

In `DecisionService.__init__` (lines 933-980), add the new parameter. The signature currently ends with `device_name_provider`. Add after it:

```python
    guard: "AntiFraudGuard | None" = None,
```

At the end of `__init__` body, add:

```python
        self._guard: AntiFraudGuard = guard if guard is not None else AntiFraudGuard()
```

Also **remove** lines 978-979 (the old card cooldown):

```python
        # REMOVE THESE TWO LINES:
        self._card_cooldown: Dict[str, float] = {}
        self._card_cooldown_sec = 10.0
```

- [ ] **Step 4: Replace old card cooldown with guard pre-check in `run()`**

In `DecisionService.run()` (starting ~line 1016), locate and **remove** lines 1028-1043 (the old card cooldown block):

```python
# REMOVE THIS ENTIRE BLOCK (lines 1028-1043):
card_key = f"{ev.device_id}:{ev.card_no}" if ev.card_no else ""
if card_key:
    now_mono = _now_ms() / 1000.0
    last_seen = self._card_cooldown.get(card_key, 0.0)
    if (now_mono - last_seen) < self._card_cooldown_sec:
        continue
    self._card_cooldown[card_key] = now_mono
    # ... cleanup lines ...
```

After removing the old block, the flow at that point is:
```
event dedup check (keep)
settings = self.settings_provider(ev.device_id)  ← move this BEFORE verify_totp
```

Currently, `settings = self.settings_provider(ev.device_id)` is at line 1045 (after the old cooldown). It was already first in the decision logic. After removing the cooldown block, settings load naturally sits at the top of the processing. **No move needed** — just delete the old cooldown block; settings load is already at the right position.

Now, **after** the settings load line and **before** the `_load_local_state()` call, insert the card anti-fraud pre-check:

```python
        # [NEW] Card anti-fraud pre-check (before verify_totp)
        _af_card_blocked = False
        _af_remaining = 0.0
        if settings.get("anti_fraude_card") and ev.card_no:
            _af_card_blocked, _af_remaining = self._guard.check(
                ev.device_id, str(ev.card_no), "card"
            )

        if _af_card_blocked:
            vr: dict = {
                "allowed": False,
                "reason": "DENY_ANTI_FRAUD_CARD",
                "_af_remaining": _af_remaining,
            }
        else:
            creds_payload, users_by_am, users_by_card = self._load_local_state()
            vr = self._verify_totp(
                scanned=ev.card_no,
                settings=settings,
                creds_payload=creds_payload,
                users_by_am=users_by_am,
                users_by_card=users_by_card,
            )
```

> **Important:** The existing code calls `_load_local_state()` then `_verify_totp()` unconditionally. You are wrapping those two calls in the `else` branch. Everything that was previously between the settings load and the `vr` assignment should move into the `else` block.

- [ ] **Step 5: Add QR anti-fraud post-verify check**

After `vr` is obtained (from either the card-blocked synthetic dict or from `_verify_totp`), and after extracting `allowed = bool(vr.get("allowed", False))` and `reason = ...`, **add** the QR check:

```python
        # [NEW] QR anti-fraud post-verify
        _af_qr_blocked = False
        scan_mode = str(vr.get("scanMode") or vr.get("scan_mode") or "")
        cred_id: str | None = vr.get("credId")

        if allowed and scan_mode == "QR_TOTP" and settings.get("anti_fraude_qr_code") and cred_id:
            _af_qr_blocked, _af_remaining = self._guard.check(
                ev.device_id, cred_id, "qr"
            )
            if _af_qr_blocked:
                allowed = False
                reason = "DENY_ANTI_FRAUD_QR"
                vr = {**vr, "allowed": False, "reason": reason, "_af_remaining": _af_remaining}
```

> **Note on `scan_mode` key:** Check `app/core/access_verification.py` for the exact key name returned in `vr` for QR scans — it may be `"scanMode"`, `"scan_mode"`, or similar. The `or` chain above handles both casing variants.

- [ ] **Step 6: Add `guard.record()` after `insert_access_history`**

Locate the `_history_claimed = insert_access_history(...)` block (~line 1090). After the history insert and after the existing error handling, add:

```python
        # [NEW] Record successful grant in anti-fraud guard
        if allowed and not _af_card_blocked and not _af_qr_blocked and _history_claimed > 0:
            duration = float(settings.get("anti_fraude_duration", 30))
            if scan_mode == "QR_TOTP" and cred_id:
                self._guard.record(ev.device_id, cred_id, "qr", duration)
            elif ev.card_no:
                self._guard.record(ev.device_id, str(ev.card_no), "card", duration)
```

- [ ] **Step 7: Add anti-fraud message to notifications**

In the notification construction block (~lines 1214-1236), add a case for anti-fraud denials. Find where `msg` (or the notification message string) is constructed for deny reasons, and add:

```python
        if reason in ("DENY_ANTI_FRAUD_CARD", "DENY_ANTI_FRAUD_QR"):
            af_remaining = vr.get("_af_remaining", 0.0)
            kind_label = "Carte" if reason == "DENY_ANTI_FRAUD_CARD" else "QR Code"
            msg = (
                f"Accès refusé — anti-fraude actif ({AntiFraudGuard.format_remaining(af_remaining)} restant)"
                f" [{kind_label}]"
            )
```

> Place this before the generic `else` message branch so it overrides the default deny message for anti-fraud reasons.

- [ ] **Step 8: Pass guard from `AgentRealtimeEngine` to `DecisionService`**

In `AgentRealtimeEngine.__init__` (search for `class AgentRealtimeEngine`), add:

```python
        self._guard = AntiFraudGuard()
```

In `AgentRealtimeEngine.start()` (~line 1705), where `DecisionService` instances are created, add the `guard` kwarg:

```python
            d = DecisionService(
                logger=self.logger,
                event_queue=self._event_q,
                command_bus=self._cmd_bus,
                notify_q=self._notify_q,
                popup_q=self._popup_q,
                history_q=self._history_q,
                settings_provider=self._device_settings,
                global_settings=self.get_global_settings,
                notify_gate=self._notify_gate,
                decision_ema=self._decision_ema,
                device_name_provider=self._resolve_device_name,
                guard=self._guard,   # ← ADD THIS
            )
```

All `DecisionService` workers share one guard instance so they don't have split state.

- [ ] **Step 9: Run all anti-fraud tests**

```
python -m pytest tests/test_anti_fraud.py tests/test_decision_service_anti_fraud.py -v
```
Expected: all PASS.

- [ ] **Step 10: Run existing regression tests to check nothing is broken**

```
python -m pytest tests/test_launch_safety_regressions.py -v
```
Expected: all PASS. (The `guard` parameter is optional with a default `AntiFraudGuard()`, so existing test factories work without modification.)

- [ ] **Step 11: Commit**

```bash
git add app/core/realtime_agent.py tests/test_decision_service_anti_fraud.py
git commit -m "feat: replace hardcoded card cooldown with AntiFraudGuard in DecisionService"
```

---

## Task 5: `device_sync.py` — `_normalize_device` + hardware anti-passback push

**Files:**
- Modify: `app/core/device_sync.py` (~lines 227–266 and ~lines 963–974)

---

- [ ] **Step 1: Write tests**

Add to a new file `tests/test_device_sync_anti_fraud.py`:

```python
"""
Verify _normalize_device reads anti-fraud columns, and that SetDeviceParam
is called correctly during sync when anti_fraude_card is enabled.
"""
import pytest
from unittest.mock import MagicMock, patch, call


def _make_row(overrides=None):
    base = {
        "id": 1,
        "name": "Door 1",
        "active": 1,
        "access_device": 1,
        "ip_address": "192.168.1.5",
        "port_number": "4370",
        "password": "",
        "access_data_mode": "DEVICE",
        "door_ids_json": "[1]",
        "allowed_memberships_json": "[]",
        "authorize_timezone_id": 1,
        "pushing_to_device_policy": "MERGE",
        "door_presets": None,
        "anti_fraude_card": 1,
        "anti_fraude_qr_code": 1,
        "anti_fraude_duration": 30,
    }
    return {**base, **(overrides or {})}


class TestNormalizeDevice:
    def test_anti_fraude_card_true_by_default(self):
        from app.core.device_sync import _normalize_device_row
        result = _normalize_device_row(_make_row())
        assert result["anti_fraude_card"] is True

    def test_anti_fraude_card_false_when_zero(self):
        from app.core.device_sync import _normalize_device_row
        result = _normalize_device_row(_make_row({"anti_fraude_card": 0}))
        assert result["anti_fraude_card"] is False

    def test_anti_fraude_duration_default(self):
        from app.core.device_sync import _normalize_device_row
        result = _normalize_device_row(_make_row())
        assert result["anti_fraude_duration"] == 30

    def test_anti_fraude_duration_custom(self):
        from app.core.device_sync import _normalize_device_row
        result = _normalize_device_row(_make_row({"anti_fraude_duration": 60}))
        assert result["anti_fraude_duration"] == 60
```

> **Note:** The test imports `_normalize_device_row` — a module-level function. Currently `_normalize_device` is a method on the sync class. If it's a method, test it through the class or refactor to a module-level function. Adjust the import accordingly.

- [ ] **Step 2: Run tests to verify they fail**

```
python -m pytest tests/test_device_sync_anti_fraud.py -v
```
Expected: FAIL — columns missing from `_normalize_device`.

- [ ] **Step 3: Add 3 fields to `_normalize_device`** (~line 266)

In `app/core/device_sync.py`, locate `_normalize_device` (~line 227). In the returned dict, add after the last existing field (e.g. `"pushingToDevicePolicy"`):

```python
        "anti_fraude_card":     _boolish(g("anti_fraude_card",    default=True), True),
        "anti_fraude_qr_code":  _boolish(g("anti_fraude_qr_code", default=True), True),
        "anti_fraude_duration": _to_int(g("anti_fraude_duration", default=30), default=30) or 30,
```

`_boolish` and `_to_int` are already defined in `device_sync.py` (lines 88-101 and 64-73).

- [ ] **Step 4: Add `SetDeviceParam` anti-passback push**

Locate the door-presets `SetDeviceParam` block (~lines 963-974). Immediately **after** the door-presets loop (after it finishes iterating `presets`), add:

```python
        # [NEW] Anti-passback hardware parameter push
        anti_fraude_card = bool(device.get("anti_fraude_card", True))
        anti_fraude_duration = int(device.get("anti_fraude_duration") or 30)
        if anti_fraude_card:
            param_str = f"AntiPassback=1&AntiPassbackTime={anti_fraude_duration}"
        else:
            param_str = "AntiPassback=0"
        try:
            sdk.set_device_param(items=param_str)
            self.logger.info(
                "[DeviceSync] Device id=%s anti-passback param OK (%s)",
                dev_id, param_str,
            )
        except Exception as ex:
            self.logger.warning(
                "[DeviceSync] Device id=%s anti-passback param FAILED (non-fatal): %s",
                dev_id, ex,
            )
            # Non-fatal: software guard remains the primary enforcer
```

> **Caveat:** `AntiPassback` and `AntiPassbackTime` are the expected ZKTeco C3 series parameter names. Verify against the PullSDK reference for the specific `DeviceModel` of each connected device. If different device models use different names, add a per-model lookup dict. Any failure here is non-fatal — log and continue.

- [ ] **Step 5: Run tests**

```
python -m pytest tests/test_device_sync_anti_fraud.py -v
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/core/device_sync.py tests/test_device_sync_anti_fraud.py
git commit -m "feat: add anti-fraud fields to _normalize_device and push SetDeviceParam anti-passback"
```

---

## Task 6: Backend — `monclub_backend` (Java / Spring Boot)

**Files:**
- Modify: `src/main/java/.../model/GymDevice.java`
- Modify: `src/main/java/.../dto/GymDeviceDto.java`
- Modify: `src/main/java/.../controller/GymAccessController.java`
- Create: `src/main/resources/db/migration/V<next>__anti_fraude_columns.sql`

> **Note:** Find the exact package paths by searching for `class GymDevice` in the backend repo.

---

- [ ] **Step 1: Add JPA columns to `GymDevice.java`**

Find `GymDevice.java`. Add the three fields alongside the existing device fields (after `totpEnabled`, `rfidEnabled`, etc.):

```java
@Column(name = "anti_fraude_card", nullable = false)
private boolean antiFraudeCard = true;

@Column(name = "anti_fraude_qr_code", nullable = false)
private boolean antiFraudeQrCode = true;

@Column(name = "anti_fraude_duration", nullable = false)
private int antiFraudeDuration = 30;
```

Add getters and setters (or use Lombok `@Getter @Setter` if the class already uses it):

```java
public boolean isAntiFraudeCard() { return antiFraudeCard; }
public void setAntiFraudeCard(boolean antiFraudeCard) { this.antiFraudeCard = antiFraudeCard; }

public boolean isAntiFraudeQrCode() { return antiFraudeQrCode; }
public void setAntiFraudeQrCode(boolean antiFraudeQrCode) { this.antiFraudeQrCode = antiFraudeQrCode; }

public int getAntiFraudeDuration() { return antiFraudeDuration; }
public void setAntiFraudeDuration(int antiFraudeDuration) { this.antiFraudeDuration = antiFraudeDuration; }
```

- [ ] **Step 2: Add fields to `GymDeviceDto.java`**

Find `GymDeviceDto.java`. Add:

```java
private boolean antiFraudeCard = true;
private boolean antiFraudeQrCode = true;
private int antiFraudeDuration = 30;
```

Add getters/setters (or use Lombok).

- [ ] **Step 3: Map new fields in `GymAccessController.java`**

Find `GymAccessController.java` and the `get_gym_users` endpoint that builds the devices list. Locate where `GymDeviceDto` is constructed for each device (the `.builder()` or `new GymDeviceDto()` pattern). Add:

```java
.antiFraudeCard(device.isAntiFraudeCard())
.antiFraudeQrCode(device.isAntiFraudeQrCode())
.antiFraudeDuration(device.getAntiFraudeDuration())
```

alongside the existing field mappings (e.g. next to `totpEnabled`, `rfidEnabled`).

- [ ] **Step 4: Create DB migration**

Find the existing migration directory. Create the next migration file (increment the version number):

```sql
-- V<next>__anti_fraude_columns.sql
ALTER TABLE gym_device
    ADD COLUMN anti_fraude_card     BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN anti_fraude_qr_code  BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN anti_fraude_duration INTEGER NOT NULL DEFAULT 30;
```

- [ ] **Step 5: Build and run backend tests**

```bash
cd <backend-repo-root>
./mvnw test -pl . -Dtest="GymDevice*,GymAccess*" 2>&1 | tail -20
```

Or if using Gradle:
```bash
./gradlew test --tests "*GymDevice*" --tests "*GymAccess*"
```

Expected: BUILD SUCCESS.

- [ ] **Step 6: Commit backend changes**

```bash
git add src/main/java/ src/main/resources/db/migration/
git commit -m "feat: add anti_fraude columns to GymDevice, DTO, and migration"
```

---

## Task 7: Dashboard — `mon_club_dashboard` (React / TypeScript)

**Files:**
- Modify: `src/models/GymDeviceModel.ts` (or wherever the device model class/interface lives)
- Modify: device edit form component (search for `totpEnabled` to find the right file)

---

- [ ] **Step 1: Add 3 fields to `GymDeviceModel.ts`**

Find `GymDeviceModel.ts`. Add the three fields with defaults alongside the existing `totpEnabled`, `rfidEnabled` fields:

```typescript
antiFraudeCard: boolean = true;
antiFraudeQrCode: boolean = true;
antiFraudeDuration: number = 30;
```

In `fromJson()` (or the JSON deserialisation method), add:

```typescript
antiFraudeCard:     data.antiFraudeCard     ?? true,
antiFraudeQrCode:   data.antiFraudeQrCode   ?? true,
antiFraudeDuration: data.antiFraudeDuration ?? 30,
```

In `toJson()` (or the serialisation method), add:

```typescript
antiFraudeCard:     this.antiFraudeCard,
antiFraudeQrCode:   this.antiFraudeQrCode,
antiFraudeDuration: this.antiFraudeDuration,
```

- [ ] **Step 2: Add Anti-Fraude section to device edit form**

Find the device edit form component (search for `totpEnabled` to locate it). Add a new "Anti-Fraude" section **below** the TOTP settings block:

```tsx
{/* ── Anti-Fraude ─────────────────────────────────── */}
<div className="border rounded-lg p-4 space-y-4">
  <h3 className="font-semibold text-sm text-muted-foreground uppercase tracking-wide">
    Anti-Fraude
  </h3>

  <div className="flex items-center justify-between">
    <label className="text-sm font-medium">Anti-fraude Carte</label>
    <Switch
      checked={device.antiFraudeCard}
      onCheckedChange={(val) => setDevice({ ...device, antiFraudeCard: val })}
    />
  </div>

  <div className="flex items-center justify-between">
    <label className="text-sm font-medium">Anti-fraude QR Code</label>
    <Switch
      checked={device.antiFraudeQrCode}
      onCheckedChange={(val) => setDevice({ ...device, antiFraudeQrCode: val })}
    />
  </div>

  <div className="space-y-1">
    <label className="text-sm font-medium">
      Durée (secondes)
      <span className="text-muted-foreground ml-2 text-xs">min 5 · max 300</span>
    </label>
    <Input
      type="number"
      min={5}
      max={300}
      value={device.antiFraudeDuration}
      disabled={!device.antiFraudeCard && !device.antiFraudeQrCode}
      onChange={(e) =>
        setDevice({
          ...device,
          antiFraudeDuration: Math.min(300, Math.max(5, parseInt(e.target.value) || 30)),
        })
      }
    />
  </div>
</div>
```

> Use the same `Switch` and `Input` components already used in the TOTP block. Import from wherever those are imported.

The form already calls `updateGymDevice(device)` on save — no new endpoint needed.

- [ ] **Step 3: Build dashboard**

```bash
cd <dashboard-repo-root>
npm run build 2>&1 | tail -10
```
Expected: build succeeds with no TypeScript errors.

- [ ] **Step 4: Commit dashboard changes**

```bash
git add src/models/GymDeviceModel.ts src/pages/  # or the exact form file
git commit -m "feat: add antiFraude fields to GymDeviceModel and device edit form"
```

---

## End-to-End Verification Checklist

After all tasks are done:

- [ ] Operator opens dashboard → edits a device → sets `antiFraudeCard=true`, `antiFraudeDuration=20`, saves.
- [ ] Access app syncs → `sync_devices.anti_fraude_card = 1`, `anti_fraude_duration = 20` in SQLite. Verify: `SELECT anti_fraude_card, anti_fraude_duration FROM sync_devices WHERE id = <device_id>;`
- [ ] User scans card → granted. Second scan within 20s → access app log shows `DENY_ANTI_FRAUD_CARD`, Windows notification shown.
- [ ] User scans QR code → granted. Same QR credential (different TOTP code) within 20s → log shows `DENY_ANTI_FRAUD_QR`.
- [ ] Operator sets `antiFraudeCard=false` → re-syncs → card can be used within 20s without block.
- [ ] Device sync log shows `[DeviceSync] Device id=X anti-passback param OK (AntiPassback=1&AntiPassbackTime=20)`.
- [ ] Full test suite passes: `python -m pytest tests/ -v --tb=short`
