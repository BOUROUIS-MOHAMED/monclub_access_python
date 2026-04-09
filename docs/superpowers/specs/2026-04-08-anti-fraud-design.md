# Anti-Fraud System Design

**Date:** 2026-04-08
**Status:** Draft
**Repos affected:** `monclub_access_python`, `mon_club_dashboard`, `monclub_backend`

---

## Overview

Add a configurable anti-fraud system that prevents the same card or QR code from being
used to open any door on the same device more than once within a configurable duration.
Three new per-device settings control the feature. The card anti-fraud is enforced both
in software (for AGENT/ULTRA mode) and via a ZKTeco hardware parameter push (for DEVICE
mode). The QR code anti-fraud is enforced entirely in software by blocking the matched
credential for the configured duration after each successful grant.

---

## Goals

- Block reuse of the same **card number** on the same device within `anti_fraude_duration`
  seconds after a successful open.
- Block reuse of the same **QR credential** (identified by credential ID, not code string)
  on the same device within `anti_fraude_duration` seconds after a successful open.
- Push the card anti-fraud duration to the ZKTeco device hardware as an anti-passback
  parameter during every device sync.
- Show a notification on the PC screen when a blocked attempt occurs.
- Allow each feature to be toggled independently per device.
- Provide a clean, testable module that does not entangle anti-fraud logic with the
  existing event-processing loop.

---

## Non-Goals

- Cross-device (gym-wide) anti-fraud correlation.
- Persistent anti-fraud state that survives access app restarts (30-second TTL makes
  this unnecessary).
- Rate-limiting beyond the single configurable duration window.
- Biometric (fingerprint/face) anti-fraud.

---

## New Device Fields

Three new fields are added to the device model across all three repos:

| Field | Type | Default | Description |
|---|---|---|---|
| `antiFraudeCard` | boolean | `true` | Enable card anti-fraud on this device |
| `antiFraudeQrCode` | boolean | `true` | Enable QR code anti-fraud on this device |
| `antiFraudeDuration` | integer (seconds) | `30` | Block window after a successful grant |

---

## Architecture

### 1. Backend (`monclub_backend` — Java / Spring Boot)

**`GymDevice.java`**
Add three new JPA columns:
```java
@Column(name = "anti_fraude_card", nullable = false)
private boolean antiFraudeCard = true;

@Column(name = "anti_fraude_qr_code", nullable = false)
private boolean antiFraudeQrCode = true;

@Column(name = "anti_fraude_duration", nullable = false)
private int antiFraudeDuration = 30;
```

**`GymDeviceDto.java`**
Add the three fields to the DTO (matching camelCase names).

**`GymAccessController.java`** — `get_gym_users` sync response
Include the three fields in the `GymDeviceDto` builder inside the devices list, the same
way `totpEnabled`, `rfidEnabled`, and other device fields are already mapped.

**Database migration**
```sql
ALTER TABLE gym_device
    ADD COLUMN anti_fraude_card    BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN anti_fraude_qr_code BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN anti_fraude_duration INTEGER NOT NULL DEFAULT 30;
```
Existing devices automatically receive the default values — no manual data update needed.

---

### 2. Dashboard (`mon_club_dashboard` — React / TypeScript)

**`GymDeviceModel.ts`**
Add three fields with their defaults:
```typescript
antiFraudeCard: boolean = true;
antiFraudeQrCode: boolean = true;
antiFraudeDuration: number = 30;
```
Include them in `toJson()` / `fromJson()` serialisation methods.

**Device edit form**
Add a new **"Anti-Fraude"** section below the existing TOTP settings block:

```
┌─ Anti-Fraude ───────────────────────────────────────────┐
│                                                          │
│  Anti-fraude Carte         [ toggle ]                   │
│  Anti-fraude QR Code       [ toggle ]                   │
│                                                          │
│  Durée (secondes)          [ 30 ]                       │
│  (min 5 · max 300 · disabled when both toggles are OFF) │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

Saved via the existing `updateGymDevice` API call — no new endpoint required.

---

### 3. Access App (`monclub_access_python` — Python)

#### 3a. Database — `sync_devices` table (`app/core/db.py`)

Add three columns to the `sync_devices` table schema and migration:

```sql
anti_fraude_card     INTEGER NOT NULL DEFAULT 1,
anti_fraude_qr_code  INTEGER NOT NULL DEFAULT 1,
anti_fraude_duration INTEGER NOT NULL DEFAULT 30
```

`save_sync_cache_delta` already upserts every field from the backend device payload;
map the new camelCase keys to their snake_case column names in the existing INSERT
statement.

#### 3b. Settings normalisation — `normalize_device_settings()` (`app/core/settings_reader.py`)

Add three keys to the normalised settings dict returned for each device:

```python
"anti_fraude_card":     _boolish(raw.get("antiFraudeCard"), True),
"anti_fraude_qr_code":  _boolish(raw.get("antiFraudeQrCode"), True),
"anti_fraude_duration": _clamp_int(raw.get("antiFraudeDuration"), default=30, lo=5, hi=300),
```

`_boolish` and `_clamp_int` are helpers already present in `settings_reader.py`; they handle `None`,
integer-encoded booleans, and out-of-range integers defensively.

All downstream consumers (DecisionService, device sync) read device settings through
this dict, so no other plumbing is needed.

#### 3b′. `_coerce_device_row_to_payload()` in `db.py`

`_coerce_device_row_to_payload` converts a raw SQLite row from `sync_devices` into the
camelCase dict that `normalize_device_settings()` consumes. The three new columns must be
mapped here so the values survive the SQLite→settings round-trip:

```python
"antiFraudeCard":     _boolish(row["anti_fraude_card"], True),
"antiFraudeQrCode":   _boolish(row["anti_fraude_qr_code"], True),
"antiFraudeDuration": int(row["anti_fraude_duration"] or 30),
```

Use `_boolish()` (the same helper used for every other boolean column in that function)
to correctly handle `NULL`, integer-encoded booleans, and string values. Bare `bool()`
would silently misinterpret `"false"` as `True`.

Without this mapping, `normalize_device_settings()` would receive `None` for all three
keys and fall back to the defaults, making per-device configuration invisible at runtime.

#### 3c. `AntiFraudGuard` — new file `app/core/anti_fraud.py`

```python
class AntiFraudGuard:
    """
    Thread-safe in-memory guard that blocks reuse of a card or QR credential
    on a given device for a configurable duration after a successful grant.

    Key: (device_id: int, token: str, kind: str)
    Value: expires_at (monotonic float)
    kind is "card" or "qr".
    For cards, token = card_no.
    For QR, token = credential ID (cred_id UUID string).
    """

    def check(
        self, device_id: int, token: str, kind: str
    ) -> tuple[bool, float]:
        """
        Returns (is_blocked, seconds_remaining).
        seconds_remaining is 0.0 when not blocked.
        """

    def record(
        self, device_id: int, token: str, kind: str, duration: float
    ) -> None:
        """
        Record a successful access grant. Overwrites any existing entry
        for the same key (extends the window if called twice quickly).
        Evicts stale entries lazily on every call.
        """
```

**Internal state:**
```python
_entries: dict[tuple[int, str, str], float]  # key → expires_at (monotonic)
_lock: threading.Lock
```

**Eviction:** On every `record()` call, entries whose `expires_at < now` are removed
before inserting the new one. At gym scale (< 100 doors, 30s TTL) the dict never grows
large enough to require a background eviction thread.

**Lifecycle:** A single `AntiFraudGuard` instance is created in `MainApp.__init__` and
passed to `DecisionService` at construction. Because TTLs are 30 seconds, state lost on
restart is operationally irrelevant.

#### 3d. `DecisionService` integration — `realtime_agent.py`

The existing hardcoded 10-second card cooldown dict is **removed** and replaced by the
`AntiFraudGuard`. Two insertion points:

**Pre-check (before `verify_totp`):**
```
receive event
→ event_id dedup (existing)
→ [NEW] if anti_fraude_card enabled:
      blocked, remaining = guard.check(device_id, card_no, "card")
      if blocked → deny DENY_ANTI_FRAUD_CARD, notify, skip
→ verify_totp() / verify_card()
```

The pre-check covers **card anti-fraud only**. Because TOTP strings rotate with every
code generation, matching an incoming QR scan by `card_no` at this stage provides no
meaningful protection — the physical card number that arrives on the ZKTeco event is the
TOTP device serial, not the credential. QR anti-fraud must therefore be checked
post-verify, after `cred_id` has been resolved.

**Post-verify, pre-door-open (only when `allowed=True`):**
```
verify_totp() → result vr, scan_mode known, allowed flag
→ cred_id = vr.get("credId")          # stable UUID across code rotations; None if absent
→ [NEW] if scan_mode == "QR_TOTP" and anti_fraude_qr_code enabled and cred_id:
      blocked, remaining = guard.check(device_id, cred_id, "qr")
      if blocked → override allowed=False, reason=DENY_ANTI_FRAUD_QR, notify
→ _history_claimed = insert_access_history(...)   # rowcount after INSERT
→ [NEW] if allowed and not blocked and _history_claimed > 0:
      if scan_mode == "QR_TOTP" and cred_id:
                               guard.record(device_id, cred_id, "qr", duration)
      else:                    guard.record(device_id, card_no, "card", duration)
→ open door (existing)
```

Key constraints:
- `cred_id` is only present in `vr` when `verify_totp()` successfully resolves a
  credential. It is absent on denials such as `DENY_COLLISION` or `DENY_AMBIGUOUS_COUNTER`.
  Always guard with `if cred_id:` before using it as a guard key.
- `guard.record()` requires `allowed=True` in addition to `not blocked` and
  `_history_claimed > 0`. Without the `allowed` check, a rejected card scan
  (`DENY_UNKNOWN_CARD`) would record the card_no and block the next legitimate scan.
- `guard.record()` is called **after** `insert_access_history()` and only when
  `_history_claimed > 0`. This prevents extending the block window on duplicate events
  that were deduped and never written to history.

**Notification on block:**
`reason="DENY_ANTI_FRAUD_CARD"` or `"DENY_ANTI_FRAUD_QR"` is passed to the existing
notification service. The notification message reads:

> *Accès refusé — anti-fraude actif (Xs restant)*

where X is `ceil(seconds_remaining)`.

#### 3e. `_normalize_device()` in `device_sync.py`

`device_sync.py` builds its per-device config dict via `_normalize_device(row)`, which
reads columns directly from the `sync_devices` SQLite row. The three new columns must be
extracted here so the hardware-push logic in §3f can access them:

```python
"anti_fraude_card":     _boolish(row.get("anti_fraude_card"), True),
"anti_fraude_qr_code":  _boolish(row.get("anti_fraude_qr_code"), True),
"anti_fraude_duration": _to_int(row.get("anti_fraude_duration"), 30),
```

Use `_boolish()` (consistent with every other boolean in `_normalize_device()`) and
the module-local `_to_int()` helper already used for other integer fields. Bare `bool()`
would silently misinterpret string or NULL values.

Without this, `device_sync.py` would always read `None` for these keys regardless of
what the operator configured in the dashboard.

#### 3f. ZKTeco hardware push — `device_sync.py`

After user data is successfully pushed to a DEVICE-mode or ULTRA-mode device, one
additional `SetDeviceParam` call configures the hardware anti-passback:

```python
if anti_fraude_card:
    param_value = f"AntiPassback=1&AntiPassbackTime={anti_fraude_duration}"
else:
    param_value = "AntiPassback=0"

result = pullsdk.set_device_param(device_addr, param_value)
if not result:
    logger.warning("[DeviceSync] anti-passback param push failed for device %s", device_id)
    # Non-fatal — software guard remains the primary enforcer
```

**Parameter name caveat:** `AntiPassback` and `AntiPassbackTime` are the expected
parameter names for ZKTeco C3-200/C3-400 series via `SetDeviceParam`. The exact names
must be verified against the SDK reference for each `DeviceModel` enum value during
implementation. A per-model lookup dict should be used if names differ across models.
If a device model does not support the parameter, the failure is logged and silently
skipped.

---

## Data Flow Summary

```
Dashboard edit device
  → PATCH /updateGymDevice { antiFraudeCard, antiFraudeQrCode, antiFraudeDuration }
  → Backend saves to gym_device columns
  → Next sync cycle (get_gym_users) includes new fields in devices array
  → Access app: save_sync_cache_delta writes to sync_devices table
  → normalize_device_settings() exposes them as snake_case keys
  → DecisionService reads settings per event → checks/records via AntiFraudGuard
  → device_sync.py reads settings → pushes SetDeviceParam to ZKTeco hardware
```

---

## Deny Reasons Added

| Reason | Trigger |
|---|---|
| `DENY_ANTI_FRAUD_CARD` | Card used within `anti_fraude_duration` on same device |
| `DENY_ANTI_FRAUD_QR` | QR credential used within `anti_fraude_duration` on same device |

Both are recorded in `access_history` with `allowed=False` like any other denial.

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| ZKTeco `SetDeviceParam` parameter names differ by model | Per-model lookup dict; failure is non-fatal, software guard is primary |
| Race condition: two events for same card arrive simultaneously | `AntiFraudGuard` uses a single lock; one thread records first, second hits `check` and is blocked |
| Anti-fraud blocks legitimate rapid re-entry (e.g. door didn't open) | Duration is configurable (minimum 5s); operator can reduce it per device |
| In-memory state lost on restart | 30s TTL makes this operationally irrelevant |

---

## Success Criteria

- A card scanned twice within `anti_fraude_duration` on the same device: second attempt
  denied with `DENY_ANTI_FRAUD_CARD` and a PC notification shown.
- A QR credential used twice within `anti_fraude_duration` on the same device (even with
  a freshly generated code): second attempt denied with `DENY_ANTI_FRAUD_QR`.
- With `antiFraudeCard=False`: card anti-fraud is fully disabled; existing behaviour
  unchanged.
- With `antiFraudeQrCode=False`: QR anti-fraud is fully disabled; TOTP age validation
  still active.
- `SetDeviceParam` is called on every device sync when `antiFraudeCard=True`; failure
  does not abort the sync.
- Dashboard saves the three fields via the existing update call with no new endpoint.
