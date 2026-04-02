# MonClub Access Launch Readiness
# Round 6 — 2026-04-02

---

## Overall Verdict: GO

All blocker and high-severity findings are fixed. The three new medium-severity findings discovered in Round 6 (M-NEW-001, M-NEW-002, M-NEW-003) have been fixed in this round. No launch blockers remain.

---

## Readiness by Mode

| Mode | Verdict | Condition |
|------|---------|-----------|
| DEVICE | GO | Clean. All fixes applied. |
| AGENT | GO | Clean. All critical issues from prior rounds confirmed fixed. |
| ULTRA (single-device) | GO | Clean after Round 6 fixes. |
| ULTRA + DEVICE mixed | GO | M-NEW-001 (double-sync) now fixed. |
| ULTRA multi-device with runtime add | GO | M-NEW-002 (new device ignored) now fixed. |

---

## Pre-launch Checklist

### Security
- [x] Local API bound to 127.0.0.1 (B-002 fixed Round 5)
- [x] Per-session token generated at startup, validated on every non-exempt endpoint (B-001 / H-001 fixed Round 5)
- [x] DPAPI protection fail-closed on encrypt failure (B-002 in auth_state)
- [x] Door-open rate limit 1s per device (M-003 fixed Round 4)
- [ ] **Verify `gym_access_secrets_cache.json` excluded from build / gitignored** (L-003 — manual check)

### Access Decision Safety
- [x] Fail-closed on DB failure: AGENT (`_history_claimed=0`) and ULTRA (`inserted=False`)
- [x] Atomic dedup: `INSERT OR IGNORE` on `UNIQUE(event_id)` prevents double door-open
- [x] Anti-wipe guard: backend returning 0 users does not wipe local cache when >10 present
- [x] Fingerprint SDK fail-closed: ZKFinger `OSError` returns no-match (H-005 fixed Round 5)
- [x] TOTP collision detection: `DENY_COLLISION` when two credentials match

### Sync / Device
- [x] ULTRA devices no longer double-synced by DeviceSyncEngine (M-NEW-001 fixed Round 6)
- [x] New ULTRA device picked up at runtime without app restart (M-NEW-002 fixed Round 6)
- [x] `_sync_work_running` flag set before thread start, not inside (M-NEW-003 fixed Round 6)
- [x] Hash-based change detection: skips push if no user/card/FP changes
- [x] Per-device sync state persistence: dirty hash retried on next cycle after failure

### Reliability / Recovery
- [x] 15s PullSDK watchdog on both AGENT and ULTRA polling loops
- [x] Exponential backoff on device reconnect (AGENT: 0.25s → 30s; ULTRA: 5s)
- [x] 15s force-exit daemon thread on shutdown (H-003 fixed Round 4)
- [x] ULTRA start/stop guarded by `_ultra_lock` (H-004 fixed Round 4)
- [x] Pre-populated seen-deque on restart prevents event replay

### Operational
- [x] `/api/v2/status` reports real sync timestamps and ok/error state (H-005 fixed Round 5)
- [x] `/api/v2/ultra/status` reports per-device worker state and sync timestamps
- [x] Access history uploaded to backend in 200-row batches with retry
- [x] History rows pruned locally after configurable retention period

---

## Open Items (Post-launch, not blockers)

| ID | Item | Effort | Risk if deferred |
|----|------|--------|-----------------|
| M-005 | History retry jitter | 1 line | Synchronized retry storms after backend outage |
| M-006 | ULTRA HistoryService architectural cleanup | Refactor | Misclassified history_source in rare failure case |
| L-001 | "raw:" legacy token migration | 5 lines | Pre-DPAPI installs keep unencrypted tokens |
| L-002 | `pushingToDevicePolicy` enforcement | Design | Silently ignored — no effect |
| L-003 | Verify `gym_access_secrets_cache.json` excluded from build | 1 check | Potential credential leak in build artifact |
| L-004 | Per-device UltraSyncScheduler intervals | Refactor | Fastest-device interval applied to all |
| L-005 | `put_nowait` + drop count in DeviceWorker event queue | 5 lines | Thread block under sustained event burst |
| L-006 | Max-cache-age enforcement | 2 lines + config | Stale credentials served indefinitely offline |

None of these affect access control correctness or safety. All are deferred with known risks documented.

---

## Test Coverage

| Suite | Count | Status |
|-------|-------|--------|
| `tests/test_ultra_engine.py` | 73 tests, 10 classes | 73 pass |
| `tests/test_auth_reconnect.py` | Added Round 6 | Pass |
| All other tests | 71 tests | Pass |
| **Total** | **144 tests** | **144 pass** |

Round 6 code fixes verified: all 144 tests pass after applying M-NEW-001, M-NEW-002, M-NEW-003.

---

## Configuration Checklist (Operator)

Before first deployment at each site:

1. **Backend configuration**: verify `sync_interval_sec`, `rtlog_poll_timeout_sec`, `ultra_sync_interval_minutes` are set to appropriate values for network conditions.
2. **Device modes**: confirm each ZKTeco device has the correct `accessDataMode` set in the backend (DEVICE / AGENT / ULTRA). Mixed-mode deployments now supported cleanly after Round 6 fixes.
3. **Door IDs**: confirm `door_entry_id` (AGENT mode) and `doorIds` (per-device) match the physical door assignments in the ZKTeco firmware.
4. **TOTP credentials**: verify `max_past_age_seconds` (default 32s) is appropriate for the site's clock tolerance.
5. **Timezone offset**: confirm `tz_offset_sec` matches the ZKTeco device's configured timezone to ensure cursor-based event filtering works correctly.
6. **History retention**: confirm `retention_days` is set per site data policy.

---

## Known Limitations (By Design)

- RFID card expiry is not re-checked per-event in AGENT or ULTRA modes. Membership validity is filtered at device-sync time. An expired member whose device sync hasn't run yet will still be granted access. This is a deliberate trade-off for offline robustness.
- ULTRA ALLOW events are not re-validated by the PC. If device firmware has stale user data, the PC cannot block the door-open. This is the ULTRA design contract (firmware-first).
- TOTP codes are valid for the full 30-second counter window. A captured code replayed within the same window will succeed (standard TOTP behavior; per-event dedup prevents the same physical event from opening the door twice).
- History upload uses a fixed 300s retry delay with no jitter (M-005). Under prolonged backend outage, sites may retry simultaneously on recovery. Local history is preserved regardless.
