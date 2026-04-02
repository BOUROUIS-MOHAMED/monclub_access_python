# MonClub Access Launch Audit — Round 6 (2026-04-02)

Scope: `monclub_access_python` — full re-audit after previous fixes
Auditor role: principal software auditor / QA architect / security reviewer

---

## 1. Overall Assessment

The two previous launch blockers (B-001: local-API authentication, B-002: loopback bind) are **confirmed fixed and intact**.
Four logic bugs fixed in earlier rounds (AGENT fail-closed, ULTRA history source, TOTP rescue door routing, ULTRA sync scoping) are **confirmed intact**.

This round found **no new launch blockers** but identified **two medium-severity issues** that should be fixed before launch and **several medium/low issues** that should be addressed in the first post-launch sprint.

Verdict: **GO WITH TARGETED FIXES**

All previously-fixed blockers remain solid. The two new medium issues do not create false-allow door opens or expose the API beyond loopback; they create reliability and sync-correctness problems under specific configurations. Both are one-line or two-line fixes.

---

## 2. Launch Readiness Verdict

**GO WITH TARGETED FIXES**

Required before shipping:
- **M-NEW-001**: DeviceSyncEngine silently processes ULTRA-mode devices as DEVICE — fix `_normalize_device()` (one line)
- **M-NEW-002**: `_sync_work_running` flag set inside thread body rather than before thread start — fix scope (one line)

Confidence: **High on code-level findings, Medium on hardware runtime**

---

## 3. Top 10 Most Important Findings

| # | Severity | Title | Status |
|---|----------|-------|--------|
| 1 | Blocker → FIXED | Local API middleware validates real per-session token | Fixed in Round 5 |
| 2 | Blocker → FIXED | Local API bind hardcoded to 127.0.0.1 | Fixed in Round 5 |
| 3 | High → FIXED | End-to-end X-Local-Token bootstrap chain | Fixed in Round 5 |
| 4 | High → FIXED | AGENT mode fail-closed on history insert failure | Fixed in Round 4 |
| 5 | High → FIXED | ULTRA history_source preserved as "ULTRA" | Fixed in Round 4 |
| 6 | **Medium — NEW** | ULTRA devices double-synced by DeviceSyncEngine when DEVICE devices co-exist | **Needs fix** |
| 7 | **Medium — NEW** | New ULTRA device added while engine is running is silently ignored until app restart | **Needs fix** |
| 8 | **Medium — NEW** | `_sync_work_running` race: flag set inside thread, not before start | **Needs fix** |
| 9 | Medium → tracked | Fixed 5-min retry delay for history upload with no backoff/jitter | Post-launch sprint |
| 10 | Medium → tracked | ULTRA HistoryService double-insert on architecture is confusing and has edge-case history_source risk | Post-launch sprint |

---

## 4. Top Launch Blockers

### Previously resolved

**B-001 (FIXED):** Local API now enforces `X-Local-Token` on every non-exempt route.
Evidence: `app/api/local_access_api_v2.py:4237-4252` — `_AUTH_EXEMPT` set + `_caller_token != _expected_token` 401 gate.

**B-002 (FIXED):** `_effective_local_api_bind()` hardcodes `host = "127.0.0.1"`.
Evidence: `app/ui/app.py:670`.

### New findings requiring fix before launch

**M-NEW-001 — ULTRA devices double-synced by DeviceSyncEngine**

Affected file: `app/core/device_sync.py:206-210`

`_normalize_device()` maps `accessDataMode` to "DEVICE" for any value not in `{"DEVICE","AGENT"}`. "ULTRA" therefore becomes "DEVICE". When the full sync cache is passed to `DeviceSyncEngine.run_blocking()` and DEVICE-mode devices also exist (meaning the guard check at `app/ui/app.py:971` passes), ULTRA devices are synced every 60 seconds by DeviceSyncEngine in addition to every 15 minutes by `UltraSyncScheduler`. Concurrent PullSDK connections to the same device cause connection failures.

Fix: add `"ULTRA"` to the recognized-but-skipped set in `_normalize_device()` and in `_sync_all_devices()`.

**M-NEW-002 — New ULTRA device silently ignored by running engine**

Affected file: `app/ui/app.py:1010-1021`

`UltraEngine.start()` is guarded by `if self._running: return`. If the engine is already running for device A and device B switches to ULTRA, `sync_tick` fires with `ultra_count > 0 and self._ultra_engine.running` — neither start nor stop branch fires. Device B is never picked up until the last ULTRA device goes away and the engine restarts.

Fix: compare the current ULTRA device list against what the engine has and restart if it changed.

**M-NEW-003 — `_sync_work_running` race window**

Affected file: `app/ui/app.py:941-1058`

`self._sync_work_running = True` is set inside the worker thread body, not before `threading.Thread(...).start()`. A second `_sync_tick` fire could pass the guard check before the first thread sets the flag. Fix: set the flag before starting the thread.

---

## 5. Confidence Level

| Area | Confidence |
|------|-----------|
| Local API auth enforcement | High — directly traced |
| Loopback bind enforcement | High — directly traced |
| AGENT fail-closed logic | High — confirmed in code + regression test |
| ULTRA history source | High — confirmed in code + regression test |
| ULTRA TOTP rescue door routing | High — confirmed in code + regression test |
| ULTRA sync scoping | High — confirmed in code + regression test |
| DeviceSyncEngine double-sync of ULTRA | High — confirmed by tracing `_normalize_device()` |
| New ULTRA device not picked up | High — confirmed by tracing `UltraEngine.start()` guard |
| Runtime hardware behavior | Medium — not tested against live ZKTeco hardware |
| Installer / update path | Medium — not traced end-to-end |
