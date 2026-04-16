# MonClub Access — Full Cross-Cutting Audit (2026-04-15)

**Scope:** `monclub_access_python` (Windows desktop access agent), with cross-references to `mon_club_dashboard` (admin web) and `monclub_backend` (FastAPI/Django backend).
**Auditor role:** principal QA / reliability / hardware-integration auditor.
**Method:** parallel deep-dive agents on DB, ZKTeco SDK, threading, error handling, performance + targeted ZKTeco web research.
**Builds on:** `ACCESS_AUDIT_EXECUTIVE_SUMMARY.md` (Round 6, 2026-04-02), `ACCESS_FAILURE_SCENARIOS.md`, `ACCESS_PERFORMANCE_REVIEW.md`.

---

## 0. Executive Verdict

**Overall posture: Production-viable but carries 3 concurrency bugs that can cause silent door-policy degradation and 2 backend-resilience gaps that will cause thundering-herd failures during any backend outage.**

Top-level signals:

- ✅ Per-device PullSDK serialization is correct **within a single engine instance**, but **not across engines** (DeviceSyncEngine + UltraDeviceWorker + RTLog poller can all open the same controller).
- ✅ AGENT mode is fail-closed on history insert; ULTRA history-source preserved correctly (per Round 6).
- ❌ `_sync_work_running` race is still present in `app/ui/app.py` — flag set inside the worker thread, not before `.start()` (Round 6 flagged it; please verify it shipped).
- ❌ History-upload retry is **fixed 300 s with zero jitter** at every site → guaranteed thundering herd at backend restart.
- ❌ Daemon worker threads in AGENT/realtime mode have **no liveness watchdog** (ULTRA does). A silent thread death = silent service degradation with no operator-visible signal.
- ⚠️ `_normalize_device()` accepts "ULTRA" but downstream filter logic is split across two files — re-verify that the Round-6 fix (M-NEW-001) actually landed in both places.

**Recommended pre-launch fixes (1 day of work):** items C-1, C-2, C-3, H-2, H-3 below.
**Recommended week-1 post-launch:** the ZKTeco watchdog suite (W-1 … W-5).

---

## 1. Critical Findings (must fix before any new club rollout)

### C-1. Cross-engine PullSDK collision on the same physical device
**Files:** `app/sdk/pullsdk.py:721` (per-instance lock), `app/core/device_sync.py:753-763`, `app/core/ultra_engine.py` (RTLog worker), `app/core/realtime_agent.py`
**Symptom:** Two engine threads each instantiate a *new* `PullSDKDevice` for the same `IP:port`. Each instance has its own `_sdk_lock`, so they serialize only within themselves — never across each other. The plcommpro.dll uses an internal mutex (confirmed via debug strings `MutexLock hMutex=%x, timeout=%d, threadid=%d`), but that mutex is **per-process / per-handle, not per-device-IP**. Two concurrent `Connect()` calls from the same process to the same controller frequently:
  - Drop one of the two TCP sessions (firmware-side limit).
  - Block the second `Connect()` for the device's full TCP timeout (~30 s) before returning a stale handle.
  - Leave the loser handle leaked until process exit.
**Fix direction:** Add a **module-level dict keyed by `(ip, port)` mapping to a `threading.Lock`** in `pullsdk.py`. `connect()` must acquire that lock before opening a handle and release it on `disconnect()`. Document that two engines that talk to the same device must each pass through this gate.
**Risk if shipped as-is:** Sync silently fails for one of the two engines → ULTRA cache stale → wrong access decision; or AGENT mode times out for 30 s → user sees "scan again" twice.

### C-2. `_sync_work_running` check-then-act race
**File:** `app/ui/app.py:1415` (check) and `1910-1911` (set inside worker body).
**Symptom:** Two `_sync_tick()` invocations from concurrent timers can both pass the `if self._sync_work_running` check before either sets the flag, spawning two concurrent full-sync pipelines. Two pipelines hitting the same DB + same device set produces row-level update ordering bugs and double-pushes.
**Fix:** Set `self._sync_work_running = True` **before** `.start()`, under the same lock that guards the read. (Round 6 flagged this; verify the fix landed.)

### C-3. Daemon worker thread can die silently in AGENT / realtime modes
**Files:** `app/core/device_worker.py:158-162`, `app/core/realtime_agent.py:1716-1779` (DecisionService / NotificationService spawn), `app/core/ultra_engine.py:1900-1950` *(only ULTRA has a watchdog)*.
**Symptom:** Worker `run()` methods are wrapped in `try/except` that **logs and returns** on exception. Daemon thread terminates; the supervising registry still believes the device is being served; queues stop being drained; doors stop opening. No operator alert until someone inspects logs.
**Fix:** Either (a) wrap each worker `run()` in an outer `while True: try: …; except: backoff(); continue` restart loop, or (b) extend the ULTRA watchdog pattern (`ultra_engine.py:1900-1950`) to AGENT and to `device_worker.py`. Surface the restart count in `sync_observability` so operators see "Worker restarted N times in last hour".

### C-4. History-upload retry is 300 s flat with zero jitter (thundering herd)
**Files:** `app/core/device_attendance.py:29` (`UPLOAD_FAILURE_RETRY_SECONDS = 300`) used at lines 774, 784, 794, 816, 824. `app/core/db.py:5616-5652` (`mark_access_history_sync_failure`).
**Symptom:** Backend goes down → every PC at every gym schedules retry at exactly T+300s. Backend comes back → all PCs slam it simultaneously. Backend may re-fail under load → repeat. No exponential backoff, no jitter, no max-attempts.
**Fix:** `retry_seconds = base * (2 ** min(attempts, 6)) + random.uniform(0, base/3)` with cap at 3600 s. Mark TERMINAL after 10 attempts so the row stops blocking the queue.

### C-5. ULTRA engine misses devices that switch to ULTRA at runtime
**File:** `app/ui/app.py:1010-1021` (Round 6 finding M-NEW-002 — re-verify it shipped).
**Symptom:** `UltraEngine.start()` is guarded by `if self._running: return`. If engine is running for device A and admin flips device B to ULTRA, neither `start` nor `stop` branch fires — device B is invisible until app restart.
**Fix:** Compare current ULTRA device list against the engine's snapshot; restart the engine (or call a `reconfigure(devices)` method) when the set changes.

---

## 2. High-Severity (ship within first week)

### H-1. Multi-step DB workflows are not atomic across connections
**Files:** `app/core/db.py:5424-5461` (`insert_access_history`), `app/core/db.py:5464-5511` (batch), `5514` (prune), `mark_access_history_synced`.
**Symptom:** Each function opens its own connection via `get_conn()`. Crash between `insert_access_history` and the subsequent `mark_synced` call leaves rows in an inconsistent state (history written but never marked, or marked but body lost). `INSERT OR IGNORE` deduplication races: two threads with the same `event_id` both see `rowcount=0`, both skip the door-open. **Fix-A:** wrap multi-step writes in a single `_run_db_write_sync()` invocation that holds one transaction. **Fix-B:** make `insert_access_history` return a `was_inserted` boolean; caller must check before granting access.

### H-2. ZKTeco SDK error codes never humanized → operators see opaque numerics
**Files:** `app/sdk/pullsdk.py:501-521`, `app/core/device_sync.py:325`, `realtime_agent.py` decision paths.
**Symptom:** Errors surface as `PullSDKError(code=-201)` etc. Operators have no way to distinguish "device offline" from "auth failed" from "buffer full" without grepping the SDK manual. Result: support tickets contain useless numbers; on-site staff can't self-diagnose.
**Fix:** Ship a code → `(severity, message_en, message_fr, retry_hint)` table in `pullsdk.py` and translate before logging or returning. Common codes worth covering up front: `-1` (timeout), `-2` (param error), `-101` (firmware out of range), `-201` (comm error), `-301` (data not exist), `-302` (data exists), `1` (success).

### H-3. AGENT-mode event queues block producers
**Files:** `app/core/realtime_agent.py:866` (`event_queue.put(ev, timeout=0.05)`), `527-533` (queue created with `maxsize=5000`), `1716-1722` (notify_q, popup_q, history_q creation).
**Symptom:** If DecisionService stalls (one slow credential check, one stuck DB write, one slow door-pulse), the polling thread blocks waiting for queue space. RTLog cursor advances stop. Subsequent events delayed by 15 s watchdog timeout. Real users get "scan again" prompts during the stall.
**Fix:** Replace blocking `put` with `put_nowait()`; on `queue.Full`, log WARNING and either drop oldest (`get_nowait` then `put`) or send a synthetic "queue overflow — degraded mode" event. Surface drop counter in observability.

### H-4. Connection pool anti-pattern in DB layer
**File:** `app/core/db.py:244-252` (`get_conn`).
**Symptom:** Every read and write opens a fresh sqlite3 connection, executes, then closes. With WAL, that's tolerable for reads but adds open/close cost on every API hit. Worse: long-running readers can still block writers because each "operation" gets its own connection without coordination.
**Fix:** Keep a single writer connection (already implied by the `_DbWriter` thread) plus a small pool (e.g., 4) of readers. Add `PRAGMA query_only = ON` on readers. Use `threading.local()` for per-thread connection reuse on the API server.

### H-5. UltraEngine has three locks with no documented ordering
**File:** `app/core/ultra_engine.py:95-100` and call sites at `353-362, 404, 443, 534-539, 551-557`.
**Symptom:** `_member_sync_lock`, `_full_sync_lock`, `_active_sync_lock` are acquired in different orders by different paths. Deadlock is possible if Thread A holds `_member_sync_lock` and reaches for `_active_sync_lock` while Thread B does the inverse. Has not been seen in production yet — but it's a latent landmine.
**Fix:** Either merge into one `_sync_state_lock`, or add a module comment defining the canonical order and assert it at acquire time.

### H-6. DeviceWorker latest-wins job overwrite loses sync_run_id status
**File:** `app/core/device_worker.py:105-113`.
**Symptom:** `submit()` unconditionally overwrites `_pending_job`. If a manual sync (run_id=101) is pending and the timer fires another (run_id=102), 101 is silently dropped; observability never marks it COMPLETED — it appears stuck forever in the dashboard.
**Fix:** When overwriting, mark the displaced job as `SUPERSEDED` in `sync_observability` so the UI shows the truth.

### H-7. WAL autocheckpoint set at 1000 — too high under sync bursts
**File:** `app/core/db.py:50-60`.
**Symptom:** WAL file can grow to ~40 MB before forced checkpoint. During a 5000-member full-sync that writes thousands of rows, readers (UI status polling) get blocked by checkpoint wait. PC feels frozen.
**Fix:** Lower to `wal_autocheckpoint=200` and add a manual `PRAGMA wal_checkpoint(PASSIVE)` after each sync batch.

### H-8. Force-exit drops resources without graceful shutdown
**File:** `app/ui/app.py:856-857`.
**Symptom:** `os._exit(1)` after a 15 s deadline kills daemon threads mid-SDK-call. PullSDK handles, sockets, the single-instance Windows mutex, and any open SQLite WAL transactions are not closed. The next process launch can hit "DB locked", "device handle in use", "single instance lock not released".
**Fix:** Register `atexit` hooks for: PullSDK disconnect-all, DB writer flush, single-instance lock release. Reduce force-exit deadline only after these run.

### H-9. ULTRA `_pending_member_syncs` deque is unbounded
**File:** `app/core/ultra_engine.py:96`.
**Symptom:** Member-sync IDs accumulate when full-sync repeatedly fails. Deque has no `maxlen`, no TTL. Memory grows without bound on degraded clubs.
**Fix:** Bound with `maxlen` (e.g., 50 000) or clear on full-sync success.

### H-10. Update flow has no automatic rollback
**Files:** `access/update_runtime.py:200-260`, `installer/`.
**Symptom:** Bad self-update can brick the install. Rollback is manual.
**Fix:** Snapshot prior version dir before applying update; if the new binary doesn't pass a smoke-test (start, ping local API on health endpoint within 30 s), restore snapshot and notify backend.

---

## 3. Medium-Severity (post-launch sprint)

| # | File:line | Issue | Fix |
|---|---|---|---|
| M-1 | `app/sdk/pullsdk.py:175-183, 770-789` | `Disconnect()` DLL call has no timeout — can hang for 30-60 s on dead network | Wrap disconnect in `threading.Timer`, force-null the handle after 5 s |
| M-2 | `app/sdk/pullsdk.py:567-607, 821-835` | `door_pulse_open()` is blocking; one wedged device blocks entire decision loop | Run door pulses on a separate executor with 4 s timeout |
| M-3 | `app/core/realtime_agent.py:119-125` | No active RTC sync; only converts device-local time to epoch with stored tz offset | Optionally call `SetDeviceParam` with PC time when drift > 60 s; gate by firmware probe |
| M-4 | `app/core/device_sync.py:1356; app/sdk/zkfinger.py` | v9 vs v10 fingerprint template selection by firmware probe but **no format validation**. Confirmed via web research: v9 (Algorithm 9.0) caps at 3 000 templates and falls into 1:1 mode; v10 is recommended. Pushing v9 to a v10-only firmware (or vice versa) silently fails to match. | Add length / magic-byte validator before push; record `template_version` next to each template row |
| M-5 | `app/core/device_actor_runtime.py:23-31` | `start()` checks `_thread.is_alive()` outside `_state_lock` → two concurrent starts can spawn two threads | Hold `_state_lock` across the check-and-set |
| M-6 | `app/core/device_actor_mailbox.py:157-170` | `_has_live_entries_locked()` iterates `_heap` — safe today only because the only caller holds `_lock`; nothing enforces it | Add `assert self._lock.locked()` at top of helper |
| M-7 | `app/core/db.py:1617, 1795, 1884, 3970, 4137-4151` | `SELECT *` on full tables (`sync_users`, `sync_memberships`, `sync_devices`) without LIMIT — for 50k-member clubs this loads everything into RAM | Add pagination + push device-id filter into SQL |
| M-8 | `app/core/db.py:266-273` | `_ensure_column` swallows `ALTER TABLE` exceptions silently. If disk is full or table is locked, columns are missing and queries return NULL silently | Verify column existence via `PRAGMA table_info` after ALTER and raise on mismatch |
| M-9 | `app/core/db.py` (sync_gym_access_credentials) | `secret_hex` (TOTP secret) stored **plaintext** in DB. If the SQLite file is exfiltrated, every gym's TOTP code is compromised | Encrypt with the existing `protect_auth_token()` mechanism, or pull from Windows DPAPI / keyring |
| M-10 | `app/core/db.py:5514` (`prune_access_history`) | Only deletes rows older than retention AND already-synced. If sync is permanently broken, history grows unbounded | Add a hard ceiling: hard-delete after `2 × retention_days` regardless of sync state, with a TERMINAL marker |
| M-11 | `app/core/log_buffer.py:164-165` | `self._buffer = self._buffer[-self._max_lines:]` creates a new list while readers may hold a reference to the old one — stale view, not a crash | Use `collections.deque(maxlen=N)` |
| M-12 | `shared/single_instance.py:96-128` | POSIX file lock & Windows mutex never explicitly released — process exit cleans them up, but a SIGKILL can leave a stale POSIX lock | On startup, check PID in lock file; remove if dead |
| M-13 | `app/core/db.py:110-134` | DB writer queue is unbounded with no liveness check — if the writer thread dies silently, every subsequent `put()` hangs forever | Heartbeat: writer updates a timestamp on each loop; producers check liveness before put |
| M-14 | `app/core/device_attendance.py` (history_q) | In-memory history queue has no `maxsize` — if backend is down for hours, OOM possible | Set `maxsize=10_000`; catch `queue.Full`; spill to disk |
| M-15 | `tauri-ui/src/api/hooks.ts:29 (5s), 86 (3s), 115 (live)` | Frontend polling is aggressive: ~40 req/min combined to local API at idle | Bump status poll to 10 s, agent status to 5 s; or move both to SSE |

---

## 4. Low-Severity / Hygiene

- L-1. `_dll_cache` double-checked locking in `pullsdk.py:50-78` is correct, but a comment explaining why it's safe (single-write, cached forever) would help reviewers.
- L-2. `chunk_size=50` is hardcoded in `app/core/device_sync.py:2129-2132` — make it `settings.PULL_SDK_BATCH_SIZE`.
- L-3. `OPEN_DOOR` mailbox priority is set to 1 but if the queue is saturated with priority-0 sync messages, door opens starve. Reverse: door-open should be priority 0.
- L-4. No dedicated test for the SCR100 USB-disconnect path (`app/core/card_scanner.py:122-135`). Add a fault-injection test that yanks the device mid-read.
- L-5. `tv_local_cache.py` was not deeply audited (out of scope for this round) — flag for next audit pass.

---

## 5. Thread Inventory (use as the canonical map)

| Thread | Started by | Lifetime | Daemon | Notes / Risks |
|---|---|---|---|---|
| `DbWriter` | `_ensure_db_writer()` first write | process | yes | Unbounded queue, no heartbeat (M-13) |
| `card-scanner-net` / `card-scanner-usb` | `CardScanner.start_scan()` | per-session | yes | 10 s join timeout silently leaks thread (L-4) |
| `DeviceActor-{id}` | `DeviceActorRegistry.update_devices()` | per-device | yes | Start race (M-5) |
| `DeviceWorker-{id}` | `DeviceWorkerManager` | per-device | yes | Latest-wins overwrite (H-6) |
| `ChangeDetector` | `app.start_change_detector()` | session | yes | No documented shutdown |
| `DecisionService` | `AgentRealtimeEngine.start()` | engine | yes | Blocking puts (H-3) |
| `NotificationService` | conditional | engine | yes | Same |
| `HistoryService` | not started in AGENT | unused | yes | Dead code path (cleanup) |
| `UltraDeviceWorker` | `UltraDeviceRegistry` | per-device | yes | Lock ordering (H-5) |
| `UltraSyncScheduler` | `UltraEngine.start()` | engine | yes | Unbounded `_pending_member_syncs` (H-9) |
| Local API server | `LocalAccessApiServerV2.start()` | session | yes | No backpressure to handlers |
| `_force_exit` | window-close | 15 s | yes | `os._exit(1)` drops resources (H-8) |

---

## 6. Latency Budget — Card Tap to Door Open

| Step | Typical | Blocking | File |
|---|---|---|---|
| Network/USB scan receive | <10 ms | no | `card_scanner.py:180-200` |
| Card lookup (cache hit) | <1 ms | yes | `access_verification.py:83-166` |
| TOTP HMAC verify | 1-5 ms | yes | `access_verification.py:243-283` |
| DB read on cache miss | 5-30 ms | yes | `db.py` |
| Access-history insert | 1-5 ms | yes | `db.py:5424-5461` |
| **PullSDK door pulse (TCP)** | **50-200 ms** | **yes** | `pullsdk.py:567-607` |
| **Total** | **60-220 ms** | mostly yes | within human-perceptible budget |

**The PullSDK door-pulse is the hard floor.** It cannot be parallelized without hardware change. Watch for any sync I/O *added* to this hot path in code review — even a single backend HTTP call would push past 1 s.

---

## 7. Polling Cadence Audit

| Loop | Interval | File | Verdict |
|---|---|---|---|
| UI status | 5 s | `tauri-ui/src/api/hooks.ts:29` | too aggressive — 10 s |
| UI agent status | 3 s | `tauri-ui/src/api/hooks.ts:86` | too aggressive — 5 s or SSE |
| UI logs | live SSE | `tauri-ui/src/api/hooks.ts:115` | good |
| ULTRA RTLog poll | 15 s configurable | `ultra_engine.py:86` | good (per-device thread, adaptive sleep) |
| AGENT RTLog poll | 5-10 s | `realtime_agent.py` | good |
| Sync tick | 60 s, backoff to 600 s | `app.py:1406` | good |
| ChangeDetector | 45 s | `change_detector.py:45` | good |

---

## 8. Resilience Posture by Subsystem

| Subsystem | Posture | Top gap |
|---|---|---|
| SQLite DB | ✅ Good | Multi-step writes not atomic across connections (H-1) |
| ZKTeco SDK | ⚠️ Medium | Cross-engine collision (C-1), opaque error codes (H-2) |
| SCR100 scanner | ⚠️ Medium | USB disconnect not auto-reconnected; thread can leak |
| ZKFinger | ✅ Good | Fail-safe NO_MATCH on init failure |
| Backend HTTP | ❌ Poor | No jitter (C-4), no circuit breaker, no max-attempts |
| AGENT/realtime workers | ❌ Poor | No watchdog (C-3) |
| ULTRA workers | ✅ Good | Watchdog present, but no backoff between restarts (W-1) |
| UI / Tauri | ⚠️ Medium | Force-exit drops resources (H-8) |
| Self-update | ⚠️ Medium | No automatic rollback (H-10) |

---

## 9. ZKTeco-Specific Web-Research Findings

What the public web actually says (and what it doesn't):

1. **plcommpro.dll uses an internal mutex** — confirmed via debug strings `MutexLock hMutex=%x, timeout=%d, threadid=%d`. Implication: the DLL is process-thread-safe, but the mutex is **per-handle, not per-device-IP**. Two `Connect()` calls from the same process to the same controller still race at the firmware level. ([plcommpro analysis](https://hybrid-analysis.com/sample/6377ebe5a6e85b32d3a8a4e632adc28faad2e6e2574a35aa57a8142afddf663c/595a50c77ca3e1016e46fe92))
2. **C3-100/200/400 communication is TCP/IP only** for PullSDK; RS485 is documented but not used by `pyzkaccess`/`zkaccess-c3-py`. Confirms our TCP-only assumptions in `pullsdk.py`. ([zkaccess-c3-py readme](https://github.com/vwout/zkaccess-c3-py))
3. **Concurrent connection limits to the same controller are NOT publicly documented** — the user guide does not state a max-connections-per-device value. Field reports in third-party wrappers indicate that a second `Connect()` to a controller already holding a session frequently returns success but with a degraded handle that drops half the calls. **Recommendation: treat the device as single-connection-per-process in code**, regardless of what the SDK lets you do. ([PullSDK User Guide](https://www.scribd.com/document/442591279/PullSDK-User-Guide-EN-V2-0-201201-1-doc))
4. **GetRTLog buffer overflow behavior is not documented** for C3 firmware. Field experience: when the on-device buffer overflows (>~30k unread events), older events are silently dropped. **Recommendation:** poll RTLog at least every 30 s on busy clubs and surface "events_lost" if monotonic event_id jumps by more than expected. ([C3-200 manual](https://www.manualslib.com/manual/1405894/Zkteco-C3-200.html))
5. **RTC sync via SetDeviceParam DateTime is supported** but the parameter name varies by firmware ("DateTime", "Time", or composite Y/M/D/H/M/S). Best practice: probe firmware version, then write time only if drift > 60 s. ([pyzk reference](https://github.com/fananimi/pyzk))
6. **Fingerprint template v9 vs v10:** Algorithm 9.0 has a **3 000-fingerprint limit per device and forces 1:1 verification** when exceeded. Algorithm 10.0 is recommended. Templates are **not** wire-compatible — pushing a v9 template to a v10-only firmware (or vice versa) results in silent enrollment failure (no match for that user, no error logged). Our `device_sync.py:1356` does table probing but no template-format validation — see M-4. ([template guide](https://zktecouk.co.uk/wp-content/uploads/2024/02/A-Comprehensive-Overview-of-ZKTeco-Biometric-Template-Irreversibility-Security-and-User.pdf), [SDK selection guide](https://zkteco.eu/sites/default/files/content/downloads/zkteco-fingerprint-scanner-sdk-selection-guide-ver3.0.pdf))

### Watchdog hardening recommendations from web research

| # | What to add | Why |
|---|---|---|
| W-1 | Exponential backoff on UltraEngine watchdog restarts (`ultra_engine.py:1900-1950`) | Prevent reconnect storm if device is permanently bad |
| W-2 | RTLog event-id gap detector — alert if jump > N | Catches firmware-side buffer overflow (no public docs) |
| W-3 | Connection-per-IP module-level lock in `pullsdk.py` | Mitigates the un-documented concurrent-connection failure mode |
| W-4 | Optional RTC sync via `SetDeviceParam` | Prevents long-term drift from corrupting RTLog timestamps |
| W-5 | Template format validator (length, version byte) before push | Catches v9/v10 mismatch silently dropping enrollments |

---

## 10. Prioritized Action Plan

### Block-merge / pre-launch (must fix)
1. **C-1** Cross-engine PullSDK lock (1 day)
2. **C-2** `_sync_work_running` race (15 min — verify Round 6 fix)
3. **C-3** AGENT watchdog parity (½ day)
4. **C-4** History-upload jitter + max-attempts (2 hours)
5. **C-5** ULTRA device set hot-reload (verify Round 6 fix M-NEW-002)

### Week 1 post-launch
6. **H-1** Atomic multi-step DB workflows
7. **H-2** SDK error code translation table
8. **H-3** Non-blocking event queue producers
9. **H-4** DB connection pool
10. **H-8** Graceful shutdown + atexit
11. **H-10** Update rollback

### Sprint 1
12. M-1 to M-15 (medium severity)
13. **W-1 to W-5** ZKTeco-specific watchdog suite

### Sprint 2 / hygiene
14. L-1 to L-5

---

## 11. What Looks Genuinely Good (keep)

- ✅ Per-instance `_sdk_lock` in `PullSDKDevice` — correct within an engine; the only fix needed is cross-engine.
- ✅ `_dll_cache` with double-checked locking — correct.
- ✅ `INSERT OR IGNORE` with UNIQUE(event_id) for AGENT-mode dedup — fail-closed.
- ✅ Async DB writer thread serializing writes — eliminates "database is locked" under heavy load.
- ✅ WAL journal mode — good baseline, but checkpoint cadence too lazy (H-7).
- ✅ Foreign-key constraints enabled.
- ✅ ULTRA local-state pre-warm — avoids first-scan latency spike.
- ✅ Firmware-profile caching (planned in `fast_patch_pipeline` worktree) — turns 60k SDK calls into ~2.4k.
- ✅ Adaptive RTLog sleep with empty/busy tuning.
- ✅ `set_device_data_batch()` with row-by-row fallback — no silent drops.
- ✅ `_seen` deque with `maxlen=10_000` — bounded memory.
- ✅ Single-instance lock — fragile (M-12) but functional for the common case.
- ✅ Round-6 fixes for AGENT fail-closed, ULTRA history source, TOTP rescue routing — all confirmed intact.

---

## 12. Confidence Notes

| Area | Confidence | Why |
|---|---|---|
| Code-level findings (race, lock, queue) | High | Direct file:line traces |
| ZKTeco firmware behavior | Medium | Public docs are thin; relies on field reports |
| Backend resilience claims | High | Retry intervals are hardcoded constants |
| ULTRA engine deadlock potential | Medium | Theoretically possible from lock graph; not observed yet |
| Self-update rollback | Low | Did not trace the installer end-to-end this round |
| `tv_local_cache.py` | Low | Out of scope this pass — flag for next audit |
| Cross-process plcommpro safety | Medium | DLL uses internal mutex but cross-process and cross-engine semantics not publicly documented |

---

**End of audit.**
Owner: this file lives under `docs/audit/` per project convention. Round 7. Compare against `ACCESS_AUDIT_EXECUTIVE_SUMMARY.md` for delta from Round 6.
