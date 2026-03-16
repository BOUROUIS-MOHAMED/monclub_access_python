# MonClub Access — Full Technical Audit Report

**Date:** 2026-03-15
**Scope:** Entire codebase (`monclub_access_python/`)
**Auditor:** Claude (automated deep-code audit)
**Verdict:** NOT PRODUCTION-READY — 7 critical, 15 high, 18 medium-severity issues

---

## 1. Executive Summary

MonClub Access is a Windows desktop application that manages physical access control for gym/club facilities using ZKTeco controllers (PullSDK) and ZKFinger fingerprint readers. It operates in two per-device modes: **DEVICE** (push users/fingerprints/access rules to controllers) and **AGENT** (poll RTLog events, authorize locally via TOTP/RFID, command door open). The system includes a Python backend with a localhost HTTP API, a Tauri 2.x + React 19 frontend, SQLite local cache with DPAPI-encrypted tokens, and a .NET updater.

**The codebase has strong architectural bones.** The per-device mode design, adaptive sleep, delta sync with SHA1 hashes, and the realtime agent's event pipeline (DeviceWorker → Queue → DecisionService → CommandBus) are well-engineered. However, there are **7 critical and 15 high-severity findings** that make this system unsafe for production deployment controlling physical security doors.

**Top 3 production blockers:**
1. Plaintext TOTP secrets committed to source control (`gym_access_secrets_cache.json`)
2. PullSDK ignores the `password` parameter — every controller connects with empty password (line 100)
3. ZKFinger `db_match()` returns score=1 (MATCH) on OSError — a DLL crash grants fingerprint access

---

## 2. System Understanding (Verified Architecture)

### Components confirmed via code reading:

| Component | File(s) | Role |
|-----------|---------|------|
| PullSDK wrapper | `app/sdk/pullsdk.py` (794 lines) | ctypes bridge to plcommpro.dll for ZKTeco controllers |
| ZKFinger wrapper | `app/sdk/zkfinger.py` (909 lines) | ctypes bridge to libzkfp.dll for fingerprint enrollment |
| Config | `app/core/config.py` (517 lines) | AppConfig dataclass, local JSON persistence |
| SQLite DB | `app/core/db.py` (1000+ lines) | Local cache, auth state, sync data, offline queue |
| DEVICE sync | `app/core/device_sync.py` (775 lines) | Push users/fingerprints/access rules to controllers |
| AGENT engine | `app/core/realtime_agent.py` (1300+ lines) | Poll RTLog, authorize TOTP/RFID, open doors |
| Settings reader | `app/core/settings_reader.py` (393 lines) | Normalize backend settings from SQLite cache |
| Secure store | `app/core/secure_store.py` (96 lines) | DPAPI encrypt/decrypt for auth tokens |
| V1 API (legacy) | `app/api/local_access_api.py` (152 lines) | 2 endpoints, wildcard CORS |
| V2 API (current) | `app/api/local_access_api_v2.py` (500+ lines) | Full router, improved CORS, SSE |
| Backend client | `app/api/monclub_api.py` (200+ lines) | HTTP client to MonClub backend |
| Utilities | `app/core/utils.py` (365 lines) | Path helpers, ANSI encoding, device text parsing |
| Tauri UI | `tauri-ui/` | React 19 + TypeScript + Vite + Tailwind |

### Mode dispatch (verified):

- `device_sync.py` line 763: `if str(d.get("accessDataMode", "DEVICE")).strip().upper() != "DEVICE": continue`
- `realtime_agent.py`: filters for `accessDataMode == "AGENT"` devices
- Config still has global `data_mode` field (line 119) marked deprecated but functional

---

## 3. Findings by Severity

### CRITICAL (6 findings)

---

#### C-01: Plaintext TOTP Secrets in Source Control

- **File:** `gym_access_secrets_cache.json` (root directory)
- **Evidence:** File contains 50+ entries with `"secretHex": "0305dd6b17c8be4f4df4952a7b1ae3e4b9522373"` etc., along with `gymId`, `accountId`, and `grantedActiveMembershipIds`
- **Category:** Security Issue
- **Impact:** Any person with repo access can generate valid TOTP codes for any member. Full access bypass. If this repo is ever leaked or shared, all member access tokens are compromised.
- **Failure Scenario:** Attacker clones repo → reads secretHex values → generates valid TOTP codes → enters gym as any member
- **Fix:** (1) Add `gym_access_secrets_cache.json` to `.gitignore` immediately. (2) Rotate all TOTP secrets via backend. (3) Run `git filter-branch` or `BFG Repo-Cleaner` to purge from history. (4) Ensure TOTP secrets are only stored in DPAPI-protected SQLite, never as plaintext JSON files.

---

#### C-02: PullSDK connect() Ignores Password Parameter

- **File:** `app/sdk/pullsdk.py`, line 100
- **Function:** `PullSDK.connect()`
- **Evidence:** `f"passwd={''}"` — the f-string hardcodes an empty string literal. The `password` parameter passed to the function is never used in the connection string.
- **Category:** Bug (security-critical)
- **Impact:** Every ZKTeco controller is accessed with no password regardless of what password is configured. If controllers have passwords set, connections will either fail silently or succeed without authentication.
- **Failure Scenario:** Admin sets controller password for security → PullSDK connects with empty password → connection fails → sync/agent stops working with no clear error message about password mismatch.
- **Fix:** Change line 100 to `f"passwd={password}"`. Verify the password parameter flows correctly from device settings through `PullSDKDevice`.

---

#### C-03: ZKFinger db_match() Returns MATCH on DLL Error

- **File:** `app/sdk/zkfinger.py`, line 747-749
- **Function:** `ZKFinger.db_match()`
- **Evidence:**
  ```python
  except OSError as e:
      self._log.warning("ZKFPM_DBMatch raised OSError (skipping match check): %s", e)
      return 1  # score=1 means MATCH
  ```
- **Category:** Bug (security-critical)
- **Impact:** If the ZKFinger DLL crashes, throws an access violation, or encounters any OS-level error during fingerprint comparison, the function returns score=1 (positive match). This means a DLL malfunction grants fingerprint access to anyone.
- **Failure Scenario:** DLL becomes corrupted → every fingerprint scan returns OSError → every scan returns score=1 → unauthorized physical access.
- **Fix:** Return `0` (no match) or `-1` (error) on OSError. Never fail-open on a security check.

---

#### C-04: V1 API Wildcard CORS — Any Website Can Call the API

- **File:** `app/api/local_access_api.py`, line 17
- **Function:** `_cors_headers()`
- **Evidence:** `handler.send_header("Access-Control-Allow-Origin", "*")`
- **Category:** Security Issue
- **Impact:** Any website visited in the user's browser can make cross-origin requests to `http://127.0.0.1:8788` and interact with the access control system. The V1 API exposes `/api/v1/access/enroll` (fingerprint enrollment) with no authentication.
- **Failure Scenario:** User visits malicious website → JavaScript calls `http://127.0.0.1:8788/api/v1/access/enroll` → attacker enrolls fingerprints remotely.
- **Fix:** Either (1) remove V1 API entirely (V2 exists), or (2) apply the same origin-check logic from V2 (`_ALLOWED_ORIGIN` + prefix checks).

---

#### C-05: DPAPI Fallback Returns Raw Bytes (Encryption Silently Disabled)

- **File:** `app/core/secure_store.py`, lines 49-51 and 93-95
- **Functions:** `protect_bytes()`, `unprotect_bytes()`
- **Evidence:**
  ```python
  except Exception:
      # fallback (not ideal, but avoids crashing)
      return data   # returns UNENCRYPTED data
  ```
- **Category:** Security Issue / Design Flaw
- **Impact:** If DPAPI fails for any reason (running as a service account, Windows API unavailable, etc.), auth tokens are stored and read as plaintext with no indication to the operator. The same pattern appears in `db.py` lines 85-86 (`return "raw:" + plain`).
- **Failure Scenario:** App runs in a context where DPAPI is unavailable → all tokens stored in plaintext in SQLite → any local user can read auth tokens.
- **Fix:** Log a CRITICAL warning when DPAPI fails. Consider refusing to store tokens without encryption and requiring the user to re-authenticate.

---

#### C-06: HTTP (not HTTPS) for All Backend Communication

- **File:** `app/core/config.py`, line 134
- **Evidence:** `api_latest_release_url: str = "http://monclubwigo.tn/api/v1/..."`
- **Also:** `app/api/monclub_api.py` uses `requests.get(url)` / `requests.post(url)` with these HTTP URLs
- **Category:** Security Issue
- **Impact:** Auth tokens, TOTP secrets, user data, and fingerprint templates are transmitted over unencrypted HTTP. Any network observer (Wi-Fi, ISP, proxy) can intercept credentials and member data.
- **Failure Scenario:** Gym uses public WiFi → attacker performs MITM → captures auth token → impersonates the gym's access system.
- **Fix:** Change all API URLs to `https://`. Verify the backend supports TLS. Add certificate verification to the `requests` calls.

---

#### C-07: TOTP Replay State Also Committed to Source Control

- **File:** `totp_replay_state.json` (root directory)
- **Evidence:** Contains replay prevention state mapping credential IDs to counter values. Not in `.gitignore`. Leaks which credentials are actively being used and their replay counters.
- **Category:** Security Issue
- **Impact:** Combined with C-01, an attacker can see which TOTP secrets are active and their current counter state, making targeted replay attacks trivial.
- **Fix:** Add `totp_replay_state.json` to `.gitignore` and purge from git history.

---

### HIGH (15 findings)

---

#### H-01: No Thread Safety on PullSDK Singleton

- **File:** `app/sdk/pullsdk.py`
- **Class:** `PullSDK`
- **Evidence:** No threading.Lock on `_h` (connection handle), `_dll`, or any method. `PullSDKDevice` creates per-device wrappers but the underlying DLL is shared.
- **Category:** Race Condition
- **Impact:** If multiple threads call `connect()`/`disconnect()`/`GetDeviceData()` concurrently on different devices sharing the same DLL instance, ctypes calls can corrupt the DLL's internal state.
- **Fix:** Add a `threading.Lock()` to `PullSDK` and acquire it around every DLL call. Alternatively, use separate `PullSDK` instances per thread.

---

#### H-02: SQLite check_same_thread=False Without Mutex

- **File:** `app/core/db.py`, line 23
- **Function:** `get_conn()`
- **Evidence:** `conn = sqlite3.connect(DB_PATH, check_same_thread=False)` — creates a new connection per call, but no module-level lock protects concurrent writes.
- **Category:** Race Condition
- **Impact:** Multiple threads writing simultaneously can cause `database is locked` errors or corrupt WAL state. The DeviceWorker threads, DecisionService, sync engine, and API handlers all use this.
- **Fix:** Either (1) use a module-level `threading.Lock()` for write operations, or (2) switch to WAL mode with `PRAGMA journal_mode=WAL` and handle busy timeouts.

---

#### H-03: `requests` Library Missing from requirements.txt

- **File:** `requirements.txt` (line 1-10), `app/api/monclub_api.py` (line 9: `import requests`)
- **Category:** Missing Implementation
- **Impact:** `pip install -r requirements.txt` does not install `requests`. Fresh deployments will crash on first backend API call with `ModuleNotFoundError: No module named 'requests'`.
- **Fix:** Add `requests>=2.28.0` to `requirements.txt`.

---

#### H-04: Tkinter Remnants in V2 API (Production Crash Risk)

- **File:** `app/api/local_access_api_v2.py`, line 489
- **Function:** `_handle_auth_logout()`
- **Evidence:** `ctx.app.after(0, ctx.app._on_click_logout.__wrapped__ ...)` — calls `after()` which is a Tkinter method. Also references `__wrapped__` (Tkinter decorator pattern).
- **Category:** Broken Assumption / Dead Code
- **Impact:** If Tkinter is no longer the UI framework (migrated to Tauri), calling `ctx.app.after()` will raise `AttributeError` at runtime when a user tries to logout. The `try/except` silences it, but the logout flow may be incomplete.
- **Fix:** Remove all Tkinter-specific method calls. Replace `ctx.app.after()` with direct function calls or `threading.Thread(target=...).start()`.

---

#### H-05: Global `data_mode` Still Active in Config

- **File:** `app/core/config.py`, line 119
- **Evidence:** `data_mode: str = "DEVICE"` — still present and defaults to "DEVICE". The `is_device_mode` property (line 246-252) still reads it. `set_agent_device_override()` is a no-op (line 330-337).
- **Category:** Architecture Drift
- **Impact:** If any code path still reads `config.data_mode` or `config.is_device_mode` instead of per-device `accessDataMode`, it will apply a global mode override, contradicting the per-device architecture. A single global flip could disable AGENT mode on all devices.
- **Fix:** (1) Grep all callers of `is_device_mode` and `data_mode`. (2) Replace with per-device checks. (3) Remove the deprecated fields.

---

#### H-06: TOTP Disabled Means ALLOW ALL (Bypass)

- **File:** `app/core/realtime_agent.py`, lines 1089-1096
- **Function:** `DecisionService._verify_totp()`
- **Evidence:**
  ```python
  if not totp_enabled:
      return {
          "allowed": True,
          "reason": "ALLOW_BYPASS_TOTP_DISABLED",
          ...
      }
  ```
- **Category:** Design Flaw
- **Impact:** When `totp_enabled=False` in device settings, every scanned code is accepted regardless of what was scanned. This is documented as intentional but is dangerous: a misconfiguration or backend bug setting `totp_enabled=False` opens all doors.
- **Fix:** When TOTP is disabled, the system should still require RFID card match. At minimum, log a WARNING every time ALLOW_BYPASS fires, and add a backend-side safety check.

---

#### H-07: Event Queue Silently Drops Events

- **File:** `app/core/realtime_agent.py`, line 803-805
- **Function:** `DeviceWorker.run()` (inner loop)
- **Evidence:**
  ```python
  try:
      self.event_queue.put(ev, timeout=0.05)
  except Exception:
      pass  # silently dropped
  ```
- **Category:** Bad Logic
- **Impact:** If the event queue is full (queue.Full) or any other exception occurs, access events are silently dropped. There is no retry, no counter, no log. Events that should trigger door-open decisions are lost.
- **Fix:** Log dropped events with a counter. Consider using an unbounded queue (with a sanity cap) or a backpressure mechanism.

---

#### H-08: Synthetic eventId Has Collision Risk

- **File:** `app/sdk/pullsdk.py` (in `poll_rtlog_once()`)
- **Evidence:** Event IDs are constructed by concatenating field values from RTLog rows. Multiple events from the same card at the same second on the same door produce identical eventIds.
- **Category:** Design Flaw
- **Impact:** Replay protection uses eventId for deduplication. Colliding IDs mean legitimate duplicate-second events are silently dropped, OR replay attacks succeed if the collision evicts the real event from the LRU.
- **Fix:** Include a monotonic counter or UUID in the synthetic eventId to guarantee uniqueness.

---

#### H-09: Duplicate DPAPI Implementation

- **File:** `app/core/db.py` (lines 37-141) and `app/core/secure_store.py` (lines 10-95)
- **Category:** Code Duplication / Maintainability
- **Impact:** Two independent implementations of DPAPI encryption with different error handling. `db.py` returns `"raw:" + plain` on failure (data preserved but unencrypted). `secure_store.py` returns raw bytes on failure. Bugs fixed in one copy won't be fixed in the other.
- **Fix:** Delete the DPAPI code from `db.py`. Have `db.py` import from `secure_store.py`.

---

#### H-10: PullSDK.connect() Overwrites Active Handle Without Disconnecting

- **File:** `app/sdk/pullsdk.py`, lines 90-119
- **Function:** `PullSDK.connect()`
- **Evidence:** If `connect()` is called while `_h` is already set (already connected), the old handle is silently overwritten without calling `Disconnect` first. `PullSDKDevice.connect()` does call `disconnect()` first (line 566), but the low-level `PullSDK.connect()` does not.
- **Category:** Bug / Resource Leak
- **Impact:** The old DLL-level connection leaks. ZKTeco devices support only 1-4 concurrent connections — leaked handles consume connection slots, eventually blocking all new connections until device reboot.
- **Fix:** Call `self.disconnect()` at the start of `PullSDK.connect()`, or raise if already connected.

---

#### H-11: Sensitive Card/PIN Data Logged at INFO Level

- **File:** `app/sdk/pullsdk.py`, lines 390 and 407
- **Functions:** `set_device_data()`, `delete_device_data()`
- **Evidence:** The entire `data` payload (which may include card numbers, PINs, access credentials) is logged at INFO level.
- **Category:** Security Issue
- **Impact:** Log files contain plaintext access credentials. Anyone with access to logs can extract card numbers and PINs.
- **Fix:** Log only table name and row count at INFO level. Move full payload to DEBUG level.

---

#### H-12: CSP Disabled in Tauri Config (XSS Risk)

- **File:** `tauri-ui/src-tauri/tauri.conf.json`, line 23
- **Evidence:** `"csp": null` — Content Security Policy is entirely disabled.
- **Category:** Security Issue
- **Impact:** The Tauri UI renders content from the localhost API and potentially from backend-sourced data. Without CSP, any XSS vulnerability in rendered content can execute arbitrary JavaScript with full access to the Tauri API bridge, potentially controlling door hardware.
- **Fix:** Set a restrictive CSP: `"csp": "default-src 'self'; connect-src 'self' http://127.0.0.1:8788; script-src 'self'"`.

---

#### H-13: Installer Wipes All User Data on Every Install/Update

- **File:** `installer/MonClubAccess.iss`, lines 317-333
- **Function:** `PrepareToInstall()`
- **Evidence:** Unconditionally deletes all user data directories (LocalAppData, CommonAppData, RoamingAppData). Combined with `UsePreviousAppDir=no` (line 41), every install/update is destructive — the SQLite database, logs, auth tokens, and cached credentials are destroyed.
- **Category:** Design Flaw
- **Impact:** Users lose all local data on every update. Must re-login, re-sync devices, re-enroll fingerprints after each update. In production, this means doors stop working after every software update until manual reconfiguration.
- **Fix:** Only perform destructive cleanup on explicit user request or first install. Add a conditional check for existing installations.

---

#### H-14: No Code Signing in Build or Release Pipeline

- **Files:** `build_release.ps1`, `publish_github_release.ps1`
- **Category:** Security Issue / Deployment Blocker
- **Evidence:** Neither the PyInstaller EXE, the Inno Setup installer, nor the Tauri binary are code-signed. The release process uploads unsigned binaries to GitHub.
- **Impact:** Windows SmartScreen blocks unsigned executables. Users cannot verify binary authenticity. Enterprise environments may outright reject unsigned software.
- **Fix:** Integrate `signtool.exe` with a code signing certificate after PyInstaller build and Inno Setup compilation.

---

#### H-15: `winotify` Not Bundled in PyInstaller Spec

- **File:** `MonClubAccess.spec`, lines 53-67 (hiddenimports section)
- **Evidence:** `winotify` is in `requirements.txt` but NOT in `hiddenimports`. PyInstaller may fail to detect and bundle it.
- **Category:** Missing Implementation
- **Impact:** Windows toast notifications crash at runtime with `ModuleNotFoundError` in the frozen executable. Notifications are used for access events — operators lose visibility into door access in real-time.
- **Fix:** Add `hiddenimports += safe_collect_submodules("winotify")` to the spec file.

---

### MEDIUM (18 findings)

**Note:** M-01 through M-12 documented above, plus the following additional findings:

---

#### M-13: `platform` Parameter Never Appended to Connection String

- **File:** `app/sdk/pullsdk.py`, lines 95-103
- **Function:** `PullSDK.connect()`
- **Evidence:** The `platform` parameter is accepted and logged (line 111) but never appended to the `parts` list. The connection string never includes `platform=...`.
- **Category:** Bug
- **Impact:** Devices requiring a specific platform string (e.g., `platform=ZEM` for certain ZKTeco models) will fail to communicate correctly.
- **Fix:** Add `if platform: parts.append(f"platform={platform}")` before `conn_str = ",".join(parts)`.

---

#### M-14: `GetDeviceDataCount` Returns Negative Error Codes as Valid Counts

- **File:** `app/sdk/pullsdk.py`, lines 374-383
- **Function:** `get_device_data_count()`
- **Evidence:** Unlike all other methods, this returns `rc` directly without checking `rc < 0`. Also returns `-1` if the function is not available.
- **Category:** Bad Logic
- **Impact:** Caller interprets negative error code as a count (e.g., `range(-3)` or reporting "minus 3 records").
- **Fix:** Raise `PullSDKError` on `rc < 0` consistent with other methods, or return 0 on error.

---

#### M-15: SetDeviceData Partial Failure Not Detected

- **File:** `app/sdk/pullsdk.py`, lines 385-395
- **Function:** `set_device_data()`
- **Evidence:** PullSDK `SetDeviceData` can return a positive number (rows written) less than the total submitted when partial failure occurs. The code only checks `rc < 0`, so partial success (e.g., 5 of 10 rows) is treated as full success.
- **Category:** Bad Logic
- **Impact:** Data partially pushed to controller with no indication of which rows failed. Controller ends up in inconsistent state.
- **Fix:** Compare `rc` against expected row count. Log or raise if `rc < expected`.

---

#### M-16: CSV Parser Cannot Handle Commas in Field Values

- **File:** `app/core/utils.py`, `parse_device_text()` function
- **Evidence:** Parser splits on commas without handling quoting. A field value containing a comma (e.g., user name "Smith, John") produces misaligned columns.
- **Category:** Bad Logic
- **Impact:** User records with commas in names silently produce wrong data in all subsequent columns of that row.
- **Fix:** Use proper delimiter handling or document that comma-containing values are not supported.

---

#### M-01: No Schema Migration Versioning

- **File:** `app/core/db.py`, function `_ensure_column()`
- **Evidence:** Migrations are ad-hoc `ALTER TABLE ADD COLUMN` calls with no version tracking. The `_ensure_column()` function silently catches all exceptions (line 161: `except Exception: pass`).
- **Impact:** No way to know what schema version a user's database is at. Failed migrations are silently ignored. Rolling back is impossible.
- **Fix:** Add a `schema_version` table. Run migrations in order with version checks.

---

#### M-02: sync_users Table Has No PRIMARY KEY

- **File:** `app/core/db.py` (CREATE TABLE for sync_users)
- **Impact:** Without a PK, duplicate rows can accumulate. SQLite cannot optimize lookups. UPSERT operations become unreliable.
- **Fix:** Add `PRIMARY KEY` on the user's unique identifier (likely `id` from backend).

---

#### M-03: V2 API CORS Allows All localhost Origins

- **File:** `app/api/local_access_api_v2.py`, lines 180-184
- **Evidence:** `origin.startswith("http://localhost")` or `origin.startswith("http://127.0.0.1")` — any port on localhost is allowed.
- **Impact:** Any local web application or malicious localhost service can interact with the access control API.
- **Fix:** Restrict to specific ports (e.g., only `http://localhost:1420` for Vite dev server).

---

#### M-04: No Token Refresh Mechanism

- **File:** `app/api/monclub_api.py`
- **Evidence:** `login()` returns a raw token string. No refresh token, no expiry check, no automatic re-authentication.
- **Impact:** When the token expires, the system silently fails to sync until the user manually re-logs in.

---

#### M-05: SSE Token in Query Parameter

- **File:** `tauri-ui/src/api/client.ts`
- **Evidence:** `EventSource` uses token in query parameter (SSE doesn't support custom headers natively).
- **Impact:** Token appears in server access logs, browser history, and proxy logs.

---

#### M-06: Frontend Uses Browser fetch() Not Tauri HTTP Plugin

- **File:** `tauri-ui/src/api/client.ts`
- **Evidence:** Uses `window.fetch()` with `http://127.0.0.1:8788`. Does not use `@tauri-apps/plugin-http`.
- **Impact:** Subject to browser CORS restrictions. Tauri's HTTP plugin would bypass CORS entirely for local API calls.

---

#### M-07: Image Download Without TLS Verification

- **File:** `app/core/realtime_agent.py`, lines 247-281
- **Class:** `ImageCache._download()`
- **Evidence:** Uses `urllib.request.urlopen(req, timeout=self.timeout_sec)` — no SSL context, no certificate verification.
- **Impact:** Notification images could be intercepted or replaced via MITM.

---

#### M-08: Config Loaded from Local File, Not Backend Sync

- **File:** `app/core/config.py`
- **Evidence:** `AppConfig` is loaded/saved from `config.json` on local disk. Settings like API URLs, timeouts, and modes are user-editable locally.
- **Impact:** Contradicts the stated architecture where config comes from backend sync. A user modifying `config.json` can override backend-intended behavior.

---

#### M-09: ZKFinger open() Leaks Device Handle if DBInit Fails

- **File:** `app/sdk/zkfinger.py`, lines 656-665
- **Function:** `ZKFinger.open()`
- **Evidence:** Line 656 opens the device and stores the handle. Line 663 initializes the DB. If `DBInit` returns NULL (line 665), `ZKFingerError` is raised but `device_handle` is already set and never closed.
- **Category:** Resource Leak
- **Impact:** Device handle leaked → next `open()` call fails because the device is still locked by the process.
- **Fix:** Wrap post-`OpenDevice` code in try/except that calls `ZKFPM_CloseDevice` and resets `device_handle` on any failure.

---

#### M-10: No Fingerprint Quality Validation During Enrollment

- **File:** `app/sdk/zkfinger.py`, lines 866-878
- **Function:** `enroll_3_samples()`
- **Evidence:** Acceptance criteria for captured templates are only `rc == 0` and `got_len > 0`. No quality score check. The ZKFinger SDK provides quality scoring but this wrapper does not use it.
- **Category:** Missing Implementation
- **Impact:** Low-quality templates (partial prints, smudged) are accepted and merged, producing poor registration templates that fail to match later.
- **Fix:** Query template quality score and reject samples below a configurable threshold.

---

#### M-11: No Duplicate Fingerprint Detection During Enrollment

- **File:** `app/sdk/zkfinger.py`, lines 813-891
- **Function:** `enroll_3_samples()`
- **Evidence:** `db_identify()` exists (line 777) but is never called during enrollment. No check for whether the fingerprint already exists.
- **Category:** Missing Implementation
- **Impact:** Same finger can be enrolled multiple times under different IDs. Identification returns arbitrary match among duplicates.
- **Fix:** Call `db_identify()` with the first captured template before proceeding. Abort or warn if a match is found.

---

#### M-12: ZKFinger Has No Context Manager — Resource Leak on Exception

- **File:** `app/sdk/zkfinger.py`, entire class
- **Class:** `ZKFinger`
- **Evidence:** No `__enter__`/`__exit__` implementation. If an unhandled exception prevents `close()`/`terminate()` from running, device handle, DB handle, and DLL references are leaked. The SDK may keep the device locked until process exit.
- **Category:** Design Flaw
- **Impact:** Exception during enrollment leaves device handle open → subsequent attempts to open device fail.
- **Fix:** Implement context manager protocol (`__enter__`/`__exit__`) that calls `close()` then `terminate()`.

#### M-17: Deprecated `block_cipher` in PyInstaller Spec

- **File:** `MonClubAccess.spec`, lines 6, 80, 84
- **Evidence:** `block_cipher = None` and `cipher=block_cipher` are deprecated in PyInstaller 5.x and removed in 6+. The build script installs latest PyInstaller (`--upgrade pyinstaller`).
- **Category:** Broken Assumption
- **Impact:** Build may fail or produce warnings with newer PyInstaller versions.
- **Fix:** Remove `block_cipher` variable and all `cipher=` parameters.

---

#### M-18: UI Assets Not Bundled in PyInstaller Spec

- **File:** `MonClubAccess.spec`, lines 42-47
- **Evidence:** `datas` list only collects `certifi` data files. Tray icons and runtime assets from `app/ui/assets/` are not included.
- **Category:** Missing Implementation
- **Impact:** System tray icon and any runtime image assets are missing from the frozen executable.
- **Fix:** Add `datas.append(('app/ui/assets', 'app/ui/assets'))` to the spec file.

---

### LOW (7 findings)

---

#### L-01: `_safe_int()` and `_safe_str()` Duplicated Across 5+ Modules

Multiple modules define their own `_safe_int()`, `_safe_str()`, `_safe_float()`, `_boolish()` helpers.

#### L-02: Broad `except Exception: pass` Patterns

Over 40 instances of bare `except Exception: pass` across the codebase. This masks real errors.

#### L-03: PullSDK Growing Buffer Allocates Up to 8MB Per Call

`GetDeviceData` retries with 1MB → 2MB → 4MB → 8MB buffers. For frequent polling, this creates GC pressure.

#### L-04: `_rebuild_sync_users_without_legacy_fingerprint()` Migration Has No Guard Against Re-Runs

If the table rebuild fails halfway, subsequent runs may fail or lose data.

#### L-05: Hardcoded `User-Agent: MonClubAccess/1.0`

Minor information disclosure. Not a real security issue but reveals application identity.

#### L-06: No Real Test Framework or CI/CD Pipeline

`_test_integration.py` uses `assert` statements (optimized away with `-O`), uses `_` prefix (skipped by test runners). `totp_file_test.py` is a CLI tool, not a test. No pytest/unittest, no GitHub Actions, no CI.

#### L-07: Build Manifest Leaks Build Machine Paths

`build_release.ps1` includes absolute local paths (`python.executable`, `outputs.distDir`) in the published manifest JSON.

---

## 4. Findings by Subsystem

### 4.1 PullSDK (`app/sdk/pullsdk.py`)

| ID | Severity | Finding |
|----|----------|---------|
| C-02 | CRITICAL | `connect()` hardcodes empty password (line 100) |
| H-01 | HIGH | No thread locking on DLL calls |
| H-08 | HIGH | Synthetic eventId collision risk |
| H-10 | HIGH | `connect()` overwrites active handle without disconnecting |
| H-11 | HIGH | Sensitive card/PIN data logged at INFO level |
| M-13 | MEDIUM | `platform` parameter never sent to DLL |
| M-14 | MEDIUM | `GetDeviceDataCount` returns negative errors as counts |
| M-15 | MEDIUM | `SetDeviceData` partial failure not detected |
| M-16 | MEDIUM | CSV parser cannot handle commas in values |
| L-03 | LOW | Growing buffer up to 8MB |

### 4.2 ZKFinger (`app/sdk/zkfinger.py`)

| ID | Severity | Finding |
|----|----------|---------|
| C-03 | CRITICAL | `db_match()` returns MATCH on OSError (line 749) |
| M-09 | MEDIUM | `open()` leaks device handle if DBInit fails |
| M-10 | MEDIUM | No fingerprint quality validation during enrollment |
| M-11 | MEDIUM | No duplicate fingerprint detection during enrollment |
| M-12 | MEDIUM | No context manager — resource leak on exception |

### 4.3 Device Communication & Sync (`app/core/device_sync.py`)

| ID | Severity | Finding |
|----|----------|---------|
| — | — | Multiple fallback patterns for `userauthorize` table (3 field name variants) — robust but hard to debug |
| — | — | Creates new PullSDK connection per device per sync run (no pooling) — acceptable for periodic sync |

### 4.4 Realtime Agent (`app/core/realtime_agent.py`)

| ID | Severity | Finding |
|----|----------|---------|
| H-06 | HIGH | TOTP disabled = allow all |
| H-07 | HIGH | Silent event drop on full queue |
| M-07 | MEDIUM | Image download without TLS verification |

### 4.5 Local API / Tauri Integration

| ID | Severity | Finding |
|----|----------|---------|
| C-04 | CRITICAL | V1 API wildcard CORS |
| H-04 | HIGH | Tkinter remnants crash logout |
| M-03 | MEDIUM | V2 API allows all localhost origins |
| M-06 | MEDIUM | Frontend uses browser fetch, not Tauri HTTP plugin |

### 4.6 Security Store & Database

| ID | Severity | Finding |
|----|----------|---------|
| C-05 | CRITICAL | DPAPI fallback returns raw bytes |
| H-02 | HIGH | SQLite no mutex with check_same_thread=False |
| H-09 | HIGH | Duplicate DPAPI implementation |
| M-01 | MEDIUM | No schema migration versioning |
| M-02 | MEDIUM | sync_users no PRIMARY KEY |

### 4.7 Backend Communication

| ID | Severity | Finding |
|----|----------|---------|
| C-06 | CRITICAL | HTTP not HTTPS for all backend calls |
| H-03 | HIGH | `requests` missing from requirements.txt |
| M-04 | MEDIUM | No token refresh mechanism |

### 4.8 Source Control

| ID | Severity | Finding |
|----|----------|---------|
| C-01 | CRITICAL | Plaintext TOTP secrets committed |
| C-07 | CRITICAL | TOTP replay state committed |

### 4.9 Build, Installer & Deployment

| ID | Severity | Finding |
|----|----------|---------|
| H-12 | HIGH | CSP disabled in Tauri config |
| H-13 | HIGH | Installer wipes all user data on every install/update |
| H-14 | HIGH | No code signing in build pipeline |
| H-15 | HIGH | `winotify` not bundled in PyInstaller spec |
| M-17 | MEDIUM | Deprecated `block_cipher` in PyInstaller spec |
| M-18 | MEDIUM | UI assets not bundled in PyInstaller |
| L-06 | LOW | No test framework or CI/CD pipeline |
| L-07 | LOW | Build manifest leaks local paths |

---

## 5. Architecture Drift Analysis

| Stated Architecture | Actual Code | Drift Level |
|---------------------|-------------|-------------|
| Per-device accessDataMode | `config.py` line 119 still has global `data_mode = "DEVICE"` with working `is_device_mode` property. `device_sync.py` and `realtime_agent.py` correctly filter by per-device mode. | **PARTIAL** — new code is correct, old global field persists |
| Config from backend sync | `config.py` loads from `config.json` file. Only agent/device settings use `settings_reader.py` (backend cache). API URLs, timeouts, ports are local-only. | **SIGNIFICANT** — hybrid config, not fully backend-driven |
| Tkinter removed | `local_access_api_v2.py` line 489 calls `ctx.app.after()` (Tkinter method). References `__wrapped__` (Tkinter decorator). | **INCOMPLETE** — migration artifacts remain |
| DEVICE mode = push to controller | Confirmed in `device_sync.py`. Correct implementation. | **ALIGNED** |
| AGENT mode = poll + local auth + door control | Confirmed in `realtime_agent.py`. Well-implemented pipeline. | **ALIGNED** |

---

## 6. Missing Implementations

| What's Missing | Where Expected | Impact |
|----------------|---------------|--------|
| Token refresh/re-auth | `monclub_api.py` | System goes offline silently when token expires |
| Connection pooling for PullSDK | `device_sync.py` creates new connection per device per sync | Performance overhead on every sync cycle |
| Fingerprint match threshold | `zkfinger.py` `db_match()` returns raw score, no threshold check visible | Caller must handle threshold — unclear if they do |
| V2 API authentication | `local_access_api_v2.py` has `X-Local-Token` header check but token validation logic unclear | API may be accessible without valid token |
| `.gitignore` for sensitive files | Root directory | Secrets files committed to repo |
| Health monitoring / watchdog | No process-level health check | If the main process hangs, no automatic recovery |

---

## 7. Bad Logic / Correctness Issues

| Location | Issue | Fix |
|----------|-------|-----|
| `zkfinger.py:749` | `return 1` on OSError in security-critical match function | Return 0 or raise |
| `pullsdk.py:100` | `f"passwd={''}"` ignores password param | Use `f"passwd={password}"` |
| `pullsdk.py:90-119` | `connect()` overwrites active handle without disconnect | Call `disconnect()` first |
| `pullsdk.py:374-383` | `get_device_data_count` returns negative errors as counts | Check `rc < 0` |
| `pullsdk.py:385-395` | `set_device_data` partial failure treated as success | Compare rc vs expected rows |
| `realtime_agent.py:803-805` | `except Exception: pass` drops access events | Log and count drops |
| `realtime_agent.py:1089-1096` | TOTP disabled = allow all entries | At minimum require RFID |
| `secure_store.py:49-51` | DPAPI failure returns unencrypted data silently | Log CRITICAL, refuse to store |
| `db.py:161` | `_ensure_column` catches all exceptions silently | Log migration failures |

---

## 8. Error Handling Audit

**Pattern observed:** The codebase overwhelmingly uses `except Exception: pass` — over 40 instances. This is the single biggest maintainability risk.

**Critical exception swallowing:**

| File | Line(s) | Consequence |
|------|---------|-------------|
| `secure_store.py` | 49-51, 93-95 | Encryption silently disabled |
| `db.py` | 85-86 | Token stored unencrypted |
| `db.py` | 161 | Schema migration silently fails |
| `realtime_agent.py` | 803-805 | Access events silently dropped |
| `realtime_agent.py` | 822 | Event processing errors ignored |
| `pullsdk.py` | 86-88 | DLL load failure properly raised ✓ |
| `local_access_api_v2.py` | 489-491 | Logout partially fails silently |

**Good exception handling:**
- `PullSDK.load()` properly raises `PullSDKError` on DLL load failure
- `DeviceWorker` reconnects with exponential backoff on connection failure
- `DeviceSyncEngine` has `_run_lock` to prevent concurrent sync runs

---

## 9. Security Audit

### Authentication & Authorization

| Check | Status | Notes |
|-------|--------|-------|
| Auth token encrypted at rest | ⚠️ PARTIAL | DPAPI used but falls back to plaintext silently |
| API authentication | ⚠️ WEAK | V1 has none. V2 has X-Local-Token but validation unclear |
| CORS policy | ❌ V1, ⚠️ V2 | V1: wildcard. V2: any localhost origin |
| Backend TLS | ❌ FAIL | All HTTP, no HTTPS |
| TOTP secret storage | ❌ FAIL | Plaintext in repo |
| Controller passwords | ❌ FAIL | Ignored (hardcoded empty) |

### Data Protection

| Check | Status | Notes |
|-------|--------|-------|
| DPAPI for tokens | ⚠️ PARTIAL | Fallback defeats the purpose |
| Secrets in source control | ❌ FAIL | `gym_access_secrets_cache.json` committed |
| SSE token exposure | ⚠️ WARN | Token in query parameter |
| Log data leakage | ❌ FAIL | Card/PIN data logged at INFO level (H-11) |

### Physical Security

| Check | Status | Notes |
|-------|--------|-------|
| Fingerprint match on error | ❌ FAIL | Returns MATCH on DLL crash |
| TOTP bypass | ⚠️ WARN | totp_enabled=false opens all doors |
| Replay protection | ✅ OK | In-memory LRU (2000) + DB cursor |
| Event integrity | ⚠️ WARN | Synthetic eventId collision risk |

---

## 10. Performance & Concurrency Audit

### Thread Model

| Thread/Component | Thread Safety | Notes |
|-----------------|---------------|-------|
| PullSDK DLL calls | ❌ No lock | Multiple DeviceWorkers may share DLL |
| SQLite writes | ❌ No mutex | check_same_thread=False without coordination |
| DeviceWorker (per device) | ✅ OK | Each has own PullSDKDevice instance |
| DecisionService | ✅ OK | Single consumer thread with cache lock |
| NotificationGate | ✅ OK | Has internal threading.Lock |
| DeviceSyncEngine | ✅ OK | Has _run_lock for mutual exclusion |

### Memory & Performance

| Component | Concern | Severity |
|-----------|---------|----------|
| PullSDK buffer | Grows to 8MB per GetDeviceData call | LOW |
| ImageCache | 5MB max, 1000 files, with LRU pruning | OK |
| Replay LRU deque | maxlen=2000 — adequate for normal use | OK |
| User cache TTL | 2-second TTL in DecisionService — very aggressive | OK for access control |
| Notification _recent dict | Can grow to 5000 before pruning | OK |

---

## 11. Improvements Plan (Prioritized)

### Phase 1 — Emergency (Before Any Deployment)

1. **Remove `gym_access_secrets_cache.json` and `totp_replay_state.json` from repo** — add to `.gitignore`, purge from git history
2. **Fix `pullsdk.py:100`** — use the actual password parameter
3. **Fix `zkfinger.py:749`** — return 0 on OSError, not 1
4. **Fix V1 API CORS** — remove wildcard or remove V1 entirely
5. **Switch all backend URLs to HTTPS**
6. **Add `requests` to requirements.txt**
7. **Fix installer** — stop wiping user data on every update

### Phase 2 — High Priority (Before Beta)

8. **Add threading.Lock to PullSDK** DLL calls
9. **Add WAL mode + busy timeout** to SQLite, or add a write mutex
10. **Remove Tkinter remnants** from V2 API
11. **Delete duplicate DPAPI code** from db.py, import from secure_store.py
12. **Make DPAPI failure loud** — log CRITICAL, don't silently fall back
13. **Remove global `data_mode`** from AppConfig (or make it truly dead)
14. **Fix PullSDK.connect()** to call disconnect() before overwriting handle
15. **Stop logging sensitive card/PIN data** at INFO level
16. **Enable CSP in Tauri config** — restrict to self + localhost API
17. **Add `winotify` to PyInstaller hiddenimports**
18. **Implement code signing** for EXE and installer
19. **Fix `platform` parameter** — actually append it to connection string

### Phase 3 — Medium Priority (Before GA)

20. **Add schema migration versioning** (version table + ordered migrations)
21. **Add PRIMARY KEY to sync_users** table
22. **Restrict V2 CORS** to specific ports
23. **Add token refresh** mechanism to monclub_api.py
24. **Fix `GetDeviceDataCount`** to raise on negative rc
25. **Fix `SetDeviceData`** partial failure detection
26. **Use Tauri HTTP plugin** instead of browser fetch
27. **Add dropped-event counter** with logging
28. **Add ZKFinger context manager** for resource cleanup
29. **Add fingerprint quality validation** during enrollment
30. **Bundle UI assets in PyInstaller spec**
31. **Remove deprecated `block_cipher`** from spec file

### Phase 4 — Nice to Have

26. **Consolidate `_safe_int` / `_safe_str`** helpers into a single utility module
27. **Replace `except Exception: pass`** with proper logging throughout
28. **Add connection pooling** for PullSDK in device_sync
29. **Add a health-check watchdog** thread
30. **Add duplicate fingerprint detection** during enrollment
31. **Fix CSV parser** to handle commas in field values

---

## 12. Action List

### Top 25 Fixes in Priority Order

| # | ID | Fix | Effort | Files |
|---|-----|-----|--------|-------|
| 1 | C-01 | Remove secrets file, add .gitignore, purge git history | 30 min | `.gitignore`, git commands |
| 2 | C-02 | Fix password in connect string | 5 min | `pullsdk.py:100` |
| 3 | C-03 | Return 0 on OSError in db_match | 5 min | `zkfinger.py:749` |
| 4 | C-04 | Remove V1 API or fix CORS | 15 min | `local_access_api.py:17` |
| 5 | C-06 | Change all URLs to HTTPS | 15 min | `config.py`, `monclub_api.py` |
| 6 | H-03 | Add `requests` to requirements.txt | 2 min | `requirements.txt` |
| 7 | C-05 | Make DPAPI fallback loud, not silent | 30 min | `secure_store.py`, `db.py` |
| 8 | H-01 | Add Lock to PullSDK | 1 hr | `pullsdk.py` |
| 9 | H-10 | Fix PullSDK.connect() to disconnect before overwriting | 10 min | `pullsdk.py` |
| 10 | H-11 | Stop logging card/PIN data at INFO level | 15 min | `pullsdk.py` |
| 11 | H-02 | Add WAL mode + write mutex to SQLite | 1 hr | `db.py` |
| 12 | H-04 | Remove Tkinter code from V2 API | 30 min | `local_access_api_v2.py` |
| 13 | H-09 | Delete duplicate DPAPI from db.py | 30 min | `db.py` |
| 14 | H-05 | Remove or truly deprecate global data_mode | 1 hr | `config.py` + all callers |
| 15 | H-06 | Add safety check for TOTP disabled mode | 30 min | `realtime_agent.py` |
| 16 | H-07 | Log dropped events + add counter | 15 min | `realtime_agent.py:803` |
| 17 | H-08 | Add counter to synthetic eventId | 30 min | `pullsdk.py` |
| 18 | M-13 | Fix platform parameter — append to connection string | 5 min | `pullsdk.py` |
| 19 | M-14 | Fix GetDeviceDataCount to raise on negative rc | 10 min | `pullsdk.py` |
| 20 | M-15 | Fix SetDeviceData partial failure detection | 15 min | `pullsdk.py` |
| 21 | M-01 | Add schema version table | 2 hr | `db.py` |
| 22 | M-02 | Add PRIMARY KEY to sync_users | 30 min | `db.py` |
| 23 | M-03 | Restrict V2 CORS to specific ports | 15 min | `local_access_api_v2.py` |
| 24 | M-04 | Add token refresh logic | 2 hr | `monclub_api.py` |
| 25 | M-06 | Switch to Tauri HTTP plugin | 2 hr | `client.ts` |

### Production-Blockers Only (Must Fix Before Any Deployment)

1. **C-01** — Secrets in repo (immediate data breach risk)
2. **C-02** — PullSDK ignores password (controller security bypassed)
3. **C-03** — Fingerprint match on DLL error (physical access bypass)
4. **C-04** — Wildcard CORS on API (remote exploitation via browser)
5. **C-06** — HTTP for backend comms (credentials in plaintext on wire)
6. **H-03** — Missing `requests` dependency (crash on fresh install)

---

## 13. Final Verdict

### Rating: 4/10 — NOT PRODUCTION-READY

**What kills it:**
The system has 6 critical findings that each independently could allow unauthorized physical access to a secured facility. The combination of plaintext TOTP secrets in source control, a fingerprint matcher that returns MATCH on DLL errors, ignored controller passwords, and wildcard CORS on the enrollment API creates a security posture that is unacceptable for any system controlling physical doors.

**What saves it:**
The core architecture is genuinely well-designed. The per-device mode dispatch, the DeviceWorker → Queue → DecisionService pipeline, delta sync with SHA1 hashing, adaptive sleep with exponential backoff, and the notification rate limiting are all solid engineering. The TOTP verification logic (when enabled) correctly implements drift steps, time validation, and replay protection. The code quality is generally high — these are implementation bugs and security oversights, not fundamental design failures.

### Good Parts Worth Keeping

1. **Realtime agent pipeline** (`realtime_agent.py`) — well-structured producer-consumer with proper separation of concerns (polling, decision, notification, history)
2. **Delta sync engine** (`device_sync.py`) — SHA1 hash comparison for change detection is efficient and correct
3. **Adaptive sleep** — exponential backoff on empty polls prevents tight-looping while maintaining responsiveness
4. **NotificationGate** — proper rate limiting with sliding window and deduplication
5. **EMA tracking** — lightweight performance monitoring for poll and command latencies
6. **PullSDKDevice wrapper** — clean abstraction over the raw DLL with RTLogExt→RTLog fallback
7. **Settings normalization** (`settings_reader.py`) — clamping, defaults, and fallback chains are thorough
8. **Offline creation queue** — full state machine (pending → processing → succeeded/failed_retryable/failed_terminal) with proper retry semantics
9. **V2 API CORS** — significantly better than V1, shows the right direction

### Bottom Line

Fix the 6 critical items (estimated 2-3 hours total), then the 11 high items (estimated 8-10 hours), and this system moves from 4/10 to 7/10. The architecture doesn't need rethinking — it needs the security holes plugged and the legacy debris cleaned out.
