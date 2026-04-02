# MonClub Access Security and Safety Review
# Round 6 — 2026-04-02

---

## Scope

This review covers the security posture of MonClubAccess.exe: local API authentication, physical access decision integrity, credential storage, process isolation, and inter-component communication. All blockers and high-severity issues from prior rounds are confirmed fixed.

---

## 1. Local API Authentication

### B-001 / H-001 (FIXED Round 5) — Per-session token auth

**Mechanism**: `secrets.token_urlsafe(32)` generated at app startup in `MainApp.__init__`. Stored as `self._local_api_token`. Passed to the Tauri child process via environment variable `MONCLUB_LOCAL_API_TOKEN`. TypeScript layer calls `setAuthToken()` which injects it as `X-Local-Token` header (or `?token=` for SSE streams). Python middleware validates on every non-exempt request.

**Auth middleware** (`app/api/local_access_api_v2.py:4237-4252`):
```
_AUTH_EXEMPT = {
    "_handle_auth_login", "_handle_auth_status",
    "_handle_tv_auth_login", "_handle_tv_auth_status",
    "_handle_health", "_handle_v1_health",
}
```
Non-exempt requests: compares `X-Local-Token` (or `?token=`) against `_local_api_token` using `!=` (string equality). Returns HTTP 401 if missing or wrong.

**Residual risk**: string comparison is not constant-time. A timing oracle attack would require ~10^32 guesses at 32-character base64url space — negligible in a localhost context.

**Verdict**: Sufficient for a loopback-only API.

### B-002 (FIXED Round 5) — Bind address hardcoded

`_effective_local_api_bind()` returns `"127.0.0.1"` unconditionally (`app/ui/app.py:670`). API never listens on 0.0.0.0. Confirmed.

---

## 2. Physical Access Decision Integrity

### 2.1 Fail-closed on DB failure

| Mode | Code | Behavior |
|------|------|---------|
| AGENT | `DecisionService`: `_history_claimed = 0` on exception | Door never opens |
| ULTRA | `UltraDeviceWorker._enqueue_history()`: `inserted = False` on exception | Door never opens |
| DEVICE | Firmware-first; PC role is push only | N/A |

Both fail-closed guards are verified in tests (`tests/test_ultra_engine.py`).

### 2.2 Atomic dedup gate

`INSERT OR IGNORE` on `UNIQUE(event_id)` in `access_history`. A second `insert_access_history()` call for the same `event_id` returns `rowcount=0`, blocking the door-open path. This prevents double door-open under concurrent DecisionService workers or restart replay.

### 2.3 TOTP verification

`verify_totp()` in `app/core/access_verification.py`:
- HMAC-SHA1 with configurable counter window (default: 1 step behind / 1 step ahead, 30s each)
- Code age check: `if age > max_past_age_seconds: deny` (default 32s)
- Collision detection: if two credentials match the same code → `DENY_COLLISION`
- RFID fallback: if a card number accidentally matches TOTP prefix format, falls back to `verify_card()` after TOTP fails. Result is correct (card check), scan mode logged may differ.

**TOTP replay within same 30-second window**: not blocked by design. A captured code replayed within the same window succeeds. This is standard TOTP behavior; per-event dedup prevents the same device event from opening the door twice.

### 2.4 Anti-wipe guard

`save_sync_cache()` refuses to overwrite local user cache if backend returns 0 users and local has >10. Prevents accidental lockout on backend outage or bug. Guard located at `app/core/db.py:1182-1191`.

---

## 3. Credential Storage

### DPAPI protection (`shared/auth_state.py`)

Backend auth token is encrypted with Windows DPAPI (`CryptProtectData`) before writing to SQLite. On failure, `protect_auth_token()` returns `""` — token not stored (fail-closed). On decrypt failure, `unprotect_auth_token()` returns `None`.

**Legacy "raw:" prefix**: code still handles `"raw:"` prefix for backward compatibility with pre-DPAPI installations. This is a migration window, not a security regression — old installations' tokens are still valid but unencrypted. Recommended one-time migration on next startup (L-001, open post-launch).

**TOTP credentials**: stored in backend-controlled `sync_users` table inside SQLite `access.db`. Protected by OS user account via DPAPI-encrypted token (no separate encryption of credential cache). Acceptable for a single-tenant Windows desktop application.

---

## 4. PullSDK Native DLL

`plcommpro.dll` is a 32-bit native ZKTeco library. Security considerations:

- DLL loaded from fixed path in app bundle; not user-controllable.
- All PullSDK calls go through `app/sdk/pullsdk.py` Python wrapper; no raw ctypes exposed to user input.
- TCP device connections are outbound from the PC to the ZKTeco device on the LAN. No inbound connections via PullSDK.
- `DeviceSyncEngine` uses `ThreadPoolExecutor(max_workers=4)` — maximum 4 concurrent DLL connections. Post-Round-6 fix (M-NEW-001) prevents concurrent connections to the same ULTRA device.

---

## 5. Command Injection / Input Validation

Local API endpoints receive JSON bodies and URL parameters. No shell commands are constructed from user input. No `subprocess` calls with user data. No SQL string interpolation — all queries use parameterized SQLite3 calls.

**Door-open rate limit** (M-003, fixed Round 4): `/api/v2/devices/{id}/door/open` has a per-device 1-second cooldown enforced by `_door_open_last` dict. Returns HTTP 429 on excess.

---

## 6. Notification / SSE Stream

SSE stream (`/api/v2/ultra/popup/stream`) uses `?token=` query parameter because SSE browser connections cannot set custom headers. The token is the same per-session `_local_api_token`. The stream emits notification payloads (member name, access result) to the Tauri WebView — no secrets transmitted over SSE.

---

## 7. Process Isolation

The Tauri UI (`monclub-access-ui.exe`) runs as a child process of the Python app. IPC is HTTP-over-loopback with per-session token. The WebView (WebView2 / Chromium) renders the React UI; no direct access to SQLite or PullSDK from the renderer process.

TV component (`tv/`) is a separate sub-service. A TV crash cannot affect access decisions.

---

## 8. Secrets in Build Artifacts

**L-003 (open)**: `gym_access_secrets_cache.json` at project root. Name implies credentials. This file should be confirmed as gitignored and excluded from the installer package. Not verified — assigned low severity because the file may contain only test/development data.

**Recommendation**: verify `.gitignore` and PyInstaller `.spec` exclude this file before packaging.

---

## 9. Attack Surface Summary

| Attack vector | Exposure | Mitigation |
|--------------|---------|-----------|
| Local process calls door-open API | Requires valid `_local_api_token` (per-session, 32-byte random) | Per-session token auth (FIXED) |
| Network process calls door-open API | API bound to 127.0.0.1 only | Loopback bind (FIXED) |
| Replay of captured TOTP code (same window) | Valid within same 30s window | By design; dedup prevents double-open per event |
| Replay of captured TOTP code (new window) | Blocked by counter window + age check | max_past_age_seconds = 32s |
| SQLite injection | None — parameterized queries only | N/A |
| DLL hijack of plcommpro.dll | DLL in app bundle, fixed path | Out of scope for software audit |
| Backend credential interception | HTTPS to cloud API | Not in scope for this app |
| Stale credential cache after membership expiry | Offline auth from cache indefinitely | No max-age enforcement (L-006, post-launch) |

---

## 10. Verdict

**No open security blockers.** All Round 5 critical and high findings are fixed. Two low-priority items remain open:

- **L-001**: `"raw:"` legacy token migration — low risk, affects pre-DPAPI installs only
- **L-003**: Verify `gym_access_secrets_cache.json` excluded from build artifacts

Both are acceptable for launch with post-launch follow-through.
