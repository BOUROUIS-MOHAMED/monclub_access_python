# Log Upload System Design

**Date:** 2026-05-01  
**Status:** Approved  
**Scope:** monclub_access_python (client) + monclub_backend (server)

---

## Problem

Debugging production bugs in MonClub Access requires log files that currently live only on the gym's local machine. Collecting them means visiting each gym physically — too slow and too costly.

## Goal

After each log rotation, automatically upload the finalized log file (compressed) to the backend. Zero impact on the turnstile read path. Crash-safe with no SQLite or local database.

---

## Architecture

### Client side — `app/core/log_uploader.py`

A `LogUploadQueue` class runs as a background daemon thread. It is completely isolated from the turnstile path.

**Marker file protocol:**

When a log file is finalized (rotated away), a `.pending` marker file is created alongside it:

```
logs/
  app-2026-05-01-am.log           ← active, never touched by uploader
  app-2026-04-30-pm.log           ← rotated, ready to read
  app-2026-04-30-pm.log.pending   ← signals "upload this file" (content = retry count as ASCII int)
  app-2026-04-29-am.log.uploaded  ← upload confirmed
  app-2026-04-28-pm.log.failed    ← gave up (see retry policy)
```

**Marker file states:**

| Marker | Meaning |
|--------|---------|
| `.pending` | Rotated, waiting for upload. File content = retry count as plain ASCII integer (e.g. `"0"`, `"3"`). Parse failure treated as `0`. |
| `.uploaded` | Successfully uploaded. |
| `.failed` | Permanently skipped (see retry policy). |

No marker = file is either the active log or an orphan from a crash (handled by startup scan).

---

### Hook points in `HalfDaySizeRotatingFileHandler`

Add `on_log_rotated: Callable[[Path], None] | None = None` to `__init__`. The handler calls it with the finalized file path in two places.

**Invariant:** the callback is ONLY called after the file handle is closed. Both `_set_active_path` and `_rotate_active_file` already call `self.stream.close()` before any rename/path change. The callback must not be called if the underlying filesystem operation (rename) fails.

**1. `_switch_if_needed` (time rotation: AM→PM, day boundary):**

```python
def _switch_if_needed(self, now: dt.datetime) -> None:
    path = self._path_for(now)
    if Path(self.baseFilename) != path:
        old_path = Path(self.baseFilename)   # capture BEFORE overwriting
        self._set_active_path(path)          # closes stream, updates self.baseFilename
        if self.on_log_rotated and old_path.exists():
            self.on_log_rotated(old_path)
```

`old_path` must be captured before `_set_active_path` is called, because that method overwrites `self.baseFilename`.

**2. `_rotate_active_file` (size overflow):**

```python
def _rotate_active_file(self) -> None:
    source = Path(self.baseFilename)
    if self.stream:
        self.stream.flush()
        self.stream.close()
        self.stream = None
    try:
        if not source.exists() or source.stat().st_size <= 0:
            return
        dest = self._next_suffix_path(source)
        source.rename(dest)                  # rename must succeed first
        if self.on_log_rotated:
            self.on_log_rotated(dest)        # called with the RENAMED destination
    except OSError:
        return                               # do not call callback on failure
```

---

### `register_pending(path: Path) -> None`

This is the `on_log_rotated` callback. It creates `{path}.pending` with content `"0"` (initial retry count). Write is atomic: write to `{path}.pending.tmp`, then rename to `{path}.pending`. This prevents a corrupt marker if the process crashes mid-write.

---

### `LogUploadQueue` behaviour

**Constructor signature:**
```python
class LogUploadQueue:
    def __init__(
        self,
        log_dir: Path,
        get_token: Callable[[], str | None],       # lazy: reads token at upload time
        get_upload_url: Callable[[], str | None],  # lazy: reads config at upload time
    ) -> None
```

**Bootstrap wiring (in `app/ui/app.py`, `MonClubApp.__init__`, after `setup_logging` at line 321):**

```python
from app.core.db import load_auth_token
from app.core.log_uploader import LogUploadQueue

upload_queue = LogUploadQueue(
    log_dir=LOG_DIR,
    get_token=load_auth_token,                    # reads from local SQLite, no import cycle
    get_upload_url=lambda: self.cfg.log_upload_url,
)
# Wire the callback into the file handler
for h in self.logger.handlers:
    if isinstance(h, HalfDaySizeRotatingFileHandler):
        h.on_log_rotated = upload_queue.register_pending
        break

upload_queue.scan_orphans()   # crash recovery: must run before start()
upload_queue.start()          # launches daemon thread
```

`load_auth_token` is already importable from `app.core.db` (used in `monclub_api.py`). `self.cfg.log_upload_url` comes from the config file — added as an optional field, defaults to `""`. When the upload URL is empty or the token is None, the upload attempt is skipped silently and retried next cycle.

**Startup scan — `scan_orphans()`:**

Scans `log_dir` for files matching `_LOG_FILE_RE` that are NOT the currently active log file and have no `.uploaded` or `.failed` sibling. For each: calls `register_pending(path)` if `.pending` does not already exist (skips if already registered to avoid resetting retry count).

To identify the currently active file: instantiate a throwaway `dt.datetime.now()` path using the same `_path_for` logic, compare by name. Do not access the handler object from the uploader (avoids coupling).

**Upload loop — runs every 60 seconds:**

1. Glob all `*.pending` markers in `log_dir`
2. For each marker:
   a. Read content → parse as int, default `0` on parse failure
   b. Check if corresponding `.log` file exists. If not: delete the `.pending` marker, log a WARNING (file was deleted before upload, nothing to upload), continue to next
   c. Read `.log` file bytes
   d. Gzip-compress in memory (`gzip.compress(data, compresslevel=6)`)
   e. Call `_upload(log_path, compressed_bytes)` (two-step: presign → PUT)
   f. On success: delete `.pending`, create `.uploaded` (empty file)
   g. On failure: increment retry count, write atomically to `.pending`, apply backoff

**Retry policy (no hard cap):**

Retry interval grows with attempt count, capped at 60 minutes:

| Attempt | Wait before next try |
|---------|---------------------|
| 0 → 1   | next 60s loop cycle |
| 1 → 2   | 2 min               |
| 2 → 3   | 4 min               |
| 3 → 4   | 8 min               |
| 4 → 5   | 16 min              |
| 5+      | 60 min (max)        |

Retry count is stored in the `.pending` file content (plain ASCII integer). At each loop tick, the uploader reads the count and only attempts upload if enough time has passed since the previous attempt. The last-attempt timestamp is tracked in-memory (not on disk) — on process restart, all `.pending` files are retried immediately regardless of count (conservative: prefer re-attempt over permanent skip).

There is NO maximum retry count. Files are retried indefinitely until upload succeeds or the `.log` file is deleted by the 7-day retention cleanup. After the `.log` is gone, the `.pending` is removed with a warning (covered above).

---

### Retention conflict fix

`_cleanup_old_logs` must be extended with one guard: before calling `path.unlink()` on a `.log` file, check if `Path(str(path) + ".pending")` exists. If it does, skip deletion for this cycle. This prevents deleting a log before its upload succeeds.

Additionally, clean up stale `.uploaded` and `.failed` marker files older than 30 days (housekeeping — they have no `.log` counterpart):

```python
for path in self.log_dir.iterdir():
    if path.suffix in (".uploaded", ".failed") and ...:
        if log_date < cutoff_30d:
            path.unlink(missing_ok=True)
```

---

### Upload flow — two requests (presign + PUT)

`ObjectStorageService` only provides presigned URL generation — it has no `putObject(bytes)` method. Therefore the upload uses two HTTP calls:

**Step 1: Request presigned URL from backend**

```
POST /api/v1/gym/access/logs/presign
Authorization: Bearer {token}
Content-Type: application/json

{"filename": "app-2026-04-30-pm.log"}
```

Response:
```json
{
  "url": "https://r2.example.com/...",
  "method": "PUT",
  "headers": {"Content-Type": "application/gzip"},
  "expiresAt": "2026-05-01T12:30:00"
}
```

`filename` field: original `.log` filename, no `.gz` suffix (e.g. `app-2026-04-30-pm.log`). The backend appends `.gz` when constructing the R2 key.

**Step 2: Upload directly to R2**

```
PUT {url}
Content-Type: application/gzip
{headers from step 1}

[gzip-compressed log bytes]
```

This is a direct client-to-R2 PUT. The backend is not involved.

**`MonClubApi.upload_log_file` method:**

```python
def upload_log_file(
    self,
    *,
    token: str,
    filename: str,       # original .log name, no .gz suffix
    compressed: bytes,   # gzip-compressed bytes
    timeout: int = 120,
) -> None:
    """Two-step: get presigned URL, then PUT directly to R2."""
```

Raises `MonClubApiError` on any failure. The uploader catches this and increments retry count.

---

### New `ApiEndpoints` field

```python
log_presign_url: str = ""   # e.g. https://api.example.com/api/v1/gym/access/logs/presign
```

---

## Backend side — `monclub_backend`

### New controller: `AccessLogUploadController.java`

**Route:** `POST /api/v1/gym/access/logs/presign`

**Security:** `/api/v1/gym/**` is already restricted to `Role.GYM + Role.ADMIN` in `SecurityConfiguration`. No changes needed.

**Request body:**
```json
{"filename": "app-2026-05-01-am.log"}
```

**Validation:**
- `filename` must match `^app-\d{4}-\d{2}-\d{2}-(am|pm)(\.\d+)?\.log$` — prevents path traversal and garbage filenames
- Empty filename → `400`

**Processing:**
1. Extract `gymId` from JWT (same pattern used everywhere via `JwtService`)
2. Extract year from filename for R2 key partitioning
3. Build R2 object key: `access-logs/{gymId}/{year}/{filename}.gz`
4. Call `objectStorageService.createPresignedPut(bucket, key, "application/gzip", FileVisibility.PRIVATE, 30)` (30-minute TTL)
5. Return `200 OK` with `{url, method, headers, expiresAt}`

**Error responses:**
- `400` — invalid or missing filename
- `500` — presign generation failure

### No Spring multipart config changes needed

The presigned approach means the backend never receives the file. No `max-file-size` tuning required.

---

## Data flow

```
[Logger writes record]
         │
         ▼
[HalfDaySizeRotatingFileHandler]
         │ time/size rotation triggers
         │ (stream closed, rename done first)
         ▼
[on_log_rotated(old_or_dest_path)]
         │ atomic write: .pending.tmp → .pending (content = "0")
         │ (<1ms, no locks, no DB)
         │
         │  (completely separate daemon thread, 60s loop)
         ▼
[LogUploadQueue._upload_loop]
  1. read retry count from .pending
  2. check .log file exists (if not: delete .pending, warn, skip)
  3. read .log bytes, gzip-compress in memory
  4. POST /api/v1/gym/access/logs/presign → get R2 presigned URL
  5. PUT compressed bytes directly to R2
         │
         ├── 200 OK → delete .pending, create .uploaded (empty)
         └── error  → increment retry count, atomic write to .pending
                       retry after backoff (max 60 min interval)
                       indefinite retries until .log file is deleted
```

---

## What this does NOT touch

- Turnstile read path (`access_verification.py`, `device_worker.py`, `card_scanner.py`)
- Main application database (`app.db`) — only `load_auth_token` reads from it, same as sync loop
- Any UI thread
- Any existing sync logic

---

## Files to create / modify

### monclub_access_python

| File | Change |
|------|--------|
| `app/core/log_uploader.py` | **New** — `LogUploadQueue` class |
| `app/core/logger.py` | Add `on_log_rotated` callback; fix `_switch_if_needed` and `_rotate_active_file` to capture old path and call callback correctly |
| `app/api/monclub_api.py` | Add `log_presign_url` to `ApiEndpoints`; add `upload_log_file` method |
| `app/core/config.py` | Add `log_upload_url: str = ""` (or `log_presign_url`) to config dataclass |
| `app/ui/app.py` | Wire `LogUploadQueue` after `setup_logging` call |

### monclub_backend

| File | Change |
|------|--------|
| `Controllers/AccessLogUploadController.java` | **New** — presign endpoint |
| No `application.yml` change | Presigned approach; no multipart limit needed |
