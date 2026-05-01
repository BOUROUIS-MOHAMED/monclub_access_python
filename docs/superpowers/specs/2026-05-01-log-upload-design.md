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

A `LogUploadQueue` class runs as a daemon background thread. It is completely isolated from the turnstile path.

**Marker file protocol:**

When a log file is finalized (rotated away), a `.pending` marker file is created alongside it:

```
logs/
  app-2026-05-01-am.log           ← active, never touched by uploader
  app-2026-04-30-pm.log           ← rotated, ready to read
  app-2026-04-30-pm.log.pending   ← signals "upload this file"
  app-2026-04-29-am.log.uploaded  ← upload confirmed
  app-2026-04-28-pm.log.failed    ← gave up after max retries
```

**Marker file states:**

| Marker | Meaning |
|--------|---------|
| `.pending` | Rotated, waiting for upload |
| `.uploaded` | Successfully uploaded |
| `.failed` | Max retries exceeded, skipped |

No marker = file is either the active log or an orphan from a crash.

---

### Hook points in `HalfDaySizeRotatingFileHandler`

Add an `on_log_rotated: Callable[[Path], None] | None` parameter to `__init__`. The handler calls it with the finalized file path in two places:

1. **`_switch_if_needed`** — when the active file path changes (AM→PM, day boundary). Called with the old path before switching.
2. **`_rotate_active_file`** — when a file is renamed due to size overflow. Called with the renamed destination path.

The callback does one thing: create `{path}.pending`. This is a single atomic filesystem operation — no locks, no DB writes, no latency on the logging thread.

---

### `LogUploadQueue` behaviour

**Startup scan (crash recovery):**

On `start()`, scans `LOG_DIR` for any `.log` file that:
- Matches `_LOG_FILE_RE` pattern
- Is NOT the currently active log file
- Has no `.uploaded` or `.failed` sibling

Creates a `.pending` marker for each. This recovers files orphaned by a hard crash.

**Upload loop (runs every 60 seconds):**

1. Glob all `*.pending` markers in `LOG_DIR`
2. For each: read the corresponding `.log` file, gzip-compress in memory, POST to backend
3. On success: delete `.pending`, create `.uploaded`
4. On failure: increment retry count (stored as content of the `.pending` file), backoff
5. After 5 failures: delete `.pending`, create `.failed`, log a warning

**Retry backoff:** 1 min → 2 min → 4 min → 8 min → 16 min (tracked via loop sleep, not wall clock)

**Internet-down behaviour:** upload attempt silently fails, `.pending` stays, retried next cycle. No crash, no exception propagation.

**Thread safety:** The uploader only reads files that have been rotated away (the logger no longer writes them). Marker file creation is a single `Path.touch()` call — atomic at the OS level. No shared mutable state between threads.

---

### Retention conflict fix

`_cleanup_old_logs` currently deletes `.log` files older than 7 days. It must be extended to:
- Skip any `.log` file that has a `.pending` sibling (upload not yet done)
- Still delete `.uploaded` and `.failed` marker files older than 30 days (housekeeping)

---

### API changes — `app/api/monclub_api.py`

**`ApiEndpoints`:** add `log_upload_url: str = ""`

**`MonClubApi`:** add method:
```python
def upload_log_file(
    self,
    *,
    token: str,
    filename: str,
    compressed_data: bytes,
    timeout: int = 120,
) -> None
```
Posts as `multipart/form-data` with fields `file` (gzip bytes) and `filename`. Raises `MonClubApiError` on failure.

---

### Bootstrap wiring

In `access/bootstrap.py` (or wherever `setup_logging` is called):

1. Create `LogUploadQueue(log_dir=LOG_DIR, ...)`
2. Pass `on_log_rotated=queue.register_pending` to `setup_logging` / the handler
3. Call `queue.scan_orphans()` 
4. Call `queue.start()` (starts daemon thread)

The queue needs access to the auth token and upload URL. It reads them lazily on each upload attempt (so it still works if the token is refreshed mid-session). Injected via callables: `get_token: Callable[[], str | None]` and `get_upload_url: Callable[[], str | None]`.

---

## Backend side — `monclub_backend`

### New controller: `AccessLogUploadController.java`

**Route:** `POST /api/v1/gym/access/logs/upload`

**Security:** `/api/v1/gym/**` is already restricted to `Role.GYM + Role.ADMIN` in `SecurityConfiguration`. No changes needed.

**Request:** `multipart/form-data`
- `file` — gzip-compressed log file (max 60 MB)
- `filename` — original log filename (e.g. `app-2026-05-01-am.log`)

**Validation:**
- `filename` must match regex `^app-\d{4}-\d{2}-\d{2}-(am|pm)(\.\d+)?\.log$` — prevents path traversal
- File must not be empty

**Processing:**
1. Extract `gymId` from JWT (same pattern used everywhere in the codebase)
2. Extract year from filename for storage partitioning
3. Store via `ObjectStorageService.putObject(bucket, key, bytes)` at key: `access-logs/{gymId}/{year}/{filename}.gz`
4. Return `200 OK` with `{"stored": "access-logs/{gymId}/{year}/{filename}.gz"}`

**Error responses:**
- `400` — invalid filename or empty file
- `413` — file too large (Spring multipart limit)
- `500` — storage failure (client will retry)

### Spring config

```yaml
spring:
  servlet:
    multipart:
      max-file-size: 60MB
      max-request-size: 65MB
```

---

## Data flow

```
[Logger writes record]
       │
       ▼
[HalfDaySizeRotatingFileHandler]
       │ time/size rotation triggers
       ▼
[on_log_rotated(path)] ─── creates {path}.pending  (atomic, <1ms)
       │
       │   (completely separate thread, 60s loop)
       ▼
[LogUploadQueue._upload_loop]
  reads {path}.log
  gzip-compresses in memory
  POST /api/v1/gym/access/logs/upload
       │
       ├── 200 OK → delete .pending, create .uploaded
       └── error  → increment retry counter in .pending
                    retry later with backoff
                    → after 5 failures: .failed
```

---

## What this does NOT touch

- Turnstile read path (`access_verification.py`, `device_worker.py`, `card_scanner.py`)
- Main application database (`app.db`)
- Any UI thread
- Any existing sync logic

---

## Files to create / modify

### monclub_access_python
| File | Change |
|------|--------|
| `app/core/log_uploader.py` | **New** — `LogUploadQueue` |
| `app/core/logger.py` | Add `on_log_rotated` callback to handler |
| `app/api/monclub_api.py` | Add `log_upload_url` to `ApiEndpoints`, add `upload_log_file` method |
| `app/core/utils.py` | No change needed |
| `access/bootstrap.py` | Wire uploader into startup |

### monclub_backend
| File | Change |
|------|--------|
| `Controllers/AccessLogUploadController.java` | **New** |
| `application.yml` (or `application.properties`) | Add multipart size limits |
