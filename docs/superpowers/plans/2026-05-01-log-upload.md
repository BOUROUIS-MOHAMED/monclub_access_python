# Log Upload System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After each AM/PM log rotation, automatically gzip-compress and upload the finalized log file to the backend (via presigned R2 URL), using marker files for state — no DB, no impact on the turnstile path.

**Architecture:** `HalfDaySizeRotatingFileHandler` gains an `on_log_rotated` callback that creates a `.pending` marker file (atomic). A background `LogUploadQueue` daemon thread scans for `.pending` files every 60 s, compresses the log, requests a presigned R2 URL from the backend, and PUTs directly to R2. Retries are indefinite with capped backoff (max 60 min). The backend only issues presigned URLs — it never receives the file bytes.

**Tech Stack:** Python 3.11, `requests`, `gzip` (stdlib), `pathlib` (stdlib), `threading` (stdlib); Java 17 / Spring Boot, Cloudflare R2 via AWS S3 SDK (already wired in `ObjectStorageService`).

**Spec:** `docs/superpowers/specs/2026-05-01-log-upload-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `app/core/log_uploader.py` | **Create** | `LogUploadQueue`: marker files, compress, upload, retry |
| `app/core/logger.py` | **Modify** | Add `on_log_rotated` callback to `HalfDaySizeRotatingFileHandler`; fix `_switch_if_needed` and `_rotate_active_file` |
| `app/api/monclub_api.py` | **Modify** | Add `log_presign_url` to `ApiEndpoints` only (no upload method — queue handles it directly) |
| `app/core/config.py` | **Modify** | Add `log_presign_url: str = ""` field to `AppConfig` |
| `app/ui/app.py` | **Modify** | Wire `LogUploadQueue` after `setup_logging` |
| `tests/test_log_uploader.py` | **Create** | All unit tests for the uploader |
| `tests/test_logger_rotation_hook.py` | **Create** | Tests for the `on_log_rotated` callback |
| `monclub_backend/.../AccessLogUploadController.java` | **Create** | Presign endpoint |

---

## Part 1: Python client

---

### Task 1: Add `on_log_rotated` callback to the logger

**Files:**
- Modify: `app/core/logger.py`
- Create: `tests/test_logger_rotation_hook.py`

- [ ] **Step 1.1: Write failing tests**

Create `tests/test_logger_rotation_hook.py`:

```python
"""Tests for on_log_rotated callback in HalfDaySizeRotatingFileHandler."""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.core.logger import HalfDaySizeRotatingFileHandler


def _make_handler(tmp_path: Path, callback=None, *, max_bytes: int = 1024) -> HalfDaySizeRotatingFileHandler:
    h = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=max_bytes,
        retention_days=7,
        on_log_rotated=callback,
    )
    fmt = logging.Formatter("%(message)s")
    h.setFormatter(fmt)
    return h


def _emit(h: HalfDaySizeRotatingFileHandler, msg: str, when: dt.datetime) -> None:
    record = logging.LogRecord("test", logging.DEBUG, "", 0, msg, (), None)
    h.now_func = lambda: when
    h.emit(record)


class TestOnLogRotatedCallback:
    def test_callback_receives_old_path_on_time_rotation(self, tmp_path):
        """Switching from AM to PM must call the callback with the AM log path."""
        captured = []
        h = _make_handler(tmp_path, callback=captured.append)

        am = dt.datetime(2026, 5, 1, 9, 0)
        _emit(h, "hello am", am)

        pm = dt.datetime(2026, 5, 1, 13, 0)
        _emit(h, "hello pm", pm)  # triggers time rotation

        h.close()
        assert len(captured) == 1
        assert captured[0].name == "app-2026-05-01-am.log"

    def test_callback_receives_dest_path_on_size_rotation(self, tmp_path):
        """Exceeding max_bytes must call the callback with the renamed file path."""
        captured = []
        h = _make_handler(tmp_path, callback=captured.append, max_bytes=10)

        now = dt.datetime(2026, 5, 1, 9, 0)
        _emit(h, "a" * 20, now)  # forces size rotation
        _emit(h, "b", now)

        h.close()
        assert len(captured) >= 1
        # renamed file has .1 suffix
        assert ".1" in captured[0].name

    def test_callback_not_called_when_no_rotation(self, tmp_path):
        """No rotation → callback is never called."""
        captured = []
        h = _make_handler(tmp_path, callback=captured.append)

        now = dt.datetime(2026, 5, 1, 9, 0)
        _emit(h, "x", now)
        _emit(h, "y", now)

        h.close()
        assert captured == []

    def test_callback_none_is_safe(self, tmp_path):
        """on_log_rotated=None must not raise when rotation happens."""
        h = _make_handler(tmp_path, callback=None)
        am = dt.datetime(2026, 5, 1, 9, 0)
        pm = dt.datetime(2026, 5, 1, 13, 0)
        _emit(h, "x", am)
        _emit(h, "y", pm)  # time rotation, no callback
        h.close()

    def test_callback_not_called_on_failed_size_rotation(self, tmp_path, monkeypatch):
        """If rename raises OSError, callback must NOT be called."""
        captured = []
        h = _make_handler(tmp_path, callback=captured.append, max_bytes=10)

        now = dt.datetime(2026, 5, 1, 9, 0)
        # First emit seeds the file with data (size was 0, no rotation yet)
        _emit(h, "a" * 20, now)

        # Now the file has content; next emit will trigger _should_rotate.
        # Apply the monkeypatch AFTER the first write so the file exists.
        def failing_rename(self_path, target):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "rename", failing_rename)
        _emit(h, "b" * 5, now)   # triggers size rotation → rename fails → no callback

        h.close()
        assert captured == []
```

- [ ] **Step 1.2: Run tests to confirm they fail**

```bash
cd /c/Users/mohaa/Desktop/monclub_access_python
python -m pytest tests/test_logger_rotation_hook.py -v
```

Expected: `ERROR` — `HalfDaySizeRotatingFileHandler.__init__` does not accept `on_log_rotated`.

- [ ] **Step 1.3: Implement the callback in `app/core/logger.py`**

**In `__init__`**, add the parameter:
```python
def __init__(
    self,
    log_dir: str | Path,
    *,
    max_bytes: int = LOG_MAX_BYTES,
    retention_days: int = LOG_RETENTION_DAYS,
    encoding: str = "utf-8",
    now_func: Callable[[], dt.datetime] | None = None,
    on_log_rotated: Callable[[Path], None] | None = None,   # ← add this
) -> None:
    ...
    self.on_log_rotated = on_log_rotated   # ← store it (before super().__init__)
```

**Replace `_switch_if_needed`:**
```python
def _switch_if_needed(self, now: dt.datetime) -> None:
    path = self._path_for(now)
    if Path(self.baseFilename) != path:
        old_path = Path(self.baseFilename)      # capture BEFORE overwrite
        self._set_active_path(path)             # closes stream, updates baseFilename
        if self.on_log_rotated and old_path.exists():
            try:
                self.on_log_rotated(old_path)
            except Exception:
                pass
```

**Replace `_rotate_active_file`:**
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
        source.rename(dest)                     # rename must succeed first
        if self.on_log_rotated:
            try:
                self.on_log_rotated(dest)       # called with RENAMED destination
            except Exception:
                pass
    except OSError:
        return                                  # do NOT call callback on failure
```

- [ ] **Step 1.4: Run tests and confirm pass**

```bash
python -m pytest tests/test_logger_rotation_hook.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 1.5: Commit**

```bash
git add app/core/logger.py tests/test_logger_rotation_hook.py
git commit -m "feat: add on_log_rotated callback to HalfDaySizeRotatingFileHandler"
```

---

### Task 2: `LogUploadQueue` — `register_pending` with atomic write

**Files:**
- Create: `app/core/log_uploader.py`
- Create: `tests/test_log_uploader.py`

- [ ] **Step 2.1: Write failing test**

Create `tests/test_log_uploader.py` with this first section:

```python
"""Tests for LogUploadQueue."""
from __future__ import annotations

import datetime as dt
import gzip
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from app.core.log_uploader import LogUploadQueue


def _make_queue(tmp_path: Path, get_token=None, get_url=None) -> LogUploadQueue:
    get_token = get_token or (lambda: "test-token")
    get_url = get_url or (lambda: "https://api.example.com/api/v1/gym/access/logs/presign")
    return LogUploadQueue(log_dir=tmp_path, get_token=get_token, get_upload_url=get_url)


class TestRegisterPending:
    def test_creates_pending_marker(self, tmp_path):
        """register_pending creates {path}.pending with content '0'."""
        log = tmp_path / "app-2026-05-01-am.log"
        log.write_text("log content")

        q = _make_queue(tmp_path)
        q.register_pending(log)

        marker = Path(str(log) + ".pending")
        assert marker.exists()
        assert marker.read_text().strip() == "0"

    def test_atomic_write_no_tmp_left_over(self, tmp_path):
        """No .pending.tmp file should remain after register_pending."""
        log = tmp_path / "app-2026-05-01-am.log"
        log.write_text("x")

        q = _make_queue(tmp_path)
        q.register_pending(log)

        tmp_marker = Path(str(log) + ".pending.tmp")
        assert not tmp_marker.exists()

    def test_idempotent_does_not_reset_count(self, tmp_path):
        """Calling register_pending twice must not overwrite an existing .pending."""
        log = tmp_path / "app-2026-05-01-am.log"
        log.write_text("x")

        q = _make_queue(tmp_path)
        q.register_pending(log)

        marker = Path(str(log) + ".pending")
        marker.write_text("3")  # simulate 3 prior retries

        q.register_pending(log)  # second call
        assert marker.read_text().strip() == "3"  # must not be reset to 0
```

- [ ] **Step 2.2: Run tests to confirm they fail**

```bash
python -m pytest tests/test_log_uploader.py::TestRegisterPending -v
```

Expected: `ModuleNotFoundError: No module named 'app.core.log_uploader'`

- [ ] **Step 2.3: Create `app/core/log_uploader.py` with minimal implementation**

```python
"""Log upload queue — marker-file based, zero impact on turnstile path."""
from __future__ import annotations

import gzip
import logging
import re
import threading
import time
from pathlib import Path
from typing import Callable

logger = logging.getLogger("zkapp")

# Must match the same pattern as HalfDaySizeRotatingFileHandler
_LOG_FILE_RE = re.compile(r"^app-(\d{4}-\d{2}-\d{2})-(am|pm)(?:\.(\d+))?\.log$")

# Retry backoff intervals (seconds) indexed by attempt count; last value is the cap.
_BACKOFF_SECONDS = [0, 120, 240, 480, 960, 3600]


class LogUploadQueue:
    """
    Background daemon that uploads finalized log files to the backend via
    presigned R2 URLs. Uses marker files for state — no SQLite, no DB.

    Files never touched by this class while the logger is actively writing to them.
    """

    def __init__(
        self,
        log_dir: Path,
        get_token: Callable[[], object | None],       # returns AuthTokenState|None or str|None
        get_upload_url: Callable[[], str | None],
    ) -> None:
        self.log_dir = Path(log_dir)
        self._get_token = get_token
        self._get_upload_url = get_upload_url
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # In-memory: maps marker path string → monotonic time of last attempt
        # Enforces backoff without writing to disk. Reset on restart (intentional:
        # conservative policy is to retry immediately after restart).
        self._last_attempt: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_pending(self, log_path: Path) -> None:
        """Called by on_log_rotated when a log file is finalized.

        Creates {log_path}.pending atomically. Content = "0" (retry count).
        Idempotent: does not overwrite an existing .pending file.
        """
        marker = Path(str(log_path) + ".pending")
        if marker.exists():
            return  # already registered, don't reset retry count
        tmp = Path(str(marker) + ".tmp")
        try:
            tmp.write_text("0", encoding="utf-8")
            tmp.rename(marker)
        except OSError as e:
            logger.warning("LogUploadQueue: failed to create .pending for %s: %s", log_path.name, e)

    def scan_orphans(self) -> None:
        """Called once at startup to recover files orphaned by a hard crash.

        Any .log file that matches the naming pattern, is not the currently
        active file, and has no .uploaded or .failed sibling gets a .pending
        marker created for it.
        """
        active_name = self._active_log_name()
        try:
            for path in self.log_dir.iterdir():
                if not path.is_file():
                    continue
                if not _LOG_FILE_RE.match(path.name):
                    continue
                if path.name == active_name:
                    continue
                if Path(str(path) + ".uploaded").exists():
                    continue
                if Path(str(path) + ".failed").exists():
                    continue
                self.register_pending(path)
        except OSError as e:
            logger.warning("LogUploadQueue: scan_orphans error: %s", e)

    def start(self) -> None:
        """Start the background daemon thread."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._upload_loop,
            name="log-uploader",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the background thread to stop (used in tests)."""
        self._stop.set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _active_log_name(self) -> str:
        """Return the filename of the currently active log (not yet rotated)."""
        import datetime as dt
        now = dt.datetime.now()
        period = "am" if now.hour < 12 else "pm"
        return f"app-{now.date().isoformat()}-{period}.log"

    def _read_retry_count(self, marker: Path) -> int:
        try:
            return max(0, int(marker.read_text(encoding="utf-8").strip()))
        except Exception:
            return 0

    def _write_retry_count(self, marker: Path, count: int) -> None:
        tmp = Path(str(marker) + ".tmp")
        try:
            tmp.write_text(str(count), encoding="utf-8")
            tmp.rename(marker)
        except OSError as e:
            logger.warning("LogUploadQueue: failed to write retry count to %s: %s", marker.name, e)

    def _backoff_for(self, attempt: int) -> int:
        """Return seconds to wait before the next attempt."""
        if attempt < len(_BACKOFF_SECONDS):
            return _BACKOFF_SECONDS[attempt]
        return _BACKOFF_SECONDS[-1]

    def _upload_loop(self) -> None:
        """Main loop: scan for .pending markers and process them."""
        while not self._stop.is_set():
            self._process_pending_files()
            self._stop.wait(timeout=60)

    def _process_pending_files(self) -> None:
        try:
            markers = list(self.log_dir.glob("*.pending"))
        except OSError:
            return
        for marker in markers:
            if self._stop.is_set():
                break
            self._handle_marker(marker)

    def _handle_marker(self, marker: Path) -> None:
        log_path = Path(str(marker)[: -len(".pending")])

        # If the .log file is gone (deleted by cleanup), abandon this marker.
        if not log_path.exists():
            logger.warning(
                "LogUploadQueue: %s deleted before upload; removing .pending", log_path.name
            )
            try:
                marker.unlink(missing_ok=True)
                self._last_attempt.pop(str(marker), None)
            except OSError:
                pass
            return

        retry_count = self._read_retry_count(marker)

        # Enforce backoff: skip if not enough time has passed since last attempt.
        now_mono = time.monotonic()
        required_wait = self._backoff_for(retry_count)
        last = self._last_attempt.get(str(marker), 0.0)
        if retry_count > 0 and (now_mono - last) < required_wait:
            return  # too soon; wait for the next loop cycle

        try:
            compressed = self._compress(log_path)
        except OSError as e:
            logger.warning("LogUploadQueue: cannot read %s: %s", log_path.name, e)
            return

        self._last_attempt[str(marker)] = time.monotonic()
        success = self._upload(log_path.name, compressed)
        if success:
            try:
                marker.unlink(missing_ok=True)
                self._last_attempt.pop(str(marker), None)
                Path(str(log_path) + ".uploaded").touch()
            except OSError:
                pass
            logger.info("LogUploadQueue: uploaded %s", log_path.name)
        else:
            new_count = retry_count + 1
            self._write_retry_count(marker, new_count)
            backoff = self._backoff_for(new_count)
            logger.debug(
                "LogUploadQueue: upload failed for %s (attempt %d), next retry in %ds",
                log_path.name, new_count, backoff,
            )

    def _compress(self, log_path: Path) -> bytes:
        data = log_path.read_bytes()
        return gzip.compress(data, compresslevel=6)

    def _upload(self, filename: str, compressed: bytes) -> bool:
        """Two-step upload: get presigned URL, then PUT directly to R2."""
        token_state = self._get_token()
        if token_state is None:
            logger.debug("LogUploadQueue: no auth token, skipping upload")
            return False

        # Support both raw str token and AuthTokenState object
        token = token_state.token if hasattr(token_state, "token") else str(token_state)
        if not token:
            return False

        presign_url = self._get_upload_url()
        if not presign_url:
            logger.debug("LogUploadQueue: no upload URL configured, skipping")
            return False

        try:
            import requests
            # Step 1: request presigned URL
            resp = requests.post(
                presign_url,
                json={"filename": filename},
                headers={"Authorization": f"Bearer {token}"},
                timeout=20,
            )
            if resp.status_code < 200 or resp.status_code >= 300:
                logger.warning(
                    "LogUploadQueue: presign request failed HTTP %d for %s",
                    resp.status_code, filename,
                )
                return False

            data = resp.json()
            put_url = data["url"]
            put_headers = dict(data.get("headers") or {})
            put_headers.setdefault("Content-Type", "application/gzip")

            # Step 2: PUT directly to R2
            put_resp = requests.put(put_url, data=compressed, headers=put_headers, timeout=120)
            if put_resp.status_code < 200 or put_resp.status_code >= 300:
                logger.warning(
                    "LogUploadQueue: R2 PUT failed HTTP %d for %s",
                    put_resp.status_code, filename,
                )
                return False

            return True

        except Exception as e:
            logger.warning("LogUploadQueue: upload error for %s: %s", filename, e)
            return False
```

- [ ] **Step 2.4: Run tests and confirm pass**

```bash
python -m pytest tests/test_log_uploader.py::TestRegisterPending -v
```

Expected: all 3 tests PASS.

- [ ] **Step 2.5: Commit**

```bash
git add app/core/log_uploader.py tests/test_log_uploader.py
git commit -m "feat: add LogUploadQueue with register_pending atomic marker write"
```

---

### Task 3: `scan_orphans` — crash recovery

**Files:**
- Modify: `tests/test_log_uploader.py` (add new test class)

- [ ] **Step 3.1: Add failing tests**

Append to `tests/test_log_uploader.py`:

```python
class TestScanOrphans:
    # Fixtures use past dates (e.g. 2026-04-30) so _active_log_name()
    # (which returns today's AM/PM filename) never matches them.
    # This avoids date-sensitive test failures without mocking the clock.
    def _write_log(self, path: Path, content: str = "log") -> None:
        path.write_text(content)

    def test_creates_pending_for_untracked_log(self, tmp_path):
        """An untracked rotated log gets a .pending marker."""
        log = tmp_path / "app-2026-04-30-pm.log"
        self._write_log(log)

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert Path(str(log) + ".pending").exists()

    def test_skips_already_pending(self, tmp_path):
        """A log with an existing .pending marker is not re-registered."""
        log = tmp_path / "app-2026-04-30-pm.log"
        self._write_log(log)
        marker = Path(str(log) + ".pending")
        marker.write_text("3")  # 3 previous retries

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert marker.read_text().strip() == "3"  # count not reset

    def test_skips_uploaded_logs(self, tmp_path):
        """A log with .uploaded marker is skipped."""
        log = tmp_path / "app-2026-04-29-am.log"
        self._write_log(log)
        Path(str(log) + ".uploaded").touch()

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert not Path(str(log) + ".pending").exists()

    def test_skips_failed_logs(self, tmp_path):
        """A log with .failed marker is skipped."""
        log = tmp_path / "app-2026-04-29-am.log"
        self._write_log(log)
        Path(str(log) + ".failed").touch()

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert not Path(str(log) + ".pending").exists()

    def test_skips_non_log_files(self, tmp_path):
        """Files that don't match the log pattern are skipped."""
        junk = tmp_path / "config.json"
        junk.write_text("{}")

        q = _make_queue(tmp_path)
        q.scan_orphans()

        assert not Path(str(junk) + ".pending").exists()
```

- [ ] **Step 3.2: Run tests**

```bash
python -m pytest tests/test_log_uploader.py::TestScanOrphans -v
```

Expected: all 5 tests PASS (scan_orphans already implemented in Task 2).

> If any fail, fix `scan_orphans` in `app/core/log_uploader.py` — the `_active_log_name()` check may incorrectly match fixture log files. In tests, fixture log dates (e.g. `2026-04-30`) are old so `_active_log_name()` (today's date) won't match them. This is correct behavior.

- [ ] **Step 3.3: Commit**

```bash
git add tests/test_log_uploader.py
git commit -m "test: add scan_orphans tests for crash recovery"
```

---

### Task 4: Upload loop — missing `.log` file handling

**Files:**
- Modify: `tests/test_log_uploader.py`

- [ ] **Step 4.1: Add failing tests**

Append to `tests/test_log_uploader.py`:

```python
class TestHandleMarker:
    def test_removes_pending_when_log_missing(self, tmp_path):
        """If the .log file is gone, .pending is deleted and no upload is attempted."""
        # Create .pending marker but NOT the .log file
        log = tmp_path / "app-2026-04-28-am.log"
        marker = Path(str(log) + ".pending")
        marker.write_text("0")

        uploaded_calls = []
        q = _make_queue(tmp_path)
        q._upload = lambda name, data: uploaded_calls.append(name) or True

        q._handle_marker(marker)

        assert not marker.exists()           # .pending removed
        assert uploaded_calls == []          # upload never attempted

    def test_successful_upload_creates_uploaded_and_removes_pending(self, tmp_path):
        """Successful upload deletes .pending and creates .uploaded."""
        log = tmp_path / "app-2026-04-28-am.log"
        log.write_text("log line\n" * 100)
        marker = Path(str(log) + ".pending")
        marker.write_text("0")

        q = _make_queue(tmp_path)
        q._upload = lambda name, data: True  # mock success

        q._handle_marker(marker)

        assert not marker.exists()
        assert Path(str(log) + ".uploaded").exists()

    def test_failed_upload_increments_retry_count(self, tmp_path):
        """Failed upload increments the count stored in .pending."""
        log = tmp_path / "app-2026-04-28-am.log"
        log.write_text("data")
        marker = Path(str(log) + ".pending")
        marker.write_text("2")

        q = _make_queue(tmp_path)
        q._upload = lambda name, data: False  # mock failure

        q._handle_marker(marker)

        assert marker.exists()
        assert marker.read_text().strip() == "3"

    def test_compressed_data_is_valid_gzip(self, tmp_path):
        """Data passed to _upload is valid gzip content."""
        log = tmp_path / "app-2026-04-28-am.log"
        original = b"log line\n" * 50
        log.write_bytes(original)
        marker = Path(str(log) + ".pending")
        marker.write_text("0")

        received = []
        q = _make_queue(tmp_path)
        q._upload = lambda name, data: received.append(data) or True

        q._handle_marker(marker)

        assert len(received) == 1
        assert gzip.decompress(received[0]) == original
```

- [ ] **Step 4.2: Run tests**

```bash
python -m pytest tests/test_log_uploader.py::TestHandleMarker -v
```

Expected: all 4 tests PASS (implementation already covers this in Task 2 code).

- [ ] **Step 4.3: Commit**

```bash
git add tests/test_log_uploader.py
git commit -m "test: add handle_marker tests (missing log, success, retry increment, gzip)"
```

---

### Task 5: `_upload` — presign + R2 PUT

**Files:**
- Modify: `tests/test_log_uploader.py`

- [ ] **Step 5.1: Add failing tests**

Append to `tests/test_log_uploader.py`:

```python
class TestUpload:
    def _make_token_state(self, token="tok"):
        state = MagicMock()
        state.token = token
        return state

    def test_returns_false_when_no_token(self, tmp_path):
        q = _make_queue(tmp_path, get_token=lambda: None)
        assert q._upload("app-2026-05-01-am.log", b"data") is False

    def test_returns_false_when_no_url(self, tmp_path):
        q = _make_queue(tmp_path, get_url=lambda: "")
        assert q._upload("app-2026-05-01-am.log", b"data") is False

    def test_two_step_upload_success(self, tmp_path):
        """Happy path: presign returns URL, PUT succeeds."""
        state = self._make_token_state("mytoken")
        q = _make_queue(tmp_path, get_token=lambda: state)

        presign_resp = MagicMock()
        presign_resp.status_code = 200
        presign_resp.json.return_value = {
            "url": "https://r2.example.com/put-here",
            "method": "PUT",
            "headers": {"Content-Type": "application/gzip"},
        }

        put_resp = MagicMock()
        put_resp.status_code = 200

        with patch("requests.post", return_value=presign_resp) as mock_post, \
             patch("requests.put", return_value=put_resp) as mock_put:
            result = q._upload("app-2026-05-01-am.log", b"\x1f\x8b\x08data")

        assert result is True
        mock_post.assert_called_once()
        post_args = mock_post.call_args
        assert post_args.kwargs["json"] == {"filename": "app-2026-05-01-am.log"}
        assert "Bearer mytoken" in post_args.kwargs["headers"]["Authorization"]

        mock_put.assert_called_once()
        put_args = mock_put.call_args
        assert put_args.kwargs["data"] == b"\x1f\x8b\x08data"

    def test_returns_false_on_presign_http_error(self, tmp_path):
        state = self._make_token_state()
        q = _make_queue(tmp_path, get_token=lambda: state)

        presign_resp = MagicMock()
        presign_resp.status_code = 500

        with patch("requests.post", return_value=presign_resp):
            result = q._upload("app-2026-05-01-am.log", b"data")

        assert result is False

    def test_returns_false_on_r2_put_error(self, tmp_path):
        state = self._make_token_state()
        q = _make_queue(tmp_path, get_token=lambda: state)

        presign_resp = MagicMock()
        presign_resp.status_code = 200
        presign_resp.json.return_value = {"url": "https://r2.example.com/x", "headers": {}}

        put_resp = MagicMock()
        put_resp.status_code = 403

        with patch("requests.post", return_value=presign_resp), \
             patch("requests.put", return_value=put_resp):
            result = q._upload("app-2026-05-01-am.log", b"data")

        assert result is False

    def test_returns_false_on_network_exception(self, tmp_path):
        state = self._make_token_state()
        q = _make_queue(tmp_path, get_token=lambda: state)

        with patch("requests.post", side_effect=ConnectionError("offline")):
            result = q._upload("app-2026-05-01-am.log", b"data")

        assert result is False

    def test_accepts_plain_string_token(self, tmp_path):
        """get_token may return a plain string instead of AuthTokenState."""
        q = _make_queue(tmp_path, get_token=lambda: "plain-token")

        presign_resp = MagicMock()
        presign_resp.status_code = 200
        presign_resp.json.return_value = {"url": "https://r2.example.com/x", "headers": {}}

        put_resp = MagicMock()
        put_resp.status_code = 200

        with patch("requests.post", return_value=presign_resp), \
             patch("requests.put", return_value=put_resp):
            result = q._upload("app-2026-05-01-am.log", b"data")

        assert result is True
```

- [ ] **Step 5.2: Run tests**

```bash
python -m pytest tests/test_log_uploader.py::TestUpload -v
```

Expected: all 7 tests PASS.

- [ ] **Step 5.3: Commit**

```bash
git add tests/test_log_uploader.py
git commit -m "test: add _upload tests (presign flow, error cases, token formats)"
```

---

### Task 6: Fix `_cleanup_old_logs` — skip `.log` with `.pending` sibling

**Files:**
- Modify: `app/core/logger.py`
- Modify: `tests/test_logger_rotation_hook.py`

- [ ] **Step 6.1: Add failing tests**

Append to `tests/test_logger_rotation_hook.py`:

```python
class TestCleanupSkipsPending:
    def test_does_not_delete_log_with_pending_sibling(self, tmp_path):
        """_cleanup_old_logs must not delete a .log that has a .pending marker."""
        import datetime as dt
        from app.core.logger import HalfDaySizeRotatingFileHandler

        h = HalfDaySizeRotatingFileHandler(tmp_path, retention_days=1)

        # Create an old log file (will be within cleanup window)
        old_log = tmp_path / "app-2020-01-01-am.log"
        old_log.write_text("old log")
        pending = Path(str(old_log) + ".pending")
        pending.write_text("2")

        # Run cleanup for today's date (cutoff = yesterday → 2020-01-01 is old)
        today = dt.date.today()
        h._cleanup_old_logs(today)

        assert old_log.exists(), "log with .pending sibling must NOT be deleted"
        assert pending.exists()
        h.close()

    def test_deletes_log_without_pending_sibling(self, tmp_path):
        """_cleanup_old_logs DOES delete old .log files with no .pending."""
        import datetime as dt
        from app.core.logger import HalfDaySizeRotatingFileHandler

        h = HalfDaySizeRotatingFileHandler(tmp_path, retention_days=1)

        old_log = tmp_path / "app-2020-01-01-am.log"
        old_log.write_text("old log")

        today = dt.date.today()
        h._cleanup_old_logs(today)

        assert not old_log.exists(), "old log without .pending should be deleted"
        h.close()

    def test_cleans_up_stale_uploaded_markers(self, tmp_path):
        """_cleanup_old_logs removes .uploaded markers older than 30 days."""
        import datetime as dt
        from app.core.logger import HalfDaySizeRotatingFileHandler

        h = HalfDaySizeRotatingFileHandler(tmp_path, retention_days=1)

        old_uploaded = tmp_path / "app-2020-01-01-am.log.uploaded"
        old_uploaded.touch()

        today = dt.date.today()
        h._cleanup_old_logs(today)

        assert not old_uploaded.exists()
        h.close()
```

- [ ] **Step 6.2: Run tests to confirm first test fails**

```bash
python -m pytest tests/test_logger_rotation_hook.py::TestCleanupSkipsPending -v
```

Expected: `test_does_not_delete_log_with_pending_sibling` FAILS (current code deletes it).

- [ ] **Step 6.3: Fix `_cleanup_old_logs` in `app/core/logger.py`**

Replace the existing `_cleanup_old_logs` method:

```python
_STALE_MARKER_CUTOFF_DAYS = 30

def _cleanup_old_logs(self, today: dt.date) -> None:
    cutoff = today - dt.timedelta(days=self.retention_days - 1)
    stale_cutoff = today - dt.timedelta(days=_STALE_MARKER_CUTOFF_DAYS)

    for path in self.log_dir.iterdir():
        if not path.is_file():
            continue

        # Clean up stale .uploaded and .failed markers (30-day retention)
        if path.suffix in (".uploaded", ".failed"):
            stem = path.stem  # e.g. "app-2020-01-01-am.log"
            m = _LOG_FILE_RE.match(stem)
            if m:
                try:
                    log_date = dt.date.fromisoformat(m.group(1))
                    if log_date < stale_cutoff:
                        path.unlink(missing_ok=True)
                except (ValueError, OSError):
                    pass
            continue

        # Only delete .log files matched by the pattern
        match = _LOG_FILE_RE.match(path.name)
        if not match:
            continue
        try:
            log_date = dt.date.fromisoformat(match.group(1))
        except ValueError:
            continue
        if log_date >= cutoff:
            continue

        # Skip if a .pending sibling exists (upload not yet done)
        if Path(str(path) + ".pending").exists():
            continue

        try:
            path.unlink()
        except OSError:
            continue
```

Also add the constant at module level near the top:
```python
_STALE_MARKER_CUTOFF_DAYS = 30
```

- [ ] **Step 6.4: Run tests**

```bash
python -m pytest tests/test_logger_rotation_hook.py -v
```

Expected: all tests PASS.

- [ ] **Step 6.5: Commit**

```bash
git add app/core/logger.py tests/test_logger_rotation_hook.py
git commit -m "feat: skip .log deletion when .pending sibling exists; clean stale markers"
```

---

### Task 7: Add `log_presign_url` to `ApiEndpoints`

The `LogUploadQueue` makes HTTP calls directly via `requests` — it does not use `MonClubApi`. Adding `upload_log_file` to `MonClubApi` would create a dead parallel implementation that drifts. Only the URL field is added here so it appears in the endpoints config alongside other URLs.

**Files:**
- Modify: `app/api/monclub_api.py`

- [ ] **Step 7.1: Add `log_presign_url` to `ApiEndpoints`**

In `app/api/monclub_api.py`, inside the `ApiEndpoints` dataclass, add:

```python
log_presign_url: str = ""
```

Place it after `optional_content_sync_url` for consistency with other optional URL fields.

- [ ] **Step 7.2: Run the full test suite to check for regressions**

```bash
python -m pytest tests/ -v --ignore=tests/test_log_uploader.py --ignore=tests/test_logger_rotation_hook.py -x -q 2>&1 | tail -20
```

Expected: no new failures.

- [ ] **Step 7.3: Commit**

```bash
git add app/api/monclub_api.py
git commit -m "feat: add log_presign_url to ApiEndpoints"
```

---

### Task 8: Add `log_presign_url` to `AppConfig`

**Files:**
- Modify: `app/core/config.py`

- [ ] **Step 8.1: Add the field**

In `AppConfig` dataclass, add after `log_level`:

```python
# -------------------------
# Log upload
# -------------------------
log_presign_url: str = ""
```

No changes needed to `from_dict` or `to_dict` — the generic loop at line 411-417 handles new string fields automatically.

- [ ] **Step 8.2: Verify config round-trip**

```bash
python -c "
from app.core.config import AppConfig
cfg = AppConfig(log_presign_url='https://example.com/presign')
d = cfg.to_dict()
cfg2 = AppConfig.from_dict(d)
assert cfg2.log_presign_url == 'https://example.com/presign', cfg2.log_presign_url
print('OK')
"
```

Expected: `OK`

- [ ] **Step 8.3: Commit**

```bash
git add app/core/config.py
git commit -m "feat: add log_presign_url to AppConfig"
```

---

### Task 9: Wire `LogUploadQueue` in `app/ui/app.py`

**Files:**
- Modify: `app/ui/app.py`

- [ ] **Step 9.1: Add `LOG_DIR` import at the top of `app/ui/app.py`**

`LOG_DIR` is NOT currently imported in `app/ui/app.py`. Add it to the existing `app.core.utils` import block near the top of the file. Find the line that imports from `app.core.utils` (or add a new import):

```python
from app.core.utils import LOG_DIR
```

Note: `load_auth_token` is already imported at line 41 via `from access.store import (..., load_auth_token, ...)` — do NOT add a second import of it.

- [ ] **Step 9.2: Add wiring after `setup_logging` call**

In `app/ui/app.py`, locate the line:
```python
self.logger = setup_logging(self.cfg.log_level, ui_queue=self.log_queue)
```

**Immediately after it**, add:

```python
# --- Log upload queue (marker-file based, daemon thread) ---
try:
    from app.core.log_uploader import LogUploadQueue
    from app.core.logger import HalfDaySizeRotatingFileHandler
    # load_auth_token already imported from access.store at top of file

    self._log_upload_queue = LogUploadQueue(
        log_dir=LOG_DIR,
        get_token=load_auth_token,          # imported from access.store line 41
        get_upload_url=lambda: (self.cfg.log_presign_url or "").strip(),
    )
    # Wire the callback into the rotating file handler
    for _h in self.logger.handlers:
        if isinstance(_h, HalfDaySizeRotatingFileHandler):
            _h.on_log_rotated = self._log_upload_queue.register_pending
            break
    self._log_upload_queue.scan_orphans()
    self._log_upload_queue.start()
    self.logger.info("Log upload queue started (presign_url=%s)", bool(self.cfg.log_presign_url))
except Exception as _lue:
    # Never crash startup due to upload system
    self.logger.warning("Log upload queue failed to start: %s", _lue)
```

- [ ] **Step 9.3: Verify imports are resolvable**

```bash
python -c "
from app.core.log_uploader import LogUploadQueue
from app.core.logger import HalfDaySizeRotatingFileHandler
from app.core.utils import LOG_DIR
print('All imports OK')
"
```

Expected: `All imports OK`

- [ ] **Step 9.4: Run full test suite**

```bash
python -m pytest tests/ -x -q 2>&1 | tail -20
```

Expected: no failures.

- [ ] **Step 9.5: Commit**

```bash
git add app/ui/app.py
git commit -m "feat: wire LogUploadQueue into MonClubApp startup"
```

---

## Part 2: Backend (Spring Boot)

---

### Task 10: `AccessLogUploadController.java` — presign endpoint

**Files:**
- Create: `src/main/java/com/tpjava/tpjava/Controllers/AccessLogUploadController.java`

> **Note:** The backend is Java/Spring Boot. There is no TDD step here — write the implementation directly. The existing test suite covers security configuration.

- [ ] **Step 10.1: Create the controller**

Create `src/main/java/com/tpjava/tpjava/Controllers/AccessLogUploadController.java`:

```java
package com.tpjava.tpjava.Controllers;

import com.tpjava.tpjava.AppConstants;
import com.tpjava.tpjava.Configuration.JwtService;
import com.tpjava.tpjava.Models.Enumurations.FileVisibility;
import com.tpjava.tpjava.Services.media.ObjectStorageService;
import com.tpjava.tpjava.Services.media.MediaProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Issues presigned R2 upload URLs for MonClub Access log files.
 *
 * Route: POST /api/v1/gym/access/logs/presign
 * Security: /api/v1/gym/** → Role.GYM + Role.ADMIN (SecurityConfiguration, no changes needed)
 *
 * The client compresses the log file with gzip, then PUTs the bytes directly
 * to R2 using the presigned URL. This controller never receives the file bytes.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping(AppConstants.API_BASE_URL + "/gym/access/logs")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class AccessLogUploadController {

    // Matches: app-2026-05-01-am.log  or  app-2026-05-01-am.1.log
    private static final Pattern LOG_FILENAME_PATTERN =
            Pattern.compile("^app-\\d{4}-\\d{2}-\\d{2}-(am|pm)(\\.\\d+)?\\.log$");

    // R2 presigned URL TTL in minutes
    private static final int PRESIGN_TTL_MINUTES = 30;

    private final ObjectStorageService objectStorageService;
    private final MediaProperties mediaProperties;
    private final JwtService jwtService;

    @Data
    static class PresignRequest {
        @NotBlank
        private String filename;
    }

    /**
     * POST /api/v1/gym/access/logs/presign
     *
     * Body: {"filename": "app-2026-05-01-am.log"}
     *
     * Returns presigned PUT URL for the client to upload gzip-compressed log directly to R2.
     */
    @PostMapping("/presign")
    public ResponseEntity<?> presignLogUpload(
            @RequestBody PresignRequest body,
            HttpServletRequest request
    ) {
        String filename = (body.getFilename() == null) ? "" : body.getFilename().trim();

        // Validate filename (prevents path traversal and garbage)
        if (!LOG_FILENAME_PATTERN.matcher(filename).matches()) {
            return ResponseEntity.badRequest().body(
                    Map.of("error", "Invalid log filename: " + filename)
            );
        }

        // Extract gymId from JWT
        Long gymId = extractGymId(request);
        if (gymId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Cannot resolve gymId from token"));
        }

        // Extract year from filename for R2 key partitioning
        // filename format: app-YYYY-MM-DD-am.log
        String year = filename.substring(4, 8);  // "app-" is 4 chars

        // R2 key: access-logs/{gymId}/{year}/{filename}.gz
        String objectKey = String.format("access-logs/%d/%s/%s.gz", gymId, year, filename);

        String bucket = mediaProperties.getBucket();

        try {
            ObjectStorageService.PresignedUpload presigned = objectStorageService.createPresignedPut(
                    bucket,
                    objectKey,
                    "application/gzip",
                    FileVisibility.PRIVATE,
                    PRESIGN_TTL_MINUTES
            );

            return ResponseEntity.ok(Map.of(
                    "url", presigned.url(),
                    "method", presigned.method(),
                    "headers", presigned.headers(),
                    "expiresAt", presigned.expiresAt().toString(),
                    "objectKey", objectKey
            ));

        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(
                    Map.of("error", "Failed to generate presigned URL: " + e.getMessage())
            );
        }
    }

    private Long extractGymId(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) return null;
            String token = authHeader.substring(7);
            String gymIdStr = jwtService.extractClaim(token, claims -> {
                Object v = claims.get("gymId");
                return v != null ? v.toString() : null;
            });
            if (gymIdStr == null) return null;
            return Long.parseLong(gymIdStr.trim());
        } catch (Exception e) {
            return null;
        }
    }
}
```

- [ ] **Step 10.2: Check `MediaProperties` has `getBucket()`**

```bash
grep -n "getBucket\|bucket" /d/projects/MonClub/monclub_backend/src/main/java/com/tpjava/tpjava/Services/media/MediaProperties.java | head -10
```

If `getBucket()` doesn't exist or the bucket name is stored differently, adjust accordingly. The existing `R2ObjectStorageService` uses `mediaProperties` already — look at how it accesses the bucket name there and copy the same pattern.

- [ ] **Step 10.3: Check `JwtService.extractClaim` and `gymId` claim name**

```bash
grep -n "extractClaim\|gymId\|gym_id" /d/projects/MonClub/monclub_backend/src/main/java/com/tpjava/tpjava/Configuration/JwtService.java | head -15
grep -n "gymId\|gym_id" /d/projects/MonClub/monclub_backend/src/main/java/com/tpjava/tpjava/Configuration/SecurityConfiguration.java | head -10
```

The claim name `"gymId"` is confirmed in `SecurityConfiguration.java` line 120. Adjust the `extractClaim` call signature to match what `JwtService` actually exposes (it may use a `Function<Claims, T>` lambda).

- [ ] **Step 10.4: Build the backend**

```bash
cd /d/projects/MonClub/monclub_backend
./mvnw compile -q 2>&1 | tail -30
```

Expected: `BUILD SUCCESS` (or equivalent for Gradle). Fix any compile errors before continuing.

- [ ] **Step 10.5: Commit**

```bash
cd /d/projects/MonClub/monclub_backend
git add src/main/java/com/tpjava/tpjava/Controllers/AccessLogUploadController.java
git commit -m "feat: add AccessLogUploadController — presigned R2 URL for log uploads"
```

---

## End-to-end smoke test (manual)

After both sides are deployed:

1. Configure `log_presign_url` in the gym's `config.json`:
   ```json
   {"log_presign_url": "https://api.monclub.app/api/v1/gym/access/logs/presign"}
   ```

2. Start MonClub Access. Check logs:
   ```
   Log upload queue started (presign_url=True)
   ```

3. Trigger a time rotation manually by temporarily setting `now_func` in a dev build to return PM when it's AM (or just wait until noon/midnight).

4. Check that `{logfile}.pending` is created, then within 60s: deleted and `{logfile}.uploaded` appears.

5. Check the R2 bucket under `access-logs/{gymId}/{year}/` for the uploaded `.log.gz` file.

---

## Full test run

```bash
cd /c/Users/mohaa/Desktop/monclub_access_python
python -m pytest tests/test_log_uploader.py tests/test_logger_rotation_hook.py -v
```

All tests must pass before declaring done.
