# AM/PM Log Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace generic `app.log` size backups with AM/PM dated log files, 50 MB chunk rotation, and 7-day retention.

**Architecture:** Add a focused custom logging handler in `app/core/logger.py` that selects the active file from the current local date and AM/PM period. The handler rotates the active file to the next numeric suffix at the configured size and deletes only new-pattern files older than the retention window. Existing console and Tk queue logging stay unchanged.

**Tech Stack:** Python 3.11, standard `logging`, `pathlib`, `datetime`, `pytest`.

---

## File Structure

- Modify `app/core/logger.py`: replace the current `RotatingFileHandler` usage with a custom `HalfDaySizeRotatingFileHandler`.
- Create `tests/test_logger_rotation.py`: unit tests for filename selection, period switching, size rotation, retention cleanup, and legacy-file safety.

## Constants

- Max bytes: `50 * 1024 * 1024`
- Retention days: `7`
- Filename format: `app-YYYY-MM-DD-am.log`, `app-YYYY-MM-DD-pm.log`, and suffixed chunks `app-YYYY-MM-DD-am.1.log`

---

### Task 1: Add Failing Tests

**Files:**
- Create: `tests/test_logger_rotation.py`

- [ ] **Step 1: Write tests for the desired handler behavior**

Use an injectable `now_func` so tests can force AM/PM and retention dates:

```python
from __future__ import annotations

import datetime as dt
import logging

from app.core.logger import HalfDaySizeRotatingFileHandler


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_handler_writes_to_am_and_pm_files(tmp_path):
    current = dt.datetime(2026, 4, 27, 9, 15)
    handler = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=1024,
        retention_days=7,
        now_func=lambda: current,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record("morning"))
    current = dt.datetime(2026, 4, 27, 14, 30)
    handler.emit(_record("afternoon"))
    handler.close()

    assert (tmp_path / "app-2026-04-27-am.log").read_text(encoding="utf-8").strip() == "morning"
    assert (tmp_path / "app-2026-04-27-pm.log").read_text(encoding="utf-8").strip() == "afternoon"
```

- [ ] **Step 2: Add size rotation and retention tests**

```python
def test_handler_rotates_current_period_by_size(tmp_path):
    current = dt.datetime(2026, 4, 27, 9, 15)
    handler = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=10,
        retention_days=7,
        now_func=lambda: current,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record("1234567890"))
    handler.emit(_record("abc"))
    handler.close()

    assert (tmp_path / "app-2026-04-27-am.1.log").exists()
    assert (tmp_path / "app-2026-04-27-am.log").read_text(encoding="utf-8").strip() == "abc"


def test_handler_uses_next_available_suffix(tmp_path):
    current = dt.datetime(2026, 4, 27, 9, 15)
    (tmp_path / "app-2026-04-27-am.1.log").write_text("old", encoding="utf-8")
    handler = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=10,
        retention_days=7,
        now_func=lambda: current,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record("1234567890"))
    handler.emit(_record("abc"))
    handler.close()

    assert (tmp_path / "app-2026-04-27-am.1.log").read_text(encoding="utf-8") == "old"
    assert (tmp_path / "app-2026-04-27-am.2.log").exists()
```

- [ ] **Step 3: Add cleanup safety tests**

```python
def test_handler_cleanup_keeps_last_7_days_and_legacy_logs(tmp_path):
    current = dt.datetime(2026, 4, 27, 9, 15)
    stale = tmp_path / "app-2026-04-20-am.log"
    keep_boundary = tmp_path / "app-2026-04-21-pm.1.log"
    legacy = tmp_path / "app.log.1"
    unrelated = tmp_path / "notes-2026-04-19-am.log"
    for path in (stale, keep_boundary, legacy, unrelated):
        path.write_text("x", encoding="utf-8")

    handler = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=1024,
        retention_days=7,
        now_func=lambda: current,
    )
    handler.close()

    assert not stale.exists()
    assert keep_boundary.exists()
    assert legacy.exists()
    assert unrelated.exists()
```

- [ ] **Step 4: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/test_logger_rotation.py -q
```

Expected: import failure because `HalfDaySizeRotatingFileHandler` does not exist yet.

---

### Task 2: Implement Handler

**Files:**
- Modify: `app/core/logger.py`

- [ ] **Step 1: Add imports and constants**

```python
import datetime as dt
import os
import re
```

Add:

```python
LOG_MAX_BYTES = 50 * 1024 * 1024
LOG_RETENTION_DAYS = 7
_LOG_FILE_RE = re.compile(r"^app-(\d{4}-\d{2}-\d{2})-(am|pm)(?:\.(\d+))?\.log$")
```

- [ ] **Step 2: Add `HalfDaySizeRotatingFileHandler`**

Implement a handler that:

- Accepts `log_dir`, `max_bytes`, `retention_days`, and optional `now_func`.
- Builds active names from `now_func()`.
- Switches files when date/period changes.
- Before writing a record, rotates if current active file plus formatted record would exceed `max_bytes`.
- Moves the active file to the first missing suffix.
- Deletes only files matching `_LOG_FILE_RE` whose parsed date is older than `today - (retention_days - 1)`.

- [ ] **Step 3: Wire into `setup_logging()`**

Replace:

```python
file_handler = RotatingFileHandler(str(log_path), maxBytes=5_000_000, backupCount=5, encoding="utf-8")
```

with:

```python
file_handler = HalfDaySizeRotatingFileHandler(LOG_DIR)
```

Keep formatter, level, console handler, and Tk queue handler behavior unchanged.

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```powershell
python -m pytest tests/test_logger_rotation.py -q
```

Expected: all tests pass.

---

### Task 3: Regression Checks

**Files:**
- Verify: `app/core/logger.py`
- Verify: `tests/test_logger_rotation.py`

- [ ] **Step 1: Run targeted logger tests**

```powershell
python -m pytest tests/test_logger_rotation.py -q
```

Expected: all tests pass.

- [ ] **Step 2: Run a focused import/compile check**

```powershell
python -m py_compile app/core/logger.py tests/test_logger_rotation.py
```

Expected: exit code 0.

- [ ] **Step 3: Review diff**

```powershell
git diff -- app/core/logger.py tests/test_logger_rotation.py docs/superpowers/plans/2026-04-27-am-pm-log-rotation.md
```

Expected: only the logger, logger tests, and this plan changed for this feature.
