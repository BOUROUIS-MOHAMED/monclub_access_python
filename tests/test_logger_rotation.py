from __future__ import annotations

import datetime as dt
import logging

from app.core.logger import (
    HalfDaySizeRotatingFileHandler,
    active_log_name_for,
    window_bounds_for_hour,
    window_label_for,
)


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


def test_window_bounds_for_hour_covers_every_hour():
    expected = {
        0: (0, 3), 1: (0, 3), 2: (0, 3),
        3: (3, 6), 4: (3, 6), 5: (3, 6),
        6: (6, 8), 7: (6, 8),
        8: (8, 9), 9: (9, 10), 10: (10, 11), 11: (11, 12),
        12: (12, 13), 13: (13, 14), 14: (14, 15), 15: (15, 16),
        16: (16, 17), 17: (17, 18), 18: (18, 19), 19: (19, 20),
        20: (20, 21), 21: (21, 22), 22: (22, 23), 23: (23, 24),
    }
    for hour in range(24):
        assert window_bounds_for_hour(hour) == expected[hour], hour


def test_window_label_and_active_name_are_zero_padded():
    assert window_label_for(dt.datetime(2026, 4, 27, 8, 5)) == "from-08-to-09"
    assert window_label_for(dt.datetime(2026, 4, 27, 23, 59)) == "from-23-to-24"
    assert active_log_name_for(dt.datetime(2026, 4, 27, 8, 5)) == "app-2026-04-27-from-08-to-09.log"


def test_handler_writes_to_separate_window_files(tmp_path):
    current = dt.datetime(2026, 4, 27, 9, 15)
    handler = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=1024,
        retention_days=7,
        now_func=lambda: current,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record("nine"))
    current = dt.datetime(2026, 4, 27, 14, 30)
    handler.emit(_record("fourteen"))
    handler.close()

    assert (tmp_path / "app-2026-04-27-from-09-to-10.log").read_text(encoding="utf-8").strip() == "nine"
    assert (tmp_path / "app-2026-04-27-from-14-to-15.log").read_text(encoding="utf-8").strip() == "fourteen"


def test_handler_finalizes_file_when_crossing_hourly_boundary(tmp_path):
    """Crossing into the next hourly window closes the prior file and opens a new one."""
    current = dt.datetime(2026, 4, 27, 9, 50)
    finalized: list[str] = []
    handler = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=1024,
        retention_days=7,
        now_func=lambda: current,
        on_log_rotated=lambda p: finalized.append(p.name),
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record("before"))
    current = dt.datetime(2026, 4, 27, 10, 5)  # one hour later -> next window
    handler.emit(_record("after"))
    handler.close()

    # The 09-10 file was finalized (and thus queued for upload) at the boundary.
    assert finalized == ["app-2026-04-27-from-09-to-10.log"]
    assert (tmp_path / "app-2026-04-27-from-09-to-10.log").read_text(encoding="utf-8").strip() == "before"
    assert (tmp_path / "app-2026-04-27-from-10-to-11.log").read_text(encoding="utf-8").strip() == "after"


def test_handler_rotates_current_period_by_size(tmp_path):
    current = dt.datetime(2026, 4, 27, 9, 15)
    handler = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=12,
        retention_days=7,
        now_func=lambda: current,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record("1234567890"))
    handler.emit(_record("abc"))
    handler.close()

    assert (tmp_path / "app-2026-04-27-from-09-to-10.1.log").exists()
    assert (tmp_path / "app-2026-04-27-from-09-to-10.1.log").read_text(encoding="utf-8").strip() == "1234567890"
    assert (tmp_path / "app-2026-04-27-from-09-to-10.log").read_text(encoding="utf-8").strip() == "abc"


def test_handler_uses_next_available_suffix(tmp_path):
    current = dt.datetime(2026, 4, 27, 9, 15)
    (tmp_path / "app-2026-04-27-from-09-to-10.1.log").write_text("old", encoding="utf-8")
    handler = HalfDaySizeRotatingFileHandler(
        tmp_path,
        max_bytes=12,
        retention_days=7,
        now_func=lambda: current,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    handler.emit(_record("1234567890"))
    handler.emit(_record("abc"))
    handler.close()

    assert (tmp_path / "app-2026-04-27-from-09-to-10.1.log").read_text(encoding="utf-8") == "old"
    assert (tmp_path / "app-2026-04-27-from-09-to-10.2.log").read_text(encoding="utf-8").strip() == "1234567890"
    assert (tmp_path / "app-2026-04-27-from-09-to-10.log").read_text(encoding="utf-8").strip() == "abc"


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
