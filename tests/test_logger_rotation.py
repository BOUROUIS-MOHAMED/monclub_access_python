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

    assert (tmp_path / "app-2026-04-27-am.1.log").exists()
    assert (tmp_path / "app-2026-04-27-am.1.log").read_text(encoding="utf-8").strip() == "1234567890"
    assert (tmp_path / "app-2026-04-27-am.log").read_text(encoding="utf-8").strip() == "abc"


def test_handler_uses_next_available_suffix(tmp_path):
    current = dt.datetime(2026, 4, 27, 9, 15)
    (tmp_path / "app-2026-04-27-am.1.log").write_text("old", encoding="utf-8")
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

    assert (tmp_path / "app-2026-04-27-am.1.log").read_text(encoding="utf-8") == "old"
    assert (tmp_path / "app-2026-04-27-am.2.log").read_text(encoding="utf-8").strip() == "1234567890"
    assert (tmp_path / "app-2026-04-27-am.log").read_text(encoding="utf-8").strip() == "abc"


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
