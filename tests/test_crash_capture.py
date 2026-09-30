"""A process that ends without "App shutting down" leaves evidence in the next start's app log.

Field, 2026-09-30 07:50 (gym PC "Accueil", 1.4.35): the log stopped mid-cadence, a new process
started 17 s later on the same Windows boot, and nothing said why. Crashes are exercised in a
SUBPROCESS: pytest owns faulthandler in this process.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from app.core import crash_capture

ROOT = Path(__file__).resolve().parents[1]


def _run(code: str, state_dir: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    prelude = textwrap.dedent(f"""
        import logging, sys
        from pathlib import Path
        from app.core import crash_capture
        STATE = Path({str(state_dir)!r})
        log = logging.getLogger("zkapp")
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        log.addHandler(h)
        log.setLevel(logging.DEBUG)
    """)
    return subprocess.run(
        [sys.executable, "-c", prelude + textwrap.dedent(code)],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120,
    )


def test_a_native_crash_is_reported_at_the_next_start_with_its_dump(tmp_path):
    crashed = _run("""
        crash_capture.install(STATE)
        import faulthandler
        faulthandler._sigsegv()
    """, tmp_path)
    assert crashed.returncode != 0

    nxt = _run("""
        crash_capture.install(STATE)
        crash_capture.report_previous(log)
    """, tmp_path)

    out = nxt.stdout
    assert "ERROR [CRASH] previous run" in out, out + nxt.stderr
    assert "ended WITHOUT a clean exit while Windows kept running" in out
    assert "Segmentation fault" in out or "access violation" in out, out
    assert "_sigsegv" in out or "<string>" in out  # the Python stack of the crashing thread


def test_a_clean_exit_reports_nothing_at_the_next_start(tmp_path):
    first = _run("""
        crash_capture.install(STATE)
        log.info("working")
    """, tmp_path)
    assert first.returncode == 0, first.stderr
    assert "[CRASH] interpreter exiting normally" in first.stdout

    nxt = _run("""
        crash_capture.install(STATE)
        crash_capture.report_previous(log)
    """, tmp_path)
    assert "[CRASH] previous run" not in nxt.stdout


def test_the_report_is_written_once(tmp_path):
    _run("crash_capture.install(STATE)\nimport os\nos._exit(3)\n", tmp_path)
    nxt = _run("""
        crash_capture.install(STATE)
        crash_capture.report_previous(log)
        crash_capture.report_previous(log)
    """, tmp_path)
    assert nxt.stdout.count("[CRASH] previous run") == 1, nxt.stdout
    assert "no faulthandler output" in nxt.stdout


def test_an_unhandled_thread_exception_reaches_the_app_log(tmp_path):
    res = _run("""
        crash_capture.install(STATE)
        import threading
        def boom():
            raise RuntimeError("thread blew up")
        t = threading.Thread(target=boom, name="worker-x")
        t.start(); t.join()
    """, tmp_path)
    assert "ERROR [CRASH] unhandled exception in thread worker-x" in res.stdout, res.stdout
    assert "RuntimeError: thread blew up" in res.stdout


def test_a_marker_from_another_boot_says_windows_restarted(tmp_path):
    wall, mono = time.time(), 5000.0
    (tmp_path / "running.json").write_text(json.dumps({
        "pid": 1, "started": "2026-09-30 13:00:00",
        "boot_epoch": wall - mono - 3600,  # a boot one hour earlier than this one
    }), encoding="utf-8")

    level, message = crash_capture.previous_run_report(tmp_path, wall=wall, mono=mono)

    assert level == logging.INFO  # no dump: the daily power-off at most gyms, not an alarm
    assert "Windows has restarted since" in message


def test_no_marker_no_report(tmp_path):
    assert crash_capture.previous_run_report(tmp_path, wall=time.time(), mono=1.0) is None


def test_setup_logging_reports_the_previous_run_once_its_handlers_exist(monkeypatch, tmp_path):
    from app.core import logger as logger_mod

    # The real file handler prunes old logs in LOG_DIR: never the installed app's folder.
    monkeypatch.setattr(logger_mod, "LOG_DIR", tmp_path)
    monkeypatch.setattr(logger_mod, "ensure_dirs", lambda: None)
    seen: list[int] = []
    monkeypatch.setattr(crash_capture, "report_previous",
                        lambda lg: seen.append(len(lg.handlers)))
    zk = logging.getLogger("zkapp")
    saved = list(zk.handlers)
    zk.handlers = []
    try:
        logger_mod.setup_logging("DEBUG")
        added = [h for h in zk.handlers if h not in saved]
    finally:
        for h in zk.handlers:
            if h not in saved:
                h.close()
        zk.handlers = saved
    assert seen == [len(added)] and len(added) >= 2  # the file handler is in place first


def test_access_main_installs_the_capture_after_the_single_instance_guard(monkeypatch):
    import faulthandler

    import access.bootstrap
    import access.main as access_main
    import shared.dev_dependency_sync
    import shared.single_instance

    order: list[str] = []

    class _Guard:
        def release(self):
            order.append("release")

    monkeypatch.setattr(faulthandler, "enable", lambda *a, **k: None)
    monkeypatch.setattr(shared.dev_dependency_sync, "ensure_local_requirements_synced",
                        lambda **k: None)
    monkeypatch.setattr(shared.single_instance, "acquire_single_instance_guard",
                        lambda **k: order.append("guard") or _Guard())
    monkeypatch.setattr(crash_capture, "install", lambda *a, **k: order.append("install") or True)
    monkeypatch.setattr(access.bootstrap, "run_access_app", lambda: order.append("run"))

    access_main.main()

    assert order == ["guard", "install", "run", "release"]
