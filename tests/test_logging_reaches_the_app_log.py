"""What reaches the app log (2026-10-02).

Two losses, both proven on the dev PC before the fix and confirmed by 30 h of gym 45 logs
(1.4.35: DISK_SELFTEST and WAL_CHECKPOINT_STARTUP 0 times over 4 starts):

* ``MainApp.__init__`` ran ``init_db`` before ``setup_logging``, so every line ``init_db`` logged
  -- its telemetry and the stale-lock resets -- was written while no handler existed.
* The handlers sit on the "zkapp" logger only. The 34 modules that log under
  ``logging.getLogger(__name__)`` ("app.*", "access.*", "shared.*") and the "db" / driver loggers
  had none: their warnings went to stderr, which a windowed PC never shows.
"""
from __future__ import annotations

import glob
import logging
import os
from types import SimpleNamespace

import pytest

from app.core import logger as logger_mod


@pytest.fixture
def isolated_logging(monkeypatch, tmp_path):
    """setup_logging mutates process-wide loggers: save and restore every one it touches."""
    monkeypatch.setattr(logger_mod, "LOG_DIR", tmp_path)
    monkeypatch.setattr(logger_mod, "ensure_dirs", lambda: None)
    from app.core import crash_capture

    monkeypatch.setattr(crash_capture, "report_previous", lambda lg: None)
    names = ("zkapp",) + tuple(logger_mod.OWN_PACKAGE_LOGGERS)
    saved = {}
    for n in names:
        lg = logging.getLogger(n)
        saved[n] = (list(lg.handlers), lg.level, lg.propagate, lg.__dict__.get("_monclub_handlers_attached"))
        lg.handlers = []
        lg.__dict__.pop("_monclub_handlers_attached", None)
        # setup_logging leaves "zkapp" propagate=False; pytest then attaches its capture handler to
        # every non-propagating logger when the call phase starts, and setup_logging, seeing a
        # handler, returns early. Start each test from a propagating logger, as a fresh process does.
        lg.propagate = True
    yield tmp_path
    for n in names:
        lg = logging.getLogger(n)
        for h in lg.handlers:
            if h not in saved[n][0]:
                try:
                    h.close()
                except Exception:
                    pass
        lg.handlers, lg.level, lg.propagate = saved[n][0], saved[n][1], saved[n][2]
        if saved[n][3] is None:
            lg.__dict__.pop("_monclub_handlers_attached", None)
        else:
            lg._monclub_handlers_attached = saved[n][3]


def _log_text(folder) -> str:
    for h in logging.getLogger("zkapp").handlers:
        try:
            h.flush()
        except Exception:
            pass
    return "".join(
        open(f, encoding="utf-8", errors="replace").read()
        for f in glob.glob(os.path.join(str(folder), "**", "*.log"), recursive=True)
    )


def test_own_module_warnings_reach_the_file_once_and_their_info_stays_out(isolated_logging):
    logger_mod.setup_logging("DEBUG")

    logging.getLogger("app.api.local_access_api_v2").warning("PROBE_NAME_WARNING")
    logging.getLogger("app.api.local_access_api_v2").info("PROBE_NAME_INFO")
    logging.getLogger("access.pc_identity").error("PROBE_ACCESS_ERROR")
    logging.getLogger("db").warning("PROBE_DB_WARNING")
    logging.getLogger("PullSDKDevice").warning("PROBE_DRIVER_WARNING")
    logging.getLogger("zkapp.telemetry").info("PROBE_TELEMETRY_INFO")

    text = _log_text(isolated_logging)
    for probe in ("PROBE_NAME_WARNING", "PROBE_ACCESS_ERROR", "PROBE_DB_WARNING",
                  "PROBE_DRIVER_WARNING", "PROBE_TELEMETRY_INFO"):
        assert text.count(probe) == 1, probe
    assert "PROBE_NAME_INFO" not in text


def test_a_second_setup_attaches_nothing_twice(isolated_logging):
    logger_mod.setup_logging("DEBUG")
    counts = {n: len(logging.getLogger(n).handlers) for n in logger_mod.OWN_PACKAGE_LOGGERS}
    logger_mod.setup_logging("DEBUG")
    logger_mod._attach_own_package_loggers(logging.getLogger("zkapp").handlers)
    assert counts == {n: len(logging.getLogger(n).handlers) for n in logger_mod.OWN_PACKAGE_LOGGERS}

    logging.getLogger("db").warning("PROBE_ONCE")
    assert _log_text(isolated_logging).count("PROBE_ONCE") == 1


def test_a_logger_set_quieter_on_purpose_keeps_its_level(isolated_logging):
    logging.getLogger("settings_reader").setLevel(logging.ERROR)
    logger_mod.setup_logging("DEBUG")
    assert logging.getLogger("settings_reader").level == logging.ERROR


class _StopAfterInitDb(Exception):
    pass


def test_main_app_sets_up_logging_before_init_db(monkeypatch):
    import app.ui.app as app_module

    order: list[str] = []
    cfg = SimpleNamespace(plcomm_dll_path="C:/sdk/plcommpro.dll", zkfp_dll_path="C:/sdk/libzkfp.dll",
                          log_level="INFO", log_presign_url="")
    monkeypatch.setattr(app_module, "add_windows_dll_search_paths", lambda: None)
    monkeypatch.setattr(app_module, "ensure_dirs", lambda: None)
    monkeypatch.setattr(app_module, "load_access_app_config", lambda: order.append("config") or cfg)
    monkeypatch.setattr(app_module, "setup_logging",
                        lambda *a, **k: order.append("setup_logging") or logging.getLogger("zkapp.test"))

    def fake_init_db():
        order.append("init_db")
        raise _StopAfterInitDb

    monkeypatch.setattr(app_module, "init_db", fake_init_db)
    with pytest.raises(_StopAfterInitDb):
        app_module.MainApp()
    assert order == ["config", "setup_logging", "init_db"]


def test_init_db_telemetry_reaches_the_file_once_logging_is_up(isolated_logging, monkeypatch):
    """The two init_db diagnostics log through zkapp.telemetry; with the handler in place first
    they land in the file (they did not, in any gym log, before)."""
    from app.core import db

    monkeypatch.setattr(db, "_resolve_db_path", lambda: os.path.join(str(isolated_logging), "probe.db"))
    logger_mod.setup_logging("DEBUG")
    db.disk_selftest(mb=1)
    assert "[T] DISK_SELFTEST " in _log_text(isolated_logging)
