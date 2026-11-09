"""Suite-wide safety net: no test may open the default Access database.

With ``app.core.db._DB_PATH`` left at ``None``, every ``get_conn()`` resolves to
``<data root>/access/access.db`` -- and the default data root is
``C:\\ProgramData\\MonClub Access``, i.e. the *installed* gym database on any PC that has
the app. A per-file sweep (guide §9) found 34 test files reaching it through unpatched
db calls, several of them writing (``access_history``, ``sync_devices``,
``push_batch_history``, ``sync_run_history``, and ``init_db()`` migrations).

These fixtures point ``_DB_PATH`` at one temp file for the whole session. The design is
deliberate:

* Session-scoped, set before any module- or function-scoped fixture runs: four files
  run ``init_db()`` in a module-scoped fixture, which would execute before a
  function-scoped override; and background threads (the db writer, the sync-cache
  loader, the popup prefetch) outlive single tests, so the path is never reverted to
  ``None`` -- not even at session end.
* Re-applied around every test: several fixtures ``importlib.reload(app.core.db)``,
  which re-executes ``_DB_PATH = None``; their ``monkeypatch`` then restores *that*
  ``None`` at teardown. Without the re-apply, every later test would open the default
  database again.
* Created empty (no ``init_db()`` here), so a file run alone still fails on an unpatched
  read of a missing table. In a full-suite run this does NOT hold: four files call
  ``init_db()`` from a module-scoped fixture without their own override, which migrates
  this shared file early in the session. The per-file sweep in guide §9 is what keeps
  such reads detectable. Tests that need a schema still patch ``_DB_PATH`` to their own
  ``tmp_path`` and call ``init_db()``; their ``monkeypatch`` wins for the test and
  reverts to this path afterwards.

Two more session guards follow the same rules (session-scoped, never reverted), for
files outside ``data/`` that the per-file sweep found under the data root:

* Split config. The first config read in a process runs
  ``shared.config.migrate_split_config_if_needed``, which calls ``ensure_dirs()`` and
  writes default ``access/config.json``, ``tv/config.json`` and ``shared/install.json``
  when they are missing -- on a gym PC, into the installed app's folder. The config paths
  are read from ``shared.desktop_paths`` module globals at call time, so repointing those
  globals redirects every layout user.
* Popup image cache. An allow event with a member image calls
  ``popup_image_cache.prefetch``, whose pool thread did a real ``requests.get`` against
  the production backend (sending the stored bearer token when one exists) and cached the
  reply under ``access/cache/images``. The cache dir is repointed and ``requests`` is
  replaced by a stub that refuses; ``fetch_and_cache`` treats that like any fetch error,
  so a blocked prefetch also puts its URL in the module's negative cache (transient
  backoff). Tests that exercise the fetch still ``patch.object(pic, "requests")``
  themselves and clear that cache.

This file guards only what is collected under ``tests/``.
"""
from __future__ import annotations

import pytest


def _apply_suite_db_path(path: str) -> None:
    from app.core import db

    if db._DB_PATH is None:
        db._DB_PATH = path


@pytest.fixture(scope="session")
def _suite_db_path(tmp_path_factory) -> str:
    return str(tmp_path_factory.mktemp("suite-default-db") / "access.db")


@pytest.fixture(scope="session", autouse=True)
def _never_open_the_default_access_db(_suite_db_path):
    _apply_suite_db_path(_suite_db_path)
    yield


@pytest.fixture(autouse=True)
def _reapply_suite_db_path_after_reload(_suite_db_path):
    _apply_suite_db_path(_suite_db_path)
    yield
    _apply_suite_db_path(_suite_db_path)


@pytest.fixture(autouse=True)
def _never_a_real_data_root_dialog_or_icacls(monkeypatch):
    # shared/data_root_permissions.py: a test that reaches access/tv main() must never block the
    # run on a real MessageBoxW, nor run icacls on this PC (its real ProgramData root may be the
    # read-only one, 2026-10-17). Tests that need these replace them themselves.
    import shared.data_root_permissions as drp

    def _no_dialog(title, text):
        raise AssertionError("a test reached the real data-root MessageBoxW: " + title)

    def _no_icacls(*a, **k):
        raise AssertionError("a test reached the real icacls repair")

    monkeypatch.setattr(drp, "show_error_dialog", _no_dialog)
    monkeypatch.setattr(drp, "repair_data_root_acl", _no_icacls)
    yield


@pytest.fixture(autouse=True)
def _fresh_zkem_replay_memory():
    # Process-wide per-turnstile memory (app/core/zkem_rtlog_filter.py): one test's events
    # must never read as another test's replays.
    import app.core.zkem_rtlog_filter as zkem_rtlog
    zkem_rtlog.reset_for_tests()
    yield


@pytest.fixture(scope="session", autouse=True)
def _never_write_the_default_config(tmp_path_factory):
    import shared.config as shared_config
    import shared.desktop_paths as desktop_paths

    root = tmp_path_factory.mktemp("suite-config-root")
    desktop_paths.CONFIG_PATH = root / "data" / "config.json"  # legacy, read-only here
    desktop_paths.ACCESS_CONFIG_PATH = root / "access" / "config.json"
    desktop_paths.TV_CONFIG_PATH = root / "tv" / "config.json"
    desktop_paths.SHARED_INSTALL_CONFIG_PATH = root / "shared" / "install.json"
    # The migration's ensure_dirs() only creates data-root folders (save_json makes the
    # parents it needs) and would copy a legacy ./data folder into the data root.
    shared_config.ensure_dirs = lambda: None
    # Defensive: re-arm the one-shot guard in case something ran the migration while test
    # modules were imported. Not observed -- it is still False after collecting the suite.
    shared_config._MIGRATION_DONE = False
    yield


class _NoNetworkRequests:
    """Stand-in for ``requests`` in popup_image_cache: tests never reach the backend."""

    def get(self, url, *args, **kwargs):
        raise RuntimeError(f"tests/conftest.py: popup image fetch of {url!r} blocked")


@pytest.fixture(scope="session", autouse=True)
def _never_fetch_or_cache_popup_images_in_the_data_root(tmp_path_factory):
    import app.core.popup_image_cache as pic

    pic._cache_dir_cached = str(tmp_path_factory.mktemp("suite-popup-images"))
    pic.requests = _NoNetworkRequests()
    yield


# --------------------------------------------------------------------------------------------
# Parallel runs (pytest-xdist, `-n N --dist loadgroup`, used by build_release.ps1).
#
# These files start real PowerShell scripts or look at machine-wide state (every running
# process, a global lock, the data-root ACL). Run at the same time they see each other:
# the watchdog script treats any process named monclub_access_<x> as "an installer is
# running" and stands down, while the updater tests start fake Setups with exactly that
# name; the install helper in turn sees the other tests' Setups and answers 22 instead of
# 20 (measured 2026-11-09: 5 failures at -n 8, all in these files; all pass serially).
# One xdist group = one worker, one file after another; the rest of the suite fills the
# other workers. Without xdist the marker is inert.
# --------------------------------------------------------------------------------------------
_MACHINE_WIDE_TEST_FILES = frozenset({
    # Only the files that actually collide (measured 2026-11-09): the watchdog script and the
    # updater scripts look at every running process; the updater tests start fake Setups.
    # Other files that start PowerShell ran in parallel cleanly and stay out of the group,
    # which is the slowest chain of the run.
    "test_watchdog_script.py",
    "test_updater_v2_files_and_wrapper.py",
    "test_updater_v2_installer_scripts.py",
    "test_updater_v2_install_helper.py",
    "test_updater_v2_startup_journal.py",
    "test_updater_v2_user_rollback.py",
    "test_updater_v2_watchdog_journal.py",
})


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "xdist_group(name): run every test of the group on one xdist worker"
    )


# tryfirst: xdist's own collection hook turns the marker into the scheduling group; when ours
# ran after it, the marker was ignored and the files spread over several workers.
@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.path.name in _MACHINE_WIDE_TEST_FILES:
            item.add_marker(pytest.mark.xdist_group("machine_wide"))


@pytest.fixture(autouse=True)
def _fresh_refused_info_cache(monkeypatch):
    """Every test starts with the refused-entry switch read fresh (not cached).

    ``refused_info.is_enabled()`` caches the switch in a module global; a test that turned it on
    left ``_enabled = True`` for every later test in the same process. Which test ran later
    changed with the parallel scheduling: test_ultra_engine's deny-path test then got
    DENY_NO_CARD_MATCH instead of DEVICE_DENIED (2026-11-09, -n 8). Tests that need the switch
    on still set it themselves (test_refused_info_resolve's autouse fixture runs after this one).
    """
    try:
        from app.core import refused_info
    except Exception:
        yield
        return
    monkeypatch.setattr(refused_info, "_enabled", None, raising=False)
    monkeypatch.setattr(refused_info, "_index", None, raising=False)
    yield
