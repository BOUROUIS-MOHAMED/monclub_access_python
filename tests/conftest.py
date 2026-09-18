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
* Left empty (no ``init_db()`` here): a pre-migrated shared file would hide unpatched
  reads that only pass against an already-migrated database. Tests that need a schema
  still patch ``_DB_PATH`` to their own ``tmp_path`` and call ``init_db()``; their
  ``monkeypatch`` wins for the test and reverts to this path afterwards.
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
