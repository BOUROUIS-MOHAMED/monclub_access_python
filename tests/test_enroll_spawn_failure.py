"""A failed enrol-worker spawn must not wedge enrolment for the life of the process.

``begin_remote_enroll`` sets ``_enroll_running = True`` under ``_enroll_state_lock``
and then starts ``_remote_enroll_worker`` on a daemon thread. The ONLY place that
clears the flag is that worker's ``finally``.

So if ``Thread.start()`` raises -- ``RuntimeError: can't start new thread``, the
Type-2 resource-exhaustion failure this codebase already instruments in
``ultra_engine._poll_with_watchdog`` and ``zk_standalone._ensure_sta_thread`` -- the
worker never runs, its ``finally`` never runs, and the flag stays True forever. Every
later enrolment then answers ``409 Enroll already running on this PC`` until someone
restarts the app.

That is plausible on the 4 GB gym PC: ``PROC_HB`` there reported 24 threads at
``sys_mem_load=89`` with ``sys_avail_mb=406``.

These tests pin the reset. They deliberately assert on the FLAG and on the ability to
start a SECOND enrolment afterwards -- asserting only on the returned dict would pass
against the pre-fix code, since the caller already gets an exception-shaped failure.
"""

from __future__ import annotations

import logging
import threading
from types import SimpleNamespace

import pytest


def _main_app():
    try:
        from app.ui.app import MainApp
    except Exception as e:  # heavy module (Tkinter/scanner) -- fine to skip
        pytest.skip(f"MainApp import unavailable: {e}")
    return MainApp


def _self_obj():
    """The minimal MainApp surface begin_remote_enroll actually touches."""
    return SimpleNamespace(
        logger=logging.getLogger("test-enroll-spawn"),
        _enroll_state_lock=threading.Lock(),
        _enroll_running=False,
        _enroll_cancel_event=threading.Event(),
        _remote_enroll_worker=lambda *a, **kw: None,
    )


def _begin(self_obj, **kw):
    MainApp = _main_app()
    params = {"user_id": "35", "finger_id": "0", "full_name": "Member",
              "device": "zk9500"}
    params.update(kw)
    return MainApp.begin_remote_enroll(self_obj, **params)


class _ExplodingThread:
    """Stands in for threading.Thread and fails the way an exhausted PC does."""

    def __init__(self, *a, **kw):
        pass

    def start(self):
        raise RuntimeError("can't start new thread")


class TestSpawnFailureReleasesTheEnrollFlag:
    def test_flag_is_cleared_when_the_worker_thread_cannot_start(self, monkeypatch):
        import app.ui.app as app_module

        self_obj = _self_obj()
        monkeypatch.setattr(app_module.threading, "Thread", _ExplodingThread)

        res = _begin(self_obj)

        assert res["ok"] is False
        assert self_obj._enroll_running is False, (
            "_enroll_running stayed True after a failed spawn -- every later enrolment "
            "will answer 409 until the app is restarted"
        )

    def test_a_later_enrolment_is_not_blocked_by_the_failed_one(self, monkeypatch):
        """The behaviour that actually matters to the gym: try again and it works."""
        import app.ui.app as app_module

        self_obj = _self_obj()

        monkeypatch.setattr(app_module.threading, "Thread", _ExplodingThread)
        first = _begin(self_obj)
        assert first["ok"] is False

        started: list = []

        class _OkThread:
            def __init__(self, *a, **kw):
                self._kw = kw

            def start(self):
                started.append(self._kw)

        monkeypatch.setattr(app_module.threading, "Thread", _OkThread)
        second = _begin(self_obj)

        assert second["ok"] is True, (
            f"the retry was refused after a failed spawn: {second!r}"
        )
        assert len(started) == 1
        assert self_obj._enroll_running is True   # the real worker now owns the reset

    def test_failure_is_reported_as_503_with_the_enroll_id(self, monkeypatch):
        """Resource exhaustion is a server-state problem, not a bad request."""
        import app.ui.app as app_module

        self_obj = _self_obj()
        monkeypatch.setattr(app_module.threading, "Thread", _ExplodingThread)

        res = _begin(self_obj)

        assert res["status"] == 503
        assert "enrollId" in res and res["enrollId"]
        assert "restart" in res["error"].lower()

    def test_spawn_failure_is_reported_to_telemetry(self, monkeypatch):
        """Matches the two other Thread.start() sites, so a field lockup names itself."""
        import app.ui.app as app_module

        self_obj = _self_obj()
        seen: list = []
        monkeypatch.setattr(app_module.threading, "Thread", _ExplodingThread)
        monkeypatch.setattr(
            app_module._tel, "thread_spawn_failure",
            lambda where, **f: seen.append((where, f)),
        )

        _begin(self_obj)

        assert len(seen) == 1, "no THREAD_SPAWN_FAILURE emitted"
        where, fields = seen[0]
        assert where == "app.begin_remote_enroll"
        assert fields.get("user_id") == 35
        assert fields.get("finger_id") == 0


class TestGuardStillWorks:
    """The 409 must still fire for a genuinely concurrent enrolment."""

    def test_concurrent_enrolment_is_still_refused(self, monkeypatch):
        import app.ui.app as app_module

        self_obj = _self_obj()

        class _OkThread:
            def __init__(self, *a, **kw):
                pass

            def start(self):
                pass

        monkeypatch.setattr(app_module.threading, "Thread", _OkThread)

        first = _begin(self_obj)
        assert first["ok"] is True

        second = _begin(self_obj)
        assert second["ok"] is False
        assert second["status"] == 409
