"""Design section 12 (owner decision O7): the watchdog's status and on/off switch in Settings.

``access/watchdog_control.py`` reads the per-user scheduled task 'MonClub Access Watchdog'
(through a hidden, time-bounded PowerShell) and the watchdog's own files under
``{app}\\logs`` (``watchdog-state.json``, ``watchdog.log``), and turns the task on or off
with Enable-/Disable-ScheduledTask -- registering it first, through the installed
``{app}\\watchdog\\register_watchdog.ps1``, when it is missing. It never unregisters it.

Nothing here reaches the real Task Scheduler except ``TestRealPowerShell``, which only
READS a task name that does not exist.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from access import watchdog_control as wc

NOW = 1_800_000_000.0  # a fixed "now" (epoch seconds)


class FakeRunner:
    """Stands in for PowerShell: records every call, answers from a queue."""

    def __init__(self, *answers: Any):
        self.calls: list[dict] = []
        self.answers = list(answers)

    def __call__(self, args, timeout):
        self.calls.append({"args": list(args), "timeout": timeout})
        answer = self.answers.pop(0) if self.answers else (0, "{}", "")
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, dict):
            return 0, json.dumps(answer), ""
        return answer

    def scripts(self) -> list[str]:
        out = []
        for c in self.calls:
            if "-Command" in c["args"]:
                out.append(c["args"][c["args"].index("-Command") + 1])
            else:
                out.append(" ".join(c["args"]))
        return out


def task_json(**over: Any) -> dict:
    base = {
        "registered": True,
        "taskPath": "\\",
        "state": "Ready",
        "settingsEnabled": True,
        "lastRunAt": int(NOW - 60),
        "nextRunAt": int(NOW + 60),
        "lastTaskResult": 0,
        "intervals": ["PT2M", "PT2M"],
        "execute": r"C:\WINDOWS\System32\wscript.exe",
        "arguments": (r'//B //Nologo "C:\Users\gym\AppData\Local\MonClubAccess\watchdog\monclub_access_watchdog_hidden.vbs" '
                      r'"C:\Users\gym\AppData\Local\MonClubAccess\watchdog\monclub_access_watchdog.ps1" '
                      r'-InstallRoot "C:\Users\gym\AppData\Local\MonClubAccess"'),
    }
    base.update(over)
    return base


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    r = tmp_path / "MonClubAccess"
    (r / "watchdog").mkdir(parents=True)
    (r / "logs").mkdir()
    (r / "current").mkdir()
    (r / "watchdog" / "register_watchdog.ps1").write_text("# stand-in\n", encoding="utf-8")
    return r


def control(root: Path | None, runner: FakeRunner, *, setup_running: bool = False) -> wc.WatchdogControl:
    return wc.WatchdogControl(
        install_root=root,
        runner=runner,
        now=lambda: NOW,
        setup_running=lambda: setup_running,
        cache_sec=0,
    )


def write_bom_utf8(path: Path, text: str) -> None:
    # Windows PowerShell 5.1 "-Encoding UTF8" writes a BOM.
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))


def local_stamp(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


# ----------------------------------------------------------------- status: the task


class TestTaskStatus:
    def test_an_enabled_task(self, root: Path):
        s = control(root, FakeRunner(task_json())).status()
        assert s["registered"] is True and s["enabled"] is True
        assert s["state"] == "Ready"
        assert s["intervalMinutes"] == 2
        assert s["lastRunAt"] == wc.iso_utc(NOW - 60)
        assert s["nextRunAt"] == wc.iso_utc(NOW + 60)
        assert s["lastResult"] == "ok" and s["lastResultCode"] == 0
        assert s["scriptPath"] == r"C:\Users\gym\AppData\Local\MonClubAccess\watchdog\monclub_access_watchdog.ps1"
        assert s["lastError"] is None
        assert s["available"] is True

    def test_a_disabled_task_caught_mid_check_reads_off(self, root: Path):
        """TASK_STATE_DISABLED means "disabled and nothing running": a disabled task whose
        check runs reads 'Running'. Enabled is the definition's (register_watchdog.ps1's
        Test-WatchdogTaskDisabled rule)."""
        s = control(root, FakeRunner(task_json(state="Running", settingsEnabled=False))).status()
        assert s["enabled"] is False
        s = control(root, FakeRunner(task_json(state="Disabled", settingsEnabled=True))).status()
        assert s["enabled"] is False

    def test_a_missing_task(self, root: Path):
        s = control(root, FakeRunner({"registered": False})).status()
        assert s["registered"] is False and s["enabled"] is False
        assert s["state"] is None and s["lastRunAt"] is None and s["intervalMinutes"] is None
        assert s["lastError"] is None

    def test_a_task_that_never_ran(self, root: Path):
        s = control(root, FakeRunner(task_json(lastRunAt=None, lastTaskResult=267011))).status()
        assert s["lastRunAt"] is None
        assert s["lastResult"] == "not_run_yet"

    @pytest.mark.parametrize("code,expected", [(267009, "running"), (267045, "running"),
                                                (267014, "failed"), (1, "failed"), (2147942402, "failed")])
    def test_task_result_codes(self, root: Path, code: int, expected: str):
        s = control(root, FakeRunner(task_json(lastTaskResult=code))).status()
        assert s["lastResult"] == expected and s["lastResultCode"] == code

    def test_powershell_timing_out_is_an_error_not_a_hang(self, root: Path):
        runner = FakeRunner(subprocess.TimeoutExpired(cmd="powershell", timeout=20))
        s = control(root, runner).status()
        assert s["registered"] is None and s["enabled"] is None
        assert "timed out" in s["lastError"]
        assert runner.calls[0]["timeout"] == wc.STATUS_TIMEOUT_SEC

    def test_a_query_error_is_reported(self, root: Path):
        s = control(root, FakeRunner({"error": "Accès refusé"})).status()
        assert s["registered"] is None
        assert s["lastError"] == "Accès refusé"

    def test_unparseable_output_is_an_error(self, root: Path):
        s = control(root, FakeRunner((0, "not json", "boom"))).status()
        assert s["registered"] is None and s["lastError"]

    def test_the_query_never_changes_a_task(self, root: Path):
        runner = FakeRunner(task_json())
        control(root, runner).status()
        script = runner.scripts()[0]
        for verb in ("Unregister-ScheduledTask", "Register-ScheduledTask", "Enable-ScheduledTask",
                     "Disable-ScheduledTask", "Set-ScheduledTask", "Start-ScheduledTask"):
            assert verb not in script, verb
        assert wc.TASK_NAME in script

    def test_a_short_cache_avoids_a_powershell_per_request(self, root: Path):
        runner = FakeRunner(task_json(), task_json(state="Running"))
        c = wc.WatchdogControl(install_root=root, runner=runner, now=lambda: NOW,
                               setup_running=lambda: False, cache_sec=10)
        assert c.status()["state"] == "Ready"
        assert c.status()["state"] == "Ready"
        assert len(runner.calls) == 1


# ----------------------------------------------------------------- status: the watchdog's files


class TestWatchdogFiles:
    def test_restarts_in_the_last_hour_are_counted(self, root: Path):
        stamps = [int(NOW - 4000), int(NOW - 3000), int(NOW - 60)]
        write_bom_utf8(root / "logs" / "watchdog-state.json",
                       json.dumps({"misses": 0, "missAt": 0, "restarts": stamps}))
        s = control(root, FakeRunner(task_json())).status()
        assert s["restartsLastHour"] == 2
        assert s["stoodDown"] is False and s["stoodDownReason"] is None

    def test_five_restarts_in_an_hour_is_a_stand_down(self, root: Path):
        """monclub_access_watchdog.ps1: MaxRestartsPerWindow 5 / RateWindowMinutes 60 --
        past that it will not start Access again until the window rolls over."""
        stamps = [int(NOW - 3000 + i * 100) for i in range(5)]
        write_bom_utf8(root / "logs" / "watchdog-state.json",
                       json.dumps({"misses": 0, "missAt": 0, "restarts": stamps}))
        s = control(root, FakeRunner(task_json())).status()
        assert s["restartsLastHour"] == 5
        assert s["stoodDown"] is True
        assert "5" in s["stoodDownReason"]

    def test_a_refusal_whose_restarts_have_aged_out_is_over(self, root: Path):
        """Review #1: 5 restarts 10:00-10:05, refusal logged at 10:50; at 11:03 fewer than 5 are
        inside the hour, so the watchdog WOULD restart Access again -- not stood down any more."""
        stamps = [int(NOW - 3780 + i * 120) for i in range(5)]  # 2 of them older than an hour
        write_bom_utf8(root / "logs" / "watchdog-state.json",
                       json.dumps({"misses": 2, "missAt": int(NOW - 120), "restarts": stamps}))
        write_bom_utf8(root / "logs" / "watchdog.log", (
            f"{local_stamp(NOW - 780)} | ERROR | app is down but it has already been restarted 5 time(s) "
            f"in the last 60 min -- NOT restarting again. This build is crash-looping and needs a human.\n"))
        s = control(root, FakeRunner(task_json())).status()
        assert s["restartsLastHour"] == 3
        assert s["stoodDown"] is False

    def test_the_stand_down_ends_when_the_fifth_newest_restart_is_an_hour_old(self, root: Path):
        stamps = [int(NOW - 3000), int(NOW - 2000), int(NOW - 1000), int(NOW - 500), int(NOW - 100),
                  int(NOW - 50)]
        write_bom_utf8(root / "logs" / "watchdog-state.json", json.dumps({"restarts": stamps}))
        s = control(root, FakeRunner(task_json())).status()
        assert s["stoodDown"] is True
        assert wc.iso_utc(NOW - 2000 + 3600) in s["stoodDownReason"]

    def test_a_corrupt_state_file_counts_nothing(self, root: Path):
        (root / "logs" / "watchdog-state.json").write_text("{not json", encoding="utf-8")
        s = control(root, FakeRunner(task_json())).status()
        assert s["restartsLastHour"] == 0 and s["stoodDown"] is False

    def test_legacy_iso_restart_stamps_are_not_counted(self, root: Path):
        """The watchdog dropped ISO date strings (culture bug); so does the reader."""
        write_bom_utf8(root / "logs" / "watchdog-state.json",
                       json.dumps({"restarts": ["09/11/2026 10:35:26", int(NOW - 10)]}))
        s = control(root, FakeRunner(task_json())).status()
        assert s["restartsLastHour"] == 1

    def test_the_last_log_line_is_reported(self, root: Path):
        write_bom_utf8(root / "logs" / "watchdog.log", (
            f"{local_stamp(NOW - 900)} | INFO | app not running (miss 1/2) -- will confirm next tick\n"
            f"{local_stamp(NOW - 30)} | WARN | app is not running and no install/update is in progress -- starting X\n"
            f"{local_stamp(NOW - 30)} | INFO | restart issued\n\n"))
        s = control(root, FakeRunner(task_json(lastRunAt=int(NOW - 40)))).status()
        entry = s["lastLogEntry"]
        assert entry["level"] == "INFO" and entry["message"] == "restart issued"
        assert entry["at"] == wc.iso_utc(NOW - 30)
        assert entry["fromLastCheck"] is True

    def test_a_log_line_older_than_the_last_check_is_not_its_result(self, root: Path):
        write_bom_utf8(root / "logs" / "watchdog.log",
                       f"{local_stamp(NOW - 3600)} | INFO | restart issued\n")
        s = control(root, FakeRunner(task_json(lastRunAt=int(NOW - 60)))).status()
        assert s["lastLogEntry"]["fromLastCheck"] is False

    def test_an_unparseable_log_stamp_is_kept_as_text(self, root: Path):
        """Get-Date -Format follows the PC's calendar (the L2 #7 Hijri trap)."""
        write_bom_utf8(root / "logs" / "watchdog.log", "1448-04-18 10:00:00x | WARN | something\n")
        s = control(root, FakeRunner(task_json())).status()
        assert s["lastLogEntry"]["at"] is None
        assert s["lastLogEntry"]["rawAt"] == "1448-04-18 10:00:00x"
        assert s["lastLogEntry"]["message"] == "something"

    def test_no_files_no_problem(self, root: Path):
        s = control(root, FakeRunner(task_json())).status()
        assert s["restartsLastHour"] == 0 and s["lastLogEntry"] is None and s["stoodDown"] is False

    def test_only_the_tail_of_a_big_log_is_read(self, root: Path):
        big = ("x" * 200 + "\n") * 20000 + f"{local_stamp(NOW - 5)} | INFO | last\n"
        (root / "logs" / "watchdog.log").write_text(big, encoding="utf-8")
        s = control(root, FakeRunner(task_json())).status()
        assert s["lastLogEntry"]["message"] == "last"


# ----------------------------------------------------------------- not an installed build


class TestNotInstalled:
    def test_dev_run_reads_the_task_but_not_the_install(self):
        """A source run must never act on %LOCALAPPDATA%\\MonClubAccess -- on the dev PC that
        is the real install."""
        runner = FakeRunner(task_json())
        s = control(None, runner).status()
        assert s["available"] is False and s["installRoot"] is None
        assert s["registered"] is True  # the read-only task query still runs
        assert s["restartsLastHour"] == 0

    def test_no_change_without_an_install(self):
        runner = FakeRunner()
        with pytest.raises(wc.WatchdogUnavailable):
            control(None, runner).set_enabled(False, actor="t")
        assert runner.calls == []

    def test_no_change_without_the_installed_register_script(self, root: Path):
        (root / "watchdog" / "register_watchdog.ps1").unlink()
        runner = FakeRunner()
        with pytest.raises(wc.WatchdogUnavailable):
            control(root, runner).set_enabled(True, actor="t")
        assert runner.calls == []

    def test_resolve_install_root_in_a_source_run(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(wc, "is_frozen", lambda: False)
        monkeypatch.delenv(wc.INSTALL_ROOT_ENV, raising=False)
        assert wc.resolve_install_root() is None
        monkeypatch.setenv(wc.INSTALL_ROOT_ENV, str(tmp_path))
        assert wc.resolve_install_root() == tmp_path

    def test_resolve_install_root_frozen_is_the_parent_of_current(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(wc, "is_frozen", lambda: True)
        monkeypatch.setattr(wc, "runtime_base_dir", lambda: tmp_path / "current")
        assert wc.resolve_install_root() == tmp_path


# ----------------------------------------------------------------- the switch


class TestSetEnabled:
    def test_turning_off_disables_never_unregisters(self, root: Path):
        runner = FakeRunner(task_json(), (0, "", ""), task_json(state="Disabled", settingsEnabled=False))
        s = control(root, runner).set_enabled(False, actor="owner@gym.tn")
        assert s["enabled"] is False
        scripts = runner.scripts()
        assert any("Disable-ScheduledTask" in x for x in scripts), scripts
        assert not any("Unregister-ScheduledTask" in x for x in scripts), scripts
        assert not any("register_watchdog.ps1" in x for x in scripts), scripts

    def test_turning_on_enables(self, root: Path):
        runner = FakeRunner(task_json(state="Disabled", settingsEnabled=False), (0, "", ""), task_json())
        s = control(root, runner).set_enabled(True, actor="owner@gym.tn")
        assert s["enabled"] is True
        assert any("Enable-ScheduledTask" in x for x in runner.scripts())

    def test_a_change_is_logged_with_who_made_it(self, root: Path):
        runner = FakeRunner(task_json(), (0, "", ""), task_json(state="Disabled", settingsEnabled=False))
        control(root, runner).set_enabled(False, actor="owner@gym.tn")
        log = (root / "logs" / "watchdog-register.log").read_text(encoding="utf-8-sig")
        assert "SETTINGS" in log and "owner@gym.tn" in log and "Disabled" in log, log

    def test_missing_and_turned_on_registers_it_enabled(self, root: Path):
        runner = FakeRunner({"registered": False}, (0, "registered", ""), task_json())
        s = control(root, runner).set_enabled(True, actor="t")
        assert s["enabled"] is True
        reg = runner.calls[1]
        assert reg["args"][0] == "-File"  # run_powershell adds powershell.exe -NoProfile ...
        assert str(root / "watchdog" / "register_watchdog.ps1") in reg["args"]
        assert reg["args"][reg["args"].index("-InstallRoot") + 1] == str(root)
        assert reg["args"][reg["args"].index("-WhenMissing") + 1] == "Enabled"
        assert reg["timeout"] == wc.REGISTER_TIMEOUT_SEC

    def test_missing_and_turned_off_registers_it_disabled(self, root: Path):
        runner = FakeRunner({"registered": False}, (0, "registered", ""),
                            task_json(state="Disabled", settingsEnabled=False))
        s = control(root, runner).set_enabled(False, actor="t")
        assert s["enabled"] is False
        reg = runner.calls[1]
        assert reg["args"][reg["args"].index("-WhenMissing") + 1] == "Disabled"

    def test_a_registration_that_lands_in_the_wrong_state_is_corrected(self, root: Path):
        runner = FakeRunner({"registered": False}, (0, "", ""), task_json(), (0, "", ""),
                            task_json(state="Disabled", settingsEnabled=False))
        s = control(root, runner).set_enabled(False, actor="t")
        assert s["enabled"] is False
        assert "Disable-ScheduledTask" in runner.scripts()[3]

    def test_a_failed_register_is_an_error(self, root: Path):
        runner = FakeRunner({"registered": False}, (1, "", "Registering failed"), {"registered": False})
        with pytest.raises(wc.WatchdogError) as e:
            control(root, runner).set_enabled(True, actor="t")
        assert "Registering failed" in str(e.value)

    def test_a_failed_enable_is_an_error(self, root: Path):
        runner = FakeRunner(task_json(state="Disabled", settingsEnabled=False), (1, "", "Accès refusé"),
                            task_json(state="Disabled", settingsEnabled=False))
        with pytest.raises(wc.WatchdogError) as e:
            control(root, runner).set_enabled(True, actor="t")
        assert "Accès refusé" in str(e.value)

    def test_a_change_that_did_not_take_is_an_error(self, root: Path):
        runner = FakeRunner(task_json(), (0, "", ""), task_json())
        with pytest.raises(wc.WatchdogError):
            control(root, runner).set_enabled(False, actor="t")

    def test_an_unknown_task_state_refuses_to_act(self, root: Path):
        runner = FakeRunner(subprocess.TimeoutExpired(cmd="powershell", timeout=20))
        with pytest.raises(wc.WatchdogError):
            control(root, runner).set_enabled(False, actor="t")
        assert len(runner.calls) == 1

    def test_refused_while_an_install_or_update_runs(self, root: Path):
        runner = FakeRunner()
        with pytest.raises(wc.WatchdogBusy):
            control(root, runner, setup_running=True).set_enabled(False, actor="t")
        assert runner.calls == []

    def test_refused_while_the_update_sentinel_is_fresh(self, root: Path):
        sentinel = root / ".update-in-progress"
        sentinel.write_text("x", encoding="utf-8")
        os.utime(sentinel, (NOW - 60, NOW - 60))
        runner = FakeRunner()
        with pytest.raises(wc.WatchdogBusy):
            control(root, runner).set_enabled(False, actor="t")
        assert runner.calls == []

    def test_a_stale_sentinel_does_not_block(self, root: Path):
        sentinel = root / ".update-in-progress"
        sentinel.write_text("x", encoding="utf-8")
        os.utime(sentinel, (NOW - 31 * 60, NOW - 31 * 60))
        runner = FakeRunner(task_json(), (0, "", ""), task_json(state="Disabled", settingsEnabled=False))
        assert control(root, runner).set_enabled(False, actor="t")["enabled"] is False

    def test_two_changes_at_once_the_second_is_busy(self, root: Path):
        c = control(root, FakeRunner())
        assert c._change_lock.acquire(blocking=False)
        try:
            with pytest.raises(wc.WatchdogBusy):
                c.set_enabled(False, actor="t")
        finally:
            c._change_lock.release()

    def test_a_read_that_started_before_a_change_does_not_overwrite_its_status(self, root: Path):
        """Review #5: GET misses the cache and runs its query; a POST finishes meanwhile; the
        GET's older answer must not become the cached status."""
        c = wc.WatchdogControl(install_root=root, runner=None, now=lambda: NOW,
                               setup_running=lambda: False, cache_sec=60)
        disabled = task_json(state="Disabled", settingsEnabled=False)
        answers = [disabled, (0, "", ""), task_json()]

        def runner(args, timeout):
            if not answers:
                return 0, json.dumps(disabled), ""
            a = answers.pop(0)
            return (0, json.dumps(a), "") if isinstance(a, dict) else a

        def slow_get_runner(args, timeout):
            # The GET's own query: while it "runs", a change turns the task on.
            c._runner = runner
            c.set_enabled(True, actor="t")
            return 0, json.dumps(disabled), ""

        c._runner = slow_get_runner
        stale = c.status()
        assert stale["enabled"] is False  # the GET itself answers what it read
        assert c.status()["enabled"] is True  # but the cache holds the change's status

    def test_a_change_drops_the_cached_status(self, root: Path):
        runner = FakeRunner(task_json(), task_json(), (0, "", ""),
                            task_json(state="Disabled", settingsEnabled=False))
        c = wc.WatchdogControl(install_root=root, runner=runner, now=lambda: NOW,
                               setup_running=lambda: False, cache_sec=60)
        c.status()
        c.set_enabled(False, actor="t")
        assert c.status()["enabled"] is False


# ----------------------------------------------------------------- PowerShell is hidden and bounded


class TestRunner:
    def test_powershell_runs_hidden_and_with_a_timeout(self, monkeypatch):
        seen: dict = {}

        def fake_run(args, **kw):
            seen["args"] = args
            seen.update(kw)
            return subprocess.CompletedProcess(args, 0, b'{"registered": false}', b"")

        monkeypatch.setattr(wc.subprocess, "run", fake_run)
        rc, out, err = wc.run_powershell(["-Command", "1"], timeout=7)
        assert rc == 0 and out == '{"registered": false}'
        assert seen["timeout"] == 7
        assert seen["stdin"] == subprocess.DEVNULL
        assert seen["capture_output"] is True
        if os.name == "nt":
            assert seen["creationflags"] & 0x08000000  # CREATE_NO_WINDOW
            si = seen["startupinfo"]
            assert si.dwFlags & subprocess.STARTF_USESHOWWINDOW and si.wShowWindow == 0
        assert seen["args"][0].lower().endswith("powershell.exe")
        assert "-NoProfile" in seen["args"] and "-NonInteractive" in seen["args"]


# ----------------------------------------------------------------- local API


class FakeHandler:
    def __init__(self):
        self.headers = {}


class FakeCtx:
    def __init__(self, app, body=None):
        self.app = app
        self._body = body
        self.sent: list[tuple[int, dict]] = []
        self.handler = FakeHandler()

    def body(self):
        return self._body

    def send_json(self, code, payload):
        self.sent.append((code, payload))


class FakeLogger:
    def __init__(self):
        self.lines: list[str] = []

    def info(self, msg, *a):
        self.lines.append(msg % a if a else msg)

    warning = error = exception = debug = info


class FakeApp:
    def __init__(self, control_obj):
        self.logger = FakeLogger()
        self._watchdog_control = control_obj


class TestLocalApi:
    def test_routes_are_registered(self):
        from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS

        specs = set(ACCESS_LOCAL_ROUTE_SPECS)
        assert ("GET", "/api/v2/watchdog", "_handle_watchdog_status") in specs
        assert ("POST", "/api/v2/watchdog", "_handle_watchdog_set") in specs

    def test_routes_need_the_local_token_like_other_settings_changes(self):
        """Same gate as PATCH /api/v2/config: the per-session X-Local-Token -- neither
        handler is in the dispatcher's _AUTH_EXEMPT set."""
        src = Path(wc.__file__).resolve().parents[1].joinpath(
            "app", "api", "local_access_api_v2.py").read_text(encoding="utf-8")
        start = src.index("_AUTH_EXEMPT = {")
        exempt = src[start:src.index("}", start)]
        assert "_handle_watchdog" not in exempt
        assert "_handle_config_patch" not in exempt

    def test_get(self, root: Path):
        from app.api import local_access_api_v2 as api

        ctx = FakeCtx(FakeApp(control(root, FakeRunner(task_json()))))
        api._handle_watchdog_status(ctx)
        code, payload = ctx.sent[0]
        assert code == 200 and payload["ok"] is True
        assert payload["watchdog"]["enabled"] is True
        for key in ("registered", "enabled", "state", "lastRunAt", "lastResult", "nextRunAt",
                    "intervalMinutes", "restartsLastHour", "stoodDown", "stoodDownReason",
                    "scriptPath", "lastError"):
            assert key in payload["watchdog"], key

    def test_post_requires_a_boolean(self, root: Path):
        from app.api import local_access_api_v2 as api

        for body in (None, {}, {"enabled": "false"}, {"enabled": 0}):
            ctx = FakeCtx(FakeApp(control(root, FakeRunner())), body)
            api._handle_watchdog_set(ctx)
            assert ctx.sent[0][0] == 400, body

    def test_post_turns_it_off_and_logs_who(self, root: Path, monkeypatch):
        from app.api import local_access_api_v2 as api

        monkeypatch.setattr(api, "_watchdog_actor", lambda: "owner@gym.tn")
        runner = FakeRunner(task_json(), (0, "", ""), task_json(state="Disabled", settingsEnabled=False))
        app = FakeApp(control(root, runner))
        ctx = FakeCtx(app, {"enabled": False})
        api._handle_watchdog_set(ctx)
        code, payload = ctx.sent[0]
        assert code == 200 and payload["watchdog"]["enabled"] is False
        assert any("owner@gym.tn" in ln and "OFF" in ln for ln in app.logger.lines), app.logger.lines

    def test_post_while_updating_is_409(self, root: Path):
        from app.api import local_access_api_v2 as api

        ctx = FakeCtx(FakeApp(control(root, FakeRunner(), setup_running=True)), {"enabled": False})
        api._handle_watchdog_set(ctx)
        assert ctx.sent[0][0] == 409

    def test_post_without_an_install_is_409(self):
        from app.api import local_access_api_v2 as api

        ctx = FakeCtx(FakeApp(control(None, FakeRunner())), {"enabled": True})
        api._handle_watchdog_set(ctx)
        assert ctx.sent[0][0] == 409

    def test_post_failure_is_502_with_the_status(self, root: Path):
        from app.api import local_access_api_v2 as api

        runner = FakeRunner(task_json(), (1, "", "Accès refusé"), task_json())
        ctx = FakeCtx(FakeApp(control(root, runner)), {"enabled": False})
        api._handle_watchdog_set(ctx)
        code, payload = ctx.sent[0]
        assert code == 502 and "Accès refusé" in payload["error"]
        assert payload["watchdog"]["enabled"] is True


# ----------------------------------------------------------------- real PowerShell, read only


@pytest.mark.skipif(sys.platform != "win32" or not shutil.which("powershell"),
                    reason="Windows PowerShell not available")
class TestRealPowerShell:
    def test_the_status_query_of_a_task_that_does_not_exist(self, tmp_path: Path):
        """The shipped query, really run (read-only), for a throwaway name: valid JSON,
        registered false, and quick enough for a Settings page."""
        name = f"MonClub TEST {uuid.uuid4().hex}"
        c = wc.WatchdogControl(install_root=None, task_name=name, cache_sec=0)
        t0 = time.monotonic()
        s = c.status()
        assert s["lastError"] is None, s
        assert s["registered"] is False, s
        assert time.monotonic() - t0 < wc.STATUS_TIMEOUT_SEC

    def test_the_status_query_reads_a_real_task(self):
        """Every Windows has \\Microsoft\\Windows\\...\\ tasks; read one through the same
        query to prove the fields and the ASCII-only JSON."""
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-ScheduledTask | Select-Object -First 1).TaskName"],
            capture_output=True, text=True, timeout=60)
        name = out.stdout.strip()
        if not name:
            pytest.skip("no scheduled task visible")
        c = wc.WatchdogControl(install_root=None, task_name=name, cache_sec=0)
        s = c.status()
        assert s["lastError"] is None, s
        assert s["registered"] is True, s
        assert isinstance(s["enabled"], bool) and isinstance(s["state"], str)
