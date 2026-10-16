"""« Revenir à la version précédente » -- the manual rollback (Access v5 follow-up Card B).

shared/update_runtime.py::local_rollback_info / launch_rollback and the local API handler. The
rollback has no copy code of its own: it writes the install journal and starts the start-up
check's restore helper, which runs the installed update_helper.ps1 ``-Action recover``. The
re-update guard is the loop guard's existing per-version ban.

Every test uses a throw-away install root under tmp_path and a fake (or dead) app pid: nothing
here touches this PC's real install or the running test process.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

import shared.update_runtime as ur
from app.api import local_access_api_v2 as api_v2
from shared import update_wrapper as uw
from shared.component_identity import get_component_identity
from shared.update_wrapper import HelperLaunchError
from tests.updater_v2_support import TEST_KEYRING, installer_bytes, make_offer

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "installer" / "update_helper.ps1"
WINDOWS = os.name == "nt"
WHOAMI = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "whoami.exe"
EXE = "MonClubAccess.exe"
DEAD_PID = 999_999_999  # no process ever has it; the fake launchers never run the script


class _Logger:
    def __init__(self) -> None:
        self.lines: List[tuple] = []

    def __getattr__(self, level):
        return lambda msg, *a, **k: self.lines.append((level, msg % a if a else msg))


class _Api:
    def __init__(self) -> None:
        self.offer: Any = {"shouldUpdate": False, "noRelease": True}

    def get_latest_software_release(self, **kw):
        return self.offer

    def post_software_update_event(self, *, token, event, timeout):
        return 201


class _Response:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.status_code = 200
        self.headers = {"Content-Length": str(len(data))}

    def iter_content(self, chunk_size):
        for i in range(0, len(self.data), 1024):
            yield self.data[i:i + 1024]

    def close(self):
        pass


class _Session:
    def __init__(self) -> None:
        self.payloads: Dict[str, bytes] = {}

    def get(self, url, stream=True, timeout=None):
        return _Response(self.payloads.get(url, b""))


def _payload(folder: Path, version: str, *, component: str | None = "access", exe_bytes: bytes = b"exe") -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / EXE).write_bytes(exe_bytes)
    data: Dict[str, Any] = {"version": version}
    if component is not None:
        data["component"] = component
    (folder / "version.json").write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def env(tmp_path, monkeypatch):
    installed = {"version": "1.5.1"}
    monkeypatch.setattr(ur, "_runtime_version_payload", lambda _c: dict(installed))
    root = tmp_path / "MonClubAccess"
    _payload(root / "current", "1.5.1")
    _payload(root / "previous", "1.5.0")
    (root / "state").mkdir(parents=True)
    (root / "watchdog").mkdir()
    shutil.copy(HELPER, root / "watchdog" / "update_helper.ps1")
    launched: List[Dict[str, Any]] = []
    flags = {"setup_running": False}
    clock = {"now": time.time()}
    app = SimpleNamespace(after=lambda *a: None, after_cancel=lambda *a: None)
    api, session = _Api(), _Session()

    def launcher(script, *, cwd):
        launched.append({"script": script, "cwd": cwd})
        return 4321

    def make(target="access", **kw):
        cfg = SimpleNamespace(update_enabled=True, update_channel="stable", update_platform="WINDOWS",
                              update_check_interval_sec=3 * 3600, update_auto_download_zip=True)
        params = dict(
            component=get_component_identity(target), app=app, cfg=cfg, logger=_Logger(),
            api_factory=lambda: api, install_root=root, keys_provider=lambda: TEST_KEYRING,
            auto_install_allowed=True, launcher=launcher, setup_running=lambda: flags["setup_running"],
            clock=lambda: clock["now"], pc_key_provider=lambda: "pc-uuid-1", boot_epoch=lambda: 1_000.0,
        )
        params.update(kw)
        mgr = ur.ComponentUpdateManager(**params)
        mgr._session = session
        mgr._token = None
        return mgr

    return SimpleNamespace(make=make, root=root, launched=launched, installed=installed, flags=flags,
                           clock=clock, api=api, session=session)


def _journal(root: Path) -> Path:
    return root / "state" / "install_journal.json"


def _versions(mgr) -> Dict[str, Any]:
    return mgr.state.load().get("versions") or {}


# ------------------------------------------------------------------ what the page may offer

def test_a_complete_older_v2_previous_is_offered(env):
    info = env.make().local_rollback_info()
    assert info == {"available": True, "currentVersion": "1.5.1", "previousVersion": "1.5.0", "reason": None}


def test_a_previous_without_a_component_field_is_still_access(env):
    _payload(env.root / "previous", "1.5.0", component=None)
    assert env.make().local_rollback_info()["available"] is True


@pytest.mark.parametrize(
    "arrange, reason",
    [
        (lambda e: (e.root / "previous" / EXE).unlink(), "no_previous"),
        (lambda e: (e.root / "previous" / "version.json").unlink(), "no_previous"),
        (lambda e: shutil.rmtree(e.root / "previous"), "no_previous"),
        (lambda e: (e.root / "previous" / "version.json").write_text("{not json", encoding="utf-8"), "previous_unreadable"),
        (lambda e: _payload(e.root / "previous", "garbage"), "previous_unreadable"),
        (lambda e: _payload(e.root / "previous", "1.5.0", component="tv"), "previous_other_component"),
        (lambda e: _payload(e.root / "previous", "1.5.1"), "previous_not_older"),
        (lambda e: _payload(e.root / "previous", "1.6.0"), "previous_not_older"),
        (lambda e: _payload(e.root / "previous", "1.4.35"), "previous_too_old"),
        (lambda e: _payload(e.root / "previous", "1.5.0-beta.1"), "previous_too_old"),
        (lambda e: (e.root / "watchdog" / "update_helper.ps1").unlink(), "helper_missing"),
        (lambda e: e.installed.update(version="garbage"), "previous_not_older"),
    ],
)
def test_the_rollback_is_not_offered_when(env, arrange, reason):
    arrange(env)
    info = env.make().local_rollback_info()
    assert info["available"] is False and info["reason"] == reason


def test_a_source_run_or_a_copied_exe_is_never_offered_a_rollback(env):
    info = env.make(auto_install_allowed=False).local_rollback_info()
    assert info["available"] is False and info["reason"] == "not_installed_build"


def test_tv_is_not_offered_a_rollback(env):
    _payload(env.root / "previous", "1.5.0", component="tv")
    info = env.make(target="tv").local_rollback_info()
    assert info["available"] is False and info["reason"] == "not_supported"


# ------------------------------------------------------------------ launch

def test_launch_writes_the_journal_bans_the_version_left_and_starts_the_restore_helper(env):
    mgr = env.make()
    pid = mgr.launch_rollback(expected_previous="1.5.0", expected_current="1.5.1", app_pid=DEAD_PID)
    assert pid == 4321 and mgr.status.installing is True
    journal = json.loads(_journal(env.root).read_text(encoding="utf-8"))
    assert journal["phase"] == "restoring" and journal["reason"] == "user_rollback"
    # Setup's direction: from = the version the install started from (restored), to = the one left.
    assert (journal["from"], journal["to"], journal["setupPid"]) == ("1.5.0", "1.5.1", DEAD_PID)
    assert journal["at"].endswith("Z")
    assert _versions(mgr)["1.5.1"] == {"banned": True, "banReason": "user_rollback"}
    [call] = env.launched
    assert Path(call["cwd"]) == env.root / "state"
    script = call["script"]
    # The start-up check's restore helper, unchanged: waits for this pid, runs the installed
    # update_helper.ps1 -Action recover, relaunches current\MonClubAccess.exe.
    assert script == uw.build_restore_script(
        setup_image_re=uw.setup_image_ps_re("access"), app_pid=DEAD_PID, install_root=env.root,
        exe_name=EXE, restore_log=env.root / "logs" / "update-restore.log",
    )
    assert "-Action recover" in script and str(env.root / "watchdog" / "update_helper.ps1") in script
    assert f"Get-Process -Id {DEAD_PID}" in script


def test_launch_drops_the_pending_download_so_the_restored_version_does_not_update_at_once(env):
    mgr = env.make()
    folder = env.root / "downloads" / "access" / "stable" / "1.5.2"
    folder.mkdir(parents=True)
    (folder / "monclub_access_1.5.2.exe").write_bytes(b"x")
    mgr.state.update(lambda d: d.update(pending={"version": "1.5.2", "downloaded": True,
                                                 "path": str(folder / "monclub_access_1.5.2.exe")}))
    mgr.launch_rollback(app_pid=DEAD_PID)
    assert "pending" not in mgr.state.load()
    assert not folder.exists()


def test_launch_keeps_the_other_versions_loop_guard_entries(env):
    mgr = env.make()
    mgr.state.update(lambda d: d.update(versions={"1.5.1": {"strikes": 1, "lastFailureAt": 5.0},
                                                  "1.4.99": {"banned": True, "banReason": "crash"}}))
    mgr.launch_rollback(app_pid=DEAD_PID)
    v = _versions(mgr)
    assert v["1.5.1"] == {"strikes": 1, "lastFailureAt": 5.0, "banned": True, "banReason": "user_rollback"}
    assert v["1.4.99"] == {"banned": True, "banReason": "crash"}


def _nothing_changed(env, mgr, versions_before=None):
    assert not _journal(env.root).exists()
    assert _versions(mgr) == (versions_before or {})
    assert env.launched == []
    assert mgr.status.installing is False


@pytest.mark.parametrize(
    "expected_previous, expected_current",
    [("1.4.99", "1.5.1"), ("1.5.0", "1.5.2")],
)
def test_launch_refuses_when_the_versions_differ_from_the_confirmation(env, expected_previous, expected_current):
    mgr = env.make()
    with pytest.raises(ur.RollbackRefused) as err:
        mgr.launch_rollback(expected_previous=expected_previous, expected_current=expected_current, app_pid=DEAD_PID)
    assert err.value.code == "changed"
    _nothing_changed(env, mgr)


def test_launch_refuses_what_the_page_would_not_offer(env):
    _payload(env.root / "previous", "1.4.35")
    mgr = env.make()
    with pytest.raises(ur.RollbackRefused) as err:
        mgr.launch_rollback(app_pid=DEAD_PID)
    assert err.value.code == "previous_too_old"
    _nothing_changed(env, mgr)


def test_launch_refuses_while_a_setup_runs(env):
    env.flags["setup_running"] = True
    mgr = env.make()
    with pytest.raises(ur.RollbackRefused) as err:
        mgr.launch_rollback(app_pid=DEAD_PID)
    assert err.value.code == "setup_running"
    _nothing_changed(env, mgr)


@pytest.mark.parametrize("name", ["install_journal.json", "install_journal.restoring-1234.json"])
def test_launch_refuses_while_a_journal_or_a_restore_claim_exists(env, name):
    marker = env.root / "state" / name
    marker.write_text('{"phase":"copying","from":"1.5.0","to":"1.5.1","at":"2026-01-01T00:00:00Z"}', encoding="ascii")
    mgr = env.make()
    with pytest.raises(ur.RollbackRefused) as err:
        mgr.launch_rollback(app_pid=DEAD_PID)
    assert err.value.code == "journal_present"
    assert marker.read_text(encoding="ascii").startswith('{"phase":"copying"')  # left to its restorer
    assert _versions(mgr) == {} and env.launched == []


def test_launch_refuses_under_a_fresh_pause_sentinel_but_not_an_old_one(env):
    sentinel = env.root / ".update-in-progress"
    sentinel.write_text("x", encoding="ascii")
    mgr = env.make()
    env.clock["now"] = sentinel.stat().st_mtime + 60
    with pytest.raises(ur.RollbackRefused) as err:
        mgr.launch_rollback(app_pid=DEAD_PID)
    assert err.value.code == "update_in_progress"
    _nothing_changed(env, mgr)
    env.clock["now"] = sentinel.stat().st_mtime + 31 * 60
    mgr.launch_rollback(app_pid=DEAD_PID)
    assert _journal(env.root).exists()


def test_launch_refuses_while_an_install_is_starting(env):
    mgr = env.make()
    mgr.status.installing = True
    with pytest.raises(ur.RollbackRefused) as err:
        mgr.launch_rollback(app_pid=DEAD_PID)
    assert err.value.code == "busy"
    assert not _journal(env.root).exists() and _versions(mgr) == {}


def test_a_helper_that_does_not_start_leaves_no_journal_and_no_ban(env):
    def failing(script, *, cwd):
        raise HelperLaunchError("PowerShell helper exited immediately (code 1)")

    mgr = env.make(launcher=failing)
    before = {"1.5.1": {"strikes": 1}}
    mgr.state.update(lambda d: d.update(versions=json.loads(json.dumps(before)),
                                        pending={"version": "1.5.2", "downloaded": False, "path": ""}))
    with pytest.raises(ur.RollbackRefused) as err:
        mgr.launch_rollback(app_pid=DEAD_PID)
    assert err.value.code == "launch_failed"
    assert not _journal(env.root).exists()  # it would roll the PC back at the next start
    assert _versions(mgr) == before
    assert mgr.state.load()["pending"]["version"] == "1.5.2"
    assert mgr.status.installing is False


# ------------------------------------------------------------------ the re-update guard

def test_the_restored_version_does_not_install_the_version_left_by_itself(env, monkeypatch):
    """After the rollback the OLDER build runs and consumes the result: simulate it with today's
    engine but the ban reasons an older engine has (no user_rollback). The version left stays
    banned from the start-up gate and the 24 h fallback; the Update page button still installs it."""
    env.make().launch_rollback(app_pid=DEAD_PID)
    # What update_helper.ps1 -Action recover writes after the restore (exit 20).
    (env.root / "state" / "last_update.json").write_text(json.dumps(
        {"result": "ROLLED_BACK", "from": "1.5.1", "to": "1.5.0", "reason": "user_rollback", "log": "", "at": "2026-10-16T10:00:00Z"}),
        encoding="ascii")
    _journal(env.root).unlink()
    env.installed["version"] = "1.5.0"
    monkeypatch.setattr(ur, "_BAN_REASONS", {"crash", "after_copy_failed", "setup_failed", "copy_failed", "post_install_failed"})
    env.launched.clear()
    old = env.make()
    old.consume_results(at_boot=True)
    assert old.state.load()["lastResult"]["result"] == "ROLLED_BACK"
    assert old.state.load()["lastResult"]["to"] == "1.5.1"
    # The server still offers 1.5.1: it is downloaded but never installed automatically.
    offer = make_offer(version="1.5.1")
    env.api.offer = offer
    env.session.payloads[offer["installer"]["url"]] = installer_bytes("1.5.1")
    old._run_check_and_download(token="tok")
    assert old.state.load()["pending"]["version"] == "1.5.1" and old.state.load()["pending"]["downloaded"] is True
    assert old.startup_gate(token="tok") is False
    env.clock["now"] += 30 * 24 * 3600  # long after a 24 h retry window
    assert old._auto_install(token="tok", mode="fallback") is False
    assert env.launched == []
    assert _versions(old)["1.5.1"]["banned"] is True
    assert old.status.auto_install_blocked is True and old.status.auto_install_blocked_reason == "user_rollback"
    assert old.can_install_now() == (True, "OK")  # « Redémarrer et installer » still works


def test_a_newer_release_than_the_version_left_still_installs_automatically(env):
    env.make().launch_rollback(app_pid=DEAD_PID)
    _journal(env.root).unlink()
    env.installed["version"] = "1.5.0"
    env.launched.clear()
    old = env.make()
    offer = make_offer(version="1.5.2")
    env.api.offer = offer
    env.session.payloads[offer["installer"]["url"]] = installer_bytes("1.5.2")
    old._run_check_and_download(token="tok")
    env.api.offer = offer  # still offered at the start-up re-check
    assert old.startup_gate(token="tok") is True
    assert len(env.launched) == 1


# ------------------------------------------------------------------ local API

class _Ctx:
    def __init__(self, app, body=None) -> None:
        self.app = app
        self._body = body
        self.responses: List[tuple] = []

    def body(self):
        return self._body

    def send_json(self, status: int, payload: object) -> None:
        self.responses.append((status, payload))


def _handler_app(um):
    return SimpleNamespace(_update_manager=um, after=MagicMock(), quit_app=MagicMock(), logger=MagicMock())


def test_the_rollback_route_is_registered_and_token_gated():
    text = (REPO / "access" / "local_api_routes.py").read_text(encoding="utf-8")
    assert '("POST", "/api/v2/update/rollback", "_handle_update_rollback")' in text
    api_text = (REPO / "app" / "api" / "local_access_api_v2.py").read_text(encoding="utf-8")
    exempt = api_text[api_text.index("_AUTH_EXEMPT = {"):]
    exempt = exempt[:exempt.index("}")]
    assert "_handle_update_rollback" not in exempt


def test_the_handler_answers_ok_and_quits_only_after_the_helper_started():
    order: List[str] = []
    um = MagicMock()
    um.launch_rollback.side_effect = lambda **kw: order.append(f"launched {kw['expected_current']}->{kw['expected_previous']}") or 1
    app = _handler_app(um)
    ctx = _Ctx(app, {"previousVersion": "1.5.0", "currentVersion": "1.5.1"})
    ctx.send_json = lambda status, payload: order.append(f"answer {status}")
    api_v2._handle_update_rollback(ctx)
    assert order == ["launched 1.5.1->1.5.0", "answer 200"]
    app.after.assert_called_once()
    assert app.after.call_args[0][1] is app.quit_app


def test_a_refused_rollback_is_a_409_with_its_code_and_the_app_keeps_running():
    um = MagicMock()
    um.launch_rollback.side_effect = ur.RollbackRefused("setup_running", "An installer of MonClub Access is running.")
    app = _handler_app(um)
    ctx = _Ctx(app, {"previousVersion": "1.5.0", "currentVersion": "1.5.1"})
    api_v2._handle_update_rollback(ctx)
    status, payload = ctx.responses[-1]
    assert status == 409 and payload == {"ok": False, "code": "setup_running", "error": "An installer of MonClub Access is running."}
    app.after.assert_not_called()


@pytest.mark.parametrize("body", [None, {}, {"previousVersion": "1.5.0"}, {"previousVersion": 1, "currentVersion": "1.5.1"}])
def test_the_handler_needs_both_confirmed_versions(body):
    um = MagicMock()
    app = _handler_app(um)
    ctx = _Ctx(app, body)
    api_v2._handle_update_rollback(ctx)
    assert ctx.responses[-1][0] == 400
    um.launch_rollback.assert_not_called()
    app.after.assert_not_called()


def test_an_unexpected_error_is_a_500_and_never_quits():
    um = MagicMock()
    um.launch_rollback.side_effect = OSError("disk full")
    app = _handler_app(um)
    ctx = _Ctx(app, {"previousVersion": "1.5.0", "currentVersion": "1.5.1"})
    api_v2._handle_update_rollback(ctx)
    assert ctx.responses[-1][0] == 500
    app.after.assert_not_called()


def test_the_status_payload_carries_the_local_rollback_apart_from_the_server_rollback_flag(env):
    mgr = env.make()
    data = api_v2._build_update_status_payload(SimpleNamespace(_update_manager=mgr, cfg=SimpleNamespace()))
    assert data["rollback"] is False
    assert data["localRollback"] == {"available": True, "currentVersion": "1.5.1", "previousVersion": "1.5.0", "reason": None}
    json.dumps(data)  # the payload stays JSON


# ------------------------------------------------------------------ for real (PowerShell + the real helper)

def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


@pytest.mark.skipif(not WINDOWS or not WHOAMI.exists(), reason="needs Windows PowerShell")
def test_a_rollback_runs_for_real_through_the_installed_helper_and_relaunches(env):
    """The script launch_rollback starts, run for real against a throw-away root: current\\ becomes
    previous\\, the result names the rollback, the journal is gone, the app is relaunched."""
    root = env.root
    shutil.rmtree(root / "current")
    shutil.rmtree(root / "previous")
    _payload(root / "current", "1.5.1", exe_bytes=WHOAMI.read_bytes())
    (root / "current" / "only-in-new.dll").write_text("new", encoding="ascii")
    _payload(root / "previous", "1.5.0", exe_bytes=WHOAMI.read_bytes())
    (root / "previous" / "_internal").mkdir()
    (root / "previous" / "_internal" / "old.pyd").write_text("old", encoding="ascii")

    def run_for_real(script, *, cwd):
        subprocess.run(uw.powershell_command(script), cwd=str(cwd), timeout=150, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 1

    mgr = env.make(launcher=run_for_real)
    mgr.launch_rollback(expected_previous="1.5.0", expected_current="1.5.1", app_pid=_dead_pid())

    def tree(folder: Path) -> Dict[str, bytes]:
        return {str(p.relative_to(folder)): p.read_bytes() for p in sorted(folder.rglob("*")) if p.is_file()}

    assert tree(root / "current") == tree(root / "previous")
    assert not list((root / "state").glob("install_journal*"))
    result = json.loads((root / "state" / "last_update.json").read_text(encoding="utf-8-sig"))
    assert (result["result"], result["from"], result["to"], result["reason"]) == ("ROLLED_BACK", "1.5.1", "1.5.0", "user_rollback")
    restore_log = (root / "logs" / "update-restore.log").read_text(encoding="utf-8", errors="replace")
    assert "update_helper recover exit 20" in restore_log and "relaunched" in restore_log
    assert "claimed stale journal phase=restoring" in (root / "logs" / "update-recover.log").read_text(encoding="utf-8", errors="replace")
    assert _versions(mgr)["1.5.1"]["banned"] is True
