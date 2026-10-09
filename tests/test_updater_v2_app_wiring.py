"""Updater v2 wiring into Access / TV (D1, D25; design section 7)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, List
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
import app.ui.app as app_module
from app.api import local_access_api_v2 as api_v2
from app.ui.app import MainApp
from shared.update_runtime import InstallRefused, UpdateInstallStarted, UpdateStatus
from tests.test_p3b1_app_wiring import _stub_heavy_init


# ------------------------------------------------------------------ start-up order (O1, D25)

def _gate_stubs(monkeypatch, tmp_path, *, gate_result: bool) -> List[str]:
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "init.db"), raising=False)
    _stub_heavy_init(monkeypatch)
    built: List[str] = []
    gate_calls: List[Any] = []

    def manager(**kwargs):
        def gate(*, token):
            gate_calls.append(token)
            built.append("gate")
            return gate_result

        return SimpleNamespace(startup_gate=gate, on_local_api_ready=lambda: None)

    monkeypatch.setattr(app_module, "UpdateManager", manager)
    monkeypatch.setattr(app_module, "load_auth_token", lambda: SimpleNamespace(token="gym-token"))
    for name in ("DeviceSyncEngine", "DeviceAttendanceMaintenanceEngine", "AgentRealtimeEngine", "UltraEngine"):
        monkeypatch.setattr(app_module, name, lambda _n=name, **kw: built.append(_n) or SimpleNamespace())
    monkeypatch.setattr(MainApp, "_apply_date_flips", lambda self, source, **_kw: built.append("date_flip"))
    return built


def test_a_startup_install_happens_before_any_engine_or_door_work(tmp_path, monkeypatch):
    built = _gate_stubs(monkeypatch, tmp_path, gate_result=True)
    scheduled: List[str] = []
    monkeypatch.setattr(MainApp, "after", lambda self, d, cb: scheduled.append(getattr(cb, "__name__", "?")) or 1)
    with pytest.raises(UpdateInstallStarted):
        MainApp()
    assert built == ["gate"]
    assert "_sync_tick" not in scheduled


def test_without_an_update_the_engines_start_after_the_gate(tmp_path, monkeypatch):
    built = _gate_stubs(monkeypatch, tmp_path, gate_result=False)

    class StopInit(Exception):
        pass

    def stop_at_flip(self, source, **_kw):
        built.append("date_flip")
        raise StopInit()

    monkeypatch.setattr(MainApp, "_apply_date_flips", stop_at_flip)
    with pytest.raises(StopInit):
        MainApp()
    assert built[0] == "gate" and "UltraEngine" in built and built.index("UltraEngine") > 0


def test_run_access_app_treats_the_update_exit_as_a_clean_return(monkeypatch):
    import access.bootstrap as boot

    def raise_started():
        raise UpdateInstallStarted()

    monkeypatch.setattr(boot, "create_access_app", raise_started)
    assert boot.run_access_app() is None


def test_run_tv_app_treats_the_update_exit_as_a_clean_return(monkeypatch):
    import tv.bootstrap as boot

    def raise_started():
        raise UpdateInstallStarted()

    monkeypatch.setattr(boot, "create_tv_app", raise_started)
    assert boot.run_tv_app() is None


def test_tv_app_runs_the_gate_before_scheduling_its_shell():
    text = Path("tv/app.py").read_text(encoding="utf-8")
    init = text[text.index("def __init__"):text.index("def after(")]
    assert init.index("_run_update_startup_gate()") < init.index("schedule_tv_shell_startup(self)")
    assert init.index("_run_update_startup_gate()") < init.index("self.after(200, self._poll_logs)")


def test_boot_ok_is_scheduled_once_the_local_api_started():
    for path, needle in (("app/ui/app.py", "self._local_api.start()"), ("tv/app.py", "self._local_api.start()")):
        text = Path(path).read_text(encoding="utf-8")
        after_start = text[text.index(needle):]
        assert "self.after(0, self._update_manager.on_local_api_ready)" in after_start[:900], path


# ------------------------------------------------------------------ install handler (D1)

class _Ctx:
    def __init__(self, app) -> None:
        self.app = app
        self.responses: List[tuple] = []

    def send_json(self, status: int, payload: object) -> None:
        self.responses.append((status, payload))


def _handler_app(um):
    return SimpleNamespace(_update_manager=um, after=MagicMock(), quit_app=MagicMock())


def test_install_answers_an_error_and_never_quits_when_the_wrapper_fails():
    um = MagicMock()
    um.can_install_now.return_value = (True, "OK")
    um.launch_install.side_effect = InstallRefused("Could not start the installer: blocked")
    app = _handler_app(um)
    ctx = _Ctx(app)
    api_v2._handle_component_update_install(ctx)
    status, payload = ctx.responses[-1]
    assert status == 500 and payload["ok"] is False and "blocked" in payload["error"]
    app.after.assert_not_called()


def test_install_answers_ok_and_quits_only_after_the_wrapper_started():
    order: List[str] = []
    um = MagicMock()
    um.can_install_now.return_value = (True, "OK")
    um.launch_install.side_effect = lambda **kw: order.append("launched") or 1234
    app = _handler_app(um)
    ctx = _Ctx(app)
    ctx.send_json = lambda status, payload: order.append(f"answer {status}")
    api_v2._handle_component_update_install(ctx)
    assert order == ["launched", "answer 200"]
    app.after.assert_called_once()
    assert app.after.call_args[0][1] is app.quit_app


def test_install_without_a_ready_update_is_a_409():
    um = MagicMock()
    um.can_install_now.return_value = (False, "Update not downloaded yet.")
    ctx = _Ctx(_handler_app(um))
    api_v2._handle_component_update_install(ctx)
    assert ctx.responses[-1][0] == 409
    um.launch_install.assert_not_called()


def test_status_payload_carries_the_v2_fields_and_no_updater_exe():
    st = UpdateStatus(update_available=True, latest_version="1.5.1", verify_error=None,
                      auto_install_blocked=True, auto_install_blocked_reason="crash",
                      last_result={"result": "ROLLED_BACK", "reason": "crash"}, rollback=False)
    um = SimpleNamespace(status=st, get_current_version=lambda: "1.5.0", get_current_codename=lambda: "",
                         get_current_release_id=lambda: "1.5.0", install_root=Path("C:/x"),
                         component=SimpleNamespace(component_id="access", display_name="MonClub Access",
                                                   artifact_name="MonClubAccess", main_exe_name="MonClubAccess.exe"))
    data = api_v2._build_update_status_payload(SimpleNamespace(_update_manager=um, cfg=SimpleNamespace()))
    assert data["autoInstallBlocked"] is True and data["autoInstallBlockedReason"] == "crash"
    assert data["lastResult"] == {"result": "ROLLED_BACK", "reason": "crash"}
    assert "updaterInstalled" not in data and "updaterExecutable" not in data


# ------------------------------------------------------------------ UI (D33)

@pytest.mark.parametrize("page", ["tauri-ui/src/pages/UpdatePage.tsx", "tauri-ui/src/tv/pages/TvUpdatePage.tsx"])
def test_release_notes_are_never_injected_as_raw_html(page):
    text = Path(page).read_text(encoding="utf-8")
    assert "dangerouslySetInnerHTML" not in text
    assert "<ReleaseNotes" in text and "<UpdateNotices" in text
