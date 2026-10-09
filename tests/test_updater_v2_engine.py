"""shared/update_runtime.py -- the client engine of updater v2 (design section 7).

Defects covered: D1 (install refuses + app keeps running), D3/D8 (signed offers only,
rollback), D11/D12 (cache + size/SHA), D16 (404 = no update), D19 (telemetry), D25
(start-up / 24 h auto-install), D35 (downloads cleaned), D37 (cancel aborts), D38 (one
version rule).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import shared.update_runtime as ur
from shared.component_identity import get_component_identity
from shared.update_files import UpdatePaths, utc_now_iso
from tests.updater_v2_support import OTHER_SEED, TEST_KEYRING, installer_bytes, make_offer


class FakeApp:
    def __init__(self) -> None:
        self.scheduled: List[tuple] = []
        self.quit_calls = 0
        self.statuses: List[Any] = []

    def after(self, delay_ms, cb):
        self.scheduled.append((delay_ms, cb))
        return len(self.scheduled)

    def after_cancel(self, _sid):
        pass

    def on_update_status_changed(self, st):
        self.statuses.append(st)

    def on_update_ready(self, st):
        pass

    def on_update_error(self, msg):
        pass

    def quit_app(self):
        self.quit_calls += 1


class FakeApi:
    def __init__(self) -> None:
        self.offer: Any = {"shouldUpdate": False, "noRelease": True}
        self.raise_on_get: Exception | None = None
        self.calls: List[Dict[str, Any]] = []
        self.events: List[Dict[str, Any]] = []
        self.event_status = 201

    def get_latest_software_release(self, **kw):
        self.calls.append(kw)
        if self.raise_on_get is not None:
            raise self.raise_on_get
        return self.offer

    def post_software_update_event(self, *, token, event, timeout):
        self.events.append(event)
        return self.event_status


class FakeResponse:
    def __init__(self, data: bytes, status: int = 200, on_chunk=None) -> None:
        self.data = data
        self.status_code = status
        self.on_chunk = on_chunk
        self.headers = {"Content-Length": str(len(data))}

    def iter_content(self, chunk_size):
        for i in range(0, len(self.data), 1024):
            if self.on_chunk:
                self.on_chunk(i)
            yield self.data[i:i + 1024]

    def close(self):
        pass


class FakeSession:
    def __init__(self) -> None:
        self.payloads: Dict[str, bytes] = {}
        self.gets: List[str] = []
        self.on_chunk = None
        self.status = 200

    def get(self, url, stream=True, timeout=None):
        self.gets.append(url)
        return FakeResponse(self.payloads.get(url, b""), self.status, self.on_chunk)


@pytest.fixture
def env(tmp_path, monkeypatch):
    installed = {"version": "1.5.0"}
    monkeypatch.setattr(ur, "_runtime_version_payload", lambda _c: dict(installed))
    app, api, session = FakeApp(), FakeApi(), FakeSession()
    launched: List[Dict[str, Any]] = []
    clock = {"now": 1_800_000_000.0}
    boot = {"epoch": 1_799_000_000.0}

    def launcher(script, *, cwd):
        launched.append({"script": script, "cwd": cwd})
        return 4321

    def make(target="access", **kw):
        cfg = SimpleNamespace(update_enabled=True, update_channel="stable", update_platform="WINDOWS",
                              update_check_interval_sec=3 * 3600, update_auto_download_zip=True)
        params = dict(
            component=get_component_identity(target), app=app, cfg=cfg, logger=_Logger(),
            api_factory=lambda: api, install_root=tmp_path / target, keys_provider=lambda: TEST_KEYRING,
            auto_install_allowed=True, launcher=launcher, setup_running=lambda: False,
            clock=lambda: clock["now"], pc_key_provider=lambda: "pc-uuid-1",
            boot_epoch=lambda: boot["epoch"],
        )
        params.update(kw)
        mgr = ur.ComponentUpdateManager(**params)
        mgr._session = session
        mgr._token = None  # no background telemetry flush: tests call flush_outbox()
        return mgr

    return SimpleNamespace(make=make, app=app, api=api, session=session, launched=launched,
                           installed=installed, clock=clock, boot=boot, root=tmp_path)


class _Logger:
    def __init__(self):
        self.lines = []

    def __getattr__(self, level):
        return lambda msg, *a, **k: self.lines.append((level, msg % a if a else msg))


def _serve(env, offer, version="1.5.1", target="access"):
    env.api.offer = offer
    env.session.payloads[offer["installer"]["url"]] = installer_bytes(version)


def _check(mgr, **kw):
    return mgr._run_check_and_download(token="tok", **kw)


def _state(mgr) -> Dict[str, Any]:
    return mgr.state.load()


# ------------------------------------------------------------------ check / accept

def test_check_sends_the_signed_capability_and_the_bare_version(env):
    env.installed["version"] = "1.5.0 Orion"
    mgr = env.make()
    _check(mgr)
    call = env.api.calls[-1]
    assert call["capabilities"] == "signed-v1" and call["current_version"] == "1.5.0" and call["target"] == "access"


def test_404_is_no_update_and_not_a_failed_check(env):
    mgr = env.make()
    assert _check(mgr) is None  # None = success; False would start the retry schedule
    assert mgr.status.update_available is False and mgr.status.last_error is None


def test_a_signed_offer_downloads_verifies_and_becomes_pending(env):
    mgr = env.make()
    offer = make_offer(version="1.5.1")
    _serve(env, offer)
    _check(mgr)
    pending = _state(mgr)["pending"]
    path = Path(pending["path"])
    assert path == env.root / "access" / "downloads" / "access" / "stable" / "1.5.1" / "monclub_access_1.5.1.exe"
    assert path.read_bytes() == installer_bytes("1.5.1")
    assert pending["downloaded"] is True and not path.with_name(path.name + ".part").exists()
    assert mgr.status.update_available and mgr.status.downloaded and mgr.status.latest_version == "1.5.1"


def test_todays_unsigned_backend_is_refused_reported_once_and_never_downloaded(env):
    mgr = env.make()
    env.api.offer = {"shouldUpdate": True, "version": "1.5.1",
                     "installer": {"url": "https://x/monclub_access_1.5.1.exe", "name": "a.exe", "size": 9}}
    assert _check(mgr) is None
    assert _check(mgr) is None
    assert env.session.gets == []
    assert "pending" not in _state(mgr)
    assert mgr.status.update_available is False and "no signed manifest" in mgr.status.verify_error
    queued = [e for e in _state(mgr)["outbox"] if e["result"] == "VERIFY_FAILED"]
    assert len(queued) == 1 and queued[0]["toVersion"] == "1.5.1"


def test_a_forged_offer_is_refused(env):
    mgr = env.make()
    _serve(env, make_offer(seed=OTHER_SEED))
    _check(mgr)
    assert env.session.gets == [] and "pending" not in _state(mgr)


def test_a_truncated_download_is_refused_and_deleted(env):
    mgr = env.make()
    offer = make_offer(version="1.5.1")
    env.api.offer = offer
    env.session.payloads[offer["installer"]["url"]] = installer_bytes("1.5.1")[:-10]
    assert _check(mgr) is False
    folder = env.root / "access" / "downloads" / "access" / "stable" / "1.5.1"
    assert list(folder.iterdir()) == []
    assert _state(mgr)["pending"]["downloaded"] is False
    assert any(e["result"] == "VERIFY_FAILED" for e in _state(mgr)["outbox"])


def test_a_tampered_download_of_the_right_size_is_refused(env):
    mgr = env.make()
    offer = make_offer(version="1.5.1")
    env.api.offer = offer
    bad = bytearray(installer_bytes("1.5.1"))
    bad[100] ^= 0xFF
    env.session.payloads[offer["installer"]["url"]] = bytes(bad)
    assert _check(mgr) is False
    assert not Path(_state(mgr)["pending"]["path"]).exists()


def test_a_cached_file_is_reused_only_when_its_sha256_matches(env):
    mgr = env.make()
    offer = make_offer(version="1.5.1")
    _serve(env, offer)
    target = env.root / "access" / "downloads" / "access" / "stable" / "1.5.1" / "monclub_access_1.5.1.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"replaced bad binary of any size")
    _check(mgr)
    assert env.session.gets == [offer["installer"]["url"]]  # re-downloaded (D11)
    assert target.read_bytes() == installer_bytes("1.5.1")
    env.session.gets.clear()
    _check(mgr)
    assert env.session.gets == []  # good cache reused


def test_cancel_aborts_a_running_download(env):
    mgr = env.make()
    offer = make_offer(version="1.5.1")
    _serve(env, offer)

    def on_chunk(i):
        if i == 2048:
            mgr.cancel_download()

    env.session.on_chunk = on_chunk
    assert _check(mgr) is None
    folder = env.root / "access" / "downloads" / "access" / "stable" / "1.5.1"
    assert list(folder.iterdir()) == []
    assert _state(mgr)["pending"]["downloaded"] is False


def test_pause_or_withdraw_discards_the_pending_download(env):
    mgr = env.make()
    _serve(env, make_offer(version="1.5.1"))
    _check(mgr)
    folder = env.root / "access" / "downloads" / "access" / "stable" / "1.5.1"
    assert folder.is_dir()
    env.api.offer = {"shouldUpdate": False, "noRelease": True}
    _check(mgr)
    assert "pending" not in _state(mgr) and not folder.exists()


def test_an_older_eligible_release_answer_also_discards_the_pending(env):
    mgr = env.make()
    _serve(env, make_offer(version="1.5.1"))
    _check(mgr)
    env.api.offer = {"shouldUpdate": False, "version": "1.5.0"}
    _check(mgr)
    assert "pending" not in _state(mgr)


def test_a_newer_offer_replaces_the_pending_and_old_folders_are_cleaned(env):
    mgr = env.make()
    legacy = env.root / "access" / "downloads" / "windows" / "stable" / "monclub_access_1.4.35.exe"
    legacy.parent.mkdir(parents=True)
    legacy.write_bytes(b"old layout")
    _serve(env, make_offer(version="1.5.1"))
    _check(mgr)
    _serve(env, make_offer(version="1.5.2"), version="1.5.2")
    _check(mgr)
    downloads = env.root / "access" / "downloads"
    files = sorted(str(p.relative_to(downloads)) for p in downloads.rglob("*") if p.is_file())
    assert files == [str(Path("access/stable/1.5.2/monclub_access_1.5.2.exe"))]
    assert _state(mgr)["pending"]["version"] == "1.5.2"


def test_a_network_failure_is_a_failed_check(env):
    mgr = env.make()
    env.api.raise_on_get = RuntimeError("boom")
    assert _check(mgr) is False


# ------------------------------------------------------------------ install (D1)

def _pending_ready(env, version="1.5.1"):
    mgr = env.make()
    _serve(env, make_offer(version=version), version=version)
    _check(mgr)
    return mgr


def test_install_starts_the_wrapper_records_the_attempt_and_queues_pending(env):
    mgr = _pending_ready(env)
    pid = mgr.launch_install(mode="manual")
    assert pid == 4321
    launch = env.launched[-1]
    assert launch["cwd"] == env.root / "access" / "state"
    assert "/VERYSILENT" in launch["script"] and "monclub_access_1.5.1.exe" in launch["script"]
    attempt = _state(mgr)["attempt"]
    assert (attempt["version"], attempt["from"], attempt["mode"]) == ("1.5.1", "1.5.0", "manual")
    assert any(e["result"] == "PENDING" for e in _state(mgr)["outbox"])


def test_install_refuses_when_the_wrapper_cannot_start_and_keeps_no_attempt(env):
    def broken(script, *, cwd):
        raise ur.HelperLaunchError("PowerShell blocked")

    mgr = _pending_ready(env)
    mgr._launcher = broken
    with pytest.raises(ur.InstallRefused):
        mgr.launch_install()
    assert "attempt" not in _state(mgr)


def test_install_refuses_and_deletes_a_file_changed_after_download(env):
    mgr = _pending_ready(env)
    path = Path(_state(mgr)["pending"]["path"])
    path.write_bytes(b"x" * path.stat().st_size)
    with pytest.raises(ur.InstallRefused):
        mgr.launch_install()
    assert not path.exists() and env.launched == []


def test_install_refuses_without_a_pending_update(env):
    mgr = env.make()
    with pytest.raises(ur.InstallRefused):
        mgr.launch_install()
    ok, reason = mgr.can_install_now()
    assert ok is False and reason


# ------------------------------------------------------------------ rollback (D8)

def test_a_rollback_offer_is_installed_only_on_the_withdrawn_version(env):
    env.installed["version"] = "1.5.1"
    mgr = env.make()
    _serve(env, make_offer(version="1.5.0", rollback_from="1.5.1"), version="1.5.0")
    _check(mgr)
    assert _state(mgr)["pending"]["rollback"] is True and mgr.status.rollback is True
    mgr.launch_install(mode="manual")
    env.installed["version"] = "1.5.2"
    mgr2 = env.make()
    _serve(env, make_offer(version="1.5.0", rollback_from="1.5.1"), version="1.5.0")
    _check(mgr2)
    assert "pending" not in _state(mgr2)


# ------------------------------------------------------------------ start-up gate (D25)

def test_startup_without_a_pending_update_makes_no_network_call(env):
    mgr = env.make()
    assert mgr.startup_gate(token="tok") is False
    assert env.api.calls == []


def test_startup_installs_a_pending_update_still_offered(env):
    mgr = _pending_ready(env)
    env.api.calls.clear()
    assert mgr.startup_gate(token="tok") is True
    assert env.api.calls[-1]["timeout"] == 5
    assert _state(mgr)["attempt"]["mode"] == "startup"


def test_startup_installs_when_the_server_is_unreachable(env):
    mgr = _pending_ready(env)
    env.api.raise_on_get = RuntimeError("no network at 07:00")
    assert mgr.startup_gate(token="tok") is True


def test_startup_discards_a_paused_or_withdrawn_update(env):
    mgr = _pending_ready(env)
    env.api.offer = {"shouldUpdate": False, "noRelease": True}
    assert mgr.startup_gate(token="tok") is False
    assert env.launched == [] and "pending" not in _state(mgr)


def test_startup_discards_a_pending_replaced_by_another_release(env):
    mgr = _pending_ready(env)
    env.api.offer = make_offer(version="1.5.2")
    assert mgr.startup_gate(token="tok") is False
    assert "pending" not in _state(mgr)


def test_startup_never_auto_installs_from_a_source_run(env):
    mgr = _pending_ready(env)
    mgr._auto_install_allowed = False
    assert mgr.startup_gate(token="tok") is False and env.launched == []


def test_startup_skips_while_a_setup_is_running(env):
    mgr = _pending_ready(env)
    mgr._setup_running = lambda: True
    assert mgr.startup_gate(token="tok") is False


# ------------------------------------------------------------------ results + loop guard

def _write_result(mgr, *, result, reason="", tried="1.5.1", before="1.5.0", **fields):
    """A result in the writers' real field order (L2 update_safety.iss UpdWriteLastUpdate,
    the restore helper, the wrapper): ROLLED_BACK names the transition back, so from = the
    version that failed, to = the one restored; INSTALLED / ABORTED from = before, to = tried."""
    if result == "ROLLED_BACK":
        data = {"result": result, "from": tried, "to": before}
    else:
        data = {"result": result, "from": before, "to": tried}
    data.update({"reason": reason, "log": "C:\\x.log", "at": utc_now_iso()})
    data.update(fields)
    mgr.paths.state_dir.mkdir(parents=True, exist_ok=True)
    mgr.paths.last_update.write_text(json.dumps(data), encoding="utf-8")


def _new_boot(env):
    env.boot["epoch"] = env.clock["now"] + 1


def test_a_crash_bans_the_version_from_auto_install_but_not_from_the_button(env):
    mgr = _pending_ready(env)
    mgr.launch_install(mode="startup")
    _write_result(mgr, result="ROLLED_BACK", reason="crash")
    assert mgr.startup_gate(token="tok") is False
    _new_boot(env)
    assert mgr.startup_gate(token="tok") is False  # not at the next boot either
    assert len(env.launched) == 1
    assert mgr.status.auto_install_blocked is True and "crash" in mgr.status.auto_install_blocked_reason
    assert _state(mgr)["versions"]["1.5.1"]["banned"] is True and "1.5.0" not in _state(mgr)["versions"]
    assert not mgr.paths.last_update.exists() and mgr.paths.last_update_consumed.exists()
    assert mgr.launch_install(mode="manual") == 4321  # the button still works


def test_regression_l2_rolled_back_json_bans_the_failed_version_not_the_running_one(env):
    """Review C1: the literal JSON of UpdWriteLastUpdate(..., 'ROLLED_BACK', '{#AppVersion}',
    UpdFromVersion, 'crash') -- from = the new (failed) version. Without an open attempt."""
    mgr = _pending_ready(env)
    mgr.paths.last_update.write_text(
        '{"result":"ROLLED_BACK","from":"1.5.1","to":"1.5.0","reason":"crash",'
        '"log":"C:\\\\Users\\\\x\\\\MonClubAccess\\\\logs\\\\update-1.5.1.log","at":"2026-10-10T07:01:02Z"}',
        encoding="ascii",
    )
    assert mgr.startup_gate(token="tok") is False
    assert env.launched == []
    st = _state(mgr)
    assert st["versions"]["1.5.1"]["banned"] is True and "1.5.0" not in st["versions"]
    assert (st["lastResult"]["from"], st["lastResult"]["to"]) == ("1.5.0", "1.5.1")
    event = [e for e in st["outbox"] if e["result"] == "ROLLED_BACK"][0]
    assert (event["fromVersion"], event["toVersion"]) == ("1.5.0", "1.5.1")


def test_regression_restore_helper_json_strikes_the_abandoned_version(env):
    """Review C1: the restore helper writes from = journal.to (abandoned), to = journal.from."""
    mgr = _pending_ready(env)
    mgr.paths.last_update.write_text(
        '{"result":"ROLLED_BACK","from":"1.5.1","to":"1.5.0","reason":"interrupted","log":"x","at":"2026-10-10T07:01:02Z"}',
        encoding="ascii",
    )
    mgr.consume_results(at_boot=True)
    assert _state(mgr)["versions"]["1.5.1"]["strikes"] == 1 and "1.5.0" not in _state(mgr)["versions"]


def test_a_health_timeout_is_retried_once_at_the_next_pc_start_not_at_the_relaunch(env):
    mgr = _pending_ready(env)
    mgr.launch_install(mode="startup")
    _write_result(mgr, result="ROLLED_BACK", reason="health_timeout")
    assert mgr.startup_gate(token="tok") is False  # Setup relaunched the old version: same boot
    _new_boot(env)
    assert mgr.startup_gate(token="tok") is True  # next morning: one retry
    _write_result(mgr, result="ROLLED_BACK", reason="health_timeout", at="2026-10-10T08:00:01Z")
    _new_boot(env)
    assert mgr.startup_gate(token="tok") is False  # second failure: banned
    assert mgr.status.auto_install_blocked is True


def test_a_struck_version_is_retried_after_24h_on_a_pc_never_switched_off(env):
    mgr = _pending_ready(env)
    mgr.launch_install(mode="startup")
    _write_result(mgr, result="ROLLED_BACK", reason="health_timeout")
    assert mgr.startup_gate(token="tok") is False
    env.clock["now"] += 24 * 3600
    assert mgr._auto_install(token="tok", mode="fallback") is True


def test_an_install_that_left_no_result_counts_as_one_strike(env):
    mgr = _pending_ready(env)
    mgr.launch_install(mode="startup")
    env.clock["now"] += 600
    assert mgr.startup_gate(token="tok") is False  # no result: one strike, retry next boot
    _new_boot(env)
    env.clock["now"] += 600
    assert mgr.startup_gate(token="tok") is True
    env.clock["now"] += 600
    _new_boot(env)
    assert mgr.startup_gate(token="tok") is False  # second: banned
    assert [e["result"] for e in _state(mgr)["outbox"]].count("ABORTED") == 2


def test_a_result_racing_with_itself_counts_once(env):
    mgr = _pending_ready(env)
    data = {"result": "ROLLED_BACK", "from": "1.5.1", "to": "1.5.0", "reason": "health_timeout", "at": "x"}
    from shared.update_files import consume_marker

    assert mgr._apply_result(data, consume_marker(data)) is not None
    assert mgr._apply_result(data, consume_marker(data)) is None  # the second thread sees it applied
    assert _state(mgr)["versions"]["1.5.1"]["strikes"] == 1


def test_installed_result_clears_pending_reports_and_measures_duration(env):
    mgr = _pending_ready(env)
    mgr.launch_install(mode="startup")
    env.clock["now"] += 95
    env.installed["version"] = "1.5.1"
    _write_result(mgr, result="INSTALLED", reason="")
    mgr.consume_results()
    st = _state(mgr)
    assert "pending" not in st and "attempt" not in st
    assert st["lastResult"]["result"] == "INSTALLED" and mgr.status.last_result["to"] == "1.5.1"
    installed = [e for e in st["outbox"] if e["result"] == "INSTALLED"][0]
    assert "took=95s" in installed["detail"] and "mode=startup" in installed["detail"]
    assert not (env.root / "access" / "downloads" / "access" / "stable" / "1.5.1").exists()


def test_a_result_is_consumed_once(env):
    mgr = env.make()
    _write_result(mgr, result="ABORTED", reason="backup_failed")
    mgr.consume_results()
    raw = mgr.paths.last_update_consumed.read_text(encoding="utf-8")
    mgr.paths.last_update.write_text(raw, encoding="utf-8")
    mgr.consume_results()
    assert [e["result"] for e in _state(mgr)["outbox"]] == ["ABORTED"]


def test_same_version_abort_is_no_strike(env):
    mgr = env.make()
    _write_result(mgr, result="ABORTED", reason="same_version")
    mgr.consume_results()
    assert _state(mgr)["versions"] == {}


def test_same_version_abort_is_not_reported_as_a_failed_update(env):
    """L4 E2E (g): the dashboard counted a PC as "1 failed" on the version it ran fine, because Setup's
    harmless same-version answer was reported as ABORTED. Nothing was attempted: nothing is reported."""
    mgr = env.make()
    _write_result(mgr, result="ABORTED", reason="same_version")
    mgr.consume_results()
    assert _state(mgr).get("outbox", []) == []
    assert _state(mgr)["lastResult"]["reason"] == "same_version"  # still shown on the Update page


# ------------------------------------------------------------------ boot_ok + 24 h fallback

def test_boot_ok_is_written_with_the_running_version(env):
    mgr = env.make()
    mgr.on_local_api_ready()
    data = json.loads(mgr.paths.boot_ok.read_text(encoding="utf-8"))
    assert data["version"] == "1.5.0" and isinstance(data["pid"], int)
    assert any(delay == ur.RESULT_RESCAN_MS for delay, _cb in env.app.scheduled)


def test_fallback_waits_24h_and_15_minutes_without_a_door_event(env):
    idle = {"sec": 60.0}
    mgr = _pending_ready(env)
    mgr._door_idle_sec_provider = lambda: idle["sec"]
    assert mgr.fallback_due() is False
    env.clock["now"] += 24 * 3600
    assert mgr.fallback_due() is False  # a door event a minute ago
    idle["sec"] = 15 * 60
    assert mgr.fallback_due() is True


def test_fallback_does_the_same_pause_recheck(env):
    mgr = _pending_ready(env)
    env.clock["now"] += 25 * 3600
    env.api.offer = {"shouldUpdate": False, "noRelease": True}
    assert mgr._auto_install(token="tok", mode="fallback") is False
    assert env.launched == []


# ------------------------------------------------------------------ telemetry (D19)

def test_events_are_posted_with_an_idempotent_id_and_dropped_once_accepted(env):
    mgr = env.make()
    event = mgr.emit_event("VERIFY_FAILED", to_version="1.5.1", detail="x", once_key="k", flush=False)
    assert event["pcKey"] == "pc-uuid-1" and event["target"] == "access" and event["occurredAt"].endswith("Z")
    assert mgr.emit_event("VERIFY_FAILED", to_version="1.5.1", once_key="k", flush=False) is None
    assert mgr.flush_outbox(token="tok") == 1
    assert env.api.events[0]["eventId"] == event["eventId"]
    assert _state(mgr)["outbox"] == []


def test_server_errors_keep_the_event_and_an_old_backend_404_drops_it(env):
    mgr = env.make()
    mgr.emit_event("INSTALLED", to_version="1.5.1", flush=False)
    env.api.event_status = 503
    assert mgr.flush_outbox(token="tok") == 0 and len(_state(mgr)["outbox"]) == 1
    env.api.event_status = 404
    assert mgr.flush_outbox(token="tok") == 1 and _state(mgr)["outbox"] == []


def test_an_expired_or_refused_token_keeps_the_event_for_the_next_flush(env):
    """L4 review M1: 401 (expired token), 403 (subscription inactive), 428 (upgrade required) describe the
    gym token, not the event -- the INSTALLED report must survive until a good token sends it."""
    mgr = env.make()
    mgr.emit_event("INSTALLED", to_version="1.5.1", flush=False)
    for code in (401, 403, 428, 408, 429):
        env.api.event_status = code
        assert mgr.flush_outbox(token="tok") == 0 and len(_state(mgr)["outbox"]) == 1, code
    env.api.event_status = 400
    assert mgr.flush_outbox(token="tok") == 1 and _state(mgr)["outbox"] == []


def test_the_same_installer_result_gives_the_same_event_id(env):
    mgr = env.make()
    a = mgr.emit_event("INSTALLED", to_version="1.5.1", id_seed="m1", flush=False)
    mgr.state.update(lambda d: d.update(outbox=[]))
    b = mgr.emit_event("INSTALLED", to_version="1.5.1", id_seed="m1", flush=False)
    assert a["eventId"] == b["eventId"]


def test_tv_uses_a_stable_install_id_as_pc_key(env):
    mgr = env.make(target="tv", pc_key_provider=None)
    first = mgr.emit_event("PENDING", to_version="1.5.1", flush=False)["pcKey"]
    again = env.make(target="tv", pc_key_provider=None).emit_event("ABORTED", to_version="1.5.1", flush=False)["pcKey"]
    assert first.startswith("tv-") and first == again


def test_the_outbox_is_bounded(env):
    mgr = env.make()
    for i in range(ur.OUTBOX_MAX + 10):
        mgr.emit_event("DOWNLOAD_FAILED", to_version=f"1.5.{i}", flush=False)
    assert len(_state(mgr)["outbox"]) == ur.OUTBOX_MAX


def test_a_frozen_exe_outside_current_never_auto_installs(env, monkeypatch, tmp_path):
    """Review M2: the wrapper would relaunch {root}/current/<exe>, which is not there."""
    monkeypatch.setattr(ur, "is_frozen", lambda: True)
    monkeypatch.setattr(ur, "runtime_base_dir", lambda: tmp_path / "copied-build")
    assert env.make(auto_install_allowed=None)._auto_install_allowed is False
    monkeypatch.setattr(ur, "runtime_base_dir", lambda: tmp_path / "MonClubAccess" / "current")
    assert env.make(auto_install_allowed=None)._auto_install_allowed is True


def test_the_wrapper_is_built_with_this_components_setup_pattern_only(env):
    mgr = _pending_ready(env)
    mgr.launch_install()
    script = env.launched[-1]["script"]
    assert "^monclub_access_[0-9]" in script and "(access|tv)" not in script

def test_an_aborted_setup_failed_is_a_strike_not_a_ban(env):
    """L4 review M4: Setup writes ABORTED setup_failed / restore_failed when it ended BEFORE changing
    anything -- the new version never ran, so one such result must not ban it (design 7 bans only a
    version that crashed or failed after the copy)."""
    mgr = env.make()
    d = {}
    mgr._record_failure(d, "1.5.1", "setup_failed", "ABORTED")
    assert not d["versions"]["1.5.1"].get("banned") and d["versions"]["1.5.1"]["strikes"] == 1
    mgr._record_failure(d, "1.5.2", "setup_failed", "ROLLED_BACK")
    assert d["versions"]["1.5.2"]["banned"] is True

