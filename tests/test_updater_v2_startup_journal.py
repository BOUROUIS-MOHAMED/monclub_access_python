"""shared/update_startup.py -- the start-up journal check (design 7, 8.0; power-cut case)."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from shared import update_startup as us
from shared.update_files import utc_now_iso
from shared.update_wrapper import HelperLaunchError

NOW = 1_800_000_000.0


def _root(tmp_path, *, phase="copying", age=11 * 60, previous=True, journal=True):
    root = tmp_path / "MonClub Access"
    (root / "current").mkdir(parents=True)
    (root / "state").mkdir()
    if previous:
        (root / "previous").mkdir()
        (root / "previous" / "MonClubAccess.exe").write_bytes(b"MZ")
        (root / "previous" / "version.json").write_text('{"version":"1.5.0"}', encoding="ascii")
    if journal:
        (root / "state" / "install_journal.json").write_text(
            json.dumps({"phase": phase, "from": "1.5.0", "to": "1.5.1", "at": utc_now_iso(NOW - age)}), encoding="ascii")
    return root


def _check(root, launched, *, setup_running=False, launcher=None):
    def fake_launcher(script, *, cwd):
        launched.append((script, cwd))
        return 99

    return us.check_install_journal(
        exe_name="MonClubAccess.exe", install_root=root, launcher=launcher or fake_launcher,
        setup_running=lambda setup_pid=None: setup_running, now=NOW, boot_epoch=NOW - 3600,
    )


def test_no_journal_starts_normally(tmp_path):
    launched = []
    assert _check(_root(tmp_path, journal=False), launched) is False and launched == []


def test_a_stale_copying_journal_starts_the_restore_helper_and_exits(tmp_path):
    launched = []
    root = _root(tmp_path)
    assert _check(root, launched) is True
    script, cwd = launched[0]
    assert cwd == root / "state"
    assert "Restore-Journal" in script and "install_journal.restoring-" in script
    assert "update-startup.log" in [p.name for p in (root / "logs").iterdir()]


def test_a_journal_while_setup_runs_is_left_alone(tmp_path):
    launched = []
    root = _root(tmp_path)
    assert _check(root, launched, setup_running=True) is False
    assert launched == [] and (root / "state" / "install_journal.json").exists()


def test_a_fresh_journal_waits(tmp_path):
    launched = []
    # at after the last boot and under 10 min old, no setupPid
    assert _check(_root(tmp_path, age=60), launched) is False and launched == []


def test_a_stale_backing_up_journal_is_deleted_without_restore(tmp_path):
    launched = []
    root = _root(tmp_path, phase="backing_up")
    assert _check(root, launched) is False
    assert launched == [] and list((root / "state").iterdir()) == []


def test_an_unreadable_journal_still_restores_when_previous_is_complete(tmp_path):
    launched = []
    root = _root(tmp_path)
    (root / "state" / "install_journal.json").write_text("{half", encoding="ascii")
    assert _check(root, launched) is True


def test_if_the_helper_cannot_start_the_app_starts_anyway(tmp_path):
    def broken(script, *, cwd):
        raise HelperLaunchError("blocked")

    assert _check(_root(tmp_path), [], launcher=broken) is False


def test_a_source_run_never_restores(monkeypatch):
    monkeypatch.delenv(us.TEST_OVERRIDE_ENV, raising=False)
    assert us._install_root_for("MonClubAccess.exe") is None


@pytest.mark.parametrize("module", ["shared/update_startup.py", "shared/update_files.py", "shared/update_wrapper.py"])
def test_the_journal_check_imports_only_the_standard_library(module):
    """A half-copied current may not import the app: these must load on their own."""
    tree = ast.parse(Path(module).read_text(encoding="utf-8"))
    allowed_local = {"shared.update_files", "shared.update_wrapper"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in {"shared", "app", "access", "tv"}:
            assert node.module in allowed_local, node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in {"shared", "app", "access", "tv", "requests"}, alias.name


@pytest.mark.parametrize("main_file,exe", [("access/main.py", "MonClubAccess.exe"), ("tv/main.py", "MonClubTV.exe")])
def test_both_entry_points_run_the_journal_check_before_the_app(main_file, exe):
    text = Path(main_file).read_text(encoding="utf-8")
    assert f'check_install_journal(exe_name="{exe}")' in text
    assert text.index("check_install_journal(") < text.index("bootstrap import run_")
