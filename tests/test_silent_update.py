"""Tests for silent update behaviour."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# _launch_installer_exe
# ---------------------------------------------------------------------------

def _call_launch(silent: bool, exe_path: str = r"C:\fake\setup.exe"):
    """Helper: call _launch_installer_exe and return the Popen call args."""
    from shared.update_runtime import _launch_installer_exe
    with patch("shared.update_runtime.subprocess.Popen") as mock_popen:
        _launch_installer_exe(Path(exe_path), silent=silent)
        return mock_popen.call_args


def _cmd_contains(call, flag: str) -> bool:
    """Return True if *flag* appears anywhere in the Popen command list."""
    cmd = call[0][0]   # first positional arg = the command list
    return any(flag in part for part in cmd if isinstance(part, str))


def test_launch_installer_exe_silent_adds_flags():
    """Default silent=True must pass /VERYSILENT and /SUPPRESSMSGBOXES.

    With the PowerShell wrapper the flags live inside the PS command string
    rather than as top-level list elements, so we search all parts.
    """
    call = _call_launch(silent=True)
    assert _cmd_contains(call, "/VERYSILENT")
    assert _cmd_contains(call, "/SUPPRESSMSGBOXES")


def test_launch_installer_exe_not_silent_omits_flags():
    """silent=False must NOT pass silent flags."""
    call = _call_launch(silent=False)
    assert not _cmd_contains(call, "/VERYSILENT")
    assert not _cmd_contains(call, "/SUPPRESSMSGBOXES")


def test_launch_installer_exe_default_is_silent():
    """Calling _launch_installer_exe without silent kwarg must be silent."""
    from shared.update_runtime import _launch_installer_exe
    with patch("shared.update_runtime.subprocess.Popen") as mock_popen:
        _launch_installer_exe(Path(r"C:\fake\setup.exe"))
        call = mock_popen.call_args
    assert _cmd_contains(call, "/VERYSILENT")


# ---------------------------------------------------------------------------
# _auto_download fallback
# ---------------------------------------------------------------------------

def _make_manager(has_attr: bool, value: bool | None = None):
    """Build a minimal ComponentUpdateManager with a controlled cfg."""
    from shared.update_runtime import ComponentUpdateManager
    cfg = SimpleNamespace()
    if has_attr:
        cfg.update_auto_download_zip = value
    identity = MagicMock()
    identity.component_id = "access"
    identity.default_install_root_name = "MonClubAccess"
    identity.legacy_install_root_names = []
    identity.updater_exe_name = "MonClubAccessUpdater.exe"
    app = MagicMock()
    mgr = ComponentUpdateManager.__new__(ComponentUpdateManager)
    mgr.cfg = cfg
    return mgr


def test_auto_download_fallback_is_true_when_attr_missing():
    """When cfg has no update_auto_download_zip, default must be True."""
    mgr = _make_manager(has_attr=False)
    assert mgr._auto_download() is True


def test_auto_download_explicit_false_is_respected():
    """Operator can still disable auto-download by setting it explicitly."""
    mgr = _make_manager(has_attr=True, value=False)
    assert mgr._auto_download() is False


def test_auto_download_explicit_true_is_respected():
    mgr = _make_manager(has_attr=True, value=True)
    assert mgr._auto_download() is True


# ---------------------------------------------------------------------------
# AppConfig defaults
# ---------------------------------------------------------------------------

def test_appconfig_field_default_is_true():
    """AppConfig() with no args must have update_auto_download_zip = True."""
    from app.core.config import AppConfig
    cfg = AppConfig()
    assert cfg.update_auto_download_zip is True


def test_appconfig_from_dict_empty_defaults_to_true():
    """AppConfig.from_dict({}) must produce update_auto_download_zip = True."""
    from app.core.config import AppConfig
    cfg = AppConfig.from_dict({})
    assert cfg.update_auto_download_zip is True


def test_appconfig_from_dict_explicit_false_is_respected():
    """Operator config with update_auto_download_zip=false must be False."""
    from app.core.config import AppConfig
    cfg = AppConfig.from_dict({"update_auto_download_zip": False})
    assert cfg.update_auto_download_zip is False
