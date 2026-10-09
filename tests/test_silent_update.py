"""Tests for silent update behaviour."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# The installer always runs silently, through the v2 wrapper (D36)
# ---------------------------------------------------------------------------

def _wrapper_script() -> str:
    from shared.update_wrapper import build_install_script

    root = Path(r"C:\Users\x\AppData\Local\MonClubAccess")
    return build_install_script(
        app_pid=1,
        installer=root / "downloads" / "monclub_access_1.5.1.exe",
        install_root=root,
        exe_name="MonClubAccess.exe",
        from_version="1.5.0",
        to_version="1.5.1",
        setup_log=root / "logs" / "update-1.5.1-x.log",
        wrapper_log=root / "logs" / "update-wrapper.log",
    )


def test_the_wrapper_runs_setup_with_all_silent_flags_and_a_log():
    script = _wrapper_script()
    for flag in ("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/LOG="):
        assert flag in script


def test_the_zip_and_csharp_updater_path_is_gone():
    """D2: the ZIP path could never work (no --manifest, no updater exe installed)."""
    import shared.update_runtime as ur
    from shared.component_identity import get_component_identity

    assert not hasattr(ur, "_launch_installer_exe")
    assert not hasattr(ur, "_updater_exe_path")
    assert not hasattr(ur.ComponentUpdateManager, "launch_updater_and_exit")
    assert not hasattr(get_component_identity("access"), "updater_exe_name")
    source = Path(ur.__file__).read_text(encoding="utf-8")
    assert "--zip" not in source and "Updater.exe" not in source


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
