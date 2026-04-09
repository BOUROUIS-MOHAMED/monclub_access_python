"""Tests for FirmwareProfile SQLite persistence in db.py."""
import pytest
from unittest.mock import MagicMock, patch, call


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Provide an isolated db module pointed at a temp database."""
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()  # creates tables in temp path
    return db_module


def test_save_and_load_firmware_profile(db):
    """Saved firmware profile can be loaded back with same values."""
    db.save_firmware_profile(device_id=42, template_table="templatev10",
                             template_body_index=0, authorize_body_index=2)
    profile = db.load_firmware_profile(device_id=42)
    assert profile is not None
    assert profile["template_table"] == "templatev10"
    assert profile["template_body_index"] == 0
    assert profile["authorize_body_index"] == 2


def test_load_firmware_profile_returns_none_for_unknown_device(db):
    """Loading a profile for an unknown device returns None."""
    assert db.load_firmware_profile(device_id=999) is None


def test_save_firmware_profile_overwrites_existing(db):
    """Saving a profile twice updates the existing record."""
    db.save_firmware_profile(device_id=1, template_table="template",
                             template_body_index=1, authorize_body_index=0)
    db.save_firmware_profile(device_id=1, template_table="templatev10",
                             template_body_index=3, authorize_body_index=1)
    profile = db.load_firmware_profile(device_id=1)
    assert profile["template_table"] == "templatev10"
    assert profile["template_body_index"] == 3


def test_clear_firmware_profile_removes_entry(db):
    """Clearing a profile removes it from SQLite."""
    db.save_firmware_profile(device_id=5, template_table="templatev10",
                             template_body_index=0, authorize_body_index=0)
    db.clear_firmware_profile(device_id=5)
    assert db.load_firmware_profile(device_id=5) is None


def test_multiple_devices_independent_profiles(db):
    """Each device has its own independent profile."""
    db.save_firmware_profile(device_id=1, template_table="template",
                             template_body_index=1, authorize_body_index=0)
    db.save_firmware_profile(device_id=2, template_table="templatev10",
                             template_body_index=0, authorize_body_index=2)
    p1 = db.load_firmware_profile(device_id=1)
    p2 = db.load_firmware_profile(device_id=2)
    assert p1["template_table"] == "template"
    assert p2["template_table"] == "templatev10"
