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


# ── _push_userauthorize with cache ────────────────────────────────────────

import logging


def make_engine(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    from app.core.device_sync import DeviceSyncEngine
    logger = logging.getLogger("test")
    svc = DeviceSyncEngine(cfg=MagicMock(), logger=logger)
    return svc, db_module


def test_push_userauthorize_uses_cached_pattern_on_hit(tmp_path, monkeypatch):
    """When firmware profile has authorize_body_index, only that pattern is attempted."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    db_module.save_firmware_profile(device_id=7, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=1)

    sdk = MagicMock()
    sdk.set_device_data.return_value = None  # success

    ok, err = svc._push_userauthorize(sdk, pin="42", door_bitmask=15,
                                      authorize_timezone_id=1, device_id=7)

    assert ok == 1
    assert err is None
    # Only 1 SDK call (cached pattern index=1), not 4
    assert sdk.set_device_data.call_count == 1


def test_push_userauthorize_retries_all_on_cache_miss(tmp_path, monkeypatch):
    """When no profile cached, tries all patterns until one succeeds."""
    svc, db_module = make_engine(tmp_path, monkeypatch)

    sdk = MagicMock()
    # First 2 patterns fail, 3rd succeeds
    sdk.set_device_data.side_effect = [Exception("fail"), Exception("fail"), None]

    ok, err = svc._push_userauthorize(sdk, pin="42", door_bitmask=15,
                                      authorize_timezone_id=1, device_id=99)

    assert ok == 1
    assert sdk.set_device_data.call_count == 3  # failed x2, succeeded x1
    # Profile should now be cached (index=2)
    profile = db_module.load_firmware_profile(device_id=99)
    assert profile["authorize_body_index"] == 2


def test_push_userauthorize_clears_cache_on_cached_pattern_failure(tmp_path, monkeypatch):
    """If cached pattern fails (firmware upgrade), cache is cleared and retry loop runs."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    db_module.save_firmware_profile(device_id=3, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=0)

    sdk = MagicMock()
    # Cached pattern (index=0) fails, then index=0 fails again, index=1 fails, index=2 succeeds
    sdk.set_device_data.side_effect = [Exception("cached fail"), Exception("fail"),
                                       Exception("fail"), None]

    ok, err = svc._push_userauthorize(sdk, pin="42", door_bitmask=15,
                                      authorize_timezone_id=1, device_id=3)

    assert ok == 1
    # New winning profile should be index=2
    profile = db_module.load_firmware_profile(device_id=3)
    assert profile["authorize_body_index"] == 2


# ── _push_templates with cache ────────────────────────────────────────────

def make_template(fid=0, version=10, size=500, data="AABBCC"):
    return {"fingerId": fid, "templateVersion": version, "templateSize": size, "templateData": data}


def test_push_templates_uses_cached_pattern(tmp_path, monkeypatch):
    """Cached (table, body_index) results in 1 SDK call per fingerprint."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    db_module.save_firmware_profile(device_id=10, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=0)

    sdk = MagicMock()
    sdk.set_device_data.return_value = None

    ok, errs = svc._push_templates(sdk, pin="1", templates=[make_template(), make_template(fid=1)],
                                   device_id=10)
    assert ok == 2
    assert errs == []
    assert sdk.set_device_data.call_count == 2  # 1 call per fingerprint (cached)


def test_push_templates_discovers_and_caches_working_combo(tmp_path, monkeypatch):
    """On cache miss, tries combos until one works; caches winner."""
    svc, db_module = make_engine(tmp_path, monkeypatch)

    sdk = MagicMock()
    # First 3 combos fail, 4th (templatev10, body_index=3) succeeds
    sdk.set_device_data.side_effect = [
        Exception("fail"), Exception("fail"), Exception("fail"), None
    ]

    ok, errs = svc._push_templates(sdk, pin="1", templates=[make_template()], device_id=20)

    assert ok == 1
    assert errs == []
    profile = db_module.load_firmware_profile(device_id=20)
    assert profile["template_table"] == "templatev10"
    assert profile["template_body_index"] == 3


def test_push_templates_clears_cache_on_cached_combo_failure(tmp_path, monkeypatch):
    """Cached combo failure triggers cache clear and retry loop."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    db_module.save_firmware_profile(device_id=15, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=0)

    sdk = MagicMock()
    # Cached combo (templatev10, index=0) fails; then all 5 templatev10 bodies fail,
    # then template[0] succeeds
    sdk.set_device_data.side_effect = [
        Exception("cached fail"),           # cached combo fails
        Exception("fail"), Exception("fail"), Exception("fail"),  # templatev10[0..2]
        Exception("fail"), Exception("fail"),                     # templatev10[3..4]
        None,                               # template[0] succeeds
    ]

    ok, errs = svc._push_templates(sdk, pin="1", templates=[make_template()], device_id=15)

    assert ok == 1
    profile = db_module.load_firmware_profile(device_id=15)
    assert profile["template_table"] == "template"


# ---------------------------------------------------------------------------
# F9: a malformed record must not abort the OTHER templates for the same pin.
#
# The loop head used to be a bare `int(t.get("fingerId"))` / 
# `int(t.get("templateVersion") or 10)`. A None fingerId raises TypeError and a
# truthy non-numeric templateVersion raises ValueError -- note `or 10` does NOT
# guard the latter, because a non-empty string is truthy. Either exception
# escaped _push_templates entirely, so every VALID template later in the same
# list was silently never attempted.
#
# _compute_desired_hash (same file) and ultra_engine already guarded this field;
# _push_templates was the odd one out.
# ---------------------------------------------------------------------------

def test_push_templates_skips_invalid_fingerprint_and_continues_others(tmp_path, monkeypatch):
    """A bad fingerId is skipped AND reported -- it must not vanish, and must not
    take the pin's other fingers down with it."""
    svc, _db = make_engine(tmp_path, monkeypatch)

    sdk = MagicMock()
    sdk.set_device_data.return_value = None

    bad = {"fingerId": None, "templateVersion": 10, "templateSize": 500,
           "templateData": "AABBCC"}
    ok, errs = svc._push_templates(sdk, pin="1", templates=[bad, make_template(fid=1)],
                                   device_id=50)

    # the valid record still got pushed
    assert ok == 1
    assert sdk.set_device_data.call_count == 1

    # and the bad one is REPORTED, not silently dropped -- this is what lets F0
    # count it as a failed sync rather than stamping the pin SUCCESS.
    assert len(errs) == 1
    assert "invalid fingerId" in errs[0]


def test_push_templates_defaults_non_numeric_template_version_to_10(tmp_path, monkeypatch):
    """templateVersion only biases which table is tried FIRST; the probe loop tries
    both regardless. So a junk version must not cost the member their fingerprint."""
    svc, _db = make_engine(tmp_path, monkeypatch)

    sdk = MagicMock()
    sdk.set_device_data.return_value = None

    junk = {"fingerId": 2, "templateVersion": "v10", "templateSize": 500,
            "templateData": "AABBCC"}
    ok, errs = svc._push_templates(sdk, pin="1", templates=[junk], device_id=51)

    assert ok == 1
    assert errs == []


def test_push_templates_reports_every_invalid_record(tmp_path, monkeypatch):
    """Two bad records produce two error entries -- the count must not collapse."""
    svc, _db = make_engine(tmp_path, monkeypatch)

    sdk = MagicMock()
    sdk.set_device_data.return_value = None

    templates = [
        {"fingerId": None, "templateVersion": 10, "templateSize": 5, "templateData": "AA"},
        {"fingerId": "finger-three", "templateVersion": 10, "templateSize": 5, "templateData": "AA"},
        make_template(fid=4),
    ]
    ok, errs = svc._push_templates(sdk, pin="1", templates=templates, device_id=52)

    assert ok == 1
    assert len(errs) == 2

