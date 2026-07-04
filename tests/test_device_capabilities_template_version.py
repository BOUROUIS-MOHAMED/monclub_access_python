"""Per-device fingerprint template-version override (deviceCapabilities JSON).

The dashboard writes {"fingerprintTemplateVersion": 9|10} into the device's
opaque deviceCapabilities TEXT column. The desktop must:
  1. persist it through the sync_devices ingest and project it back as a parsed
     dict (db.py) — same survival family as the deviceProtocol chain;
  2. normalize it to fingerprint_template_version (settings_reader);
  3. use it in device_sync._push_templates to BIAS the preferred template-table
     order only — the firmware-profile cache and the probe fallback that tries
     BOTH tables stay exactly as they are.
"""
from __future__ import annotations

import importlib
import logging

import pytest
from unittest.mock import MagicMock


# ── settings_reader: parse + normalize ─────────────────────────────────────

class TestParseFingerprintTemplateVersion:
    def _parse(self, v):
        from app.core.settings_reader import parse_fingerprint_template_version
        return parse_fingerprint_template_version(v)

    def test_dict_input_value_9(self):
        assert self._parse({"fingerprintTemplateVersion": 9}) == 9

    def test_dict_input_value_10(self):
        assert self._parse({"fingerprintTemplateVersion": 10}) == 10

    def test_json_string_input(self):
        assert self._parse('{"fingerprintTemplateVersion": 9}') == 9

    def test_malformed_json_returns_none(self):
        assert self._parse("{not json") is None

    def test_absent_returns_none(self):
        assert self._parse(None) is None
        assert self._parse("") is None
        assert self._parse({}) is None

    def test_non_int_returns_none(self):
        assert self._parse({"fingerprintTemplateVersion": "abc"}) is None
        assert self._parse({"fingerprintTemplateVersion": True}) is None
        assert self._parse({"fingerprintTemplateVersion": None}) is None

    def test_out_of_range_returns_none(self):
        # Only 9 and 10 exist as template tables — anything else is ignored.
        assert self._parse({"fingerprintTemplateVersion": 12}) is None
        assert self._parse({"fingerprintTemplateVersion": 0}) is None

    def test_alternate_keys_accepted(self):
        assert self._parse({"template_version": 9}) == 9
        assert self._parse({"templateVersion": 10}) == 10

    def test_non_dict_json_returns_none(self):
        assert self._parse("[9]") is None
        assert self._parse("9") is None


class TestNormalizeDeviceSettings:
    def _norm(self, dev):
        from app.core.settings_reader import normalize_device_settings
        return normalize_device_settings(dev)

    def test_dict_capabilities(self):
        s = self._norm({"id": 1, "deviceCapabilities": {"fingerprintTemplateVersion": 9}})
        assert s["fingerprint_template_version"] == 9

    def test_json_string_capabilities(self):
        s = self._norm({"id": 1, "deviceCapabilities": '{"fingerprintTemplateVersion": 10}'})
        assert s["fingerprint_template_version"] == 10

    def test_malformed_json_is_none(self):
        s = self._norm({"id": 1, "deviceCapabilities": "{oops"})
        assert s["fingerprint_template_version"] is None

    def test_absent_is_none(self):
        s = self._norm({"id": 1})
        assert s["fingerprint_template_version"] is None

    def test_non_int_is_none(self):
        s = self._norm({"id": 1, "deviceCapabilities": {"fingerprintTemplateVersion": "x"}})
        assert s["fingerprint_template_version"] is None

    def test_snake_case_key_fallback(self):
        s = self._norm({"id": 1, "device_capabilities": '{"fingerprintTemplateVersion": 9}'})
        assert s["fingerprint_template_version"] == 9


# ── db.py: ingest -> projection round-trip ─────────────────────────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "caps.db"), raising=False)
    db_module.init_db()
    return db_module


def _device(**extra):
    d = {
        "id": 42,
        "name": "Entree 1",
        "ipAddress": "192.168.1.50",
        "portNumber": 4370,
        "accessDataMode": "ULTRA",
    }
    d.update(extra)
    return d


def _ingest(db, device):
    with db.get_conn() as conn:
        cur = conn.cursor()
        db._insert_device_row(cur, device)
        conn.commit()


class TestDeviceCapabilitiesSurvival:
    def test_json_string_survives_ingest_to_parsed_dict(self, db):
        _ingest(db, _device(deviceCapabilities='{"fingerprintTemplateVersion":9}'))

        payload = db.list_sync_devices_payload()
        assert len(payload) == 1
        assert payload[0]["deviceCapabilities"] == {"fingerprintTemplateVersion": 9}

    def test_dict_payload_survives_ingest_to_parsed_dict(self, db):
        _ingest(db, _device(deviceCapabilities={"fingerprintTemplateVersion": 10}))

        payload = db.list_sync_devices_payload()
        assert payload[0]["deviceCapabilities"] == {"fingerprintTemplateVersion": 10}

    def test_absent_capabilities_is_none_not_crash(self, db):
        _ingest(db, _device())  # no deviceCapabilities key — today's reality

        payload = db.list_sync_devices_payload()
        assert payload[0]["deviceCapabilities"] is None

    def test_malformed_stored_json_projects_none(self, db):
        _ingest(db, _device(deviceCapabilities="{not json"))

        payload = db.list_sync_devices_payload()
        assert payload[0]["deviceCapabilities"] is None

    def test_get_single_device_payload_carries_capabilities(self, db):
        _ingest(db, _device(deviceCapabilities='{"fingerprintTemplateVersion":9}'))
        p = db.get_sync_device_payload(42)
        assert p is not None
        assert p["deviceCapabilities"] == {"fingerprintTemplateVersion": 9}


# ── device_sync: preferred-order bias in _push_templates ──────────────────

def make_engine(tmp_path, monkeypatch):
    import app.core.db as db_module
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    from app.core.device_sync import DeviceSyncEngine
    logger = logging.getLogger("test")
    svc = DeviceSyncEngine(cfg=MagicMock(), logger=logger)
    return svc, db_module


def make_template(fid=0, version=10, size=500, data="AABBCC"):
    return {"fingerId": fid, "templateVersion": version, "templateSize": size, "templateData": data}


def test_override_9_biases_first_table_to_template(tmp_path, monkeypatch):
    """Device override=9 beats the per-record templateVersion=10: first probe
    attempt goes to 'template' (v9), not 'templatev10'."""
    svc, db_module = make_engine(tmp_path, monkeypatch)

    sdk = MagicMock()
    sdk.set_device_data.return_value = None  # first probe succeeds

    ok, errs = svc._push_templates(
        sdk, pin="1", templates=[make_template(version=10)], device_id=30,
        template_version_override=9,
    )

    assert ok == 1
    assert errs == []
    first_call = sdk.set_device_data.call_args_list[0]
    assert first_call.kwargs["table"] == "template"


def test_no_override_keeps_v10_first(tmp_path, monkeypatch):
    """Baseline unchanged: without an override a v10 record probes templatev10 first."""
    svc, db_module = make_engine(tmp_path, monkeypatch)

    sdk = MagicMock()
    sdk.set_device_data.return_value = None

    ok, _errs = svc._push_templates(
        sdk, pin="1", templates=[make_template(version=10)], device_id=31,
    )

    assert ok == 1
    first_call = sdk.set_device_data.call_args_list[0]
    assert first_call.kwargs["table"] == "templatev10"


def test_override_does_not_disable_probe_fallback(tmp_path, monkeypatch):
    """Override only reorders: if every 'template' body fails, the probe still
    falls through to 'templatev10' and caches the winner."""
    svc, db_module = make_engine(tmp_path, monkeypatch)

    sdk = MagicMock()
    # 5 bodies on 'template' fail, then 'templatev10' body 0 succeeds
    sdk.set_device_data.side_effect = [
        Exception("fail"), Exception("fail"), Exception("fail"),
        Exception("fail"), Exception("fail"),
        None,
    ]

    ok, errs = svc._push_templates(
        sdk, pin="1", templates=[make_template(version=10)], device_id=32,
        template_version_override=9,
    )

    assert ok == 1
    assert errs == []
    tables_tried = [c.kwargs["table"] for c in sdk.set_device_data.call_args_list]
    assert tables_tried == ["template"] * 5 + ["templatev10"]
    profile = db_module.load_firmware_profile(device_id=32)
    assert profile["template_table"] == "templatev10"


def test_override_leaves_cached_combo_fast_path_alone(tmp_path, monkeypatch):
    """The firmware-profile L1 cache still wins: a cached templatev10 combo is
    used as-is (1 SDK call) even when the override says 9."""
    svc, db_module = make_engine(tmp_path, monkeypatch)
    db_module.save_firmware_profile(device_id=33, template_table="templatev10",
                                    template_body_index=0, authorize_body_index=0)

    sdk = MagicMock()
    sdk.set_device_data.return_value = None

    ok, errs = svc._push_templates(
        sdk, pin="1", templates=[make_template(version=10)], device_id=33,
        template_version_override=9,
    )

    assert ok == 1
    assert errs == []
    assert sdk.set_device_data.call_count == 1
    assert sdk.set_device_data.call_args_list[0].kwargs["table"] == "templatev10"


def test_normalize_device_carries_override_from_capabilities(tmp_path, monkeypatch):
    """_normalize_device (the gate every sync path goes through) parses the
    deviceCapabilities JSON into fingerprintTemplateVersion."""
    svc, _db = make_engine(tmp_path, monkeypatch)

    nd = svc._normalize_device({
        "id": 7, "name": "D", "ipAddress": "10.0.0.1",
        "deviceCapabilities": '{"fingerprintTemplateVersion": 9}',
    })
    assert nd["fingerprintTemplateVersion"] == 9

    nd = svc._normalize_device({
        "id": 7, "deviceCapabilities": {"fingerprintTemplateVersion": 10},
    })
    assert nd["fingerprintTemplateVersion"] == 10

    nd = svc._normalize_device({"id": 7, "deviceCapabilities": "{oops"})
    assert nd["fingerprintTemplateVersion"] is None

    nd = svc._normalize_device({"id": 7})
    assert nd["fingerprintTemplateVersion"] is None
