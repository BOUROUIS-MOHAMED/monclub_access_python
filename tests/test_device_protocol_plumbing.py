"""End-to-end survival tests for the two new per-device sync fields.

The deviceProtocol chain is 5 hops (backend column -> Java mappers -> ACCESS
ingest INSERT -> sync_devices column -> payload projection -> factory) and every
hop silently defaults to ZK_PULLSDK — the exact failure family of the past
membersType incident (field existed on the backend but one mapper dropped it,
so the desktop never saw it). These tests pin the ACCESS-side hops: a device
dict as the backend would send it must survive ingest -> projection -> the
driver factory's protocol resolution. Same for the door-preset ``direction``
(entry-vs-exit) field that the 3-turnstile MB2000 gym depends on.
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "plumb.db"), raising=False)
    db_module.init_db()
    return db_module


def _device(**extra):
    d = {
        "id": 42,
        "name": "Entree 1",
        "ipAddress": "192.168.1.50",
        "portNumber": 4370,
        "accessDataMode": "ULTRA",
        "doorPresets": [
            {
                "id": 900,
                "deviceId": 42,
                "doorNumber": 1,
                "pulseSeconds": 3,
                "doorName": "Lane 1",
                "direction": "OUT",
            }
        ],
    }
    d.update(extra)
    return d


def _ingest(db, device):
    with db.get_conn() as conn:
        cur = conn.cursor()
        db._insert_device_row(cur, device)
        conn.commit()


class TestDeviceProtocolSurvival:
    def test_standalone_protocol_survives_ingest_to_factory(self, db):
        _ingest(db, _device(deviceProtocol="ZK_STANDALONE"))

        payload = db.list_sync_devices_payload()
        assert len(payload) == 1
        assert payload[0]["deviceProtocol"] == "ZK_STANDALONE"

        from app.sdk.device_driver import DeviceProtocol, resolve_device_protocol
        assert resolve_device_protocol(payload[0]) == DeviceProtocol.ZK_STANDALONE

    def test_absent_protocol_defaults_to_pullsdk(self, db):
        _ingest(db, _device())  # no deviceProtocol key — today's reality

        payload = db.list_sync_devices_payload()
        assert payload[0]["deviceProtocol"] is None

        from app.sdk.device_driver import DeviceProtocol, resolve_device_protocol
        assert resolve_device_protocol(payload[0]) == DeviceProtocol.ZK_PULLSDK

    def test_get_single_device_payload_carries_protocol(self, db):
        _ingest(db, _device(deviceProtocol="ZK_STANDALONE"))
        p = db.get_sync_device_payload(42)
        assert p is not None
        assert p["deviceProtocol"] == "ZK_STANDALONE"

    def test_protocol_is_normalized_uppercase(self, db):
        _ingest(db, _device(deviceProtocol="zk_standalone"))
        payload = db.list_sync_devices_payload()
        assert payload[0]["deviceProtocol"] == "ZK_STANDALONE"


class TestRosterPushingPolicySurvival:
    """Same failure family as deviceProtocol: the per-device rosterPushingPolicy must
    survive ingest INSERT -> sync_devices column -> payload projection, or the desktop
    silently reads null and the MIRROR reconcile stays PRESERVE. Also guards the
    sync_devices INSERT column/value alignment (a prior off-by-one lived here)."""

    def test_mirror_policy_survives_ingest_to_payload(self, db):
        _ingest(db, _device(rosterPushingPolicy="MIRROR"))
        payload = db.list_sync_devices_payload()
        assert len(payload) == 1
        assert payload[0]["rosterPushingPolicy"] == "MIRROR"
        # deviceProtocol on the SAME row must still be correct (alignment guard)
        assert payload[0]["deviceProtocol"] is None

    def test_absent_policy_defaults_to_none(self, db):
        _ingest(db, _device())  # no rosterPushingPolicy key
        payload = db.list_sync_devices_payload()
        assert payload[0]["rosterPushingPolicy"] is None

    def test_policy_is_normalized_uppercase(self, db):
        _ingest(db, _device(rosterPushingPolicy="mirror"))
        payload = db.list_sync_devices_payload()
        assert payload[0]["rosterPushingPolicy"] == "MIRROR"

    def test_get_single_device_payload_carries_policy(self, db):
        _ingest(db, _device(rosterPushingPolicy="MIRROR"))
        p = db.get_sync_device_payload(42)
        assert p is not None and p["rosterPushingPolicy"] == "MIRROR"

    def test_policy_and_protocol_coexist_on_one_row(self, db):
        """Both new columns set together must project independently (no INSERT skew)."""
        _ingest(db, _device(deviceProtocol="ZK_STANDALONE", rosterPushingPolicy="MIRROR"))
        p = db.list_sync_devices_payload()[0]
        assert p["deviceProtocol"] == "ZK_STANDALONE"
        assert p["rosterPushingPolicy"] == "MIRROR"


class TestPresetDirectionSurvival:
    def test_direction_survives_to_device_payload_presets(self, db):
        _ingest(db, _device())
        payload = db.list_sync_devices_payload(include_door_presets=True)
        presets = payload[0].get("doorPresets") or payload[0].get("door_presets") or []
        assert len(presets) == 1
        assert presets[0]["direction"] == "OUT"

    def test_direction_survives_to_preset_payload(self, db):
        _ingest(db, _device())
        presets = db.list_sync_device_door_presets_payload(42)
        assert len(presets) == 1
        assert presets[0]["direction"] == "OUT"

    def test_absent_direction_is_none_not_crash(self, db):
        d = _device()
        del d["doorPresets"][0]["direction"]
        _ingest(db, d)
        presets = db.list_sync_device_door_presets_payload(42)
        assert presets[0]["direction"] is None


class TestLocalProtocolOverride:
    """The bring-up/kill-switch: a desktop-side device_id->protocol map that wins
    over the backend payload (D10 in the MB2000 plan)."""

    @pytest.fixture(autouse=True)
    def _clean_overrides(self):
        import app.sdk.device_driver as dd
        # isolate: clear programmatic overrides and force env re-read per test
        with dd._overrides_lock:
            dd._protocol_overrides.clear()
        dd._env_overrides_loaded = False
        yield
        with dd._overrides_lock:
            dd._protocol_overrides.clear()
        dd._env_overrides_loaded = False

    def test_override_wins_over_payload(self):
        from app.sdk.device_driver import (
            DeviceProtocol, resolve_device_protocol, set_protocol_override,
        )
        set_protocol_override(7, "ZK_STANDALONE")
        assert resolve_device_protocol({"id": 7}) == DeviceProtocol.ZK_STANDALONE

    def test_override_kill_switch_back_to_pullsdk(self):
        # A device whose PAYLOAD says standalone can be forced back to PullSDK
        # (or effectively disabled) locally without a backend round-trip.
        from app.sdk.device_driver import (
            DeviceProtocol, resolve_device_protocol, set_protocol_override,
        )
        payload = {"id": 7, "deviceProtocol": "ZK_STANDALONE"}
        assert resolve_device_protocol(payload) == DeviceProtocol.ZK_STANDALONE
        set_protocol_override(7, "ZK_PULLSDK")
        assert resolve_device_protocol(payload) == DeviceProtocol.ZK_PULLSDK

    def test_clear_override_restores_payload(self):
        from app.sdk.device_driver import (
            DeviceProtocol, resolve_device_protocol, set_protocol_override,
        )
        payload = {"id": 7, "deviceProtocol": "ZK_STANDALONE"}
        set_protocol_override(7, "ZK_PULLSDK")
        set_protocol_override(7, None)
        assert resolve_device_protocol(payload) == DeviceProtocol.ZK_STANDALONE

    def test_env_var_overrides(self, monkeypatch):
        import app.sdk.device_driver as dd
        monkeypatch.setenv(dd._OVERRIDES_ENV_VAR, '{"12": "ZK_STANDALONE"}')
        assert dd.resolve_device_protocol({"id": 12}) == dd.DeviceProtocol.ZK_STANDALONE
        # other devices unaffected
        assert dd.resolve_device_protocol({"id": 13}) == dd.DeviceProtocol.ZK_PULLSDK

    def test_malformed_env_ignored(self, monkeypatch):
        import app.sdk.device_driver as dd
        monkeypatch.setenv(dd._OVERRIDES_ENV_VAR, "{not json")
        assert dd.resolve_device_protocol({"id": 12}) == dd.DeviceProtocol.ZK_PULLSDK
