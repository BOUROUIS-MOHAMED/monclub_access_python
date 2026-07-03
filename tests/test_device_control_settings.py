"""Slice 1 of the per-device control panel: read-only device-settings scan.

_read_device_control_settings parses Door{N}Intertime (re-entry interval, seconds)
and computes RTC drift vs the PC. It must work against BOTH SDK class surfaces
(PullSDK and PullSDKDevice) — it only uses get_device_param + supports_*.
"""
from __future__ import annotations

import time

from app.api import local_access_api_v2 as v2
from app.sdk.pullsdk import zk_datetime_encode


class _FakeSDK:
    def __init__(self, raw, supports=True):
        self._raw = raw
        self._supports = supports
        self.items_seen = []

    def supports_get_device_param(self):
        return self._supports

    def get_device_param(self, *, items, initial_size=None):
        self.items_seen.append(items)
        return self._raw


def _enc_behind(seconds):
    lt = time.localtime(time.time() - seconds)
    return zk_datetime_encode(lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec)


def test_parse_param_kv_handles_crlf_and_commas():
    kv = v2._parse_device_param_kv("Door1Intertime=30\r\nDoor2Intertime=0,DateTime=123")
    assert kv == {"Door1Intertime": "30", "Door2Intertime": "0", "DateTime": "123"}


def test_read_settings_doors_and_drift():
    raw = f"Door1Intertime=30\r\nDoor2Intertime=30\r\nDateTime={_enc_behind(74)}"
    out = v2._read_device_control_settings(_FakeSDK(raw))
    assert out["doors"] == [
        {"doorNumber": 1, "intertimeSec": 30},
        {"doorNumber": 2, "intertimeSec": 30},
    ]
    assert 70 <= out["clock"]["driftSec"] <= 78  # device behind PC ~74s


def test_read_settings_off_is_zero():
    raw = f"Door1Intertime=0\r\nDoor2Intertime=0\r\nDateTime={_enc_behind(0)}"
    out = v2._read_device_control_settings(_FakeSDK(raw))
    assert out["doors"] == [
        {"doorNumber": 1, "intertimeSec": 0},
        {"doorNumber": 2, "intertimeSec": 0},
    ]
    assert abs(out["clock"]["driftSec"]) <= 3


def test_read_settings_unsupported_param():
    out = v2._read_device_control_settings(_FakeSDK("", supports=False))
    assert out == {"doors": [], "clock": {}}


def test_read_settings_only_present_doors():
    # a 2-door C3-200 returns only doors 1 and 2 (no Door3/Door4)
    raw = f"Door1Intertime=15\r\nDoor2Intertime=15\r\nDateTime={_enc_behind(5)}"
    out = v2._read_device_control_settings(_FakeSDK(raw))
    assert [d["doorNumber"] for d in out["doors"]] == [1, 2]


def test_handler_and_helpers_exist():
    # route registration binds these by name via getattr(module, name)
    assert callable(getattr(v2, "_handle_device_settings_get", None))
    assert callable(getattr(v2, "_read_device_control_settings", None))
    assert callable(getattr(v2, "_parse_device_param_kv", None))


# ---------------------------------------------------------------------------
# Slice 2: apply the re-entry block (device Door{N}Intertime + software anti_fraude).
# ---------------------------------------------------------------------------
def test_device_door_numbers_fallback(monkeypatch):
    import app.core.db as db
    monkeypatch.setattr(db, "list_sync_device_door_presets_payload", lambda did: [])
    assert v2._device_door_numbers(123) == [1, 2]  # C3-200 default


def test_device_door_numbers_from_presets(monkeypatch):
    import app.core.db as db
    monkeypatch.setattr(
        db, "list_sync_device_door_presets_payload",
        lambda did: [{"doorNumber": 2}, {"doorNumber": 1}, {"doorNumber": 1}],
    )
    assert v2._device_door_numbers(123) == [1, 2]  # unique + sorted


def test_verify_reentry_readback():
    rb = {"doors": [{"doorNumber": 1, "intertimeSec": 30}, {"doorNumber": 2, "intertimeSec": 30}]}
    assert v2._verify_reentry_readback(rb, [1, 2], 30) is True
    assert v2._verify_reentry_readback(rb, [1, 2], 15) is False        # device didn't take it
    assert v2._verify_reentry_readback({"doors": []}, [1, 2], 0) is False  # nothing read back
    assert v2._verify_reentry_readback(rb, [], 30) is False            # no doors targeted


class _FakeWorker:
    def __init__(self, settings):
        self._settings = settings
        self._device = {"id": 7}
        self.captured = None

    def update_device(self, device, settings):
        self.captured = settings


def test_apply_software_reentry_enabled_sets_toggles_and_duration():
    w = _FakeWorker({"anti_fraude_qr_code": False, "anti_fraude_card": False,
                     "anti_fraude_duration": 5, "other": 1})
    assert v2._apply_software_reentry(w, True, 30) is True
    s = w.captured
    assert s["anti_fraude_qr_code"] is True and s["anti_fraude_card"] is True
    assert s["anti_fraude_duration"] == 30
    assert s["other"] == 1  # untouched settings preserved


def test_apply_software_reentry_disabled_turns_off():
    w = _FakeWorker({"anti_fraude_qr_code": True, "anti_fraude_card": True, "anti_fraude_duration": 30})
    assert v2._apply_software_reentry(w, False, 0) is True
    assert w.captured["anti_fraude_qr_code"] is False
    assert w.captured["anti_fraude_card"] is False


def test_apply_device_side_set_then_readback_verifies():
    # mirrors the handler's _apply: set_device_param(items) then read-back + verify
    sets = []

    class FakeSDK:
        def supports_set_device_param(self):
            return True

        def supports_get_device_param(self):
            return True

        def set_device_param(self, *, items):
            sets.append(items)
            return 0

        def get_device_param(self, *, items, initial_size=None):
            lt = time.localtime(time.time())
            enc = zk_datetime_encode(lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec)
            return f"Door1Intertime=30\r\nDoor2Intertime=30\r\nDateTime={enc}"

    sdk = FakeSDK()
    items = ",".join(f"Door{n}Intertime=30" for n in (1, 2))
    sdk.set_device_param(items=items)
    rb = v2._read_device_control_settings(sdk)
    assert sets == ["Door1Intertime=30,Door2Intertime=30"]
    assert v2._verify_reentry_readback(rb, [1, 2], 30) is True


# ---------------------------------------------------------------------------
# Slice 3: clock control (drift + sync) and backend persistence.
# ---------------------------------------------------------------------------
class _ClockSDK:
    def __init__(self, behind_sec=0.0, supports=True):
        self._behind = behind_sec
        self._supports = supports
        self.sets = []

    def supports_get_device_param(self):
        return self._supports

    def supports_set_device_param(self):
        return self._supports

    def get_device_param(self, *, items, initial_size=None):
        lt = time.localtime(time.time() - self._behind)
        return f"DateTime={zk_datetime_encode(lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec)}"

    def set_device_param(self, *, items):
        self.sets.append(items)
        self._behind = 0.0  # syncing brings the device to ~now
        return 0


def test_read_device_clock_drift():
    out = v2._read_device_clock(_ClockSDK(behind_sec=74.0))
    assert 70 <= out["driftSec"] <= 78


def test_read_device_clock_unsupported():
    assert v2._read_device_clock(_ClockSDK(supports=False)) == {}


def test_sync_device_clock_sets_then_reads_back():
    sdk = _ClockSDK(behind_sec=74.0)
    out = v2._sync_device_clock(sdk)
    assert len(sdk.sets) == 1 and sdk.sets[0].startswith("DateTime=")
    assert abs(out["driftSec"]) <= 3  # device now ~aligned with PC


def test_sync_device_clock_unsupported_raises():
    import pytest
    with pytest.raises(RuntimeError):
        v2._sync_device_clock(_ClockSDK(supports=False))


def _make_api():
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app.api.monclub_api import MonClubApi
    api = MonClubApi.__new__(MonClubApi)
    api.endpoints = SimpleNamespace(login_url="https://monclubwigo.tn/api/v1/auth/login")
    api.logger = MagicMock()
    api._session = MagicMock()
    return api


def _resp(status, payload):
    from unittest.mock import MagicMock
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload
    r.text = ""
    return r


def test_update_device_control_settings_patches_only_antifraude_and_preserves_rest():
    api = _make_api()
    full = {"id": 7, "name": "Turnstile", "ipAddress": "1.2.3.4", "doorIds": [1, 2],
            "antiFraudeCard": False, "antiFraudeQrCode": False, "antiFraudeDuration": 5, "keep": "x"}
    api._session.post.side_effect = [_resp(200, full), _resp(200, {"ok": True})]
    out = api.update_device_control_settings(
        token="t", device_id=7, anti_fraude_card=True, anti_fraude_qr_code=True, anti_fraude_duration=30,
    )
    assert out == {"ok": True}
    get_call, upd_call = api._session.post.call_args_list
    # Must include the /api/v1 prefix (the backend serves /api/v1/connected/**;
    # hitting the bare host 405s at nginx) — uses _derive_api_base(), not host-only.
    assert get_call.args[0] == "https://monclubwigo.tn/api/v1/connected/gym-device/get/7"
    assert upd_call.args[0] == "https://monclubwigo.tn/api/v1/connected/gym-device/update"
    sent = upd_call.kwargs["json"]
    assert sent["antiFraudeCard"] is True and sent["antiFraudeQrCode"] is True
    assert sent["antiFraudeDuration"] == 30
    # every other field preserved (full-model round-trip, no field loss)
    assert sent["name"] == "Turnstile" and sent["ipAddress"] == "1.2.3.4" and sent["keep"] == "x"


def test_update_device_control_settings_clamps_duration_to_backend_range():
    api = _make_api()
    api._session.post.side_effect = [_resp(200, {"id": 7}), _resp(200, {"ok": True})]
    api.update_device_control_settings(token="t", device_id=7, anti_fraude_card=True,
                                       anti_fraude_qr_code=True, anti_fraude_duration=400)
    assert api._session.post.call_args_list[1].kwargs["json"]["antiFraudeDuration"] == 300


def test_update_device_control_settings_raises_on_http_error():
    from app.api.monclub_api import MonClubApiHttpError
    import pytest
    api = _make_api()
    api._session.post.side_effect = [_resp(403, {})]
    with pytest.raises(MonClubApiHttpError):
        api.update_device_control_settings(token="t", device_id=7, anti_fraude_card=True,
                                           anti_fraude_qr_code=True, anti_fraude_duration=30)
