"""The admin single-user push uses the SHARED engine, not a weaker fork of it (F10).

WHAT WAS WRONG
--------------
``_handle_device_users_push`` (POST /api/v2/devices/{id}/users/push) reimplemented
template pushing badly:

  * ONE table and ONE body format, chosen by ``ver >= 10``, versus the shared
    ``DeviceSyncEngine._push_templates``' ten probed combinations plus the
    firmware-profile fast-path cache;
  * never consulted ``deviceCapabilities.fingerprintTemplateVersion``;
  * no pre-delete, so a firmware with a silent-upsert failure kept the old template;
  * ``Size=0`` sent verbatim when the caller omitted templateSize;
  * and it returned ``{"ok": true}`` even when it pushed **nothing** -- the same
    "reported success, member can't open the door" defect F0 fixed on the sync paths.

So a member pushed through the admin action could be reported fine and still be
refused at the door, on firmware the main sync handles correctly.

The fix delegates to the shared method. Two deliberate choices:

  * **fingerId is NOT coerced.** An earlier draft mapped a missing fingerId to slot
    0 so the request could report "2/2 pushed". That writes a biometric to a finger
    the caller never named. F9 already makes the shared method skip AND report a bad
    record, so the honest answer is "1/2 pushed" plus an error.
  * **templateData is normalised through ``_template_wire``.** This handler is the
    one template path that does not flow through ``_collect_templates_for_pin``, so
    it is where a HEX template can still arrive -- straight off an HTTP body.
"""
from __future__ import annotations

import base64
import logging
from unittest.mock import MagicMock

import pytest


RAW = bytes([0x00, 0x01, 0xAB, 0xFF, 0x10, 0x7F])
HEXT = RAW.hex()
B64 = base64.b64encode(RAW).decode("ascii")


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    return db_module


def _run(monkeypatch, db, templates, *, auth_fails=False):
    """Drive the handler with a fake ctx and a recording SDK."""
    import app.api.local_access_api_v2 as v2

    sent = {}
    sdk = MagicMock()
    sdk.set_device_data.return_value = None
    sdk.supports_delete_device_data.return_value = True

    if auth_fails:
        def _sd(table=None, data=None, options=None, **kw):
            if table == "userauthorize":
                raise RuntimeError("authorize refused")
            return None
        sdk.set_device_data.side_effect = _sd

    class _App:
        cfg = MagicMock()

    class _Ctx:
        app = _App()

        def param_int(self, _name):
            return 77

        def body(self):
            return {"pin": "1001", "name": "Jane", "cardNo": "123",
                    "doorIds": [1], "templates": templates}

        def send_json(self, status, payload):
            sent["status"] = status
            sent["payload"] = payload

    monkeypatch.setattr(v2, "_unsupported_for_protocol", lambda *a, **k: False)
    monkeypatch.setattr(v2, "_connect_device", lambda *a, **k: (sdk, None))

    v2._handle_device_users_push(_Ctx())
    return sent, sdk


def _tpl(**over):
    base = {"fingerId": 6, "templateVersion": 10, "templateSize": len(RAW),
            "templateData": B64}
    base.update(over)
    return base


def _pushed_payloads(sdk):
    """Every `data=` string handed to the device."""
    out = []
    for call in sdk.set_device_data.call_args_list:
        out.append(call.kwargs.get("data") or "")
    return out


class TestAdminPushDelegates:
    def test_a_good_template_is_pushed_and_reported_ok(self, monkeypatch, db):
        sent, sdk = _run(monkeypatch, db, [_tpl()])

        assert sent["payload"]["ok"] is True
        assert sent["payload"]["templateResult"] == "1/1 pushed"
        assert sent["payload"]["errors"] == []

    def test_a_missing_fingerId_does_not_abort_the_other_templates(self, monkeypatch, db):
        """1/2, not 2/2: the bad record is skipped AND reported, never invented
        into finger slot 0."""
        sent, sdk = _run(monkeypatch, db, [
            {"templateVersion": 10, "templateSize": len(RAW), "templateData": B64},
            _tpl(fingerId=2),
        ])

        assert sent["payload"]["templateResult"] == "1/2 pushed"
        assert len(sent["payload"]["errors"]) == 1
        assert "fingerId" in sent["payload"]["errors"][0]
        assert sent["payload"]["ok"] is False

    def test_ok_is_false_when_nothing_landed(self, monkeypatch, db):
        """Reporting ok:true on a failed push is the defect F0 fixed elsewhere."""
        sent, sdk = _run(monkeypatch, db, [
            {"templateVersion": 10, "templateData": B64},  # no fingerId
        ])
        assert sent["payload"]["ok"] is False
        assert sent["payload"]["templateResult"] == "0/1 pushed"

    def test_ok_is_false_when_authorize_failed(self, monkeypatch, db):
        sent, sdk = _run(monkeypatch, db, [_tpl()], auth_fails=True)
        assert sent["payload"]["ok"] is False
        assert sent["payload"]["authResult"] != "OK"

    def test_a_hex_template_is_converted_before_it_reaches_the_device(self, monkeypatch, db):
        """This endpoint bypasses _collect_templates_for_pin, so it needs its own
        normalisation or a migrated gym's template goes to the device as hex."""
        sent, sdk = _run(monkeypatch, db, [
            _tpl(templateEncoding="HEX", templateData=HEXT),
        ])

        payloads = " ".join(_pushed_payloads(sdk))
        assert f"Template={B64}" in payloads
        assert HEXT not in payloads
        assert sent["payload"]["ok"] is True

    def test_an_undecodable_hex_template_is_reported_not_pushed(self, monkeypatch, db):
        sent, sdk = _run(monkeypatch, db, [
            _tpl(templateEncoding="HEX", templateData="zzznothex"),
        ])
        assert sent["payload"]["templateResult"] == "0/1 pushed"
        assert sent["payload"]["ok"] is False
        assert "decodable hex" in sent["payload"]["errors"][0]

    def test_size_is_no_longer_hardcoded_to_zero(self, monkeypatch, db):
        """The fork sent Size=0 whenever the caller omitted templateSize."""
        sent, sdk = _run(monkeypatch, db, [
            {"fingerId": 6, "templateVersion": 10, "templateData": B64},
        ])
        payloads = " ".join(_pushed_payloads(sdk))
        assert "Size=0\t" not in payloads
        assert sent["payload"]["ok"] is True
