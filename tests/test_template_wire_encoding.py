"""Both device wires take BASE64 ASCII. A HEX-stored template must be converted (F5).

THE DEFECT
----------
The backend stores a fingerprint's ``TemplateEncoding`` per row and, before the
matching backend release, delivered a HEX row as hex TEXT. The Access client then
dropped the encoding entirely -- ``_collect_templates_for_pin`` emitted only
``{fingerId, templateVersion, templateData, templateSize}`` and never read
``templateEncoding`` -- and copied that text verbatim onto a device field that
accepts nothing but base64:

  * PullSDK  ``Template=`` in templatev10/template
  * zkemkeeper ``SetUserTmpExStr``

So the terminal received a template it could never match. The member is refused at
the door while Access reports the push as done. On the standalone driver it is
actively misdiagnosed: the refusal warning blames "store full" or "version
mismatch" and never considers encoding.

HEX is reachable in production through the GMS legacy migration
(``CsvLegacySourceAdapter`` accepts HEX, ``GmsMigrationService`` persists
``TemplateEncoding.HEX``) -- i.e. exactly the migrated gyms.

WHY THE CLIENT HALF IS NOT OPTIONAL
-----------------------------------
The backend fix (always emit BASE64 on the Access wire) repairs FUTURE deliveries
only. ``GymAccessController.buildDeltaChangedAmIds`` keys the delta on
``updatedAt`` timestamps, and changing an ENCODER bumps no row timestamp, so no
member re-enters the delta. The watermark also lives in the client's SQLite, so a
restart does not force a refresh. A gym whose HEX rows were already delivered
keeps a poisoned cache indefinitely -- and this conversion is what repairs it.

Deployment order is free and double conversion is impossible: once the backend
sends ``templateEncoding="BASE64"``, ``_template_wire`` passes the data through.

TOLERANT DECODE
---------------
The backend's own hex decoder accepts a ``0x`` prefix and embedded whitespace
(pinned by its ``GmsFingerprintDecodeTest``), while ``bytes.fromhex`` rejects
both. Accepting less than the backend did would drop templates the backend
considered valid, so the decode here is deliberately as tolerant.
"""
from __future__ import annotations

import base64
import logging
from unittest.mock import MagicMock

import pytest

from app.core.device_sync import DeviceSyncEngine, _template_wire


RAW = bytes([0x00, 0x01, 0xAB, 0xFF, 0x10, 0x7F])
HEX = RAW.hex()                    # "0001abff107f"
B64 = base64.b64encode(RAW).decode("ascii")


class TestTemplateWire:
    def test_hex_becomes_base64_and_reports_the_byte_count(self):
        text, nbytes = _template_wire(HEX, "HEX")
        assert text == B64
        assert nbytes == len(RAW)

    def test_base64_passes_through_untouched(self):
        text, nbytes = _template_wire(B64, "BASE64")
        assert text == B64
        assert nbytes is None, "no decode happened, so there is no byte count to report"

    @pytest.mark.parametrize("enc", [None, "", "   ", "base64", "BASE64", "unknown"])
    def test_anything_that_is_not_hex_passes_through(self, enc):
        """The historical contract for every already-deployed row, and for
        templates that carry no encoding at all."""
        assert _template_wire(B64, enc) == (B64, None)

    def test_encoding_is_matched_case_insensitively(self):
        assert _template_wire(HEX, "hex")[0] == B64
        assert _template_wire(HEX, " Hex ")[0] == B64

    def test_decode_is_as_tolerant_as_the_backends_own_decoder(self):
        """The backend accepts "0x" and whitespace; bytes.fromhex does not.
        Rejecting what the backend accepted would drop a valid template."""
        assert _template_wire("0x0001abff107f", "HEX")[0] == B64
        assert _template_wire("00 01 ab ff 10 7f", "HEX")[0] == B64
        assert _template_wire("0001abff\n107f", "HEX")[0] == B64

    def test_undecodable_hex_raises_so_the_caller_can_drop_it(self):
        with pytest.raises(Exception):
            _template_wire("nothexatall!!", "HEX")
        with pytest.raises(Exception):
            _template_wire("4af", "HEX")  # odd length


class TestCollectAppliesTheWireEncoding:
    @pytest.fixture()
    def engine(self):
        return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))

    def _collect(self, engine, fp):
        return engine._collect_templates_for_pin(
            user={"fingerprints": [fp]}, pin="1001",
            local_fp_index={}, fingerprint_enabled=True,
        )

    def test_a_hex_template_reaches_the_device_as_base64(self, engine):
        got = self._collect(engine, {
            "fingerId": 6, "templateVersion": 10, "templateEncoding": "HEX",
            "templateData": HEX, "templateSize": len(RAW), "enabled": True,
        })
        assert len(got) == 1
        assert got[0]["templateData"] == B64
        assert got[0]["templateData"] != HEX

    def test_a_base64_template_is_untouched(self, engine):
        got = self._collect(engine, {
            "fingerId": 6, "templateVersion": 10, "templateEncoding": "BASE64",
            "templateData": B64, "templateSize": len(RAW), "enabled": True,
        })
        assert got[0]["templateData"] == B64

    def test_a_template_with_no_encoding_key_is_untouched(self, engine):
        """Every payload shipped before this change omits the key."""
        got = self._collect(engine, {
            "fingerId": 6, "templateVersion": 10,
            "templateData": B64, "templateSize": len(RAW), "enabled": True,
        })
        assert got[0]["templateData"] == B64

    def test_an_undecodable_hex_template_is_dropped_not_pushed(self, engine):
        """Pushing garbage would occupy the finger slot with something that can
        never match. Dropping is the lesser evil -- and it is logged."""
        got = self._collect(engine, {
            "fingerId": 6, "templateVersion": 10, "templateEncoding": "HEX",
            "templateData": "zzzznothex", "templateSize": 6, "enabled": True,
        })
        assert got == []

    def test_a_hex_row_with_no_templateSize_reports_the_DECODED_length(self, engine):
        """F4's concern on the hex path: falling back to len(text) would send the
        device a Size of 12 for a 6-byte template."""
        got = self._collect(engine, {
            "fingerId": 6, "templateVersion": 10, "templateEncoding": "HEX",
            "templateData": HEX, "enabled": True,
        })
        assert got[0]["templateSize"] == len(RAW), "must be 6, not len('0001abff107f')==12"

    def test_one_bad_template_does_not_take_the_good_one_with_it(self, engine):
        got = engine._collect_templates_for_pin(
            user={"fingerprints": [
                {"fingerId": 6, "templateVersion": 10, "templateEncoding": "HEX",
                 "templateData": "zzzznothex", "templateSize": 6, "enabled": True},
                {"fingerId": 2, "templateVersion": 10, "templateEncoding": "HEX",
                 "templateData": HEX, "templateSize": len(RAW), "enabled": True},
            ]},
            pin="1001", local_fp_index={}, fingerprint_enabled=True,
        )
        assert [g["fingerId"] for g in got] == [2]
        assert got[0]["templateData"] == B64


class TestTemplateSizeIsTheByteCount:
    """F4: `Size=` describes the payload, so it must be the DECODED byte count.

    The fallback used to be `len(td)` -- the ENCODED text length. A 512-byte
    template reported 684 (base64) or 1024 (hex), so the device was handed a length
    field that disagreed with the data beside it. 3 of the 5 probed body formats
    include `Size=`, so a wrong value reaches firmware in the majority of them.

    Only reachable when the server omits templateSize (backend rows have it NOT
    NULL), which is why the decode is lazy.
    """

    @pytest.fixture()
    def engine(self):
        return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))

    def _size(self, engine, fp):
        got = engine._collect_templates_for_pin(
            user={"fingerprints": [fp]}, pin="1001",
            local_fp_index={}, fingerprint_enabled=True,
        )
        return got[0]["templateSize"] if got else None

    def test_base64_without_templateSize_reports_bytes_not_chars(self, engine):
        big = bytes(range(256)) * 2                    # a realistic 512-byte template
        b64 = base64.b64encode(big).decode("ascii")
        assert len(b64) == 684                         # the value that used to be sent
        got = self._size(engine, {"fingerId": 6, "templateVersion": 10,
                                  "templateData": b64, "enabled": True})
        assert got == 512

    def test_hex_without_templateSize_reports_bytes_not_chars(self, engine):
        got = self._size(engine, {"fingerId": 6, "templateVersion": 10,
                                  "templateEncoding": "HEX", "templateData": HEX,
                                  "enabled": True})
        assert got == len(RAW)

    def test_an_explicit_templateSize_is_still_honoured(self, engine):
        """The server's value wins; we do not second-guess it."""
        got = self._size(engine, {"fingerId": 6, "templateVersion": 10,
                                  "templateData": B64, "templateSize": 999,
                                  "enabled": True})
        assert got == 999

    def test_undecodable_base64_falls_back_to_text_length(self, engine):
        """A wrong Size beats dropping a template that might otherwise work."""
        got = self._size(engine, {"fingerId": 6, "templateVersion": 10,
                                  "templateData": "!!!not base64!!!", "enabled": True})
        assert got == len("!!!not base64!!!")
