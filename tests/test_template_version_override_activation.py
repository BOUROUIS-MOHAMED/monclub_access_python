"""The per-device fingerprint template-version dropdown finally takes effect (F1).

WHAT WAS WRONG
--------------
The dashboard has a real, user-facing setting -- Device settings -> "Fingerprint
template" -> AUTO / ZKFinger 9 / ZKFinger 10 -- stored as
``deviceCapabilities.fingerprintTemplateVersion``. It did nothing, for two
compounding reasons:

  a. **The per-pin desired hash ignored it.** ``_compute_desired_hash`` hashed the
     RECORD's templateVersion, never the effective one. Flipping the dropdown moved
     no pin's stored hash, so ``device_sync`` reported "sync skip: fingerprint
     unchanged" and pushed **nothing at all**.
  b. **The warm L1 firmware cache ignored it.** Even when a push happened for some
     other reason, the cached ``(template_table, body_index)`` combo was reused
     without consulting the override -- and that cached table is the very thing the
     setting is supposed to choose.

So on any device that had ever pushed a fingerprint, the dropdown was inert.

THE LEVER IS THE HASH, NOT THE HEADER
-------------------------------------
The obvious fix -- adding the field to the device-level checksum header -- makes the
sync RUN but select ZERO pins, because the per-pin gate (``device_sync_state`` vs
``_compute_desired_hash``) is what decides which pins move. Worse, it would force a
FULL roster re-push on every device carrying the setting, including devices where no
member's effective template version actually changed.

Putting it in the per-pin hash instead is both necessary and sufficient: it
propagates into the header-bearing checksum automatically, and it selects exactly
the pins that genuinely need re-pushing. ``test_the_checksum_header_itself_was_not_widened``
pins that the header stayed put.

ONE RESOLVER, FIVE SITES
------------------------
The push path and BOTH desired-hash paths must agree on the effective version. If
any site diverges, the stored hash never matches what the push produced and the pin
is re-pushed on every cycle forever. Hence
``DeviceSyncEngine._resolve_template_version_override`` as the single source.

THE PROBE IS UNCHANGED
----------------------
The override only biases which table is tried FIRST. The probe still tries both, so
a wrong setting costs one extra SDK call -- never a member who cannot badge in.
"""
from __future__ import annotations

import logging
import sqlite3
from unittest.mock import MagicMock

import pytest


def make_engine(tmp_path, monkeypatch, *, name="test.db"):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / name), raising=False)
    db_module.init_db()
    from app.core.device_sync import DeviceSyncEngine
    return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test")), db_module


def make_template(fid=6, version=10, size=500, data="AABBCC"):
    return {"fingerId": fid, "templateVersion": version,
            "templateSize": size, "templateData": data}


# ---------------------------------------------------------------------------
# The migration trap
# ---------------------------------------------------------------------------

class TestBiasColumnSurvivesTheRebuildMigration:
    """NT9 -- the only test that can catch this, because the failure is INVISIBLE
    on a fresh database.

    ``_relax_firmware_profiles_not_null`` rebuilds ``sync_firmware_profiles`` from a
    HARDCODED ``CREATE TABLE`` and a HARDCODED ``INSERT...SELECT`` column list,
    partway through ``init_db``. A column added by ``_ensure_column`` BEFORE it is
    silently dropped on any upgraded field DB still carrying the old NOT NULL
    constraints -- while every fresh-DB test passes, because a fresh DB gets the
    column from the ``CREATE TABLE`` later in ``init_db`` instead.

    Both paths are required and neither alone is enough. These tests pin both.
    """

    def _old_shape(self, path):
        conn = sqlite3.connect(path)
        conn.execute(
            """
            CREATE TABLE sync_firmware_profiles (
                device_id            INTEGER PRIMARY KEY,
                template_table       TEXT    NOT NULL,
                template_body_index  INTEGER NOT NULL,
                authorize_body_index INTEGER NOT NULL,
                updated_at           TEXT    NOT NULL
            );
            """
        )
        conn.execute("INSERT INTO sync_firmware_profiles VALUES (?,?,?,?,?)",
                     (7, "templatev10", 0, 0, "2026-01-01 00:00:00"))
        conn.commit()
        conn.close()

    def _cols(self, db_module):
        with db_module.get_conn() as conn:
            return {r["name"] for r in conn.execute("PRAGMA table_info(sync_firmware_profiles)")}

    def test_an_upgraded_database_gets_the_column(self, tmp_path, monkeypatch):
        import app.core.db as db_module
        path = str(tmp_path / "upgraded.db")
        self._old_shape(path)
        monkeypatch.setattr(db_module, "_DB_PATH", path, raising=False)
        db_module.init_db()

        assert "template_version_bias" in self._cols(db_module), (
            "the column must be added AFTER _relax_firmware_profiles_not_null, or "
            "that rebuild drops it on every upgraded field PC"
        )

    def test_the_upgrade_preserves_the_learned_combo(self, tmp_path, monkeypatch):
        """The rebuild must not cost a device its learned combo -- that would be a
        full re-probe on every field PC that upgrades."""
        import app.core.db as db_module
        path = str(tmp_path / "upgraded2.db")
        self._old_shape(path)
        monkeypatch.setattr(db_module, "_DB_PATH", path, raising=False)
        db_module.init_db()

        prof = db_module.load_firmware_profile(device_id=7)
        assert prof is not None
        assert prof["template_table"] == "templatev10"
        assert prof["template_version_bias"] == 0, "an upgraded row means 'no override'"

    def test_a_fresh_database_also_gets_the_column(self, tmp_path, monkeypatch):
        """The mirror case: init_db's CREATE TABLE runs AFTER the migration block,
        so on a fresh DB _ensure_column is a no-op and the CREATE TABLE is what
        carries the column."""
        import app.core.db as db_module
        monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "fresh.db"), raising=False)
        db_module.init_db()
        assert "template_version_bias" in self._cols(db_module)


# ---------------------------------------------------------------------------
# The lever
# ---------------------------------------------------------------------------

class TestTheOverrideReachesTheDesiredHash:
    def _hash(self, svc, override, templates=None):
        return svc._compute_desired_hash(
            pin="1001",
            user={"fullName": "Jane", "firstCardId": "123"},
            door_bitmask=1,
            templates=[make_template()] if templates is None else templates,
            authorize_timezone_id=1,
            template_version_override=override,
        )

    def test_flipping_the_override_changes_the_pin_hash(self, tmp_path, monkeypatch):
        svc, _ = make_engine(tmp_path, monkeypatch)
        assert self._hash(svc, 9) != self._hash(svc, 10), (
            "identical hashes are exactly why the setting did nothing"
        )

    def test_no_override_matches_the_records_own_version(self, tmp_path, monkeypatch):
        """Backward compatibility: a device with no dropdown value must hash exactly
        as it always did, or every member on every such device re-pushes once."""
        svc, _ = make_engine(tmp_path, monkeypatch)
        assert self._hash(svc, None) == self._hash(svc, 10), (
            "the template is v10, so an absent override must hash identically"
        )

    def test_a_member_with_no_templates_is_unaffected(self, tmp_path, monkeypatch):
        """Most members have no fingerprint at all. They must not re-push."""
        svc, _ = make_engine(tmp_path, monkeypatch)
        assert self._hash(svc, 9, templates=[]) == self._hash(svc, None, templates=[])

    def test_a_junk_template_version_still_hashes(self, tmp_path, monkeypatch):
        """The hash must use F9's guard form too, or it raises where the push path
        merely defaults -- and the 'mirrors _push_templates exactly' claim breaks."""
        svc, _ = make_engine(tmp_path, monkeypatch)
        junk = [{"fingerId": 6, "templateVersion": "v10",
                 "templateSize": 500, "templateData": "AABBCC"}]
        assert self._hash(svc, None, templates=junk) == self._hash(svc, 10, templates=junk)


class TestTheDeviceChecksum:
    def _dev(self, tv):
        return {"id": 7, "name": "Gate", "ipAddress": "10.0.0.1", "portNumber": 4370,
                "accessDataMode": "DEVICE", "fingerprintEnabled": True,
                "deviceCapabilities": {"fingerprintTemplateVersion": tv}}

    _USERS = [{
        "activeMembershipId": 1001, "userId": 1001, "fullName": "Jane",
        "firstCardId": "123",
        "fingerprints": [{"fingerId": 6, "templateVersion": 10, "templateData": "QUJD",
                          "templateSize": 3, "enabled": True}],
    }]

    def test_the_device_checksum_moves(self, tmp_path, monkeypatch):
        """End to end. This comparison returning EQUAL is the original defect: the
        sync reported 'unchanged' and never pushed."""
        svc, _ = make_engine(tmp_path, monkeypatch)
        h9, n9 = svc.build_device_sync_fingerprint(device=self._dev(9), users=self._USERS,
                                                   local_fp_index={})
        h10, n10 = svc.build_device_sync_fingerprint(device=self._dev(10), users=self._USERS,
                                                     local_fp_index={})
        assert n9 == 1 and n10 == 1, "the user must actually be in the roster"
        assert h9 != h10

    def test_the_header_itself_was_not_widened(self, tmp_path, monkeypatch):
        """Deliberate. Had the field gone into the device-level header, EVERY device
        carrying the setting would take a full roster re-push, including devices
        where no member's effective version changed. With no users, only the header
        contributes -- so it must be identical."""
        svc, _ = make_engine(tmp_path, monkeypatch)
        h9, _n = svc.build_device_sync_fingerprint(device=self._dev(9), users=[],
                                                   local_fp_index={})
        h10, _n2 = svc.build_device_sync_fingerprint(device=self._dev(10), users=[],
                                                     local_fp_index={})
        assert h9 == h10, "the header must not move; only per-pin hashes may"


class TestTheResolverIsTheSingleSource:
    """A divergence between the push path and either hash path makes the stored hash
    permanently disagree with what the push produced -- the pin then re-pushes every
    cycle, forever. One resolver is what prevents that."""

    def test_it_reads_the_normalised_key(self, tmp_path, monkeypatch):
        svc, _ = make_engine(tmp_path, monkeypatch)
        assert svc._resolve_template_version_override({"fingerprintTemplateVersion": 9}) == 9

    def test_it_falls_back_to_the_raw_capabilities_json(self, tmp_path, monkeypatch):
        svc, _ = make_engine(tmp_path, monkeypatch)
        assert svc._resolve_template_version_override(
            {"deviceCapabilities": '{"fingerprintTemplateVersion": 10}'}) == 10

    @pytest.mark.parametrize("bad", [None, 0, 8, 11, "", "auto", "nine", True, {}])
    def test_anything_that_is_not_9_or_10_is_no_override(self, tmp_path, monkeypatch, bad):
        """AUTO in the dashboard means "no value stored", and every malformed value
        must degrade to the same thing rather than biasing something arbitrary."""
        svc, _ = make_engine(tmp_path, monkeypatch)
        assert svc._resolve_template_version_override({"fingerprintTemplateVersion": bad}) is None

    def test_an_empty_device_is_no_override(self, tmp_path, monkeypatch):
        svc, _ = make_engine(tmp_path, monkeypatch)
        assert svc._resolve_template_version_override({}) is None
        assert svc._resolve_template_version_override(None) is None
