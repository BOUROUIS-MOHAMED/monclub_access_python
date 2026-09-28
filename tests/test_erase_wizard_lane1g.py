"""Lane 1g (2026-09-28): the independent review of lane 1f -- the Erase wizard's code points.

Guide §3.2h. Against the same fakes as tests/test_erase_wizard.py -- nothing reaches a device:
* C1  a missing ``sync_devices`` row means "deleted in MonClub" only when the list was written
      WHOLE since the logout (``sync_device_list_state``: a full device replace writes it, in the
      same transaction; ``save_sync_cache(None)`` deletes it) -- one row a fast patch puts into
      the emptied list after a login is not the list. The review's repro, and its controls;
* C2  (tests/test_erase_wizard_lane1e.py / lane1f.py, the ``erase``-row cases) a run over a row
      already at ``erase`` whose scheme moved ends ``HELD_BEFORE_SCHEME_MOVED``, not "press Refill";
* C3  (tests/test_erase_wizard_lane1f.py) no device row is read as "could not be read", never
      "moved to None";
* C4  the page's generic « Remplir » line is not shown under ``KEEP_MARK_NOT_WRITTEN_HELD``;
* C5  the ``erase_record_undone`` label names the step, not its success;
* C6  the start-up side of C1 fails closed when its read raises.
"""
from __future__ import annotations

import logging
import re
import sqlite3
from pathlib import Path

import app.core.db as dbmod
import app.core.erase_wizard as ew
from app.core import device_hold
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    _devices, sqlite_db,
)
from tests.test_erase_wizard_lane1e import _device_row, _hold_row, _restart, _signed_in

REPO = Path(__file__).resolve().parents[1]


def _cut_run_row(db, did=5, scheme="MEMBERSHIP"):
    """A run cut (a power cut, a crash) before any delete: its row still at ``erase-prep``."""
    db.set_device_write_hold(device_id=did, reason=db.HOLD_REASON_ERASE_PREP, run_id="r-cut",
                             pin_scheme=scheme)


def _logout(db):
    """``_handle_auth_logout``, in its order."""
    db.clear_auth_token()
    db.save_sync_cache(None)
    db.clear_version_tokens()


def _login(db):
    """The login saves the token; the first sync comes after it."""
    db.save_auth_token(email="gym@example.test", token="tok-lane1g")


def _device_payload(did, scheme="MEMBERSHIP"):
    return {"id": did, "name": f"Door {did}", "pinScheme": scheme}


def _device_bundle(did, bundle_id="b-6"):
    """What the dashboard posts to 127.0.0.1 after a device save (``AccessPatchBundleService.
    buildDeviceBundle``): one GYM_DEVICE upsert."""
    return {"bundleId": bundle_id, "items": [{
        "kind": "ENTITY_UPSERT", "entityType": "GYM_DEVICE", "entityId": did,
        "revision": "2026-09-28T22:00:00Z", "payload": {"device": _device_payload(did)}}]}


def _marker(db):
    with db.get_conn() as conn:
        return conn.execute("SELECT 1 FROM sync_device_list_state WHERE id=1").fetchone() is not None


def _device_ids(db):
    with db.get_conn() as conn:
        return sorted(r[0] for r in conn.execute("SELECT id FROM sync_devices").fetchall())


# ─────────────────────── C1: a partial list after a re-login ───────────────────────

class TestAPartialListAfterAReLogin:

    def test_the_review_repro_the_row_stays_held(self, sqlite_db):
        """Signed in with rows 5 and 6; a cut run's row on 5; logout; login; one fast patch for 6
        only; a restart before the first full sync. Lane 1f released 5 as "deleted in MonClub"."""
        db = sqlite_db
        _signed_in(db, 5, 6)
        _cut_run_row(db)
        _logout(db)
        _login(db)
        out = db.apply_fast_patch_bundle(_device_bundle(6))
        assert out["applied"] == 1, out
        assert _device_ids(db) == [6], "the list holds the patched row alone"
        assert not _marker(db), "a fast patch never says the list is whole"
        _restart()
        assert device_hold.is_held(5)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP, "left as it is"

    def test_the_run_side_does_not_read_it_as_gone_either(self, sqlite_db, monkeypatch):
        db = sqlite_db
        _signed_in(db, 5, 6)
        _logout(db)
        _login(db)
        db.apply_fast_patch_bundle(_device_bundle(6))
        _devices(monkeypatch)
        assert db.device_list_is_authoritative() is False
        assert ew.EraseWizard._device_gone(5) is False

    def test_the_first_full_sync_then_decides(self, sqlite_db):
        """Control: the real full save (a login's first sync) writes the marker, and a list
        without 5 then says 5 was deleted -- released at the next start."""
        db = sqlite_db
        _signed_in(db, 5, 6)
        _cut_run_row(db)
        _logout(db)
        _login(db)
        db.apply_fast_patch_bundle(_device_bundle(6))
        _restart()
        assert device_hold.is_held(5)
        db.save_sync_cache({"users": [], "devices": [_device_payload(6)]})
        assert _marker(db) and _device_ids(db) == [6]
        _restart()
        assert not device_hold.is_held(5) and _hold_row(db, 5) is None


class TestTheMarker:

    def test_a_full_save_writes_it_and_the_logout_deletes_it(self, sqlite_db):
        db = sqlite_db
        assert not _marker(db), "a fresh database has no whole list"
        db.save_sync_cache({"users": [], "devices": [_device_payload(5)]})
        assert _marker(db)
        db.save_sync_cache(None)
        assert not _marker(db) and _device_ids(db) == []

    def test_a_delta_writes_it_only_when_its_devices_refresh(self, sqlite_db):
        db = sqlite_db
        refresh = {"members": False, "devices": False, "credentials": False, "settings": False}
        db.save_sync_cache_delta({"devices": [_device_payload(5)]}, refresh)
        assert not _marker(db) and _device_ids(db) == [], "no devices section: untouched"
        db.save_sync_cache_delta({"devices": [_device_payload(5)]}, dict(refresh, devices=True))
        assert _marker(db) and _device_ids(db) == [5]

    def test_an_answer_without_a_device_list_writes_none(self, sqlite_db):
        """Review of lane 1g: a payload with no ``devices`` key empties the table but says nothing
        about the list -- no marker (a later fast patch's single row would count as whole). Lane 1h
        (review C1): a marker already there is deleted too -- tests/test_erase_wizard_lane1h.py.
        The delta's payload is not ``{}``, which returns before any write."""
        db = sqlite_db
        db.save_sync_cache({"users": []})
        assert not _marker(db)
        refresh = {"members": False, "devices": True, "credentials": False, "settings": False}
        db.save_sync_cache_delta({"_clientReceivedAtEpoch": 1790000000}, refresh)
        assert not _marker(db) and _device_ids(db) == []

    def test_a_fast_patch_leaves_it_as_it_was(self, sqlite_db):
        db = sqlite_db
        db.save_sync_cache({"users": [], "devices": [_device_payload(5)]})
        db.apply_fast_patch_bundle(_device_bundle(6))
        assert _marker(db) and _device_ids(db) == [5, 6], "a whole list plus a patch: still whole"
        db.save_sync_cache(None)
        db.apply_fast_patch_bundle(_device_bundle(6, bundle_id="b-6-again"))
        assert not _marker(db)

    def test_a_refused_full_save_leaves_it_as_it_was(self, sqlite_db):
        """H-006: an empty user list over > 10 cached users is refused before the device rows --
        the list and its marker stay as they were, together."""
        db = sqlite_db
        users = [{"userId": i, "activeMembershipId": 100 + i, "membershipId": 1,
                  "fullName": f"M {i}"} for i in range(12)]
        db.save_sync_cache({"users": users, "devices": [_device_payload(5)]})
        assert _marker(db)
        with db.get_conn() as conn:
            assert conn.execute("SELECT COUNT(*) FROM sync_users").fetchone()[0] > 10
        db.save_sync_cache({"users": [], "devices": []})
        assert _marker(db) and _device_ids(db) == [5], "refused: nothing replaced"

    def test_the_authority_needs_the_token_the_marker_and_a_row(self, sqlite_db):
        db = sqlite_db
        db.save_sync_cache({"users": [], "devices": []})
        _login(db)
        assert _marker(db) and db.device_list_is_authoritative() is False, "an empty list"
        db.save_sync_cache({"users": [], "devices": [_device_payload(6)]})
        assert db.device_list_is_authoritative() is True
        db.clear_auth_token()
        assert db.device_list_is_authoritative() is False, "the TV logout: the token alone"


# ─────────────────────── C6: the start-up side fails closed ───────────────────────

class TestTheStartUpReadThatRaises:

    def test_a_raising_authority_read_releases_nothing(self, sqlite_db, monkeypatch, caplog):
        """A cut row on 5 whose turnstile has no row (the authority is asked), and a second cut
        row on 7 that alone would be released (same scheme): the read raises, the write rolls back,
        and every row stays held."""
        db = sqlite_db
        _signed_in(db, 7)
        _cut_run_row(db, 7)
        _cut_run_row(db, 5)

        def _boom(conn):
            raise sqlite3.OperationalError("database is locked")
        monkeypatch.setattr(dbmod, "_device_list_is_authoritative", _boom)
        with caplog.at_level(logging.ERROR, logger="zkapp.device_hold"):
            _restart()
        assert device_hold.is_held(5) and device_hold.is_held(7)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP
        assert _hold_row(db, 7)["reason"] == db.HOLD_REASON_ERASE_PREP, "rolled back with it"
        assert any("NOT released" in r.getMessage() for r in caplog.records), \
            [r.getMessage() for r in caplog.records]


# ─────────────────────── C2, C4, C5: the page ───────────────────────

class TestThePage:

    TEXT = REPO / "tauri-ui" / "src" / "lib" / "eraseWizardText.ts"
    DIALOG = REPO / "tauri-ui" / "src" / "components" / "EraseWizardDialog.tsx"

    def test_both_languages_have_the_scheme_moved_held_before(self):
        text = self.TEXT.read_text(encoding="utf-8")
        notes = re.findall(r"\bHELD_BEFORE_SCHEME_MOVED:\s*\n?\s*\"([^\"]+)\"", text)
        assert len(notes) == 2, notes
        assert "« Remplir » seulement une fois le schéma revenu" in notes[0]
        assert "Refill only once the scheme is step 1's again" in notes[1]
        # _refill's DONE note keeps its plain "press Refill".
        assert len(re.findall(r"\bHELD_BEFORE: \"", text)) == 2

    def test_the_held_keep_mark_text_says_set_it_back(self):
        text = self.TEXT.read_text(encoding="utf-8")
        held = re.findall(r"\bKEEP_MARK_NOT_WRITTEN_HELD:\s*\n?\s*\"([^\"]+)\"", text)
        assert len(held) == 2
        assert "cette opération n'a rien effacé" in held[0] and "remettez-le" in held[0]
        assert "this run erased nothing" in held[1] and "set it back" in held[1]

    def test_the_generic_refill_line_is_not_under_the_held_keep_mark(self):
        dialog = self.DIALOG.read_text(encoding="utf-8")
        line = [ln for ln in dialog.splitlines() if "t.incompleteHelp" in ln]
        assert len(line) == 1
        block = dialog[dialog.index("t.incompleteHelp") - 300:dialog.index("t.incompleteHelp")]
        assert '!== "KEEP_MARK_NOT_WRITTEN_HELD"' in block, block

    def test_the_undo_label_names_the_step(self):
        text = self.TEXT.read_text(encoding="utf-8")
        labels = re.findall(r"\berase_record_undone: \"([^\"]+)\"", text)
        assert labels == ["Annulation de l'enregistrement de l'effacement (aucune suppression faite)",
                          "Undo of the erase record (no delete made)"], labels
