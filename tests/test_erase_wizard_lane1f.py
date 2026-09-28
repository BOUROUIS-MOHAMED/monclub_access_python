"""Lane 1f (2026-09-28): the independent review of lane 1e -- the Erase wizard's code points.

Guide §3.2h. Against the same fakes as tests/test_erase_wizard.py -- nothing reaches a device:
* C1  a missing ``sync_devices`` row means "deleted in MonClub" only while the list can say so:
      the PC signed in (a gym token) and the list not empty. A logout empties it, and the TV
      logout deletes the token alone -- the start-up release then leaves an ``erase-prep`` row
      held (fail closed), and a stop during a run no longer reads as ``HELD_DEVICE_GONE``;
* C2  (tests/test_erase_wizard_lane1e.py, ``TestTheKeepMarkComesAfterTheEraseRecord``) a keep mark
      that cannot be written puts the erase record back;
* C4  ``PC_NOT_SIGNED_IN`` asks for the developer, never a logout, on the lock screen and in the
      wizard; nit N5: the lock screen's last two English refusals are French;
* N1  a durable write that fails on a row already at ``erase`` / ``erase-scheme-moved`` keeps that
      row's own note, not the SESSION one.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.core.db as dbmod
import app.core.erase_wizard as ew
from app.core import device_hold
from tests.test_erase_wizard import (  # noqa: F401 -- fixtures are used by name
    _body, _device, _devices, _pw_ok, _setup_c3, erase_switch_on, refill_cache, sqlite_db,
)
from tests.test_erase_wizard_lane1c import _account, _preview
from tests.test_erase_wizard_lane1e import (
    _device_row, _hold_row, _moved_during_backup, _note, _refill, _restart, _scheme, _signed_in,
)

REPO = Path(__file__).resolve().parents[1]


def _cut_run_row(db, did=5, scheme="MEMBERSHIP"):
    """A run cut (a power cut, a crash) before any delete: its row still at ``erase-prep``."""
    db.set_device_write_hold(device_id=did, reason=db.HOLD_REASON_ERASE_PREP, run_id="r-cut",
                             pin_scheme=scheme)


# ─────────────────────── C1: the start-up release after a logout ───────────────────────

class TestAStartThatCannotReadTheListKeepsTheRow:

    def test_signed_out_with_an_empty_list_the_row_stays_held(self, sqlite_db):
        db = sqlite_db
        _cut_run_row(db)
        _restart()
        assert device_hold.is_held(5)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP, "left as it is"

    def test_signed_in_with_an_empty_list_the_row_stays_held(self, sqlite_db):
        db = sqlite_db
        _signed_in(db)
        _cut_run_row(db)
        _restart()
        assert device_hold.is_held(5)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP

    def test_a_token_cleared_alone_keeps_it_too(self, sqlite_db):
        """The TV logout deletes the Access token and keeps the list (``_handle_tv_auth_logout``)."""
        db = sqlite_db
        _signed_in(db, 6)
        db.clear_auth_token()
        _cut_run_row(db)
        _restart()
        assert device_hold.is_held(5)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP

    def test_the_next_start_signed_in_with_the_list_decides(self, sqlite_db):
        db = sqlite_db
        _cut_run_row(db)
        _restart()
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE_PREP
        _signed_in(db)
        _device_row(db, 5, "MEMBERSHIP")                  # the same scheme: nothing moved
        _restart()
        assert not device_hold.is_held(5) and _hold_row(db, 5) is None

    def test_a_row_that_records_no_scheme_is_released_as_before(self, sqlite_db):
        """Written before lane 1e: no scheme to compare, whatever the list says."""
        db = sqlite_db
        _cut_run_row(db, scheme=None)
        _restart()
        assert not device_hold.is_held(5)

    def test_the_log_says_why_it_is_kept(self, sqlite_db, caplog):
        db = sqlite_db
        _cut_run_row(db)
        with caplog.at_level(logging.WARNING, logger="zkapp.device_hold"):
            _restart()
        assert any("cannot tell whether its pin scheme moved" in r.getMessage()
                   for r in caplog.records), [r.getMessage() for r in caplog.records]

    def test_the_review_path_logout_then_restart_then_login(self, sqlite_db, monkeypatch,
                                                            tmp_path):
        """The finding, end to end with the real calls the logout makes: a cut run's row records
        « Par abonnement », the scheme moves to « Par personne », P1 is logged out
        (``clear_auth_token`` + ``save_sync_cache(None)``) and restarts. Lane 1e released the row
        -- the first pass after login would have written account pins beside every old one."""
        db = sqlite_db
        _signed_in(db)
        _device_row(db, 5, "MEMBERSHIP")
        _cut_run_row(db)
        _device_row(db, 5, "ACCOUNT")                     # the switch reached this PC
        db.clear_auth_token()                             # _handle_auth_logout, in its order
        db.save_sync_cache(None)
        with db.get_conn() as conn:
            assert conn.execute("SELECT COUNT(*) FROM sync_devices").fetchone()[0] == 0
        _restart()
        assert device_hold.is_held(5), "a logged-out start must not release it"
        _signed_in(db)                                    # login, then the first sync
        _device_row(db, 5, "ACCOUNT")
        _restart()
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_SCHEME_MOVED
        wiz, _w, _p, _ = _setup_c3(monkeypatch, tmp_path, db)
        _account(monkeypatch, 5, _device())
        status, out = _refill(wiz, "ACCOUNT")
        assert (status, out["code"]) == (409, "HELD_SCHEME_MOVED"), out


class TestARunStoppedWhileSignedOut:

    def test_a_missing_row_is_not_read_as_deleted(self, sqlite_db, monkeypatch, tmp_path):
        """``_device_gone`` makes the same inference: signed out, the hold is made durable
        (``erase-scheme-moved``), not HELD_DEVICE_GONE's "a restart releases it"."""
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, sqlite_db)
        _scheme(monkeypatch, "MEMBERSHIP")
        pv = _preview(wiz, 5)
        real = panel.read_table_strict

        def _read(*, table, fields="*"):
            _devices(monkeypatch)                         # no row: the list was emptied
            _scheme(monkeypatch, None)
            return real(table=table, fields=fields)
        panel.read_table_strict = _read
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        note = _note(wiz)
        assert not note.startswith("HELD_DEVICE_GONE:"), note
        assert note.startswith("HELD_SCHEME_MOVED:"), note
        assert _hold_row(sqlite_db, 5)["reason"] == sqlite_db.HOLD_REASON_SCHEME_MOVED
        _restart()
        assert device_hold.is_held(5)

    def test_signed_in_with_the_list_it_is_still_gone(self, sqlite_db, monkeypatch):
        _signed_in(sqlite_db, 6)
        _devices(monkeypatch)
        assert ew.EraseWizard._device_gone(5) is True
        sqlite_db.clear_auth_token()
        assert ew.EraseWizard._device_gone(5) is False

    def test_a_list_that_does_not_read_is_not_gone(self, sqlite_db, monkeypatch):
        _devices(monkeypatch)

        def _boom():
            raise RuntimeError("database is locked")
        monkeypatch.setattr(dbmod, "device_list_is_authoritative", _boom)
        assert ew.EraseWizard._device_gone(5) is False


# ─────────────────────── N1: the SESSION note only for an erase-prep row ───────────────────────

class TestADurableWriteThatFailsOnARowAlreadyKept:

    def test_a_row_at_erase_keeps_held_before(self, sqlite_db, monkeypatch, tmp_path):
        db = sqlite_db
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, db)
        _scheme(monkeypatch, "MEMBERSHIP")
        device_hold.hold(5, reason=device_hold.REASON_ERASE, run_id="r-erased",
                         pin_scheme="MEMBERSHIP")

        def _boom(**kw):
            raise RuntimeError("disk I/O error")
        monkeypatch.setattr(dbmod, "keep_erase_hold_after_scheme_move", _boom)
        pv = _preview(wiz, 5)
        _moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert _note(wiz).startswith("HELD_BEFORE:"), _note(wiz)
        assert _hold_row(db, 5)["reason"] == db.HOLD_REASON_ERASE

    def test_an_erase_prep_row_still_gets_the_session_note(self, sqlite_db, monkeypatch, tmp_path):
        db = sqlite_db
        wiz, _w, panel, _ = _setup_c3(monkeypatch, tmp_path, db)
        _scheme(monkeypatch, "MEMBERSHIP")

        def _boom(**kw):
            raise RuntimeError("disk I/O error")
        monkeypatch.setattr(dbmod, "keep_erase_hold_after_scheme_move", _boom)
        pv = _preview(wiz, 5)
        _moved_during_backup(monkeypatch, panel)
        wiz.start(5, _body(pv["previewId"]), verify_password=_pw_ok)
        assert _note(wiz).startswith("HELD_SCHEME_MOVED_SESSION:"), _note(wiz)


# ─────────────────────── C4 / N5: the lock screen's texts ───────────────────────

def _lock_screen(monkeypatch, body, token="t"):
    from app.api import local_access_api_v2 as api_mod
    monkeypatch.setattr("access.store.load_auth_token",
                        lambda: None if token is None else SimpleNamespace(token=token))
    sent = {}
    ctx = SimpleNamespace(body=lambda: body,
                          app=SimpleNamespace(_api=lambda: None, logger=logging.getLogger("t")),
                          send_json=lambda s, p: sent.update(status=s, payload=p))
    api_mod._handle_auth_verify_admin_password(ctx)
    return sent


class TestTheLockScreenTexts:

    def test_no_password_answers_in_french(self, monkeypatch):
        sent = _lock_screen(monkeypatch, {})
        assert sent["status"] == 400 and sent["payload"]["code"] == "ADMIN_PASSWORD_REQUIRED"
        assert sent["payload"]["error"] == "Saisissez le mot de passe administrateur."

    def test_no_gym_token_answers_in_french_and_asks_for_the_developer(self, monkeypatch):
        sent = _lock_screen(monkeypatch, {"password": "pw"}, token=None)
        assert sent["status"] == 401 and sent["payload"]["code"] == "PC_NOT_SIGNED_IN"
        error = sent["payload"]["error"]
        assert error.startswith("Ce PC n'est pas connecté à MonClub"), error
        assert "Appelez le développeur" in error and "Reconnectez" not in error

    def test_no_text_invites_a_logout_on_its_own(self):
        """The refused-login branch (tested for its code in lane 1e) and both languages of the
        wizard: « appelez le développeur », never « reconnectez » (review C4)."""
        server = (REPO / "app" / "api" / "local_access_api_v2.py").read_text(encoding="utf-8")
        text = (REPO / "tauri-ui" / "src" / "lib" / "eraseWizardText.ts").read_text(encoding="utf-8")
        assert "Reconnectez" not in server and "Reconnectez" not in text
        assert "Sign this PC in again" not in text
        codes = re.findall(r"PC_NOT_SIGNED_IN: \"([^\"]+)\"", text)
        assert len(codes) == 2, codes
        assert "Appelez le développeur" in codes[0] and "Call the developer" in codes[1]
        assert codes[0].startswith("Ce PC n'est pas connecté à MonClub"), "the runbook quotes it"


class TestThePage:

    def test_both_languages_have_the_new_texts(self):
        text = (REPO / "tauri-ui" / "src" / "lib" / "eraseWizardText.ts").read_text(encoding="utf-8")
        assert len(re.findall(r"\bKEEP_MARK_NOT_WRITTEN_HELD:\s*\n?\s*\"", text)) == 2
        assert len(re.findall(r"\bKEEP_MARK_NOT_WRITTEN:\s*\n?\s*\"", text)) == 2
        assert len(re.findall(r"\berase_record_undone: \"", text)) == 2
