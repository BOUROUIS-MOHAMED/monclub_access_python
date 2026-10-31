from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core import refused_info as ri


USER = dict(userId=7, activeMembershipId=900, mainAccountId=42, fullName="Yasmine Ben Salah",
            image="photo", membershipId=10, firstCardId="111", validTo="2026-10-15T00:00:00")


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setattr(ri, "_enabled", True)
    monkeypatch.setattr(ri, "_index", None)


def directory(monkeypatch, reason="MEMBERSHIP_EXPIRED", date="2026-10-15", collision=False):
    entry = ri.DirectoryEntry(7, 42, 900, "Directory name", "photo", "Annuel", reason, date)
    monkeypatch.setattr(ri, "_index", ri.DirectoryIndex({"111": None if collision else entry}, {42: entry}))


def card(*, roster=None, held=None, reason="DEVICE_DENIED", number="111"):
    return ri.resolve_card(number, users_by_card=roster or {}, held_index=held, current_reason=reason)


def held(reason, **kwargs):
    return ri.build_held_index([{**USER, "heldReason": reason, **kwargs}], set())


def test_roster_hit_neutral_reason():
    info = card(roster={"111": [USER]})
    assert info.reason == "DEVICE_DENIED"
    assert info.fields["user_full_name"] == USER["fullName"]


def test_roster_collision():
    info = card(roster={"111": [USER, {**USER, "userId": 8}]})
    assert (info.reason, info.fields) == ("DENY_CARD_COLLISION", {})


def test_duplicate_memberships_of_one_user_are_not_a_collision():
    assert card(roster={"111": [USER, {**USER, "activeMembershipId": 901}]}).fields["user_full_name"] == USER["fullName"]


def test_held_expired_uses_valid_to_date():
    info = card(held=held("expired"))
    assert (info.reason, info.reason_date) == ("MEMBERSHIP_EXPIRED", "2026-10-15")


def test_held_not_started_uses_valid_from():
    info = card(held=held("not_started", validFrom="2026-11-15"))
    assert (info.reason, info.reason_date) == ("MEMBERSHIP_NOT_STARTED", "2026-11-15")


def test_held_off_hours_vs_entry_limit():
    assert card(held=held("off_hours")).reason == "OFF_HOURS"
    index = ri.build_held_index([{**USER, "heldReason": "off_hours"}], {900})
    assert card(held=index).reason == "ENTRY_LIMIT"


def test_held_frozen_takes_date_from_directory(monkeypatch):
    directory(monkeypatch, "MEMBERSHIP_FROZEN", "2026-11-21")
    assert card(held=held("frozen")).reason_date == "2026-11-21"
    directory(monkeypatch)
    assert card(held=held("frozen")).reason_date == ""


def test_frozen_date_uses_dictionary_lookups_only(monkeypatch):
    class LookupOnly(dict):
        def values(self):
            raise AssertionError("scan must not walk the directory")
    directory(monkeypatch, "MEMBERSHIP_FROZEN", "2026-11-21")
    index = ri.current_index()
    monkeypatch.setattr(ri, "_index", ri.DirectoryIndex(LookupOnly(index.by_card), LookupOnly(index.by_account)))
    assert card(held=held("frozen")).reason_date == "2026-11-21"


def test_resolvers_do_not_read_database_or_network(monkeypatch):
    from app.core import db
    directory(monkeypatch)
    def unexpected(*args, **kwargs):
        raise AssertionError("scan performed I/O")
    monkeypatch.setattr(db, "get_conn", unexpected)
    monkeypatch.setattr(ri, "_fetch_directory", unexpected)
    assert card().fields["user_full_name"] == "Directory name"
    assert ri.resolve_account(42, users_by_am={}, held_index=None, current_reason="DEVICE_DENIED") is not None


def test_unknown_held_reason_falls_through_to_directory(monkeypatch):
    directory(monkeypatch)
    assert card(held=held("other")).reason == "MEMBERSHIP_EXPIRED"


@pytest.mark.parametrize("reason,expected", [(None, "NOT_ALLOWED_NOW"), ("MEMBERSHIP_EXPIRED", "MEMBERSHIP_EXPIRED"), ("FUTURE_RULE", "NOT_ALLOWED_NOW")])
def test_directory_reason_and_null_reason_fallback(monkeypatch, reason, expected):
    directory(monkeypatch, reason)
    info = card()
    assert info.reason == expected
    assert info.fields["user_membership_title"] == "Annuel"


def test_roster_wins_over_directory(monkeypatch):
    directory(monkeypatch)
    info = card(roster={"111": [USER]})
    assert info.reason == "DEVICE_DENIED"
    assert info.fields["user_full_name"] == USER["fullName"]


def test_directory_collision(monkeypatch):
    directory(monkeypatch, collision=True)
    assert (card().reason, card().fields) == ("DENY_CARD_COLLISION", {})


def test_held_collision():
    index = ri.build_held_index([{**USER, "heldReason": "expired"},
                                 {**USER, "userId": 8, "heldReason": "expired"}], set())
    assert card(held=index).reason == "DENY_CARD_COLLISION"
    assert card(held=index).fields == {}


def test_unknown_card_carries_card_number():
    info = card(number=" 001234 ")
    assert (info.reason, info.fields, info.card_no) == ("DENY_NO_CARD_MATCH", {}, "001234")
    assert card(number="not-card") is None


def test_resolve_account_uses_roster_held_directory_and_unknown(monkeypatch):
    directory(monkeypatch)
    kw = dict(account_id=42, users_by_am={}, held_index=None, current_reason="DENY_NOT_ALLOWED_TODAY")
    assert ri.resolve_account(**kw).reason == "MEMBERSHIP_EXPIRED"
    assert ri.resolve_account(**{**kw, "held_index": held("off_hours")}).reason == "OFF_HOURS"
    assert ri.resolve_account(**{**kw, "users_by_am": {900: USER}}).fields["user_full_name"] == USER["fullName"]
    assert ri.resolve_account(**{**kw, "account_id": 404}) is None


def worker(monkeypatch):
    from tests.test_ultra_engine import _make_worker
    w = _make_worker()
    monkeypatch.setattr(w, "_get_cached_local_state", lambda: ([], {}, {}))
    w._refused_held_index = ri.build_held_index([], set())
    w._enqueue_history = MagicMock()
    return w


def test_handle_deny_switch_off_is_unchanged(monkeypatch):
    monkeypatch.setattr(ri, "_enabled", False)
    w = worker(monkeypatch)
    w._handle_deny("111", "t", "e", 1, "27", {})
    req = w._popup_q.get_nowait()
    assert (req.reason, req.user_full_name, req.refused_display) == ("DEVICE_DENIED", "", False)


def test_handle_deny_switch_on_enriches_and_history_unchanged(monkeypatch):
    directory(monkeypatch)
    w = worker(monkeypatch)
    w._handle_deny("111", "t", "e", 1, "27", {})
    req = w._popup_q.get_nowait()
    assert (req.reason, req.reason_date, req.user_full_name, req.user_membership_title, req.refused_display) == (
        "MEMBERSHIP_EXPIRED", "2026-10-15", "Directory name", "Annuel", True)
    assert w._enqueue_history.call_args.kwargs["reason"] == "DEVICE_DENIED"


@pytest.mark.parametrize("raw", [{"scan_mode_hint": "FINGERPRINT"}, {"scan_mode_hint": "FACE"},
                                      {"scan_mode_hint": "PASSWORD"}, {"cardno": ""}])
def test_non_card_refusal_is_never_displayable(monkeypatch, raw):
    directory(monkeypatch)
    w = worker(monkeypatch)
    w._handle_deny("111", "t", "e", 1, "27", raw)
    assert w._popup_q.get_nowait().refused_display is False


def test_pc_card_refusal_enriches_without_changing_history(monkeypatch):
    directory(monkeypatch)
    w = worker(monkeypatch)
    w._settings.update(rfid_enabled=True, card_decision="PC")
    w._handle_pc_card("111", "t", "e", 1, "27", {})
    assert w._popup_q.get_nowait().refused_display
    assert w._enqueue_history.call_args.kwargs["reason"] == "DENY_NO_CARD_MATCH"


def test_totp_verification_failure_shows_name_when_account_known(monkeypatch):
    from tests.test_ultra_pc_entry import _worker, _rescue_qr
    directory(monkeypatch)
    w = _worker()
    _rescue_qr(w, "91234567", "e", {"allowed": False, "reason": "DENY_EXPIRED", "accountId": 42})
    kw = w._enqueue_notification.call_args.kwargs
    assert (kw["reason"], kw["user_full_name"], kw["refused_display"]) == ("DENY_EXPIRED", "Directory name", True)
    assert w._enqueue_history.call_args.kwargs["reason"] == "DENY_EXPIRED"


@pytest.mark.parametrize("offset,reason", [(-1, "DENY_EXPIRED"), (1, "DENY_FUTURE_SKEW")])
def test_real_qr_verification_failure_resolves_credential_account(monkeypatch, offset, reason):
    from app.core import access_verification as av
    from tests.test_ultra_pc_entry import _worker, _rescue_qr
    directory(monkeypatch)
    w = _worker(totp_max_past_age_seconds=10, totp_max_future_skew_seconds=5, totp_drift_steps=2)
    secret = "3132333435363738393031323334353637383930"
    creds = [dict(id=1, accountId=42, enabled=True, secretHex=secret, grantedActiveMembershipIds=[900])]
    now = 1_800_000_015
    code = "9" + av._totp_hotp(bytes.fromhex(secret), now // 30 + offset, 7)
    result = av.verify_totp(scanned=code, settings=w._settings, creds_payload=creds,
                            users_by_am={}, users_by_card={}, now_unix=now)
    assert result["reason"] == reason and result["credId"] == "1"
    assert "accountId" not in result
    monkeypatch.setattr(w, "_get_cached_local_state", lambda: (creds, {}, {}))
    _rescue_qr(w, code, "real-qr", result)
    kw = w._enqueue_notification.call_args.kwargs
    assert (kw["reason"], kw["user_full_name"], kw["refused_display"]) == (reason, "Directory name", True)


def test_allow_path_never_calls_resolver(monkeypatch):
    from tests.test_ultra_pc_entry import _worker, _rescue_qr, _qr_result
    from tests.test_ultra_engine import _make_event
    def unexpected(*args, **kwargs):
        raise AssertionError("allowed scan touched refused directory")
    monkeypatch.setattr(ri, "resolve_card", unexpected)
    monkeypatch.setattr(ri, "resolve_account", unexpected)
    w = _worker()
    w._process_event(_make_event(card_no="22222222", event_type="0"))
    _rescue_qr(w, "91234567", "q", _qr_result())
    assert w._enqueue_notification.call_args.kwargs["allowed"]


def test_payload_has_new_keys():
    from app.core.access_types import NotificationRequest
    from app.core.realtime_agent import _popup_payload_from_request
    data = _popup_payload_from_request(NotificationRequest("e", "", "", reason_date="2026-10-15",
                                                         refused_display=True, refused_card_no="123"))
    assert (data["reasonDate"], data["refusedDisplay"], data["refusedCardNo"]) == ("2026-10-15", True, "123")
