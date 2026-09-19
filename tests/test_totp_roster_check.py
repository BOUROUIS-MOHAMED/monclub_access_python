"""QR/TOTP roster check: a matched code is allowed only if one of the credential's
granted memberships is on the PC's member list (``users_by_am``).

Before 2026-09-18 ``verify_totp`` allowed any matching code and fell back to the first
grant id when none was on the list (still pinned, for trial mode, by
``test_access_verification.py::test_totp_no_matching_user_in_users_by_am``). A member
removed from the list kept opening the door by QR until the credentials refreshed.

The check lives in verify_totp's final ALLOW step -- never in _iter_eligible_totp_creds,
which the TOTP speed index shares -- so the index and the loop decide identically.
TRIAL (the default) records the verdict and still allows; ENFORCE refuses.
"""

from __future__ import annotations

import random
import time
from unittest.mock import MagicMock, patch

import pytest

from app.core import access_verification as av
from tests.test_totp_index import _code_for, _settings, _strip


def _cred(cred_id, grants, rng):
    return {
        "id": cred_id, "accountId": 5000 + cred_id, "enabled": True,
        "secretHex": "".join(rng.choice("0123456789abcdef") for _ in range(32)),
        "grantedActiveMembershipIds": list(grants),
    }


def _user(am, **extra):
    return {"activeMembershipId": am, "userId": 7000 + am, "fullName": f"M{am}", **extra}


def _verify(scanned, settings, creds, users_by_am, now, idx=None):
    return av.verify_totp(
        scanned=scanned, settings=settings, creds_payload=creds,
        users_by_am=users_by_am, users_by_card={}, now_unix=now, totp_index=idx,
    )


@pytest.fixture
def world():
    rng = random.Random(7)
    member = _cred(1, [101], rng)
    removed = _cred(2, [202], rng)          # its membership is no longer on the list
    shared = _cred(3, [303, 304], rng)      # family / shared plan: only 304 is listed
    creds = [member, removed, shared]
    users_by_am = {101: _user(101), 304: _user(304)}
    return creds, users_by_am, member, removed, shared


def test_trial_is_the_default_and_still_allows(world):
    creds, users_by_am, _m, removed, _s = world
    now = time.time()
    r = _verify(_code_for(removed, _settings(), now), _settings(), creds, users_by_am, now)
    assert r["allowed"] is True and r["reason"] == "ALLOW"
    assert r["rosterCheck"] == av.ROSTER_NOT_IN and r["rosterCheckMode"] == av.ROSTER_MODE_TRIAL
    assert r["user"] is None and r["activeMembershipId"] == 202


def test_enforce_refuses_a_code_whose_memberships_are_not_on_the_list(world):
    creds, users_by_am, _m, removed, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _verify(_code_for(removed, s, now), s, creds, users_by_am, now)
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_IN_LOCAL_ROSTER"
    assert r["rosterCheck"] == av.ROSTER_NOT_IN and r["rosterCheckMode"] == av.ROSTER_MODE_ENFORCE
    assert r["user"] is None and r["credId"] == "2"


def test_enforce_allows_a_listed_member(world):
    creds, users_by_am, member, _r, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _verify(_code_for(member, s, now), s, creds, users_by_am, now)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_IN
    assert r["user"] is users_by_am[101] and r["activeMembershipId"] == 101


def test_a_shared_plan_credential_passes_when_any_grant_is_listed(world):
    creds, users_by_am, _m, _r, shared = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _verify(_code_for(shared, s, now), s, creds, users_by_am, now)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_IN
    assert r["activeMembershipId"] == 304 and r["user"] is users_by_am[304]


def test_an_empty_member_list_is_unevaluable_and_never_refuses(world):
    # load_local_state turns a failed users read into [] -- indistinguishable from
    # "no members" -- and ultra_engine falls back to ({}, {}, {}) on a bad load.
    # Enforcing then would refuse every QR at every door.
    creds, _u, member, _r, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _verify(_code_for(member, s, now), s, creds, {}, now)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_UNEVALUABLE


@pytest.mark.parametrize("account_value", [5002, "5002"])
def test_a_renewed_member_with_stale_grants_passes_by_account(world, account_value):
    # The PC's credential diff ignores grantedActiveMembershipIds, so after a renewal the
    # cached credential still grants the OLD membership id (202) while the member list
    # carries the new one (909) for the same main account (cred 2 -> accountId 5002).
    creds, users_by_am, _m, removed, _s = world
    roster = {**users_by_am, 909: _user(909, mainAccountId=account_value)}
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _verify(_code_for(removed, s, now), s, creds, roster, now)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_IN_BY_ACCOUNT
    # The allow itself is unchanged from before: first grant, no user resolved.
    assert r["activeMembershipId"] == 202 and r["user"] is None


@pytest.mark.parametrize("other_row", [
    _user(909, mainAccountId=5999),   # another person's account
    _user(909),                       # row with no account at all
    _user(909, mainAccountId=None),
])
def test_the_account_second_chance_needs_the_same_account(world, other_row):
    creds, users_by_am, _m, removed, _s = world
    roster = {**users_by_am, 909: other_row}
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _verify(_code_for(removed, s, now), s, creds, roster, now)
    assert r["allowed"] is False and r["rosterCheck"] == av.ROSTER_NOT_IN


def test_a_roster_refusal_found_on_the_wall_clock_retry_is_the_reported_verdict(world):
    # Device RTC 5 min ahead (inside the 3600 s sanity bound): the scan-clock pass finds
    # no match, the wall-clock retry matches the credential and refuses it on the
    # roster. The reported reason -- and the count -- must be the roster refusal.
    creds, users_by_am, _m, removed, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = av.verify_totp_resilient(
        scanned=_code_for(removed, s, now), settings=s, creds_payload=creds,
        users_by_am=users_by_am, users_by_card={}, scan_epoch=now + 300,
    )
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_IN_LOCAL_ROSTER"
    assert r["rosterCheck"] == av.ROSTER_NOT_IN and r["clockUsed"] == "wall"


def test_an_enforced_roster_refusal_does_not_rerun_the_verification(world):
    # The wall-clock retry is for clock skew; a roster refusal already matched a
    # credential, so re-running the full HMAC loop would only double the worker's time.
    creds, users_by_am, _m, removed, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    with patch("app.core.access_verification.verify_totp", wraps=av.verify_totp) as spy:
        r = av.verify_totp_resilient(
            scanned=_code_for(removed, s, now), settings=s, creds_payload=creds,
            users_by_am=users_by_am, users_by_card={}, scan_epoch=now,
        )
    assert r["reason"] == "DENY_NOT_IN_LOCAL_ROSTER"
    assert spy.call_count == 1


@pytest.mark.parametrize("caps, expected", [
    ({"totpRosterCheckMode": "enforce"}, "enforce"),
    ('{"totpRosterCheckMode": "ENFORCE", "fingerprintTemplateVersion": 9}', "enforce"),
    ({"totpRosterCheckMode": "trial"}, "trial"),
    ({"fingerprintTemplateVersion": 10}, "trial"),
    ("not json", "trial"),
    (None, "trial"),
    ({"totpRosterCheckMode": True}, "trial"),
])
def test_the_mode_arrives_from_the_device_payload(caps, expected):
    # The switch must reach the engines: both build their settings through
    # normalize_device_settings, whose dict is explicit -- an unread key is inert.
    from app.core.settings_reader import normalize_device_settings
    dev = {"id": 3, "active": True, "accessDevice": True, "accessDataMode": "ULTRA"}
    if caps is not None:
        dev["deviceCapabilities"] = caps
    settings = normalize_device_settings(dev)
    assert settings["totp_roster_check_mode"] == expected
    assert av.totp_roster_check_mode(settings) == expected


def test_the_mode_survives_device_ingest_to_the_engine_settings(tmp_path, monkeypatch):
    # guide §6.2: prove the key survives every layer between the source and its reader --
    # sync_devices storage, list_sync_devices_payload, normalize_device_settings.
    from tests.test_device_capabilities_template_version import _device, _ingest
    import importlib
    import app.core.db as db_module
    from app.core.settings_reader import normalize_device_settings

    importlib.reload(db_module)
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "roster.db"), raising=False)
    db_module.init_db()
    _ingest(db_module, _device(deviceCapabilities='{"totpRosterCheckMode":"enforce"}'))

    payload = db_module.list_sync_devices_payload()
    assert normalize_device_settings(payload[0])["totp_roster_check_mode"] == "enforce"


@pytest.mark.parametrize("mode", ["trial", "enforce"])
@pytest.mark.parametrize("which", ["member", "removed", "shared", "empty_list", "renewed"])
def test_index_and_loop_reach_the_same_roster_verdict(world, mode, which):
    creds, users_by_am, member, removed, shared = world
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    cred = {"member": member, "removed": removed, "shared": shared, "empty_list": member,
            "renewed": removed}[which]
    roster = {} if which == "empty_list" else users_by_am
    if which == "renewed":
        roster = {**users_by_am, 909: _user(909, mainAccountId=5002)}
    idx = av.build_totp_index(creds, s, now, margin=1)
    code = _code_for(cred, s, now)
    loop = _verify(code, s, creds, roster, now)
    indexed = _verify(code, s, creds, roster, now, idx=idx)
    assert _strip(loop) == _strip(indexed)
    assert "rosterCheck" in loop


def test_the_index_itself_is_not_filtered_by_the_roster(world):
    # The eligibility filter is shared with build_totp_index; a roster check there
    # would silently drop credentials from the index. It must stay roster-blind.
    creds, _u, _m, _r, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    idx = av.build_totp_index(creds, s, time.time(), margin=1)
    assert idx["credCount"] == len(creds)


def test_resilient_enforce_denial_keeps_the_roster_reason(world):
    creds, users_by_am, _m, removed, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = av.verify_totp_resilient(
        scanned=_code_for(removed, s, now), settings=s, creds_payload=creds,
        users_by_am=users_by_am, users_by_card={}, scan_epoch=now,
    )
    assert r["allowed"] is False and r["reason"] == "DENY_NOT_IN_LOCAL_ROSTER"


def test_a_code_that_matches_nothing_carries_no_roster_verdict(world):
    creds, users_by_am, _m, _r, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    r = _verify("9" + "0" * 7, s, creds, users_by_am, time.time())
    assert r["allowed"] is False and "rosterCheck" not in r


@pytest.mark.parametrize("raw, expected", [
    (None, "trial"), ("", "trial"), ("trial", "trial"), ("enforce", "enforce"),
    ("ENFORCE", "enforce"), (" Enforce ", "enforce"), ("on", "trial"), ("off", "trial"),
])
def test_mode_parsing_is_trial_unless_exactly_enforce(raw, expected):
    assert av.totp_roster_check_mode({"totp_roster_check_mode": raw}) == expected


# ---------------------------------------------------------------------------
# Counting: once per scan, at the engine, never inside verify_totp.
# ---------------------------------------------------------------------------

def _counts_delta(before, after):
    return {k: after[k] - before[k]
            for k in (av.ROSTER_IN, av.ROSTER_NOT_IN, av.ROSTER_UNEVALUABLE, av.ROSTER_BEHIND)}


_NO_CHANGE = {av.ROSTER_IN: 0, av.ROSTER_NOT_IN: 0, av.ROSTER_UNEVALUABLE: 0, av.ROSTER_BEHIND: 0}


def test_verify_totp_itself_counts_nothing(world):
    creds, users_by_am, _m, removed, _s = world
    now = time.time()
    before = av.totp_roster_check_counts()
    _verify(_code_for(removed, _settings(), now), _settings(), creds, users_by_am, now)
    assert _counts_delta(before, av.totp_roster_check_counts()) == _NO_CHANGE


def test_record_counts_one_scan_and_logs_no_member_identity(world):
    creds, users_by_am, _m, removed, _s = world
    now = time.time()
    r = _verify(_code_for(removed, _settings(), now), _settings(), creds, users_by_am, now)
    before = av.totp_roster_check_counts()
    with patch("app.core.access_verification._tel.event") as tel:
        av.record_totp_roster_check(r, source="ULTRA:9")
    assert _counts_delta(before, av.totp_roster_check_counts())[av.ROSTER_NOT_IN] == 1
    tel.assert_called_once()
    assert tel.call_args.args[0] == "QR_ROSTER_CHECK"
    assert tel.call_args.kwargs == {"source": "ULTRA:9", "verdict": av.ROSTER_NOT_IN,
                                    "mode": av.ROSTER_MODE_TRIAL, "allowed": True}


def test_an_in_roster_scan_is_counted_but_not_logged(world):
    creds, users_by_am, member, _r, _s = world
    now = time.time()
    r = _verify(_code_for(member, _settings(), now), _settings(), creds, users_by_am, now)
    before = av.totp_roster_check_counts()
    with patch("app.core.access_verification._tel.event") as tel:
        av.record_totp_roster_check(r)
    assert _counts_delta(before, av.totp_roster_check_counts())[av.ROSTER_IN] == 1
    tel.assert_not_called()


def test_an_enforced_refusal_is_also_counted_as_refused(world):
    creds, users_by_am, _m, removed, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    r = _verify(_code_for(removed, s, now), s, creds, users_by_am, now)
    before = av.totp_roster_check_counts()
    av.record_totp_roster_check(r)
    after = av.totp_roster_check_counts()
    assert after[av.ROSTER_NOT_IN] - before[av.ROSTER_NOT_IN] == 1
    assert after[av.ROSTER_REFUSED] - before[av.ROSTER_REFUSED] == 1


def test_the_summary_line_is_logged_at_most_once_per_interval():
    due = time.monotonic() + 10 * av.ROSTER_SUMMARY_INTERVAL_SEC
    with patch("app.core.access_verification._tel.event") as tel:
        assert av.maybe_log_totp_roster_summary(now_mono=due) is True
        assert av.maybe_log_totp_roster_summary(now_mono=due + 1) is False
    tel.assert_called_once()
    assert tel.call_args.args[0] == "QR_ROSTER_SUMMARY"
    assert set(tel.call_args.kwargs) == {
        "since", "in_roster", "in_roster_by_account", "not_in_roster", "roster_empty",
        "roster_behind", "refused", "not_today"}


def test_a_card_result_is_not_counted():
    before = av.totp_roster_check_counts()
    av.record_totp_roster_check({"allowed": True, "reason": "ALLOW_CARD", "scanMode": "RFID_CARD"})
    av.record_totp_roster_check(None)
    assert _counts_delta(before, av.totp_roster_check_counts()) == _NO_CHANGE


# ---------------------------------------------------------------------------
# ULTRA rescue, end to end through the real verifier.
# ---------------------------------------------------------------------------

def _ultra_worker(settings, creds, users_by_am):
    from tests.test_ultra_engine import _make_settings, _make_worker
    worker = _make_worker(settings=_make_settings(**settings))
    worker._cached_state = (creds, users_by_am, {})
    worker._cached_state_ts = time.monotonic()
    worker._sdk = MagicMock()
    worker._sdk.open_door.return_value = True
    worker._connected = True
    return worker


def _ultra_scan(worker, code):
    from tests.test_ultra_engine import _make_event
    with (
        patch("app.core.ultra_engine.insert_access_history", return_value=1),
        patch("app.core.ultra_engine.get_staff_membership_ids_cached", return_value=set()),
    ):
        worker._process_event(_make_event(event_id=f"e-{code}", card_no=code, event_type=1, door_id=1))
    return worker._history_q.get_nowait()


@pytest.mark.parametrize("mode, opens, reason", [
    ("trial", True, "ALLOW"),
    ("enforce", False, "DENY_NOT_IN_LOCAL_ROSTER"),
])
def test_ultra_rescue_of_a_removed_member(world, mode, opens, reason):
    creds, users_by_am, _m, removed, _s = world
    s = {**_settings(), "totp_roster_check_mode": mode}
    worker = _ultra_worker(s, creds, users_by_am)
    before = av.totp_roster_check_counts()

    rec = _ultra_scan(worker, _code_for(removed, s, time.time()))

    assert worker._sdk.open_door.called is opens
    assert rec.allowed is opens and rec.reason == reason
    assert _counts_delta(before, av.totp_roster_check_counts())[av.ROSTER_NOT_IN] == 1


def test_ultra_rescue_of_a_listed_member_opens_in_enforce(world):
    creds, users_by_am, member, _r, _s = world
    s = {**_settings(), "totp_roster_check_mode": "enforce"}
    worker = _ultra_worker(s, creds, users_by_am)
    rec = _ultra_scan(worker, _code_for(member, s, time.time()))
    worker._sdk.open_door.assert_called_once()
    assert rec.allowed is True and rec.reason == "ALLOW"


@pytest.mark.parametrize("shared_gen, verdict", [(6, "in_roster"), (5, "roster_behind")])
def test_ultra_checks_a_newer_index_against_a_member_list_at_least_as_new(shared_gen, verdict):
    # The shared index is accepted when its generation is >= the worker's own, so it
    # can carry a credential for a member added after this worker's member list was
    # loaded. The roster check must then use the process-wide member list (published
    # before the index is built from it). With no list as new as the index, the
    # verdict is roster_behind -- never a refusal of a member newer than the list.
    import app.core.ultra_engine as _ue
    rng = random.Random(11)
    member, newbie = _cred(1, [101], rng), _cred(9, [505], rng)
    s = {**_settings(), "totp_roster_check_mode": "enforce"}
    old_state = ([member], {101: _user(101)}, {})
    new_state = ([member, newbie], {101: _user(101), 505: _user(505)}, {})
    worker = _ultra_worker(s, *old_state[:2])
    worker._cached_state_gen = 5
    worker._get_cached_local_state = MagicMock(return_value=old_state)
    _ue._set_shared_totp_index(av.build_totp_index(new_state[0], s, time.time(), margin=1), 6)
    _ue._set_shared_local_state(new_state if shared_gen == 6 else old_state, shared_gen)
    before = av.totp_roster_check_counts()
    try:
        rec = _ultra_scan(worker, _code_for(newbie, s, time.time()))
    finally:
        _ue._set_shared_totp_index(None, -1)
        _ue._set_shared_local_state(None, -1)
    assert worker._sdk.open_door.called is True
    assert rec.allowed is True
    key = {"in_roster": av.ROSTER_IN, "roster_behind": av.ROSTER_BEHIND}[verdict]
    assert _counts_delta(before, av.totp_roster_check_counts())[key] == 1


@pytest.mark.parametrize("who", ["removed", "member"])
def test_ultra_never_adopts_an_empty_shared_member_list(world, who):
    # Another worker's refresh read the credentials but failed the users query:
    # load_local_state returned (creds, {}, {}) and it was published at gen 6 with the
    # index. Adopting that empty list would lose the member's name from popup and
    # history. The worker keeps its own list -- which is older than the index, so a
    # "not listed" code is roster_behind: never refused, never roster_empty.
    import app.core.ultra_engine as _ue
    creds, users_by_am, member, removed, _s = world
    s = {**_settings(), "totp_roster_check_mode": "enforce"}
    worker = _ultra_worker(s, creds, users_by_am)
    worker._cached_state_gen = 5
    worker._get_cached_local_state = MagicMock(return_value=(creds, users_by_am, {}))
    _ue._set_shared_totp_index(av.build_totp_index(creds, s, time.time(), margin=1), 6)
    _ue._set_shared_local_state((creds, {}, {}), 6)
    cred = removed if who == "removed" else member
    try:
        before = av.totp_roster_check_counts()
        _ultra_scan(worker, _code_for(cred, s, time.time()))
        req = worker._popup_q.get_nowait()
    finally:
        _ue._set_shared_totp_index(None, -1)
        _ue._set_shared_local_state(None, -1)
    assert worker._sdk.open_door.called is True
    delta = _counts_delta(before, av.totp_roster_check_counts())
    assert delta[av.ROSTER_UNEVALUABLE] == 0
    if who == "member":
        assert req.user_full_name == "M101" and delta[av.ROSTER_IN] == 1
    else:
        assert delta[av.ROSTER_BEHIND] == 1


def test_the_shared_member_list_never_goes_back_a_generation():
    # A refresh whose slow load straddled a sync commit publishes an OLDER list after a
    # newer one; the shared index already refuses that, the member list must too.
    import app.core.ultra_engine as _ue
    new, old, same = (["c"], {1: "n"}, {}), (["c"], {1: "o"}, {}), (["c"], {1: "s"}, {})
    try:
        _ue._set_shared_local_state(new, 6)
        _ue._set_shared_local_state(old, 5)
        assert _ue._get_shared_local_state() == (new, 6)
        _ue._set_shared_local_state(same, 6)
        assert _ue._get_shared_local_state() == (same, 6)
        _ue._set_shared_local_state(None, -1)  # a clear is always allowed
        assert _ue._get_shared_local_state() == (None, -1)
    finally:
        _ue._set_shared_local_state(None, -1)


def test_an_empty_member_list_is_not_newer_information():
    # A refresh whose users read failed publishes (creds, {}, {}) at the newest
    # generation. An older COMPLETE list finishing afterwards may replace it -- the
    # empty one says nothing about members -- but never the other way round.
    import app.core.ultra_engine as _ue
    full, empty = (["c"], {1: {"activeMembershipId": 1}}, {}), (["c"], {}, {})
    try:
        _ue._set_shared_local_state(empty, 6)
        _ue._set_shared_local_state(full, 5)
        assert _ue._get_shared_local_state() == (full, 5)
        _ue._set_shared_local_state(full, 6)
        _ue._set_shared_local_state(empty, 5)
        assert _ue._get_shared_local_state() == (full, 6)
        _ue._set_shared_local_state(empty, 6)  # same generation, strictly less information
        assert _ue._get_shared_local_state() == (full, 6)
        _ue._set_shared_local_state(empty, 7)  # a real drop to zero comes with a bump
        assert _ue._get_shared_local_state() == (empty, 7)
    finally:
        _ue._set_shared_local_state(None, -1)


def test_a_refresh_landing_mid_read_never_makes_an_old_list_look_current():
    # The refresh thread stores _cached_state, then _cached_state_gen, without a lock.
    # Here it lands while the rescue reads: the rescue gets the OLD gen-5 list, and the
    # generation reads 6 right after. Trusting that 6 would check new member N against
    # the old list and refuse N; the rescue must treat the list as gen 5 and use the
    # shared gen-6 list, which has N.
    import app.core.ultra_engine as _ue
    rng = random.Random(21)
    member, newbie = _cred(1, [101], rng), _cred(9, [505], rng)
    s = {**_settings(), "totp_roster_check_mode": "enforce"}
    old_state = ([member], {101: _user(101)}, {})
    new_state = ([member, newbie], {101: _user(101), 505: _user(505)}, {})
    worker = _ultra_worker(s, *old_state[:2])
    worker._cached_state_gen = 5

    def _read_then_refresh_lands():
        worker._cached_state_gen = 6
        return old_state

    worker._get_cached_local_state = _read_then_refresh_lands
    _ue._set_shared_totp_index(av.build_totp_index(new_state[0], s, time.time(), margin=1), 6)
    _ue._set_shared_local_state(new_state, 6)
    try:
        rec = _ultra_scan(worker, _code_for(newbie, s, time.time()))
    finally:
        _ue._set_shared_totp_index(None, -1)
        _ue._set_shared_local_state(None, -1)
    worker._sdk.open_door.assert_called_once()
    assert rec.allowed is True


def test_a_cold_worker_that_adopts_an_empty_list_refreshes_itself():
    # At the current generation nothing else would reload it before the 300 s TTL:
    # every QR scan would be roster_empty (no refusal, no names) and staff cards unknown.
    import app.core.ultra_engine as _ue
    from app.core.db import get_local_state_generation
    worker = _ultra_worker(_settings(), [], {})
    worker._cached_state = None
    gen = get_local_state_generation()
    worker._trigger_bg_cache_refresh = MagicMock()
    try:
        _ue._set_shared_local_state((["c"], {}, {}), gen)
        adopted = worker._get_cached_local_state()
    finally:
        _ue._set_shared_local_state(None, -1)
    assert adopted == (["c"], {}, {})
    worker._trigger_bg_cache_refresh.assert_called_once()


def test_ultra_loop_fallback_keeps_a_trustworthy_refusal(world):
    # Newer index (gen 6), empty shared list, worker at gen 5 -- but the scan is outside
    # the index's window, so verify_totp checks the worker's OWN gen-5 credentials
    # against its OWN gen-5 list: the refusal is trustworthy and stands in enforce.
    import app.core.ultra_engine as _ue
    creds, users_by_am, _m, removed, _s = world
    s = {**_settings(), "totp_roster_check_mode": "enforce"}
    worker = _ultra_worker(s, creds, users_by_am)
    worker._cached_state_gen = 5
    worker._get_cached_local_state = MagicMock(return_value=(creds, users_by_am, {}))
    _ue._set_shared_totp_index(av.build_totp_index(creds, s, time.time() - 3600, margin=1), 6)
    _ue._set_shared_local_state((creds, {}, {}), 6)
    try:
        rec = _ultra_scan(worker, _code_for(removed, s, time.time()))
    finally:
        _ue._set_shared_totp_index(None, -1)
        _ue._set_shared_local_state(None, -1)
    worker._sdk.open_door.assert_not_called()
    assert rec.allowed is False and rec.reason == "DENY_NOT_IN_LOCAL_ROSTER"


@pytest.mark.parametrize("mode", ["trial", "enforce"])
def test_a_list_older_than_the_index_that_matched_never_refuses(world, mode):
    creds, users_by_am, member, removed, _s = world
    s = _settings(totp_roster_check_mode=mode)
    now = time.time()
    idx = av.build_totp_index(creds, s, now, margin=1)
    r = av.verify_totp(scanned=_code_for(removed, s, now), settings=s, creds_payload=creds,
                       users_by_am=users_by_am, users_by_card={}, now_unix=now,
                       totp_index=idx, roster_current=False)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_BEHIND
    r = av.verify_totp(scanned=_code_for(member, s, now), settings=s, creds_payload=creds,
                       users_by_am=users_by_am, users_by_card={}, now_unix=now,
                       totp_index=idx, roster_current=False)
    assert r["allowed"] is True and r["rosterCheck"] == av.ROSTER_IN


def test_roster_current_only_qualifies_an_index_match(world):
    # roster_current describes the INDEX. When verify_totp falls back to the loop, the
    # caller's own credentials matched -- from the same load as its list -- so a
    # "not listed" verdict stands (refused in enforce), whatever the flag says.
    creds, users_by_am, _m, removed, _s = world
    s = _settings(totp_roster_check_mode="enforce")
    now = time.time()
    stale_idx = av.build_totp_index(creds, s, now - 3600, margin=1)  # does not cover now
    for idx in (None, stale_idx):
        r = av.verify_totp(scanned=_code_for(removed, s, now), settings=s, creds_payload=creds,
                           users_by_am=users_by_am, users_by_card={}, now_unix=now,
                           totp_index=idx, roster_current=False)
        assert r["allowed"] is False and r["rosterCheck"] == av.ROSTER_NOT_IN


# ---------------------------------------------------------------------------
# AGENT decision, end to end through the real verifier.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode, opens", [("trial", True), ("enforce", False)])
def test_agent_decision_for_a_removed_member(world, mode, opens):
    from tests.test_decision_service_anti_fraud import _make_ds, _make_event as _agent_event
    creds, users_by_am, _m, removed, _s = world
    s = {**_settings(), "totp_roster_check_mode": mode,
         "anti_fraude_qr_code": False, "anti_fraude_card": False}
    ds, cmd_bus = _make_ds(settings_override=s)
    code = _code_for(removed, s, time.time())
    before = av.totp_roster_check_counts()

    def _seen():
        return _counts_delta(before, av.totp_roster_check_counts())[av.ROSTER_NOT_IN]

    with (
        patch("app.core.realtime_agent.access_history_exists", return_value=False),
        patch("app.core.realtime_agent.insert_access_history", return_value=0),
        patch.object(ds, "_load_local_state", return_value=(creds, users_by_am, {})),
    ):
        ds.event_queue.put(_agent_event(card_no=code, event_time=""))
        ds.start()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and _seen() < 1:
            time.sleep(0.01)
        time.sleep(0.2)  # let the decision reach the door command
        ds.stop()

    assert cmd_bus.open_door.called is opens
    assert _seen() == 1
