"""The missing-member check (lane B, 2026-09-26, guide §3.4 "authoritative revocation" neighbour, §3.6).

The promise: a valid member the server has and this PC lacks triggers an immediate full member
refresh. Before, the only detector was the member-cache self-heal (sync_scope.member_cache_is_stale):
it fires when the local cache holds under 50 % of the count the membersVersion token encodes, so a
PC missing a handful of members -- a row lost to a stale fast-patch delete, an entrant the server
counts as delivered but never sent -- stayed that way until an unrelated change moved the token.

Now, after every successful sync, the server's list is compared with the PC's (sync_users + the
rows P3b-1 holds for a later day, sync_users_held):
  * a delta members section: its validMemberIds (any backend);
  * a full members section: the users[] it carried -- a gap there is a row the PC could not store,
    which another full refresh cannot fix: reported, never refreshed again;
  * no members section, protocol-2 windows trusted: the stored windows are exactly the server's
    set of the day (replaced whole by every members section; a fast patch drops its membership's);
  * no members section, not trusted, a P1a token: the token's id-set digest against the local
    set. A digest cannot tell a missing member from an extra row, so a mismatch only asks ONE
    delta answer (membersVersion dropped, the watermark kept), whose validMemberIds decide.
The check itself never deletes anything; the refresh it asks for is the ordinary one (H-006 and
the previous-day guards included).
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

import app.core.db as dbmod
from app.core import sync_scope
from app.core.sync_scope import (
    apply_trigger_hint_to_version_tokens,
    member_id_set_digest,
    token_id_set_digest,
)

# ── the digest, byte-exact with the backend ─────────────────────────────────────────
# Vectors produced by running a verbatim copy of GymAccessController.shortDigest +
# memberIdSetDigest (backend main 919231a8) on JDK 17, 2026-09-26 (scratch, not committed).


@pytest.mark.parametrize(("ids", "expected"), [
    ([], "e3b0c44298fc1c14"),
    ([5], "ef2d127de37b942b"),
    ([31000, 5, 9, 5, 100], "4ad0a51d7af1c16f"),          # numeric sort, distinct
    ([200000 - i * 7 for i in range(1860)], "bbaa25bcdfe7a892"),
])
def test_the_id_set_digest_is_the_backends(ids, expected) -> None:
    assert member_id_set_digest(ids) == expected


def test_the_token_carries_the_digest_as_its_last_component() -> None:
    # count:maxMemberUpdated:fpCount:maxFpUpdated:enrCount:maxEnrUpdated:idSetDigest -- the
    # timestamps are LocalDateTime strings WITH colons, so the digest is read from the end.
    token = "3:2026-09-26T10:00:00:2:2026-09-20T08:00:00.123456:1:2026-09-21T09:00:00:ef2d127de37b942b"
    assert token_id_set_digest(token) == "ef2d127de37b942b"
    assert token_id_set_digest("0:0:0:0:0:0:e3b0c44298fc1c14") == "e3b0c44298fc1c14"   # empty scope


@pytest.mark.parametrize("token", [
    None, "", 12,
    "12:2026-09-26T10:00:00:3:2026-09-20T08:00:00",                    # pre-P1a: 4 fields
    "12:2026-09-26T10:00:00:3:2026-09-20T08:00:00:1:2026-09-21T09:00", # 6 fields
    "12:2026-09-26T10:00:00:3:2026-09-20T08:00:00.123456:0:0",         # 6 fields ending "0"
    "12:x:0:0:0:0:NOTHEX0000000000", "12:x:0:0:0:0:abc", "12:x:0:0:0:0:EF2D127DE37B942B",
])
def test_a_token_without_a_digest_has_none(token) -> None:
    assert token_id_set_digest(token) is None


# ── the hints the check sends ───────────────────────────────────────────────────────

_TOKENS = {"membersVersion": "3:x", "membersUpdatedAfter": "2026-09-26T10:00:00",
           "devicesVersion": "d", "windowsVersion": "p2.7.a.b"}


def test_a_forced_member_refresh_drops_both_member_tokens() -> None:
    out = apply_trigger_hint_to_version_tokens(
        _TOKENS, {"reason": "missing-members", "forceMemberRefresh": True})
    assert out == {"devicesVersion": "d", "windowsVersion": "p2.7.a.b"}


def test_a_member_set_probe_drops_only_the_members_version() -> None:
    out = apply_trigger_hint_to_version_tokens(
        _TOKENS, {"reason": "member-set-probe", "probeMemberSet": True})
    assert out == {"membersUpdatedAfter": "2026-09-26T10:00:00", "devicesVersion": "d",
                   "windowsVersion": "p2.7.a.b"}


# ── the decision, with its suppression ──────────────────────────────────────────────


def _checker():
    import app.ui.app as app_module

    app = object.__new__(app_module.MainApp)
    app.logger = MagicMock()
    return app


def test_a_member_missing_after_a_delta_asks_a_full_refresh() -> None:
    app = _checker()
    assert app._missing_member_action(server_ids={5, 6, 7}, local_ids={5, 6}, source="delta") == (
        "full_refresh", {7})


def test_nothing_missing_asks_nothing() -> None:
    app = _checker()
    assert app._missing_member_action(server_ids={5, 6}, local_ids={5, 6, 9}, source="delta") == (
        None, set())


def test_a_gap_a_full_refresh_left_is_reported_not_refreshed_again() -> None:
    app = _checker()
    assert app._missing_member_action(server_ids={5, 7}, local_ids={5}, source="delta")[0] == "full_refresh"
    # the forced full refresh came back and 7 is still not stored: a row this PC cannot keep
    assert app._missing_member_action(server_ids={5, 7}, local_ids={5}, source="full") == (
        "suppressed", {7})
    assert app._missing_member_action(server_ids={5, 7}, local_ids={5}, source="delta") == (None, set())
    # a NEW missing member still gets its refresh
    assert app._missing_member_action(server_ids={5, 7, 8}, local_ids={5}, source="delta") == (
        "full_refresh", {8})


def test_a_suppressed_member_that_arrives_is_forgotten() -> None:
    app = _checker()
    app._missing_member_action(server_ids={5, 7}, local_ids={5}, source="full")
    app._missing_member_action(server_ids={5, 7}, local_ids={5, 7}, source="delta")
    # it went missing again later: a fresh loss, refreshed again
    assert app._missing_member_action(server_ids={5, 7}, local_ids={5}, source="delta")[0] == "full_refresh"


def test_a_full_section_gap_is_never_refreshed() -> None:
    app = _checker()
    assert app._missing_member_action(server_ids={5, 7}, local_ids={5}, source="full") == (
        "suppressed", {7})


# ── end to end on the §3.6 harness, a real temp database ───────────────────────────
from tests.test_p3b1_app_wiring import (  # noqa: E402,F401  (fixtures + helpers)
    SERVER_EPOCH, _Api, _meta, _row, _run_worker, _tel_calls, fake_tel, wired,
)


def _v1_full(users: List[Dict[str, Any]], token: str) -> Dict[str, Any]:
    return {"refreshMembers": True, "refreshDevices": False, "refreshCredentials": False,
            "refreshSettings": False, "membersDeltaMode": False, "users": users,
            "validMemberIds": None, "currentMembersVersion": token,
            "currentMembersRefreshedAt": "2026-09-26T10:00:00"}


def _v1_delta(valid: List[int], users: List[Dict[str, Any]], token: str) -> Dict[str, Any]:
    return {"refreshMembers": True, "refreshDevices": False, "refreshCredentials": False,
            "refreshSettings": False, "membersDeltaMode": True, "users": users,
            "validMemberIds": valid, "currentMembersVersion": token,
            "currentMembersRefreshedAt": "2026-09-26T10:05:00"}


def _v1_skipped(token: str) -> Dict[str, Any]:
    return {"refreshMembers": False, "refreshDevices": False, "refreshCredentials": False,
            "refreshSettings": False, "currentMembersVersion": token}


def _local_ids() -> set:
    with dbmod.get_conn() as conn:
        return {int(r[0]) for r in conn.execute(
            "SELECT active_membership_id FROM sync_users").fetchall()}


def _sync(wired, api) -> None:
    wired.app._api = lambda: api
    _run_worker(wired)
    wired.run_due()                       # posted follow-ups (the check's own request included)


def _next_request_tokens(wired, api) -> Dict[str, Any]:
    _sync(wired, api)
    return api.version_tokens[-1] or {}


@pytest.fixture
def quiet(wired, monkeypatch):
    import app.ui.app as app_module

    wired.app._maybe_apply_date_flips = lambda source: None
    # The harness captures every thread, the sync cache's background reload included, so a
    # second tick would wait out that reload's 10 s timeout; these ticks read no device from it.
    monkeypatch.setattr(app_module, "load_sync_cache", lambda: None)
    return wired


def test_a_delta_that_names_a_member_the_pc_lacks_is_followed_by_a_full_refresh(quiet, fake_tel) -> None:
    api = _Api([_v1_full([_row(5), _row(6)], "2:a"),
                _v1_delta([5, 6, 7], [], "3:b"),                  # 7: "delivered", never sent
                _v1_full([_row(5), _row(6), _row(7)], "3:b")], quiet.events)
    _sync(quiet, api)
    _sync(quiet, api)
    assert _local_ids() == {5, 6}
    ctx = quiet.app._pending_sync_context
    assert ctx is not None and ctx.trigger_hint == {"reason": "missing-members", "forceMemberRefresh": True}

    tokens = _next_request_tokens(quiet, api)

    assert "membersVersion" not in tokens and "membersUpdatedAfter" not in tokens, tokens
    assert _local_ids() == {5, 6, 7}
    [ev] = _tel_calls(fake_tel, "warn", "MEMBERS_MISSING")
    assert (ev["source"], ev["count"], ev["action"]) == ("delta", 1, "full_refresh")


def test_a_held_member_is_not_missing(quiet) -> None:
    api = _Api([_v1_full([_row(5), _row(6), _row(7)], "2:a"),
                _v1_delta([5, 6, 7], [], "3:b")], quiet.events)
    _sync(quiet, api)
    # P3b-1: 7 is held for a later gym date -- still in the server's list, not on sync_users
    with dbmod.get_conn() as conn:
        conn.execute("INSERT INTO sync_users_held SELECT *, 'test', '2026-09-27', '2026-09-26' "
                     "FROM sync_users WHERE active_membership_id = 7")
        conn.execute("DELETE FROM sync_users WHERE active_membership_id = 7")
        conn.commit()
    _sync(quiet, api)
    assert quiet.app._pending_sync_context is None


def test_a_skipped_section_with_a_matching_digest_asks_nothing(quiet) -> None:
    token = "3:2026-09-26T10:00:00:0:0:0:0:" + member_id_set_digest([5, 6])
    api = _Api([_v1_full([_row(5), _row(6)], token), _v1_skipped(token)], quiet.events)
    _sync(quiet, api)
    _sync(quiet, api)
    assert quiet.app._pending_sync_context is None


def test_a_skipped_section_whose_digest_disagrees_asks_one_delta_probe(quiet, fake_tel) -> None:
    token = "3:2026-09-26T10:00:00:0:0:0:0:" + member_id_set_digest([5, 6, 7])
    api = _Api([_v1_full([_row(5), _row(6), _row(7)], token)], quiet.events)
    _sync(quiet, api)
    with dbmod.get_conn() as conn:        # a row lost locally (the 2026-09-06 fast-patch shape)
        conn.execute("DELETE FROM sync_users WHERE active_membership_id = 7")
        conn.commit()
    api.answers += [_v1_skipped(token), _v1_delta([5, 6, 7], [], token),
                    _v1_full([_row(5), _row(6), _row(7)], token)]
    _sync(quiet, api)
    ctx = quiet.app._pending_sync_context
    assert ctx is not None and ctx.trigger_hint == {"reason": "member-set-probe", "probeMemberSet": True}

    tokens = _next_request_tokens(quiet, api)          # the probe: a delta, watermark kept
    assert "membersVersion" not in tokens and tokens.get("membersUpdatedAfter"), tokens
    ctx = quiet.app._pending_sync_context
    assert ctx is not None and ctx.trigger_hint.get("forceMemberRefresh") is True

    _next_request_tokens(quiet, api)                   # the full refresh brings 7 back
    assert _local_ids() == {5, 6, 7}
    sources = [(f["source"], f["action"]) for f in _tel_calls(fake_tel, "warn", "MEMBERS_MISSING")]
    assert sources == [("digest", "probe"), ("delta", "full_refresh")]


def test_the_digest_probe_is_asked_once_per_token(quiet) -> None:
    token = "3:2026-09-26T10:00:00:0:0:0:0:" + member_id_set_digest([5, 6, 99])
    api = _Api([_v1_full([_row(5), _row(6)], token), _v1_skipped(token),
                _v1_delta([5, 6], [], token), _v1_skipped(token)], quiet.events)
    _sync(quiet, api)
    _sync(quiet, api)                                 # mismatch -> probe
    _next_request_tokens(quiet, api)                  # the probe's delta: nothing missing
    quiet.app._pending_sync_context = None
    _sync(quiet, api)                                 # still mismatched, same token: no second probe
    assert quiet.app._pending_sync_context is None


def test_protocol_2_windows_find_a_member_missing_with_no_members_section(quiet, fake_tel) -> None:
    full = {"syncMeta": _meta(), "currentWindowsVersion": "p2.7.a.b", "refreshMembers": True,
            "refreshDevices": False, "refreshCredentials": False, "refreshSettings": False,
            "membersDeltaMode": False, "users": [_row(5), _row(6), _row(7)], "memberWindows": [],
            "upcoming": [], "upcomingIds": [], "upcomingCredentials": [],
            "currentMembersVersion": "3:x", "_clientReceivedAtEpoch": SERVER_EPOCH + 2}
    skipped = {"syncMeta": _meta(), "currentWindowsVersion": "p2.7.a.b", "refreshMembers": False,
               "refreshDevices": False, "refreshCredentials": False, "refreshSettings": False,
               "currentMembersVersion": "3:x", "_clientReceivedAtEpoch": SERVER_EPOCH + 60}
    api = _Api([full], quiet.events)
    _sync(quiet, api)
    assert dbmod.get_access_v2_state()["trusted"] is True
    with dbmod.get_conn() as conn:
        conn.execute("DELETE FROM sync_users WHERE active_membership_id = 7")
        conn.commit()
    api.answers.append(skipped)
    _sync(quiet, api)
    ctx = quiet.app._pending_sync_context
    assert ctx is not None and ctx.trigger_hint.get("forceMemberRefresh") is True
    [ev] = _tel_calls(fake_tel, "warn", "MEMBERS_MISSING")
    assert (ev["source"], ev["action"]) == ("windows", "full_refresh")


def test_the_check_never_deletes_anything(quiet) -> None:
    """Removal safety: the check reads; it removes no row. Extra local rows (a promoted starter,
    a fast-patch member) are not "missing" and are left exactly as they are."""
    token = "3:2026-09-26T10:00:00:0:0:0:0:" + member_id_set_digest([5])
    api = _Api([_v1_full([_row(5), _row(6)], token), _v1_skipped(token)], quiet.events)
    _sync(quiet, api)
    before = _local_ids()
    _sync(quiet, api)                                 # digest says {5}; the PC holds {5, 6}
    assert _local_ids() == before == {5, 6}


def test_after_a_midnight_promotion_and_hold_nothing_is_missing_and_nothing_moves(quiet, fake_tel) -> None:
    """The P3b-1 power-on shape: yesterday's answer, a flip that held one member and promoted a
    starter, then a sync with no members section. The held member is still in the server's set
    (held, not missing); the starter is an extra row, never "missing"; nothing is asked, and no
    row moves. (The digest probe cannot fire here at all: it is only for untrusted PCs, and an
    untrusted PC never flips.)"""
    from tests.test_p3b1_app_wiring import _epoch

    full = {"syncMeta": _meta(), "currentWindowsVersion": "p2.7.a.b", "refreshMembers": True,
            "refreshDevices": False, "refreshCredentials": False, "refreshSettings": False,
            "membersDeltaMode": False, "users": [_row(1, until="2026-09-19"), _row(5)],
            "memberWindows": [], "upcoming": [_row(3, frm="2026-09-20", qrAccountId=55)],
            "upcomingIds": [3], "upcomingCredentials": [], "currentMembersVersion": "2:abc",
            "_clientReceivedAtEpoch": SERVER_EPOCH + 2}
    # The next morning's answer: the server is on the 20th too (an answer still carrying the
    # 19th rolls the applied day back -- P3b-1's own rule, not this check's business).
    next_day = dict(_meta(), today="2026-09-20", horizonEnd="2026-09-27",
                    serverTime="2026-09-20T07:31:00.000+01:00",
                    snapshotAt="2026-09-20T07:30:59.500+01:00")
    skipped = {"syncMeta": next_day, "currentWindowsVersion": "p2.7.a.b", "refreshMembers": False,
               "refreshDevices": False, "refreshCredentials": False, "refreshSettings": False,
               "currentMembersVersion": "2:abc",
               "_clientReceivedAtEpoch": _epoch("2026-09-20T07:31:00+01:00")}
    api = _Api([full], quiet.events)
    _sync(quiet, api)
    out = quiet.app._apply_date_flips("startup", pc_now=_epoch("2026-09-20T07:30:00+01:00"))
    assert (out["held"], out["promoted"]) == (1, 1)
    before = (_local_ids(), set(dbmod.list_local_member_ids()))

    api.answers.append(skipped)
    _sync(quiet, api)

    assert quiet.app._pending_sync_context is None
    assert _tel_calls(fake_tel, "warn", "MEMBERS_MISSING") == []
    assert (_local_ids(), set(dbmod.list_local_member_ids())) == before == ({3, 5}, {1, 3, 5})
