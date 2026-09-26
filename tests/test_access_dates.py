"""P3b-1: the pure date/clock logic of sync protocol 2 (app/core/access_dates.py).

Windows, deliverability (horizon, freeze days, offline grace), the gym date and the clock checks,
the flip plan, the QR date verdict and the upcoming-credential augmentation. No database here.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

import app.core.access_dates as ad

TUNIS = 3600  # +01:00, the offset syncMeta.serverTime carries


def _d(s: str) -> date:
    return date.fromisoformat(s)


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _w(frm="2026-09-01", until="2026-09-30", off=(), beyond=False):
    return ad.AccessWindow(_d(frm), _d(until), frozenset(_d(x) for x in off), beyond)


# ------------------------------------------------------------------ windows & deliverability
class TestWindows:
    def test_parse_window_reads_the_contract_fields(self):
        w = ad.parse_window({"activeMembershipId": 5, "accessFrom": "2026-09-01",
                             "accessUntil": "2026-09-30", "offDays": ["2026-09-10"],
                             "offDaysBeyondHorizon": True})
        assert w == _w(off=["2026-09-10"], beyond=True)

    @pytest.mark.parametrize("obj", [
        {}, {"accessFrom": "2026-09-01"}, {"accessFrom": "x", "accessUntil": "2026-09-30"},
        {"accessFrom": "2026-09-30", "accessUntil": "2026-09-01"},
        {"accessFrom": "2026-09-01", "accessUntil": "2026-09-30", "offDays": "2026-09-10"},
        {"accessFrom": "2026-09-01", "accessUntil": "2026-09-30", "offDays": ["nope"]},
        {"accessFrom": None, "accessUntil": None, "offDays": []},
    ])
    def test_a_missing_or_malformed_window_is_none(self, obj):
        assert ad.parse_window(obj) is None

    def test_absent_off_days_is_an_empty_set(self):
        assert ad.parse_window({"accessFrom": "2026-09-01", "accessUntil": "2026-09-30"}) == _w()

    def test_status_inside_before_after_and_on_a_freeze_day(self):
        w = _w(off=["2026-09-10"])
        kw = dict(horizon_end=_d("2026-09-26"), server_today=_d("2026-09-19"), grace_days=0)
        assert ad.window_status(w, _d("2026-09-01"), **kw) == "ok"
        assert ad.window_status(w, _d("2026-09-30"), **kw) == "ok"          # both ends inclusive
        assert ad.window_status(w, _d("2026-08-31"), **kw) == "not_started"
        assert ad.window_status(w, _d("2026-10-01"), **kw) == "expired"
        assert ad.window_status(w, _d("2026-09-10"), **kw) == "frozen"

    def test_beyond_the_horizon_an_unknown_freeze_day_is_kept_inside_the_window(self):
        # Policy (plan §9): the server states no default; the end date still applies.
        w = _w(until="2026-12-31", beyond=True)
        kw = dict(horizon_end=_d("2026-09-26"), server_today=_d("2026-09-19"), grace_days=0)
        assert ad.window_status(w, _d("2026-10-05"), **kw) == "ok"
        assert ad.window_status(w, _d("2027-01-01"), **kw) == "expired"

    def test_offline_grace_keeps_an_expiry_only_on_days_after_the_last_server_day(self):
        w = _w(until="2026-09-19")
        # Online day (G == server today): no grace ever needed -- the server's set is current.
        assert ad.window_status(w, _d("2026-09-20"), horizon_end=_d("2026-09-26"),
                                server_today=_d("2026-09-20"), grace_days=2) == "expired"
        kw = dict(horizon_end=_d("2026-09-26"), server_today=_d("2026-09-19"))
        assert ad.window_status(w, _d("2026-09-20"), grace_days=0, **kw) == "expired"
        assert ad.window_status(w, _d("2026-09-20"), grace_days=2, **kw) == "grace"
        assert ad.window_status(w, _d("2026-09-21"), grace_days=2, **kw) == "grace"
        assert ad.window_status(w, _d("2026-09-22"), grace_days=2, **kw) == "expired"

    def test_grace_never_admits_a_freeze_day_or_a_future_start(self):
        kw = dict(horizon_end=_d("2026-09-26"), server_today=_d("2026-09-19"), grace_days=5)
        assert ad.window_status(_w(off=["2026-09-20"]), _d("2026-09-20"), **kw) == "frozen"
        assert ad.window_status(_w(frm="2026-09-25"), _d("2026-09-21"), **kw) == "not_started"

    def test_deliverable_is_ok_or_grace(self):
        assert ad.DELIVERABLE_STATUSES == frozenset({"ok", "grace"})


# ------------------------------------------------------------------ syncMeta / the v2 payload
def _meta(today="2026-09-19", horizon_end="2026-09-26", server_time="2026-09-19T10:00:00.000+01:00"):
    return {"protocol": 2, "today": today, "horizonDays": 7, "horizonEnd": horizon_end,
            "serverTime": server_time, "snapshotAt": "2026-09-19T09:59:59.500+01:00",
            "reconcileSec": 600, "capabilities": ["accessWindows", "upcoming", "upcomingCredentials"]}


def _row(am, frm="2026-09-01", until="2026-09-30", off=(), **extra):
    return {"activeMembershipId": am, "userId": 7000 + am, "fullName": f"M{am}",
            "accessFrom": frm, "accessUntil": until, "offDays": list(off), **extra}


class TestParseV2:
    def test_a_v1_answer_is_none_without_an_error(self):
        assert ad.parse_v2_payload({"users": [], "refreshMembers": True}) == (None, None)

    def test_a_members_section_carries_every_window_of_today_and_the_upcoming_list(self):
        data = {"syncMeta": _meta(), "currentWindowsVersion": "p2.7.a.b", "refreshMembers": True,
                "users": [_row(1)], "memberWindows": [{"activeMembershipId": 2, "accessFrom": "2026-09-02",
                                                        "accessUntil": "2026-09-19", "offDays": []}],
                "upcoming": [_row(3, frm="2026-09-21", qrAccountId=55)], "upcomingIds": [3],
                "upcomingCredentials": [{"id": 9, "accountId": 55, "enabled": False, "secretHex": "ab",
                                          "grantedActiveMembershipIds": [3], "notYetValid": True}]}
        p, err = ad.parse_v2_payload(data)
        assert err is None
        assert p.meta.today == _d("2026-09-19") and p.meta.horizon_end == _d("2026-09-26")
        assert p.meta.utc_offset_sec == TUNIS
        assert p.meta.server_epoch == _epoch("2026-09-19T10:00:00+01:00")
        assert p.windows_version == "p2.7.a.b"
        assert set(p.today_windows) == {1, 2}
        assert p.today_windows[2].access_until == _d("2026-09-19")
        assert [r["activeMembershipId"] for r in p.upcoming_rows] == [3]
        assert p.upcoming_windows[3].access_from == _d("2026-09-21")
        assert p.upcoming_qr_account == {3: 55}
        assert p.upcoming_credentials[0]["id"] == 9

    def test_a_skipped_members_section_leaves_the_lists_unknown(self):
        p, err = ad.parse_v2_payload({"syncMeta": _meta(), "currentWindowsVersion": "p2.7.a.b",
                                      "refreshMembers": False, "users": []})
        assert err is None and p.today_windows is None and p.upcoming_rows is None

    def test_a_delta_without_upcoming_keeps_the_stored_list(self):
        p, err = ad.parse_v2_payload({"syncMeta": _meta(), "refreshMembers": True,
                                      "membersDeltaMode": True, "users": [_row(1)],
                                      "memberWindows": [], "currentWindowsVersion": "v"})
        assert err is None and p.today_windows is not None and p.upcoming_rows is None

    @pytest.mark.parametrize("mutate,reason", [
        (lambda d: d["syncMeta"].update(today="x"), "sync_meta"),
        (lambda d: d["syncMeta"].update(serverTime="2026-09-19T10:00:00"), "sync_meta"),  # no offset
        (lambda d: d["syncMeta"].update(horizonEnd="2026-09-18"), "sync_meta"),
        (lambda d: d.update(upcomingIds=[4]), "upcoming_ids"),
        (lambda d: d.pop("upcomingIds"), "upcoming_ids"),
        (lambda d: d["memberWindows"].append({"activeMembershipId": 1, "accessFrom": "2026-09-01",
                                               "accessUntil": "2026-09-30"}), "duplicate_window"),
        (lambda d: d["memberWindows"].append({"activeMembershipId": 8, "accessFrom": "bad",
                                               "accessUntil": "2026-09-30"}), "member_window"),
        (lambda d: d["upcoming"].append(_row(3)), "upcoming_ids"),
        (lambda d: d.update(upcomingCredentials="x"), "upcoming_credentials"),
    ])
    def test_a_malformed_protocol_2_part_is_rejected_whole(self, mutate, reason):
        data = {"syncMeta": _meta(), "currentWindowsVersion": "v", "refreshMembers": True,
                "users": [_row(1)], "memberWindows": [], "upcoming": [_row(3, frm="2026-09-21")],
                "upcomingIds": [3], "upcomingCredentials": []}
        mutate(data)
        p, err = ad.parse_v2_payload(data)
        assert p is None and err.startswith(reason)

    def test_a_user_row_without_a_window_is_windowless_not_malformed(self):
        row = _row(1)
        row.update(accessFrom=None, accessUntil=None, offDays=[])
        p, err = ad.parse_v2_payload({"syncMeta": _meta(), "refreshMembers": True, "users": [row],
                                      "memberWindows": [], "currentWindowsVersion": "v"})
        assert err is None and p.today_windows == {} and p.windowless_ids == {1}


# ------------------------------------------------------------------ the gym date & the clock
def _clock(**kw):
    base = dict(server_today=_d("2026-09-19"), server_epoch=_epoch("2026-09-19T10:00:00+01:00"),
                utc_offset_sec=TUNIS, skew_sec=2.0, floor_date=_d("2026-09-19"),
                max_pc_epoch=_epoch("2026-09-19T10:00:02+01:00"))
    base.update(kw)
    return ad.ClockState(**base)


class TestGymDate:
    def test_no_protocol_2_state_means_no_gym_date(self):
        g = ad.evaluate_gym_date(ad.ClockState(), _epoch("2026-09-19T10:00:00+01:00"))
        assert g.gym_date is None and not g.suspect

    def test_the_date_comes_from_the_pc_clock_in_tunis_time(self):
        # 23:30 UTC on the 19th is 00:30 on the 20th in Tunis, whatever the PC's own timezone.
        g = ad.evaluate_gym_date(_clock(), _epoch("2026-09-19T23:30:00+00:00"))
        assert g.gym_date == _d("2026-09-20") and not g.suspect
        assert g.new_floor_date == _d("2026-09-20")

    def test_power_on_after_a_night_advances_the_date(self):
        g = ad.evaluate_gym_date(_clock(), _epoch("2026-09-20T07:30:00+01:00"))
        assert g.gym_date == _d("2026-09-20") and not g.suspect

    def test_a_flat_battery_clock_never_goes_below_the_last_server_day(self):
        g = ad.evaluate_gym_date(_clock(), _epoch("2000-01-01T00:05:00+01:00"))
        assert g.suspect and "behind" in g.reason
        assert g.gym_date == _d("2026-09-19")

    def test_nor_below_a_later_day_already_applied_offline(self):
        # Applied 21st while offline, then the battery died: the 21st holds, nobody re-admitted.
        st = _clock(floor_date=_d("2026-09-21"), max_pc_epoch=_epoch("2026-09-21T09:00:00+01:00"))
        g = ad.evaluate_gym_date(st, _epoch("2020-05-05T09:00:00+01:00"))
        assert g.suspect and g.gym_date == _d("2026-09-21")
        assert g.new_floor_date == _d("2026-09-21")
        assert g.new_max_pc_epoch == st.max_pc_epoch      # a suspect clock teaches nothing

    def test_a_clock_moved_back_a_few_hours_is_suspect_and_holds_the_applied_day(self):
        st = _clock(floor_date=_d("2026-09-21"), max_pc_epoch=_epoch("2026-09-21T09:00:00+01:00"))
        g = ad.evaluate_gym_date(st, _epoch("2026-09-20T22:00:00+01:00"))
        assert g.suspect and g.gym_date == _d("2026-09-21")

    def test_a_small_step_back_within_the_tolerance_is_not_suspect(self):
        st = _clock(max_pc_epoch=_epoch("2026-09-19T12:00:00+01:00"))
        g = ad.evaluate_gym_date(st, _epoch("2026-09-19T11:57:00+01:00"))   # 180 s < 300 s
        assert not g.suspect

    def test_a_clock_more_than_a_day_ahead_at_the_last_sync_is_suspect(self):
        st = _clock(skew_sec=ad.CLOCK_AHEAD_LIMIT_SEC + 1)
        g = ad.evaluate_gym_date(st, _epoch("2026-09-21T10:00:00+01:00"))
        assert g.suspect and "ahead" in g.reason and g.gym_date == _d("2026-09-19")

    def test_a_clock_hours_ahead_is_not_suspect_by_the_rule(self):
        st = _clock(skew_sec=4 * 3600)
        g = ad.evaluate_gym_date(st, _epoch("2026-09-19T21:00:00+01:00"))
        assert not g.suspect

    def test_the_sync_measurement(self):
        server = _epoch("2026-09-19T10:00:00+01:00")
        assert ad.clock_at_sync(server, server + 10) == (10.0, "")
        assert ad.clock_at_sync(server, server - 301)[1] == "behind"
        assert ad.clock_at_sync(server, server + 86401)[1] == "ahead"

    def test_seconds_until_the_next_gym_midnight(self):
        now = _epoch("2026-09-19T23:59:50+01:00")
        assert ad.seconds_until_gym_time(now, TUNIS, 0, 0, 5) == pytest.approx(15.0)
        now = _epoch("2026-09-20T00:00:06+01:00")
        assert ad.seconds_until_gym_time(now, TUNIS, 0, 0, 5) == pytest.approx(86399.0)

    def test_gym_seconds_of_day(self):
        assert ad.gym_seconds_of_day(_epoch("2026-09-20T00:16:30+01:00"), TUNIS) == 16 * 60 + 30


# ------------------------------------------------------------------ the flip plan
class TestFlipPlan:
    def _plan(self, gym="2026-09-20", **kw):
        base = dict(gym_date=_d(gym), server_today=_d("2026-09-19"), horizon_end=_d("2026-09-26"),
                    grace_days=0, active_ids=set(), held_ids=set(), today_windows={},
                    upcoming_windows={})
        base.update(kw)
        return ad.plan_flip(**base)

    def test_an_expiry_is_held_out_and_a_starter_promoted(self):
        p = self._plan(active_ids={1, 2}, today_windows={1: _w(until="2026-09-19"), 2: _w()},
                       upcoming_windows={3: _w(frm="2026-09-20")})
        assert p.hold == {1: "expired"} and p.promote == [3] and p.restore == []

    def test_a_freeze_day_holds_and_the_next_day_restores(self):
        tw = {1: _w(off=["2026-09-20"])}
        p = self._plan(active_ids={1}, today_windows=tw)
        assert p.hold == {1: "frozen"}
        p2 = self._plan(gym="2026-09-21", held_ids={1}, today_windows=tw)
        assert p2.restore == [1] and p2.hold == {}

    def test_a_windowless_row_is_never_moved(self):
        p = self._plan(active_ids={1}, today_windows={})
        assert p.hold == {} and p.moved == 0

    def test_a_held_row_whose_window_is_gone_stays_held(self):
        p = self._plan(held_ids={1}, today_windows={})
        assert p.restore == [] and p.moved == 0

    def test_a_promoted_row_is_judged_by_its_upcoming_window_later(self):
        uw = {3: _w(frm="2026-09-20", off=["2026-09-22"])}
        p = self._plan(gym="2026-09-22", active_ids={3}, upcoming_windows=uw)
        assert p.hold == {3: "frozen"}
        p2 = self._plan(gym="2026-09-23", held_ids={3}, upcoming_windows=uw)
        assert p2.restore == [3]

    def test_an_upcoming_row_already_held_is_restored_not_promoted_twice(self):
        uw = {3: _w(frm="2026-09-20")}
        p = self._plan(held_ids={3}, upcoming_windows=uw)
        assert p.restore == [3] and p.promote == []

    def test_starters_on_the_gym_date(self):
        p = self._plan(active_ids={1}, today_windows={1: _w()},
                       upcoming_windows={3: _w(frm="2026-09-20"), 4: _w(frm="2026-09-22")})
        assert p.starters == [3]


# ------------------------------------------------------------------ QR: the date verdict
def _snap(gym="2026-09-20", trusted=True, windows=None, **kw):
    return ad.AccessDaysSnapshot(trusted=trusted, gym_date=_d(gym) if gym else None,
                                 server_today=_d("2026-09-19"), horizon_end=_d("2026-09-26"),
                                 grace_days=kw.pop("grace_days", 0), windows=windows or {},
                                 upcoming_qr_account=kw.pop("upcoming_qr_account", {}), **kw)


class TestQrDateVerdict:
    def test_unchecked_without_trusted_windows(self):
        assert ad.qr_date_verdict(None, grants=[1], users_by_am={}) == "unchecked"
        assert ad.qr_date_verdict(_snap(trusted=False), grants=[1], users_by_am={}) == "unchecked"
        assert ad.qr_date_verdict(_snap(gym=None), grants=[1], users_by_am={}) == "unchecked"

    def test_a_grant_deliverable_today_opens(self):
        assert ad.qr_date_verdict(_snap(windows={1: _w()}), grants=[1], users_by_am={}) == "ok"

    def test_an_expired_grant_does_not_open(self):
        s = _snap(windows={1: _w(until="2026-09-19")})
        assert ad.qr_date_verdict(s, grants=[1], users_by_am={1: {}}) == "not_today"

    def test_a_freeze_day_does_not_open(self):
        s = _snap(windows={1: _w(off=["2026-09-20"])})
        assert ad.qr_date_verdict(s, grants=[1], users_by_am={}) == "not_today"

    def test_any_deliverable_grant_is_enough(self):
        s = _snap(windows={1: _w(until="2026-09-19"), 2: _w()})
        assert ad.qr_date_verdict(s, grants=[1, 2], users_by_am={}) == "ok"

    def test_a_windowless_roster_row_opens(self):
        assert ad.qr_date_verdict(_snap(), grants=[5], users_by_am={5: {}}) == "ok"

    def test_a_grant_with_no_window_and_no_roster_row_is_left_to_the_roster_check(self):
        # Review R2 (inverts the part-D rule): no stored window = no date the PC knows.
        assert ad.qr_date_verdict(_snap(), grants=[5], users_by_am={9: {}}) == "unchecked"

    def test_a_windowed_grant_still_refuses_beside_a_windowless_one_that_is_listed(self):
        s = _snap(windows={1: _w(until="2026-09-19")})
        assert ad.qr_date_verdict(s, grants=[1, 5], users_by_am={5: {}}) == "ok"
        assert ad.qr_date_verdict(s, grants=[1], users_by_am={5: {}}) == "not_today"

    def test_a_renewal_with_stale_grants_opens_by_account(self):
        s = _snap(windows={1: _w(until="2026-09-19")})
        assert ad.qr_date_verdict(s, grants=[1], users_by_am={2: {}}, account_on_roster=True) == "ok"

    def test_an_unevaluable_roster_cannot_refuse_a_windowless_grant(self):
        assert ad.qr_date_verdict(_snap(), grants=[5], users_by_am={}) == "unchecked"
        assert ad.qr_date_verdict(_snap(), grants=[5], users_by_am={9: {}},
                                  roster_current=False) == "unchecked"

    def test_but_a_window_still_refuses_with_an_unevaluable_roster(self):
        s = _snap(windows={1: _w(until="2026-09-19")})
        assert ad.qr_date_verdict(s, grants=[1], users_by_am={}) == "not_today"

    def test_offline_grace_counts_for_qr_too(self):
        s = _snap(windows={1: _w(until="2026-09-19")}, grace_days=1)
        assert ad.qr_date_verdict(s, grants=[1], users_by_am={}) == "ok"


# ------------------------------------------------------------------ QR: upcoming credentials
class TestEffectiveCredentials:
    def _cred(self, cid, account, grants, enabled=True, **extra):
        return {"id": cid, "accountId": account, "enabled": enabled, "secretHex": "ab" * 16,
                "grantedActiveMembershipIds": list(grants), **extra}

    def test_untrusted_windows_change_nothing(self):
        main = [self._cred(1, 50, [1])]
        up = [self._cred(2, 60, [3], enabled=False)]
        assert ad.effective_credentials(main, up, _snap(trusted=False)) == main

    def test_an_upcoming_only_credential_opens_on_its_first_day(self):
        up = [self._cred(2, 60, [3], enabled=False, notYetValid=True)]
        s = _snap(windows={3: _w(frm="2026-09-20")})
        out = ad.effective_credentials([], up, s)
        assert len(out) == 1 and out[0]["enabled"] is True and out[0]["id"] == 2
        assert out[0]["upcomingPromoted"] is True
        assert up[0]["enabled"] is False                      # the stored list is not changed

    def test_but_not_the_day_before(self):
        up = [self._cred(2, 60, [3], enabled=False)]
        s = _snap(gym="2026-09-19", windows={3: _w(frm="2026-09-20")})
        assert ad.effective_credentials([], up, s) == []

    def test_an_account_with_an_enabled_main_credential_is_not_doubled(self):
        main = [self._cred(1, 60, [1])]
        up = [self._cred(2, 60, [3], enabled=False)]
        s = _snap(windows={1: _w(), 3: _w(frm="2026-09-20")})
        out = ad.effective_credentials(main, up, s)
        assert [c["id"] for c in out] == [1]

    def test_a_renewal_adds_the_starting_membership_to_the_existing_credential(self):
        main = [self._cred(1, 60, [1])]
        s = _snap(windows={1: _w(until="2026-09-19"), 3: _w(frm="2026-09-20")},
                  upcoming_qr_account={3: 60})
        out = ad.effective_credentials(main, [], s)
        assert out[0]["grantedActiveMembershipIds"] == [1, 3]
        assert main[0]["grantedActiveMembershipIds"] == [1]   # copied, not mutated

    def test_a_renewal_that_has_not_started_adds_nothing(self):
        main = [self._cred(1, 60, [1])]
        s = _snap(gym="2026-09-19", windows={1: _w(), 3: _w(frm="2026-09-20")},
                  upcoming_qr_account={3: 60})
        assert ad.effective_credentials(main, [], s)[0]["grantedActiveMembershipIds"] == [1]
