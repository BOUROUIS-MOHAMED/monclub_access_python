from datetime import date, datetime

import pytest

from app.core import entry_limits as el


def dt(value):
    return datetime.fromisoformat(value)


def state(raw, passes, now, start="2026-11-01", end="2026-11-30", from_=None,
          adjustment=0, frozen=False):
    limits = el.parse_limits(raw)
    return el.evaluate(limits, date.fromisoformat(start), date.fromisoformat(end),
                       date.fromisoformat(from_) if from_ else None, frozen,
                       el.group_visits(map(dt, passes), limits.visit_minutes), adjustment, dt(now))


def test_v01_three_hour_visits():
    assert el.group_visits(map(dt, ["2026-11-02T05:00", "2026-11-02T06:10",
                                   "2026-11-02T07:59", "2026-11-02T08:00"]), 180) == [
        dt("2026-11-02T05:00"), dt("2026-11-02T08:00")]


def test_v02_two_hour_visits():
    assert el.group_visits(map(dt, ["2026-11-02T05:00", "2026-11-02T06:59",
                                   "2026-11-02T07:00"]), 120) == [
        dt("2026-11-02T05:00"), dt("2026-11-02T07:00")]


def test_v03_running_visit():
    assert not state({"perDay": 1}, ["2026-11-02T05:00"], "2026-11-02T07:59").held


def test_v04_visit_end_holds():
    s = state({"perDay": 1}, ["2026-11-02T05:00"], "2026-11-02T08:00")
    assert s.held and s.blocked_until == dt("2026-11-02T23:55") and s.reasons == {"DAY"}


def test_v05_release_lead():
    assert not state({"perDay": 1}, ["2026-11-02T05:00"], "2026-11-02T23:55").held


def test_v06_second_visit_boundary():
    passes = ["2026-11-02T05:00", "2026-11-02T09:00"]
    assert not state({"perDay": 2}, passes, "2026-11-02T11:59").held
    s = state({"perDay": 2}, passes, "2026-11-02T12:00")
    assert s.held and s.blocked_until == dt("2026-11-02T23:55")


def test_v07_limit_day_stays_open():
    assert not state({"perWeekDays": 2}, ["2026-11-02T10:00", "2026-11-03T10:00"],
                     "2026-11-03T18:00").held


def test_v08_new_day_blocked():
    s = state({"perWeekDays": 2}, ["2026-11-02T10:00", "2026-11-03T10:00"], "2026-11-04T08:00")
    assert s.held and s.blocked_until == dt("2026-11-08T23:55")


def test_v09_anchored_month():
    passes = ["2026-10-20T10:00", "2026-10-25T10:00"]
    s = state({"perMonth": 2}, passes, "2026-11-14T12:00", start="2026-10-15")
    assert s.held and s.blocked_until == dt("2026-11-14T23:55")
    assert not state({"perMonth": 2}, passes, "2026-11-15T12:00", start="2026-10-15").held


def test_v10_exhausted():
    s = state({"total": 2}, ["2026-11-01T10:00", "2026-11-02T10:00"], "2026-11-02T13:00")
    assert s.held and s.exhausted and s.blocked_until is None


def test_v11_adjustment():
    s = state({"total": 2}, ["2026-11-01T10:00", "2026-11-02T10:00"], "2026-11-02T13:00", adjustment=1)
    assert not s.held and s.total_used == 1


def test_v12_inclusive_apply_day():
    assert state({"perDay": 1}, ["2026-11-02T08:00"], "2026-11-02T12:00", from_="2026-11-02").held


def test_v13_week_before_apply():
    assert not state({"perWeekDays": 1}, ["2026-11-02T10:00"], "2026-11-04T10:00", from_="2026-11-04").held


def test_v14_total_ignores_apply_day():
    assert state({"total": 2}, ["2026-11-02T10:00", "2026-11-03T10:00"], "2026-11-04T12:00", from_="2026-11-04").held


def test_v15_visit_across_midnight():
    s = state({"perDay": 1}, ["2026-11-01T23:00", "2026-11-02T00:30"], "2026-11-02T01:00")
    assert not s.held and s.today == 0


def test_v16_month_clamp():
    assert el.add_months(date(2026, 1, 31), 1) == date(2026, 2, 28)
    assert el.add_months(date(2026, 1, 31), 2) == date(2026, 3, 31)
    s = state({"perMonth": 1}, ["2026-02-28T08:00"], "2026-02-28T12:00", start="2026-01-31", end="2026-04-30")
    assert s.blocked_until == dt("2026-03-30T23:55")


def usage(**kw):
    return el.parse_usage({"asOf": None, "listFrom": "2026-11-01T00:00:00", "totalBefore": 0,
                           "visits": ["2026-11-02T05:00:00"], "termStart": "2026-11-01",
                           "termEnd": "2026-11-30", "from": None, **kw})


def test_merge_uploaded_and_pending_local_passes():
    limits = el.parse_limits({"total": 2})
    s = el.merged_state(limits, usage(), [dt("2026-11-02T05:30"), dt("2026-11-02T09:00")], dt("2026-11-02T12:00"))
    assert s.total_used == 2 and s.held
    assert el.merged_state(limits, usage(totalBefore=-5), [], dt("2026-11-02T12:00")).total_used == 0


def test_merge_uploaded_pass_stays_in_backend_visit():
    s = el.merged_state(el.parse_limits({"total": 2}), usage(),
                        [dt("2026-11-02T05:30")], dt("2026-11-02T12:00"))
    assert s.total_used == 1 and not s.held


def test_merge_pending_pass_counts_even_before_as_of():
    s = el.merged_state(el.parse_limits({"total": 2}), usage(asOf="2026-11-02T11:00:00"),
                        [dt("2026-11-02T09:00")], dt("2026-11-02T12:00"))
    assert s.total_used == 2 and s.held


def test_merge_excludes_local_passes_before_list_from():
    s = el.merged_state(el.parse_limits({"total": 2}), usage(),
                        [dt("2026-10-31T12:00")], dt("2026-11-02T12:00"))
    assert s.total_used == 1


@pytest.mark.parametrize("raw", [None, "bad", "{}", {}, {"visitMinutes": 180}, {"total": True},
                                      {"total": "1"}, {"total": 1.5}, {"total": 501}, {"perDay": 21},
                                      {"perWeekDays": 8}, {"perMonth": 101}, {"total": 1, "visitMinutes": 31}])
def test_bad_limits_fail_open(raw):
    assert el.parse_limits(raw) is None


@pytest.mark.parametrize("kw", [{"listFrom": "bad"}, {"visits": ["bad"]}, {"totalBefore": True},
                                    {"asOf": "2026-11-02T00:00:00Z"}, {"termEnd": "2026-10-01"}])
def test_bad_usage_fails_open(kw):
    assert usage(**kw) is None


def test_frozen_keeps_counters_without_holding():
    s = state({"total": 1}, ["2026-11-02T05:00"], "2026-11-02T08:00", frozen=True)
    assert s.total_used == 1 and s.exhausted and not s.held
