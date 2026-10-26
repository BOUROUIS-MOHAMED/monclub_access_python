from datetime import datetime

import pytest

from app.core.off_hours import (OffWindow, closed, decode_windows, encode_windows, held,
                               local_week_minute, parse_windows, plan_off_hours)


def test_gym_week_minute():
    epoch = datetime.fromisoformat("2026-10-26T00:00:00+01:00").timestamp()
    assert local_week_minute(epoch, 3600) == (0, 0)
    assert local_week_minute(epoch - 1, 3600) == (6, 1439)
    assert local_week_minute(epoch, 0) == (6, 1380)
    assert local_week_minute(epoch, -3600) == (6, 1320)


@pytest.mark.parametrize("ws,day,minute,is_held,is_closed", [
    ((OffWindow(0, 1320, 480),), 1, 359, False, True),
    ((OffWindow(0, 1320, 480),), 1, 360, False, False),
    ((OffWindow(0, 1320, 480),), 1, 354, True, True),
    ((OffWindow(0, 1320, 480),), 1, 355, False, True),
    ((OffWindow(6, 1380, 120),), 0, 59, False, True),
    ((OffWindow(6, 1380, 120),), 0, 54, True, True),
    ((OffWindow(0, 720, 120),), 1, 0, False, False),
    ((OffWindow(0, 720, 15),), 0, 729, True, True),
    ((OffWindow(0, 720, 15),), 0, 730, False, True),
    ((OffWindow(0, 720, 15), OffWindow(1, 720, 15)), 1, 720, True, True),
    ((), 0, 0, False, False),
])
def test_boundaries(ws, day, minute, is_held, is_closed):
    assert held(ws, day, minute) is is_held
    assert closed(ws, day, minute) is is_closed


def test_lenient_parse_and_roundtrip():
    good = {"day": "MON", "startMinute": 1320, "durationMinutes": 480}
    bad = [None, 1, [], {}, {**good, "startMinute": True}, {**good, "day": []},
           {**good, "durationMinutes": 1440}, {**good, "startMinute": 1}]
    assert parse_windows(bad + [good]) == (OffWindow(0, 1320, 480),)
    assert len(parse_windows([good] * 8)) == 7
    for raw in (None, "", {}, 1, False):
        assert parse_windows(raw) == ()
    ws = parse_windows([good])
    assert decode_windows(encode_windows(ws)) == ws
    assert decode_windows("bad json") == ()
    assert encode_windows(()) is None


@pytest.mark.parametrize("trust,suspect,offset", [(True, False, 3600), (False, False, 3600),
                                                        (True, True, 3600), (True, False, None)])
def test_plan_and_fail_open(trust, suspect, offset):
    p = plan_off_hours(now_epoch=datetime.fromisoformat("2026-10-26T23:00:00+01:00").timestamp(),
                       utc_offset_sec=offset, trusted=trust, clock_suspect=suspect,
                       windows_by_am={n: (OffWindow(0, 1320, 480),) for n in (1, 2, 9)},
                       known_ids={1, 2, 3}, intent_ids={2, 3, 8})
    if trust and not suspect and offset is not None:
        assert p.target == {1, 2} and p.newly_held == {1} and p.retry == {2}
        assert p.released == {3, 8}
    else:
        assert not p.target and p.released == {2, 3, 8}
