"""P3b-2 step 1: the server clock (owner decision 5a), lenient time parsing, and the v2 HTTP
client (error envelope, what counts as "the server switched v2 off", rate-limit back-off,
``sentAt`` stamped per attempt).

Wire facts are from backend main c7d4b532 (read-only): success bodies are raw DTOs, errors are
``{status:false, errorMsg, code, details}``; with ``monclub.access.v2.commands.enabled`` off every
v2 PC route answers 404 ``NOT_FOUND`` in that envelope; REST ``LocalDateTime`` fields are Tunis
local time with 0-6 fraction digits; the socket's times carry an offset and 0-3 digits.
"""
from __future__ import annotations

import json
import time

import pytest

from app.core.v2 import timefmt
from app.core.v2.server_clock import ServerClock
from app.core.v2.api import V2Api, V2ApiError


# --------------------------------------------------------------------------- times

@pytest.mark.parametrize("text,expected", [
    ("2026-09-26T10:00:00+01:00", 1790413200.0),
    ("2026-09-26T10:00:00.12+01:00", 1790413200.12),
    ("2026-09-26T10:00:00.123+01:00", 1790413200.123),
    ("2026-09-26T09:00:00.123456Z", 1790413200.123456),
    ("2026-09-26T10:00+01:00", 1790413200.0),
])
def test_offset_times_parse_with_any_fraction_length(text, expected):
    assert timefmt.to_epoch(text) == pytest.approx(expected, abs=1e-6)


def test_a_local_time_needs_the_gym_offset():
    assert timefmt.to_epoch("2026-09-26T10:00:00.123456") is None
    assert timefmt.to_epoch("2026-09-26T10:00:00.123456", default_offset_sec=3600) == pytest.approx(
        1790413200.123456, abs=1e-6)
    # CLOCK_SKEW details.serverTime is LocalDateTime.toString(): seconds dropped when zero.
    assert timefmt.to_epoch("2026-09-26T10:00", default_offset_sec=3600) == pytest.approx(1790413200.0)


@pytest.mark.parametrize("bad", ["", None, "yesterday", "2026-13-01T00:00:00Z", "2026-09-26 10:00:00+1"])
def test_unreadable_times_are_none(bad):
    assert timefmt.to_epoch(bad, default_offset_sec=0) is None


def test_offset_is_read_from_a_socket_time():
    assert timefmt.utc_offset_of("2026-09-26T10:00:00.12+01:00") == 3600
    assert timefmt.utc_offset_of("2026-09-26T09:00:00Z") == 0
    assert timefmt.utc_offset_of("2026-09-26T10:00:00") is None


def test_the_distance_between_two_local_times_needs_no_offset():
    # claim answers carry serverTime and finishBy in the same Tunis local clock.
    assert timefmt.local_seconds_between("2026-09-26T10:00:00.5", "2026-09-26T10:00:20") == pytest.approx(19.5)


def test_sent_times_are_utc_with_microseconds():
    assert timefmt.format_utc(1790413200.123456) == "2026-09-26T09:00:00.123456Z"
    assert timefmt.to_epoch(timefmt.format_utc(1790413200.5)) == pytest.approx(1790413200.5)


# --------------------------------------------------------------------------- clock

class _Clocks:
    def __init__(self, wall=1_000_000.0):
        self.wall_v = wall
        self.mono_v = 50.0

    def wall(self):
        return self.wall_v

    def mono(self):
        return self.mono_v

    def advance(self, sec):
        self.wall_v += sec
        self.mono_v += sec


def test_no_sample_means_no_offset_and_the_pc_clock():
    c = _Clocks()
    clk = ServerClock(wall=c.wall, mono=c.mono)
    assert not clk.has_sample()
    assert clk.offset() is None
    assert clk.now() == pytest.approx(c.wall_v)


def test_a_sample_is_the_server_time_minus_the_midpoint_of_the_request():
    c = _Clocks()
    clk = ServerClock(wall=c.wall, mono=c.mono)
    # PC sent at 1000, got the answer at 1002; the server stamped 1101 -> PC is 100 s behind.
    assert clk.add_sample(1101.0, 1000.0, 1002.0, source="test")
    assert clk.offset() == pytest.approx(100.0)
    assert clk.now() == pytest.approx(c.wall_v + 100.0)
    assert clk.has_sample()


def test_a_slow_round_trip_is_not_a_sample():
    c = _Clocks()
    clk = ServerClock(wall=c.wall, mono=c.mono)
    assert not clk.add_sample(2000.0, 1000.0, 1006.0, source="test")
    assert clk.offset() is None


def test_the_offset_is_the_median_so_one_wild_sample_moves_nothing():
    c = _Clocks()
    clk = ServerClock(wall=c.wall, mono=c.mono)
    for server in (1010.0, 1010.2, 1009.9, 5000.0, 1010.1):
        clk.add_sample(server, 1000.0, 1000.0, source="t")
    assert clk.offset() == pytest.approx(10.1, abs=0.15)


def test_corrected_time_never_goes_backwards_it_slows_down_instead():
    c = _Clocks()
    clk = ServerClock(wall=c.wall, mono=c.mono)
    clk.add_sample(c.wall_v + 120.0, c.wall_v, c.wall_v, source="t")    # server 120 s ahead
    first = clk.now()
    # Better samples arrive: the server is really only 20 s ahead.
    for _ in range(7):
        clk.add_sample(c.wall_v + 20.0, c.wall_v, c.wall_v, source="t")
    issued = [first]
    for _ in range(40):
        c.advance(5.0)
        issued.append(clk.now())
    assert all(b >= a for a, b in zip(issued, issued[1:])), "corrected time went backwards"
    assert issued[-1] == pytest.approx(c.wall_v + 20.0, abs=0.01), "it converged on the new offset"


def test_a_pc_clock_stepped_back_does_not_rewind_the_corrected_time():
    c = _Clocks()
    clk = ServerClock(wall=c.wall, mono=c.mono)
    clk.add_sample(c.wall_v, c.wall_v, c.wall_v, source="t")
    before = clk.now()
    c.wall_v -= 3600.0          # someone set the PC clock back an hour
    c.mono_v += 1.0
    assert clk.now() > before


def test_the_offset_is_persisted_and_reused_after_a_restart_only_while_recent():
    c = _Clocks()
    saved = {}
    clk = ServerClock(wall=c.wall, mono=c.mono, persist=lambda d: saved.update(d))
    clk.add_sample(c.wall_v + 42.0, c.wall_v, c.wall_v, source="t")
    clk.flush()
    assert saved["offset_sec"] == pytest.approx(42.0)
    c2 = _Clocks(wall=c.wall_v + 600.0)
    again = ServerClock(wall=c2.wall, mono=c2.mono, load=lambda: dict(saved))
    assert again.has_sample() and again.offset() == pytest.approx(42.0)
    stale = ServerClock(wall=_Clocks(wall=c.wall_v + 13 * 3600.0).wall, mono=c2.mono, load=lambda: dict(saved))
    assert not stale.has_sample(), "a day-old offset is not a measurement of today's clock"


def test_the_report_carries_the_offset_for_the_heartbeat():
    c = _Clocks()
    clk = ServerClock(wall=c.wall, mono=c.mono)
    assert clk.report() is None
    clk.add_sample(c.wall_v - 3.5, c.wall_v, c.wall_v, source="welcome")
    rep = clk.report()
    assert rep["offsetSec"] == pytest.approx(-3.5)
    assert rep["samples"] == 1
    assert rep["source"] == "welcome"


# --------------------------------------------------------------------------- HTTP client

class _Resp:
    def __init__(self, status, body, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        if isinstance(self._body, (dict, list)):
            return self._body
        return json.loads(self._body)


class _Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _api(responses, *, clock=None, token="tok"):
    s = _Session(responses)
    api = V2Api(base_url="https://example.test", token_provider=lambda: token, session=s,
                clock=clock or ServerClock(), app_version="1.4.35")
    return api, s


def test_paths_and_the_bearer_header():
    api, s = _api([_Resp(200, {"serverTime": "2026-09-26T10:00:00", "pollIntervalSec": 120, "commands": []})])
    body = api.pending()
    assert body["pollIntervalSec"] == 120
    method, url, kw = s.calls[0]
    assert (method, url) == ("GET", "https://example.test/api/v1/public/access/v2/pc/commands/pending")
    assert kw["headers"]["Authorization"] == "Bearer tok"
    assert "Origin" not in kw["headers"]
    assert kw["timeout"]


def test_a_backend_404_not_found_is_the_switch_being_off():
    body = {"status": False, "errorMsg": "Resource not found", "code": "NOT_FOUND",
            "details": {"path": "/api/v1/public/access/v2/pc/assignment"}}
    api, _ = _api([_Resp(404, body)])
    with pytest.raises(V2ApiError) as ei:
        api.assignment()
    assert ei.value.switched_off


@pytest.mark.parametrize("resp", [
    _Resp(404, "<html><body>nginx 404</body></html>"),              # a proxy page
    _Resp(404, {"status": False, "code": "DEVICE_NOT_FOUND"}),      # a real v2 answer
    _Resp(502, "<html>bad gateway</html>"),
    ConnectionError("no route to host"),
])
def test_anything_else_is_never_read_as_switched_off(resp):
    api, _ = _api([resp])
    with pytest.raises(Exception) as ei:
        api.assignment()
    assert not getattr(ei.value, "switched_off", False)


def test_a_429_backs_every_call_off_for_retry_after():
    t = {"now": 100.0}
    api, s = _api([_Resp(429, {"status": False, "code": "RATE_LIMITED"}, {"Retry-After": "30"})])
    api._mono = lambda: t["now"]
    with pytest.raises(V2ApiError) as ei:
        api.pending()
    assert ei.value.status == 429
    with pytest.raises(V2ApiError) as ei2:
        api.pending()                           # no request sent while backing off
    assert ei2.value.code == "LOCAL_BACKOFF" and len(s.calls) == 1
    t["now"] += 31.0
    s.responses.append(_Resp(200, {"commands": []}))
    api.pending()
    assert len(s.calls) == 2


def test_no_token_sends_nothing():
    api, s = _api([], token=None)
    with pytest.raises(V2ApiError) as ei:
        api.pending()
    assert ei.value.code == "NO_PC_TOKEN" and not s.calls


def test_sent_at_is_stamped_per_attempt_from_the_corrected_clock():
    c = _Clocks(wall=1790413200.0)
    clk = ServerClock(wall=c.wall, mono=c.mono)
    clk.add_sample(c.wall_v + 7.0, c.wall_v, c.wall_v, source="t")
    api, s = _api([_Resp(200, {"stored": 0})], clock=clk)
    api.ownership_upload({"gymDeviceId": 8, "pinScheme": "MEMBERSHIP", "generation": 1,
                          "finalPage": False, "rows": []})
    sent = s.calls[0][2]["json"]["sentAt"]
    assert timefmt.to_epoch(sent) == pytest.approx(c.wall_v + 7.0, abs=1e-3)


def test_a_clock_skew_refusal_is_a_sample_and_the_page_is_sent_once_more():
    c = _Clocks(wall=1790413200.0)
    clk = ServerClock(wall=c.wall, mono=c.mono)
    clk.set_utc_offset(3600)
    skew = {"status": False, "code": "CLOCK_SKEW",
            "details": {"serverTime": "2026-09-26T10:10:00", "skewSeconds": 600}}
    api, s = _api([_Resp(409, skew), _Resp(200, {"stored": 1})], clock=clk)
    out = api.turnstile_problems({"gymDeviceId": 8, "pinScheme": "MEMBERSHIP",
                                  "observedAt": timefmt.format_utc(c.wall_v), "problems": []})
    assert out == {"stored": 1}
    assert clk.offset() == pytest.approx(600.0, abs=1.0)
    first, second = (timefmt.to_epoch(call[2]["json"]["sentAt"]) for call in s.calls)
    assert second - first == pytest.approx(600.0, abs=1.0)


def test_rest_server_times_feed_the_clock_when_the_gym_offset_is_known():
    c = _Clocks(wall=1790413200.0)          # 09:00:00Z = 10:00:00 Tunis
    clk = ServerClock(wall=c.wall, mono=c.mono)
    clk.set_utc_offset(3600)
    api, _ = _api([_Resp(200, {"serverTime": "2026-09-26T10:00:05.000001", "commands": []})], clock=clk)
    api._wall = c.wall
    api.pending()
    assert clk.offset() == pytest.approx(5.0, abs=0.01)


def test_a_clock_skew_refusal_outvotes_earlier_wrong_samples():
    # Found in the end-to-end run: a PC that believed the server 15 min ahead got CLOCK_SKEW,
    # but the median of [900, 0] is 450 s -- still refused on the retry.
    c = _Clocks(wall=1790413200.0)
    clk = ServerClock(wall=c.wall, mono=c.mono)
    clk.set_utc_offset(3600)
    clk.add_sample(c.wall_v + 900.0, c.wall_v, c.wall_v, source="wrong")
    skew = {"status": False, "code": "CLOCK_SKEW",
            "details": {"serverTime": "2026-09-26T10:00:00", "skewSeconds": -900}}
    api, s = _api([_Resp(409, skew), _Resp(200, {"stored": 1})], clock=clk)
    api._wall = c.wall
    assert api.turnstile_problems({"gymDeviceId": 8, "pinScheme": "MEMBERSHIP", "problems": []}) == {"stored": 1}
    assert clk.offset() == pytest.approx(0.0, abs=1.0)
    assert timefmt.to_epoch(s.calls[1][2]["json"]["sentAt"]) == pytest.approx(c.wall_v, abs=1.0)


def test_fact_times_are_capped_at_the_sent_at_of_each_attempt():
    # Found in the end-to-end run: after a CLOCK_SKEW correction the body's observedAt (computed
    # with the old estimate) was later than the new sentAt -> 400 OBSERVED_AT_INVALID.
    c = _Clocks(wall=1790413200.0)
    clk = ServerClock(wall=c.wall, mono=c.mono)
    clk.set_utc_offset(3600)
    clk.add_sample(c.wall_v + 900.0, c.wall_v, c.wall_v, source="wrong")
    early = timefmt.format_utc(clk.now())
    skew = {"status": False, "code": "CLOCK_SKEW", "details": {"serverTime": "2026-09-26T10:00:00"}}
    api, s = _api([_Resp(409, skew), _Resp(200, {"stored": 1})], clock=clk)
    api._wall = c.wall
    api.ownership_upload({"gymDeviceId": 8, "pinScheme": "MEMBERSHIP", "generation": 1, "finalPage": False,
                          "rows": [{"pin": "1", "state": "APPLIED", "observedAt": early}]})
    second = s.calls[1][2]["json"]
    assert timefmt.to_epoch(second["rows"][0]["observedAt"]) <= timefmt.to_epoch(second["sentAt"])
    assert api.last_body["rows"][0]["observedAt"] == second["rows"][0]["observedAt"]
