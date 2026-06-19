"""Tests for scan-time (event_time) TOTP validation and clock-skew handling.

Covers the production incident fix: the gym PC validated QR/TOTP codes against
wall-clock-at-processing instead of the moment the code was scanned, so RTLog
pipeline latency + clock skew rejected still-valid codes as DENY_NO_MATCH.
"""
import time

import pytest

from app.core.access_verification import (
    EVENT_TIME_SANITY_BOUND_SEC,
    _totp_counter,
    _totp_hotp,
    parse_event_time_to_epoch,
    resolve_totp_clock,
    verify_totp,
    verify_totp_resilient,
)
from app.sdk.pullsdk import zk_datetime_encode, zk_datetime_decode

# RFC-4226 test key: b"12345678901234567890"
_RFC_SECRET_HEX = "3132333435363738393031323334353637383930"
_RFC_SECRET = bytes.fromhex(_RFC_SECRET_HEX)
PERIOD = 30
DIGITS = 6  # gym config: prefix '9' + 6 digits = 7-char QR (matches "9986566")
PREFIX = "9"


def _settings(**over):
    s = {
        "rfid_enabled": True,
        "totp_enabled": True,
        "totp_validation": True,
        "totp_period_seconds": PERIOD,
        "totp_drift_steps": 1,
        "totp_digits": DIGITS,
        "totp_prefix": PREFIX,
        "rfid_min_digits": 1,
        "rfid_max_digits": 16,
        "totp_max_past_age_seconds": 32,
        "totp_max_future_skew_seconds": 3,
    }
    s.update(over)
    return s


def _cred():
    return {
        "id": 1,
        "accountId": 10,
        "secretHex": _RFC_SECRET_HEX,
        "grantedActiveMembershipIds": [42],
        "enabled": True,
    }


def _qr_for(scan_epoch: float) -> str:
    """The QR string a phone shows at scan_epoch: prefix + HOTP(counter)."""
    ctr = _totp_counter(int(scan_epoch), PERIOD)
    return PREFIX + _totp_hotp(_RFC_SECRET, ctr, DIGITS)


# ── The core fix ─────────────────────────────────────────────────────────────

def test_late_processing_rejects_without_scan_time(monkeypatch):
    """Reproduces the bug: a valid code processed 60s late is rejected when
    validated at processing wall-clock (the pre-fix behaviour)."""
    scan = 1_700_000_000 + 10  # 10s into its 30s window
    qr = _qr_for(scan)
    monkeypatch.setattr(time, "time", lambda: float(scan + 60))  # processed 60s late
    r = verify_totp(
        scanned=qr, settings=_settings(), creds_payload=[_cred()],
        users_by_am={42: {"activeMembershipId": 42}}, users_by_card={},
    )
    assert r["allowed"] is False
    assert r["reason"] in ("DENY_NO_MATCH", "DENY_EXPIRED")


def test_late_processing_allows_with_scan_time(monkeypatch):
    """The fix: validating at the scan time accepts the code no matter how late
    the PC processes it."""
    scan = 1_700_000_000 + 10
    qr = _qr_for(scan)
    monkeypatch.setattr(time, "time", lambda: float(scan + 300))  # 5 min late
    r = verify_totp(
        scanned=qr, settings=_settings(), creds_payload=[_cred()],
        users_by_am={42: {"activeMembershipId": 42}}, users_by_card={},
        now_unix=float(scan),
    )
    assert r["allowed"] is True
    assert r["reason"] == "ALLOW"
    # Age is measured from the scan time (within one period), NOT the 300s of
    # processing latency — which is the whole point of the fix.
    assert 0 <= r["ageSeconds"] < PERIOD


def test_fresh_code_still_allows_without_scan_time(monkeypatch):
    """Sanity: with no latency, the default (wall-clock) path still works."""
    scan = 1_700_000_000 + 5
    qr = _qr_for(scan)
    monkeypatch.setattr(time, "time", lambda: float(scan))
    r = verify_totp(
        scanned=qr, settings=_settings(), creds_payload=[_cred()],
        users_by_am={42: {"activeMembershipId": 42}}, users_by_card={},
    )
    assert r["allowed"] is True


# ── parse_event_time_to_epoch ────────────────────────────────────────────────

def test_parse_event_time_epoch_seconds_and_ms():
    assert parse_event_time_to_epoch("1700000000") == 1700000000.0
    assert parse_event_time_to_epoch("1700000000000") == 1700000000.0


def test_parse_event_time_iso_utc():
    assert parse_event_time_to_epoch("2023-11-14T22:13:20Z") == pytest.approx(1700000000.0, abs=1)


def test_parse_event_time_local_roundtrip():
    epoch = 1_700_000_000.0
    s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    assert parse_event_time_to_epoch(s) == pytest.approx(epoch, abs=1)


def test_parse_event_time_garbage():
    assert parse_event_time_to_epoch("not a time") is None
    assert parse_event_time_to_epoch("") is None
    assert parse_event_time_to_epoch(None) is None  # type: ignore[arg-type]


# ── resolve_totp_clock (sanity bound) ────────────────────────────────────────

def test_resolve_totp_clock_within_bound(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1_700_000_000.0)
    assert resolve_totp_clock(1_700_000_030.0) == 1_700_000_030.0


def test_resolve_totp_clock_none():
    assert resolve_totp_clock(None) is None


def test_resolve_totp_clock_beyond_bound_falls_back(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1_700_000_000.0)
    far = 1_700_000_000.0 + EVENT_TIME_SANITY_BOUND_SEC + 100
    assert resolve_totp_clock(far) is None  # device clock misconfigured → use wall clock


# ── ZK DateTime codec (device-clock discipline) ──────────────────────────────

# ── verify_totp_resilient (dual-clock: scan time OR wall clock) ───────────────

def test_resilient_allows_via_scan_when_pc_clock_wrong(monkeypatch):
    """PC clock is far ahead; device scan time is accurate → accept via scan."""
    scan = 1_700_000_000 + 7
    qr = _qr_for(scan)
    monkeypatch.setattr(time, "time", lambda: float(scan + 200))  # PC 200s ahead
    r = verify_totp_resilient(
        scanned=qr, settings=_settings(), creds_payload=[_cred()],
        users_by_am={42: {"activeMembershipId": 42}}, users_by_card={},
        scan_epoch=float(scan),
    )
    assert r["allowed"] is True
    assert r["clockUsed"] == "scan"


def test_resilient_allows_via_wall_when_device_clock_wrong(monkeypatch):
    """Device RTC is 120s behind; PC clock is accurate → accept via wall clock."""
    real = 1_700_000_000 + 7
    qr = _qr_for(real)
    monkeypatch.setattr(time, "time", lambda: float(real))  # PC accurate
    r = verify_totp_resilient(
        scanned=qr, settings=_settings(), creds_payload=[_cred()],
        users_by_am={42: {"activeMembershipId": 42}}, users_by_card={},
        scan_epoch=float(real - 120),  # device timestamp 120s behind reality
    )
    assert r["allowed"] is True
    assert r["clockUsed"] == "wall"


def test_resilient_denies_when_both_clocks_wrong(monkeypatch):
    """Neither the PC clock nor the device timestamp is near reality → deny."""
    real = 1_700_000_000 + 7
    qr = _qr_for(real)
    monkeypatch.setattr(time, "time", lambda: float(real + 200))  # PC 200s ahead
    r = verify_totp_resilient(
        scanned=qr, settings=_settings(), creds_payload=[_cred()],
        users_by_am={42: {"activeMembershipId": 42}}, users_by_card={},
        scan_epoch=float(real - 200),  # device 200s behind
    )
    assert r["allowed"] is False


@pytest.mark.parametrize(
    "y,mo,d,h,mi,s",
    [
        (2026, 6, 12, 12, 6, 59),
        (2000, 1, 1, 0, 0, 0),
        (2031, 12, 31, 23, 59, 59),
    ],
)
def test_zk_datetime_roundtrip(y, mo, d, h, mi, s):
    enc = zk_datetime_encode(y, mo, d, h, mi, s)
    assert zk_datetime_decode(enc) == (y, mo, d, h, mi, s)
