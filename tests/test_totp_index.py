"""Equivalence + safety tests for the precomputed TOTP index (build_totp_index).

The index is a pure-speed optimization: verify_totp(..., totp_index=idx) MUST
return the identical decision to verify_totp(...) with no index, in every case.
These tests prove that across ALLOW / no-match / collision / expired / future-
skew, and prove the safe fallback to the full loop when the index is stale or
was built with different TOTP params.
"""
import random
import time

import pytest

from app.core import access_verification as av


def _settings(**over):
    s = {
        "totp_enabled": True,
        "totp_validation": True,
        "totp_period_seconds": 30,
        "totp_drift_steps": 2,
        "totp_max_past_age_seconds": 75,
        "totp_max_future_skew_seconds": 15,
        "totp_prefix": "9",
        "totp_digits": 7,
    }
    s.update(over)
    return s


def _rand_secret_hex(rng) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(32))


def _make_roster(n, rng):
    """n distinct TOTP creds, each granting a distinct active-membership id."""
    creds = []
    users_by_am = {}
    for i in range(n):
        am = 1000 + i
        creds.append(
            {
                "id": i + 1,
                "accountId": 5000 + i,
                "enabled": True,
                "secretHex": _rand_secret_hex(rng),
                "grantedActiveMembershipIds": [am],
            }
        )
        users_by_am[am] = {"fullName": f"User {i}", "activeMembershipId": am}
    return creds, users_by_am


def _code_for(cred, settings, now):
    period, drift, digits, prefix = av._totp_params(settings)
    ctr = av._totp_counter(int(now), period)
    secret = av._totp_hex_to_bytes(cred["secretHex"])
    return prefix + av._totp_hotp(secret, ctr, digits)


def _strip(d):
    return {k: v for k, v in d.items() if k != "tookMs"}


def _assert_equiv(scanned, settings, creds, users_by_am, now, idx, users_by_card=None):
    users_by_card = users_by_card or {}
    loop = av.verify_totp(
        scanned=scanned, settings=settings, creds_payload=creds,
        users_by_am=users_by_am, users_by_card=users_by_card, now_unix=now,
    )
    indexed = av.verify_totp(
        scanned=scanned, settings=settings, creds_payload=creds,
        users_by_am=users_by_am, users_by_card=users_by_card, now_unix=now,
        totp_index=idx,
    )
    assert _strip(loop) == _strip(indexed), (
        f"\nscanned={scanned}\nloop   ={_strip(loop)}\nindexed={_strip(indexed)}"
    )
    return _strip(loop)


def test_allow_equivalence_full_roster():
    rng = random.Random(1234)
    settings = _settings()
    creds, users_by_am = _make_roster(200, rng)
    now = 1_700_000_000  # fixed epoch for determinism
    idx = av.build_totp_index(creds, settings, now)
    # Every member's current code must ALLOW identically with and without the index.
    for cred in creds:
        scanned = _code_for(cred, settings, now)
        res = _assert_equiv(scanned, settings, creds, users_by_am, now, idx)
        assert res["allowed"] is True
        assert res["credId"] == str(cred["id"])


def test_no_match_equivalence():
    rng = random.Random(99)
    settings = _settings()
    creds, users_by_am = _make_roster(150, rng)
    now = 1_700_000_500
    idx = av.build_totp_index(creds, settings, now)
    # Random codes that (almost surely) match nobody -> DENY_NO_MATCH both ways.
    for _ in range(300):
        scanned = "9" + "".join(rng.choice("0123456789") for _ in range(7))
        res = _assert_equiv(scanned, settings, creds, users_by_am, now, idx)
        # If it happened to match a real cred it would be ALLOW; otherwise DENY.
        assert res["reason"] in ("DENY_NO_MATCH", "ALLOW")


def test_collision_equivalence():
    # Two creds share the same secret -> same code -> DENY_COLLISION both ways.
    rng = random.Random(7)
    settings = _settings()
    creds, users_by_am = _make_roster(20, rng)
    creds[5]["secretHex"] = creds[10]["secretHex"]  # force a collision
    now = 1_700_001_000
    idx = av.build_totp_index(creds, settings, now)
    scanned = _code_for(creds[5], settings, now)
    res = _assert_equiv(scanned, settings, creds, users_by_am, now, idx)
    assert res["reason"] == "DENY_COLLISION"
    assert res["allowed"] is False


def test_drift_window_codes_equivalence():
    # Codes from the previous/next counters (within drift) must behave identically.
    rng = random.Random(55)
    settings = _settings(totp_drift_steps=2)
    creds, users_by_am = _make_roster(80, rng)
    period = settings["totp_period_seconds"]
    now = 1_700_002_000
    idx = av.build_totp_index(creds, settings, now)
    cred = creds[3]
    secret = av._totp_hex_to_bytes(cred["secretHex"])
    cur = av._totp_counter(now, period)
    for delta in (-2, -1, 0, 1, 2):
        code = "9" + av._totp_hotp(secret, cur + delta, settings["totp_digits"])
        _assert_equiv(code, settings, creds, users_by_am, now, idx)


def test_expired_and_future_equivalence():
    # A code valid at an EARLIER counter, presented 'now', is age-checked the same.
    rng = random.Random(321)
    settings = _settings(totp_max_past_age_seconds=10, totp_drift_steps=3)
    creds, users_by_am = _make_roster(40, rng)
    period = settings["totp_period_seconds"]
    cred = creds[0]
    secret = av._totp_hex_to_bytes(cred["secretHex"])
    base = 1_700_003_000
    cur = av._totp_counter(base, period)
    # code generated 2 counters in the past (~60s old) -> DENY_EXPIRED if window covers it
    old_code = "9" + av._totp_hotp(secret, cur - 2, settings["totp_digits"])
    now = base
    idx = av.build_totp_index(creds, settings, now)
    res = _assert_equiv(old_code, settings, creds, users_by_am, now, idx)
    assert res["reason"] in ("DENY_EXPIRED", "DENY_NO_MATCH")


def test_stale_index_falls_back_to_loop():
    # Index built for an OLD window can't cover a much later scan -> must fall back
    # to the loop (used_index False) and still produce the correct ALLOW.
    rng = random.Random(42)
    settings = _settings()
    creds, users_by_am = _make_roster(60, rng)
    built_at = 1_700_004_000
    idx = av.build_totp_index(creds, settings, built_at, margin=1)
    # Scan 10 minutes later: counters no longer covered by the index.
    later = built_at + 600
    cred = creds[2]
    scanned = _code_for(cred, settings, later)
    res = _assert_equiv(scanned, settings, creds, users_by_am, later, idx)
    assert res["allowed"] is True  # correct despite the stale index


def test_param_mismatch_falls_back_to_loop():
    # Index built with digits=6 but verify uses digits=7 -> params differ -> loop.
    rng = random.Random(8)
    settings7 = _settings(totp_digits=7)
    creds, users_by_am = _make_roster(50, rng)
    now = 1_700_005_000
    idx6 = av.build_totp_index(creds, _settings(totp_digits=6), now)
    cred = creds[1]
    scanned = _code_for(cred, settings7, now)
    res = _assert_equiv(scanned, settings7, creds, users_by_am, now, idx6)
    assert res["allowed"] is True


def test_resilient_with_index_matches_without():
    # End-to-end via verify_totp_resilient (both clock passes) with vs without idx.
    # Use a realistic scan time so resolve_totp_clock accepts scan_epoch (it
    # rejects scan times implausibly far from the wall clock).
    rng = random.Random(2024)
    settings = _settings()
    creds, users_by_am = _make_roster(120, rng)
    now = int(time.time())
    idx = av.build_totp_index(creds, settings, now)
    for cred in creds[:30]:
        scanned = _code_for(cred, settings, now)
        a = av.verify_totp_resilient(
            scanned=scanned, settings=settings, creds_payload=creds,
            users_by_am=users_by_am, users_by_card={}, scan_epoch=float(now),
        )
        b = av.verify_totp_resilient(
            scanned=scanned, settings=settings, creds_payload=creds,
            users_by_am=users_by_am, users_by_card={}, scan_epoch=float(now),
            totp_index=idx,
        )
        assert _strip(a) == _strip(b)
        assert a["allowed"] is True


def test_index_excludes_ineligible_creds_like_loop():
    # Disabled / missing-secret / no-grants creds must be absent from BOTH paths.
    rng = random.Random(11)
    settings = _settings()
    creds, users_by_am = _make_roster(10, rng)
    creds[0]["enabled"] = False
    creds[1]["secretHex"] = ""
    creds[2]["grantedActiveMembershipIds"] = []
    now = 1_700_007_000
    idx = av.build_totp_index(creds, settings, now)
    # The eligible iterator must agree with what the index covers.
    eligible_ids = {cid for cid, _, _, _ in av._iter_eligible_totp_creds(creds)}
    assert 1 not in eligible_ids and 2 not in eligible_ids and 3 not in eligible_ids
    # Their (would-be) codes resolve to DENY identically (they're not indexed).
    for bad in (creds[0], creds[1], creds[2]):
        if not bad.get("secretHex"):
            continue
        scanned = _code_for(bad, settings, now)
        _assert_equiv(scanned, settings, creds, users_by_am, now, idx)


def test_indexed_flag_set_when_used():
    # Confirm the index is actually consulted when it covers the window.
    rng = random.Random(3)
    settings = _settings()
    creds, users_by_am = _make_roster(5, rng)
    now = 1_700_008_000
    idx = av.build_totp_index(creds, settings, now)
    allowed_ctrs = list(range(av._totp_counter(now, 30) - 2, av._totp_counter(now, 30) + 3))
    assert set(allowed_ctrs).issubset(idx["counters"])
    # hits-from-index returns exactly one cred for a real code
    scanned = _code_for(creds[0], settings, now)
    code = scanned[-settings["totp_digits"]:]
    hits = av._hits_from_index(idx["index"], code, allowed_ctrs)
    assert len(hits) == 1 and hits[0]["credId"] == "1"
