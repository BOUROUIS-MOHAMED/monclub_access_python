"""
Simulation: prove how clock skew / pipeline latency (Delta) between the moment a
phone generates a TOTP QR code and the moment the gym PC validates it maps to the
exact deny reasons seen in the gym logs.

Uses the REAL verification algorithm from app.core.access_verification (imported,
not reimplemented) with the live gym settings (period=30, drift=1, digits=6,
prefix='9', max_past_age=32, max_future_skew=3).

We monkeypatch time.time() so verify_totp() believes "now" is base_time + Delta.
"""
from __future__ import annotations
import time as _time

# Real algorithm from the shipping code:
from app.core.access_verification import _totp_hotp, _totp_hex_to_bytes, verify_totp

# ---- live gym settings (per the logs + user confirmation) ----
SETTINGS = {
    "totp_enabled": True,
    "totp_validation": True,
    "totp_period_seconds": 30,
    "totp_drift_steps": 1,
    "totp_max_past_age_seconds": 32,
    "totp_max_future_skew_seconds": 3,
    "totp_prefix": "9",
    "totp_digits": 6,          # code = prefix '9' + 6 digits = 7 chars (matches "9986566")
    "rfid_enabled": True,
}

# A real credential secret (gym_access_secrets_cache.json id=5). The specific
# secret value is irrelevant to the mechanism; only the algorithm + timing matter.
SECRET_HEX = "0305dd6b17c8be4f4df4952a7b1ae3e4b9522373"
CRED = [{
    "id": "5", "accountId": "85", "enabled": True,
    "secretHex": SECRET_HEX, "grantedActiveMembershipIds": [16],
}]
USERS_BY_AM = {16: {"fullName": "SIM MEMBER", "activeMembershipId": 16}}

PERIOD = SETTINGS["totp_period_seconds"]
DIGITS = SETTINGS["totp_digits"]
PREFIX = SETTINGS["totp_prefix"]

# Pick a fixed base time = the instant the member's phone shows the QR.
# Put it mid-window so r (position within the 30s window) ~ 12s, like a typical scan.
base_time = 1_760_000_000 + 12          # ...some epoch, +12s into its window
phone_counter = base_time // PERIOD
phone_code_6 = _totp_hotp(_totp_hex_to_bytes(SECRET_HEX), phone_counter, DIGITS)
qr_string = PREFIX + phone_code_6        # what the device reads off the QR

print(f"Phone shows QR at epoch {base_time} (counter={phone_counter})")
print(f"QR code string scanned by turnstile = {qr_string!r}  (len={len(qr_string)})")
print(f"max_past_age={SETTINGS['totp_max_past_age_seconds']}s  "
      f"future_skew={SETTINGS['totp_max_future_skew_seconds']}s  "
      f"drift=+/-{SETTINGS['totp_drift_steps']} step  period={PERIOD}s")
print("-" * 78)
print(f"{'Delta(s)':>8} | {'PC clock ahead of scan by':>26} | {'reason':<16} | age")
print("-" * 78)

_real_time = _time.time
results = []
for delta in [0, 10, 20, 29, 30, 32, 33, 40, 44, 45, 46, 60, 63, 75, 90]:
    # Make verify_totp believe the current wall-clock is base_time + delta.
    _time.time = (lambda d=delta: float(base_time + d))
    try:
        r = verify_totp(
            scanned=qr_string, settings=SETTINGS, creds_payload=CRED,
            users_by_am=USERS_BY_AM, users_by_card={},
        )
    finally:
        _time.time = _real_time
    age = r.get("ageSeconds", "")
    reason = r.get("reason", "?")
    verdict = "ALLOW OK" if r.get("allowed") else "DENY  "
    results.append((delta, reason, r.get("allowed")))
    print(f"{delta:>8} | {('+' + str(delta) + 's'):>26} | {reason:<16} | age={age}")

print("-" * 78)
# Summarize the thresholds
allow_max = max((d for d, _, ok in results if ok), default=None)
first_nomatch = min((d for d, rsn, _ in results if rsn == "DENY_NO_MATCH"), default=None)
print(f"Largest Delta still ALLOWED : {allow_max}s")
print(f"First Delta -> DENY_NO_MATCH : {first_nomatch}s   "
      f"(this is the reason in the gym logs)")

# ----------------------------------------------------------------------------
# THE FIX (#1): validate at the scan's event_time (now_unix=base_time) instead
# of wall-clock-at-processing. The processing delay no longer matters.
# ----------------------------------------------------------------------------
print()
print("=== WITH FIX #1 (now_unix = scan time) — processed LATE by Delta ===")
print(f"{'Delta(s)':>8} | {'reason':<16} | age | verdict")
print("-" * 78)
for delta in [0, 30, 60, 120, 300]:
    # PC processes 'delta' seconds late, but we pass the SCAN time as now_unix.
    _time.time = (lambda d=delta: float(base_time + d))
    try:
        r = verify_totp(
            scanned=qr_string, settings=SETTINGS, creds_payload=CRED,
            users_by_am=USERS_BY_AM, users_by_card={},
            now_unix=float(base_time),   # <-- validate at scan time
        )
    finally:
        _time.time = _real_time
    verdict = "ALLOW OK" if r.get("allowed") else f"DENY NO ({r.get('reason')})"
    print(f"{delta:>8} | {r.get('reason',''):<16} | age={r.get('ageSeconds','')} | {verdict}")
print("-" * 78)
print("With the fix, a code stays valid regardless of how late the PC processes it.")
