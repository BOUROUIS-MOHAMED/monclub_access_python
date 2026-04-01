"""Tests for access_verification module."""
import struct
import time
import pytest
from app.core.access_verification import (
    _totp_counter,
    _totp_hotp,
    _totp_is_hex,
    _totp_hex_to_bytes,
    verify_totp,
    verify_card,
)


# ─────────────────────────────────────────────
# Helpers shared by multiple test classes
# ─────────────────────────────────────────────

# RFC-4226 test key: b"12345678901234567890"
_RFC_SECRET_HEX = "3132333435363738393031323334353637383930"
_RFC_SECRET = bytes.fromhex(_RFC_SECRET_HEX)


def _make_cred(
    *,
    cred_id: int = 1,
    account_id: int = 10,
    secret_hex: str = _RFC_SECRET_HEX,
    grants: list | None = None,
    enabled: bool = True,
) -> dict:
    """Build a minimal credential dict that verify_totp accepts."""
    return {
        "id": cred_id,
        "accountId": account_id,
        "secretHex": secret_hex,
        "grantedActiveMembershipIds": grants if grants is not None else [42],
        "enabled": enabled,
    }


def _make_settings(
    *,
    rfid_enabled: bool = True,
    totp_enabled: bool = True,
    totp_period_seconds: int = 30,
    totp_drift_steps: int = 1,
    totp_digits: int = 7,
    totp_prefix: str = "9",
    rfid_min_digits: int = 1,
    rfid_max_digits: int = 16,
    totp_max_past_age_seconds: int = 32,
    totp_max_future_skew_seconds: int = 3,
) -> dict:
    return {
        "rfid_enabled": rfid_enabled,
        "totp_enabled": totp_enabled,
        "totp_period_seconds": totp_period_seconds,
        "totp_drift_steps": totp_drift_steps,
        "totp_digits": totp_digits,
        "totp_prefix": totp_prefix,
        "rfid_min_digits": rfid_min_digits,
        "rfid_max_digits": rfid_max_digits,
        "totp_max_past_age_seconds": totp_max_past_age_seconds,
        "totp_max_future_skew_seconds": totp_max_future_skew_seconds,
    }


def _current_totp_code(secret: bytes, digits: int = 7, period: int = 30) -> str:
    """Generate the current TOTP code for a secret."""
    ctr = _totp_counter(int(time.time()), period)
    return _totp_hotp(secret, ctr, digits)


# ─────────────────────────────────────────────
# _totp_counter
# ─────────────────────────────────────────────

class TestTotpCounter:
    # Use a timestamp that starts at the beginning of a window to avoid
    # accidental boundary splits: 1_700_000_010 % 30 == 0, so t+0 through
    # t+29 are all in the same window, and t+30 is the next window start.
    _T = 1_700_000_010  # 1_700_000_010 % 30 == 0  (window boundary start)

    def test_30s_period_advances_by_one(self):
        t = self._T
        c1 = _totp_counter(t, 30)
        c2 = _totp_counter(t + 30, 30)
        assert c2 == c1 + 1

    def test_same_window_returns_same_counter(self):
        t = self._T
        assert _totp_counter(t, 30) == _totp_counter(t + 15, 30)

    def test_boundary_just_before_next_window(self):
        t = self._T
        assert _totp_counter(t, 30) == _totp_counter(t + 29, 30)

    def test_exactly_on_boundary_advances(self):
        t = self._T
        assert _totp_counter(t + 30, 30) == _totp_counter(t, 30) + 1

    def test_60s_period(self):
        # 1_700_000_040 % 60 == 0
        t = 1_700_000_040
        assert _totp_counter(t, 60) == _totp_counter(t + 59, 60)
        assert _totp_counter(t + 60, 60) == _totp_counter(t, 60) + 1

    def test_zero_timestamp(self):
        assert _totp_counter(0, 30) == 0

    def test_result_is_integer(self):
        assert isinstance(_totp_counter(1_700_000_000, 30), int)


# ─────────────────────────────────────────────
# _totp_is_hex
# ─────────────────────────────────────────────

class TestTotpIsHex:
    def test_valid_lowercase(self):
        assert _totp_is_hex("abcdef0123456789") is True

    def test_valid_uppercase(self):
        assert _totp_is_hex("ABCDEF0123456789") is True

    def test_valid_with_0x_prefix(self):
        assert _totp_is_hex("0x48656c6c6f") is True

    def test_valid_with_0X_prefix(self):
        assert _totp_is_hex("0X48656c6c6f") is True

    def test_invalid_chars(self):
        assert _totp_is_hex("xyz") is False

    def test_empty_string(self):
        assert _totp_is_hex("") is False

    def test_whitespace_only(self):
        assert _totp_is_hex("   ") is False

    def test_odd_length_no_prefix(self):
        # Odd number of hex nibbles is invalid (bytes.fromhex requires even)
        assert _totp_is_hex("abc") is False

    def test_two_bytes(self):
        assert _totp_is_hex("ffff") is True

    def test_rfc_secret(self):
        assert _totp_is_hex(_RFC_SECRET_HEX) is True


# ─────────────────────────────────────────────
# _totp_hex_to_bytes
# ─────────────────────────────────────────────

class TestTotpHexToBytes:
    def test_hello(self):
        assert _totp_hex_to_bytes("48656c6c6f") == b"Hello"

    def test_0x_prefix_stripped(self):
        assert _totp_hex_to_bytes("0x48656c6c6f") == b"Hello"

    def test_0X_prefix_stripped(self):
        assert _totp_hex_to_bytes("0X48656c6c6f") == b"Hello"

    def test_whitespace_stripped(self):
        assert _totp_hex_to_bytes("  48656c6c6f  ") == b"Hello"

    def test_rfc_secret_roundtrip(self):
        assert _totp_hex_to_bytes(_RFC_SECRET_HEX) == _RFC_SECRET

    def test_ff_byte(self):
        assert _totp_hex_to_bytes("ff") == b"\xff"

    def test_empty_string(self):
        # bytes.fromhex("") == b""
        assert _totp_hex_to_bytes("") == b""


# ─────────────────────────────────────────────
# _totp_hotp
# ─────────────────────────────────────────────

class TestTotpHotp:
    def test_deterministic(self):
        code1 = _totp_hotp(_RFC_SECRET, 1, 7)
        code2 = _totp_hotp(_RFC_SECRET, 1, 7)
        assert code1 == code2

    def test_result_length_matches_digits(self):
        for digits in (4, 6, 7, 8, 10):
            code = _totp_hotp(_RFC_SECRET, 0, digits)
            assert len(code) == digits, f"Expected {digits} digits, got {len(code)}"

    def test_result_is_all_digits(self):
        code = _totp_hotp(_RFC_SECRET, 1, 7)
        assert code.isdigit()

    def test_different_counters_produce_different_codes(self):
        code1 = _totp_hotp(_RFC_SECRET, 1, 7)
        code2 = _totp_hotp(_RFC_SECRET, 2, 7)
        assert code1 != code2

    def test_different_secrets_produce_different_codes(self):
        other_secret = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        code1 = _totp_hotp(_RFC_SECRET, 5, 7)
        code2 = _totp_hotp(other_secret, 5, 7)
        assert code1 != code2

    def test_zero_padded(self):
        # Result must be left-zero-padded to 'digits' length
        code = _totp_hotp(_RFC_SECRET, 0, 7)
        assert len(code) == 7

    def test_counter_zero(self):
        # Should not raise
        code = _totp_hotp(_RFC_SECRET, 0, 6)
        assert len(code) == 6 and code.isdigit()


# ─────────────────────────────────────────────
# verify_card
# ─────────────────────────────────────────────

class TestVerifyCard:
    def _settings(self, **kwargs):
        return _make_settings(**kwargs)

    # --- happy path ---

    def test_valid_card_allowed(self):
        user = {"id": 1, "name": "Alice", "activeMembershipId": 42}
        result = verify_card(
            scanned="123456",
            settings=self._settings(),
            users_by_card={"123456": [user]},
        )
        assert result["allowed"] is True
        assert result["reason"] == "ALLOW_CARD"
        assert result["scanMode"] == "RFID_CARD"
        assert result["user"] is user
        assert result["activeMembershipId"] == 42

    def test_active_membership_id_coerced_to_int(self):
        user = {"activeMembershipId": "99"}
        result = verify_card(
            scanned="111",
            settings=self._settings(),
            users_by_card={"111": [user]},
        )
        assert result["allowed"] is True
        assert result["activeMembershipId"] == 99

    def test_none_active_membership_id_stays_none(self):
        user = {"activeMembershipId": None}
        result = verify_card(
            scanned="111",
            settings=self._settings(),
            users_by_card={"111": [user]},
        )
        assert result["allowed"] is True
        assert result["activeMembershipId"] is None

    def test_result_contains_took_ms(self):
        result = verify_card(
            scanned="123",
            settings=self._settings(),
            users_by_card={},
        )
        assert "tookMs" in result
        assert isinstance(result["tookMs"], float)

    # --- RFID disabled ---

    def test_rfid_disabled_denies(self):
        user = {"activeMembershipId": 1}
        result = verify_card(
            scanned="123456",
            settings=self._settings(rfid_enabled=False),
            users_by_card={"123456": [user]},
        )
        assert result["allowed"] is False
        assert result["reason"] == "DENY_RFID_DISABLED"

    def test_rfid_disabled_false_string_denies(self):
        # settings value as string "False" — bool("False") is True, test that
        # the function uses bool() on the value correctly
        result = verify_card(
            scanned="123456",
            settings={"rfid_enabled": False},
            users_by_card={"123456": [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is False

    # --- unknown card ---

    def test_unknown_card_denied(self):
        result = verify_card(
            scanned="999999",
            settings=self._settings(),
            users_by_card={"111111": [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is False
        assert result["reason"] == "DENY_NO_CARD_MATCH"

    def test_empty_card_map_denied(self):
        result = verify_card(
            scanned="123456",
            settings=self._settings(),
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "DENY_NO_CARD_MATCH"

    # --- format validation ---

    def test_empty_scanned_denied(self):
        result = verify_card(
            scanned="",
            settings=self._settings(),
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "INVALID_CARD_FORMAT"

    def test_non_digit_scanned_denied(self):
        result = verify_card(
            scanned="ABC123",
            settings=self._settings(),
            users_by_card={"ABC123": [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is False
        assert result["reason"] == "INVALID_CARD_FORMAT"

    def test_whitespace_only_denied(self):
        result = verify_card(
            scanned="   ",
            settings=self._settings(),
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "INVALID_CARD_FORMAT"

    # --- digit length constraints ---

    def test_card_too_short_denied(self):
        result = verify_card(
            scanned="1",
            settings=self._settings(rfid_min_digits=4, rfid_max_digits=10),
            users_by_card={"1": [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is False
        assert result["reason"] == "INVALID_CARD_LENGTH"
        assert result["minDigits"] == 4
        assert result["maxDigits"] == 10

    def test_card_too_long_denied(self):
        result = verify_card(
            scanned="12345678901",
            settings=self._settings(rfid_min_digits=1, rfid_max_digits=5),
            users_by_card={"12345678901": [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is False
        assert result["reason"] == "INVALID_CARD_LENGTH"

    def test_card_at_min_length_allowed(self):
        result = verify_card(
            scanned="1234",
            settings=self._settings(rfid_min_digits=4, rfid_max_digits=10),
            users_by_card={"1234": [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is True

    def test_card_at_max_length_allowed(self):
        result = verify_card(
            scanned="1234567890",
            settings=self._settings(rfid_min_digits=4, rfid_max_digits=10),
            users_by_card={"1234567890": [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is True

    def test_max_len_clamps_at_16(self):
        # rfid_max_digits > 16 should be clamped to 16
        code = "1" * 16
        result = verify_card(
            scanned=code,
            settings=self._settings(rfid_min_digits=1, rfid_max_digits=20),
            users_by_card={code: [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is True

    def test_min_len_clamps_at_1(self):
        result = verify_card(
            scanned="5",
            settings=self._settings(rfid_min_digits=0, rfid_max_digits=10),
            users_by_card={"5": [{"activeMembershipId": 1}]},
        )
        assert result["allowed"] is True

    # --- collision ---

    def test_card_collision_denied(self):
        users = [{"id": 1, "activeMembershipId": 1}, {"id": 2, "activeMembershipId": 2}]
        result = verify_card(
            scanned="123456",
            settings=self._settings(),
            users_by_card={"123456": users},
        )
        assert result["allowed"] is False
        assert result["reason"] == "DENY_CARD_COLLISION"
        assert result["count"] == 2


# ─────────────────────────────────────────────
# verify_totp
# ─────────────────────────────────────────────

class TestVerifyTotp:
    """
    Tests for verify_totp.

    verify_totp generates TOTP codes using the current wall clock, so tests
    that exercise a valid-match path must generate the code at call time via
    _totp_hotp / _totp_counter.  Tests that exercise deny paths can use
    fixed/invalid data without time dependency.
    """

    def _settings(self, **kwargs):
        return _make_settings(**kwargs)

    # ── TOTP disabled ──

    def test_totp_disabled_valid_card_falls_back_to_rfid(self):
        user = {"activeMembershipId": 7}
        result = verify_totp(
            scanned="12345",
            settings=self._settings(totp_enabled=False),
            creds_payload=[],
            users_by_am={7: user},
            users_by_card={"12345": [user]},
        )
        assert result["allowed"] is True
        assert result["scanMode"] == "RFID_ONLY"

    def test_totp_disabled_unknown_card_denied(self):
        result = verify_totp(
            scanned="99999",
            settings=self._settings(totp_enabled=False),
            creds_payload=[],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False

    # ── wrong prefix (length mismatch → RFID direct) ──

    def test_wrong_prefix_falls_back_to_rfid_allowed(self):
        """A scan that doesn't start with the TOTP prefix is treated as RFID."""
        user = {"activeMembershipId": 5}
        # Default prefix="9", digits=7 => expected_len=8.
        # Send a 5-digit card that starts with "1" — doesn't match QR format.
        result = verify_totp(
            scanned="12345",
            settings=self._settings(),
            creds_payload=[],
            users_by_am={5: user},
            users_by_card={"12345": [user]},
        )
        assert result["allowed"] is True
        assert result["scanMode"] == "RFID_DIRECT"

    def test_wrong_prefix_falls_back_to_rfid_denied(self):
        result = verify_totp(
            scanned="12345",
            settings=self._settings(),
            creds_payload=[],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False

    # ── invalid scan format ──

    def test_empty_scan_invalid_format(self):
        result = verify_totp(
            scanned="",
            settings=self._settings(),
            creds_payload=[],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "INVALID_FORMAT"

    def test_non_digit_scan_invalid_format(self):
        result = verify_totp(
            scanned="ABCDEFGH",
            settings=self._settings(),
            creds_payload=[],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "INVALID_FORMAT"

    # ── no credential match → DENY_NO_MATCH ──

    def test_no_creds_payload_deny_no_match(self):
        # Correct prefix + correct length but no credentials in list
        # prefix="9", digits=7 => expected_len=8 => send "9" + 7 digits
        result = verify_totp(
            scanned="91234567",
            settings=self._settings(),
            creds_payload=[],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "DENY_NO_MATCH"

    def test_disabled_cred_not_matched(self):
        cred = _make_cred(enabled=False, secret_hex=_RFC_SECRET_HEX)
        code = "9" + _totp_hotp(_RFC_SECRET, _totp_counter(int(time.time()), 30), 7)
        result = verify_totp(
            scanned=code,
            settings=self._settings(),
            creds_payload=[cred],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "DENY_NO_MATCH"

    def test_cred_without_grants_skipped(self):
        cred = _make_cred(grants=[])
        code = "9" + _totp_hotp(_RFC_SECRET, _totp_counter(int(time.time()), 30), 7)
        result = verify_totp(
            scanned=code,
            settings=self._settings(),
            creds_payload=[cred],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "DENY_NO_MATCH"

    def test_cred_with_invalid_hex_secret_skipped(self):
        cred = _make_cred(secret_hex="NOTVALID")
        code = "9" + "1234567"
        result = verify_totp(
            scanned=code,
            settings=self._settings(),
            creds_payload=[cred],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False

    # ── valid TOTP match → ALLOW ──

    def test_valid_totp_allowed(self):
        """Generate the current TOTP code and verify it is accepted."""
        now = int(time.time())
        ctr = _totp_counter(now, 30)
        digits = 7
        code = _totp_hotp(_RFC_SECRET, ctr, digits)
        scan = "9" + code  # prefix "9" + 7-digit code

        cred = _make_cred(grants=[42])
        user = {"activeMembershipId": 42, "name": "Bob"}

        result = verify_totp(
            scanned=scan,
            settings=self._settings(),
            creds_payload=[cred],
            users_by_am={42: user},
            users_by_card={},
        )
        assert result["allowed"] is True
        assert result["reason"] == "ALLOW"
        assert result["scanMode"] == "QR_TOTP"
        assert result["user"] is user
        assert result["activeMembershipId"] == 42

    def test_valid_totp_result_contains_metadata(self):
        now = int(time.time())
        ctr = _totp_counter(now, 30)
        code = _totp_hotp(_RFC_SECRET, ctr, 7)
        scan = "9" + code

        result = verify_totp(
            scanned=scan,
            settings=self._settings(),
            creds_payload=[_make_cred()],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is True
        assert "tookMs" in result
        assert "credId" in result
        assert "matchedCounter" in result
        assert "ageSeconds" in result

    # ── TOTP collision (2 distinct credentials match same code) ──

    def test_totp_collision_denied(self):
        """Two different creds that produce the same current TOTP code → collision."""
        now = int(time.time())
        ctr = _totp_counter(now, 30)
        digits = 7

        # Both credentials use the same secret so they produce the same TOTP code.
        # They have different IDs, which triggers the collision path.
        cred1 = _make_cred(cred_id=1, account_id=10, secret_hex=_RFC_SECRET_HEX, grants=[42])
        cred2 = _make_cred(cred_id=2, account_id=20, secret_hex=_RFC_SECRET_HEX, grants=[43])

        code = _totp_hotp(_RFC_SECRET, ctr, digits)
        scan = "9" + code

        result = verify_totp(
            scanned=scan,
            settings=self._settings(),
            creds_payload=[cred1, cred2],
            users_by_am={},
            users_by_card={},
        )
        assert result["allowed"] is False
        assert result["reason"] == "DENY_COLLISION"
        assert result["scanMode"] == "QR_TOTP"

    # ── grant resolution ──

    def test_totp_no_matching_user_in_users_by_am(self):
        """Credential grant ID not in users_by_am → allowed=True but user=None."""
        now = int(time.time())
        ctr = _totp_counter(now, 30)
        code = _totp_hotp(_RFC_SECRET, ctr, 7)
        scan = "9" + code

        cred = _make_cred(grants=[999])

        result = verify_totp(
            scanned=scan,
            settings=self._settings(),
            creds_payload=[cred],
            users_by_am={},  # grant 999 not present
            users_by_card={},
        )
        assert result["allowed"] is True
        assert result["user"] is None
        assert result["activeMembershipId"] == 999

    # ── result always has tookMs ──

    def test_result_always_has_took_ms(self):
        result = verify_totp(
            scanned="",
            settings=self._settings(),
            creds_payload=[],
            users_by_am={},
            users_by_card={},
        )
        assert "tookMs" in result
        assert isinstance(result["tookMs"], float)
