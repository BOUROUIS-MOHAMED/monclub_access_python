"""shared/ed25519.py against RFC 8032 section 7.1 and an independent implementation.

TEST 1-3 are the RFC 8032 section 7.1 vectors. Every expected value below was also produced
by Node's built-in crypto (OpenSSL Ed25519) on 2026-10-09, an implementation independent
of this one.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from shared import ed25519
from shared.release_keys import PROD_KEYS, TEST_KEYS, trusted_keys

RFC8032_VECTORS = [
    (  # TEST 1
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac"
        "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (  # TEST 2
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e"
        "458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (  # TEST 3
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290"
        "ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]

TEST_SEED_FILE = Path(__file__).parent / "fixtures" / "release_signing" / "test-l2-2026-10.seed"


@pytest.mark.parametrize("seed_hex,public_hex,msg_hex,sig_hex", RFC8032_VECTORS)
def test_rfc8032_public_key_sign_and_verify(seed_hex, public_hex, msg_hex, sig_hex):
    seed = bytes.fromhex(seed_hex)
    msg = bytes.fromhex(msg_hex)
    assert ed25519.public_key_from_seed(seed).hex() == public_hex
    assert ed25519.sign(seed, msg).hex() == sig_hex
    assert ed25519.verify(bytes.fromhex(public_hex), msg, bytes.fromhex(sig_hex)) is True


@pytest.mark.parametrize("seed_hex,public_hex,msg_hex,sig_hex", RFC8032_VECTORS)
def test_rfc8032_a_flipped_bit_anywhere_fails(seed_hex, public_hex, msg_hex, sig_hex):
    public = bytes.fromhex(public_hex)
    msg = bytes.fromhex(msg_hex)
    sig = bytearray(bytes.fromhex(sig_hex))
    for index in (0, 31, 32, 63):
        bad = bytearray(sig)
        bad[index] ^= 0x01
        assert ed25519.verify(public, msg, bytes(bad)) is False
    assert ed25519.verify(public, msg + b"x", bytes(sig)) is False
    other_public = bytes.fromhex(RFC8032_VECTORS[0][1] if public_hex != RFC8032_VECTORS[0][1] else RFC8032_VECTORS[1][1])
    assert ed25519.verify(other_public, msg, bytes(sig)) is False


def test_the_shared_test_key_matches_its_seed_file_and_node():
    seed_hex = TEST_SEED_FILE.read_text(encoding="ascii").strip()  # git may check it out CRLF
    assert seed_hex == hashlib.sha256(b"monclub-updater-v2-test-key-2026-10").hexdigest()
    seed = bytes.fromhex(seed_hex)
    public = ed25519.public_key_from_seed(seed)
    assert public.hex() == TEST_KEYS["test-l2-2026-10"]
    # Node crypto, same seed, message b'{"a":1}'.
    assert ed25519.sign(seed, b'{"a":1}').hex() == (
        "aae9290b58577cf804df00707b7d789559cd3426c481449be7ac85ba029f5be7"
        "5e41b6a88262624bddd5fc1eb81b04512b5b55db3a719e96f00719a21a1bee01"
    )


def test_verify_never_raises_on_malformed_input():
    public = bytes.fromhex(RFC8032_VECTORS[0][1])
    sig = bytes.fromhex(RFC8032_VECTORS[0][3])
    for args in [
        (public[:31], b"", sig),
        (public, b"", sig[:63]),
        (public, b"", sig + b"\x00"),
        (None, b"", sig),
        (public, None, sig),
        (public, b"", None),
        ("00" * 32, b"", sig),
        (b"\xff" * 32, b"", sig),  # y >= p: non-canonical point encoding
    ]:
        assert ed25519.verify(*args) is False


def test_verify_rejects_s_not_below_the_group_order():
    seed_hex, public_hex, _msg, sig_hex = RFC8032_VECTORS[0]
    sig = bytes.fromhex(sig_hex)
    order = 2**252 + 27742317777372353535851937790883648493
    s = int.from_bytes(sig[32:], "little") + order  # same point equation, malleated S
    assert s < 2**256
    assert ed25519.verify(bytes.fromhex(public_hex), b"", sig[:32] + s.to_bytes(32, "little")) is False


def test_sign_refuses_a_seed_that_is_not_32_bytes():
    with pytest.raises(ValueError):
        ed25519.sign(b"\x00" * 31, b"")


def test_production_key_list_ships_empty_until_the_owner_keygen():
    assert PROD_KEYS == {}
    assert all(key_id.startswith("test-") for key_id in TEST_KEYS)


def test_test_keys_are_trusted_from_source_but_never_in_a_frozen_build(monkeypatch):
    monkeypatch.delenv("MONCLUB_UPDATER_TEST_KEYS", raising=False)
    assert "test-l2-2026-10" in trusted_keys(frozen=False)
    assert trusted_keys(frozen=True) == {}
    monkeypatch.setenv("MONCLUB_UPDATER_TEST_KEYS", "1")
    assert trusted_keys(frozen=True) == {}
    monkeypatch.setenv("MONCLUB_UPDATER_TEST_KEYS", "0")
    assert trusted_keys(frozen=False) == {}


def test_a_test_key_injected_into_prod_keys_is_trusted_in_a_frozen_e2e_build(monkeypatch):
    monkeypatch.setitem(PROD_KEYS, "test-l2-2026-10", TEST_KEYS["test-l2-2026-10"])
    assert trusted_keys(frozen=True) == {"test-l2-2026-10": TEST_KEYS["test-l2-2026-10"]}
