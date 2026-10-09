"""Updater v2 (lane L2): tools/release_sign.py -- the signed release contract (design.md 5)
and the build refusals (design 5.1 / 8 "Build / publish")."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from shared import ed25519 as shared_ed25519  # noqa: E402
import release_sign as rs  # noqa: E402

TEST_SEED_FILE = REPO / "tests" / "fixtures" / "release_signing" / "test-l2-2026-10.seed"


# ------------------------------------------------------------------ Ed25519 (RFC 8032 7.1)

RFC8032_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


@pytest.mark.parametrize("seed, pub, msg, sig", RFC8032_VECTORS)
def test_signing_ed25519_matches_rfc8032_vectors(seed, pub, msg, sig):
    s, m = bytes.fromhex(seed), bytes.fromhex(msg)
    assert shared_ed25519.public_key_from_seed(s).hex() == pub
    assert shared_ed25519.sign(s, m).hex() == sig
    assert shared_ed25519.verify(bytes.fromhex(pub), m, bytes.fromhex(sig)) is True
    assert shared_ed25519.verify(bytes.fromhex(pub), m + b"x", bytes.fromhex(sig)) is False


def test_signing_verify_never_raises_on_garbage():
    assert shared_ed25519.verify(b"short", b"m", b"x" * 64) is False
    assert shared_ed25519.verify(b"\xff" * 32, b"m", b"\xff" * 64) is False
    assert shared_ed25519.verify(b"\x00" * 32, b"m", b"short") is False


def test_signing_uses_the_one_shared_ed25519_implementation():
    # Design 5.1: one Ed25519 implementation (shared/ed25519.py); the L2 fallback is gone.
    assert rs.ED25519_SOURCE == "shared.ed25519"
    assert rs._ed is shared_ed25519
    assert not (REPO / "tools" / "_ed25519_fallback.py").exists()


def test_test_key_fixture_is_the_agreed_deterministic_seed():
    # Shared with lane L3 byte for byte (tests/fixtures/release_signing/test-l2-2026-10.seed).
    expected = hashlib.sha256(b"monclub-updater-v2-test-key-2026-10").hexdigest()
    assert TEST_SEED_FILE.read_text(encoding="ascii").strip() == expected
    assert rs.TEST_KEY_ID == "test-l2-2026-10"


# ------------------------------------------------------------------ manifest (design 5.2)


def manifest(**over):
    base = dict(target="access", channel="stable", version="1.5.0",
                installer_name="monclub_access_1.5.0.exe", installer_sha256="a" * 64,
                installer_size=123456789, issued_at="2026-10-10T08:00:00Z")
    base.update(over)
    return rs.build_manifest(**base)


def test_canonical_manifest_is_sorted_compact_ascii_exactly_as_design_5_2():
    s = rs.canonical_manifest(manifest())
    assert s == (
        '{"allowDowngrade":false,"channel":"stable","installerName":"monclub_access_1.5.0.exe",'
        '"installerSha256":"' + "a" * 64 + '","installerSize":123456789,"issuedAt":"2026-10-10T08:00:00Z",'
        '"platform":"WINDOWS","rollbackFrom":null,"schema":1,"target":"access","version":"1.5.0"}'
    )


def test_rollback_manifest_allows_downgrade_and_names_the_bad_version():
    m = manifest(version="1.5.0", rollback_from="1.5.1")
    assert m["allowDowngrade"] is True and m["rollbackFrom"] == "1.5.1"
    with pytest.raises(rs.ReleaseSignError):
        manifest(version="1.5.0", rollback_from="1.5.0")


@pytest.mark.parametrize("over", [
    {"version": ""}, {"version": "1.5"}, {"version": "1.5.0+build"}, {"version": "01.5.0"},
    {"target": "kiosk"}, {"channel": "nightly"}, {"installer_sha256": "A" * 64},
    {"installer_sha256": "a" * 63}, {"installer_size": 0}, {"installer_size": True},
    {"installer_name": "monclub_accès_1.5.0.exe"}, {"installer_name": "x.msi"},
    {"issued_at": "2026-10-10 08:00:00"}, {"platform": "windows"},
])
def test_build_manifest_refuses_bad_fields(over):
    with pytest.raises(rs.ReleaseSignError):
        manifest(**over)


def test_prerelease_versions_are_accepted():
    assert manifest(version="1.5.0-beta.1")["version"] == "1.5.0-beta.1"


def test_canonical_manifest_refuses_non_ascii_instead_of_escaping_it():
    m = manifest()
    m["channel"] = "stablé"
    with pytest.raises(rs.ReleaseSignError):
        rs.canonical_manifest(m)


# ------------------------------------------------------------------ release file (design 5.3)


@pytest.fixture()
def seed() -> bytes:
    return rs.read_seed(TEST_SEED_FILE)


@pytest.fixture()
def installer(tmp_path: Path) -> Path:
    p = tmp_path / "monclub_access_1.5.0.exe"
    p.write_bytes(b"MZ" + b"\x00" * 1000 + b"installer body")
    return p


def test_test_build_release_file_signs_and_verifies(installer, seed):
    trusted = {rs.TEST_KEY_ID: rs.public_key_hex(seed)}
    data = rs.make_release_file(installer=installer, target="access", channel="stable", version="1.5.0",
                                key_id=rs.TEST_KEY_ID, seed=seed, trusted_keys=trusted,
                                publishable=False, tests_skipped=True, release_notes="Notes é",
                                codename="Mango")
    assert set(data) >= {"signedManifest", "signature", "keyId", "installerUrl", "releaseNotes", "codename"}
    assert data["publishable"] is False and data["testsSkipped"] is True
    m = rs.verify_release_file(data, trusted, installer)
    assert m["installerSha256"] == hashlib.sha256(installer.read_bytes()).hexdigest()
    assert m["installerSize"] == installer.stat().st_size
    assert data["githubTag"] == "access-win-stable-v1.5.0"
    assert data["installerUrl"] == (
        "https://github.com/BOUROUIS-MOHAMED/monclub_access_python/releases/download/"
        "access-win-stable-v1.5.0/monclub_access_1.5.0.exe")
    # Notes are NOT signed (design 5.2) and may carry any text.
    assert "Notes" not in data["signedManifest"]


def test_tampering_with_manifest_signature_or_installer_is_detected(installer, seed):
    trusted = {rs.TEST_KEY_ID: rs.public_key_hex(seed)}
    data = rs.make_release_file(installer=installer, target="access", channel="stable", version="1.5.0",
                                key_id=rs.TEST_KEY_ID, seed=seed, trusted_keys=trusted, publishable=False)
    forged = dict(data, signedManifest=data["signedManifest"].replace('"1.5.0"', '"1.5.9"'))
    with pytest.raises(rs.ReleaseSignError, match="SIGNATURE INVALID"):
        rs.verify_release_file(forged, trusted)
    bad_sig = dict(data, signature=("0" if data["signature"][0] != "0" else "1") + data["signature"][1:])
    with pytest.raises(rs.ReleaseSignError):
        rs.verify_release_file(bad_sig, trusted)
    installer.write_bytes(installer.read_bytes() + b"!")
    with pytest.raises(rs.ReleaseSignError):
        rs.verify_release_file(data, trusted, installer)
    with pytest.raises(rs.ReleaseSignError, match="not trusted"):
        rs.verify_release_file(data, {})


def test_a_key_file_that_does_not_match_the_trusted_public_key_is_refused(installer, seed):
    with pytest.raises(rs.ReleaseSignError, match="does not match"):
        rs.make_release_file(installer=installer, target="access", channel="stable", version="1.5.0",
                             key_id=rs.TEST_KEY_ID, seed=seed, trusted_keys={rs.TEST_KEY_ID: "b" * 64},
                             publishable=False)
    with pytest.raises(rs.ReleaseSignError, match="not in the trusted"):
        rs.make_release_file(installer=installer, target="access", channel="stable", version="1.5.0",
                             key_id=rs.TEST_KEY_ID, seed=seed, trusted_keys={}, publishable=False)


def test_publishable_release_refuses_test_key_skipped_tests_missing_commit_and_http(installer, seed, tmp_path):
    prod_seed = bytes(range(32))
    prod = {"monclub-2026-10": rs.public_key_hex(prod_seed)}
    good_payload = {"publishable": True, "e2eTestKeys": False}
    common = dict(installer=installer, target="access", channel="stable", version="1.5.0",
                  publishable=True, payload_version=good_payload)
    with pytest.raises(rs.ReleaseSignError, match="test key"):
        rs.make_release_file(**common, key_id=rs.TEST_KEY_ID, seed=seed,
                             trusted_keys={rs.TEST_KEY_ID: rs.public_key_hex(seed)},
                             build_commit="a" * 40)
    with pytest.raises(rs.ReleaseSignError, match="skip"):
        rs.make_release_file(**common, key_id="monclub-2026-10", seed=prod_seed, trusted_keys=prod,
                             build_commit="a" * 40, tests_skipped=True)
    with pytest.raises(rs.ReleaseSignError, match="commit"):
        rs.make_release_file(**common, key_id="monclub-2026-10", seed=prod_seed, trusted_keys=prod,
                             build_commit="abc1234")
    with pytest.raises(rs.ReleaseSignError, match="https"):
        rs.make_release_file(**common, key_id="monclub-2026-10", seed=prod_seed, trusted_keys=prod,
                             build_commit="a" * 40, installer_url="http://127.0.0.1:8000/x.exe")
    ok = rs.make_release_file(**common, key_id="monclub-2026-10", seed=prod_seed, trusted_keys=prod,
                              build_commit="a" * 40)
    assert ok["publishable"] is True and ok["buildCommit"] == "a" * 40


def test_publishable_is_never_a_default_and_a_test_payload_cannot_be_signed_as_publishable(installer):
    """Review #6: a hand-run `sign` with the prod key used to write "publishable": true for any
    installer -- including one whose payload was built with -E2ETestKeys (trusts only the test
    key: shipped, those PCs could never verify another release)."""
    prod_seed = bytes(range(32))
    prod = {"monclub-2026-10": rs.public_key_hex(prod_seed)}
    common = dict(installer=installer, target="access", channel="stable", version="1.5.0",
                  key_id="monclub-2026-10", seed=prod_seed, trusted_keys=prod, build_commit="a" * 40)
    assert rs.make_release_file(**common)["publishable"] is False
    with pytest.raises(rs.ReleaseSignError, match="version.json"):
        rs.make_release_file(**common, publishable=True)
    for payload in ({"publishable": True, "e2eTestKeys": True}, {"publishable": False}, {}):
        with pytest.raises(rs.ReleaseSignError, match="test / non-publishable"):
            rs.make_release_file(**common, publishable=True, payload_version=payload)


def test_test_build_may_point_at_a_local_http_server_but_not_a_remote_one(installer, seed):
    trusted = {rs.TEST_KEY_ID: rs.public_key_hex(seed)}
    common = dict(installer=installer, target="tv", channel="stable", version="1.5.0",
                  key_id=rs.TEST_KEY_ID, seed=seed, trusted_keys=trusted, publishable=False)
    assert rs.make_release_file(**common, installer_url="http://127.0.0.1:8765/a.exe")["installerUrl"].startswith(
        "http://127.0.0.1")
    with pytest.raises(rs.ReleaseSignError):
        rs.make_release_file(**common, installer_url="http://evil.example/a.exe")


# ------------------------------------------------------------------ trust gate (build refusal)


@pytest.mark.parametrize("keys, ok", [
    (None, False),
    ({}, False),
    ({"test-l2-2026-10": "a" * 64}, False),
    ({"monclub-2026-10": "a" * 64, "test-x": "b" * 64}, False),
    ({"monclub-2026-10": "A" * 64}, False),
    ({"monclub-2026-10": "a" * 63}, False),
    ({"monclub-2026-10": "a" * 64}, True),
])
def test_check_trust_refuses_empty_test_or_malformed_key_lists(keys, ok):
    assert (rs.check_trust(keys) == []) is ok


def test_check_trust_cli_refuses_this_branch_until_the_owner_adds_a_prod_key(capsys, monkeypatch):
    monkeypatch.setattr(rs, "load_release_keys", lambda: ({}, {}))
    assert rs.main(["check-trust"]) == 1
    assert "NOT PUBLISHABLE" in capsys.readouterr().err


# ------------------------------------------------------------------ keygen


def test_keygen_writes_a_private_key_never_prints_it_and_never_overwrites(tmp_path, capsys):
    rc = rs.main(["keygen", "--key-id", "monclub-2026-10", "--dir", str(tmp_path)])
    assert rc == 0
    key_file = tmp_path / "monclub-2026-10.key"
    seed_hex = key_file.read_text(encoding="ascii").strip()
    out = capsys.readouterr().out
    assert seed_hex not in out
    assert rs.public_key_hex(bytes.fromhex(seed_hex)) in out
    assert rs.main(["keygen", "--key-id", "monclub-2026-10", "--dir", str(tmp_path)]) == 1
    assert key_file.read_text(encoding="ascii").strip() == seed_hex


def test_keygen_refuses_test_prefix_without_the_test_flag(tmp_path):
    assert rs.main(["keygen", "--key-id", "test-owner", "--dir", str(tmp_path)]) == 1
    assert not (tmp_path / "test-owner.key").exists()


# ------------------------------------------------------------------ CLI round trip


def test_cli_sign_then_verify_with_the_test_key(installer, capsys):
    out = installer.parent / "release.json"
    assert rs.main(["sign", "--installer", str(installer), "--target", "access", "--channel", "stable",
                    "--version", "1.5.0", "--key-id", rs.TEST_KEY_ID, "--allow-test-keys",
                    "--not-publishable", "--tests-skipped", "--out", str(out)]) == 0
    data = json.loads(out.read_text(encoding="ascii"))
    assert data["publishable"] is False
    assert rs.main(["verify", "--release-file", str(out), "--installer", str(installer),
                    "--allow-test-keys"]) == 0
    # publish_github_release.ps1 calls verify with --require-publishable: refused here.
    assert rs.main(["verify", "--release-file", str(out), "--allow-test-keys", "--require-publishable"]) == 1
    # Without --allow-test-keys the test key is not trusted.
    assert rs.main(["verify", "--release-file", str(out)]) == 1


def test_release_tag_is_the_single_source_used_by_the_publish_script():
    assert rs.release_tag("tv", "beta", "1.5.0-beta.1") == "tv-win-beta-v1.5.0-beta.1"
    assert rs.release_file_name("access", "1.5.0") == "release-access-1.5.0.json"
    assert rs.release_file_name("access", "1.5.0", rollback_from="1.5.1") == \
        "release-access-1.5.0-rollback-from-1.5.1.json"
