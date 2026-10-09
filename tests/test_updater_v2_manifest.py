"""shared/release_manifest.py: what a signed offer must prove before any download (D3, D8)."""

from __future__ import annotations

import pytest

from shared.release_manifest import OfferRefused, canonical_manifest, verify_offer
from tests.updater_v2_support import OTHER_SEED, TEST_KEYRING, make_offer, manifest_fields


def _verify(offer, *, installed="1.5.0", target="access", platform="WINDOWS", channel="stable", keys=TEST_KEYRING):
    return verify_offer(offer, target=target, platform=platform, channel=channel, installed_version=installed, keys=keys)


def _refused(offer, **kw) -> OfferRefused:
    with pytest.raises(OfferRefused) as info:
        _verify(offer, **kw)
    return info.value


def test_a_signed_newer_release_is_accepted_with_the_manifest_values():
    offer = make_offer(version="1.5.1")
    v = _verify(offer)
    assert (v.version, v.target, v.rollback, v.rollback_from) == ("1.5.1", "access", False, None)
    assert v.installer_name == "monclub_access_1.5.1.exe"
    assert v.installer_sha256 == offer["installerSha256"]
    assert v.manifest_text == offer["signedManifest"]


def test_todays_backend_without_signed_fields_is_refused_as_unsigned_not_a_crash():
    offer = {"shouldUpdate": True, "version": "1.5.1", "installer": {"url": "https://x/y.exe", "name": "y.exe", "size": 10}}
    err = _refused(offer)
    assert err.code == "UNSIGNED" and err.is_verify_failure


def test_a_forged_signature_is_refused():
    offer = make_offer(seed=OTHER_SEED)
    assert _refused(offer).code == "BAD_SIGNATURE"


def test_a_manifest_edited_after_signing_is_refused():
    offer = make_offer()
    offer["signedManifest"] = offer["signedManifest"].replace('"installerSize":4096', '"installerSize":4097')
    assert _refused(offer).code == "BAD_SIGNATURE"


def test_an_unknown_key_id_is_refused():
    assert _refused(make_offer(key_id="test-other")).code == "UNKNOWN_KEY"
    assert _refused(make_offer(), keys={}).code == "UNKNOWN_KEY"


def test_non_ascii_manifest_is_refused():
    offer = make_offer()
    offer["signedManifest"] = offer["signedManifest"].replace("stable", "stabl\u00e9")
    assert _refused(offer).code == "BAD_MANIFEST"


@pytest.mark.parametrize(
    "kw",
    [
        {"target": "tv"},
        {"platform": "LINUX"},
        {"channel": "beta"},
    ],
)
def test_a_manifest_for_another_component_platform_or_channel_is_refused(kw):
    offer = make_offer(fields=manifest_fields(**kw))
    assert _refused(offer).code == "MISMATCH"


def test_the_dto_version_must_equal_the_signed_version():
    offer = make_offer(version="1.5.1")
    offer["version"] = "1.5.2"
    assert _refused(offer).code == "MISMATCH"


def test_a_normal_manifest_for_an_older_or_equal_version_is_not_newer():
    err = _refused(make_offer(version="1.5.0"), installed="1.5.0")
    assert err.code == "NOT_NEWER" and not err.is_verify_failure
    assert _refused(make_offer(version="1.4.35"), installed="1.5.0").code == "NOT_NEWER"


def test_a_prerelease_above_the_installed_version_is_accepted():
    assert _verify(make_offer(version="1.5.1-beta.1"), installed="1.5.0").version == "1.5.1-beta.1"
    assert _refused(make_offer(version="1.5.0-beta.1"), installed="1.5.0").code == "NOT_NEWER"


def test_a_rollback_manifest_is_accepted_only_on_the_bad_version():
    offer = make_offer(version="1.5.0", rollback_from="1.5.1")
    v = _verify(offer, installed="1.5.1")
    assert v.rollback is True and v.rollback_from == "1.5.1" and v.version == "1.5.0"
    # Replayed against any other installed version: refused.
    assert _refused(offer, installed="1.5.2").code == "ROLLBACK_NOT_FOR_US"
    assert _refused(offer, installed="1.4.35").code == "ROLLBACK_NOT_FOR_US"


def test_a_rollback_manifest_must_go_down():
    offer = make_offer(version="1.5.2", rollback_from="1.5.1")
    assert _refused(offer, installed="1.5.1").code == "ROLLBACK_NOT_FOR_US"


def test_allow_downgrade_without_rollback_from_is_refused():
    offer = make_offer(fields=manifest_fields(version="1.5.0", allowDowngrade=True))
    assert _refused(offer, installed="1.5.1").code == "BAD_MANIFEST"


@pytest.mark.parametrize(
    "override",
    [
        {"installerName": "..\\evil.exe"},
        {"installerName": "C:/x/setup.exe"},
        {"installerName": "setup.msi"},
        {"installerName": "setup.exe"},
        {"installerName": "monclub_tv_1.5.1.exe"},  # another target's installer
        {"installerName": "monclub_access_1.5.1.exe\n"},
        {"installerSha256": "ABC"},
        {"installerSha256": "A" * 64},
        {"installerSize": 0},
        {"installerSize": "4096"},
        {"installerSize": True},
        {"schema": 2},
        {"allowDowngrade": "false"},
    ],
)
def test_invalid_manifest_fields_are_refused(override):
    offer = make_offer(fields=manifest_fields(**override))
    assert _refused(offer).code == "BAD_MANIFEST"


def test_installer_url_must_be_https_or_this_pc():
    assert _refused(make_offer(url="http://evil.example/monclub_access_1.5.1.exe")).code == "BAD_MANIFEST"
    assert _verify(make_offer(url="http://127.0.0.1:8099/monclub_access_1.5.1.exe")).installer_url.startswith("http://127.0.0.1")


def test_canonical_manifest_is_sorted_compact_ascii():
    text = canonical_manifest({"b": 1, "a": "\u00e9"})
    assert text == '{"a":"\\u00e9","b":1}'


def test_a_failure_injection_test_build_name_is_accepted():
    offer = make_offer(fields=manifest_fields(name="monclub_access_1.5.1_TESTFAIL_health.exe"))
    assert _verify(offer).installer_name == "monclub_access_1.5.1_TESTFAIL_health.exe"


def test_a_signature_with_a_trailing_newline_is_refused():
    offer = make_offer()
    offer["manifestSignature"] = offer["manifestSignature"] + "\n"
    assert _verify(offer)  # stripped by the reader: still the same 128 hex
    offer["manifestSignature"] = offer["manifestSignature"].strip() + "0"
    assert _refused(offer).code == "BAD_SIGNATURE"
