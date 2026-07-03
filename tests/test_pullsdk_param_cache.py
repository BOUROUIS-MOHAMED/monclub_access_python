"""Tests for PullSDK.set_device_param() skip-if-unchanged per-connection cache.

The ULTRA device sync re-applied static door-timing / anti-fraud params on EVERY
cycle; on the antivirus-slow gym PC each SetDeviceParam is a ~200ms round-trip, so
5-10/cycle blocked the live worker ~1.8s (the recurring freeze). The cache skips
the DLL round-trip when every "K=V" pair was already written with the same value
ON THIS connection, and — because a fresh PullSDK is created per (re)connect — it
resets on reconnect so a rebooted controller always gets a full re-apply.
"""

from unittest.mock import MagicMock

from app.sdk.pullsdk import PullSDK


def _sdk() -> PullSDK:
    sdk = PullSDK("fake.dll", MagicMock())
    sdk._h = 0xABCD  # non-zero => _require_handle() passes
    dll = MagicMock()
    dll.SetDeviceParam.return_value = 1  # rc>=0 == success
    sdk._dll = dll  # non-None => load() returns early, no real DLL
    return sdk


def _calls(sdk) -> int:
    return sdk._dll.SetDeviceParam.call_count


def test_first_write_hits_dll():
    sdk = _sdk()
    sdk.set_device_param(items="Door1Drivertime=5")
    assert _calls(sdk) == 1


def test_repeat_same_value_is_skipped():
    sdk = _sdk()
    sdk.set_device_param(items="Door1Drivertime=5")
    rc = sdk.set_device_param(items="Door1Drivertime=5")  # unchanged
    assert _calls(sdk) == 1  # NOT re-sent
    assert rc == 0  # skip returns a success rc


def test_changed_value_is_rewritten():
    sdk = _sdk()
    sdk.set_device_param(items="Door1Drivertime=5")
    sdk.set_device_param(items="Door1Drivertime=7")  # value changed
    assert _calls(sdk) == 2


def test_value_oscillation_is_not_wrongly_skipped():
    # 5 -> 7 -> 5: the final 5 must be re-sent because the device currently has 7,
    # even though 5 was written earlier. (A naive set-of-strings cache would skip.)
    sdk = _sdk()
    sdk.set_device_param(items="Door1Drivertime=5")
    sdk.set_device_param(items="Door1Drivertime=7")
    sdk.set_device_param(items="Door1Drivertime=5")
    assert _calls(sdk) == 3


def test_batched_items_skip_only_when_all_pairs_unchanged():
    sdk = _sdk()
    sdk.set_device_param(items="Door1Intertime=30,Door2Intertime=30")
    sdk.set_device_param(items="Door1Intertime=30,Door2Intertime=30")  # all same -> skip
    assert _calls(sdk) == 1
    sdk.set_device_param(items="Door1Intertime=30,Door2Intertime=20")  # one changed -> write
    assert _calls(sdk) == 2


def test_unparseable_token_always_writes():
    # A token with no '=' can't be diffed, so never skip it.
    sdk = _sdk()
    sdk.set_device_param(items="ResetSomething")
    sdk.set_device_param(items="ResetSomething")
    assert _calls(sdk) == 2


def test_failed_write_not_cached_and_retried():
    sdk = _sdk()
    sdk._dll.SetDeviceParam.return_value = -1  # failure
    try:
        sdk.set_device_param(items="Door1Drivertime=5")
    except Exception:
        pass
    # A failed write must not be recorded, so the next attempt retries.
    sdk._dll.SetDeviceParam.return_value = 1
    sdk.set_device_param(items="Door1Drivertime=5")
    assert _calls(sdk) == 2


def test_reconnect_resets_cache():
    # A brand-new PullSDK (what PullSDKDevice.connect() creates on every reconnect)
    # starts with an empty cache, so the same param is re-applied once.
    sdk1 = _sdk()
    sdk1.set_device_param(items="Door1Drivertime=5")
    assert _calls(sdk1) == 1
    sdk2 = _sdk()  # simulates reconnect => fresh PullSDK
    sdk2.set_device_param(items="Door1Drivertime=5")
    assert _calls(sdk2) == 1  # re-applied on the new connection


def test_empty_items_raises():
    import pytest
    from app.sdk.pullsdk import PullSDKError

    sdk = _sdk()
    with pytest.raises(PullSDKError):
        sdk.set_device_param(items="   ")
