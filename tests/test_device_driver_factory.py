"""Tests for the device-driver factory (step 1 of the multi-vendor abstraction).

Contract for this step (ZERO behaviour change for existing ZK gyms):
  * A device with NO protocol (today's reality) resolves to ZK_PULLSDK and
    get_driver() returns a real PullSDKDevice — byte-for-byte the object the
    engines constructed directly before.
  * An absent / empty / typo'd / unknown protocol ALSO defaults to ZK_PULLSDK,
    so no existing panel can be routed away from its working path.
  * An EXPLICIT standalone protocol (MB2000 etc.) raises rather than silently
    falling back onto the PullSDK path (which cannot drive it).
  * The returned driver satisfies the DeviceDriver Protocol.
"""
from __future__ import annotations

import pytest

from app.sdk.device_driver import (
    DeviceDriver,
    DeviceProtocol,
    get_driver,
    resolve_device_protocol,
)
from app.sdk.pullsdk import PullSDKDevice


def _c3_payload(**extra):
    p = {"id": 5, "name": "Door 1", "ipAddress": "192.168.0.202", "portNumber": 4370}
    p.update(extra)
    return p


class TestResolveProtocol:
    def test_absent_defaults_to_pullsdk(self):
        assert resolve_device_protocol(_c3_payload()) == DeviceProtocol.ZK_PULLSDK

    def test_empty_defaults_to_pullsdk(self):
        assert resolve_device_protocol(_c3_payload(deviceProtocol="")) == DeviceProtocol.ZK_PULLSDK

    def test_explicit_pullsdk(self):
        assert resolve_device_protocol(_c3_payload(deviceProtocol="ZK_PULLSDK")) == DeviceProtocol.ZK_PULLSDK

    def test_unknown_value_defaults_to_pullsdk(self):
        # A typo / future value must NEVER strand an existing panel — default safe.
        assert resolve_device_protocol(_c3_payload(deviceProtocol="ZK_STANDALON")) == DeviceProtocol.ZK_PULLSDK

    @pytest.mark.parametrize("val", ["ZK_STANDALONE", "standalone", "MB2000", "zkemkeeper", "zkem"])
    def test_standalone_aliases(self, val):
        assert resolve_device_protocol(_c3_payload(deviceProtocol=val)) == DeviceProtocol.ZK_STANDALONE

    def test_snake_case_key_also_read(self):
        assert resolve_device_protocol({"device_protocol": "MB2000"}) == DeviceProtocol.ZK_STANDALONE

    def test_non_dict_defaults_to_pullsdk(self):
        assert resolve_device_protocol(None) == DeviceProtocol.ZK_PULLSDK


class TestGetDriver:
    def test_default_returns_pullsdk_device(self):
        drv = get_driver(_c3_payload())
        assert isinstance(drv, PullSDKDevice)

    def test_explicit_pullsdk_returns_pullsdk_device(self):
        drv = get_driver(_c3_payload(deviceProtocol="ZK_PULLSDK"))
        assert isinstance(drv, PullSDKDevice)

    def test_returned_driver_satisfies_protocol(self):
        drv = get_driver(_c3_payload())
        assert isinstance(drv, DeviceDriver)  # runtime_checkable structural match

    def test_payload_is_passed_through(self):
        # The factory must construct the driver from the SAME payload (no data loss).
        drv = get_driver(_c3_payload(ipAddress="10.0.0.9", portNumber=4371))
        assert drv.ip == "10.0.0.9"
        assert drv.port == 4371
        assert drv.is_connected is False  # constructed, not connected — no side effects

    def test_standalone_returns_zk_standalone_driver(self):
        # Step 2 shipped the ZK_STANDALONE driver: the factory now constructs it
        # (it does NOT fall back to PullSDK, which cannot drive an MB2000).
        from app.sdk.zk_standalone import ZKStandaloneDevice
        drv = get_driver(_c3_payload(deviceProtocol="ZK_STANDALONE"))
        assert isinstance(drv, ZKStandaloneDevice)
        assert not isinstance(drv, PullSDKDevice)
        assert isinstance(drv, DeviceDriver)
        assert drv.owns_event_source is True

    def test_standalone_alias_mb2000_routes_to_standalone_driver(self):
        from app.sdk.zk_standalone import ZKStandaloneDevice
        drv = get_driver(_c3_payload(deviceProtocol="MB2000"))
        assert isinstance(drv, ZKStandaloneDevice)

    def test_standalone_driver_construction_has_no_side_effects(self):
        # Constructing the driver must not spawn threads or touch COM/network.
        drv = get_driver(_c3_payload(deviceProtocol="ZK_STANDALONE"))
        assert drv.is_connected is False
        assert drv._sta_thread is None


class TestPushAndAdmsAreNotStandalone:
    """PUSH / ADMS name ZKTeco's HTTP PUSH protocol (SpeedFace face terminals), which
    zkemkeeper cannot speak and nothing in this app implements. Until 2026-09-27 both were
    standalone aliases, so a device saved with either would have been driven over COM /
    TCP 4370. They now take the "unrecognised" path: ZK_PULLSDK, logged, exactly like a typo.
    """

    @pytest.fixture(autouse=True)
    def _clean_state(self):
        import app.sdk.device_driver as dd
        with dd._overrides_lock:
            dd._protocol_overrides.clear()
        dd._env_overrides_loaded = True  # never read the real env var here
        with dd._driver_log_lock:
            dd._last_driver_log.clear()
        yield
        with dd._overrides_lock:
            dd._protocol_overrides.clear()
        dd._env_overrides_loaded = False
        with dd._driver_log_lock:
            dd._last_driver_log.clear()

    @pytest.mark.parametrize("val, shown", [
        ("PUSH", "PUSH"), ("ADMS", "ADMS"), (" push ", "PUSH"), ("adms", "ADMS"),
    ])
    def test_payload_value_is_unrecognised_pullsdk(self, val, shown):
        from app.sdk.device_driver import _resolve_with_source
        assert _resolve_with_source(_c3_payload(deviceProtocol=val)) == (
            DeviceProtocol.ZK_PULLSDK, "unrecognised:" + shown,
        )

    @pytest.mark.parametrize("val", ["PUSH", "ADMS"])
    def test_snake_case_key_is_unrecognised_too(self, val):
        assert resolve_device_protocol({"device_protocol": val}) == DeviceProtocol.ZK_PULLSDK

    @pytest.mark.parametrize("device_id, val", [(31, "PUSH"), (32, "ADMS")])
    def test_get_driver_builds_pullsdk_and_logs_the_unrecognised_value(self, caplog, device_id, val):
        import logging
        from app.sdk.zk_standalone import ZKStandaloneDevice
        with caplog.at_level(logging.INFO, logger="device_driver"):
            drv = get_driver(_c3_payload(id=device_id, deviceProtocol=val))
        assert isinstance(drv, PullSDKDevice)
        assert not isinstance(drv, ZKStandaloneDevice)
        assert f"id={device_id}" in caplog.text
        assert f"source=unrecognised:{val}" in caplog.text

    def test_legacy_zkemkeeper_aliases_still_route_to_standalone(self):
        # Only PUSH/ADMS left the set: a device already saved with a legacy alias keeps
        # its working driver.
        from app.sdk.zk_standalone import ZKStandaloneDevice
        for val in ("STANDALONE", "ZKEMKEEPER", "ZKEM", "MB2000"):
            assert isinstance(get_driver(_c3_payload(deviceProtocol=val)), ZKStandaloneDevice), val

    @pytest.mark.parametrize("val", ["PUSH", "ADMS"])
    def test_local_override_is_pullsdk_like_any_unknown_override(self, val):
        # Unchanged override behaviour: an override the factory does not recognise as
        # standalone routes to PullSDK with source "override" (not "unrecognised"),
        # whatever the payload says.
        from app.sdk.device_driver import _resolve_with_source, set_protocol_override
        set_protocol_override(5, val)
        assert _resolve_with_source(_c3_payload(deviceProtocol="ZK_STANDALONE")) == (
            DeviceProtocol.ZK_PULLSDK, "override",
        )
