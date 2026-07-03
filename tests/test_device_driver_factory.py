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

    @pytest.mark.parametrize("val", ["ZK_STANDALONE", "standalone", "MB2000", "zkemkeeper", "PUSH", "adms"])
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
