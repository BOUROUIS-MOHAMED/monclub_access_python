"""Device-driver abstraction — route by PROTOCOL / SDK-family, not by model.

WHY: MonClub Access must grow to many device models and vendors (ZKTeco C2/C3/C4
+ inBio over PullSDK today; a ZKTeco MB2000 standalone terminal next; more later).
Keying behaviour on the device *model* would mean one code path per model (100s).
Instead we key on the *protocol / SDK-family* — a CLOSED set of ~3-5 — and treat the
model as DATA (a capability descriptor, added in a later step). Every ZK panel that
speaks PullSDK is then the SAME driver and 1 DB row of new code; a genuinely different
SDK (MB2000 standalone/zkemkeeper) is 1 new driver, not one-per-model.

STEP 1 (this file) is deliberately a ZERO-BEHAVIOUR-CHANGE indirection:
  * ``DeviceDriver`` is a structural Protocol that ``PullSDKDevice`` ALREADY satisfies
    (no change to app/sdk/pullsdk.py).
  * ``get_driver(device_payload)`` is the single construction point that the engines
    call instead of ``PullSDKDevice(...)`` directly. It defaults to ZK_PULLSDK when the
    device carries no protocol, so existing gyms behave EXACTLY as before.
  * The second driver (ZK_STANDALONE / MB2000) is not built yet — an explicit
    ZK_STANDALONE device raises, so it can never silently fall back onto the C3 path.

Later steps (see project_device_driver_abstraction memory) add: the backend
``deviceProtocol`` column, a ``CapabilityDescriptor`` (poll|push, has_fingerprint,
template_format, max_card_digits, door_param_style, ...), the driver-owns-its-event-source
refinement (``start(on_event)``/``stop()`` so poll-vs-push never reaches the engine), and
the MB2000 standalone driver. This file is only the interface + factory.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

_log = logging.getLogger("device_driver")


class DeviceProtocol(str, Enum):
    """SDK/transport family a device speaks. The CLOSED set the factory routes on.

    ZK_PULLSDK   — ZKTeco access panels via plcommpro.dll / PullSDK (C2/C3/C4/inBio).
                   Poll-based (GetRTLogExt). One persistent TCP connection per panel.
    ZK_STANDALONE — ZKTeco standalone terminals via the standalone SDK (zkemkeeper COM
                   / TCP 4370 / Push-ADMS), e.g. MB2000. Event-push. NOT YET IMPLEMENTED.
    """

    ZK_PULLSDK = "ZK_PULLSDK"
    ZK_STANDALONE = "ZK_STANDALONE"


# Synonyms accepted from the backend/device payload for each protocol. Anything not
# recognised as an explicit non-PullSDK protocol defaults to ZK_PULLSDK, so an absent,
# empty, or typo'd value can NEVER route an existing ZK panel away from its working path.
_STANDALONE_ALIASES = frozenset(
    {"ZK_STANDALONE", "STANDALONE", "ZKEMKEEPER", "ZKEM", "PUSH", "ADMS", "MB2000"}
)


@runtime_checkable
class DeviceDriver(Protocol):
    """The device-oriented contract the engines depend on.

    ``PullSDKDevice`` (app/sdk/pullsdk.py) already implements every member below, so it
    satisfies this Protocol structurally with no inheritance change. A future driver
    (e.g. MB2000) implements the same surface; capability/transport differences (poll vs
    push, fingerprint push, card-length limits) are handled by the driver + the
    forthcoming CapabilityDescriptor, never by the engine branching on model.

    NOTE (later step): the poll model (``poll_rtlog_once``) will be superseded by a
    driver-owned event source (``start(on_event)``/``stop()``) so push devices are
    structurally possible. That refinement is intentionally NOT in step 1.
    """

    @property
    def is_connected(self) -> bool: ...
    def ensure_connected(self) -> bool: ...
    def connect(self) -> bool: ...
    def disconnect(self) -> None: ...
    def open_door(self, *, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> bool: ...
    def get_device_time(self) -> Optional[float]: ...
    def set_device_time(self, epoch: float) -> bool: ...
    def get_device_param(self, *, items: str, initial_size: int | None = None) -> Optional[str]: ...
    def set_device_param(self, *, items: str) -> int: ...
    def get_table_count(self, *, table: str, filter_expr: str = "", options: str = "") -> int: ...
    def delete_table_rows(self, *, table: str, data: str = "", options: str = "") -> int: ...
    def read_transaction_rows(self, *, options: str = "new record", initial_size: int | None = None) -> List[Dict[str, str]]: ...
    def poll_rtlog_once(self) -> List[Dict[str, Any]]: ...


class UnsupportedDeviceProtocolError(NotImplementedError):
    """Raised when a device declares a protocol whose driver is not built yet.

    Deliberately a hard error (not a fallback): a ZK_STANDALONE/MB2000 device must never
    be silently driven by the PullSDK path, which cannot talk to it and would appear to
    'work' while doing nothing.
    """


def resolve_device_protocol(device_payload: Any) -> DeviceProtocol:
    """Pick the protocol family for a device payload.

    Reads ``deviceProtocol`` (camelCase, backend convention) or ``device_protocol``.
    Absent / empty / unrecognised -> ZK_PULLSDK (the safe default: every device onboarded
    so far is a ZK PullSDK panel, and no gym should regress before the backend even sends
    a protocol). Only an explicitly-recognised standalone value routes to ZK_STANDALONE.
    """
    raw = ""
    if isinstance(device_payload, dict):
        raw = str(
            device_payload.get("deviceProtocol")
            or device_payload.get("device_protocol")
            or ""
        ).strip().upper()
    if raw in _STANDALONE_ALIASES:
        return DeviceProtocol.ZK_STANDALONE
    return DeviceProtocol.ZK_PULLSDK


def get_driver(device_payload: Dict[str, Any], logger: Any | None = None) -> DeviceDriver:
    """Single construction point for a device driver — replaces direct ``PullSDKDevice(...)``.

    Returns a driver satisfying :class:`DeviceDriver`. Today ZK_PULLSDK -> ``PullSDKDevice``
    (byte-for-byte the same object the engines built before), so this is a pure indirection.
    ZK_STANDALONE raises :class:`UnsupportedDeviceProtocolError` until its driver exists.
    """
    protocol = resolve_device_protocol(device_payload)
    if protocol == DeviceProtocol.ZK_PULLSDK:
        # Lazy import keeps this module import-cycle-free (pullsdk never imports us).
        from app.sdk.pullsdk import PullSDKDevice

        return PullSDKDevice(device_payload, logger=logger)

    raise UnsupportedDeviceProtocolError(
        f"No driver implemented for device protocol {protocol.value!r} "
        f"(device id={device_payload.get('id') if isinstance(device_payload, dict) else '?'}). "
        f"Only ZK_PULLSDK is supported in this build."
    )
