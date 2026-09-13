"""Per-device PIN scheme: which id a device user's PIN is.

Decided PER DEVICE by the backend (``GymDeviceDto.pinScheme``, delivered on the same path as
``rosterPushingPolicy``) and never implicitly by a client upgrade:

  MEMBERSHIP -> activeMembershipId, else userId. The default, and the value whenever the
                backend sends nothing. Byte-identical to every pin minted before account
                pins existed.
  ACCOUNT    -> mainAccountId only; one person's memberships collapse into one device row.

On the 2026-09-12 production data 110 main_account.id values equal an existing
active_membership.id and 99 of those are a DIFFERENT person, so a terminal must never hold
both schemes: it is switched deliberately, after a manual wipe. The derivation itself lives in
``device_sync.derive_member_pin``; this module holds only what the storage layer also needs
(it cannot import device_sync, which imports it). See guide_for_agents_and_dev.md §3.2b/§3.2e.

Deliberately dependency-free: imported by app.core.db and app.core.device_sync.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Sequence, Tuple

PIN_SCHEME_MEMBERSHIP = "MEMBERSHIP"
PIN_SCHEME_ACCOUNT = "ACCOUNT"
# Only ever a device_pin_scheme_switch.previous_scheme: the row is a FIRST SIGHTING, not a
# switch -- this DB first saw the device already on that row's scheme.
PIN_SCHEME_UNKNOWN = "UNKNOWN"

# Which field actually produced a pin. Recorded wherever a pin outlives the derivation
# (push results reported upstream), because the digits alone cannot say -- that IS the
# collision.
PIN_SOURCE_ACCOUNT = "ACCOUNT"
PIN_SOURCE_MEMBERSHIP = "MEMBERSHIP"
PIN_SOURCE_USER = "USER"


def normalize_pin_scheme(raw: Any) -> str:
    """"ACCOUNT" only for exactly that token (case/space-insensitive); anything else --
    None, "", an unknown value from a newer backend -- is MEMBERSHIP, today's behaviour."""
    return PIN_SCHEME_ACCOUNT if str(raw or "").strip().upper() == PIN_SCHEME_ACCOUNT else PIN_SCHEME_MEMBERSHIP


def recognized_pin_scheme(raw: Any) -> Optional[str]:
    """``ACCOUNT`` / ``MEMBERSHIP`` for exactly those tokens (case/space-insensitive), else None.

    Used ONLY to decide whether a device payload may CHANGE the scheme. An absent key (an
    older backend, a partial payload), null, "" or a token this client does not know says
    nothing about the device and must keep the last known scheme -- folding it to MEMBERSHIP
    would switch an ACCOUNT terminal back with no wipe. ``normalize_pin_scheme`` keeps its
    default for every other reader."""
    token = str(raw or "").strip().upper()
    return token if token in (PIN_SCHEME_ACCOUNT, PIN_SCHEME_MEMBERSHIP) else None


def device_pin_scheme(device: Any) -> str:
    """The pin scheme a device payload (raw or ``_normalize_device``-d) declares."""
    if not isinstance(device, dict):
        return PIN_SCHEME_MEMBERSHIP
    raw = device.get("pinScheme")
    if raw is None:
        raw = device.get("pin_scheme")
    return normalize_pin_scheme(raw)


def scheme_at(
    switches: Sequence[Tuple[Any, ...]],
    when: Optional[datetime],
) -> Optional[str]:
    """The scheme a device ran at ``when``, from its recorded history rows (oldest first).

    ``switches`` items are ``(scheme, switched_at)`` or ``(scheme, switched_at, previous_scheme)``.

    * No row -> MEMBERSHIP for all time: this DB has only ever seen the device on MEMBERSHIP
      (or never seen it), and every change to ACCOUNT, including a first sighting already on
      ACCOUNT, writes a row (``db._record_device_pin_scheme_switch``). The residual: a device
      that ran ACCOUNT and was switched back BEFORE this DB first saw it is read as
      MEMBERSHIP for that earlier period (guide §3.2e).
    * Before the first row the device ran that row's ``previous_scheme``: MEMBERSHIP for a
      recorded switch, ``UNKNOWN`` -> None for a FIRST SIGHTING (this DB first saw the device
      already on ACCOUNT, so when it switched is not known). A 2-tuple means MEMBERSHIP.
    * A row stamped at or before ``when`` is in force.
    * ``when`` is None (an unparseable event time) on a device with rows -> None.
    * A row whose own time could not be parsed makes events unknowable until the next
      parseable row at or before ``when``.
    """
    if not switches:
        return PIN_SCHEME_MEMBERSHIP
    if when is None:
        return None
    first = switches[0]
    current: Optional[str] = (
        recognized_pin_scheme(first[2]) if len(first) > 2 else PIN_SCHEME_MEMBERSHIP
    )
    for item in switches:
        scheme, switched_at = item[0], item[1]
        if switched_at is None:
            current = None
            continue
        if switched_at <= when:
            current = normalize_pin_scheme(scheme)
        else:
            break
    return current
