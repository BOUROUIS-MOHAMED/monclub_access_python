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
    switches: Sequence[Tuple[str, Optional[datetime]]],
    when: Optional[datetime],
) -> Optional[str]:
    """The scheme a device ran at ``when``, from its recorded switches (oldest first).

    * No switch recorded -> MEMBERSHIP for all time. That is KNOWN, not a guess: the default
      is MEMBERSHIP and every change away from it is recorded when the device row is written
      (``db._record_device_pin_scheme_switch``).
    * A switch stamped at or before ``when`` is in force; an event stamped before the first
      switch ran under that switch's ``previous`` scheme, which is MEMBERSHIP.
    * ``when`` is None (an unparseable event time) on a device that HAS switched -> None: the
      scheme genuinely cannot be known and the caller must fall back to its ambiguity rule.

    ``switches`` items are ``(scheme, switched_at)``; an item whose time could not be parsed
    makes every event after the previous parseable switch unknowable, so it answers None.
    """
    if not switches:
        return PIN_SCHEME_MEMBERSHIP
    if when is None:
        return None
    current = PIN_SCHEME_MEMBERSHIP
    for scheme, switched_at in switches:
        if switched_at is None:
            return None
        if switched_at <= when:
            current = normalize_pin_scheme(scheme)
        else:
            break
    return current
