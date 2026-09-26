"""Which turnstiles this PC may drive — one gate read by every site that connects to one.

Owner decisions 1 and 4 (2026-09-13): one driver PC per turnstile; readers NEVER connect to
any turnstile; a gym with no lease keeps today's behaviour (every PC drives every turnstile).
The server's view is ``GET /pc/assignment`` (P2c-1): ``gymUsesAssignments``, ``drive[]``
(state ``DRIVE`` or ``WAIT_FOR_RELEASE``) and ``release[]`` (turnstiles this PC must hand over).

The snapshot is immutable and swapped whole, so a reader of it (a worker thread, the door path,
a local API thread) takes no lock.

* mode ``ALL`` — no lease information (v2 off, never fetched, the gym uses no assignments):
  every turnstile is allowed, exactly as before P3b-2.
* mode ``LEASED`` — allowed = ``drive[]`` entries in state ``DRIVE`` plus ``release[]`` entries
  (the outgoing PC keeps serving the door — events, rescues, desk opens — until its release is
  acknowledged; the incoming PC must not connect while it is ``WAIT_FOR_RELEASE``). Everything
  else, including every turnstile of a reader, is refused.
* writes frozen — a ``release[]`` turnstile gets no push and no removal: the ownership record
  uploaded before the release acknowledgement must stay exact (P2c-2 §1.3).
* add-only — a driven turnstile whose record MonClub cannot fully vouch for (``handoverForced``
  on the lease, or the ownership backup not yet restored on this PC for this generation) gets
  pushes but no removal of any kind, until a read-back is confirmed (P2c-1 §1.1).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional

MODE_ALL = "ALL"
MODE_LEASED = "LEASED"


class DeviceNotLeasedError(RuntimeError):
    """A device-driving call on a turnstile this PC does not drive."""

    def __init__(self, device_id: Any) -> None:
        super().__init__(f"this PC does not drive turnstile {device_id} (driver/reader assignment)")
        self.device_id = device_id


@dataclass(frozen=True)
class DriveEntry:
    device_id: int
    generation: int
    state: str                      # DRIVE | WAIT_FOR_RELEASE
    handover_forced: bool = False
    forced_reason: Optional[str] = None
    name: str = ""


@dataclass(frozen=True)
class ReleaseEntry:
    device_id: int
    generation: int                 # the generation this PC held (what it acknowledges)
    new_driver_pc_id: Optional[int] = None
    name: str = ""


@dataclass(frozen=True)
class LeaseSnapshot:
    mode: str = MODE_ALL
    role: str = "UNKNOWN"           # ALL_TURNSTILES | DRIVER | READER | UNKNOWN
    source: str = "none"            # none | server | cache
    drive: Mapping[int, DriveEntry] = field(default_factory=dict)
    release: Mapping[int, ReleaseEntry] = field(default_factory=dict)
    add_only: FrozenSet[int] = frozenset()
    fetched_at: Optional[float] = None
    reader_of: tuple = ()

    def allows(self, device_id: Any) -> bool:
        if self.mode != MODE_LEASED:
            return True
        did = _as_id(device_id)
        if did is None:
            return False
        if did in self.release:
            return True
        entry = self.drive.get(did)
        return entry is not None and entry.state == "DRIVE"

    def writes_frozen(self, device_id: Any) -> bool:
        did = _as_id(device_id)
        return self.mode == MODE_LEASED and did is not None and did in self.release

    def removals_blocked(self, device_id: Any) -> Optional[str]:
        """None when removals may run; else the reason (``handover_release``/``add_only``)."""
        if self.mode != MODE_LEASED:
            return None
        did = _as_id(device_id)
        if did is None:
            return "not_leased"
        if did in self.release:
            return "handover_release"
        if did in self.add_only:
            return "add_only"
        if not self.allows(did):
            return "not_leased"
        return None


def _as_id(value: Any) -> Optional[int]:
    try:
        did = int(value)
    except (TypeError, ValueError):
        return None
    return did if did > 0 else None


_ALL = LeaseSnapshot()
_lock = threading.Lock()
_current: LeaseSnapshot = _ALL


def current() -> LeaseSnapshot:
    return _current


def install(snapshot: LeaseSnapshot) -> LeaseSnapshot:
    """Swap the snapshot; returns the previous one."""
    global _current
    with _lock:
        previous = _current
        _current = snapshot
    return previous


def reset_for_tests() -> None:
    install(_ALL)


def device_allowed(device_id: Any) -> bool:
    return _current.allows(device_id)


def require_device(device_id: Any) -> None:
    if not _current.allows(device_id):
        raise DeviceNotLeasedError(device_id)


def filter_devices(devices: Iterable[Any]) -> List[Any]:
    """Keep the device payloads this PC may drive (payload ``id``)."""
    snap = _current
    out = []
    for d in devices or []:
        if not isinstance(d, dict):
            continue
        if snap.allows(d.get("id")):
            out.append(d)
    return out


def writes_frozen(device_id: Any) -> bool:
    return _current.writes_frozen(device_id)


def removals_blocked(device_id: Any) -> Optional[str]:
    return _current.removals_blocked(device_id)


def snapshot_from_assignment(body: Dict[str, Any], *, source: str, add_only: Iterable[int] = (),
                             fetched_at: Optional[float] = None) -> LeaseSnapshot:
    """Build a snapshot from a ``GET /pc/assignment`` body (P2c-1 ``MyAssignment``)."""
    uses = bool(body.get("gymUsesAssignments"))
    role = str(body.get("role") or "UNKNOWN")
    reader_of = tuple(
        (int(r.get("pcId")), str(r.get("name") or ""))
        for r in (body.get("readerOf") or []) if isinstance(r, dict) and _as_id(r.get("pcId"))
    )
    if not uses:
        return LeaseSnapshot(mode=MODE_ALL, role="ALL_TURNSTILES", source=source,
                             fetched_at=fetched_at, reader_of=reader_of)
    drive: Dict[int, DriveEntry] = {}
    for item in body.get("drive") or []:
        if not isinstance(item, dict):
            continue
        did = _as_id(item.get("gymDeviceId"))
        gen = _as_id(item.get("generation"))
        if did is None or gen is None:
            continue
        drive[did] = DriveEntry(
            device_id=did, generation=gen, state=str(item.get("state") or ""),
            handover_forced=bool(item.get("handoverForced")),
            forced_reason=item.get("forcedReason"), name=str(item.get("name") or ""))
    release: Dict[int, ReleaseEntry] = {}
    for item in body.get("release") or []:
        if not isinstance(item, dict):
            continue
        did = _as_id(item.get("gymDeviceId"))
        gen = _as_id(item.get("generation"))
        if did is None or gen is None:
            continue
        release[did] = ReleaseEntry(device_id=did, generation=gen,
                                    new_driver_pc_id=_as_id(item.get("newDriverPcId")),
                                    name=str(item.get("name") or ""))
    forced = {did for did, e in drive.items() if e.handover_forced}
    return LeaseSnapshot(mode=MODE_LEASED, role=role, source=source, drive=drive, release=release,
                         add_only=frozenset(forced | {int(x) for x in add_only if _as_id(x)}),
                         fetched_at=fetched_at, reader_of=reader_of)
