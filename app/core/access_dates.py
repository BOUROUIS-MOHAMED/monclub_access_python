"""Sync protocol 2 on the PC: validity windows, the gym date and the clock (P3b-1).

Pure logic -- no database, no clock of its own (every "now" is passed in). The database side
lives in ``db.py`` (the tables, the save, the flip job); the wiring in ``app.py``.

The contract is the backend's (``ActiveMemberResponseV2``, ``ActiveMemberUserV2Dto``,
``AccessWindowDto``, ``AccessSyncMetaDto``, ``UpcomingGymAccessCredentialDto``):

* On a day D up to ``syncMeta.horizonEnd`` a membership is deliverable exactly when
  ``accessFrom <= D <= accessUntil`` and D is not in ``offDays``. After ``horizonEnd``,
  ``accessFrom``/``accessUntil`` stay exact but ``offDays`` says nothing; a membership marked
  ``offDaysBeyondHorizon`` has SOME off day there. What the door does then is the PC's policy
  (the server states no default): here such a day counts as deliverable inside the window --
  the end date still applies (guide §3.8, an owner decision).
* The day a PC applies offline comes from its own clock, in Tunis time, and never earlier than
  the last ``syncMeta.today`` it received. The Tunis offset is taken from ``syncMeta.serverTime``
  (``uuuu-MM-dd'T'HH:mm:ss.SSSXXX``): the 32-bit Python the gyms run has no ``tzdata``, so
  ``zoneinfo.ZoneInfo('Africa/Tunis')`` is not available.
* A QR grant counts on day D only when that membership is deliverable on D by its window.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

# A PC clock reading more than this BEHIND the latest trustworthy time it has seen (the last
# server time, or the highest PC time seen since) is suspect. Policy: absorbs ordinary NTP
# corrections and the PC/server skew of a normal clock; a flat CMOS battery is years behind.
CLOCK_BEHIND_TOLERANCE_SEC = 300.0
# A PC clock more than a day AHEAD of the server at the last sync is suspect (task rule).
CLOCK_AHEAD_LIMIT_SEC = 86400.0

DELIVERABLE_STATUSES = frozenset({"ok", "grace"})


# ============================================================================== windows
def parse_iso_date(value: Any) -> Optional[date]:
    """A ``yyyy-MM-dd`` string (exactly that shape) as a date, else None."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if len(s) != 10:
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


@dataclass(frozen=True)
class AccessWindow:
    access_from: date
    access_until: date
    off_days: frozenset = frozenset()
    off_days_beyond_horizon: bool = False


def parse_window(obj: Mapping[str, Any]) -> Optional[AccessWindow]:
    """The window carried by a ``users[]`` / ``upcoming[]`` row or a ``memberWindows`` entry.

    None when it is absent or malformed (a missing bound, a bad date, ``accessFrom`` after
    ``accessUntil``, ``offDays`` not a list of dates). A None window is never guessed at.
    """
    if not isinstance(obj, Mapping):
        return None
    frm = parse_iso_date(obj.get("accessFrom"))
    until = parse_iso_date(obj.get("accessUntil"))
    if frm is None or until is None or until < frm:
        return None
    raw_off = obj.get("offDays")
    if raw_off is None:
        raw_off = []
    if not isinstance(raw_off, list):
        return None
    off: Set[date] = set()
    for item in raw_off:
        d = parse_iso_date(item)
        if d is None:
            return None
        off.add(d)
    return AccessWindow(frm, until, frozenset(off), obj.get("offDaysBeyondHorizon") is True)


def window_status(
    w: AccessWindow,
    day: date,
    *,
    horizon_end: Optional[date],
    server_today: Optional[date],
    grace_days: int,
) -> str:
    """``ok`` | ``grace`` | ``expired`` | ``not_started`` | ``frozen`` for the membership on ``day``.

    ``grace``: past ``accessUntil`` but kept by the offline grace -- only on a day AFTER the last
    server day (the server's own list is current on that day) and only for an end date, never a
    freeze day or a start. Beyond ``horizon_end`` an ``offDays`` entry cannot exist, so a
    membership flagged ``offDaysBeyondHorizon`` is ``ok`` inside its window (module policy).
    """
    if day < w.access_from:
        return "not_started"
    if day > w.access_until:
        g = max(0, int(grace_days or 0))
        if (g > 0 and server_today is not None and day > server_today
                and day <= w.access_until + timedelta(days=g)):
            return "grace"
        return "expired"
    if day in w.off_days:
        return "frozen"
    return "ok"


def is_deliverable(w: AccessWindow, day: date, *, horizon_end: Optional[date],
                   server_today: Optional[date], grace_days: int) -> bool:
    return window_status(w, day, horizon_end=horizon_end, server_today=server_today,
                         grace_days=grace_days) in DELIVERABLE_STATUSES


# ============================================================================== the v2 payload
@dataclass(frozen=True)
class SyncMeta:
    protocol: int
    today: date
    horizon_days: int
    horizon_end: date
    server_time: str
    server_epoch: float
    utc_offset_sec: int
    snapshot_at: Optional[str]
    reconcile_sec: Optional[int]
    capabilities: Tuple[str, ...]


def parse_sync_meta(obj: Any) -> Tuple[Optional[SyncMeta], Optional[str]]:
    if not isinstance(obj, Mapping):
        return None, "sync_meta: not an object"
    try:
        protocol = int(obj.get("protocol"))
    except (TypeError, ValueError):
        return None, "sync_meta: protocol"
    if protocol < 2:
        return None, "sync_meta: protocol < 2"
    today = parse_iso_date(obj.get("today"))
    horizon_end = parse_iso_date(obj.get("horizonEnd"))
    if today is None or horizon_end is None or horizon_end < today:
        return None, "sync_meta: today/horizonEnd"
    raw_time = obj.get("serverTime")
    try:
        st = datetime.fromisoformat(str(raw_time))
    except (TypeError, ValueError):
        return None, "sync_meta: serverTime"
    off = st.utcoffset()
    if off is None:
        return None, "sync_meta: serverTime has no offset"
    try:
        horizon_days = int(obj.get("horizonDays"))
    except (TypeError, ValueError):
        horizon_days = (horizon_end - today).days
    reconcile = obj.get("reconcileSec")
    try:
        reconcile_sec = int(reconcile) if reconcile is not None else None
    except (TypeError, ValueError):
        reconcile_sec = None
    caps = obj.get("capabilities")
    capabilities = tuple(str(c) for c in caps) if isinstance(caps, list) else ()
    snap = obj.get("snapshotAt")
    return SyncMeta(
        protocol=protocol, today=today, horizon_days=horizon_days, horizon_end=horizon_end,
        server_time=str(raw_time), server_epoch=st.timestamp(),
        utc_offset_sec=int(off.total_seconds()), snapshot_at=str(snap) if snap is not None else None,
        reconcile_sec=reconcile_sec, capabilities=capabilities,
    ), None


def _positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


@dataclass
class V2Payload:
    meta: SyncMeta
    windows_version: Optional[str]
    # None: the members section was skipped -- every stored list is still exact.
    today_windows: Optional[Dict[int, AccessWindow]] = None
    windowless_ids: Set[int] = field(default_factory=set)
    # None: not sent (a skipped section, or a delta whose upcoming list did not change).
    upcoming_rows: Optional[List[Dict[str, Any]]] = None
    upcoming_windows: Dict[int, AccessWindow] = field(default_factory=dict)
    upcoming_qr_account: Dict[int, int] = field(default_factory=dict)
    upcoming_credentials: Optional[List[Dict[str, Any]]] = None


def parse_v2_payload(data: Mapping[str, Any]) -> Tuple[Optional[V2Payload], Optional[str]]:
    """The protocol-2 parts of a ``get_gym_users`` answer, validated as a whole.

    ``(None, None)``: a v1 answer (no ``syncMeta``). ``(None, reason)``: a malformed protocol-2
    part -- the caller treats it exactly like a v1 answer (drop the windows token, stop trusting
    the stored windows). A partial acceptance would store a list that is not what the token says.
    """
    if not isinstance(data, Mapping) or data.get("syncMeta") is None:
        return None, None
    meta, err = parse_sync_meta(data.get("syncMeta"))
    if meta is None:
        return None, err
    wv = data.get("currentWindowsVersion")
    p = V2Payload(meta=meta, windows_version=str(wv) if wv not in (None, "") else None)
    if not bool(data.get("refreshMembers", True)):
        return p, None
    users = data.get("users")
    if users is None:
        users = []
    if not isinstance(users, list):
        return None, "users: not a list"
    windows: Dict[int, AccessWindow] = {}
    for row in users:
        if not isinstance(row, Mapping):
            continue
        am = _positive_int(row.get("activeMembershipId"))
        if am is None:
            continue       # the v1 authority check owns malformed member ids
        w = parse_window(row)
        if w is None:
            p.windowless_ids.add(am)
        else:
            windows[am] = w
    mw = data.get("memberWindows")
    if mw is None:
        mw = []
    if not isinstance(mw, list):
        return None, "member_window: not a list"
    for entry in mw:
        am = _positive_int(entry.get("activeMembershipId")) if isinstance(entry, Mapping) else None
        w = parse_window(entry) if am is not None else None
        if am is None or w is None:
            return None, "member_window: malformed entry"
        if am in windows or am in p.windowless_ids:
            return None, f"duplicate_window: {am}"
        windows[am] = w
    p.today_windows = windows
    has_up, has_ids = "upcoming" in data and data.get("upcoming") is not None, \
        "upcomingIds" in data and data.get("upcomingIds") is not None
    if not has_up and not has_ids:
        if data.get("upcomingCredentials") is not None:
            return None, "upcoming_credentials: sent without upcoming"
        return p, None
    if has_up != has_ids:
        return None, "upcoming_ids: upcoming and upcomingIds must come together"
    rows, ids = data.get("upcoming"), data.get("upcomingIds")
    if not isinstance(rows, list) or not isinstance(ids, list):
        return None, "upcoming_ids: not lists"
    seen: List[int] = []
    for row in rows:
        am = _positive_int(row.get("activeMembershipId")) if isinstance(row, Mapping) else None
        w = parse_window(row) if am is not None else None
        if am is None or w is None:
            return None, "upcoming: malformed row"
        seen.append(am)
        p.upcoming_windows[am] = w
        qr = _positive_int(row.get("qrAccountId"))
        if qr is not None:
            p.upcoming_qr_account[am] = qr
    norm_ids = [_positive_int(x) for x in ids]
    if None in norm_ids or sorted(seen) != sorted(norm_ids) or len(set(seen)) != len(seen):
        return None, "upcoming_ids: do not match upcoming[]"
    creds = data.get("upcomingCredentials")
    if creds is None:
        creds = []
    if not isinstance(creds, list) or not all(isinstance(c, Mapping) for c in creds):
        return None, "upcoming_credentials: not a list of objects"
    p.upcoming_rows = [dict(r) for r in rows]
    p.upcoming_credentials = [dict(c) for c in creds]
    return p, None


# ============================================================================== gym date & clock
@dataclass(frozen=True)
class ClockState:
    server_today: Optional[date] = None
    server_epoch: Optional[float] = None
    utc_offset_sec: Optional[int] = None
    skew_sec: Optional[float] = None
    floor_date: Optional[date] = None
    max_pc_epoch: Optional[float] = None


@dataclass(frozen=True)
class GymDate:
    gym_date: Optional[date]
    pc_date: Optional[date]
    suspect: bool
    reason: str
    new_floor_date: Optional[date]
    new_max_pc_epoch: Optional[float]


def gym_local_date(epoch: float, utc_offset_sec: int) -> date:
    return date(1970, 1, 1) + timedelta(days=int((float(epoch) + int(utc_offset_sec)) // 86400))


def gym_seconds_of_day(epoch: float, utc_offset_sec: int) -> float:
    return (float(epoch) + int(utc_offset_sec)) % 86400


def seconds_until_gym_time(epoch: float, utc_offset_sec: int, hh: int, mm: int, ss: int = 0) -> float:
    """Seconds from ``epoch`` to the next hh:mm:ss gym time (strictly in the future)."""
    target = hh * 3600 + mm * 60 + ss
    now_sod = gym_seconds_of_day(epoch, utc_offset_sec)
    delta = target - now_sod
    if delta <= 0:
        delta += 86400
    return delta


def clock_at_sync(server_epoch: float, pc_epoch: float) -> Tuple[float, str]:
    """(skew, reason) measured when a protocol-2 answer arrives. skew = PC - server."""
    skew = float(pc_epoch) - float(server_epoch)
    if skew < -CLOCK_BEHIND_TOLERANCE_SEC:
        return skew, "behind"
    if skew > CLOCK_AHEAD_LIMIT_SEC:
        return skew, "ahead"
    return skew, ""


def evaluate_gym_date(state: ClockState, pc_now_epoch: float) -> GymDate:
    """The date the PC applies now, and whether its clock is suspect.

    Never earlier than the last server day nor than a day already applied since that sync
    (``floor_date``): a clock that falls back -- a flat battery, a wrong manual change -- can
    re-admit nobody. A suspect clock applies exactly that floor: dates advance only as far as
    was already known. A clock that is not suspect advances ``max_pc_epoch`` and the floor.
    """
    if state.server_today is None or state.utc_offset_sec is None:
        return GymDate(None, None, False, "", state.floor_date, state.max_pc_epoch)
    now = float(pc_now_epoch)
    pc_date = gym_local_date(now, state.utc_offset_sec)
    refs = [x for x in (state.server_epoch, state.max_pc_epoch) if x is not None]
    reasons: List[str] = []
    if refs and now < max(refs) - CLOCK_BEHIND_TOLERANCE_SEC:
        reasons.append("behind")
    if state.skew_sec is not None and float(state.skew_sec) > CLOCK_AHEAD_LIMIT_SEC:
        reasons.append("ahead")
    floor = max(d for d in (state.server_today, state.floor_date) if d is not None)
    if reasons:
        return GymDate(floor, pc_date, True, ",".join(reasons), floor, state.max_pc_epoch)
    gym = max(pc_date, floor)
    new_max = now if state.max_pc_epoch is None else max(float(state.max_pc_epoch), now)
    return GymDate(gym, pc_date, False, "", gym, new_max)


# ============================================================================== the flip plan
@dataclass
class FlipPlan:
    gym_date: date
    hold: Dict[int, str] = field(default_factory=dict)     # am -> reason
    restore: List[int] = field(default_factory=list)
    promote: List[int] = field(default_factory=list)
    starters: List[int] = field(default_factory=list)      # memberships starting on gym_date

    @property
    def moved(self) -> int:
        return len(self.hold) + len(self.restore) + len(self.promote)


def plan_flip(
    *,
    gym_date: date,
    server_today: Optional[date],
    horizon_end: Optional[date],
    grace_days: int,
    active_ids: Iterable[int],
    held_ids: Iterable[int],
    today_windows: Mapping[int, AccessWindow],
    upcoming_windows: Mapping[int, AccessWindow],
) -> FlipPlan:
    """What must move so the local roster is exactly the members deliverable on ``gym_date``.

    * a roster row whose window is not deliverable -> held out (its row is kept, not deleted);
    * a held row whose window is deliverable again -> restored; a held row with no window is
      kept held (nothing proves it may come back);
    * an upcoming row deliverable on the day, not on the roster nor held -> promoted (copied);
    * a roster row with no window (a fast patch, a v1 period) is never moved.
    """
    kw = dict(horizon_end=horizon_end, server_today=server_today, grace_days=grace_days)
    active = {int(a) for a in active_ids}
    held = {int(a) for a in held_ids}
    plan = FlipPlan(gym_date=gym_date)

    def _window(am: int) -> Optional[AccessWindow]:
        w = today_windows.get(am)
        return w if w is not None else upcoming_windows.get(am)

    for am in sorted(active):
        w = _window(am)
        if w is None:
            continue
        st = window_status(w, gym_date, **kw)
        if st not in DELIVERABLE_STATUSES:
            plan.hold[am] = st
    for am in sorted(held - active):
        w = _window(am)
        if w is not None and is_deliverable(w, gym_date, **kw):
            plan.restore.append(am)
    for am in sorted(upcoming_windows):
        if am in active or am in held:
            continue
        if is_deliverable(upcoming_windows[am], gym_date, **kw):
            plan.promote.append(am)
    plan.starters = sorted(am for am, w in upcoming_windows.items() if w.access_from == gym_date)
    return plan


# ============================================================================== QR
@dataclass(frozen=True)
class AccessDaysSnapshot:
    """What the QR check needs, frozen at one generation: the applied gym date and the windows."""
    trusted: bool
    gym_date: Optional[date]
    server_today: Optional[date]
    horizon_end: Optional[date]
    grace_days: int
    windows: Mapping[int, AccessWindow]                    # today's set and the upcoming list
    upcoming_qr_account: Mapping[int, int] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return bool(self.trusted and self.gym_date is not None)

    def deliverable(self, am: int) -> Optional[bool]:
        """True/False by the window on the gym date; None when there is no window."""
        w = self.windows.get(am)
        if w is None or self.gym_date is None:
            return None
        return is_deliverable(w, self.gym_date, horizon_end=self.horizon_end,
                              server_today=self.server_today, grace_days=self.grace_days)


def _grant_ids(grants: Iterable[Any]) -> List[int]:
    out: List[int] = []
    for g in grants or ():
        n = _positive_int(g)
        if n is not None:
            out.append(n)
    return out


def qr_date_verdict(
    snapshot: Optional[AccessDaysSnapshot],
    *,
    grants: Sequence[Any],
    users_by_am: Mapping[int, Any],
    account_on_roster: bool = False,
    roster_current: bool = True,
) -> str:
    """``ok`` | ``not_today`` | ``unchecked`` for a matched QR credential.

    ``ok``: a grant is deliverable today by its window, or a grant is on the (date-flipped)
    roster with no window (a fast patch, a v1 row), or the account second chance found a roster
    row of the same account (a renewal whose grants are stale). ``not_today``: every grant is
    provably not deliverable today -- by its window, or by having no window and no row on a
    CURRENT, non-empty roster. ``unchecked``: no trusted windows, or a grant with no window when
    the roster cannot be read or is older than the credential index -- nothing can be proven.
    """
    if snapshot is None or not snapshot.active:
        return "unchecked"
    ids = _grant_ids(grants)
    unknown = False
    for am in ids:
        d = snapshot.deliverable(am)
        if d is True:
            return "ok"
        if d is None:
            if am in users_by_am:
                return "ok"
            unknown = True
    if account_on_roster:
        return "ok"
    if unknown and (not users_by_am or not roster_current):
        return "unchecked"
    return "not_today"


def effective_credentials(
    main_creds: Sequence[Mapping[str, Any]],
    upcoming_creds: Sequence[Mapping[str, Any]],
    snapshot: Optional[AccessDaysSnapshot],
) -> List[Dict[str, Any]]:
    """The credentials the QR check uses on the gym date (the loop AND the speed index).

    Untrusted windows: exactly the main list. Trusted:
    * an upcoming credential (stored disabled, ``notYetValid``) is added, enabled, on a day one of
      its grants is deliverable -- unless the account already has an enabled main credential;
    * a main credential gains the upcoming memberships whose ``qrAccountId`` is its account and
      that are deliverable today (a renewal: "one more grant of that credential on its first day").
    Nothing stored is changed: copies only.
    """
    main = [dict(c) for c in main_creds or ()]
    if snapshot is None or not snapshot.active:
        return main
    starting_by_account: Dict[int, List[int]] = {}
    for am, account in (snapshot.upcoming_qr_account or {}).items():
        if snapshot.deliverable(am) is True:
            starting_by_account.setdefault(int(account), []).append(int(am))
    enabled_accounts: Set[int] = set()
    for c in main:
        acc = _positive_int(c.get("accountId"))
        if acc is None:
            continue
        if bool(c.get("enabled", False)):
            enabled_accounts.add(acc)
        extra = starting_by_account.get(acc)
        if extra:
            grants = list(c.get("grantedActiveMembershipIds") or [])
            have = set(_grant_ids(grants))
            add = [am for am in sorted(extra) if am not in have]
            if add:
                c["grantedActiveMembershipIds"] = grants + add
    out = main
    for u in upcoming_creds or ():
        acc = _positive_int(u.get("accountId"))
        if acc is None or acc in enabled_accounts:
            continue
        if any(snapshot.deliverable(am) is True for am in _grant_ids(u.get("grantedActiveMembershipIds") or [])):
            promoted = dict(u)
            promoted["enabled"] = True
            promoted["upcomingPromoted"] = True
            out.append(promoted)
            enabled_accounts.add(acc)
    return out
