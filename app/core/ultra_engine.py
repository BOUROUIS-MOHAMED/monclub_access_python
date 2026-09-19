"""ULTRA mode engine: device-firmware RFID/FP + PC-side RTLog observer + TOTP rescue."""

import hashlib
import logging
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Deque, Dict, List, Optional, Set

from app.core.access_types import HistoryRecord, NotificationRequest
from app.core.access_verification import (
    EVENT_TIME_SANITY_BOUND_SEC as _EVENT_TIME_SANITY_BOUND_SEC,
    build_totp_index,
    load_local_state,
    maybe_log_totp_roster_summary,
    parse_event_time_to_epoch,
    record_totp_roster_check,
    verify_card,
    verify_totp_resilient,
    _totp_counter,
    _totp_params,
)
from app.core.db import (
    get_recent_access_history,
    insert_access_history,
    count_recent_for_user_door,
    load_sync_cache,
    invalidate_sync_cache,
    get_local_state_generation,
    get_membership_brief_index,
    get_membership_brief_index_cached,
    get_staff_membership_ids,
    get_staff_membership_ids_cached,
    insert_push_batch,
    update_push_batch,
)
from app.core.popup_image_cache import prefetch as _prefetch_popup_image
from app.core import telemetry as _tel
from app.core import push_safety as _push_safety
from app.sdk.pullsdk import PullSDKDevice
from app.sdk.device_driver import DeviceProtocol, get_driver, resolve_device_protocol

logger = logging.getLogger("zkapp")


def _worker_is_usable(worker: Any) -> bool:
    """Return actual thread liveness while keeping lightweight test doubles usable."""
    is_alive = getattr(worker, "is_alive", None)
    if not callable(is_alive):
        return True
    try:
        return bool(is_alive())
    except Exception:
        return False


def _worker_request_accepted_or_pending(
    worker: Any,
    *,
    request_method: str,
    pending_method: str,
    member_id: int,
) -> bool:
    request = getattr(worker, request_method, None)
    if not callable(request):
        return False
    accepted = bool(request(int(member_id)))
    if accepted:
        return True
    pending = getattr(worker, pending_method, None)
    return bool(callable(pending) and pending(int(member_id)))


def _worker_member_revoke_accepted_or_covered(worker: Any, member_id: int) -> bool:
    """Atomically accept a revoke or confirm that worker-owned work covers it."""
    request = getattr(worker, "request_member_revoke", None)
    return bool(callable(request) and request(int(member_id)))


def _worker_full_sync_accepted_or_pending(
    worker: Any,
    *,
    reason: str,
    fingerprint_hash: str | None = None,
    revoked_ids: set[int] | None = None,
    require_full_refresh: bool = False,
    full_reconcile: bool = False,
) -> bool:
    request = getattr(worker, "request_full_sync", None)
    if not callable(request):
        return False
    kwargs: Dict[str, Any] = {"reason": reason}
    if fingerprint_hash is not None:
        kwargs["fingerprint_hash"] = fingerprint_hash
    if revoked_ids:
        kwargs["revoked_ids"] = set(revoked_ids)
    if require_full_refresh:
        kwargs["require_full_refresh"] = True
    if full_reconcile:
        kwargs["full_reconcile"] = True
    return bool(request(**kwargs))


def _sync_cache_without_revoked_ids(cache: Any, revoked_ids: set[int] | None) -> Any:
    """Copy a sync-cache snapshot while excluding authoritative revoked memberships."""
    normalized_revoked_ids = {int(member_id) for member_id in (revoked_ids or set())}
    if not normalized_revoked_ids:
        return cache
    users = []
    for user in list(getattr(cache, "users", []) or []):
        if not isinstance(user, dict):
            users.append(user)
            continue
        raw_member_id = user.get("activeMembershipId")
        try:
            if raw_member_id is not None and int(raw_member_id) in normalized_revoked_ids:
                continue
        except (TypeError, ValueError):
            pass
        users.append(user)
    filtered_cache_attrs = dict(getattr(cache, "__dict__", {}))
    filtered_cache_attrs["users"] = users
    return SimpleNamespace(**filtered_cache_attrs)


# Fix #1 / #2a — clock-skew handling for TOTP rescue.
# An RTLog event carries the device's own timestamp for when the scan happened.
# We validate TOTP against that instant (not wall-clock-at-processing) so the
# poll/sync pipeline latency can't expire a still-valid code. The sanity bound
# beyond which a scan time is treated as a broken device clock lives in
# access_verification (_EVENT_TIME_SANITY_BOUND_SEC, imported above).
#
# When an event is older than this at processing time (pipeline latency + any
# PC/device clock skew), emit a throttled warning: at this magnitude the tight
# default TOTP window (±1 step / 32 s) will start rejecting valid codes.
_CLOCK_SKEW_WARN_SEC = 20.0
_CLOCK_SKEW_WARN_INTERVAL_SEC = 120.0

# Card/QR re-scan cooldown has TWO distinct jobs that used to be conflated:
#   1. DEBOUNCE — the C3 controller fires several RTLog events per single scan
#      (one per door). We must suppress those for a few seconds so the relay
#      isn't re-pulsed. This is ALWAYS needed, even with anti-fraud off, and is
#      short (a member can't physically re-enter within it).
#   2. ANTI-PASSBACK — block re-use of the same card/QR for anti_fraude_duration
#      seconds. This applies ONLY when anti-fraud is enabled for that scan kind.
# The old code used a single frozen value (anti_fraude_duration, computed once at
# init), so disabling anti-fraud still blocked re-entry for the stale 30s. This
# debounce floor is the cooldown when anti-fraud is off.
_ULTRA_CARD_DEBOUNCE_SEC = 3.0

# How long a staff member's just-rescued TOTP code stays exempt from the
# re-entry block. Only needs to span the same code's re-scan window (the code
# rotates ~every 30s; a fresh code's first scan is never blocked anyway), so a
# couple of TOTP periods is plenty. The DEBOUNCE floor still applies to staff.
_ULTRA_STAFF_CODE_TTL_SEC = 120.0

# Minimum spacing between RTLog poll+process passes interleaved into a long
# device sync (the ``ultra_sync_yield_to_rtlog`` feature). The yield hook fires
# at every push chunk and every 128 hashed users; this throttle keeps it to at
# most ~1 poll/sec so a 1,800-user push neither hammers the single SDK
# connection nor re-reads settings on every chunk, while still observing scans
# (and letting PC-verified QR/TOTP members through) within ~a second.
_ULTRA_SYNC_RTLOG_YIELD_MIN_INTERVAL_SEC = 0.75

# The eventType the standalone driver stamps on a verify the TERMINAL refused.
# Produced by zk_standalone.normalize_att_event (`evtype = "0" if not invalid else
# "zkem_invalid"`), which is a [CODE] fact about which branch fired. It says
# NOTHING about why the terminal refused — IsInValid / AttState semantics on the
# MB2000 are [UNVERIFIED] (guide_for_agents_and_dev.md §7).
_ZKEM_INVALID_EVENT_TYPE = "zkem_invalid"

# ---- MIRROR pushing policy (per-device, ZK_STANDALONE) ----------------------
# The destructive reconcile that deletes device users NOT in the app roster.
# Guardrails (see _maybe_mirror_reconcile):
#  - only an explicit full reconcile reconciles -- the `full_reconcile` flag the
#    request carries, never a daytime or a spurious device-sync-flip full sync;
#  - abort if it would delete more than this fraction of the roster;
#  - pins >= the reserved floor are protected (manual/admin/staff enrollments);
#  - never delete a pin pushed within the grace window (a just-enrolled member the
#    stale roster hasn't caught up to yet).
#
# `full_reconcile` is a BOOLEAN carried with the request, not a string sniffed out
# of `reason`. This gate used to read
# `reason in ("user-sync", "daily-forced-sync", "hard-reset")`, but `reason` is a
# trigger_source token (SYNC_NOW_API / TIMER / CHANGE_DETECTOR / ...), so no
# producer could ever satisfy it and the reconcile was structurally dead -- see
# guide_for_agents_and_dev.md §3.2c. The distinction those literals were reaching
# for lives in `trigger_hint`, and `sync_observability.is_explicit_user_sync`
# already folds it into one predicate; the app layer evaluates that predicate once
# and the answer travels with the request.
# Single source since P3a-2: app/core/push_safety.py (one ceiling for every removal).
_MIRROR_MAX_DELETE_FRACTION = _push_safety.MAX_DELETE_FRACTION
_MIRROR_RESERVED_PIN_FLOOR = 90000
_MIRROR_ENROLL_GRACE_SEC = 600.0

# Revocation (_neutralise_revoked_pins) reuses the 25 % floor, but a percentage
# ALONE is wrong for it. MIRROR deletes device users wholesale, so a pure fraction
# suits it. Revocation is ordinary daily churn -- one member cancels -- and on a
# small roster a fraction blocks that outright: 1 departure against a 20-member gym
# is 5 %, but against a 3-member test rig it is 33 % and would abort forever.
# So a small ABSOLUTE number is always allowed, and the fraction only takes over
# once the roster is big enough for it to be the larger figure (>40 members).
# Together they still refuse the case that matters: a truncated roster presenting
# hundreds of members as departed.
_REVOKE_ABSOLUTE_FLOOR = _push_safety.REVOKE_ABSOLUTE_FLOOR

# Per-member ownership while an authoritative revoke crosses a full-sync
# attempt. RETRY is deliberately inert: it protects against ordinary-sync
# downgrade without waking the worker into a failure hot loop.
_FULL_REVOKE_ACTIVE = "active"
_FULL_REVOKE_RETRY = "retry"

# P3a-2 item 2: a FAILED removal (the terminal refused the delete and the neutralise
# fallback) is retried by the worker itself after 30 s, doubling, capped at 300 s --
# independent of the roster hash. Each retry is one full-sync pass: one roster build
# and state read (no device I/O for unchanged members) plus the failed removals only
# (SSR_DeleteEnrollData(..., 12) per pin, then the neutralise fallback), bounded by
# the removal ceiling. At the cap that is <= 12 passes an hour, and only while the
# worker is connected and a removal keeps failing.
_REMOVAL_RETRY_FIRST_SEC = 30.0
_REMOVAL_RETRY_MAX_SEC = 300.0
# A pending removal a pass could NOT attempt -- the roster was incomplete, or a safety
# guard held the removal step back (review round 2, R2-17/R2-20/R2-23) -- is parked: re-checked
# every 30 min, the streak unchanged. Dropping it stranded the member until an unrelated
# roster change; re-arming it at 300 s ran a useless full pass 288 times a day (R1-22). At
# 30 min that is <= 48 passes a day, only while such a removal is pending.
_REMOVAL_RETRY_PARKED_SEC = 1800.0
# A push-driver link that dies within this long of its reconnect is "flapping": the next
# reconnect waits 2, 4, 8 ... up to the connect backoff cap (R2-12). The first loss after a
# stable link reconnects at once -- that is the door path.
_LINK_STABLE_SEC = 60.0
# For this long after MonClub FINISHED an explicit revocation -- the full sync's removal
# step removed the pin, or the targeted revoke returned done (review R6-05: it deleted or
# neutralised the pin, re-pushed the person's other plans under ACCOUNT, or skipped a pin
# MonClub does not own) -- every pass checks the DATABASE before trusting the sync cache
# about that membership: its row gone there -> excluded from
# the pass, so a stale cache snapshot (a background load taken before the revocation
# committed) cannot push them back (review R4-11, R5-03). A restored membership is present
# again and is pushed normally. 10 min: the cache's TTL is 5 s and a whole load was
# measured at ~7 s on the live worker (the _member_row_in_db docstring). The check is ONE
# query per pass for every guarded member together -- a scan of sync_users, whose indexes
# cannot serve active_membership_id alone (review R6-07); see guide §3.4b for its cost.
_REMOVED_MEMBER_GUARD_SEC = 600.0

# P3a-2 item 5: finger-slot sweep of owned MB2000 pins never swept (guide §3.4c).
# One sweep STA command clears at most this many slots: 3 x 71-171 ms (field-measured
# per SSR_DelUserTmpExt, zkemkeeper_guide §3) = at most ~0.5 s during which the STA
# thread pumps no event and opens no door; the worker serves both between commands.
_SWEEP_SLOTS_PER_COMMAND = 3
# The daily batch sweeps at most this many pins per device per local day: <= 100 x 10
# calls x 171 ms ~= 171 s of terminal time a day, in <= 0.5 s slices, only while the
# worker is idle. A fully unswept 928-pin terminal is done in ~10 days; every targeted
# push sweeps its own pin at once regardless of this cap.
_FINGER_SWEEP_DAILY_CAP = 100
_ALL_FINGER_SLOTS = tuple(range(10))

# P3a-2 item 6: at most this many pins are PUSHED by one standalone full-sync pass
# (guide §3.4e). Removals are not counted: they run first and have their own ceiling.
# The rest stay pending -- no state row -- and the pass queues its own continuation, so
# the run loop runs between two passes. What that buys: a full sync that carries a
# removal (an expiry the scheduler found, the 30-300 s removal retry of §3.4b, an
# explicit revoke that fell back to a full sync) waits for at most one capped pass
# instead of a whole-roster push (419 s for 928 members, field v1.4.26). 50 x 0.45 s
# (that run's per-member rate) = 22.6 s, below the 30 s first removal retry. Doors and
# rescues do NOT depend on this number: they are served between chunks of 10. There
# is no opening-hours data in this app, so the cap applies at every hour.
_FULL_SYNC_MAX_PINS_PER_PASS = 50


def _revoke_skipped_not_owned(engine: Any) -> bool:
    """True when DeviceSyncEngine's last targeted revoke was SKIPPED_NOT_OWNED.

    That call returns False (nothing was removed, never a false success); this tells
    the caller the False is FINAL -- MonClub cannot prove it wrote the pin, so no
    retry could ever delete it -- rather than a failure to retry. An engine without
    the marker (or any other outcome) keeps the old fail-closed retry.
    """
    return getattr(engine, "_last_member_sync_outcome", None) == _push_safety.SKIPPED_NOT_OWNED


@dataclass(frozen=True)
class _StandalonePinRemovalResult:
    """Affirmatively confirmed outcomes from one standalone removal pass."""

    deleted: frozenset[str]
    neutralised: frozenset[str]
    failed: frozenset[str]

    @property
    def removed(self) -> frozenset[str]:
        return self.deleted | self.neutralised


def _encode_fingers(finger_ids: Any) -> str:
    """Serialise a finger-id set for device_sync_state.pushed_finger_ids.

    Always returns a string, never None: callers use None to mean "no opinion,
    leave the stored value alone", so an empty set MUST encode as '' (known-empty)
    to stay distinguishable from UNKNOWN.
    """
    return ",".join(str(int(f)) for f in sorted(set(finger_ids or ())))


def _standalone_wire_identity(entry: Dict[str, Any]) -> tuple[str, str]:
    """(name, card) exactly as ZKStandaloneDevice._do_push_roster writes them:
    the name cut at 24 characters, the card reduced to its digits. The write-ahead
    intent records these, and a read-back compares like with like."""
    return (
        str(entry.get("name") or "")[:24],
        "".join(ch for ch in str(entry.get("card") or "") if ch.isdigit()),
    )


def _local_day() -> str:
    """The PC's local calendar day (the daily maintenance slot's key)."""
    return time.strftime("%Y-%m-%d")


def _accepts_kwarg(fn: Any, name: str) -> bool:
    """True when ``fn`` takes keyword ``name`` (explicitly or through **kwargs).

    New driver hooks (on_chunk, between_chunks, sweep...) are passed only to a driver
    that can take them, so an older driver or a test double keeps working unchanged.
    """
    import inspect

    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    if name in params:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _standalone_pin_hash(entry: Dict[str, Any], templates: Any) -> str:
    """Change-detection hash of EXACTLY what push_roster hands the terminal for one pin.

    Deliberately NOT DeviceSyncEngine._compute_desired_hash: that one hashes the
    PullSDK payload (10-digit-clamped card, door bitmask, authorize timezone), none
    of which reaches a standalone terminal. Hashing fields the terminal never sees
    would (a) force a full re-push whenever a door preset changes and, worse, (b)
    let two different raw cards collapse onto one clamped value and hide a real
    change. So this mirrors the driver's own input transforms instead: the name is
    cut at 24 chars and the card reduced to its digits, exactly as _do_push_roster
    does before SSR_SetUserInfo / SetStrCardNumber. Templates are sorted so finger
    order cannot flip the hash.
    """
    name = str(entry.get("name") or "")[:24]
    card = "".join(ch for ch in str(entry.get("card") or "") if ch.isdigit())
    tpl_parts: list[str] = []
    for t in templates or []:
        if not isinstance(t, dict):
            continue
        try:
            fid = int(t.get("fingerId"))
        except (TypeError, ValueError):
            continue
        td = str(t.get("templateData") or "")
        if not td:
            continue
        try:
            tv = int(t.get("templateVersion") or 10)
        except (TypeError, ValueError):
            tv = 10
        try:
            ts = int(t.get("templateSize") or 0)
        except (TypeError, ValueError):
            ts = 0
        tpl_parts.append(f"{fid}:{tv}:{ts}:{td}")
    payload = (
        f"pin={str(entry.get('pin') or '')}\nname={name}\ncard={card}\n"
        f"templates={'|'.join(sorted(tpl_parts))}\n"
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# UltraDeviceWorker
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Process-wide "last good" local-state cache (creds, users_by_am, users_by_card).
#
# load_local_state() was measured at 78s on the gym PC (DB_READ_list_sync_users
# cold-reads 1798 rows). When a worker's own cache is empty (startup, recreation,
# or post-invalidation) the old code loaded it SYNCHRONOUSLY on the worker thread
# — freezing RTLog polling + door commands for the whole load (the user's "QR
# stuck ~3 min" symptom). Sharing the last successfully-loaded state across all
# workers means only the VERY FIRST load in the process ever blocks (at startup);
# every later cold cache adopts this shared snapshot instantly and refreshes in
# the background. The snapshot is treated as read-only (verify_totp only reads
# it), so sharing one object across workers is safe.
# ---------------------------------------------------------------------------
_SHARED_LOCAL_STATE_LOCK = threading.Lock()
_SHARED_LOCAL_STATE: Dict[str, Any] = {"value": None, "gen": -1}


def _get_shared_local_state():
    """Return (value, generation) of the process-wide last-good snapshot."""
    try:
        with _SHARED_LOCAL_STATE_LOCK:
            return _SHARED_LOCAL_STATE["value"], _SHARED_LOCAL_STATE["gen"]
    except Exception:
        return None, -1


def _snapshot_has_members(value) -> bool:
    return isinstance(value, (tuple, list)) and len(value) >= 2 and bool(value[1])


def _set_shared_local_state(value, gen) -> None:
    """Publish the process-wide member snapshot. MONOTONIC like the TOTP index: a
    refresh whose slow load finished after a newer one must not put an older list
    back (the QR roster check compares it with the index, guide §3.1b). A snapshot
    with NO members is not newer information -- load_local_state returns an empty
    list when its users read fails -- so an older complete one may replace a stored
    empty one, and an empty one never replaces a complete one at the same
    generation. An empty one at a HIGHER generation still goes through: a gym that
    really drops to zero members always comes with a generation bump. A clear
    (value=None) is always allowed."""
    try:
        g = int(gen)
        with _SHARED_LOCAL_STATE_LOCK:
            stored = _SHARED_LOCAL_STATE["value"]
            stored_gen = int(_SHARED_LOCAL_STATE["gen"])
            if value is not None and stored is not None and _snapshot_has_members(stored):
                if g < stored_gen:
                    return
                if g == stored_gen and not _snapshot_has_members(value):
                    return
            _SHARED_LOCAL_STATE["value"] = value
            _SHARED_LOCAL_STATE["gen"] = g
    except Exception:
        pass


# Process-wide precomputed TOTP index ({code -> hits}). Built off the hot path
# (bg refresh thread) and shared by both device workers since they verify against
# the same credentials. Tagged with the local-state generation it was built from
# so a worker only uses it when it matches the creds it is verifying against —
# that gen check is what prevents a stale index from allowing a removed member.
_SHARED_TOTP_INDEX_LOCK = threading.Lock()
_SHARED_TOTP_INDEX: Dict[str, Any] = {"value": None, "gen": -1}


def _get_shared_totp_index():
    """Return (index_struct, generation) of the process-wide TOTP index."""
    try:
        with _SHARED_TOTP_INDEX_LOCK:
            return _SHARED_TOTP_INDEX["value"], _SHARED_TOTP_INDEX["gen"]
    except Exception:
        return None, -1


def _set_shared_totp_index(value, gen) -> None:
    """Publish the process-wide TOTP index. MONOTONIC: never lower the stored
    generation — a lagging worker (older gen) must not overwrite a newer index
    published by the other worker (that would re-open the gen-thrash and could
    briefly expose an older, less-revoked index). Same-gen updates ARE allowed so
    the counter window can be refreshed as it rolls."""
    try:
        g = int(gen)
        with _SHARED_TOTP_INDEX_LOCK:
            # Always allow a clear (value=None) or the first publish; otherwise
            # only publish a real index whose gen is >= the stored one (monotonic).
            if (
                value is None
                or _SHARED_TOTP_INDEX["value"] is None
                or g >= int(_SHARED_TOTP_INDEX["gen"])
            ):
                _SHARED_TOTP_INDEX["value"] = value
                _SHARED_TOTP_INDEX["gen"] = g
    except Exception:
        pass


class UltraDeviceWorker(threading.Thread):
    """Per-device thread: polls RTLog, classifies events, TOTP rescue."""

    def __init__(
        self,
        device: Dict[str, Any],
        settings: Dict[str, Any],
        popup_q: "queue.Queue[NotificationRequest]",
        history_q: "queue.Queue[HistoryRecord]",
        stop_event: threading.Event,
        cfg: Any | None = None,
        on_full_sync_started: Any | None = None,
        on_full_sync_finished: Any | None = None,
    ):
        super().__init__(daemon=True, name=f"UltraWorker-{device.get('id')}")
        self._device = device
        self._settings = settings
        self._popup_q = popup_q
        self._history_q = history_q
        # Off-loop history writer: the per-event DB insert (INSERT OR IGNORE) used
        # to run synchronously on the live worker loop and, when a sync flooded the
        # DbWriter, stalled scans/door-opens/popups for seconds per event
        # (HIST_INSERT_SLOW) — the recurring ~30-min "freeze". The insert now runs
        # on a dedicated writer thread fed by this bounded queue; the worker only
        # enqueues (O(1)). Bounded so a stuck DbWriter can't grow it without limit.
        self._history_write_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=5000)
        self._history_writer_thread: Optional[threading.Thread] = None
        self._stop_evt = stop_event
        self._cfg = cfg
        self._on_full_sync_started = on_full_sync_started
        self._on_full_sync_finished = on_full_sync_finished
        self._device_id = int(device.get("id", 0))
        logger.debug(
            "[ULTRA:%s] __init__: name=%r ip=%s port=%s totp=%s rfid=%s "
            "cooldown=%.1fs poll_timeout=%.1fs",
            device.get("id"), device.get("name"),
            device.get("ipAddress", "?"), device.get("portNumber", "?"),
            settings.get("totp_enabled", True), settings.get("rfid_enabled", True),
            float(settings.get("replay_block_window_seconds", 10)),
            float(settings.get("rtlog_poll_timeout_sec", 15.0)),
        )
        self._device_name = str(device.get("name", ""))
        self._sdk: Optional[PullSDKDevice] = None
        self._seen: Deque[str] = deque(maxlen=10_000)
        self._connected = False
        self._events_processed = 0
        self._totp_rescues = 0
        self._totp_failures = 0
        self._door_cmd_failures = 0
        self._poll_ema_ms = 0.0
        # Throttle clock for the RTLog-yield-during-sync hook (see
        # _sync_yield_to_rtlog). monotonic seconds of the last yield poll.
        self._last_sync_rtlog_yield_mono = 0.0
        self._prefix = f"[ULTRA:{self._device_id}]"
        # Stable worker id used by telemetry heartbeat/state tracking.
        self._tel_wid = f"ULTRA:{self._device_id}"

        # Device timezone offset (seconds) for converting the device-local RTLog
        # eventTime into a UTC epoch comparable to time.time(). Parity with the
        # AGENT engine; defaults to 0 when the backend omits it (device shares
        # the PC's timezone, which is the common single-site case).
        try:
            self._device_tz_offset_sec: int = int(
                device.get("timezoneOffsetSeconds")
                or device.get("timezone_offset_seconds")
                or 0
            )
        except (TypeError, ValueError):
            self._device_tz_offset_sec = 0

        # Clock-skew / pipeline-latency telemetry (fix #2a): age of each RTLog
        # event at the moment we process it (pc_now - eventTime). A persistently
        # large value silently breaks TOTP validation, so we surface it.
        self._last_event_age_sec: float = 0.0
        self._max_event_age_sec: float = 0.0
        self._clock_skew_warns: int = 0
        self._last_skew_warn_mono: float = 0.0

        # Device-clock discipline (fix #2b) throttle + last measured device↔PC skew.
        # -inf (not 0.0): time.monotonic() has an arbitrary epoch, so a 0.0 seed
        # would throttle away the very first check on a freshly-booted PC (when
        # monotonic() is still < 3600). The startup clock-correction must run.
        self._last_clock_check_mono: float = float("-inf")
        self._device_pc_skew_sec: Optional[float] = None
        # Card/QR re-scan cooldown state. The effective cooldown is computed
        # PER EVENT from current settings (see _effective_card_cooldown_sec) so a
        # dashboard change (e.g. disabling anti-fraud) takes effect immediately
        # instead of being frozen at the value seen when the worker started.
        self._card_cooldown: Dict[str, float] = {}  # card_no -> monotonic timestamp
        # TOTP codes of staff members, exempt from the re-entry block (kept only
        # for the debounce floor). code -> monotonic expiry. Populated after a
        # staff TOTP rescue (see _handle_totp_rescue / _effective_card_cooldown_sec).
        self._staff_codes: Dict[str, float] = {}

        # Adaptive sleep settings (same as AGENT mode)
        self._busy_min = int(settings.get("busy_sleep_min_ms", 0))
        self._busy_max = int(settings.get("busy_sleep_max_ms", 50))
        self._empty_min = int(settings.get("empty_sleep_min_ms", 200))
        self._empty_max = int(settings.get("empty_sleep_max_ms", 500))
        self._backoff = float(settings.get("empty_backoff_factor", 1.35))
        # Idle RTLog poll cap. This is the WORST-CASE latency from "member scans the
        # QR" to "MonClub sees it": the scan sits in the controller's RTLog until the
        # next poll. The old 2000ms cap made an idle-period scan wait up to ~2s (the
        # gym owner measured 1.8-2.3s). 300ms keeps it sub-second; the held persistent
        # connection makes frequent GetRTLog cheap.
        self._backoff_cap = int(settings.get("empty_backoff_max_ms", 300))
        self._empty_sleep_ms = float(self._empty_min)
        # M-002: RTLog poll timeout configurable per-device (was hardcoded 15.0)
        self._poll_timeout_sec = float(settings.get("rtlog_poll_timeout_sec", 15.0))

        # Hot-window connect-per-cycle policy. After this many consecutive
        # empty polls we close the TCP socket and reopen on the next active
        # cycle. Matches the C2-400 / C3-200 firmware behaviour where idle
        # sockets are dropped silently and the next poll then has to eat the
        # reconnect cost while events queue on the device. Closing
        # proactively turns that into a deterministic cycle:
        #     connect -> drain commands -> poll -> process -> (maybe) disconnect
        # 0 disables holding entirely (pure connect-per-poll).
        self._hot_window_empty_polls = int(
            settings.get("ultra_hot_window_empty_polls", 20)
        )
        self._empty_polls_since_event = 0

        # Sync-pause handshake: set by UltraSyncScheduler before it connects to the device
        self._sync_pause = threading.Event()      # set = paused for sync
        self._sync_paused_ack = threading.Event() # set = worker confirmed disconnect

        # Command queue: door open requests executed inline between polls
        # (avoids TCP disconnect/reconnect needed by the old pause approach).
        self._cmd_queue: "queue.Queue" = queue.Queue(maxsize=10)
        # Separate queue for generic, operator-initiated SDK calls (read/write a
        # device parameter, sync the clock) from the DevicesPage control panel.
        # Kept distinct from _cmd_queue so the latency-critical door-open path is
        # untouched. Drained on the worker thread so these calls reuse the single
        # held SDK socket — NEVER opening a 2nd Connect (handle-leak/daily-lockup,
        # see project_pullsdk_connect_leak).
        self._sdk_cmd_queue: "queue.Queue" = queue.Queue(maxsize=8)
        self._wake_evt = threading.Event()
        self._member_sync_lock = threading.Lock()
        self._pending_member_syncs: Deque[int] = deque()
        self._pending_member_sync_ids: Set[int] = set()
        self._pending_member_revoke_ids: Set[int] = set()
        self._active_member_revoke_ids: Set[int] = set()
        # A targeted revoke may complete immediately before a co-requested full
        # sync drains. Retain that proof until the filtered full sync succeeds,
        # so the stale cache cannot re-enrol the member and a retry does not
        # mistake the now-absent ownership row for an unhandled revocation.
        self._confirmed_member_revoke_ids: Set[int] = set()
        self._full_sync_lock = threading.Lock()
        self._pending_full_sync_request: Dict[str, Any] | None = None
        self._full_sync_revocation_phase: Dict[int, str] = {}
        self._full_sync_exclusion_phase: Dict[int, str] = {}
        self._active_sync_lock = threading.Lock()
        self._active_sync_engine: Optional[Any] = None
        self._current_full_sync_reason = ""
        self._last_full_sync_started_at = ""
        self._last_full_sync_finished_at = ""
        self._last_full_sync_duration_ms = 0.0
        self._last_full_sync_error = ""
        self._full_sync_running = False

        # Local state cache (avoid per-event DB reads).
        # Reloads are gated by a generation counter (bumped only when a sync
        # actually changes members/credentials), so the TTL is just a slow safety
        # net — NOT a "re-read the 1798-row table every 60s" timer (that full read
        # measured 23-102s on the gym PC and was hammering the DB continuously).
        self._cached_state: Optional[tuple] = None
        self._cached_state_ts: float = 0.0
        self._cached_state_gen: int = -1
        self._CACHE_TTL_SEC: float = 300.0  # safety net only; real refresh is generation-driven
        self._connect_retry_base_sec = float(settings.get("connect_retry_base_sec", 2.0))
        self._connect_retry_max_sec = float(settings.get("connect_retry_max_sec", 120.0))
        self._connect_failures = 0
        self._next_connect_at_mono = 0.0
        self._last_connect_error = ""
        self._last_connect_attempt_at = ""
        self._last_connect_success_at = ""
        # Monotonic time of the current successful connection (0 = not connected).
        # Used by persistent-connection mode for the slow safety refresh.
        self._connected_since_mono = 0.0
        # Sustained-outage tracking: when set, the worker has been disconnected
        # since this monotonic timestamp. Used to (a) surface a "down for N min"
        # status to the UI and (b) suppress log spam — we keep one ERROR per
        # ~5 minutes plus DEBUG details, instead of one ERROR per retry.
        self._connect_down_since_mono: float = 0.0
        self._connect_down_since_iso: str = ""
        self._last_down_error_log_mono: float = 0.0
        self._down_error_log_interval_sec: float = 300.0

    def reset_fast_patch_caches(self) -> None:
        # A fast-patch changed member data the local cache reads. Advance the
        # generation so workers reload exactly once, and clear this worker's cache.
        # Nulling _cached_state is now safe (no longer a freeze): the cleared cache
        # takes the non-blocking "adopt the process-wide shared snapshot + refresh
        # in background" path, not the old synchronous 90s load.
        try:
            from app.core.db import bump_local_state_generation
            bump_local_state_generation()
        except Exception:
            pass
        self._cached_state = None
        self._cached_state_ts = 0.0

    def update_device(self, device: Dict[str, Any], settings: Dict[str, Any]) -> None:
        """Swap in a refreshed device dict and settings.

        Called when the dashboard updates the GymDevice (e.g. allowedMemberships,
        pushingToDevicePolicy, doorIds). The reference assignment is atomic in
        CPython, and downstream consumers re-read self._device on each request,
        so no lock is required. Refreshing in place avoids restarting the worker,
        which would tear down the RTLog observer and force a reconnect.
        """
        self._device = device
        self._settings = settings
        self._device_name = str(device.get("name", ""))
        # Hot-window tunable can change from the dashboard without restarting
        # the worker — read it back on every device refresh.
        try:
            self._hot_window_empty_polls = int(
                settings.get("ultra_hot_window_empty_polls", self._hot_window_empty_polls)
            )
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #

    def run(self):
        """Main loop: connect -> poll RTLog -> classify -> repeat."""
        logger.info(f"{self._prefix} started")
        self._pre_populate_seen()
        # Start the off-loop history writer so per-event DB inserts never block the
        # live loop (see _enqueue_history). Started before the poll loop so it is
        # already draining when the first event arrives.
        self._ensure_history_writer()

        # Pre-warm the local state cache eagerly so the first scan doesn't
        # block for 30+ seconds loading 1,275 users from SQLite.
        try:
            self._get_cached_local_state()
            logger.info(f"{self._prefix} local state cache pre-warmed")
            # Kick the bg refresh once at startup so member images start
            # downloading immediately (warms the popup-image cache before the
            # first scanners arrive — fixes black-on-first-scan).
            self._trigger_bg_cache_refresh()
        except Exception as e:
            logger.warning(f"{self._prefix} cache pre-warm failed: {e} (will retry on first event)")

        while not self._stop_evt.is_set():
            try:
                _iter_t0 = time.monotonic()
                # Yield the TCP connection to UltraSyncScheduler when requested
                if self._sync_pause.is_set():
                    if self._connected:
                        logger.info(
                            f"{self._prefix} sync pause requested — disconnecting for TCP handoff"
                        )
                        self._close_link_deciding_scans()   # none lost (R5-07, R6-01)
                    _tel.set_state(self._tel_wid, "sync_handoff_paused")
                    _tel.event("SYNC_HANDOFF_PAUSE_ACK", worker=self._tel_wid)
                    self._sync_paused_ack.set()
                    while self._sync_pause.is_set() and not self._stop_evt.is_set():
                        self._stop_evt.wait(0.5)
                    self._sync_paused_ack.clear()
                    logger.info(f"{self._prefix} sync pause ended — will reconnect")
                    _tel.event("SYNC_HANDOFF_RESUME", worker=self._tel_wid)
                    # Pre-warm cache after sync invalidated it (resume_from_sync sets _cached_state=None).
                    # Without this, the first event after resume blocks 5+ seconds loading from SQLite.
                    try:
                        self._get_cached_local_state()
                    except Exception:
                        pass
                    continue

                # Connect if needed
                if not self._connected:
                    wait_sec = self._connect_wait_remaining()
                    if wait_sec > 0:
                        _tel.set_state(self._tel_wid, "waiting", "connect backoff")
                        self._wait_for_work(min(wait_sec, 1.0))
                        continue
                    _tel.set_state(self._tel_wid, "reconnecting")
                    self._connect()
                    if not self._connected:
                        continue

                # A push driver that lost its link (review R1-21) is rebuilt here.
                if self._push_link_lost():
                    continue

                # Drain queued door-open commands (uses the already-connected SDK)
                _tel.set_state(self._tel_wid, "draining_cmds")
                self._drain_commands()

                # Poll RTLog with watchdog
                _tel.set_state(self._tel_wid, "polling")
                events = self._poll_with_watchdog()
                if events is None:
                    # Watchdog timeout or error -> reconnect
                    self._disconnect()
                    continue

                if events:
                    self._empty_sleep_ms = float(self._empty_min)
                    self._empty_polls_since_event = 0
                    _tel.set_state(self._tel_wid, "processing", f"{len(events)} evt")
                    for evt in events:
                        self._process_event(evt)
                    sleep_ms = self._busy_min
                else:
                    self._empty_polls_since_event += 1
                    self._empty_sleep_ms = min(
                        self._empty_sleep_ms * self._backoff,
                        self._backoff_cap,
                    )
                    sleep_ms = self._empty_sleep_ms

                # Drain commands again after processing events for minimal latency
                self._drain_commands()
                self._drain_member_sync_commands(limit=1)
                self._maybe_request_removal_retry()
                self._drain_full_sync_commands(limit=1)
                self._drain_daily_maintenance()
                self._drain_commands()
                # Operator SDK calls (control panel): read/write a param, sync clock.
                self._drain_sdk_commands()

                # Re-align the device RTC to the PC clock periodically. The call
                # self-throttles to once/hour and is a no-op below the drift
                # threshold; with the persistent connection the connect-path check
                # runs only once at startup, so this keeps a slowly-drifting
                # C3-200 clock corrected over a long run (prod RTCs were 38-74s
                # behind, which breaks scan-time TOTP and mass-DENYs valid codes).
                if self._connected:
                    self._maybe_discipline_device_clock()

                # Connection policy.
                #
                # The C3-200's plcommpro.dll leaks ~1 OS handle + ~280KB on
                # EVERY Connect/Disconnect cycle (measured in prod: the process
                # handle count tracks the connect count at ~1.0 per connect, and
                # private bytes climb ~175MB/h). The old hot-window closed the
                # socket after a streak of empty polls — ~680 reconnects/hour —
                # which exhausts the 32-bit address space in ~a day and produces
                # the "can't start new thread" full lockup.
                #
                # Persistent mode (default ON) holds the socket and only
                # reconnects (a) reactively when a poll actually fails — handled
                # above: `events is None` -> `_disconnect()` -> reconnect next
                # cycle — and (b) on a slow safety refresh, guarding against
                # firmware that might silently drop a long-idle socket. Prod logs
                # showed only ~4 real poll failures in 26h vs 13,465 proactive
                # disconnects, so holding is safe and removes ~99.7% of the leak.
                if bool(self._settings.get("ultra_persistent_connection", True)):
                    self._maybe_refresh_connection()
                    # else: HOLD the connection (no idle disconnect). This is the
                    # change that eliminates the reconnect-driven leak.
                elif (
                    self._hot_window_empty_polls > 0
                    and self._connected
                    and self._empty_polls_since_event >= self._hot_window_empty_polls
                ):
                    logger.debug(
                        "%s hot-window closed after %d empty polls — disconnecting",
                        self._prefix,
                        self._empty_polls_since_event,
                    )
                    self._disconnect()
                    self._empty_polls_since_event = 0
                elif self._hot_window_empty_polls <= 0:
                    # Pure connect-per-cycle: always close after each poll.
                    self._disconnect()
                    self._empty_polls_since_event = 0

                _iter_ms = (time.monotonic() - _iter_t0) * 1000
                if _iter_ms > 2000:
                    _tel.warn("LOOP_ITER_SLOW", worker=self._tel_wid, dur_ms=round(_iter_ms))

                _tel.set_state(self._tel_wid, "idle", f"sleep {sleep_ms:.0f}ms")
                self._wait_for_work(sleep_ms / 1000.0)

            except Exception as _loop_exc:
                logger.exception(f"{self._prefix} unhandled exception in run loop — will retry in 5s")
                _tel.snapshot_event(
                    "RUN_LOOP_EXCEPTION",
                    worker=self._tel_wid,
                    err=type(_loop_exc).__name__,
                )
                try:
                    self._disconnect()
                except Exception:
                    pass
                self._stop_evt.wait(5.0)

        self._disconnect()
        # Best-effort: persist any history rows still queued so a clean shutdown
        # does not lose the last few audit events (the writer thread has stopped).
        try:
            self._flush_history_writes()
        except Exception:
            pass
        logger.info(f"{self._prefix} stopped")

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #

    def _connect_wait_remaining(self, *, now: float | None = None) -> float:
        current = time.monotonic() if now is None else float(now)
        return max(0.0, float(self._next_connect_at_mono or 0.0) - current)

    def _wait_for_work(self, timeout_sec: float) -> None:
        deadline = time.monotonic() + max(0.0, float(timeout_sec or 0.0))
        while not self._stop_evt.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            if self._wake_evt.wait(timeout=min(remaining, 0.05)):
                self._wake_evt.clear()
                return

    def _record_connect_failure(self, error: str) -> float:
        self._connect_failures = min(int(self._connect_failures or 0) + 1, 32)
        delay = min(
            self._connect_retry_base_sec * (2 ** max(self._connect_failures - 1, 0)),
            self._connect_retry_max_sec,
        )
        now_mono = time.monotonic()
        self._next_connect_at_mono = now_mono + float(delay)
        self._last_connect_error = str(error or "connect failed")
        self._last_connect_attempt_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if self._connect_down_since_mono == 0.0:
            self._connect_down_since_mono = now_mono
            self._connect_down_since_iso = self._last_connect_attempt_at
        return float(delay)

    def _record_connect_success(self) -> None:
        self._connect_failures = 0
        self._next_connect_at_mono = 0.0
        self._last_connect_error = ""
        self._connect_down_since_mono = 0.0
        self._connect_down_since_iso = ""
        self._last_down_error_log_mono = 0.0
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._last_connect_attempt_at = now_iso
        self._last_connect_success_at = now_iso

    def _should_log_connect_error_now(self) -> bool:
        """During a sustained outage, throttle ERROR logs to once per interval.

        First 3 failures always log ERROR. After that we emit one ERROR every
        ``_down_error_log_interval_sec`` (default 5 min) so the log file does
        not get flooded with the same line every retry.
        """
        if self._connect_failures <= 3:
            return True
        now_mono = time.monotonic()
        if self._last_down_error_log_mono == 0.0:
            self._last_down_error_log_mono = now_mono
            return True
        if now_mono - self._last_down_error_log_mono >= self._down_error_log_interval_sec:
            self._last_down_error_log_mono = now_mono
            return True
        return False

    def _down_for_seconds(self) -> float:
        if self._connect_down_since_mono == 0.0:
            return 0.0
        return max(0.0, time.monotonic() - self._connect_down_since_mono)

    def defer_reconnect(self, delay_sec: float, *, reason: str = "deferred") -> bool:
        if self._connected:
            return False
        delay = max(0.0, float(delay_sec or 0.0))
        target = time.monotonic() + delay
        if target <= float(self._next_connect_at_mono or 0.0):
            return False
        self._next_connect_at_mono = target
        self._last_connect_error = f"deferred: {str(reason or 'deferred')}"
        return True

    @_tel.timed("CONN_CONNECT", slow_ms=0, warn_ms=3000)
    def _connect(self):
        """Connect to device via PullSDK."""
        ip = self._device.get("ipAddress") or self._device.get("ip_address", "")
        port = self._device.get("portNumber") or self._device.get("port_number") or self._device.get("devicePort") or 4370
        self._last_connect_attempt_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        attempt_level = logging.INFO if self._connect_failures <= 3 else logging.DEBUG
        logger.log(
            attempt_level,
            "%s connect attempt: name=%r ip=%s port=%s failures=%s",
            self._prefix,
            self._device_name,
            ip,
            port,
            self._connect_failures,
        )
        try:
            # Route through the driver factory (protocol-keyed). Defaults to ZK_PULLSDK
            # -> PullSDKDevice, so this is a pure indirection for the C3 gym today.
            self._sdk = get_driver(device_payload=self._device, logger=logger)
            ok = self._sdk.connect()
            if ok:
                was_down_for = self._down_for_seconds()
                self._connected = True
                self._connected_since_mono = time.monotonic()
                self._record_connect_success()
                # Check device vs PC clock (read-only log always; correct only
                # when opted in). Throttled internally; safe between polls.
                self._maybe_discipline_device_clock()
                if was_down_for >= 60.0:
                    logger.warning(
                        "%s connected OK after %.0fs downtime: name=%r ip=%s port=%s",
                        self._prefix, was_down_for, self._device_name, ip, port,
                    )
                else:
                    logger.info(
                        "%s connected OK: name=%r ip=%s port=%s",
                        self._prefix, self._device_name, ip, port,
                    )
            else:
                self._connected = False
                self._sdk = None
                delay = self._record_connect_failure("connect returned False")
                if self._should_log_connect_error_now():
                    logger.error(
                        "%s connect returned False: name=%r ip=%s port=%s "
                        "next_retry_in=%.1fs down_for=%.0fs failures=%s",
                        self._prefix, self._device_name, ip, port,
                        delay, self._down_for_seconds(), self._connect_failures,
                    )
                else:
                    logger.debug(
                        "%s connect returned False (suppressed): "
                        "next_retry_in=%.1fs down_for=%.0fs failures=%s",
                        self._prefix, delay, self._down_for_seconds(), self._connect_failures,
                    )
        except Exception as e:
            delay = self._record_connect_failure(str(e))
            if self._should_log_connect_error_now():
                logger.error(
                    "%s connect FAILED: name=%r ip=%s port=%s error=%s "
                    "next_retry_in=%.1fs down_for=%.0fs failures=%s",
                    self._prefix, self._device_name, ip, port, e,
                    delay, self._down_for_seconds(), self._connect_failures,
                )
            else:
                logger.debug(
                    "%s connect FAILED (suppressed): error=%s "
                    "next_retry_in=%.1fs down_for=%.0fs failures=%s",
                    self._prefix, e, delay, self._down_for_seconds(), self._connect_failures,
                )
            self._connected = False
            self._sdk = None

    def _push_link_lost(self) -> bool:
        """True -- and the worker disconnects, so the loop reconnects -- when a push driver
        (MB2000) reports its link down.

        The driver clears ``is_connected`` when it abandons a wedged STA thread (a COM
        call past its deadline: the daily read-back, a sweep command, a door open) or
        when its event pump dies. The worker's only other reconnect trigger is a poll
        returning None, and this driver's poll is a queue drain that never fails -- so the
        link stayed dead, with no event pumped and no door opened, until an unrelated push
        or the 30-min connection refresh (review R1-21). One attribute read per loop.
        """
        sdk = self._sdk
        if sdk is None or not self._connected or not getattr(sdk, "owns_event_source", False):
            return False
        try:
            up = bool(getattr(sdk, "is_connected", True))
        except Exception:
            up = True
        if up:
            return False
        # Scans the terminal handed over before the link died are already queued in the
        # driver: decide them before it is torn down, or they are lost -- no history row,
        # no popup (review R2-13). A rescue among them cannot open the door on this link,
        # exactly as before P3a-2; the member re-scans after the reconnect. (Carrying them
        # over the reconnect was tried in round 3 and withdrawn in round 4: aged from the
        # wrong clock it could open the door a minute late, and its age bound dropped
        # terminal-decided scans from the history -- R4-01/07/08/09.)
        self._decide_queued_events()
        now = time.monotonic()
        # Flapping = the link did not stay up _LINK_STABLE_SEC after the reconnect that
        # followed the PREVIOUS loss -- measured from that loss, not from the last connect,
        # so a routine CONN_REFRESH reconnect never inherits an old streak (review R3-01).
        prev_at = getattr(self, "_link_lost_at", None)
        prev_delay = float(getattr(self, "_link_lost_delay", 0.0) or 0.0)
        flapping = prev_at is not None and (now - float(prev_at)) < prev_delay + _LINK_STABLE_SEC
        streak = int(getattr(self, "_link_lost_streak", 0) or 0) + 1 if flapping else 1
        self._link_lost_streak = streak
        delay = 0.0 if streak <= 1 else min(
            float(self._connect_retry_max_sec),
            float(self._connect_retry_base_sec) * (2 ** min(streak - 2, 16)),
        )
        self._link_lost_at = now
        self._link_lost_delay = delay
        logger.warning("%s push driver reports its link down -- reconnecting in %.0fs",
                       self._prefix, delay)
        _tel.warn("WORKER_LINK_LOST", worker=self._tel_wid, streak=streak,
                  delay_s=round(delay) or None)
        # No second drain after this close (unlike _close_link_deciding_scans): a thread
        # abandoned inside a COM call is not joined, and a dead pump pumps no more, so the
        # old queue is empty here. A scan the abandoned thread pumps when its call finally
        # returns lands in that discarded queue (no history row, no popup), as before
        # P3a-2 (guide §3.4e, residual of R6-01).
        self._disconnect()
        # A link that dies right after every reconnect must not become a connect loop
        # (review R2-12): each flap doubles the wait, the first loss reconnects at once.
        self._next_connect_at_mono = now + delay
        if delay > 0.0 and not float(getattr(self, "_connect_down_since_mono", 0.0) or 0.0):
            # The outage clock, as a failed connect starts it: the desk's Open then answers
            # "device unreachable" at once instead of timing out (review R3-02).
            self._connect_down_since_mono = now
            self._connect_down_since_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return True

    def _decide_queued_events(self, sdk: Any = None) -> int:
        """Before tearing a push driver down, decide EVERY scan already in its queue
        (history, popup, a rescue if the link still works) -- the driver and its queue are
        discarded with it. Not only the first 64 (review R5-06); used by the link-loss,
        connection-refresh and sync-pause teardowns (R5-07). A queue drain, no COM call.
        ``sdk``: a driver already closed (default: the current one) -- see R6-01."""
        sdk = self._sdk if sdk is None else sdk
        if sdk is None or not getattr(sdk, "owns_event_source", False):
            return 0
        decided = 0
        for _ in range(64):                  # <= 64 x 64 = 4096, the driver queue's size
            try:
                batch = sdk.poll_rtlog_once() or []
            except Exception:
                break
            if not batch:
                break
            for evt in batch:
                try:
                    self._process_event(evt)
                except Exception:
                    logger.warning("%s queued event before teardown failed", self._prefix,
                                   exc_info=True)
                decided += 1
        return decided

    def _close_link_deciding_scans(self) -> None:
        """Close the connection without losing a scan: decide the push driver's queue
        while the link still works (a rescue can still open the door), close it, then
        decide what its STA thread queued on the way out. disconnect() only SETS the
        thread's stop flag and joins it, and the thread runs one more event pump before it
        looks at that flag: scans from that pump were discarded with the driver (review
        R6-01). Those get their history row and popup, but the connection is closed by
        then: a rescue among them cannot open the door and is recorded DOOR_CMD_FAILED,
        as on a link loss (the member re-scans after the reconnect). Deciding it later
        instead could open the door long after the scan (R4-01)."""
        old = self._sdk
        self._decide_queued_events()
        self._disconnect()
        if old is not None:
            self._decide_queued_events(sdk=old)

    def _maybe_refresh_connection(self) -> bool:
        """The persistent connection's slow safety refresh (see the run loop). True when
        the connection was closed. Queued scans are decided first (review R5-07)."""
        refresh_sec = float(self._settings.get("ultra_connection_refresh_sec", 1800.0))
        if not (
            refresh_sec > 0
            and self._connected
            and self._connected_since_mono > 0.0
            and (time.monotonic() - self._connected_since_mono) >= refresh_sec
        ):
            return False
        _age = time.monotonic() - self._connected_since_mono
        logger.info("%s persistent connection: safety refresh after %.0fs", self._prefix, _age)
        _tel.event("CONN_REFRESH", worker=self._tel_wid, age_s=round(_age))
        self._close_link_deciding_scans()
        self._empty_polls_since_event = 0
        return True

    @_tel.timed("CONN_DISCONNECT", slow_ms=200)
    def _disconnect(self):
        if self._connected or self._sdk:
            logger.debug(f"{self._prefix} disconnect: was_connected={self._connected}")
        if self._sdk:
            try:
                self._sdk.disconnect()
            except Exception as _disc_exc:
                logger.debug(f"{self._prefix} disconnect error (non-fatal): {_disc_exc}")
        self._sdk = None
        self._connected = False
        self._connected_since_mono = 0.0

    def pause_for_sync(self, timeout: float = 20.0) -> bool:
        """Ask worker to disconnect and wait until it confirms.

        Called by UltraSyncScheduler before it opens its own TCP connection.
        Returns True if the worker acknowledged the pause within *timeout* seconds.
        """
        self._sync_paused_ack.clear()
        self._sync_pause.set()
        acked = self._sync_paused_ack.wait(timeout=timeout)
        if not acked:
            logger.warning(
                f"{self._prefix} pause_for_sync: worker did not ack within {timeout}s "
                f"(it may still be mid-poll — sync will proceed anyway)"
            )
        return acked

    def resume_from_sync(self):
        """Allow worker to reconnect after sync engine has disconnected."""
        # Mark cache as stale (reset timestamp) but DON'T wipe the data.
        # The stale cache is still valid for immediate TOTP verification —
        # credentials/users rarely change within a single sync cycle.
        # This avoids a blocking 5-second load_local_state() on the first
        # event after resume, which delays the door-open command.
        # The cache will refresh lazily on next TTL expiry (background-safe).
        self._cached_state_ts = 0.0
        self._sync_pause.clear()

    # ------------------------------------------------------------------ #
    # Command queue: door open requests from API/tray, executed inline
    # ------------------------------------------------------------------ #

    def request_door_open(self, door_id: int, pulse_ms: int, timeout: float = 2.0) -> Dict[str, Any]:
        """Thread-safe: enqueue a door-open command, wait for result.

        Called from the HTTP handler thread.  The worker drains the queue
        between polls and executes via its already-connected SDK, avoiding
        the TCP disconnect/reconnect cycle that caused 5s latency.

        The command carries a monotonic deadline equal to ``timeout``. A command
        still queued when the caller gives up is never executed later: without it,
        an open queued during an outage or a sync hand-off pulsed the relay on the
        next reconnect, minutes after the desk was told "timed out".
        """
        # Drain stale pending commands before adding a new one.
        # When the device is offline, callers time out and return but their
        # commands linger in the queue.  Last-write-wins: the most recent
        # press is what matters; old stale entries should not pile up.
        while True:
            try:
                _, _, stale_ev, stale_box, _ = self._cmd_queue.get_nowait()
                stale_box["ok"] = False
                stale_box["error"] = "superseded"
                stale_ev.set()
            except queue.Empty:
                break

        result_event = threading.Event()
        result_box: Dict[str, Any] = {"ok": False, "error": "timeout"}
        deadline = time.monotonic() + float(timeout)
        try:
            self._cmd_queue.put_nowait((door_id, pulse_ms, result_event, result_box, deadline))
            self._wake_evt.set()
        except queue.Full:
            return {"ok": False, "error": "command queue full"}

        result_event.wait(timeout=timeout)
        # A copy: the worker may still be writing ok/error into the live box.
        result = dict(result_box)
        # The worker and this wait both run on the ~15.6 ms monotonic tick, so an
        # entry can be marked expired just before we read it. The caller's deadline
        # passed either way and nothing was sent: that is this call's "timeout".
        if result.get("error") == "expired (not executed)":
            result["error"] = "timeout"
        return result

    def request_run_sdk(
        self,
        fn: "Callable[[Any], Any]",
        *,
        label: str = "sdk_op",
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """Run ``fn(sdk)`` on the worker thread using the held SDK connection.

        For operator-initiated device reads/writes from the control panel
        (GetDeviceParam/SetDeviceParam/clock). Called from the HTTP handler
        thread; the worker drains _sdk_cmd_queue between polls and executes on
        its single connection — so the panel NEVER opens a second Connect.
        Returns {"ok", "result", "error"}. ``error`` carries the full SDK error
        string (e.g. PullSDKError with rc + PullLastError) for the UI popup.
        """
        result_event = threading.Event()
        result_box: Dict[str, Any] = {"ok": False, "result": None, "error": "timeout", "label": label}
        # Deadline so a command the caller has already abandoned (timed out) is
        # NOT executed when the worker drains it later — critical for WRITES: a
        # SetDeviceParam that lingered through a device outage must not silently
        # apply on reconnect. Reads are harmless, but the rule is uniform.
        deadline = time.monotonic() + float(timeout)
        try:
            self._sdk_cmd_queue.put_nowait((fn, label, result_event, result_box, deadline))
            self._wake_evt.set()
        except queue.Full:
            return {"ok": False, "result": None, "error": "device busy (command queue full)", "label": label}

        result_event.wait(timeout=timeout)
        return result_box

    def request_member_sync(self, member_id: int) -> bool:
        normalized_member_id = int(member_id)
        with self._member_sync_lock:
            with self._full_sync_lock:
                if (
                    normalized_member_id in self._pending_member_revoke_ids
                    or normalized_member_id in self._pending_member_sync_ids
                    or normalized_member_id in self._active_member_revoke_ids
                ):
                    return False
                pending_full_revokes = set(
                    (self._pending_full_sync_request or {}).get("revoked_ids") or set()
                )
                pending_full_exclusions = set(
                    (self._pending_full_sync_request or {}).get("excluded_ids") or set()
                )
                phased_full_revokes = set(
                    self._full_sync_revocation_phases_locked()
                )
                phased_full_exclusions = set(
                    self._full_sync_exclusion_phases_locked()
                )
                if normalized_member_id in (
                    pending_full_revokes
                    | pending_full_exclusions
                    | phased_full_revokes
                    | phased_full_exclusions
                ):
                    return False
                confirmed_revokes = getattr(self, "_confirmed_member_revoke_ids", set())
                if normalized_member_id in confirmed_revokes:
                    confirmed_revokes.discard(normalized_member_id)
                self._pending_member_sync_ids.add(normalized_member_id)
                self._pending_member_syncs.append(normalized_member_id)
            self._wake_evt.set()
        return True

    def request_member_revoke(self, member_id: int) -> bool:
        normalized_member_id = int(member_id)
        with self._member_sync_lock:
            with self._full_sync_lock:
                phases = self._full_sync_revocation_phases_locked()
                phase = phases.get(normalized_member_id)
                pending_full_revokes = set(
                    (self._pending_full_sync_request or {}).get("revoked_ids") or set()
                )
                pending_full_exclusions = set(
                    (self._pending_full_sync_request or {}).get("excluded_ids") or set()
                )
                exclusion_phase = self._full_sync_exclusion_phases_locked().get(
                    normalized_member_id
                )
                confirmed = normalized_member_id in getattr(
                    self, "_confirmed_member_revoke_ids", set()
                )
                if normalized_member_id in self._active_member_revoke_ids:
                    return True
                if phase == _FULL_REVOKE_ACTIVE:
                    return True
                if phase == _FULL_REVOKE_RETRY and confirmed:
                    return True
                if normalized_member_id in pending_full_revokes:
                    return True
                if phase == _FULL_REVOKE_RETRY:
                    phases.pop(normalized_member_id, None)
                elif normalized_member_id in pending_full_exclusions or exclusion_phase:
                    return True
                elif confirmed:
                    # Confirmation without a live exclusion/full owner is proof
                    # from an older generation, not pending revocation work.
                    getattr(self, "_confirmed_member_revoke_ids", set()).discard(
                        normalized_member_id
                    )
                self._pending_member_revoke_ids.add(normalized_member_id)
                if normalized_member_id not in self._pending_member_sync_ids:
                    self._pending_member_sync_ids.add(normalized_member_id)
                    self._pending_member_syncs.append(normalized_member_id)
                if self._pending_full_sync_request is not None:
                    pending_revoked_ids = self._pending_full_sync_request.setdefault(
                        "revoked_ids", set()
                    )
                    self._pending_full_sync_request.setdefault(
                        "excluded_ids", set(pending_revoked_ids)
                    ).add(normalized_member_id)
            self._wake_evt.set()
        return True

    def has_pending_member_sync(self, member_id: int) -> bool:
        with self._member_sync_lock:
            return int(member_id) in self._pending_member_sync_ids

    def has_pending_member_revoke(self, member_id: int) -> bool:
        with self._member_sync_lock:
            normalized_member_id = int(member_id)
            with self._full_sync_lock:
                full_sync_revokes = set(
                    (self._pending_full_sync_request or {}).get("revoked_ids") or set()
                ) | set(self._full_sync_revocation_phases_locked())
                full_sync_exclusions = set(
                    (self._pending_full_sync_request or {}).get("excluded_ids") or set()
                ) | set(self._full_sync_exclusion_phases_locked())
            return (
                normalized_member_id in self._pending_member_revoke_ids
                or normalized_member_id in self._active_member_revoke_ids
                or normalized_member_id in full_sync_revokes | full_sync_exclusions
            )

    def _mark_member_revoke_confirmed(self, member_id: int) -> None:
        with self._member_sync_lock:
            if not hasattr(self, "_confirmed_member_revoke_ids"):
                self._confirmed_member_revoke_ids = set()
            self._confirmed_member_revoke_ids.add(int(member_id))

    def _confirmed_member_revokes(self, member_ids: set[int]) -> set[int]:
        with self._member_sync_lock:
            return set(member_ids) & getattr(self, "_confirmed_member_revoke_ids", set())

    def _note_revoke_skipped(self, member_id: int) -> None:
        """Remember a SKIPPED_NOT_OWNED revocation for the pass's push-batch note.

        Report-only (P3a-2, item 9): the device-side telemetry was already emitted by
        whoever decided the skip. Bounded so a long-running worker cannot grow it.
        """
        skipped = getattr(self, "_skipped_revoke_ids", None)
        if skipped is None:
            skipped = []
            self._skipped_revoke_ids = skipped
        if int(member_id) not in skipped:
            skipped.append(int(member_id))
            del skipped[:-50]

    def _take_skipped_revokes(self) -> list[int]:
        skipped = list(getattr(self, "_skipped_revoke_ids", None) or [])
        self._skipped_revoke_ids = []
        return skipped

    def _finalize_targeted_member_revoke(self, member_id: int, *, ok: bool) -> None:
        """Release targeted ACTIVE ownership or atomically restore queue ownership."""
        normalized_member_id = int(member_id)
        with self._member_sync_lock:
            with self._full_sync_lock:
                self._active_member_revoke_ids.discard(normalized_member_id)
                if not ok:
                    self._pending_member_revoke_ids.add(normalized_member_id)
                    if normalized_member_id not in self._pending_member_sync_ids:
                        self._pending_member_sync_ids.add(normalized_member_id)
                        self._pending_member_syncs.append(normalized_member_id)
                    if self._pending_full_sync_request is not None:
                        pending_revoked_ids = self._pending_full_sync_request.setdefault(
                            "revoked_ids", set()
                        )
                        self._pending_full_sync_request.setdefault(
                            "excluded_ids", set(pending_revoked_ids)
                        ).add(normalized_member_id)
                    self._wake_evt.set()
                    return

                pending = self._pending_full_sync_request or {}
                dependency_ids = (
                    set(pending.get("revoked_ids") or set())
                    | set(pending.get("excluded_ids") or set())
                    | set(self._full_sync_revocation_phases_locked())
                    | set(self._full_sync_exclusion_phases_locked())
                )
                confirmed_ids = getattr(self, "_confirmed_member_revoke_ids", set())
                if normalized_member_id in dependency_ids:
                    confirmed_ids.add(normalized_member_id)
                else:
                    confirmed_ids.discard(normalized_member_id)

    def _full_sync_revocation_phases_locked(self) -> Dict[int, str]:
        """Return per-ID full-sync ownership while ``_full_sync_lock`` is held."""
        phases = getattr(self, "_full_sync_revocation_phase", None)
        if phases is None:
            phases = {}
            self._full_sync_revocation_phase = phases
        return phases

    def _full_sync_exclusion_phases_locked(self) -> Dict[int, str]:
        """Return per-ID roster exclusions while ``_full_sync_lock`` is held."""
        phases = getattr(self, "_full_sync_exclusion_phase", None)
        if phases is None:
            phases = {}
            self._full_sync_exclusion_phase = phases
        return phases

    def _finalize_full_sync_revokes(
        self,
        member_ids: set[int],
        *,
        ok: bool,
        excluded_ids: set[int] | None = None,
    ) -> None:
        """Finalize physical actions and stale-roster exclusions atomically."""
        normalized_ids = {int(member_id) for member_id in member_ids}
        normalized_excluded_ids = {
            int(member_id)
            for member_id in (
                normalized_ids if excluded_ids is None else excluded_ids
            )
        }
        with self._member_sync_lock:
            with self._full_sync_lock:
                phases = self._full_sync_revocation_phases_locked()
                exclusion_phases = self._full_sync_exclusion_phases_locked()
                for member_id in normalized_ids:
                    if phases.get(member_id) != _FULL_REVOKE_ACTIVE:
                        continue
                    if ok:
                        phases.pop(member_id, None)
                    else:
                        phases[member_id] = _FULL_REVOKE_RETRY
                for member_id in normalized_excluded_ids:
                    if exclusion_phases.get(member_id) != _FULL_REVOKE_ACTIVE:
                        continue
                    if ok:
                        exclusion_phases.pop(member_id, None)
                    else:
                        exclusion_phases[member_id] = _FULL_REVOKE_RETRY
                if ok:
                    pending = self._pending_full_sync_request or {}
                    protected_ids = (
                        set(pending.get("revoked_ids") or set())
                        | set(pending.get("excluded_ids") or set())
                        | set(phases)
                        | set(exclusion_phases)
                    )
                    clearable_ids = (
                        normalized_ids | normalized_excluded_ids
                    ) - protected_ids
                    getattr(self, "_confirmed_member_revoke_ids", set()).difference_update(
                        clearable_ids
                    )

    def request_full_sync(
        self,
        reason: str = "manual",
        fingerprint_hash: str | None = None,
        revoked_ids: set[int] | None = None,
        require_full_refresh: bool = False,
        full_reconcile: bool = False,
    ) -> bool:
        normalized_reason = str(reason or "manual").strip() or "manual"
        normalized_full_reconcile = bool(full_reconcile)
        normalized_revoked_ids = {
            int(member_id)
            for member_id in (revoked_ids or set())
            if member_id is not None
        }
        with self._member_sync_lock:
            confirmed_revoked_ids = set(
                getattr(self, "_confirmed_member_revoke_ids", set())
            )
            queued_targeted_revoked_ids = set(self._pending_member_revoke_ids)
            active_targeted_revoked_ids = set(self._active_member_revoke_ids)
            with self._full_sync_lock:
                phases = self._full_sync_revocation_phases_locked()
                exclusion_phases = self._full_sync_exclusion_phases_locked()
                active_revoked_ids = {
                    member_id
                    for member_id, phase in phases.items()
                    if phase == _FULL_REVOKE_ACTIVE
                }
                retry_revoked_ids = {
                    member_id
                    for member_id, phase in phases.items()
                    if phase == _FULL_REVOKE_RETRY
                }
                active_excluded_ids = {
                    member_id
                    for member_id, phase in exclusion_phases.items()
                    if phase == _FULL_REVOKE_ACTIVE
                }
                retry_excluded_ids = {
                    member_id
                    for member_id, phase in exclusion_phases.items()
                    if phase == _FULL_REVOKE_RETRY
                }
                pending = self._pending_full_sync_request
                pending_excluded_ids = set(
                    (pending or {}).get("excluded_ids") or set()
                )
                confirmed_exclusion_ids = confirmed_revoked_ids & (
                    pending_excluded_ids | set(exclusion_phases)
                )
                queued_revoked_ids = (
                    normalized_revoked_ids
                    | (retry_revoked_ids - confirmed_revoked_ids)
                    | queued_targeted_revoked_ids
                ) - (
                    active_revoked_ids
                    | active_targeted_revoked_ids
                    | confirmed_exclusion_ids
                )
                inherited_excluded_ids = (
                    normalized_revoked_ids
                    | queued_targeted_revoked_ids
                    | active_targeted_revoked_ids
                    | active_revoked_ids
                    | retry_revoked_ids
                    | active_excluded_ids
                    | retry_excluded_ids
                )
                if pending is not None:
                    pending_revoked_ids = pending.setdefault("revoked_ids", set())
                    pending_exclusions = pending.setdefault(
                        "excluded_ids", set(pending_revoked_ids)
                    )
                    pending_revoked_ids.update(queued_revoked_ids)
                    pending_exclusions.update(
                        inherited_excluded_ids | queued_revoked_ids
                    )
                    if require_full_refresh:
                        pending["require_full_refresh"] = True
                    # OR, never assignment: coalescing a later timer push into a
                    # queued explicit reconcile must not downgrade it.
                    if normalized_full_reconcile:
                        pending["full_reconcile"] = True
                    for member_id in retry_revoked_ids:
                        phases.pop(member_id, None)
                    for member_id in retry_excluded_ids:
                        exclusion_phases.pop(member_id, None)
                    if queued_revoked_ids:
                        pending["fingerprint_hash"] = (
                            str(fingerprint_hash or "").strip() or None
                        )
                    if queued_targeted_revoked_ids:
                        self._pending_member_syncs = deque(
                            member_id
                            for member_id in self._pending_member_syncs
                            if member_id not in queued_targeted_revoked_ids
                        )
                        self._pending_member_sync_ids.difference_update(
                            queued_targeted_revoked_ids
                        )
                        self._pending_member_revoke_ids.difference_update(
                            queued_targeted_revoked_ids
                        )
                    return True
                if (
                    normalized_revoked_ids
                    and not queued_revoked_ids
                    and not retry_revoked_ids
                    and not retry_excluded_ids
                    and not require_full_refresh
                    # An operator's explicit reconcile is never "already covered"
                    # by someone else's revocation ownership -- it must still run.
                    and not normalized_full_reconcile
                ):
                    return True
                for member_id in retry_revoked_ids:
                    phases.pop(member_id, None)
                for member_id in retry_excluded_ids:
                    exclusion_phases.pop(member_id, None)
                self._pending_full_sync_request = {
                    "reason": normalized_reason,
                    "fingerprint_hash": str(fingerprint_hash or "").strip() or None,
                    "revoked_ids": queued_revoked_ids,
                    "excluded_ids": inherited_excluded_ids | queued_revoked_ids,
                    "require_full_refresh": bool(require_full_refresh),
                    "full_reconcile": normalized_full_reconcile,
                }
                if queued_targeted_revoked_ids:
                    self._pending_member_syncs = deque(
                        member_id
                        for member_id in self._pending_member_syncs
                        if member_id not in queued_targeted_revoked_ids
                    )
                    self._pending_member_sync_ids.difference_update(
                        queued_targeted_revoked_ids
                    )
                    self._pending_member_revoke_ids.difference_update(
                        queued_targeted_revoked_ids
                    )
        return True

    def has_pending_full_sync(
        self,
        *,
        revoked_ids: set[int] | None = None,
        require_full_refresh: bool = False,
    ) -> bool:
        normalized_revoked_ids = set(revoked_ids or set())
        with self._full_sync_lock:
            phases = self._full_sync_revocation_phases_locked()
            exclusion_phases = self._full_sync_exclusion_phases_locked()
            if (
                self._pending_full_sync_request is None
                and not phases
                and not exclusion_phases
            ):
                return False
            if require_full_refresh and self._pending_full_sync_request is None:
                return False
            pending_revoked_ids = set(
                (self._pending_full_sync_request or {}).get("revoked_ids") or set()
            )
            pending_excluded_ids = set(
                (self._pending_full_sync_request or {}).get("excluded_ids") or set()
            )
            return normalized_revoked_ids <= (
                pending_revoked_ids
                | pending_excluded_ids
                | set(phases)
                | set(exclusion_phases)
            )

    @_tel.timed("DOOR_DRAIN", slow_ms=500)
    def _drain_commands(self):
        """Execute pending door-open commands using the current SDK connection.

        Also reached mid-push through ``_sync_yield_to_doors``. Only operator opens
        (``request_door_open``) are queued here; QR/TOTP and staff-RFID rescue opens
        call the SDK directly on this thread (``_open_door_with_retry``) and never
        pass through this queue.

        Returns ``(drained, expired)``: entries taken off the queue, and how many of
        them were skipped as expired (never sent to the device).
        """
        drained = expired = 0
        while not self._cmd_queue.empty():
            try:
                door_id, pulse_ms, result_event, result_box, deadline = self._cmd_queue.get_nowait()
            except queue.Empty:
                break
            drained += 1
            # The caller has already returned "timeout": skip, never open late.
            # Checked at dequeue, so an open taken just inside the deadline still runs
            # and can finish a few seconds after the caller gave up (the SDK call
            # itself has a 4 s timeout) -- that overlap is unchanged from before.
            if time.monotonic() > float(deadline):
                result_box.update({"ok": False, "error": "expired (not executed)"})
                logger.warning(
                    f"{self._prefix} CMD door_open EXPIRED (not executed): door={door_id} "
                    f"late_by_ms={round((time.monotonic() - float(deadline)) * 1000)}"
                )
                _tel.event("DOOR_CMD_EXPIRED", worker=self._tel_wid, door=door_id)
                result_event.set()
                expired += 1
                continue
            try:
                if self._sdk is None or not self._connected:
                    result_box.update({"ok": False, "error": "not connected"})
                else:
                    ok = self._sdk.open_door(door_id=door_id, pulse_time_ms=pulse_ms, timeout_ms=4000)
                    result_box.update({"ok": bool(ok), "error": "" if ok else "open_door returned False"})
                    logger.info(
                        f"{self._prefix} CMD door_open: door={door_id} pulse={pulse_ms}ms ok={ok}"
                    )
            except Exception as e:
                result_box.update({"ok": False, "error": str(e)})
                logger.warning(
                    f"{self._prefix} CMD door_open FAILED: door={door_id} err={e}"
                )
            finally:
                result_event.set()
        return drained, expired

    def _drain_sdk_commands(self):
        """Execute pending operator SDK calls on the held connection.

        Drained between polls, like _drain_commands. Each command is independent
        (no last-write-wins): a read and a write are distinct, so we run each and
        return its own result. Bounded by the single-event-per-call timeout on
        the caller side. Never opens a second connection.
        """
        while not self._sdk_cmd_queue.empty():
            try:
                fn, label, result_event, result_box, deadline = self._sdk_cmd_queue.get_nowait()
            except queue.Empty:
                break
            # Skip (do NOT execute) a command the caller already gave up on — a
            # late write must never land. The caller has already returned its
            # timeout box; setting the event here is harmless.
            if deadline is not None and time.monotonic() > float(deadline):
                result_box["ok"] = False
                result_box["error"] = "expired (not executed)"
                _tel.event("SDK_CMD", worker=self._tel_wid, op=label, ok=False, expired=True)
                result_event.set()
                continue
            _t0 = time.monotonic()
            try:
                if self._sdk is None or not self._connected:
                    result_box["ok"] = False
                    result_box["error"] = "device not connected"
                else:
                    result_box["result"] = fn(self._sdk)
                    result_box["ok"] = True
                    result_box["error"] = ""
            except Exception as e:
                result_box["ok"] = False
                # Full SDK error string (PullSDKError carries rc + PullLastError)
                # so the control panel can show it in the error popup.
                result_box["error"] = str(e)
            finally:
                _dur = round((time.monotonic() - _t0) * 1000)
                _tel.event(
                    "SDK_CMD", worker=self._tel_wid, op=label,
                    ok=result_box.get("ok"), dur_ms=_dur,
                )
                logger.info(
                    f"{self._prefix} SDK_CMD op={label} ok={result_box.get('ok')} dur_ms={_dur}"
                )
                result_event.set()

    def _sync_yield_to_doors(self) -> None:
        """Service queued door-open commands BETWEEN device-sync push chunks.

        A full/member sync runs inline on this worker over the single device
        connection (a Type-1 freeze: the door is starved for the whole push).
        DeviceSyncEngine calls this hook between SetDeviceData chunks — the
        connection is idle between chunks, so issuing a ControlDevice open here
        is safe and serialized on this thread — so a member scanning mid-sync is
        let in within ~one chunk instead of waiting for the entire push.
        Gated by ``ultra_sync_yield_to_doors`` (default ON) so it can be disabled
        from the backend if a device misbehaves with interleaved commands.
        """
        if not bool(self._settings.get("ultra_sync_yield_to_doors", True)):
            return
        try:
            pending = self._cmd_queue.qsize()
            if pending:
                drained, expired = self._drain_commands()
                # opened = entries sent to the device (as before, whatever it answered);
                # expired = entries past their caller's deadline, never sent (§3.1a).
                _tel.event("SYNC_DOOR_YIELD", worker=self._tel_wid,
                           opened=drained - expired, expired=expired)
        except Exception:
            pass

    def _sync_yield_to_rtlog(self) -> None:
        """Poll + process RTLog scans BETWEEN device-sync push chunks.

        A full/member sync runs INLINE on this worker over the single device
        connection, so for the entire push RTLog polling is otherwise starved
        (the primary Type-1 freeze: new scans aren't observed → the popup
        freezes, and PC-verified QR/TOTP members can't get in until the sync
        ends; only device-autonomous RFID still opens). ``_sync_yield_to_doors``
        already drains *queued* door commands between chunks but never polls
        RTLog, so member *scans* are still invisible during a sync.

        DeviceSyncEngine calls this hook between SetDeviceData chunks (and every
        128 hashed users): the connection is idle at those points and everything
        runs on this one thread, so a quick poll + _process_event here is
        serialized and safe — exactly the same safety model as the interleaved
        door opens. It lets a member scanning mid-sync be seen (and PC-verified
        ones let in) within ~one second instead of waiting for the whole push.

        Safety invariants:
          * Gated by the gym-level ``ultra_sync_yield_to_rtlog`` flag (dashboard
            /account → MonClub Access tab), DEFAULT OFF, read live (TTL-cached)
            so it can be enabled per-gym once validated on real hardware without
            a desktop redeploy or restart.
          * Throttled to ~1 poll/sec so a 1,800-user push doesn't hammer the SDK.
          * A failed poll here NEVER disconnects — tearing down the connection
            mid-push would corrupt the in-flight SetDeviceData. On poll
            error/timeout it just skips; the run loop reconnects after the sync.
          * _process_event dedups via _is_seen (check-and-set), so the run loop's
            post-sync poll won't re-process anything handled here.
        """
        try:
            now = time.monotonic()
            # Throttle FIRST (cheap) and advance the clock regardless of the
            # enabled state, so neither the SDK poll nor the settings read runs
            # more than ~once/sec during a long push. getattr-default so any
            # construction path (incl. tests) is safe before the first poll.
            last = getattr(self, "_last_sync_rtlog_yield_mono", 0.0)
            if (now - last) < _ULTRA_SYNC_RTLOG_YIELD_MIN_INTERVAL_SEC:
                return
            self._last_sync_rtlog_yield_mono = now

            # Gym-level toggle (sibling of manual_sync_mode). Read via the
            # TTL-cached backend-global-settings helper, not self._settings
            # (which is per-device). Default OFF.
            from app.core.settings_reader import get_backend_global_settings
            if not bool((get_backend_global_settings() or {}).get("ultra_sync_yield_to_rtlog", False)):
                return

            if self._sdk is None or not self._connected:
                return

            events = self._poll_with_watchdog()
            if not events:
                # None (poll timeout/error) or [] — do NOT disconnect mid-sync.
                return
            _tel.event("SYNC_RTLOG_YIELD", worker=self._tel_wid, events=len(events))
            for evt in events:
                self._process_event(evt)
        except Exception:
            # Best-effort: a yield poll must never abort the in-flight push.
            pass

    def _drain_member_sync_commands(self, limit: int = 1) -> int:
        if limit <= 0:
            return 0

        drained = 0
        while drained < limit:
            if (getattr(self._sdk, "owns_event_source", False)
                    and not bool(getattr(self._sdk, "is_connected", True))):
                # A push driver that reports its link dead: the update would be used up
                # on it; it waits for the run loop's reconnect (review R3-03, as R2-14).
                break
            with self._member_sync_lock:
                if not self._pending_member_syncs:
                    break
                member_id = int(self._pending_member_syncs.popleft())
                is_revocation = member_id in self._pending_member_revoke_ids
                if is_revocation:
                    self._active_member_revoke_ids.add(member_id)
                self._pending_member_sync_ids.discard(member_id)
                self._pending_member_revoke_ids.discard(member_id)

            try:
                if self._sdk is None or not self._connected:
                    if is_revocation:
                        self._finalize_targeted_member_revoke(member_id, ok=False)
                    else:
                        self.request_member_sync(member_id)
                    break
                # Push drivers: same livelock hazard as the full-sync drain — a
                # None raw handle would re-queue this member forever. Use the
                # driver's targeted roster push instead (always terminates).
                if getattr(self._sdk, "owns_event_source", False):
                    if is_revocation:
                        revoke_ok = self._run_standalone_member_revoke(member_id)
                        if revoke_ok:
                            # A capped continuation may still read a snapshot that
                            # predates this revocation (review R6-05).
                            self._arm_removed_member_guard([member_id])
                            self._finalize_targeted_member_revoke(member_id, ok=True)
                        else:
                            self._finalize_targeted_member_revoke(member_id, ok=False)
                            self.request_full_sync(
                                reason="revoke-failed",
                                revoked_ids={member_id},
                            )
                    else:
                        self._run_standalone_member_sync(member_id)
                    drained += 1
                    continue
                raw_sdk = getattr(self._sdk, "_sdk", None)
                if raw_sdk is None:
                    if is_revocation:
                        self._finalize_targeted_member_revoke(member_id, ok=False)
                    else:
                        self.request_member_sync(member_id)
                    break
                from app.core.device_sync import DeviceSyncEngine

                engine = DeviceSyncEngine(cfg=self._cfg or SimpleNamespace(), logger=logger)
                # Member sync runs INLINE on this worker thread over the single
                # device connection — it blocks RTLog polling + door commands
                # for its whole duration (a Type-1 freeze contributor). Track it.
                # Let it open doors queued mid-sync between push chunks, and
                # (when enabled) poll+process RTLog scans so the popup stays live.
                engine._door_yield_cb = self._sync_yield_to_doors
                engine._rtlog_yield_cb = self._sync_yield_to_rtlog
                _tel.set_state(self._tel_wid, "member_sync", f"member={member_id}")
                _ms_t0 = time.monotonic()
                try:
                    member_sync_ok = engine.sync_member_on_connected_sdk(
                        sdk=raw_sdk,
                        device=self._device,
                        member_id=member_id,
                        source="ultra_targeted_member_sync",
                        revocation=bool(is_revocation),
                    )
                    if is_revocation:
                        if member_sync_ok:
                            self._finalize_targeted_member_revoke(member_id, ok=True)
                        elif _revoke_skipped_not_owned(engine):
                            # FINAL (P3a-2): MonClub cannot prove it wrote that pin, so it
                            # will never delete it. Finished -- no re-queue, no full sync.
                            self._note_revoke_skipped(member_id)
                            self._finalize_targeted_member_revoke(member_id, ok=True)
                        else:
                            self._finalize_targeted_member_revoke(member_id, ok=False)
                            self.request_full_sync(
                                reason="revoke-failed",
                                revoked_ids={member_id},
                            )
                finally:
                    _tel.event(
                        "MEMBER_SYNC_DONE", worker=self._tel_wid, member_id=member_id,
                        dur_ms=round((time.monotonic() - _ms_t0) * 1000),
                        pending=len(self._pending_member_syncs),
                    )
            except Exception as exc:
                if is_revocation:
                    self._finalize_targeted_member_revoke(member_id, ok=False)
                    self.request_full_sync(
                        reason="revoke-handler-failed",
                        revoked_ids={member_id},
                    )
                logger.warning(
                    "%s targeted member sync failed: member_id=%s err=%s",
                    self._prefix,
                    member_id,
                    exc,
                )
                _tel.warn(
                    "MEMBER_SYNC_FAILED", worker=self._tel_wid,
                    member_id=member_id, err=type(exc).__name__,
                )
            drained += 1
        return drained

    # ------------------------------------------------------------------ #
    # ZK_STANDALONE (push-driver) sync path
    #
    # DeviceSyncEngine's push internals are PullSDK-table-specific (user/
    # userauthorize/templatev10 via SetDeviceData) and its entry point takes a
    # raw PullSDK handle. A standalone driver (MB2000/zkemkeeper) has neither —
    # extracting `_sdk` yields None and the old code would re-queue the request
    # forever (a livelock: _mark_full_sync_finished never fires, manual-sync
    # pending counters never ack). These helpers give push drivers their own
    # roster path that reuses the protocol-NEUTRAL parts of DeviceSyncEngine
    # (user filtering + template collection) and always terminates the request.
    # ------------------------------------------------------------------ #

    def _build_standalone_roster(
        self, cache: Any, *, only_member_ids: set[int] | None = None
    ) -> tuple[list[Dict[str, Any]], Dict[str, list[Dict[str, Any]]], Dict[str, str]]:
        """(users, templates_by_pin, hashes_by_pin) for driver.push_roster().

        hashes_by_pin is the per-pin change-detection hash (_standalone_pin_hash) of
        the exact entry + templates handed to the driver, used by the incremental
        full sync and recorded in device_sync_state after each push.

        Reuses DeviceSyncEngine._filter_users_for_device (allowedMemberships /
        VALID_ONLY policy / pin derivation under the device's pinScheme, guide §3.2b) and
        _collect_templates_for_pin (cache fingerprints -> local SQLite fallback)
        so a standalone device sees exactly the roster a PullSDK panel would.
        Cards are passed RAW (digits handled by the driver): the 4-byte CardNo
        clamp is a PullSDK/C3 constraint, and the MB2000 card space is verified
        on-site (plan GATE 6) before any capability-based clamping is added.
        """
        from app.core.device_sync import DeviceSyncEngine

        engine = DeviceSyncEngine(cfg=self._cfg or SimpleNamespace(), logger=logger)
        device = dict(self._device or {})
        users_all = list(getattr(cache, "users", []) or [])
        roster_stats: Dict[str, Any] = {}
        by_pin = engine._filter_users_for_device(
            users=users_all, device=device, default_door_id=1, stats_out=roster_stats,
        )
        # Read by _run_standalone_full_sync to refuse removals on an incomplete roster.
        self._last_standalone_roster_stats = roster_stats
        # ... and to name the PERSON (userId) of every desired pin: renewal ordering (P3b-1).
        self._last_standalone_pin_persons = {p: u.get("userId") for p, u in by_pin.items()}
        if only_member_ids is not None:
            # only_member_ids are MEMBERSHIP ids. MEMBERSHIP: str(int(m)), as before.
            # ACCOUNT: the person pins those memberships belong to.
            from app.core.device_sync import device_pins_for_members

            wanted = set(device_pins_for_members(
                only_member_ids, scheme=roster_stats.get("pin_scheme") or "", users=users_all,
            ).values())
            by_pin = {p: u for p, u in by_pin.items() if p in wanted}

        fp_enabled = bool(self._settings.get("fingerprint_enabled", False))
        local_fp_index = engine._build_local_fp_index_for_pins(
            pins=set(by_pin.keys()), fingerprint_enabled=fp_enabled,
        )

        users_out: list[Dict[str, Any]] = []
        templates_by_pin: Dict[str, list[Dict[str, Any]]] = {}
        hashes_by_pin: Dict[str, str] = {}
        for pin, u in by_pin.items():
            entry = {
                "pin": pin,
                "name": str(u.get("fullName") or ""),
                "card": str(u.get("firstCardId") or ""),
            }
            users_out.append(entry)
            tpls = engine._collect_templates_for_pin(
                user=u, pin=pin, local_fp_index=local_fp_index,
                fingerprint_enabled=fp_enabled,
            )
            if tpls:
                templates_by_pin[pin] = tpls
            hashes_by_pin[pin] = _standalone_pin_hash(entry, tpls)
        return users_out, templates_by_pin, hashes_by_pin

    # ------------------------------------------------------------------ #
    # Incremental standalone sync: per-pin state in device_sync_state
    #
    # WHY: push_roster has no diff of its own -- every full sync re-sent the whole
    # roster (928 members, 419s on the OXYGENE_FIT MB2000, v1.4.26). And a
    # targeted member sync never updated the scheduler's roster-hash baseline
    # (_last_hash is set only when a FULL sync finishes), so the very next hash
    # evaluation after an enrolment concluded "roster changed" and queued that
    # 7-minute full push for a single new fingerprint (field report, v1.4.28).
    #
    # The PullSDK path already solves this with device_sync_state (one
    # desired_hash per (device, pin), skip when unchanged). This reuses the same
    # table so a standalone terminal gets the same behaviour: after the first
    # complete push, a full sync only sends pins that are new, changed, or failed
    # last time. A member sync records its pin as synced, so the enrolment
    # cascade becomes a no-op reconcile that finishes in seconds.
    #
    # SAFETY DIRECTION: any failure to READ state means "push everything" (never
    # skip a pin because a lookup broke); any failure to WRITE state is logged
    # and ignored (the worst case is an unnecessary re-push next time).
    # ------------------------------------------------------------------ #
    def _standalone_pins_needing_push(
        self, users: list[Dict[str, Any]], hashes_by_pin: Dict[str, str]
    ) -> tuple[list[Dict[str, Any]], int]:
        """Return (pins to push, number skipped as unchanged)."""
        # Why each returned pin needs a push -- "new" (no row), "failed" (row, last push
        # not confirmed) or "changed" (confirmed, content differs). Read by the per-pass
        # cap to choose what goes first (P3a-2 item 6).
        kinds: Dict[str, str] = {}
        self._last_push_kinds = kinds
        try:
            from app.core.db import list_device_sync_hashes_and_status
            state = list_device_sync_hashes_and_status(device_id=self._device_id) or {}
        except Exception:
            logger.warning(
                "%s per-pin sync state unreadable -- pushing the FULL roster (safe default)",
                self._prefix, exc_info=True,
            )
            return list(users), 0
        # Bounded retry, mirroring the PullSDK gate in
        # DeviceSyncEngine._sync_one_device. Without it, marking a refused
        # template FAILED re-pushes that pin on EVERY cycle forever -- and these
        # MB2000 terminals are the slowest in the fleet (a documented 419 s for
        # 928 members), so the unbounded storm is worse here than on PullSDK.
        #
        # Fetched SEPARATELY from list_device_sync_hashes_and_status above, and
        # fail-open, for two reasons: that function is monkeypatched by several
        # standalone tests (widening or replacing it would break them), and an
        # unreadable retry state must never STOP a push -- only ever allow one.
        retry_state: Dict[str, tuple] = {}
        try:
            from app.core.db import list_device_sync_retry_state
            retry_state = list_device_sync_retry_state(device_id=self._device_id) or {}
        except Exception:
            retry_state = {}

        to_push: list[Dict[str, Any]] = []
        backoff_skipped = 0
        self._last_backoff_pins: set[str] = set()
        for u in users:
            pin = str(u.get("pin") or "").strip()
            prev_hash, prev_ok = state.get(pin, ("", False))
            if prev_ok and prev_hash and prev_hash == hashes_by_pin.get(pin):
                continue
            rs = retry_state.get(pin)
            if rs is not None:
                try:
                    _h, _ok, _streak, _attempt_hash, _seen = rs
                    # Same content, already refused repeatedly, not yet due.
                    # A re-enrolment changes the hash, so it is never delayed.
                    if (not _ok and _attempt_hash
                            and _attempt_hash == hashes_by_pin.get(pin)):
                        from app.core.device_sync import DeviceSyncEngine
                        if not DeviceSyncEngine._retry_due(fail_streak=_streak,
                                                           updated_at=_seen):
                            backoff_skipped += 1
                            self._last_backoff_pins.add(pin)
                            continue
                except Exception:
                    pass  # fail open: push it
            kinds[pin] = "new" if pin not in state else ("changed" if prev_ok else "failed")
            to_push.append(u)
        if backoff_skipped:
            # Never invisible: a pin in backoff must not look like a pin in sync.
            logger.info(
                "%s %d pin(s) held back by retry backoff: unchanged content that has "
                "already been refused repeatedly. A re-enrolment changes the hash and "
                "pushes immediately; a full or forced resync ignores this entirely.",
                self._prefix, backoff_skipped,
            )
            try:
                _tel.event("SYNC_RETRY_BACKOFF", device_id=self._device_id,
                           pins=backoff_skipped)
            except Exception:
                pass
        return to_push, len(users) - len(to_push)

    # ---------------------------------------------------------------- #
    # Finger-slot removal: which slots this device holds for each pin
    # ---------------------------------------------------------------- #
    @staticmethod
    def _desired_fingers(templates: Any) -> set[int]:
        """Finger ids push_roster will actually WRITE for one pin.

        Mirrors the driver's own skip of empty templateData, so a template row
        that will never be written cannot make us believe a slot is occupied.
        """
        out: set[int] = set()
        for t in templates or []:
            if not isinstance(t, dict):
                continue
            if not str(t.get("templateData") or ""):
                continue
            try:
                out.add(int(t.get("fingerId")))
            except (TypeError, ValueError):
                continue
        return out

    def _load_pushed_fingers(self, pins=None) -> Dict[str, Any]:
        """{pin: set[int] | None} — None is UNKNOWN, never empty. See db.py.

        ``pins``: only those rows (primary-key reads) -- a targeted push, often served
        between two push chunks, must not read the whole device table (review R4-05)."""
        try:
            from app.core.db import list_device_pushed_fingers
            if pins is not None:
                return dict(list_device_pushed_fingers(
                    device_id=self._device_id,
                    pins=[str(p).strip() for p in pins if str(p or "").strip()]) or {})
            return dict(list_device_pushed_fingers(device_id=self._device_id) or {})
        except Exception:
            # Fail SAFE, not fail-open: with no state we cannot name a vacated
            # slot, so we clear nothing. Never guess a removal set.
            logger.warning(
                "%s pushed-finger state unreadable -- no slot removals this cycle",
                self._prefix, exc_info=True,
            )
            return {}

    def _standalone_removals(
        self, *, to_push: list[Dict[str, Any]],
        templates_by_pin: Dict[str, list], pushed_fingers: Dict[str, Any],
    ) -> Dict[str, list[int]]:
        """Slots that were pushed before and are no longer desired.

        UNKNOWN (None) yields NO removals. It must not be read as the empty set
        (that keeps the original bug) and must not trigger a blanket 0..9 sweep
        (~9000 extra COM calls on a full roster would blow the 600 s bracketed
        deadline while EnableDevice(False) is held -- turnstile dead).
        """
        out: Dict[str, list[int]] = {}
        for u in to_push:
            pin = str(u.get("pin") or "").strip()
            if not pin:
                continue
            prev = pushed_fingers.get(pin)
            if prev is None:
                continue
            gone = sorted(set(prev) - self._desired_fingers((templates_by_pin or {}).get(pin)))
            if gone:
                out[pin] = gone
        return out

    def _backfill_pushed_fingers(
        self, *, skipped_pins: list[str], templates_by_pin: Dict[str, list],
        hashes_by_pin: Dict[str, str], pushed_fingers: Dict[str, Any],
    ) -> None:
        """Record finger ids for pins we did NOT push because they are unchanged.

        Safe without touching the device: being skipped means last_ok=1 AND the
        stored desired_hash equals the freshly computed one, which is the system's
        own assertion that the terminal already holds exactly this state.

        This is what gives the installed base a baseline. A pin is only pushed when
        it changes, so without the backfill every pre-upgrade member would still be
        UNKNOWN at the moment their first fingerprint is revoked -- i.e. the bug
        would persist for exactly the members who already have fingerprints.
        """
        rows: list[tuple] = []
        for pin in skipped_pins:
            if pushed_fingers.get(pin) is not None:
                continue  # already known; never overwrite
            fingers = self._desired_fingers((templates_by_pin or {}).get(pin))
            rows.append((pin, hashes_by_pin.get(pin, ""), True, None,
                         _encode_fingers(fingers)))
        if not rows:
            return
        try:
            from app.core.db import save_device_sync_state_batch
            save_device_sync_state_batch(device_id=self._device_id, rows=rows)
            logger.info("%s recorded finger slots for %d unchanged pin(s) (no device I/O)",
                        self._prefix, len(rows))
        except Exception:
            logger.debug("%s pushed-finger backfill skipped", self._prefix, exc_info=True)

    def _record_standalone_pin_state(
        self, *, users: list[Dict[str, Any]], hashes_by_pin: Dict[str, str],
        result: Dict[str, Any],
        templates_by_pin: Dict[str, list] | None = None,
        unknown_fingers_pins: set[str] | None = None,
    ) -> None:
        """Persist per-pin outcome of one push_roster call.

        Uses the driver's ``failed_pins`` when present. A driver that predates it
        (or reports ok=False with an empty list) yields only the aggregate, and the
        only safe reading of "something failed, unknown what" is: every attempted
        pin is unconfirmed -- record all of them ok=False so they are retried.
        """
        if not users:
            return
        result = result or {}
        failed_set = self._standalone_failed_pins_from_result(users=users, result=result)
        err: str | None = None
        if failed_set:
            errs = result.get("errors") or []
            err = str(errs[0]) if errs else str(result.get("error") or "push_roster failed")
        # Pins whose user row the terminal accepted (SSR_SetUserInfo -> True). They are
        # MonClub's even if a finger then failed: the member can badge in, so a departure
        # must be able to remove them (review R1-14/R1-26). A wedged chunk names none.
        written = result.get("user_written") if isinstance(result, dict) else None
        written_set = {str(p).strip() for p in written} if isinstance(written, list) else set()
        rows: list[tuple] = []
        for u in users:
            pin = str(u.get("pin") or "").strip()
            if not pin:
                continue
            ok = pin not in failed_set
            # On success the terminal now holds exactly the desired finger set --
            # including the EMPTY set, which is what makes a later re-enrol/revoke
            # cycle computable instead of falling back to UNKNOWN. On failure we
            # pass None ("no opinion"); the SQL guard keeps the previous value.
            fingers = (
                _encode_fingers(self._desired_fingers((templates_by_pin or {}).get(pin)))
                if (ok and templates_by_pin is not None) else None
            )
            if unknown_fingers_pins and pin in unknown_fingers_pins:
                # P3a-2: its slots have not been swept yet, so what else the terminal
                # holds at this pin is still UNKNOWN; recorded only after the sweep.
                fingers = None
            rows.append((pin, hashes_by_pin.get(pin, ""), ok, None if ok else err, fingers,
                         pin in written_set))
        try:
            from app.core.db import save_device_sync_state_batch
            save_device_sync_state_batch(device_id=self._device_id, rows=rows)
        except Exception:
            logger.debug("%s per-pin sync state not recorded", self._prefix, exc_info=True)

    @staticmethod
    def _standalone_failed_pins_from_result(
        *, users: list[Dict[str, Any]], result: Dict[str, Any],
    ) -> set[str]:
        """Return unconfirmed attempted pins, failing closed on ambiguous results."""
        attempted = {
            str(user.get("pin") or "").strip()
            for user in users or []
            if str(user.get("pin") or "").strip()
        }
        if not attempted or not isinstance(result, dict):
            return set(attempted)

        ok = result.get("ok")
        if type(ok) is not bool:
            return set(attempted)
        if ok:
            for field in ("failed", "templates_failed", "chunks_wedged"):
                if field not in result:
                    continue
                value = result[field]
                if type(value) is not int or value != 0:
                    return set(attempted)
        reported = result.get("failed_pins")
        if reported is None:
            if ok is True:
                failed_count = result.get("failed", 0)
                templates_failed = result.get("templates_failed", 0)
                if (
                    type(failed_count) is int
                    and failed_count == 0
                    and type(templates_failed) is int
                    and templates_failed == 0
                ):
                    return set()
            return set(attempted)
        if not isinstance(reported, list):
            return set(attempted)

        normalized = [
            str(pin if pin is not None else "").strip()
            for pin in reported
        ]
        failed = set(normalized)
        if (
            any(not pin for pin in normalized)
            or not failed <= attempted
            or (ok and failed)
            or (not ok and not failed)
        ):
            return set(attempted)
        # Every pin this result would CONFIRM must be one the driver says it wrote
        # (or skipped as an invalid pin). A driver that stopped early without naming
        # the chunks it never sent -- push_roster before P3a-2 did exactly that on
        # its three `break` exits -- reports fewer pushed than it confirms, and those
        # extra pins were recorded owned without ever reaching the terminal. Only an
        # int `pushed` can prove the gap; absent it the contract above is unchanged.
        pushed = result.get("pushed")
        skipped = result.get("skipped_pin", 0)
        if type(pushed) is int and pushed >= 0:
            skipped_n = skipped if type(skipped) is int and skipped >= 0 else 0
            if len(attempted - failed) > pushed + skipped_n:
                return set(attempted)
        return failed

    # ---------------------------------------------------------------- #
    # Capacity admission (P3a-2 item 7, guide §3.4d)
    # ---------------------------------------------------------------- #
    def _capacity_admit(
        self,
        users: list[Dict[str, Any]],
        templates_by_pin: Dict[str, list] | None,
        recorded_fingers: Dict[str, Any] | None,
    ) -> tuple[list[Dict[str, Any]], list[str], Dict[str, set[int]]]:
        """Refuse only the writes the terminal has no slot for: (admitted, skipped, withheld).

        ``skipped``: pins refused whole -- only a member certainly NOT on the terminal
        (no state row and no push intent: a row or an intent means it may already be
        there, and an update needs no new user slot) when no user slot is free.
        ``withheld``: {pin: finger ids} not written this pass because no fingerprint
        slot is free. The member itself IS pushed: user row, card, finger replacements
        and the clear of its vacated slots all land (review round 1, R1-10/11/17: the
        first version refused the whole member, so a new member got no card, and a
        deleted finger was never cleared). A replacement (a recorded finger rewritten)
        needs no new slot; an owned pin with an unknown recorded set counts none (most
        likely replacements; the terminal's own refusal is still reported). A pin's
        vacated slots are cleared before its templates are written, so they count as
        free from that pin on. The caller must record a pin with withheld fingers as
        NOT in sync. The status is re-read now (read_capacity); an unreadable value
        gates nothing. Capability-gated: PullSDK is never gated.
        """
        none: Dict[str, set[int]] = {}
        if not users or not getattr(self._sdk, "supports_capacity_check", False):
            return list(users or []), [], none
        reader = getattr(self._sdk, "read_capacity", None)
        if not callable(reader):
            return list(users), [], none
        try:
            if len(users) <= 10:
                # A targeted push (often served between two push chunks): primary-key point
                # reads, not three whole-device tables (review R3-24).
                from app.core.db import (
                    get_device_sync_ownership_for_pin,
                    get_pin_sync_status,
                    get_push_intent,
                )
                owned, known = set(), set()
                for u in users:
                    p = str(u.get("pin") or "").strip()
                    if not p:
                        continue
                    if get_device_sync_ownership_for_pin(device_id=self._device_id, pin=p):
                        owned.add(p)
                    if (get_pin_sync_status(device_id=self._device_id, pin=p) is not None
                            or get_push_intent(device_id=self._device_id, pin=p) is not None):
                        known.add(p)
            else:
                from app.core.db import (
                    list_confirmed_device_sync_pins,
                    list_device_sync_hashes_and_status,
                    list_push_intents,
                )
                owned = {str(p).strip() for p in (list_confirmed_device_sync_pins(device_id=self._device_id) or ())}
                known = {str(p).strip() for p in (list_device_sync_hashes_and_status(device_id=self._device_id) or {})}
                known |= {str(p).strip() for p in (list_push_intents(device_id=self._device_id) or {})}
        except Exception:
            return list(users), [], none
        recorded = recorded_fingers or {}
        needs: list[tuple[Dict[str, Any], str, bool, list[int], int]] = []
        any_need = False
        for u in users:
            pin = str(u.get("pin") or "").strip()
            desired = self._desired_fingers((templates_by_pin or {}).get(pin))
            rec = recorded.get(pin)
            new_user = pin not in owned and pin not in known
            if rec is not None:
                new_fingers = sorted(desired - set(rec))
                vacated = len(set(rec) - desired)
            elif pin in owned:
                new_fingers, vacated = [], 0
            else:
                new_fingers, vacated = sorted(desired), 0
            needs.append((u, pin, new_user, new_fingers, vacated))
            any_need = any_need or new_user or bool(new_fingers)
        if not any_need:
            return list(users), [], none
        cap = reader() or {}
        if not (isinstance(cap, dict) and cap.get("ok") is True):
            return list(users), [], none
        users_free = cap.get("users_free")
        fps_free = cap.get("fingerprints_free")
        if users_free is None and fps_free is None:
            return list(users), [], none
        admitted: list[Dict[str, Any]] = []
        skipped: list[str] = []
        withheld: Dict[str, set[int]] = {}
        u_left = users_free
        f_left = fps_free
        need_users = need_fps = 0
        for u, pin, new_user, new_fingers, vacated in needs:
            need_users += int(new_user)
            need_fps += len(new_fingers)
            if new_user and u_left is not None and u_left <= 0:
                skipped.append(pin)
                continue
            admitted.append(u)
            if new_user and u_left is not None:
                u_left -= 1
            if f_left is None:
                continue
            f_left += vacated
            room = max(0, f_left)
            if len(new_fingers) > room:
                withheld[pin] = set(new_fingers[room:])
            f_left -= min(len(new_fingers), room)
        if skipped or withheld:
            logger.warning(
                "%s CAPACITY_FULL: terminal reports users_free=%s fingerprints_free=%s -- %d "
                "new member(s) NOT pushed (%s), %d finger(s) of %d member(s) not written (%s); "
                "cards, updates and removals still go through",
                self._prefix, users_free, fps_free, len(skipped), ",".join(skipped[:20]),
                sum(len(v) for v in withheld.values()), len(withheld),
                ",".join(sorted(withheld)[:20]),
            )
            _tel.warn(_push_safety.CAPACITY_FULL, worker=self._tel_wid,
                      users_free=users_free, fingerprints_free=fps_free,
                      need_users=need_users, need_fingers=need_fps, skipped=len(skipped),
                      withheld_fingers=sum(len(v) for v in withheld.values()),
                      withheld_pins=len(withheld))
        return admitted, skipped, withheld

    @staticmethod
    def _without_withheld(templates_by_pin: Dict[str, list] | None,
                          withheld: Dict[str, set[int]] | None) -> Dict[str, list]:
        """templates_by_pin minus the fingers capacity admission withheld."""
        if not withheld:
            return dict(templates_by_pin or {})
        out: Dict[str, list] = {}
        for pin, tpls in (templates_by_pin or {}).items():
            drop = withheld.get(pin)
            if not drop:
                out[pin] = tpls
                continue
            kept = []
            for t in tpls or []:
                try:
                    if isinstance(t, dict) and int(t.get("fingerId")) in drop:
                        continue
                except (TypeError, ValueError):
                    pass
                kept.append(t)
            out[pin] = kept
        return out

    def _record_withheld_residents(self, users: list[Dict[str, Any]], result: Any,
                                   templates_by_pin: Dict[str, list] | None,
                                   withheld: Dict[str, set[int]] | None) -> None:
        """A pin whose fingers capacity withheld is recorded NOT in sync (it is retried), and
        a failed state write keeps the previous pushed_finger_ids -- but its vacated slots
        WERE cleared and its other fingers written. Record what is resident now, or every
        retry clears an already-empty slot, reads the False as a refusal and fails for good
        (review R3-12). Only for pins the DRIVER confirmed (fail-closed on its result)."""
        if not withheld or not isinstance(result, dict):
            return
        confirmed_failed = self._standalone_failed_pins_from_result(users=users, result=result)
        rows: list[tuple[str, str]] = []
        for u in users or []:
            pin = str(u.get("pin") or "").strip()
            if pin in withheld and pin not in confirmed_failed:
                rows.append((pin, _encode_fingers(
                    self._desired_fingers((templates_by_pin or {}).get(pin)))))
        if not rows:
            return
        try:
            from app.core.db import set_device_pushed_fingers
            set_device_pushed_fingers(device_id=self._device_id, rows=rows)
        except Exception:
            logger.debug("%s resident fingers of withheld pins not recorded", self._prefix,
                         exc_info=True)

    @staticmethod
    def _with_withheld_failed(result: Any, pins, withheld: Dict[str, set[int]] | None) -> Any:
        """The result to RECORD: a pushed pin whose fingers were withheld is not in sync.

        Only for the state write -- the pass itself is not failed by it (it is pending,
        like a refused new member: the roster hash is withheld and it is retried).
        """
        if not withheld or not isinstance(result, dict):
            return result
        if not isinstance(result.get("failed_pins"), list):
            # A result that names no failed pin (a wedged chunk) confirms NOTHING; adding
            # the withheld pins would make it name exactly those, and every other pin of
            # the chunk would be recorded written and owned (review R2-01).
            return result
        hit = [p for p in (str(x or "").strip() for x in pins) if p in withheld]
        if not hit:
            return result
        out = dict(result)
        failed = list(out.get("failed_pins") or [])
        for p in hit:
            if p not in failed:
                failed.append(p)
        out["failed_pins"] = failed
        out["ok"] = False
        return out

    # ---------------------------------------------------------------- #
    # Finger-slot sweep (P3a-2 item 5, guide §3.4c)
    # ---------------------------------------------------------------- #
    def _finger_sweep_plan(self, users: list[Dict[str, Any]],
                           templates_by_pin: Dict[str, list] | None) -> Dict[str, Dict[str, Any]]:
        """{pin: {slots, desired, unknown}} for pins about to be pushed that MonClub
        ALREADY owns and has never swept. A first push (no row) or an unowned row is never
        swept: on a shared terminal that pin may be another system's user, whose
        fingerprints are not MonClub's to clear."""
        if not bool(self._settings.get("fingerprint_enabled", False)):
            return {}
        if not callable(getattr(self._sdk, "sweep_finger_slots", None)):
            return {}
        plan: Dict[str, Dict[str, Any]] = {}
        try:
            from app.core.db import get_finger_sweep_state
        except Exception:
            return {}
        for u in users or []:
            pin = str(u.get("pin") or "").strip()
            if not pin:
                continue
            try:
                st = get_finger_sweep_state(device_id=self._device_id, pin=pin)
            except Exception:
                continue
            if st is None:
                continue
            owned, swept, recorded = st
            if not owned or swept:
                continue
            desired = self._desired_fingers((templates_by_pin or {}).get(pin))
            plan[pin] = {"slots": [s for s in _ALL_FINGER_SLOTS if s not in desired],
                         "desired": desired, "unknown": recorded is None}
        return plan

    def _sweep_pin(self, pin: str, slots: list[int], *, source: str) -> bool:
        """Clear ``slots`` of one pin in short commands, serving the door in between.
        True only when every command completed without an exception or a wedge."""
        slots = list(slots or [])
        totals = {"attempted": 0, "returned_true": 0, "returned_false": 0, "raised": 0}
        ok = True
        t0 = time.monotonic()
        while True:
            part, slots = slots[:_SWEEP_SLOTS_PER_COMMAND], slots[_SWEEP_SLOTS_PER_COMMAND:]
            res = self._sdk.sweep_finger_slots(pin, part, refresh=not slots) if (part or not slots) else {}
            if isinstance(res, dict):
                for k in totals:
                    totals[k] += int(res.get(k) or 0)
            if not (isinstance(res, dict) and res.get("ok") is True):
                ok = False
                break
            if not slots:
                break
            self._yield_during_device_work()
        _tel.event("FINGER_SWEEP", worker=self._tel_wid, pin=pin, source=source, ok=ok,
                   op="del_user_tmp_ext", cleared=totals["returned_true"],
                   empty=totals["returned_false"], raised=totals["raised"],
                   dur_ms=round((time.monotonic() - t0) * 1000))
        return ok

    def _mark_swept(self, pin: str, desired: set[int] | None) -> None:
        try:
            from app.core.db import mark_finger_slots_swept
            mark_finger_slots_swept(device_id=self._device_id, pin=pin, finger_ids=desired)
        except Exception:
            logger.warning("%s finger sweep of pin %s not recorded", self._prefix, pin,
                           exc_info=True)

    def _yield_during_device_work(self) -> None:
        """Between two commands of a long device job: let the door through.

        Standalone events are already queued by the STA thread (poll_rtlog_once is a
        queue drain, no COM call), so a QR/TOTP or staff-RFID rescue is decided and its
        door opened here instead of after the whole job; queued operator opens run too.
        Never on the STA thread (this runs on the worker, which is between commands).
        """
        if getattr(self._sdk, "owns_event_source", False) and self._connected:
            try:
                events = self._sdk.poll_rtlog_once()
            except Exception:
                events = []
            for evt in events or []:
                try:
                    self._process_event(evt)
                except Exception:
                    logger.warning("%s event during device work failed", self._prefix,
                                   exc_info=True)
        try:
            self._sync_yield_to_doors()
        except Exception:
            pass

    # ---------------------------------------------------------------- #
    # Between the chunks of a full-sync push (P3a-2 item 6, guide §3.4e)
    # ---------------------------------------------------------------- #
    def _note_push_superseded(self, pins) -> None:
        """A targeted update served INSIDE a full-sync push names the pins it handled.

        Those pins' data in the running pass is now older than what the update wrote (or
        removed): the pass must not push them from its snapshot, record them, or prune
        them. Called by the member sync / revoke paths; a no-op outside a push yield.
        """
        sink = getattr(self, "_push_yield_pins", None)
        if sink is None:
            return
        for p in pins or ():
            p = str(p if p is not None else "").strip()
            if p:
                sink.add(p)

    def _standalone_push_yield(self) -> set[str]:
        """``push_roster``'s between_chunks hook for a standalone full sync.

        Runs on the worker between two chunks (the STA thread is idle and its event pump
        already ran): decides the scans queued meanwhile -- a QR/TOTP or staff-RFID rescue
        opens the door here -- runs queued desk opens, then serves at most ONE pending
        member update or revoke. A member already served in this pass is not served again
        (a failing revoke re-queues itself; it must not be retried at every chunk).
        Returns the pins that update handled, which the driver drops from the chunks not
        yet sent. Also restarts the WORKER_STALL clock: the worker is not frozen, and the
        stall warning now measures one chunk, not the whole push.
        """
        if getattr(self, "_in_push_yield", False):
            return set()
        self._in_push_yield = True
        touched: set[str] = set()
        served = 0
        t0 = time.monotonic()
        try:
            _tel.set_state(self._tel_wid, "push_yield")
            self._yield_during_device_work()
            served_ids = getattr(self, "_pass_served_members", None)
            with self._member_sync_lock:
                nxt = self._pending_member_syncs[0] if self._pending_member_syncs else None
            # Not onto a link the driver reports dead: the update would be used up for
            # nothing (review R2-14); it waits for the run loop's reconnect.
            link_up = bool(getattr(self._sdk, "is_connected", True))
            if nxt is not None and link_up and (served_ids is None or int(nxt) not in served_ids):
                if served_ids is not None:
                    served_ids.add(int(nxt))
                self._push_yield_pins = touched
                try:
                    served = self._drain_member_sync_commands(limit=1)
                finally:
                    self._push_yield_pins = None
        except Exception:
            logger.warning("%s push yield failed (the push carries on)", self._prefix,
                           exc_info=True)
        finally:
            self._in_push_yield = False
            _tel.set_state(self._tel_wid, "full_sync", getattr(self, "_push_yield_detail", ""))
        acc = getattr(self, "_pass_touched_pins", None)
        if acc is not None:
            acc.update(touched)
        if served or touched:
            _tel.event("PUSH_YIELD", worker=self._tel_wid, member_updates=served,
                       pins=len(touched), dur_ms=round((time.monotonic() - t0) * 1000))
        return touched

    def _prioritise_for_cap(
        self,
        to_push: list[Dict[str, Any]],
        templates_by_pin: Dict[str, list] | None,
        pushed_fingers: Dict[str, Any],
    ) -> list[Dict[str, Any]]:
        """Order a pass that exceeds the cap: removals, new, failed, changed.

        A pin with a vacated finger slot goes first (a deleted finger keeps opening the
        door until its push clears the slot), then members not on the terminal yet, then
        retries of unconfirmed pushes, then plain changes. Stable: roster order within a
        group. Only the ORDER changes here; the slice is taken after capacity admission.
        """
        kinds = getattr(self, "_last_push_kinds", None) or {}
        try:
            removals = self._standalone_removals(
                to_push=to_push, templates_by_pin=templates_by_pin or {},
                pushed_fingers=pushed_fingers or {},
            )
        except Exception:
            removals = {}
        rank = {"new": 1, "failed": 2}

        def _key(u: Dict[str, Any]) -> int:
            pin = str(u.get("pin") or "").strip()
            if removals.get(pin):
                return 0
            return rank.get(kinds.get(pin, ""), 3)

        return sorted(to_push, key=_key)

    def _drain_finger_sweep(self, today: str) -> None:
        """The daily bounded batch: ONE short sweep command per run-loop iteration."""
        if not bool(self._settings.get("fingerprint_enabled", False)):
            return
        if not callable(getattr(self._sdk, "sweep_finger_slots", None)):
            return
        st = getattr(self, "_sweep_state", None)
        if st is None or st.get("day") != today:
            try:
                from app.core.db import list_finger_sweep_candidates
                cands = list_finger_sweep_candidates(device_id=self._device_id) or {}
            except Exception:
                logger.warning("%s finger sweep candidates unreadable", self._prefix,
                               exc_info=True)
                return
            desired_now = set(getattr(self, "_last_desired_pins", None) or ())
            st = {"day": today, "queue": sorted(p for p in cands if p in desired_now),
                  "done": 0, "current": None}
            self._sweep_state = st
        cur = st.get("current")
        if cur is None:
            if st["done"] >= _FINGER_SWEEP_DAILY_CAP:
                return
            while st["queue"]:
                pin = st["queue"].pop(0)
                check = self._sweep_check(pin)
                if check is None:
                    continue
                keep, record = check
                cur = {"pin": pin, "slots": [s for s in _ALL_FINGER_SLOTS if s not in keep],
                       "keep": keep, "record": record, "ok": True,
                       "t0": time.monotonic(), "cleared": 0, "empty": 0}
                st["current"] = cur
                break
            if cur is None:
                return
        else:
            # Re-checked before EVERY command (review R1-18/R1-27): a push may have run
            # between two commands -- a targeted one served by the run loop, or a full
            # sync -- and written a finger into a slot this plan was about to clear. The
            # plan is dropped (not marked swept) when anything it was built on moved.
            check = self._sweep_check(cur["pin"])
            if check is None or check[0] != cur["keep"]:
                _tel.event("FINGER_SWEEP", worker=self._tel_wid, pin=cur["pin"],
                           source="daily", ok=False, abandoned=True, op="del_user_tmp_ext",
                           cleared=cur["cleared"], empty=cur["empty"],
                           dur_ms=round((time.monotonic() - cur["t0"]) * 1000))
                st["current"] = None
                return
        part = cur["slots"][:_SWEEP_SLOTS_PER_COMMAND]
        cur["slots"] = cur["slots"][_SWEEP_SLOTS_PER_COMMAND:]
        res = self._sdk.sweep_finger_slots(cur["pin"], part, refresh=not cur["slots"])
        if isinstance(res, dict):
            cur["cleared"] += int(res.get("returned_true") or 0)
            cur["empty"] += int(res.get("returned_false") or 0)
        if not (isinstance(res, dict) and res.get("ok") is True):
            cur["ok"] = False
            cur["slots"] = []
        if not cur["slots"]:
            if cur["ok"]:
                self._mark_swept(cur["pin"], cur["record"])
            _tel.event("FINGER_SWEEP", worker=self._tel_wid, pin=cur["pin"], source="daily",
                       ok=cur["ok"], op="del_user_tmp_ext", cleared=cur["cleared"],
                       empty=cur["empty"], dur_ms=round((time.monotonic() - cur["t0"]) * 1000))
            st["current"] = None
            st["done"] += 1

    def _sweep_check(self, pin: str) -> tuple[set[int], set[int] | None] | None:
        """(keep, record) when the daily batch may sweep ``pin`` now; None when it may not.

        It may only when the terminal is known to hold exactly the member's desired
        fingers of the last COMPLETE roster: the pin is in that roster, owned, not yet
        swept, not pushed moments ago, and its state is confirmed (last_ok=1) with the
        very hash of that roster. Then ``keep`` = those desired fingers | the recorded
        set, and ``record`` = the fingers to record after the sweep (only when the
        recorded set is unknown). Anything else -- a failed push, a newer push, a pin
        missing from the snapshot -- skips the pin today (review R1-18/19/27: a stale
        plan cleared a finger written in between, and a pin absent from an incomplete
        later roster had every slot cleared).
        """
        if pin in self._mirror_grace_pins():
            return None
        desired = getattr(self, "_last_desired_pins", None) or set()
        fingers = (getattr(self, "_last_desired_fingers", None) or {}).get(pin)
        snap_hash = (getattr(self, "_last_desired_hashes", None) or {}).get(pin)
        if pin not in desired or fingers is None or not snap_hash:
            return None
        try:
            from app.core.db import get_finger_sweep_state, get_pin_sync_status
            state = get_finger_sweep_state(device_id=self._device_id, pin=pin)
            status = get_pin_sync_status(device_id=self._device_id, pin=pin)
        except Exception:
            return None
        if state is None or not state[0] or state[1]:
            return None               # no longer owned, or already swept meanwhile
        if status is None or not status[1] or status[0] != snap_hash:
            return None               # not confirmed with this roster's content
        recorded = state[2]
        keep = set(fingers) | set(recorded or ())
        return keep, (set(fingers) if recorded is None else None)

    # ---------------------------------------------------------------- #
    # Fast retry of a FAILED removal (P3a-2 item 2, guide §3.4b)
    # ---------------------------------------------------------------- #
    def _update_removal_retry(self, *, failed: list[str], errored: bool = False,
                              skipped: bool = False) -> None:
        """Arm (failure) or clear (no failure) the worker's own removal retry.

        A removal the device refused used to wait for an unrelated roster change: the
        pass reported success, the scheduler stamped the roster hash and skipped the
        device as unchanged. The worker now re-requests a pass itself, 30 s after the
        first failure, doubling, never more than 300 s apart -- a member who left must
        not keep opening the door for long. A refusal by the removal ceiling
        (REVOKE_ABORTED) is not a failure: retrying it every few seconds changes nothing.

        ``skipped``: the pass did not run its removal step (an incomplete roster) -- the
        retry is left exactly as it is; re-arming from the LAST pass's failure list meant a
        useless full pass every 300 s for as long as the roster stayed incomplete (review
        R1-08/R1-22). Every call marks the pass as having reported (see
        ``_keep_pending_removal_retry``).
        """
        self._removal_retry_reported = True
        if skipped:
            # The step could not run. A removal still pending is PARKED, not dropped: it
            # used to be lost when the skipped pass was itself the retry pass (R2-17).
            if int(getattr(self, "_removal_retry_streak", 0) or 0) > 0:
                park_at = time.monotonic() + _REMOVAL_RETRY_PARKED_SEC
                cur = getattr(self, "_removal_retry_at_mono", None)
                if cur is None or float(cur) > park_at:     # never postpone a sooner one (R3-16)
                    self._removal_retry_at_mono = park_at
                    _tel.warn("REMOVAL_RETRY_SCHEDULED", worker=self._tel_wid, pins=0,
                              delay_s=round(_REMOVAL_RETRY_PARKED_SEC),
                              streak=self._removal_retry_streak, parked=True)
            return
        if failed or errored:
            streak = int(getattr(self, "_removal_retry_streak", 0) or 0) + 1
            # The exponent is clamped: 30.0 * 2 ** 1024 raised OverflowError at streak
            # 1025 (~85 h of one failing removal), before the streak was stored, so every
            # later pass raised too -- on the MB2000 before its push (review R1-07).
            delay = min(_REMOVAL_RETRY_MAX_SEC,
                        _REMOVAL_RETRY_FIRST_SEC * (2 ** min(streak - 1, 16)))
            self._removal_retry_streak = streak
            self._removal_retry_at_mono = time.monotonic() + delay
            _tel.warn("REMOVAL_RETRY_SCHEDULED", worker=self._tel_wid,
                      pins=len(failed), delay_s=round(delay), streak=streak,
                      errored=errored or None)
        else:
            self._removal_retry_streak = 0
            self._removal_retry_at_mono = None

    def _keep_pending_removal_retry(self) -> None:
        """After a pass that never reported its removal step: keep a pending retry armed.

        A retry pass that raised, returned early or stopped before its removal step used
        to clear the retry (its timer is cleared when the pass is requested), and the
        roster hash the scheduler had already stamped then stranded the failed removal
        (review R1-06).
        """
        if getattr(self, "_removal_retry_reported", True):
            return
        if int(getattr(self, "_removal_retry_streak", 0) or 0) > 0:
            self._update_removal_retry(failed=[], errored=True)

    def _maybe_request_removal_retry(self) -> None:
        """Run loop: when a failed removal's retry is due, ask for a pass."""
        due = getattr(self, "_removal_retry_at_mono", None)
        if due is None or not self._connected or time.monotonic() < due:
            return
        if self._pending_full_sync_request is not None:
            return  # a pass is already queued; it retries the removal
        self._removal_retry_at_mono = None
        self.request_full_sync(reason="removal-retry")

    # ---------------------------------------------------------------- #
    # Write-ahead ownership (P3a-2 item 3, guide §3.4a)
    # ---------------------------------------------------------------- #
    def _record_push_intents(self, users: list[Dict[str, Any]],
                             hashes_by_pin: Dict[str, str] | None) -> bool:
        """Durably record, BEFORE any device write, what this push will write.

        False = not recorded; the caller must not write the terminal this pass (a
        member written without a record is exactly the unprovable orphan this exists
        to prevent).
        """
        rows: list[tuple] = []
        for u in users or []:
            pin = str(u.get("pin") or "").strip()
            if not pin:
                continue
            name, card = _standalone_wire_identity(u)
            rows.append((pin, name, card, (hashes_by_pin or {}).get(pin, "")))
        if not rows:
            return True
        try:
            from app.core.db import record_push_intents
            record_push_intents(device_id=self._device_id, rows=rows, protocol="ZK_STANDALONE")
            return True
        except Exception as exc:
            logger.error(
                "%s write-ahead push intent NOT recorded for %d pin(s) (%s) -- nothing is "
                "written to the terminal this pass", self._prefix, len(rows), exc,
            )
            _tel.warn("PUSH_INTENT_FAILED", worker=self._tel_wid, pins=len(rows),
                      err=type(exc).__name__)
            return False

    def _push_with_chunk_recording(
        self,
        users: list[Dict[str, Any]],
        templates_by_pin: Dict[str, list],
        hashes_by_pin: Dict[str, str],
        *,
        removals: Dict[str, list[int]],
        bracket: bool,
        between_chunks: "Callable[[], Any] | None" = None,
        withheld: Dict[str, set[int]] | None = None,
    ) -> Dict[str, Any]:
        """push_roster, recording each chunk's outcome as soon as the chunk returns.

        Recording once per roster (after push_roster returned) meant a crash or power
        cut mid-push lost every confirmation of the chunks already on the terminal.
        A driver without the ``on_chunk`` hook (or pins never sent after an early
        stop) is recorded from the aggregate result afterwards, as before.
        """
        wanted = {str(u.get("pin") or "").strip() for u in users}
        recorded: set[str] = set()

        def _on_chunk(part: list[Dict[str, Any]], res: Dict[str, Any] | None) -> None:
            part_users = [u for u in (part or []) if str(u.get("pin") or "").strip() in wanted]
            if not part_users:
                return
            self._record_standalone_pin_state(
                users=part_users, hashes_by_pin=hashes_by_pin,
                # A wedged chunk confirmed nothing. A pin whose fingers capacity admission
                # withheld is not in sync either (P3a-2, review round 1).
                result=self._with_withheld_failed(
                    res if isinstance(res, dict) else {"ok": False, "error": "chunk wedged"},
                    (u.get("pin") for u in part_users), withheld,
                ),
                templates_by_pin=templates_by_pin,
            )
            self._record_withheld_residents(part_users, res, templates_by_pin, withheld)
            recorded.update(str(u.get("pin") or "").strip() for u in part_users)

        kwargs: Dict[str, Any] = {"remove_fingers_by_pin": removals,
                                  "bracket_enable_device": bracket}
        if _accepts_kwarg(self._sdk.push_roster, "on_chunk"):
            kwargs["on_chunk"] = _on_chunk
        if between_chunks is not None and _accepts_kwarg(self._sdk.push_roster, "between_chunks"):
            kwargs["between_chunks"] = between_chunks
        result = self._sdk.push_roster(users, templates_by_pin, **kwargs)
        # A pin the between-chunks yield handled itself (P3a-2 item 6) was never sent by
        # this push; recording it from this result would overwrite the newer state the
        # targeted update just wrote -- the 2026-09-06 stale-snapshot bug again.
        superseded = {
            str(p if p is not None else "").strip()
            for p in ((result.get("superseded_pins") if isinstance(result, dict) else None) or [])
        }
        remaining = [u for u in users
                     if str(u.get("pin") or "").strip() not in recorded
                     and str(u.get("pin") or "").strip() not in superseded]
        if remaining:
            self._record_standalone_pin_state(
                users=remaining, hashes_by_pin=hashes_by_pin,
                result=self._with_withheld_failed(
                    result, (u.get("pin") for u in remaining), withheld),
                templates_by_pin=templates_by_pin,
            )
            self._record_withheld_residents(remaining, result, templates_by_pin, withheld)
        return result

    def _promote_intents_by_readback(self, *, desired_pins: set[str]) -> Dict[str, list] | None:
        """Turn intent-only pins into ownership when the terminal holds what we wrote.

        Candidates are intent pins that LEFT the desired roster (a still-desired one is
        confirmed by its next ordinary push, no enumeration needed). One enumeration of
        the terminal (``list_device_users``; on gym 45 about 1,860 users, duration
        UNVERIFIED -- FIELD-TEST) then decides per pin:

        - present with exactly the name (24 chars) and card digits MonClub wrote
          -> promoted to ownership (the next revoke pass removes it);
        - absent from a SUCCESSFUL listing -> the write never landed, intent dropped;
        - present with anything else -> not ours (another system's user, or our write
          never landed): intent kept, miss counted, never deleted.

        A failed or malformed listing changes nothing. Returns None when nothing was
        read, else {"promoted", "dropped", "mismatched"} pin lists.
        """
        try:
            from app.core.db import list_push_intents
            intents = list_push_intents(device_id=self._device_id) or {}
        except Exception:
            logger.warning("%s intent read-back: intents unreadable", self._prefix, exc_info=True)
            return None
        desired = {str(p).strip() for p in (desired_pins or ())}
        cands = {
            p: it for p, it in intents.items()
            if p not in desired and str(it.get("protocol") or "") in ("", "ZK_STANDALONE")
        }
        if not cands:
            return None
        lister = getattr(self._sdk, "list_device_users", None)
        if not callable(lister):
            return None
        t0 = time.monotonic()
        listing = lister()
        dur_ms = round((time.monotonic() - t0) * 1000)
        if not isinstance(listing, dict) or listing.get("ok") is not True \
                or not isinstance(listing.get("users"), list):
            logger.warning("%s intent read-back: terminal listing failed -- nothing changed (%s)",
                           self._prefix, (listing or {}).get("error") if isinstance(listing, dict) else listing)
            _tel.warn("PUSH_INTENT_READBACK", worker=self._tel_wid, ok=False,
                      candidates=len(cands), dur_ms=dur_ms)
            return None
        on_device: Dict[str, tuple[str, str]] = {}
        for u in listing["users"]:
            if not isinstance(u, dict):
                continue
            pin = str(u.get("pin") or "").strip()
            if pin:
                on_device[pin] = _standalone_wire_identity(u)
        drops_allowed = True
        missing_owned: list[str] = []
        owned_now: set[str] = set()
        if on_device:
            # A listing that shows NONE of the pins MonClub owns on this terminal is not
            # trusted (a wrong out-param order would put names in the pin field): it would
            # drop every departed intent (review R3-20). Nothing changes. An unreadable
            # ownership state is "cannot check", never "nothing to check" (review R4-04).
            try:
                from app.core.db import list_confirmed_device_sync_pins
                owned_now = {str(p).strip() for p in
                             (list_confirmed_device_sync_pins(device_id=self._device_id) or ())}
            except Exception:
                logger.warning("%s intent read-back: ownership unreadable -- nothing changed",
                               self._prefix, exc_info=True)
                return None
            # Absence proves "the write never landed" only on a COMPLETE listing: one that
            # misses any pin MonClub owns (a listing cut short) drops nothing (review R4-06).
            drops_allowed = owned_now <= set(on_device)
            missing_owned = sorted(owned_now - set(on_device))
            if owned_now and not (owned_now & set(on_device)):
                logger.warning("%s intent read-back: the listing shows none of MonClub's %d "
                               "owned pins -- not trusted, nothing changed", self._prefix,
                               len(owned_now))
                _tel.warn("PUSH_INTENT_READBACK", worker=self._tel_wid, ok=False,
                          candidates=len(cands), dur_ms=dur_ms, reason="no_owned_pin_listed")
                return None
        if on_device and missing_owned and (owned_now & set(on_device)):
            # A pin MonClub believes it wrote is not in the listing: deleted on the terminal
            # by someone else, or the listing was cut short -- the two cannot be told apart
            # here. REPORTED ONLY. Flagging them for a push (round 5) re-pushed most of the
            # roster after a cut-short listing and reset the retry clock of pins in backoff
            # (review R6-02, R6-03); re-adding members another system removed is loss
            # detection, outside P3a-2. While such a pin exists the listing is incomplete,
            # so no intent is dropped and the read-back runs again the next day for the
            # intents it could not settle (R5-01, guide §7). It is reported only on days
            # the read-back runs at all -- only while departed-member intents exist.
            logger.warning("%s intent read-back: %d owned pin(s) absent from the terminal "
                           "listing -- reported only, nothing changed (%s)", self._prefix,
                           len(missing_owned), ",".join(missing_owned[:20]))
        promoted: list[str] = []
        dropped: list[str] = []
        mismatched: list[str] = []
        for pin, it in sorted(cands.items()):
            if pin not in on_device:
                # An EMPTY listing cannot tell an empty terminal from a read that returned
                # nothing: drop no intent on it (review R2-06, as R1-30 on PullSDK); nor an
                # incomplete one (R4-06).
                if on_device and drops_allowed:
                    dropped.append(pin)
                continue
            want_name = str(it.get("name") or "")[:24].strip()
            want_card = "".join(ch for ch in str(it.get("card") or "") if ch.isdigit())
            got_name, got_card = on_device[pin]
            if (want_name or want_card) and got_name.strip() == want_name and got_card == want_card:
                promoted.append(pin)
            else:
                mismatched.append(pin)
        try:
            from app.core.db import drop_push_intents, note_push_intent_misses, promote_push_intents
            if promoted:
                promote_push_intents(device_id=self._device_id, pins=promoted)
            if dropped:
                drop_push_intents(device_id=self._device_id, pins=dropped)
            if mismatched:
                note_push_intent_misses(device_id=self._device_id, pins=mismatched)
        except Exception:
            logger.warning("%s intent read-back: result not recorded", self._prefix, exc_info=True)
            return None
        _tel.event("PUSH_INTENT_READBACK", worker=self._tel_wid, ok=True,
                   candidates=len(cands), listed=len(on_device), promoted=len(promoted),
                   dropped=len(dropped), mismatched=len(mismatched), dur_ms=dur_ms,
                   missing_owned=len(missing_owned) or None)
        if promoted:
            logger.warning(
                "%s intent read-back: %d pin(s) proven MonClub's (%s) -- the next revoke pass "
                "removes the departed ones", self._prefix, len(promoted), ",".join(promoted[:20]),
            )
            self.request_full_sync(reason="intent-promoted")
        return {"promoted": promoted, "dropped": dropped, "mismatched": mismatched}

    def _run_standalone_full_sync(
        self,
        *,
        reason: str,
        full_reconcile: bool = False,
        fingerprint_hash: str | None,
        revoked_ids: set[int] | None = None,
        excluded_ids: set[int] | None = None,
    ) -> None:
        """Full roster push for a push driver, with FULL parity on the started/
        finished bookkeeping so scheduler skip-hashes and manual-sync pending
        counters keep working. Always terminates (never re-queues itself)."""
        normalized_revoked_ids = {
            int(member_id)
            for member_id in (revoked_ids or set())
            if member_id is not None
        }
        normalized_excluded_ids = normalized_revoked_ids | {
            int(member_id)
            for member_id in (excluded_ids or set())
            if member_id is not None
        }
        confirmed_revoked_ids = self._confirmed_member_revokes(normalized_revoked_ids)
        unconfirmed_revoked_ids = normalized_revoked_ids - confirmed_revoked_ids
        started_at = time.time()
        started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at))
        cache = load_sync_cache()
        if cache is None:
            logger.warning("%s standalone full sync skipped: no sync cache", self._prefix)
            self._mark_full_sync_finished(reason=reason, ok=False, duration_ms=0.0,
                                          error="no sync cache available")
            self._finalize_full_sync_revokes(
                normalized_revoked_ids,
                ok=False,
                excluded_ids=normalized_excluded_ids,
            )
            self._notify_full_sync_finished(
                reason=reason,
                ok=False,
                fingerprint_hash=None,
                duration_ms=0.0,
                error="no sync cache available",
                revoked_ids=normalized_revoked_ids,
            )
            return
        # Which device pin each unconfirmed revocation names (MEMBERSHIP: str(id), as before;
        # ACCOUNT: the person's pin, absent when it cannot be named).
        revoked_pin_of: Dict[int, str] = {}
        if unconfirmed_revoked_ids:
            revoked_pin_of = self._device_pins_for_members(
                unconfirmed_revoked_ids, users=list(getattr(cache, "users", []) or []),
            )
        # Ownership of the pins those revocations name (P3a-2 item 4, guide §3.4).
        # Only an UNREADABLE state still refuses the pass before any device I/O: that
        # is "cannot tell", never "not ours". A pin MonClub provably does not own --
        # an unconfirmed row (a failed first push) or no row at all (a foreign or
        # never-pushed user) -- used to refuse the whole pass here, or abort the whole
        # revoke pass after the push, on every full sync, forever. It is now dropped
        # from the pass as SKIPPED_NOT_OWNED once the desired roster is known (below).
        owned_for_revokes: set[str] | None = None
        revoke_rows_seen: set[str] = set()
        if unconfirmed_revoked_ids:
            try:
                from app.core.db import list_device_sync_hashes_and_status
                from app.core.db import list_confirmed_device_sync_pins
                revoke_rows_seen = {
                    str(pin).strip()
                    for pin in (list_device_sync_hashes_and_status(device_id=self._device_id) or {})
                }
                owned_for_revokes = {
                    str(pin).strip()
                    for pin in (list_confirmed_device_sync_pins(device_id=self._device_id) or set())
                    if str(pin).strip()
                }
            except Exception:
                owned_for_revokes = None
                logger.warning(
                    "%s standalone full sync skipped: ownership state unreadable "
                    "for explicit revocation(s)",
                    self._prefix,
                    exc_info=True,
                )
            if owned_for_revokes is None and revoked_pin_of:
                error = "authoritative revocation ownership unconfirmed"
                self._mark_full_sync_finished(
                    reason=reason,
                    ok=False,
                    duration_ms=0.0,
                    error=error,
                )
                self._finalize_full_sync_revokes(
                    normalized_revoked_ids,
                    ok=False,
                    excluded_ids=normalized_excluded_ids,
                )
                self._notify_full_sync_finished(
                    reason=reason,
                    ok=False,
                    fingerprint_hash=None,
                    duration_ms=0.0,
                    error=error,
                    revoked_ids=normalized_revoked_ids,
                )
                return
        _guarded_gone = self._recently_removed_still_gone()
        if _guarded_gone is None:
            # The database could not say whether recently removed members are still gone.
            # Excluding them could DELETE a restored paying member (the removal step takes
            # owned pins missing from the roster) and report the roster in sync; trusting
            # the cache could re-enrol a departed one. Neither: this pass does nothing and
            # fails, so the scheduler retries it (review R6-06).
            error = "recently removed members unreadable"
            logger.warning("%s standalone full sync skipped: %s", self._prefix, error)
            self._mark_full_sync_finished(
                reason=reason,
                ok=False,
                duration_ms=0.0,
                error=error,
            )
            self._finalize_full_sync_revokes(
                normalized_revoked_ids,
                ok=False,
                excluded_ids=normalized_excluded_ids,
            )
            self._notify_full_sync_finished(
                reason=reason,
                ok=False,
                fingerprint_hash=None,
                duration_ms=0.0,
                error=error,
                revoked_ids=normalized_revoked_ids,
            )
            return
        cache = _sync_cache_without_revoked_ids(
            cache, normalized_excluded_ids | _guarded_gone,
        )

        self._mark_full_sync_started(reason=reason, engine=None, started_at=started_iso)
        self._notify_full_sync_started(reason=reason)
        _tel.set_state(self._tel_wid, "full_sync", f"reason={reason}")
        _tel.event("FULL_SYNC_START", worker=self._tel_wid, reason=reason,
                   users=len(getattr(cache, "users", []) or []))
        result: Dict[str, Any] = {}
        # Record a push-batch row. Without this "Historique push" was structurally
        # dead for a standalone terminal: an ULTRA *PullSDK* device gets rows (via
        # DeviceSyncEngine.run_one_device_on_connected_sdk -> insert_push_batch),
        # so on a mixed gym the page showed every device EXCEPT this one -- which
        # reads as "the MB2000 never syncs" minutes after a real reconcile.
        batch_id: int | None = None
        batch_attempted = 0
        skipped_unchanged = 0
        skipped_note = ""
        # Explicit revocations of pins MonClub cannot prove it owns: dropped from this
        # pass as SKIPPED_NOT_OWNED (final). {membership_id: pin}. P3a-2 item 4.
        skipped_revokes: Dict[int, str] = {}
        # Pins left for a later pass on purpose (CAPACITY_FULL now; the daytime cap in
        # item 6): the pass reports ok but withholds the roster hash, so the scheduler
        # does not stamp the device as in sync and the rest is pushed later.
        pass_incomplete = False
        capacity_skipped: list[str] = []
        capacity_withheld: Dict[str, set[int]] = {}
        # Explicit revocations whose pin the removal step (which runs first) removed.
        removed_revokes: set[int] = set()
        # P3a-2 item 6: pins left for the pass's own continuation (the per-pass cap), and
        # every pin a targeted update served between two chunks handled (never pushed
        # from this pass's snapshot, never pruned, never deleted by MIRROR).
        capped_out: list[str] = []
        pass_touched: set[str] = set()
        pushed_users: list[Dict[str, Any]] = []
        self._last_revoke_aborted = 0
        # What THIS pass's removal step did: "ran", "skipped" (incomplete roster) or
        # "errored". A stale list from the previous pass must never be read (R1-08/22).
        self._last_revoke_removal_failed = []
        self._last_revoke_step = None
        self._last_revoke_grace = set()
        self._last_revoke_holds = set()
        self._last_revoke_hold_person = {}
        desired_pins: list[str] = []
        # RENEWAL ORDERING (P3b-1, plan §7): departed pins held back by the removal step
        # until the push confirms their person's new pin ({pin: person}), those still kept
        # after the push, and the removal step's outcome while its report to the removal
        # retry waits for the post-push removal (one report per pass).
        renewal_holds: Dict[str, int] = {}
        kept_holds: set[str] = set()
        deferred_retry: tuple[list[str], bool] | None = None
        try:
            self._last_standalone_roster_stats = None
            self._last_standalone_pin_persons = None
            users, templates_by_pin, hashes_by_pin = self._build_standalone_roster(cache)
            desired_pins = [str(u.get("pin") or "").strip() for u in users]
            _roster_stats = getattr(self, "_last_standalone_roster_stats", None) or {}
            roster_withheld = int(_roster_stats.get("withheld_missing_account") or 0)
            # Read NOW: a targeted update served between two push chunks rebuilds a roster
            # and overwrites it.
            _pin_persons = dict(getattr(self, "_last_standalone_pin_persons", None) or {})
            if unconfirmed_revoked_ids and owned_for_revokes is not None:
                # A pin still in the desired roster is not a removal (ACCOUNT: the person
                # keeps another plan and is re-pushed), so only a pin that LEFT it and is
                # not owned is skipped. Decided before the push, so a failed push cannot
                # turn it back into a retry.
                _desired_set = {p for p in desired_pins if p}
                for _m, _pin in sorted(revoked_pin_of.items()):
                    if (_m in unconfirmed_revoked_ids and _pin not in _desired_set
                            and _pin not in owned_for_revokes):
                        skipped_revokes[_m] = _pin
                if skipped_revokes:
                    self._skip_unowned_revocations(skipped_revokes, revoke_rows_seen)
            # EnableDevice bracketing is DELIBERATELY OFF, including for an explicit
            # full reconcile. Plan decision D6 said the nightly/manual reconcile would
            # bracket, but it never once executed (the condition was a dead reason
            # string) and the driver has since changed underneath it: push_roster
            # collapses a bracketed roster into ONE command (`chunks = [users]`) with
            # no per-chunk timeout, which bypasses the wedge recovery added because a
            # single-command 950-member push meant "the gym never got more than the
            # first 10 members". It also holds EnableDevice(False) across the whole
            # push, and the terminal is the gym's sole verifier.
            #
            # Turning this on is a separate, hardware-gated decision, NOT a side
            # effect of repairing the MIRROR trigger. See guide §3.2c.
            bracket = False
            # REMOVALS FIRST (P3a-2 item 2, guide §3.4b). The revoke pass used to run only
            # after a SUCCESSFUL push, so one unrelated member's refused finger meant no
            # departed member was removed that pass. It has no data dependency on the
            # push: its candidates are pins MonClub owns that are not in the desired
            # roster, and a pin this pass is about to push is by construction desired.
            # MIRROR still runs after a successful push, and the prune last.
            #
            # Which pins need a push is read HERE, before the removal step, and once (it
            # records _last_push_kinds / _last_backoff_pins and emits SYNC_RETRY_BACKOFF):
            # renewal ordering needs it to decide what the removal step holds back. The
            # removal step cannot change its answer: this reads the state of DESIRED pins
            # only, and the removal step clears only the state of pins NOT desired.
            to_push, skipped_unchanged = self._standalone_pins_needing_push(users, hashes_by_pin)
            # RENEWAL ORDERING (P3b-1, plan §7). A departed owned pin whose PERSON still has
            # a desired pin that is not confirmed on the terminal -- to be pushed now, or
            # held back by the retry backoff -- is not removed first: the removal step holds
            # it, and it is removed only after the push confirmed that person's desired
            # pins (below). Removing it first left a renewed member with NEITHER pin when
            # the new pin's write failed (guide §7 R3-21). MEMBERSHIP only: under ACCOUNT a
            # renewal keeps the account pin.
            unconfirmed_at_start: set[str] = set()
            hold_persons: set[int] = set()
            if not roster_withheld and not self._pin_scheme_is_account():
                from app.core.device_sync import renewal_person_id

                unconfirmed_at_start = (
                    {str(u.get("pin") or "").strip() for u in to_push}
                    | set(getattr(self, "_last_backoff_pins", ()) or ())
                )
                for _p in unconfirmed_at_start:
                    _who = renewal_person_id(_pin_persons.get(_p))
                    if _who is not None:
                        hold_persons.add(_who)
            safe_to_prune = True
            removal_attempt_failed = False
            if roster_withheld:
                # pinScheme=ACCOUNT rows without mainAccountId were withheld, so their
                # people's pins are missing from `users`/`desired_pins` and would read as
                # departed. MIRROR, the revoke pass and the prune all remove by that
                # difference -- skip all three. safe_to_prune=False also keeps the
                # ownership evidence (guide §3.2c).
                logger.warning(
                    "%s full sync: pinScheme=ACCOUNT roster INCOMPLETE (%d row(s) withheld, "
                    "no mainAccountId) -- MIRROR reconcile, revoke pass and prune skipped",
                    self._prefix, roster_withheld,
                )
                _tel.warn("REVOKE_SKIP_INCOMPLETE_ROSTER", worker=self._tel_wid,
                          withheld=roster_withheld)
                safe_to_prune = False
                self._last_revoke_step = "skipped"
            else:
                # Strip credentials from pins WE pushed that have left the roster.
                # Must run BEFORE the prune below, which deletes the very record of
                # what we pushed to them.
                try:
                    safe_to_prune = self._neutralise_revoked_pins(
                        desired_pins=desired_pins,
                        roster_count=len(users),
                        required_pins=self._required_revocation_pins(
                            unconfirmed_revoked_ids - set(skipped_revokes),
                            desired_pins, revoked_pin_of,
                        ),
                        hold_persons=hold_persons,
                        # Members this pass revokes or keeps excluded: never held.
                        hold_exempt={str(int(m)) for m in (normalized_excluded_ids
                                                            | set(_guarded_gone))},
                    )
                except Exception as exc:
                    logger.warning("%s revoke pass error (ignored): %s", self._prefix, exc)
                    safe_to_prune = False
                    removal_attempt_failed = True
                    # Nothing held: the step's outcome is unknown, its state kept (no prune).
                    self._last_revoke_hold_person = {}
                # An explicit revocation whose pin that step removed is DONE, whatever the
                # push does next: it must not be re-queued (and re-reported) as pending.
                _removed_now = set(getattr(self, "_last_revoke_removed", ()) or ())
                for _m in sorted(unconfirmed_revoked_ids - set(skipped_revokes)):
                    if revoked_pin_of.get(_m) in _removed_now:
                        removed_revokes.add(_m)
                        self._mark_member_revoke_confirmed(_m)
                renewal_holds = dict(getattr(self, "_last_revoke_hold_person", None) or {})
            _step = getattr(self, "_last_revoke_step", None)
            if renewal_holds:
                # Reported ONCE, after the post-push removal of the holds (or by the
                # exception handler when the pass stops before it).
                deferred_retry = (
                    list(getattr(self, "_last_revoke_removal_failed", ()) or ()),
                    removal_attempt_failed or _step != "ran",
                )
            elif _step == "skipped":
                self._update_removal_retry(failed=[], skipped=True)
            else:
                self._update_removal_retry(
                    failed=list(getattr(self, "_last_revoke_removal_failed", ()) or ()),
                    errored=removal_attempt_failed or _step != "ran",
                )
            # Which finger slots this terminal currently holds per pin. Read ONCE
            # per sync; used both to name vacated slots below and to give unchanged
            # pins a baseline they would otherwise never get.
            pushed_fingers = self._load_pushed_fingers()
            _to_push_pins = {str(u.get("pin") or "").strip() for u in to_push}
            # NOT the pins held back by the retry backoff (P3a-2): they were skipped because
            # their push keeps FAILING, and the backfill writes ok=True -- it used to turn a
            # refused member into "in sync" and stop it ever being retried.
            _backoff_pins = set(getattr(self, "_last_backoff_pins", ()) or ())
            self._backfill_pushed_fingers(
                skipped_pins=[p for p in desired_pins
                              if p and p not in _to_push_pins and p not in _backoff_pins],
                templates_by_pin=templates_by_pin,
                hashes_by_pin=hashes_by_pin,
                pushed_fingers=pushed_fingers,
            )
            # P3a-2 item 6: a pass that needs more than the cap pushes the most urgent
            # first. Sorted here, SLICED after capacity admission -- never before the
            # backfill above: a pin sliced off earlier would be backfilled as in sync.
            _cap = _FULL_SYNC_MAX_PINS_PER_PASS
            if len(to_push) > _cap:
                to_push = self._prioritise_for_cap(to_push, templates_by_pin, pushed_fingers)
            # P3a-2 item 7: a write that needs a NEW user or fingerprint slot is refused
            # when the terminal reports none free (CAPACITY_FULL); the pin stays pending.
            to_push, capacity_skipped, capacity_withheld = self._capacity_admit(
                to_push, templates_by_pin, pushed_fingers,
            )
            if capacity_skipped or capacity_withheld:
                pass_incomplete = True
            if len(to_push) > _cap:
                # Only to_push is cut -- never users/desired_pins, which MIRROR, the
                # revoke pass and the prune read as "the roster". A capped-out pin gets
                # no state row: it stays pending and the continuation pushes it.
                capped_out = [str(u.get("pin") or "").strip() for u in to_push[_cap:]]
                to_push = to_push[:_cap]
                pass_incomplete = True
                logger.info(
                    "%s full sync (reason=%s): %d pin(s) need a push -- %d now, %d in the "
                    "next pass (at most %d per pass)", self._prefix, reason,
                    len(to_push) + len(capped_out), len(to_push), len(capped_out), _cap,
                )
                _tel.event("FULL_SYNC_CAPPED", worker=self._tel_wid, cap=_cap,
                           pushing=len(to_push), left=len(capped_out))
            pushed_users = list(to_push)
            batch_attempted = len(to_push)
            try:
                batch_id = insert_push_batch(
                    sync_run_id=None,
                    device_id=self._device_id,
                    device_name=self._device_name,
                    policy=str((self._device or {}).get("rosterPushingPolicy") or "PRESERVE").strip().upper(),
                    status="IN_PROGRESS",
                    created_at=started_iso,
                )
            except Exception:
                logger.debug("%s push-batch row not recorded", self._prefix, exc_info=True)
            if not to_push:
                # Everything desired is already on the terminal with the same
                # content. Skip the COM round-trips entirely; still finish with full
                # bookkeeping so the scheduler records the roster hash and stops
                # re-evaluating this as "changed".
                result = {"ok": True, "pushed": 0, "failed": 0, "templates_failed": 0,
                          "skipped_pin": 0, "chunks_wedged": 0, "errors": [],
                          "failed_pins": []}
                sync_ok = True
                sync_error = ""
                if not users:
                    skipped_note = "desired roster is empty -- nothing to push"
                    logger.info("%s full sync (reason=%s): desired roster is empty -- nothing to push",
                                self._prefix, reason)
                elif capacity_skipped:
                    skipped_note = "nothing pushed: no free slot for the pending pins"
                    logger.info("%s full sync (reason=%s): %d pending pin(s) left for a later "
                                "pass (CAPACITY_FULL)", self._prefix, reason, len(capacity_skipped))
                else:
                    skipped_note = (
                        f"{skipped_unchanged} pin(s) unchanged since the last push -- nothing sent"
                    )
                    logger.info(
                        "%s full sync (reason=%s): all %d desired pins already on the terminal "
                        "-- nothing to push", self._prefix, reason, skipped_unchanged,
                    )
            else:
                if skipped_unchanged:
                    logger.info(
                        "%s full sync (reason=%s): pushing %d new/changed/failed pin(s), "
                        "%d unchanged skipped", self._prefix, reason, len(to_push), skipped_unchanged,
                    )
                to_push_pins = {str(u.get("pin") or "").strip() for u in to_push}
                templates_to_push = {p: t for p, t in (templates_by_pin or {}).items()
                                     if p in to_push_pins}
                # Removals are computed from the FULL desired set below (a withheld
                # finger is still desired -- it must not read as vacated); only the
                # writes leave the withheld fingers out.
                # Slots this member used to have and no longer does. Without this
                # the mirror is write-only and a revoked fingerprint keeps opening
                # the turnstile (Oxyfit, 2026-09-05).
                removals = self._standalone_removals(
                    to_push=to_push, templates_by_pin=templates_to_push,
                    pushed_fingers=pushed_fingers,
                )
                if removals:
                    logger.info("%s clearing %d vacated finger slot(s) across %d pin(s)",
                                self._prefix, sum(len(v) for v in removals.values()),
                                len(removals))
                # WRITE-AHEAD (P3a-2 item 3): the intent is durable BEFORE the first
                # device write; a pass that cannot record it writes nothing.
                if not self._record_push_intents(to_push, hashes_by_pin):
                    result = {"ok": False, "pushed": 0, "failed": len(to_push),
                              "templates_failed": 0, "skipped_pin": 0, "chunks_wedged": 0,
                              "errors": ["push intent not recorded"],
                              "failed_pins": [str(u.get("pin") or "").strip() for u in to_push]}
                    sync_ok = False
                    sync_error = "push intent not recorded"
                else:
                    # Per-pin outcome is recorded per CHUNK (inside), BEFORE mirror/
                    # prune, so a failed pin is remembered as failed even if a later
                    # step raises -- and a crash between chunks loses at most the
                    # chunk in flight, which its intent still covers.
                    # Between two chunks the yield serves doors, rescues and ONE pending
                    # member update or revoke (P3a-2 item 6).
                    self._push_yield_detail = f"reason={reason}"
                    self._pass_touched_pins = pass_touched
                    self._pass_served_members = set()
                    try:
                        result = self._push_with_chunk_recording(
                            to_push,
                            self._without_withheld(templates_to_push, capacity_withheld),
                            hashes_by_pin,
                            removals=removals, bracket=bracket,
                            between_chunks=self._standalone_push_yield,
                            withheld=capacity_withheld,
                        )
                    finally:
                        self._pass_touched_pins = None
                        self._pass_served_members = None
                    _superseded = {
                        str(p if p is not None else "").strip()
                        for p in (result.get("superseded_pins") or [])
                    }
                    # A superseded pin was not sent: it is neither confirmed nor failed.
                    pushed_users = [u for u in to_push
                                    if str(u.get("pin") or "").strip() not in _superseded]
                    if _superseded or pass_touched:
                        # The update served mid-push may itself have failed or been
                        # deferred: do not stamp the roster hash as if this pass covered
                        # those pins; the next pass re-checks them (review R1-24).
                        pass_incomplete = True
                    batch_attempted = len(pushed_users)
                    sync_ok = bool(result.get("ok")) and not self._standalone_failed_pins_from_result(
                        users=pushed_users, result=result,
                    )
                    sync_error = "" if sync_ok else str(
                        (result.get("errors") or [None])[0] or result.get("error") or "push_roster failed"
                    )
            if renewal_holds:
                # RENEWAL ORDERING, second half: the holds whose person's desired pins are
                # ALL confirmed now go, through the same removal as the step above; the rest
                # stay -- state kept (prune keep set), never deleted by MIRROR (its roster),
                # not a removal failure -- until a later pass confirms the new pin.
                # Confirmed now = sent (superseded pins are not), not failed, and not left
                # short of a finger by capacity admission; capped-out and capacity-refused
                # pins were never sent.
                _sent = {str(u.get("pin") or "").strip() for u in pushed_users}
                _confirmed_now = (
                    _sent
                    - self._standalone_failed_pins_from_result(users=pushed_users, result=result)
                    - set(capacity_withheld)
                ) if _sent else set()
                kept_holds, _hold_failed, _hold_errored = self._remove_released_holds(
                    holds=renewal_holds, pin_persons=_pin_persons,
                    unconfirmed=unconfirmed_at_start, confirmed_now=_confirmed_now,
                    touched=pass_touched,
                )
                if _hold_failed or _hold_errored:
                    safe_to_prune = False     # as for a failed removal in the step above
                _failed_first, _errored_first = deferred_retry or ([], False)
                deferred_retry = None
                self._update_removal_retry(
                    failed=list(_failed_first) + sorted(_hold_failed),
                    errored=_errored_first or _hold_errored,
                )
            # MIRROR pushing policy: after a SUCCESSFUL full push, optionally delete
            # device users not in the app roster. Heavily guarded + dry-run by default;
            # a no-op for PRESERVE (the default) and for PullSDK drivers. Never allowed
            # to fail the sync.
            if sync_ok:
                # NOTE: roster_users is the FULL desired roster (`users`), never the
                # incremental `to_push` subset -- MIRROR deletes device users absent
                # from this list, so passing the subset would delete every unchanged
                # member.
                # A capped pass leaves MIRROR to its last continuation. Pins a targeted
                # update handled mid-push (a member enrolled after this snapshot) count
                # as roster, so MIRROR can never delete them (P3a-2 item 6). So do the
                # renewal holds this pass kept (P3b-1).
                if not roster_withheld and not capped_out:
                    _desired_set = {p for p in desired_pins if p}
                    _mirror_roster = list(users) + [
                        {"pin": p, "name": "", "card": ""}
                        for p in sorted((pass_touched | kept_holds) - _desired_set)
                    ]
                    try:
                        self._maybe_mirror_reconcile(full_reconcile=full_reconcile,
                                                     roster_users=_mirror_roster)
                    except Exception as exc:
                        logger.warning("%s MIRROR reconcile error (ignored): %s", self._prefix, exc)
                if (unconfirmed_revoked_ids - set(skipped_revokes) - removed_revokes) \
                        and not safe_to_prune:
                    sync_ok = False
                    sync_error = "authoritative revocation unconfirmed"
                # Forget state for pins no longer desired, so a member who leaves and
                # later returns is pushed again rather than assumed present. Skipped
                # when the revoke pass aborted: pruning would throw away the finger
                # ids those pins still need cleared.
                if safe_to_prune:
                    try:
                        from app.core.db import prune_device_sync_state
                        # + the pins a mid-push targeted update wrote: not in this
                        # snapshot, but their rows are MonClub's ownership proof.
                        # + pins pushed moments ago (the enrolment grace window): their
                        # member may not be in this cache yet (review R2-09).
                        # + the renewal holds kept for a later pass: still on the terminal,
                        # and their row is what lets that pass remove them (P3b-1).
                        prune_device_sync_state(
                            device_id=self._device_id,
                            keep_pins=(list(desired_pins) + sorted(pass_touched)
                                       + sorted(self._mirror_grace_pins())
                                       + sorted(getattr(self, "_last_revoke_grace", ()) or ())
                                       + sorted(kept_holds)),
                        )
                    except Exception:
                        logger.debug("%s per-pin sync state not pruned", self._prefix, exc_info=True)
            # This pass built the roster, pushed and ran its removal step: the day's
            # maintenance slot (intent read-back, finger-slot sweep) may open once the
            # worker is idle -- "after the morning removals", not at a fixed hour: most
            # gyms' PCs are off overnight. guide §3.4a.
            # Only from a COMPLETE roster (review R1-19): an incomplete one (ACCOUNT rows
            # withheld, an empty roster, a removal step the ceiling refused) would drop
            # members from the snapshot, and the batch then cleared their every slot; the
            # read-back would also take their intents for departures.
            if (not roster_withheld and getattr(self, "_last_revoke_step", None) == "ran"
                    and not getattr(self, "_last_revoke_aborted", 0)):
                self._last_desired_pins = {p for p in desired_pins if p}
                self._last_desired_fingers = {
                    p: self._desired_fingers((templates_by_pin or {}).get(p))
                    for p in self._last_desired_pins
                }
                self._last_desired_hashes = {
                    p: (hashes_by_pin or {}).get(p, "") for p in self._last_desired_pins
                }
            # The slot opens after every pass that pushed, whatever its roster: the batch and
            # the read-back use the last COMPLETE snapshot, re-checked per pin (_sweep_check),
            # so an always-incomplete roster no longer suspends them silently (review R2-05).
            self._maintenance_ready_day = _local_day()
        except Exception as exc:
            sync_ok = False
            sync_error = str(exc)
            if deferred_retry is not None:
                # The pass stopped between its removal step and the post-push removal of
                # the renewal holds: report the step's own outcome, once. The holds were
                # never attempted; their state is kept (no prune ran).
                self._update_removal_retry(failed=list(deferred_retry[0]),
                                           errored=deferred_retry[1])
                deferred_retry = None
                _tel.event("RENEWAL_HOLD", worker=self._tel_wid, held=len(renewal_holds),
                           removed_after_push=0, kept=len(renewal_holds))
        duration_ms = max(0.0, (time.time() - started_at) * 1000.0)
        if batch_id is not None:
            try:
                # A pin named by failed_pins is unconfirmed even when its user row
                # landed (for example, a tracked fingerprint slot refused removal).
                # Count per PIN from the same conservative normalization used by
                # retry state instead of trusting contradictory aggregate counters.
                failed_pins = self._standalone_failed_pins_from_result(
                    users=pushed_users if batch_attempted else [], result=result,
                )
                skipped_pins = max(0, int(result.get("skipped_pin") or 0))
                pins_failed = len(failed_pins)
                pins_success = max(0, batch_attempted - pins_failed - skipped_pins)
                update_push_batch(
                    id=batch_id,
                    pins_attempted=batch_attempted,
                    pins_success=pins_success,
                    pins_failed=pins_failed,
                    status=("SUCCESS" if sync_ok else ("PARTIAL" if pins_success else "FAILED")),
                    duration_ms=int(duration_ms),
                    # A no-op reconcile would otherwise read "0/0 pins" with no
                    # explanation; say why nothing was sent.
                    error_message=(_push_safety.join_notes(
                        sync_error or skipped_note or "",
                        _push_safety.outcome_note(
                            _push_safety.REVOKE_ABORTED, self._last_revoke_aborted,
                            "standalone_revoke",
                        ) if getattr(self, "_last_revoke_aborted", 0) else "",
                        _push_safety.outcome_note(
                            _push_safety.SKIPPED_NOT_OWNED, len(skipped_revokes),
                            "pins " + ",".join(sorted(skipped_revokes.values())[:20]),
                        ) if skipped_revokes else "",
                        _push_safety.outcome_note(
                            _push_safety.CAPACITY_FULL,
                            len(capacity_skipped) + len(capacity_withheld),
                            "pins " + ",".join((capacity_skipped + sorted(capacity_withheld))[:20])
                            + (f"; fingers withheld for {len(capacity_withheld)}"
                               if capacity_withheld else ""),
                        ) if (capacity_skipped or capacity_withheld) else "",
                        _push_safety.outcome_note(
                            _push_safety.PUSH_CAPPED, len(capped_out),
                            f"{_FULL_SYNC_MAX_PINS_PER_PASS} per pass; the rest next pass",
                        ) if capped_out else "",
                    ) or None),
                )
            except Exception:
                logger.debug("%s push-batch row not finalised", self._prefix, exc_info=True)
        _tel.event("FULL_SYNC_DONE", worker=self._tel_wid, reason=reason, ok=sync_ok,
                   dur_ms=round(duration_ms), pushed=result.get("pushed"),
                   failed=result.get("failed"), skipped_unchanged=skipped_unchanged)
        self._mark_full_sync_finished(reason=reason, ok=sync_ok,
                                      duration_ms=duration_ms, error=sync_error)
        # SKIPPED_NOT_OWNED ids were finalised when they were skipped; they must not go
        # back to the scheduler for a retry that could never succeed.
        effective_revoked_ids = normalized_revoked_ids - set(skipped_revokes) - removed_revokes
        if removed_revokes:
            # A stale cache snapshot must not push them back: the next passes check the
            # database for these members for _REMOVED_MEMBER_GUARD_SEC (review R4-11).
            self._arm_removed_member_guard(removed_revokes)
        if not sync_ok and removed_revokes:
            # Their physical revoke is DONE (removals run first): release the revocation and
            # its roster exclusion now. Left ACTIVE they excluded the member from every later
            # roster until a restart (R3-14); kept at RETRY they refused a membership restored
            # meanwhile, and the next successful pass left that paying member off the terminal
            # while reporting the roster in sync (R5-03). The stale-cache risk is covered by
            # the database guard above instead.
            self._finalize_full_sync_revokes(
                set(removed_revokes), ok=True, excluded_ids=set(removed_revokes),
            )
        if not sync_ok:
            self._finalize_full_sync_revokes(
                effective_revoked_ids,
                ok=False,
                excluded_ids=normalized_excluded_ids,
            )
        self._notify_full_sync_finished(
            reason=reason, ok=sync_ok,
            fingerprint_hash=fingerprint_hash if (sync_ok and not pass_incomplete) else None,
            duration_ms=duration_ms, error=sync_error,
            revoked_ids=effective_revoked_ids if not sync_ok else set(),
        )
        if sync_ok:
            self._finalize_full_sync_revokes(
                normalized_revoked_ids,
                ok=True,
                excluded_ids=normalized_excluded_ids,
            )
        # P3a-2 item 6: a capped pass queues its own continuation -- only when it wrote
        # something, so a terminal refusing everything cannot loop; the scheduler's own
        # retry (the roster hash was withheld) covers that case. The roster hash is
        # carried: the continuation builds its roster from a cache at least as new.
        if capped_out and int((result or {}).get("pushed") or 0) > 0:
            self.request_full_sync(reason="push-capped", fingerprint_hash=fingerprint_hash,
                                   full_reconcile=full_reconcile)

    def _arm_removed_member_guard(self, member_ids) -> None:
        """MonClub just finished revoking these memberships (see _REMOVED_MEMBER_GUARD_SEC:
        not always a deleted pin): for that long the passes check the database before a
        (possibly stale) cache may push them back. Only rows of THESE membership ids are
        ever excluded, and only while the database no longer has them."""
        guard = getattr(self, "_recent_removed_members", None)
        if guard is None:
            guard = self._recent_removed_members = {}
        now = time.monotonic()
        for member_id in member_ids or ():
            guard[int(member_id)] = now

    def _recently_removed_still_gone(self) -> set[int] | None:
        """Members MonClub removed within _REMOVED_MEMBER_GUARD_SEC that the DATABASE still
        does not have: excluded from this pass, whatever the (possibly stale) cache says
        (review R4-11). A member present again (a restored membership) leaves the guard.
        ONE query for all of them (review R6-07). None = the read failed: the caller must
        not decide either way (review R6-06)."""
        guard = getattr(self, "_recent_removed_members", None) or {}
        if not guard:
            return set()
        now = time.monotonic()
        for member_id, at in list(guard.items()):
            if now - float(at) > _REMOVED_MEMBER_GUARD_SEC:
                guard.pop(member_id, None)
        if not guard:
            return set()
        try:
            from app.core.db import list_sync_users_by_active_membership_ids
            rows = list_sync_users_by_active_membership_ids(sorted(guard)) or []
        except Exception:
            logger.warning("%s recently removed members: database read failed", self._prefix,
                           exc_info=True)
            return None
        present: set[int] = set()
        for row in rows:
            try:
                present.add(int(row.get("activeMembershipId")))
            except (TypeError, ValueError, AttributeError):
                continue
        for member_id in present:
            guard.pop(member_id, None)
        return {int(m) for m in guard}

    def _skip_unowned_revocations(self, skipped: Dict[int, str], rows_seen: set[str]) -> None:
        """Drop explicit revocations of pins MonClub cannot prove it owns (FINAL).

        Never deletes, never neutralises: those pins may be another system's users on a
        shared terminal. The physical-revoke phase is finalised as done so no later
        full sync retries it; the roster exclusion stays with the pass, so the member is
        still never re-pushed from a stale snapshot. Contrast REVOKE_ABORTED (retryable).
        """
        for member_id, pin in sorted(skipped.items()):
            row = "unconfirmed" if pin in rows_seen else "absent"
            logger.critical(
                "%s revocation SKIPPED_NOT_OWNED: membership %s pin %s (%s row) -- MonClub "
                "has no proof it wrote this device user, so it is never deleted; the rest "
                "of the pass continues",
                self._prefix, member_id, pin, row,
            )
            try:
                _tel.warn(
                    "MEMBER_REVOKE_SKIPPED_NOT_OWNED", worker=self._tel_wid,
                    member_id=member_id, pin=pin, row=row, protocol="ZK_STANDALONE",
                )
            except Exception:
                pass
        self._finalize_full_sync_revokes(set(skipped), ok=True, excluded_ids=set())

    def _member_row_in_db(self, member_id: int) -> list[Dict[str, Any]] | None:
        """The member's own row, read straight from sync_users. None = read failed.

        Deliberately NOT the process-wide sync cache. That snapshot is shared, has a
        5 s TTL, is served STALE while a background refresh runs, and a full scan of
        it cost 7 s on the live worker in the field. For a decision about ONE member
        it is both slower and less truthful than this direct read -- which is itself a
        scan of sync_users, NOT an indexed lookup: no index serves active_membership_id
        alone (EXPLAIN QUERY PLAN; P3a-2 review R6-07, guide §3.4b for its measured cost).
        """
        try:
            from app.core.db import list_sync_users_by_active_membership_ids
            return list(list_sync_users_by_active_membership_ids([int(member_id)]) or [])
        except Exception:
            logger.debug("%s targeted member read failed", self._prefix, exc_info=True)
            return None

    def _load_member_roster(self, member_id: int, *, fresh: bool = False):
        """Build the single-member roster, preferring a targeted DB read.

        WHY THE DB AND NOT THE SNAPSHOT. Field incident 2026-09-06 16:29:20: a member
        sync ran off a snapshot taken BEFORE a revocation and re-pushed the deleted
        fingerprint to the terminal, then stamped device_sync_state with the hash of
        that pre-deletion roster -- so no later sync ever saw a difference and the
        revoked finger kept opening the door. A targeted read is taken after the
        write commits and cannot reproduce that.

        The cache remains the FALLBACK, not dead code: a member created offline has
        no sync_users row at all and is only visible through the cache's
        projected-offline merge. Dropping to it costs a snapshot load, which is why
        it is second and not first.

        ``fresh`` still bypasses the cache TTL for that fallback -- clear_cached=True
        forces an INLINE load, because with a snapshot held load_sync_cache returns
        the stale one and refreshes in the background.
        """
        rows = self._member_row_in_db(member_id)
        if rows:
            # ACCOUNT: the device row is the collapse of EVERY membership of the person, so
            # read all of the person's rows, not just the one that changed.
            rows = self._person_rows_for_member(member_id, rows)
            return self._build_standalone_roster(
                SimpleNamespace(users=rows), only_member_ids={int(member_id)},
            )
        if fresh:
            try:
                invalidate_sync_cache(clear_cached=True)
            except Exception:
                logger.debug("%s could not force a fresh sync cache", self._prefix, exc_info=True)
        cache = load_sync_cache()
        if cache is None:
            return [], {}, {}
        return self._build_standalone_roster(cache, only_member_ids={int(member_id)})

    def _defer_member_sync(self, member_id: int, *, reason: str) -> None:
        """Flag the pin so the periodic full sync is guaranteed to re-evaluate it.

        Returning quietly here is precisely what lost a revocation in the field:
        the caller treats a plain return as success, and _standalone_pins_needing_push
        then skips the pin forever because its stored row still reads last_ok=1.
        Marking it NOT-ok routes it back through the existing, proven retry channel.
        The CASE WHEN excluded.last_ok = 1 guard in the upsert preserves both
        desired_hash and pushed_finger_ids, so flagging costs us no knowledge of
        what is actually resident on the terminal.

        Only a pin we have ALREADY pushed is flagged. Inventing a row for a member
        we have never seen would resurrect pins that prune_device_sync_state
        deliberately removed, and each stray sync request would re-add them.
        """
        pin = str(member_id or "").strip()
        # WHY the roster was empty, not just THAT it was. Reading the field log of
        # 2026-09-06 there was no way to tell "the row was deleted" from "a filter
        # rejected it" -- two completely different bugs behind one message. It cost
        # hours. in_db is that discriminator, and it is one read of sync_users (a table
        # scan, not an indexed lookup -- see _member_row_in_db):
        #   in_db=False -> the sync_users row is GONE (the signature of the backend
        #                  emitting an ACTIVE_MEMBERSHIP delete for a credential
        #                  deletion, fixed in monclub_backend a933338d)
        #   in_db=True  -> the row exists and something FILTERED it out
        #                  (allowedMemberships, validity, pin derivation)
        _rows = self._member_row_in_db(member_id)
        in_db = None if _rows is None else bool(_rows)
        if pin and self._pin_scheme_is_account():
            # The flag must land on the pin the device holds -- the person's. A membership
            # number here would flag (at best) nothing and (at worst) another person's pin.
            try:
                pin = self._device_pins_for_members({int(member_id)}, users=_rows or []).get(
                    int(member_id), ""
                )
            except Exception:
                pin = ""
            if not pin:
                logger.warning(
                    "%s member sync deferred: pinScheme=ACCOUNT and membership %s has no "
                    "known person pin -- nothing flagged; the next full sync reconciles.",
                    self._prefix, member_id,
                )
        # Inside a full-sync push (P3a-2 item 6) the push must not re-send this member
        # from its snapshot after the targeted path found them gone or unreadable.
        self._note_push_superseded([pin])
        logger.warning(
            "%s member sync deferred: member %s -- %s (row in sync_users: %s). "
            "Flagged for the next full sync rather than reported as synced.",
            self._prefix, member_id, reason,
            "yes" if in_db else ("unknown" if in_db is None else "NO"),
        )
        try:
            _tel.warn("MEMBER_SYNC_DEFERRED", worker=self._tel_wid,
                      member_id=member_id, reason=reason, in_db=in_db)
        except Exception:
            pass
        if not pin:
            return
        try:
            from app.core.db import (
                list_device_sync_hashes_and_status,
                save_device_sync_state_batch,
            )
            state = list_device_sync_hashes_and_status(device_id=self._device_id) or {}
            if pin not in state:
                return
            # hash="" and fingers=None are both ignored by the ok=0 branch of the
            # upsert. The empty hash ALSO marks this as a DEFERRAL rather than a
            # push failure, so the upsert leaves fail_streak and last_attempt_hash
            # untouched (see save_device_sync_state_batch). That matters: counting
            # deferrals would burn a member's free retry attempts, so their FIRST
            # genuine failure would land already inside the bounded-retry backoff.
            # So only last_ok/last_error actually change.
            save_device_sync_state_batch(
                device_id=self._device_id,
                rows=[(pin, "", False, reason, None)],
            )
        except Exception:
            logger.debug("%s could not flag pin %s for retry", self._prefix, pin, exc_info=True)

    def _run_standalone_member_sync(self, member_id: int) -> None:
        """Targeted single-member push for a push driver. Failure logs + telemetry
        (no endless re-queue — the periodic full sync is the safety net)."""
        _tel.set_state(self._tel_wid, "member_sync", f"member={member_id}")
        _ms_t0 = time.monotonic()
        try:
            users, templates_by_pin, hashes_by_pin = self._load_member_roster(member_id)
            if not users:
                # The member may be only TRANSIENTLY absent. load_sync_cache has a
                # 5 s TTL and is rebuilt right after a delta write, while a targeted
                # member sync is routed within seconds of that same write -- so this
                # path runs exactly when the snapshot is most likely to be in flux.
                # Field trace 2026-09-06: the delete of finger 2 landed at 14:19:57,
                # the member sync read an empty roster at 14:20:01, and the member
                # was visible again at 14:20:13. Re-read ONCE, bypassing the TTL,
                # before concluding anything about this member.
                users, templates_by_pin, hashes_by_pin = self._load_member_roster(
                    member_id, fresh=True,
                )
            if not users:
                self._defer_member_sync(
                    member_id, reason="member not visible in the sync cache",
                )
                return
            # Served between two chunks of a full-sync push (P3a-2 item 6): these pins'
            # data in that push is now older than this update's. No-op otherwise.
            self._note_push_superseded(u.get("pin") for u in users)
            # Same vacated-slot removal as the full sync. This path runs seconds
            # after a dashboard change, so without it a revoked finger stays live
            # until the next full sync happens to pick the pin up.
            pushed_fingers = self._load_pushed_fingers(pins=[u.get("pin") for u in users])
            removals = self._standalone_removals(
                to_push=users, templates_by_pin=templates_by_pin,
                pushed_fingers=pushed_fingers,
            )
            if removals:
                logger.info("%s member sync: clearing %d vacated finger slot(s) for pin(s) %s",
                            self._prefix, sum(len(v) for v in removals.values()),
                            ",".join(sorted(removals)))
            # P3a-2 item 7: a member certainly not on the terminal gets no write when no
            # user slot is free; fingers without a free slot are withheld. Decided BEFORE
            # the intent (review R1-29): a refused push must not rewrite what the intent
            # says MonClub put on the terminal.
            users, _cap_skipped, cap_withheld = self._capacity_admit(
                users, templates_by_pin, pushed_fingers,
            )
            if not users:
                self._defer_member_sync(member_id, reason="CAPACITY_FULL")
                return
            if not self._record_push_intents(users, hashes_by_pin):
                # Write-ahead (P3a-2): no record, no write. Flagged for the full sync.
                self._defer_member_sync(member_id, reason="push intent not recorded")
                return
            # P3a-2 item 5: an owned pin never swept -- read BEFORE the push, which may
            # itself confer ownership -- has its unused slots cleared right after it.
            sweep_plan = self._finger_sweep_plan(users, templates_by_pin)
            result = self._sdk.push_roster(users,
                                           self._without_withheld(templates_by_pin, cap_withheld),
                                           remove_fingers_by_pin=removals)
            # Record this pin's outcome. On success the next hash-triggered full
            # sync sees it as already-synced and skips it -- this is what stops an
            # enrolment from cascading into a whole-roster push. On failure it is
            # recorded ok=False so that full sync retries exactly this pin. A pin whose
            # fingers were withheld (CAPACITY_FULL) is not in sync either.
            self._record_standalone_pin_state(
                users=users, hashes_by_pin=hashes_by_pin,
                result=self._with_withheld_failed(
                    result, (u.get("pin") for u in users), cap_withheld),
                templates_by_pin=self._without_withheld(templates_by_pin, cap_withheld),
                unknown_fingers_pins={p for p, plan in sweep_plan.items() if plan["unknown"]},
            )
            # What is resident for a pin whose fingers were withheld (review R3-12, the
            # targeted path -- the full sync records it per chunk).
            self._record_withheld_residents(
                users, result, self._without_withheld(templates_by_pin, cap_withheld),
                cap_withheld)
            if sweep_plan:
                # The outcome as RECORDED: a pin whose fingers capacity withheld is not in
                # sync, so it is not swept either -- the sweep would record the withheld
                # finger as resident (review R2-02).
                _failed = self._standalone_failed_pins_from_result(
                    users=users,
                    result=self._with_withheld_failed(
                        result, (u.get("pin") for u in users), cap_withheld),
                )
                for _pin, _plan in sorted(sweep_plan.items()):
                    if _pin in _failed:
                        continue
                    self._yield_during_device_work()
                    if self._sweep_pin(_pin, _plan["slots"], source="targeted"):
                        self._mark_swept(_pin, _plan["desired"])
            if not result.get("ok"):
                _tel.warn("MEMBER_SYNC_FAILED", worker=self._tel_wid,
                          member_id=member_id, err="push_roster")
                # A user row that landed makes the pin MonClub's (review R1-14): it needs the
                # same enrolment grace as a clean push, or a removals-first pass built from
                # a cache that does not list the member yet deletes them (review R2-24).
                self._note_recent_pushes(result.get("user_written") or [])
            else:
                # grace window: mark these pins as just-pushed so a MIRROR full sync
                # racing this enroll/change can't delete them before the roster catches up.
                self._note_recent_pushes(u.get("pin") for u in users)
        except Exception as exc:
            logger.warning("%s standalone member sync failed: member_id=%s err=%s",
                           self._prefix, member_id, exc)
            self._defer_member_sync(
                member_id,
                reason=f"targeted push exception: {type(exc).__name__}",
            )
            _tel.warn("MEMBER_SYNC_FAILED", worker=self._tel_wid,
                      member_id=member_id, err=type(exc).__name__)
        finally:
            _tel.event("MEMBER_SYNC_DONE", worker=self._tel_wid, member_id=member_id,
                       dur_ms=round((time.monotonic() - _ms_t0) * 1000),
                       pending=len(self._pending_member_syncs))

    def _remove_standalone_pins(
        self,
        *,
        pins: list[str],
        pushed_fingers: dict[str, set[int] | None],
    ) -> _StandalonePinRemovalResult:
        """Delete owned pins, accepting only internally consistent confirmations."""
        requested: list[str] = []
        seen: set[str] = set()
        for raw_pin in pins or []:
            pin = str(raw_pin if raw_pin is not None else "").strip()
            if pin and pin not in seen:
                requested.append(pin)
                seen.add(pin)

        requested_set = set(requested)
        deleted: set[str] = set()
        delete_failed = set(requested)
        deleter = getattr(self._sdk, "delete_users", None)
        if requested and callable(deleter):
            try:
                result = deleter(requested) or {}
                if isinstance(result, dict):
                    ok = result.get("ok")
                    deleted_count = result.get("deleted")
                    failed_count = result.get("failed")
                    reported = result.get("failed_pins")
                    counts_valid = (
                        type(deleted_count) is int
                        and deleted_count >= 0
                        and type(failed_count) is int
                        and failed_count >= 0
                    )
                    pins_valid = isinstance(reported, list)
                    reported_list = (
                        [str(pin if pin is not None else "").strip() for pin in reported]
                        if pins_valid else []
                    )
                    reported_set = set(reported_list)
                    contract_valid = (
                        type(ok) is bool
                        and counts_valid
                        and pins_valid
                        and all(reported_list)
                        and len(reported_list) == len(reported_set)
                        and reported_set <= requested_set
                        and deleted_count + failed_count == len(requested)
                        and deleted_count == len(requested) - len(reported_set)
                        and failed_count == len(reported_set)
                        and ok is (failed_count == 0)
                    )
                    if contract_valid:
                        delete_failed = reported_set
                        deleted = requested_set - delete_failed
                    else:
                        logger.warning(
                            "%s delete-users result was ambiguous -- neutralising all "
                            "requested pins: %r",
                            self._prefix,
                            result,
                        )
                else:
                    logger.warning(
                        "%s delete-users returned a malformed result -- neutralising all "
                        "requested pins",
                        self._prefix,
                    )
            except Exception:
                logger.warning(
                    "%s delete-users call failed -- neutralising requested pins",
                    self._prefix,
                    exc_info=True,
                )
        elif requested:
            logger.warning("%s driver cannot delete users -- neutralising instead", self._prefix)

        neutralised: set[str] = set()
        failed: set[str] = set()
        for pin in sorted(delete_failed):
            finger_ids = sorted(set(pushed_fingers.get(pin) or ()))
            removals = {pin: finger_ids} if finger_ids else {}
            users = [
                {"pin": pin, "name": "", "card": "", "enabled": False},
            ]
            logger.warning(
                "%s pin %s survived or had an ambiguous delete -- neutralising "
                "(clearing %d slot(s))",
                self._prefix,
                pin,
                len(finger_ids),
            )
            try:
                fallback = self._sdk.push_roster(
                    users, {}, remove_fingers_by_pin=removals,
                ) or {}
                numeric_fields = (
                    "pushed",
                    "failed",
                    "templates_failed",
                    "skipped_pin",
                    "chunks_wedged",
                    "del_attempted",
                    "del_ok",
                )
                counts_valid = isinstance(fallback, dict) and all(
                    type(fallback.get(field)) is int and fallback[field] >= 0
                    for field in numeric_fields
                )
                fallback_confirmed = (
                    isinstance(fallback, dict)
                    and fallback.get("ok") is True
                    and counts_valid
                    and fallback.get("pushed") == 1
                    and fallback.get("failed") == 0
                    and fallback.get("templates_failed") == 0
                    and fallback.get("skipped_pin") == 0
                    and fallback.get("chunks_wedged") == 0
                    and fallback.get("failed_pins") == []
                    and fallback.get("del_attempted") == len(finger_ids)
                    and fallback.get("del_ok") == len(finger_ids)
                )
                if fallback_confirmed:
                    neutralised.add(pin)
                else:
                    failed.add(pin)
                    logger.warning(
                        "%s revoke fallback for pin %s was unconfirmed -- keeping state: %r",
                        self._prefix,
                        pin,
                        fallback,
                    )
            except Exception:
                failed.add(pin)
                logger.warning(
                    "%s revoke fallback raised for pin %s -- keeping state for retry",
                    self._prefix,
                    pin,
                    exc_info=True,
                )

        return _StandalonePinRemovalResult(
            deleted=frozenset(deleted),
            neutralised=frozenset(neutralised),
            failed=frozenset(failed),
        )

    # ------------------------------------------------------------------ #
    # pinScheme helpers: every request names a MEMBERSHIP; the device row is keyed by the
    # device's scheme. guide §3.2b.
    # ------------------------------------------------------------------ #
    def _pin_scheme_is_account(self) -> bool:
        from app.core.device_sync import PIN_SCHEME_ACCOUNT, device_pin_scheme

        return device_pin_scheme(self._device) == PIN_SCHEME_ACCOUNT

    def _device_pins_for_members(self, member_ids, *, users=None) -> Dict[int, str]:
        from app.core.device_sync import device_pin_scheme, device_pins_for_members

        return device_pins_for_members(member_ids, scheme=device_pin_scheme(self._device),
                                      users=users)

    def _person_rows_for_member(self, member_id: int, rows: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        """Under ACCOUNT, every cached row of the person behind ``member_id`` (falls back to
        ``rows`` when the person cannot be named or the read fails). MEMBERSHIP: ``rows``."""
        if not self._pin_scheme_is_account():
            return rows
        try:
            acct = self._device_pins_for_members({int(member_id)}, users=rows).get(int(member_id))
            if not acct:
                return rows
            from app.core.db import list_sync_users_by_main_account_ids

            person = list(list_sync_users_by_main_account_ids({int(acct)}) or [])
            return person or rows
        except Exception:
            logger.debug("%s person rows read failed", self._prefix, exc_info=True)
            return rows

    def _required_revocation_pins(
        self,
        unconfirmed_revoked_ids: set[int],
        desired_pins,
        revoked_pin_of: Dict[int, str],
    ) -> set[str]:
        """Pins an explicit revocation must see REMOVED.

        MEMBERSHIP: every revoked membership id, as before. ACCOUNT: only the person pins that
        left the desired roster -- a person who still holds another membership this device
        accepts is satisfied by the full sync's re-push, not by removal (requiring removal of a
        pin that is still desired would fail the sync forever). An unmappable membership names
        no pin; the revoke pass still removes every owned pin that left the roster.
        """
        if not self._pin_scheme_is_account():
            return {str(member_id) for member_id in unconfirmed_revoked_ids}
        desired = {str(p).strip() for p in (desired_pins or ())}
        return {
            pin for member_id, pin in (revoked_pin_of or {}).items()
            if member_id in unconfirmed_revoked_ids and pin not in desired
        }

    def _account_member_revoke(self, member_id: int) -> tuple[bool | None, str]:
        """ACCOUNT half of ``_run_standalone_member_revoke``. Returns ``(result, pin)``.

        ``result`` True/False: handled here -- the person's collapsed row was RE-PUSHED, or the
        revoke could not proceed. ``None``: nothing of the person remains deliverable to this
        device, so ``pin`` goes through the normal ownership-checked removal.
        """
        acct = ""
        try:
            rows = self._member_row_in_db(member_id) or []
            acct = self._device_pins_for_members({member_id}, users=rows).get(member_id, "")
        except Exception:
            logger.warning("%s member revoke: person pin lookup failed for membership %s",
                           self._prefix, member_id, exc_info=True)
        if not acct:
            logger.critical(
                "%s member revoke: pinScheme=ACCOUNT and membership %s cannot be mapped to its "
                "person's pin (no cached or linked mainAccountId). NOT removing by the "
                "membership number, which may be another person's account pin; deferring to "
                "full reconciliation.",
                self._prefix, member_id,
            )
            _tel.warn("MEMBER_REVOKE_PIN_UNKNOWN", worker=self._tel_wid, member_id=member_id)
            self.request_full_sync(reason="revoke-pin-unknown", revoked_ids={member_id})
            return False, ""
        try:
            from app.core.db import list_sync_users_by_main_account_ids

            remaining = []
            for row in list_sync_users_by_main_account_ids({int(acct)}) or []:
                try:
                    if int(row.get("activeMembershipId")) == int(member_id):
                        continue  # defensively: the revoked plan never counts
                except (TypeError, ValueError):
                    pass
                remaining.append(row)
        except Exception:
            logger.warning("%s member revoke: person rows unreadable for pin %s",
                           self._prefix, acct, exc_info=True)
            _tel.warn("MEMBER_REVOKE_FAILED", worker=self._tel_wid, member_id=member_id, pin=acct)
            self.request_full_sync(reason="revoke-failed", revoked_ids={member_id})
            return False, acct
        users, templates_by_pin, hashes_by_pin = self._build_standalone_roster(
            SimpleNamespace(users=remaining)
        )
        entry = next((u for u in users if str(u.get("pin") or "").strip() == acct), None)
        if entry is None:
            from app.core.device_sync import DeviceSyncEngine, account_roster_withheld_for_device

            withheld = account_roster_withheld_for_device(
                DeviceSyncEngine(cfg=self._cfg or SimpleNamespace(), logger=logger),
                dict(self._device or {}),
            )
            if withheld:
                # Nothing NAMED of this person remains, but rows without mainAccountId are
                # withheld from this device and one of them may be theirs. Removing now could
                # strip a paying member; defer to the full sync, which also refuses removals
                # on an incomplete roster.
                logger.warning(
                    "%s member revoke: pin %s not removed -- %d deliverable row(s) have no "
                    "mainAccountId, so the person cannot be proven gone",
                    self._prefix, acct, withheld,
                )
                _tel.warn("MEMBER_REVOKE_FAILED", worker=self._tel_wid, member_id=member_id,
                          pin=acct)
                self.request_full_sync(reason="revoke-roster-incomplete", revoked_ids={member_id})
                return False, acct
            return None, acct
        _tel.event("MEMBER_REVOKE_REQUESTED", worker=self._tel_wid, member_id=member_id, pin=acct)
        templates = {acct: templates_by_pin[acct]} if acct in (templates_by_pin or {}) else {}
        ok = False
        try:
            removals = self._standalone_removals(
                to_push=[entry], templates_by_pin=templates,
                pushed_fingers=self._load_pushed_fingers(pins=[acct]),
            )
            if not self._record_push_intents([entry], hashes_by_pin):
                raise RuntimeError("push intent not recorded")
            result = self._sdk.push_roster([entry], templates, remove_fingers_by_pin=removals)
            self._record_standalone_pin_state(
                users=[entry], hashes_by_pin=hashes_by_pin, result=result,
                templates_by_pin=templates,
            )
            # The same enrolment grace a targeted push gets (review R2-24, R3-13): a
            # removals-first pass from a cache that predates the renewal must not delete it.
            self._note_recent_pushes((result or {}).get("user_written") or [])
            ok = bool(result.get("ok")) and not self._standalone_failed_pins_from_result(
                users=[entry], result=result,
            )
        except Exception:
            logger.warning("%s member revoke: re-push of pin %s failed", self._prefix, acct,
                           exc_info=True)
            ok = False
        if ok:
            logger.info(
                "%s member revoke: membership %s left; person pin %s still holds another "
                "membership this device accepts -- re-pushed the collapsed row instead of "
                "deleting it", self._prefix, member_id, acct,
            )
            _tel.event("MEMBER_REVOKE_DONE", worker=self._tel_wid, member_id=member_id,
                       pin=acct, mode="repushed", ok=True)
            return True, acct
        _tel.warn("MEMBER_REVOKE_FAILED", worker=self._tel_wid, member_id=member_id, pin=acct)
        self.request_full_sync(reason="revoke-failed", revoked_ids={member_id})
        return False, acct

    def _run_standalone_member_revoke(self, member_id: int) -> bool:
        """Immediately remove one authoritative, MonClub-owned standalone PIN.

        Under pinScheme=ACCOUNT the pin is the PERSON: revoking one membership removes the pin
        only when nothing of that person remains deliverable to this device; otherwise the
        collapsed row is re-pushed (``_account_member_revoke``). guide §3.2b.
        """
        if self._pin_scheme_is_account():
            handled, pin = self._account_member_revoke(int(member_id))
            # Served inside a full-sync push (P3a-2 item 6): that push must not re-send
            # this person from its older snapshot, whatever the outcome here.
            self._note_push_superseded([pin])
            if handled is not None:
                return handled
        else:
            pin = str(int(member_id))
            self._note_push_superseded([pin])
        _tel.event(
            "MEMBER_REVOKE_REQUESTED",
            worker=self._tel_wid,
            member_id=member_id,
            pin=pin,
        )
        try:
            from app.core.db import list_confirmed_device_sync_pins

            owned = list_confirmed_device_sync_pins(device_id=self._device_id) or set()
        except Exception:
            logger.warning(
                "%s member revoke: ownership state unreadable for pin %s",
                self._prefix,
                pin,
                exc_info=True,
            )
            _tel.warn(
                "MEMBER_REVOKE_FAILED",
                worker=self._tel_wid,
                member_id=member_id,
                pin=pin,
            )
            self.request_full_sync(reason="revoke-failed", revoked_ids={member_id})
            return False

        if pin not in owned:
            # FINAL (P3a-2 item 4): MonClub cannot prove it wrote this pin, so it never
            # deletes it -- on a shared terminal it may be another system's user. It used
            # to escalate into a full sync that then refused (or aborted its whole revoke
            # pass) on every run, forever. The revocation is finished and reported.
            logger.critical(
                "%s member revoke SKIPPED_NOT_OWNED: no MonClub ownership proof for pin %s "
                "-- nothing deleted, revocation finished",
                self._prefix,
                pin,
            )
            _tel.warn(
                "MEMBER_REVOKE_SKIPPED_NOT_OWNED",
                worker=self._tel_wid,
                member_id=member_id,
                pin=pin,
                protocol="ZK_STANDALONE",
            )
            self._note_revoke_skipped(member_id)
            return True

        outcome = self._remove_standalone_pins(
            pins=[pin],
            pushed_fingers=self._load_pushed_fingers(pins=[pin]),
        )
        if pin in outcome.removed and pin not in outcome.failed:
            from app.core.db import clear_device_revocation_state

            try:
                clear_device_revocation_state(device_id=self._device_id, pin=pin)
            except Exception:
                logger.warning(
                    "%s could not atomically clear local revoke state for pin %s",
                    self._prefix,
                    pin,
                    exc_info=True,
                )
                _tel.warn(
                    "MEMBER_REVOKE_FAILED",
                    worker=self._tel_wid,
                    member_id=member_id,
                    pin=pin,
                )
                self.request_full_sync(reason="revoke-failed", revoked_ids={member_id})
                return False
            mode = "deleted" if pin in outcome.deleted else "neutralised"
            _tel.event(
                "MEMBER_REVOKE_DONE",
                worker=self._tel_wid,
                member_id=member_id,
                pin=pin,
                mode=mode,
                ok=True,
            )
            return True

        _tel.warn(
            "MEMBER_REVOKE_FAILED",
            worker=self._tel_wid,
            member_id=member_id,
            pin=pin,
        )
        self.request_full_sync(reason="revoke-failed", revoked_ids={member_id})
        return False

    # ------------------------------------------------------------------ #
    # MIRROR pushing policy (destructive reconcile) — helpers + consumer
    # ------------------------------------------------------------------ #
    def _note_recent_pushes(self, pins) -> None:
        """Record pins we just pushed (member sync) with a monotonic timestamp, for the
        MIRROR grace window. Prunes entries older than the grace window."""
        m = getattr(self, "_recent_member_push", None)
        if m is None:
            m = {}
            self._recent_member_push = m
        now = time.monotonic()
        for p in pins or []:
            s = str(p or "").strip()
            if s:
                m[s] = now
        cutoff = now - _MIRROR_ENROLL_GRACE_SEC
        for k in [k for k, v in m.items() if v < cutoff]:
            m.pop(k, None)

    def _neutralise_revoked_pins(
        self,
        *,
        desired_pins: set[str],
        roster_count: int,
        required_pins: set[str] | None = None,
        hold_persons: set[int] | None = None,
        hold_exempt: set[str] | None = None,
    ) -> bool:
        """Strip credentials from pins we pushed that are no longer desired.

        WHY THIS EXISTS. On a ZK_STANDALONE terminal the DEVICE decides and opens;
        the PC only observes the resulting rtlog ("reason=DEVICE_ALLOWED"). There is
        no PC-side veto. So a credential left on the terminal IS access, and a member
        whose membership went CANCELED / COMPLETED / INACTIVE / PENDING / EXPIRED,
        or who was frozen or had their plan withdrawn, kept walking through the
        turnstile indefinitely. `[FIELD: Oxyfit 2026-09-06 — every one of those
        statuses was set in turn and the member still entered]` The backend was
        right to drop them (shouldExposeMembership); the client simply never told
        the device.

        The only pre-existing removal path, _maybe_mirror_reconcile -> delete_users,
        returns immediately unless rosterPushingPolicy == "MIRROR" — and PRESERVE is
        the default every gym runs.

        DELETE, WITH NEUTRALISE AS FALLBACK. Whole-user deletion is field-proven for
        backup number 12. A failed or unsupported delete is rewritten disabled with
        blank card/name while only locally tracked fingerprint slots are cleared.

        OWNERSHIP IS THE SAFETY PROPERTY. The candidate set comes from
        device_sync_state — pins THIS app pushed. A terminal shared with another
        access system (Oxyfit runs one; ~930 of its users are on that hardware) can
        never be touched, because those pins were never recorded here. That is
        precisely what makes this safe where MIRROR is not.

        RENEWAL HOLDS (P3b-1, plan §7). ``hold_persons``: the userIds whose desired pins are
        not all confirmed on the terminal at the start of the pass (MEMBERSHIP only; the
        caller passes none under ACCOUNT). A departed pin of such a person -- named by
        member_person_link -- is HELD: counted by the ceiling like any other, but not
        removed here; the caller removes it after the push once that person's desired pins
        are confirmed (``_remove_released_holds``). A required pin (an explicit revocation)
        or a ``hold_exempt`` pin is never held. The held pins are left in
        ``_last_revoke_holds``; they are neither failures nor a ceiling refusal.

        Returns True when it is safe to prune per-pin state, False when the pass
        aborted and the state must be kept so a later sync can retry.
        """
        self._last_revoke_aborted = 0
        self._last_revoke_removed: set[str] = set()
        self._last_revoke_removal_failed: list[str] = []
        self._last_revoke_holds: set[str] = set()
        self._last_revoke_hold_person: Dict[str, int] = {}
        # For the removal retry (R1-06/08/22): "skipped" = nothing to attempt until the
        # roster changes; "errored" = could not evaluate, a pending retry stays armed.
        self._last_revoke_step = "errored"
        if roster_count <= 0:
            # A failed or half-built roster must never read as "everyone left".
            _tel.warn("REVOKE_SKIP_EMPTY_ROSTER", worker=self._tel_wid)
            self._last_revoke_step = "skipped"
            return False
        try:
            from app.core.db import list_confirmed_device_sync_pins
            owned = list_confirmed_device_sync_pins(device_id=self._device_id) or set()
        except Exception:
            logger.warning("%s revoke pass: per-pin state unreadable -- skipping",
                           self._prefix, exc_info=True)
            return False
        # The guards below hold the WHOLE step back: nothing is attempted, so a pending
        # retry is parked, not cleared (review R2-20). "ran" is set after them.
        self._last_revoke_step = "skipped"

        keep = {str(p).strip() for p in (desired_pins or set())}
        required = {str(p).strip() for p in (required_pins or set()) if str(p).strip()}
        owned = {str(p).strip() for p in owned if str(p).strip()}
        if not required <= owned:
            logger.warning(
                "%s revoke pass: ownership proof missing for explicit pin(s) %s",
                self._prefix,
                ",".join(sorted(required - owned)),
            )
            return False
        if required & keep:
            logger.warning(
                "%s revoke pass: explicit pin(s) still present in desired roster: %s",
                self._prefix,
                ",".join(sorted(required & keep)),
            )
            return False
        # The enrolment grace window, shared with MIRROR: a pin pushed seconds ago is
        # mid-flight, not departed.
        grace = self._mirror_grace_pins() | self._mirror_allowlist_pins()
        # The prune keeps exactly what this step spared: a grace window expiring between
        # the two left such a pin neither removed nor kept (review R3-11).
        self._last_revoke_grace = set(grace)
        if required & grace:
            logger.warning(
                "%s revoke pass: explicit pin(s) blocked by safety protection: %s",
                self._prefix,
                ",".join(sorted(required & grace)),
            )
            return False
        self._last_revoke_step = "ran"
        revoked = sorted(p for p in owned if p not in keep and p not in grace)
        if not revoked:
            return True

        # Refuse an implausible bulk revocation rather than strip a gym's worth of
        # members off a turnstile. See _REVOKE_ABSOLUTE_FLOOR for why a fraction on
        # its own is not enough here. The ONE ceiling every removal path shares
        # (push_safety, P3a-2); it emits REVOKE_ABORTED with the count.
        _verdict = _push_safety.check_bulk_removal(
            count=len(revoked), roster_count=roster_count, path="standalone_revoke",
            device_id=self._device_id, protocol="ZK_STANDALONE", worker=self._tel_wid,
            sample=revoked,
        )
        ceiling = _verdict.ceiling
        if not _verdict.allowed:
            self._last_revoke_aborted = len(revoked)
            # Kept alongside REVOKE_ABORTED: existing operator greps key on it.
            _tel.warn("REVOKE_ABORT_FLOOR", worker=self._tel_wid,
                      revoked=len(revoked), roster=roster_count,
                      ceiling=round(ceiling, 1),
                      max_frac=_MIRROR_MAX_DELETE_FRACTION,
                      abs_floor=_REVOKE_ABSOLUTE_FLOOR)
            logger.warning(
                "%s revoke pass ABORTED: %d pin(s) would be stripped against a roster "
                "of %d (ceiling %.0f) -- that is implausible, so nothing was changed "
                "and the per-pin state is kept for a later retry.",
                self._prefix, len(revoked), roster_count, ceiling,
            )
            return False

        # RENEWAL HOLDS (P3b-1): counted by the ceiling above, removed by the caller after
        # the push. Only the rest -- the real leavers -- go now.
        if hold_persons:
            from app.core.device_sync import renewal_holds

            self._last_revoke_hold_person = renewal_holds(
                revoked, pending_persons=hold_persons,
                exempt=required | {str(p).strip() for p in (hold_exempt or ())},
            )
            self._last_revoke_holds = set(self._last_revoke_hold_person)
        if self._last_revoke_holds:
            logger.info(
                "%s revoke pass: %d departed pin(s) held until the push confirms their "
                "person's new pin: %s", self._prefix, len(self._last_revoke_holds),
                ",".join(sorted(self._last_revoke_holds)[:20]),
            )
        revoked = [p for p in revoked if p not in self._last_revoke_holds]
        if not revoked:
            return True

        logger.warning(
            "%s revoking %d pin(s) no longer in the roster: %s",
            self._prefix, len(revoked), ",".join(revoked[:20]),
        )

        outcome, failed, pushed_fingers = self._remove_departed_pins(revoked)
        self._last_revoke_removed = set(outcome.removed) - failed
        self._last_revoke_removal_failed = sorted(failed)
        confirmed_slots = sum(
            len(pushed_fingers.get(pin) or ()) for pin in outcome.neutralised
        )
        _tel.event("REVOKE_DONE", worker=self._tel_wid, pins=len(revoked),
                   deleted=len(outcome.deleted), neutralised=len(outcome.neutralised),
                   slots=confirmed_slots, ok=not failed)
        if failed:
            # Keep the state so the next sync retries rather than forgetting that
            # these pins still hold credentials.
            logger.warning("%s revoke fallback failed -- keeping per-pin state for retry",
                           self._prefix)
            return False
        return outcome.removed == frozenset(revoked)

    def _remove_departed_pins(
        self, pins: list[str],
    ) -> tuple[_StandalonePinRemovalResult, set[str], Dict[str, Any]]:
        """Remove owned departed pins and forget the state of each one confirmed removed.

        Shared by the revoke pass and the post-push removal of the renewal holds (P3b-1).
        Returns ``(outcome, failed, pushed_fingers)``: ``failed`` = pins the terminal did not
        confirm removed, plus confirmed ones whose local state could not be cleared -- both
        keep their state for the retry.
        """
        pushed_fingers = self._load_pushed_fingers()
        outcome = self._remove_standalone_pins(
            pins=pins,
            pushed_fingers=pushed_fingers,
        )
        cleanup_failed: set[str] = set()
        if outcome.removed:
            from app.core.db import clear_device_revocation_state

            for pin in sorted(outcome.removed):
                try:
                    clear_device_revocation_state(device_id=self._device_id, pin=pin)
                except Exception:
                    cleanup_failed.add(pin)
                    logger.warning(
                        "%s revoke pass: local state cleanup failed for pin %s",
                        self._prefix,
                        pin,
                        exc_info=True,
                    )
        return outcome, set(outcome.failed) | cleanup_failed, pushed_fingers

    def _remove_released_holds(
        self,
        *,
        holds: Dict[str, int],
        pin_persons: Dict[str, Any],
        unconfirmed: set[str],
        confirmed_now: set[str],
        touched: set[str],
    ) -> tuple[set[str], set[str], bool]:
        """Second half of renewal ordering (P3b-1, plan §7): after the push, remove the
        holds whose person's desired pins are ALL confirmed on the terminal now.

        ``holds``: {held pin: person} from the removal step. ``pin_persons``: {desired pin:
        userId}. ``unconfirmed``: desired pins not confirmed at the start of the pass;
        ``confirmed_now``: those this pass's push confirmed. A hold is removed through the
        same removal as the revoke pass, and only while MonClub still owns it: a targeted
        revoke served between two push chunks may have removed it already (``touched``
        pins are left to that targeted path). Returns ``(kept, failed, errored)``: ``kept``
        = holds left on the terminal on purpose (their person still waits for a pin);
        ``failed`` = released holds the terminal did not confirm removed (a normal removal
        failure: state kept, fast retry); ``errored`` = ownership unreadable, nothing
        attempted. Emits one ``RENEWAL_HOLD`` line.
        """
        from app.core.device_sync import renewal_released_holds

        free = renewal_released_holds(holds, person_by_pin=pin_persons,
                                      unconfirmed=unconfirmed, confirmed_now=confirmed_now)
        released = sorted(p for p in free if p not in touched)
        kept = set(holds) - set(released)
        failed: set[str] = set()
        errored = False
        removed = 0
        if released:
            try:
                from app.core.db import list_confirmed_device_sync_pins

                owned = {str(p).strip() for p in
                         (list_confirmed_device_sync_pins(device_id=self._device_id) or ())}
            except Exception:
                logger.warning("%s renewal holds: ownership unreadable -- none removed this "
                               "pass", self._prefix, exc_info=True)
                owned = None
                errored = True
            released = [p for p in released if owned is not None and p in owned]
            if released:
                logger.warning(
                    "%s removing %d renewed member(s)' previous pin(s) now that the new pin "
                    "is confirmed: %s", self._prefix, len(released), ",".join(released[:20]),
                )
                try:
                    outcome, failed, _ = self._remove_departed_pins(released)
                    removed = len(set(outcome.removed) - failed)
                except Exception:
                    logger.warning("%s renewal holds: removal error", self._prefix,
                                   exc_info=True)
                    failed = set(released)
        _tel.event("RENEWAL_HOLD", worker=self._tel_wid, held=len(holds),
                   removed_after_push=removed, kept=len(kept))
        return kept, failed, errored

    def _mirror_grace_pins(self) -> set[str]:
        m = getattr(self, "_recent_member_push", None) or {}
        now = time.monotonic()
        return {p for p, t in m.items() if (now - t) < _MIRROR_ENROLL_GRACE_SEC}

    def _mirror_allowlist_pins(self) -> set[str]:
        """Operator pin allowlist from deviceCapabilities.mirrorProtectedPins (never deleted)."""
        caps = (self._device or {}).get("deviceCapabilities")
        out: set[str] = set()
        if isinstance(caps, dict):
            for p in (caps.get("mirrorProtectedPins") or []):
                s = str(p).strip()
                if s:
                    out.add(s)
        return out

    def _maybe_mirror_reconcile(self, *, full_reconcile: bool,
                                roster_users: list[Dict[str, Any]]) -> None:
        """MIRROR pushing policy: delete device users NOT in the app roster.

        DESTRUCTIVE — removes users off a live turnstile. Every gate is an early
        return with a MIRROR_SKIP_*/ABORT telemetry event; the first run on a device
        is dry-run only (logs the plan, deletes nothing) until an operator arms it via
        db.arm_mirror_reconcile. PRESERVE (default) and PullSDK drivers never get here.

        `full_reconcile` is the request's own flag, derived ONCE at the app layer by
        sync_observability.is_explicit_user_sync. Do not re-derive it from `reason`:
        `reason` is a trigger_source token and cannot express this distinction.
        """
        # 1) policy gate
        policy = str((self._device or {}).get("rosterPushingPolicy") or "").strip().upper()
        if policy != "MIRROR":
            return  # PRESERVE / null / pre-migration -> additive, nothing to reconcile

        # 2) trigger gate — only an explicit full reconcile (never daytime/spurious)
        if not full_reconcile:
            _tel.event("MIRROR_SKIP_NOT_FULL_RECONCILE", worker=self._tel_wid)
            return

        # 3) capability gate — driver must enumerate + delete (PullSDK cannot)
        lister = getattr(self._sdk, "list_device_users", None)
        deleter = getattr(self._sdk, "delete_users", None)
        if not callable(lister) or not callable(deleter):
            _tel.event("MIRROR_SKIP_NO_CAPABILITY", worker=self._tel_wid)
            return

        # 4) empty-roster HARD rail — a transient/empty roster must never wipe the device
        roster_pins = {str(u.get("pin")).strip()
                       for u in (roster_users or []) if str(u.get("pin") or "").strip()}
        roster_count = len(roster_pins)
        if roster_count == 0:
            _tel.warn("MIRROR_SKIP_EMPTY_ROSTER", worker=self._tel_wid)
            return

        # 5) list device users — FAIL CLOSED (a failed/partial list is NOT "empty device")
        listing = lister()
        if not (isinstance(listing, dict) and listing.get("ok")):
            _tel.warn("MIRROR_SKIP_LIST_FAILED", worker=self._tel_wid,
                      err=str((listing or {}).get("error"))[:120])
            return
        device_pins = {str(u.get("pin")).strip()
                       for u in (listing.get("users") or []) if str(u.get("pin") or "").strip()}

        # 6/7) protected floor + operator allowlist + grace window; only numeric pins
        allow = self._mirror_allowlist_pins()
        grace = self._mirror_grace_pins()
        extras: set[str] = set()
        for p in (device_pins - roster_pins - allow - grace):
            if not p.isdigit():
                continue  # never delete a non-numeric device row
            if int(p) >= _MIRROR_RESERVED_PIN_FLOOR:
                continue  # reserved floor: manual/admin/staff enrollments
            extras.add(p)

        if not extras:
            _tel.event("MIRROR_NOOP", worker=self._tel_wid,
                       device=len(device_pins), roster=roster_count)
            return

        # 8) percent-floor — refuse a mass delete (corrupt/partial roster protection)
        if len(extras) > roster_count * _MIRROR_MAX_DELETE_FRACTION:
            _tel.warn("MIRROR_ABORT_FLOOR", worker=self._tel_wid,
                      extras=len(extras), roster=roster_count,
                      max_frac=_MIRROR_MAX_DELETE_FRACTION)
            return

        sample = ",".join(sorted(extras)[:20])
        from app.core.db import (mirror_reconcile_is_armed, mirror_reconcile_record_plan,
                                 delete_device_mirror_pin)

        # 9) dry-run gate — first run logs the plan, deletes NOTHING until armed
        if not mirror_reconcile_is_armed(device_id=self._device_id):
            try:
                mirror_reconcile_record_plan(device_id=self._device_id,
                                             count=len(extras), sample=sample)
            except Exception:
                pass
            _tel.event("MIRROR_PLAN", worker=self._tel_wid,
                       would_delete=len(extras), sample=sample, armed=False)
            logger.warning("%s MIRROR dry-run: WOULD delete %d device users not in the roster "
                           "(sample: %s). Review, then arm: "
                           "db.arm_mirror_reconcile(device_id=%d)",
                           self._prefix, len(extras), sample, self._device_id)
            return

        # 10) armed — log, delete, keep the write-through content mirror consistent
        _tel.event("MIRROR_PLAN", worker=self._tel_wid,
                   would_delete=len(extras), sample=sample, armed=True)

        # Record the DESTRUCTIVE reconcile durably, before it runs.
        #
        # This is the only place the app deletes members off a terminal, and it
        # used to leave nothing behind but a log line and a telemetry event -- so
        # nobody could answer "who removed these users, and when?" from any
        # screen. A push-batch row puts it in "Historique push" next to the
        # pushes, with policy=MIRROR, and survives a restart.
        mirror_started = time.monotonic()
        mirror_batch_id = None
        try:
            mirror_batch_id = insert_push_batch(
                sync_run_id=None,
                device_id=self._device_id,
                device_name=self._device_name,
                policy="MIRROR",
                status="IN_PROGRESS",
                created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
        except Exception:
            logger.debug("%s MIRROR batch row not recorded", self._prefix, exc_info=True)

        result = deleter(sorted(extras)) or {}
        failed_pins = result.get("failed_pins")
        failed_count = result.get("failed")
        deleted_count = result.get("deleted")
        if isinstance(failed_pins, list):
            normalized_failed = [
                str(pin if pin is not None else "").strip()
                for pin in failed_pins
            ]
            failed = set(normalized_failed)
            consistent = (
                type(result.get("ok")) is bool
                and type(failed_count) is int
                and type(deleted_count) is int
                and failed_count == len(failed_pins)
                and deleted_count == len(extras) - len(failed)
                and len(failed) == len(failed_pins)
                and all(pin in extras for pin in normalized_failed)
                and failed_count + deleted_count == len(extras)
                and (
                    (
                        result.get("ok") is True
                        and not failed
                    )
                    or result.get("ok") is False
                )
            )
            confirmed_deleted = extras - failed if consistent else set()
        else:
            confirmed_deleted = (
                set(extras)
                if (
                    type(result.get("ok")) is bool
                    and result.get("ok") is True
                    and type(failed_count) is int
                    and failed_count == 0
                    and type(deleted_count) is int
                    and deleted_count >= len(extras)
                )
                else set()
            )
        for p in confirmed_deleted:
            try:
                delete_device_mirror_pin(device_id=self._device_id, pin=p)
            except Exception:
                pass
            # Also forget the per-pin sync state: if this member is ever re-added,
            # a stale "synced" row would make the incremental full sync SKIP them
            # while they are no longer on the terminal.
            try:
                from app.core.db import delete_device_sync_state
                delete_device_sync_state(device_id=self._device_id, pin=str(p))
            except Exception:
                pass
        _tel.event("MIRROR_DONE", worker=self._tel_wid,
                   deleted=len(confirmed_deleted), failed=len(extras) - len(confirmed_deleted),
                   ok=result.get("ok"))
        logger.warning("%s MIRROR reconcile: deleted %s device users not in roster "
                       "(failed=%s, pins: %s)",
                       self._prefix, len(confirmed_deleted),
                       len(extras) - len(confirmed_deleted), sample)
        if mirror_batch_id is not None:
            try:
                _deleted = len(confirmed_deleted)
                _failed = len(extras) - _deleted
                update_push_batch(
                    id=mirror_batch_id,
                    pins_attempted=len(extras),
                    pins_success=_deleted,
                    pins_failed=_failed,
                    status=("SUCCESS" if (result.get("ok") and _failed == 0) else "PARTIAL"),
                    duration_ms=int((time.monotonic() - mirror_started) * 1000),
                    # The pins are the WHOLE point of the record -- without them the
                    # row says "12 users removed" and cannot say which.
                    error_message=("deleted pins: " + sample) if sample else None,
                )
            except Exception:
                logger.debug("%s MIRROR batch row not finalised", self._prefix, exc_info=True)

    def _maintenance_idle(self) -> bool:
        """No door command, member update or full sync is waiting (lock-free peeks)."""
        try:
            if not self._cmd_queue.empty():
                return False
        except Exception:
            return False
        if self._pending_member_syncs or self._pending_full_sync_request is not None:
            return False
        return True

    def _drain_daily_maintenance(self) -> None:
        """Once per local day, after the day's first completed full sync, when idle.

        Standalone (MB2000) only: the intent read-back enumerates the whole terminal
        in one STA command -- no RTLog pump, no door service for its duration -- so it
        runs at most once a day, never during a push, only when intents of departed
        members exist, and only while nothing else is waiting. guide §3.4a.
        """
        if not getattr(self._sdk, "owns_event_source", False) or not self._connected:
            return
        if not bool(getattr(self._sdk, "is_connected", True)):
            return          # a dead link: never use up the day's read-back on it (R2-16)
        today = _local_day()
        if getattr(self, "_maintenance_ready_day", None) != today:
            return
        if getattr(self, "_last_desired_pins", None) is None:
            # No complete roster since this worker started (a latched removal ceiling, or
            # ACCOUNT rows without mainAccountId on every pass): nothing to compare against.
            # Said once a day instead of silently (review R2-05).
            if getattr(self, "_maintenance_skip_day", None) != today:
                self._maintenance_skip_day = today
                logger.warning("%s daily maintenance skipped: no complete roster yet",
                               self._prefix)
                _tel.warn("MAINTENANCE_SKIPPED", worker=self._tel_wid,
                          reason="no_complete_roster")
            return
        if not self._maintenance_idle():
            return
        if getattr(self, "_readback_done_day", None) != today:
            self._readback_done_day = today
            desired = getattr(self, "_last_desired_pins", None)
            if desired is not None:
                try:
                    self._promote_intents_by_readback(desired_pins=set(desired))
                except Exception:
                    logger.warning("%s intent read-back failed", self._prefix, exc_info=True)
            return
        try:
            self._drain_finger_sweep(today)
        except Exception:
            logger.warning("%s finger sweep step failed", self._prefix, exc_info=True)

    def _drain_full_sync_commands(self, limit: int = 1) -> int:
        if limit <= 0:
            return 0

        drained = 0
        while drained < limit:
            # Lock order is always member -> full. Moving the request to ACTIVE
            # and removing equivalent targeted commands is one ownership
            # transfer: no later member drain can execute the same revocation.
            with self._member_sync_lock:
                with self._full_sync_lock:
                    request = self._pending_full_sync_request
                    if request is not None:
                        request_revoked_ids = {
                            int(member_id)
                            for member_id in (request.get("revoked_ids") or set())
                            if member_id is not None
                        }
                        phases = self._full_sync_revocation_phases_locked()
                        exclusion_phases = self._full_sync_exclusion_phases_locked()
                        retry_revoked_ids = {
                            member_id
                            for member_id, phase in phases.items()
                            if phase == _FULL_REVOKE_RETRY
                        }
                        retry_excluded_ids = {
                            member_id
                            for member_id, phase in exclusion_phases.items()
                            if phase == _FULL_REVOKE_RETRY
                        }
                        confirmed_revoked_ids = set(
                            getattr(self, "_confirmed_member_revoke_ids", set())
                        )
                        request_revoked_ids.update(
                            retry_revoked_ids - confirmed_revoked_ids
                        )
                        request_excluded_ids = {
                            int(member_id)
                            for member_id in (
                                request.get("excluded_ids") or request_revoked_ids
                            )
                            if member_id is not None
                        }
                        request_excluded_ids.update(
                            request_revoked_ids
                            | retry_revoked_ids
                            | retry_excluded_ids
                        )
                        request_revoked_ids.update(
                            request_excluded_ids & self._pending_member_revoke_ids
                        )
                        for member_id in retry_revoked_ids:
                            phases.pop(member_id, None)
                        for member_id in retry_excluded_ids:
                            exclusion_phases.pop(member_id, None)
                        for member_id in request_revoked_ids:
                            phases[member_id] = _FULL_REVOKE_ACTIVE
                        for member_id in request_excluded_ids:
                            exclusion_phases[member_id] = _FULL_REVOKE_ACTIVE
                        adopted_revoked_ids = (
                            request_revoked_ids & self._pending_member_revoke_ids
                        )
                        if adopted_revoked_ids:
                            self._pending_member_syncs = deque(
                                member_id
                                for member_id in self._pending_member_syncs
                                if member_id not in adopted_revoked_ids
                            )
                            self._pending_member_sync_ids.difference_update(
                                adopted_revoked_ids
                            )
                            self._pending_member_revoke_ids.difference_update(
                                adopted_revoked_ids
                            )
                        self._pending_full_sync_request = None
            if request is None:
                break
            reason = str(request.get("reason") or "manual")
            fingerprint_hash = str(request.get("fingerprint_hash") or "").strip() or None
            full_reconcile = bool(request.get("full_reconcile"))
            revoked_ids = request_revoked_ids
            excluded_ids = request_excluded_ids

            self._removal_retry_reported = False
            try:
                if self._sdk is None or not self._connected or (
                        getattr(self._sdk, "owns_event_source", False)
                        and not bool(getattr(self._sdk, "is_connected", True))):
                    # Also a push driver that reports its link dead: the pass would fail
                    # every removal and escalate the retry for nothing; it is re-queued for
                    # the reconnected link (review R4-10), and it reports nothing to the
                    # removal retry -- the re-queued pass will (review R5-04).
                    self._removal_retry_reported = True
                    self._finalize_full_sync_revokes(
                        revoked_ids, ok=False, excluded_ids=excluded_ids
                    )
                    self.request_full_sync(
                        reason=reason,
                        fingerprint_hash=fingerprint_hash,
                        revoked_ids=revoked_ids,
                        full_reconcile=full_reconcile,
                    )
                    break
                # Push drivers (ZK_STANDALONE) have no raw PullSDK handle — the
                # extraction below would yield None and re-queue this request
                # FOREVER. Route them to their own roster path, which always
                # terminates the request (mark/notify fire on both outcomes).
                if getattr(self._sdk, "owns_event_source", False):
                    self._run_standalone_full_sync(
                        reason=reason,
                        full_reconcile=full_reconcile,
                        fingerprint_hash=fingerprint_hash,
                        revoked_ids=revoked_ids,
                        excluded_ids=excluded_ids,
                    )
                    drained += 1
                    continue
                raw_sdk = getattr(self._sdk, "_sdk", None)
                if raw_sdk is None:
                    self._finalize_full_sync_revokes(
                        revoked_ids, ok=False, excluded_ids=excluded_ids
                    )
                    self.request_full_sync(
                        reason=reason,
                        fingerprint_hash=fingerprint_hash,
                        revoked_ids=revoked_ids,
                        full_reconcile=full_reconcile,
                    )
                    break
                cache = load_sync_cache()
                if cache is None:
                    logger.warning("%s full sync skipped: no sync cache available", self._prefix)
                    self._mark_full_sync_finished(
                        reason=reason,
                        ok=False,
                        duration_ms=0.0,
                        error="no sync cache available",
                    )
                    self._finalize_full_sync_revokes(
                        revoked_ids, ok=False, excluded_ids=excluded_ids
                    )
                    self._notify_full_sync_finished(
                        reason=reason,
                        ok=False,
                        fingerprint_hash=None,
                        duration_ms=0.0,
                        error="no sync cache available",
                        revoked_ids=revoked_ids,
                    )
                    drained += 1
                    continue
                cache = _sync_cache_without_revoked_ids(cache, excluded_ids)

                from app.core.device_sync import DeviceSyncEngine

                device_copy = dict(self._device or {})
                device_copy["accessDataMode"] = "DEVICE"
                filtered_cache_attrs = dict(getattr(cache, "__dict__", {}))
                filtered_cache_attrs["devices"] = [device_copy]
                filtered_cache = SimpleNamespace(**filtered_cache_attrs)
                engine = DeviceSyncEngine(cfg=self._cfg or SimpleNamespace(), logger=logger)
                # Full sync runs INLINE on this worker (see comment below). Let it
                # open doors queued mid-push between SetDeviceData chunks so the
                # turnstile stays responsive during the push, and (when enabled)
                # poll+process RTLog scans so the popup keeps updating and
                # PC-verified QR/TOTP members get in during the push.
                engine._door_yield_cb = self._sync_yield_to_doors
                engine._rtlog_yield_cb = self._sync_yield_to_rtlog
                started_at = time.time()
                started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at))
                self._mark_full_sync_started(reason=reason, engine=engine, started_at=started_iso)
                self._notify_full_sync_started(reason=reason)
                # Full sync runs INLINE on this worker over the single device
                # connection: RTLog polling + door commands are blocked for the
                # entire push. This is the primary Type-1 freeze. The heartbeat
                # will raise WORKER_STALL if it runs long.
                _tel.set_state(self._tel_wid, "full_sync", f"reason={reason}")
                _tel.event(
                    "FULL_SYNC_START", worker=self._tel_wid, reason=reason,
                    users=len(getattr(filtered_cache, "users", []) or []),
                )
                # Revocations a fast retry can change (the delete failed, ownership was
                # unreadable) vs those it cannot (deferred: an incomplete ACCOUNT roster, an
                # unnameable pin) -- the latter used to re-arm the 300 s retry forever (R2-23).
                _retryable_revokes: set[int] = set()
                for member_id in sorted(
                    revoked_ids - self._confirmed_member_revokes(revoked_ids)
                ):
                    if engine.sync_member_on_connected_sdk(
                        sdk=raw_sdk,
                        device=device_copy,
                        member_id=member_id,
                        source="ultra_full_sync_revoke",
                        revocation=True,
                    ):
                        self._mark_member_revoke_confirmed(member_id)
                    elif getattr(engine, "_last_member_sync_outcome", None) in (
                            "DELETE_FAILED", "OWNERSHIP_UNREADABLE"):
                        _retryable_revokes.add(member_id)
                    elif _revoke_skipped_not_owned(engine):
                        # FINAL (P3a-2): not ours, never deleted. "Confirmed" here means
                        # "no physical work left" -- the pass must not fail for it, and the
                        # scheduler must not re-queue it forever.
                        self._note_revoke_skipped(member_id)
                        self._mark_member_revoke_confirmed(member_id)
                _skipped_now = self._take_skipped_revokes()
                if _skipped_now:
                    # Carried into this pass's push-batch note (push-history page).
                    engine._extra_batch_notes = [_push_safety.outcome_note(
                        _push_safety.SKIPPED_NOT_OWNED, len(_skipped_now),
                        "memberships " + ",".join(str(m) for m in sorted(_skipped_now)[:20]),
                    )]
                # Renewal ordering (P3b-1) never holds back an explicit revocation: a pin the
                # pre-pass above failed to delete is still removed first by the stale step.
                # Named as MEMBERSHIP pins -- the only scheme that holds.
                engine._full_sync_revoked_pins = {
                    str(int(m)) for m in (revoked_ids | excluded_ids)
                }
                sync_ok = bool(engine.run_one_device_on_connected_sdk(
                    sdk=raw_sdk,
                    cache=filtered_cache,
                    device=device_copy,
                    source=reason,
                    changed_ids=None,
                ))
                unconfirmed_revoked_ids = (
                    revoked_ids - self._confirmed_member_revokes(revoked_ids)
                )
                # P3a-2 item 2: a stale delete the panel refused (its row is now kept) or an
                # explicit revocation still pending re-requests a pass within 300 s.
                _removal_report = getattr(engine, "_last_removal_report", None) or {}
                _failed_stale = list(_removal_report.get("failed") or [])
                _hard = unconfirmed_revoked_ids & _retryable_revokes
                if _failed_stale or _hard:
                    # A removal the panel refused -- known even when the pass failed after
                    # its stale step (review R2-21) -- is retried fast.
                    self._update_removal_retry(failed=_failed_stale, errored=bool(_hard))
                elif _removal_report.get("stale_skipped") or (
                        unconfirmed_revoked_ids - _retryable_revokes):
                    # Nothing a fast retry can change: a pending removal is parked.
                    self._update_removal_retry(failed=[], skipped=True)
                elif _removal_report.get("complete", bool(_removal_report)):
                    # A pass that never reached its stale step leaves no report: that is
                    # not "complete" (review R3-04).
                    self._update_removal_retry(failed=[])
                # else: the pass stopped before its stale step -- the drain's
                # _keep_pending_removal_retry keeps a pending retry armed (R1-06).
                if sync_ok and unconfirmed_revoked_ids:
                    sync_ok = False
                    sync_error = "authoritative revocation unconfirmed"
                else:
                    sync_error = "" if sync_ok else (
                        getattr(engine, "_last_single_device_error", "")
                        or "device sync failed"
                    )
                duration_ms = max(0.0, (time.time() - started_at) * 1000.0)
                _tel.event(
                    "FULL_SYNC_DONE", worker=self._tel_wid, reason=reason,
                    ok=sync_ok, dur_ms=round(duration_ms),
                )
                self._mark_full_sync_finished(
                    reason=reason,
                    ok=sync_ok,
                    duration_ms=duration_ms,
                    error=sync_error,
                )
                if not sync_ok:
                    self._finalize_full_sync_revokes(
                        revoked_ids, ok=False, excluded_ids=excluded_ids
                    )
                self._notify_full_sync_finished(
                    reason=reason,
                    ok=sync_ok,
                    fingerprint_hash=fingerprint_hash if sync_ok else None,
                    duration_ms=duration_ms,
                    error=sync_error,
                    revoked_ids=revoked_ids if not sync_ok else set(),
                )
                if sync_ok:
                    self._finalize_full_sync_revokes(
                        revoked_ids, ok=True, excluded_ids=excluded_ids
                    )
            except Exception as exc:
                logger.warning(
                    "%s full sync failed: reason=%s err=%s",
                    self._prefix,
                    reason,
                    exc,
                )
                self._mark_full_sync_finished(
                    reason=reason,
                    ok=False,
                    duration_ms=0.0,
                    error=str(exc),
                )
                self._finalize_full_sync_revokes(
                    revoked_ids, ok=False, excluded_ids=excluded_ids
                )
                self._notify_full_sync_finished(
                    reason=reason,
                    ok=False,
                    fingerprint_hash=None,
                    duration_ms=0.0,
                    error=str(exc),
                    revoked_ids=revoked_ids,
                )
            finally:
                self._keep_pending_removal_retry()
            drained += 1
        return drained

    def _mark_full_sync_started(self, *, reason: str, engine: Any, started_at: str) -> None:
        with self._active_sync_lock:
            self._active_sync_engine = engine
            self._current_full_sync_reason = str(reason or "manual")
            self._last_full_sync_started_at = started_at
            self._full_sync_running = True
            self._last_full_sync_error = ""

    def _mark_full_sync_finished(
        self,
        *,
        reason: str,
        ok: bool,
        duration_ms: float,
        error: str,
    ) -> None:
        finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._active_sync_lock:
            self._active_sync_engine = None
            self._current_full_sync_reason = str(reason or "manual")
            self._last_full_sync_finished_at = finished_at
            self._last_full_sync_duration_ms = max(0.0, float(duration_ms or 0.0))
            self._last_full_sync_error = "" if ok else str(error or "sync failed")
            self._full_sync_running = False

    def _notify_full_sync_started(self, *, reason: str) -> None:
        cb = self._on_full_sync_started
        if cb is None:
            return
        try:
            cb(device_id=self._device_id, reason=str(reason or "manual"))
        except Exception:
            logger.debug("%s full sync started callback failed", self._prefix, exc_info=True)

    def _notify_full_sync_finished(
        self,
        *,
        reason: str,
        ok: bool,
        fingerprint_hash: str | None,
        duration_ms: float,
        error: str,
        revoked_ids: set[int] | None = None,
    ) -> None:
        cb = self._on_full_sync_finished
        if cb is None:
            return
        try:
            kwargs: Dict[str, Any] = dict(
                device_id=self._device_id,
                reason=str(reason or "manual"),
                ok=bool(ok),
                fingerprint_hash=str(fingerprint_hash or "").strip() or None,
                duration_ms=max(0.0, float(duration_ms or 0.0)),
                error=str(error or ""),
            )
            normalized_revoked_ids = {
                int(member_id)
                for member_id in (revoked_ids or set())
                if member_id is not None
            }
            if normalized_revoked_ids:
                kwargs["revoked_ids"] = normalized_revoked_ids
            cb(**kwargs)
        except Exception:
            logger.debug("%s full sync finished callback failed", self._prefix, exc_info=True)

    # ------------------------------------------------------------------ #
    # RTLog polling with watchdog (15s timeout)
    # ------------------------------------------------------------------ #

    # A wedged poll thread is unkillable, so the only question is how many we
    # tolerate before declaring the device unrecoverable. Each one costs a thread
    # and a leaked plcommpro session; three is enough to ride out transient
    # wedges without letting a permanently sick device leak without bound.
    _MAX_ORPHAN_POLL_THREADS = 3

    def _poll_with_watchdog(self) -> Optional[List[Dict[str, Any]]]:
        """Poll RTLog with thread-based watchdog. Returns events or None on timeout."""
        # Retire orphans that have since come back; each one that returns also
        # releases its PullSDK handle lease, which is what lets the deferred
        # Disconnect finally run (see PullSDK._exit_handle_use).
        orphans: List[threading.Thread] = [
            t for t in getattr(self, "_orphan_poll_threads", []) if t.is_alive()
        ]

        prev_t: Optional[threading.Thread] = getattr(self, "_watchdog_thread", None)
        if prev_t is not None and prev_t.is_alive():
            # The previous poll is still inside the DLL.
            #
            # This used to `return None` every cycle until that thread came back,
            # on the stated assumption that "the SDK disconnect should unblock the
            # orphan thread" -- which was only ever true because disconnect() freed
            # the session out from under it. That free was a use-after-free, and
            # PullSDK.disconnect() no longer does it: while a call is in flight the
            # native free is deferred. Nothing will unblock this thread now, so
            # waiting for it would mean the device NEVER polls again -- a silently
            # dead turnstile, which is worse than the crash we removed.
            #
            # So stop waiting on it. Retire it as an orphan and poll on the fresh
            # connection the run loop has already rebuilt. If it ever returns, its
            # lease drops and the old session is freed properly.
            if prev_t not in orphans:
                orphans.append(prev_t)
            logger.error(
                f"{self._prefix} poll_rtlog WATCHDOG STILL HUNG from previous cycle — "
                f"retiring it as an orphan ({len(orphans)}/{self._MAX_ORPHAN_POLL_THREADS}) "
                f"and polling on the new connection"
            )
            _tel.warn(
                "POLL_WATCHDOG_STILL_HUNG",
                worker=f"ULTRA:{self._device_id}",
                orphans=len(orphans),
            )
            self._watchdog_thread = None

        if len(orphans) >= self._MAX_ORPHAN_POLL_THREADS:
            # Every retry so far has wedged. Stop manufacturing threads and
            # sessions we can never reclaim; the device needs a human or a
            # process restart.
            self._orphan_poll_threads = orphans
            logger.error(
                f"{self._prefix} poll_rtlog: {len(orphans)} orphaned poll threads are still "
                f"stuck in the SDK — refusing to start another. This device is not "
                f"recovering on its own."
            )
            _tel.warn(
                "POLL_WATCHDOG_ORPHAN_LIMIT",
                worker=f"ULTRA:{self._device_id}",
                orphans=len(orphans),
            )
            return None

        self._orphan_poll_threads = orphans

        result: List[Optional[List[Dict[str, Any]]]] = [None]
        error: List[Optional[Exception]] = [None]

        def _poll():
            try:
                assert self._sdk is not None
                result[0] = self._sdk.poll_rtlog_once()
            except Exception as e:
                error[0] = e

        t = threading.Thread(target=_poll, daemon=True, name=f"UltraPoll-{self._device_id}")
        self._watchdog_thread = t
        t0 = time.monotonic()
        try:
            t.start()
        except RuntimeError as exc:
            # Type-2 failure mode: the process can no longer create OS threads
            # ("can't start new thread"). This is where the daily full lockup
            # surfaces. Capture the exact process resource snapshot (Python
            # thread count, private/working-set bytes, OS handles) so the cause
            # is measured, not inferred — then propagate unchanged.
            self._watchdog_thread = None
            _tel.thread_spawn_failure(
                "ultra._poll_with_watchdog",
                worker=f"ULTRA:{self._device_id}",
                err=str(exc),
            )
            raise
        t.join(timeout=self._poll_timeout_sec)
        elapsed_ms = (time.monotonic() - t0) * 1000

        # Update EMA
        alpha = 0.2
        self._poll_ema_ms = alpha * elapsed_ms + (1 - alpha) * self._poll_ema_ms

        if t.is_alive():
            logger.error(
                f"{self._prefix} poll_rtlog WATCHDOG TIMEOUT "
                f"(>{self._poll_timeout_sec}s elapsed={elapsed_ms:.0f}ms) — forcing reconnect"
            )
            _tel.warn(
                "POLL_WATCHDOG_TIMEOUT",
                worker=f"ULTRA:{self._device_id}",
                elapsed_ms=round(elapsed_ms),
                timeout_s=self._poll_timeout_sec,
            )
            # Leave _watchdog_thread set. The next call detects it is still alive
            # and retires it as a bounded orphan so polling can continue on the
            # fresh connection — it no longer waits for a thread that, since the
            # deferred-free fix, nothing will unblock.
            return None
        # Thread finished — clear the reference so the next cycle can spawn fresh.
        self._watchdog_thread = None
        if error[0]:
            logger.error(
                f"{self._prefix} poll_rtlog ERROR: {error[0]} "
                f"(elapsed={elapsed_ms:.0f}ms) — forcing reconnect"
            )
            return None
        events = result[0] or []
        _tel.note_poll(f"ULTRA:{self._device_id}", events=len(events))
        if events:
            logger.debug(f"{self._prefix} poll_rtlog OK: {len(events)} event(s) in {elapsed_ms:.0f}ms")
        return events

    # ------------------------------------------------------------------ #
    # Event deduplication
    # ------------------------------------------------------------------ #

    def _pre_populate_seen(self):
        """Load recent event IDs from DB to prevent re-processing after restart."""
        try:
            recent_rows = get_recent_access_history(limit=200)
            for row in recent_rows:
                eid = getattr(row, "event_id", "") or ""
                if eid and eid not in self._seen:
                    self._seen.append(str(eid))
            logger.debug(f"{self._prefix} pre-populated {len(self._seen)} seen event IDs")
        except Exception as e:
            logger.warning(f"{self._prefix} pre_populate_seen failed: {e}")

    def _is_seen(self, event_id: str) -> bool:
        if event_id in self._seen:
            return True
        self._seen.append(event_id)
        return False

    def _effective_card_cooldown_sec(self, card_no: str) -> float:
        """Re-scan cooldown for this card/QR, from CURRENT settings.

        Short debounce by default; the longer anti_fraude_duration only when
        anti-fraud is enabled for this scan kind (QR vs RFID). Read live each
        event so a dashboard toggle (disable anti-fraud) takes effect at once.
        """
        # Staff exemption (TOTP): a staff member's just-rescued code is exempt
        # from the long re-entry block — only the short debounce floor applies,
        # so staff re-enter freely while the C3 multi-event burst is still
        # deduped. RFID can't be exempted (the controller opens it itself).
        sc = getattr(self, "_staff_codes", None)
        if sc:
            exp = sc.get(card_no)
            if exp is not None and exp > time.monotonic():
                return float(_ULTRA_CARD_DEBOUNCE_SEC)

        s = self._settings or {}
        # Pure format check (independent of the totp enable flags) so we consult
        # the correct anti-fraud toggle for a QR/TOTP code vs an RFID card.
        prefix = str(s.get("totp_prefix", "9") or "9")
        try:
            digits = int(s.get("totp_digits", 6) or 6)
        except (TypeError, ValueError):
            digits = 6
        is_qr = (
            len(card_no) == len(prefix) + digits
            and card_no.startswith(prefix)
            and card_no[len(prefix):].isdigit()
        )
        af_on = bool(s.get("anti_fraude_qr_code") if is_qr else s.get("anti_fraude_card"))
        try:
            af_dur = int(s.get("anti_fraude_duration") or 0)
        except (TypeError, ValueError):
            af_dur = 0
        if af_on and af_dur > 0:
            return max(float(_ULTRA_CARD_DEBOUNCE_SEC), float(af_dur))
        return float(_ULTRA_CARD_DEBOUNCE_SEC)

    def _is_staff_rfid_card(self, card_no: str) -> bool:
        """True if ``card_no`` is an RFID card belonging to a STAFF member.

        Lets a staff card's device-blocked re-entry slip past the software
        re-scan cooldown so it reaches the rescue path (TOTP is handled
        separately via _staff_codes). Cheap: cached local state (dict lookup) +
        the cached staff-plan-id set. Never raises."""
        try:
            if self._is_totp_format(card_no):
                return False
            if not bool(self._settings.get("ultra_rfid_staff_rescue_enabled", True)):
                return False
            _creds, _uam, users_by_card = self._get_cached_local_state()
            hits = users_by_card.get(card_no) or []
            staff_ids = get_staff_membership_ids_cached()
            for u in (hits if isinstance(hits, list) else [hits]):
                if not isinstance(u, dict):
                    continue
                pid = u.get("membershipId")
                if pid is not None and int(pid) in staff_ids:
                    return True
        except Exception:
            return False
        return False

    # ------------------------------------------------------------------ #
    # Event classification (core ULTRA logic)
    # ------------------------------------------------------------------ #

    def _process_event(self, evt: Dict[str, Any]):
        """Classify RTLog event and route to appropriate handler."""
        t0 = time.monotonic()
        if not hasattr(self, "_card_cooldown") or not isinstance(self._card_cooldown, dict):
            self._card_cooldown = {}

        card_no = str(evt.get("cardNo", "") or "").strip()
        event_type_raw = evt.get("eventType", "")
        event_time = str(evt.get("eventTime", "") or "").strip()
        event_id = str(evt.get("eventId", "") or "").strip()
        door_id_raw = evt.get("doorId")
        raw_row = evt.get("rawRow") or {}

        # Build a fallback event_id if not present
        if not event_id:
            event_id = f"{self._device_id}:{event_time}:{card_no}"

        if self._is_seen(event_id):
            logger.debug(f"{self._prefix} SKIP duplicate event_id={event_id}")
            return

        # Card/QR re-scan cooldown. Computed per-event from CURRENT settings:
        #   - anti-fraud OFF  -> short debounce only (member can re-enter in ~3s)
        #   - anti-fraud ON   -> anti_fraude_duration (anti-passback)
        # The C3 fires several events per single scan; the debounce floor stops
        # the relay re-pulsing without blocking a deliberate re-entry.
        if card_no:
            cooldown = self._effective_card_cooldown_sec(card_no)
            now_mono = time.monotonic()
            last_seen = self._card_cooldown.get(card_no, 0.0)
            elapsed = now_mono - last_seen
            if elapsed < cooldown:
                # A re-scan inside the cooldown window — normally skip. EXCEPTION:
                # a valid STAFF RFID card must reach the rescue path (the device
                # blocked its re-entry; the PC re-opens for staff). Only the
                # debounce floor still applies, so the C3's multi-event burst is
                # still deduped. (TOTP staff use _staff_codes in the cooldown calc.)
                if (
                    elapsed >= float(_ULTRA_CARD_DEBOUNCE_SEC)
                    and self._is_staff_rfid_card(card_no)
                ):
                    logger.debug(
                        f"{self._prefix} staff RFID re-entry past debounce — "
                        f"allow through to rescue: card={card_no!r} elapsed={elapsed:.1f}s"
                    )
                else:
                    logger.debug(
                        f"{self._prefix} SKIP card cooldown: card={card_no!r} "
                        f"elapsed={elapsed:.1f}s < {cooldown}s"
                    )
                    return
            self._card_cooldown[card_no] = now_mono
            # Prune old entries to avoid unbounded growth. Anything older than the
            # max possible cooldown window is safe to evict.
            if len(self._card_cooldown) > 2000:
                cutoff = now_mono - 600.0
                self._card_cooldown = {k: v for k, v in self._card_cooldown.items() if v > cutoff}

        self._events_processed += 1

        logger.debug(
            f"{self._prefix} event #{self._events_processed}: "
            f"id={event_id} card={card_no!r} type={event_type_raw!r} time={event_time!r} door={door_id_raw!r}"
        )

        # Parse event type: 0 = normal/verified (ALLOW), anything else = DENY
        try:
            event_type_int = int(event_type_raw)
        except (ValueError, TypeError):
            event_type_int = -1
            # `zkem_invalid` is NOT an unrecognised type — it is the standalone
            # driver's own marker for "the terminal refused this verify"
            # (zk_standalone.normalize_att_event sets the literal string). It gets
            # its own named event below, once scan_epoch is known, so the generic
            # warning here would only be noise that hides real parse failures.
            if event_type_raw != _ZKEM_INVALID_EVENT_TYPE:
                logger.warning(
                    f"{self._prefix} unrecognised eventType={event_type_raw!r} for event_id={event_id}"
                )

        is_allow = (event_type_int == 0)

        # Parse door_id to int
        door_id: Optional[int] = None
        if door_id_raw is not None:
            try:
                door_id = int(door_id_raw)
            except (ValueError, TypeError):
                pass

        # Convert the device's scan timestamp to a UTC epoch and record how stale
        # the event is at processing time (pipeline latency + clock skew). This
        # feeds both the TOTP rescue clock (fix #1) and skew telemetry (fix #2a).
        scan_epoch = parse_event_time_to_epoch(event_time, self._device_tz_offset_sec)
        self._record_event_age(scan_epoch)

        # ── Standalone verify outcome (telemetry only — no behaviour change) ──
        #
        # One line per scan the TERMINAL decided, so a field test can answer "did
        # the terminal accept this finger?" with a single grep instead of inferring
        # it from the popup. Only standalone rows carry scan_mode_hint, so PullSDK
        # traffic is untouched.
        #
        # age_s is the whole point of the OK line as much as the INVALID one: on
        # 2026-08-30 the terminal replayed a backlog of events ~3500 s old at 13:51,
        # which is indistinguishable from live scans without it.
        #
        # is_invalid / att_state / verify_method are logged RAW and side by side.
        # Their MB2000 semantics are [UNVERIFIED] (guide §7, zkemkeeper_guide §8:
        # verifyMethod's value space shifts between normal and multi-verify modes,
        # so 0 is genuinely ambiguous). The event NAME mirrors which branch fired —
        # a [CODE] fact — not a claim about why the terminal refused.
        try:
            if isinstance(raw_row, dict) and "scan_mode_hint" in raw_row:
                _age_s = (
                    round(max(0.0, time.time() - scan_epoch), 1)
                    if scan_epoch is not None else None
                )
                _vfields = dict(
                    worker=self._tel_wid,
                    pin=raw_row.get("pin"),
                    verify_method=raw_row.get("verifyMethod"),
                    scan_mode_hint=raw_row.get("scan_mode_hint"),
                    age_s=_age_s,
                    event_id=event_id,
                )
                if event_type_raw == _ZKEM_INVALID_EVENT_TYPE:
                    _tel.warn(
                        "ZKEM_VERIFY_INVALID",
                        att_state=raw_row.get("attState"),
                        **_vfields,
                    )
                elif is_allow:
                    _tel.event("ZKEM_VERIFY_OK", **_vfields)
        except Exception:
            pass

        # ── Re-entry / punch-interval (DoorNIntertime) diagnostics ──
        # Only meaningful when the re-entry block (Door{N}Intertime=N) is enabled on
        # the device. Tracks the last ACCEPTED card per door; on an EVENT=20 ("Too
        # Short Punch Interval") rejection it emits REENTRY_BLOCK correlating the
        # rejected card to what last happened on that door, to answer definitively:
        #   same_card=True                       -> genuine per-CARD re-entry (OK)
        #   same_card=False & last_accept<block  -> a DIFFERENT card just entered on
        #                                           this door => DoorNIntertime is a
        #                                           per-DOOR lockout (the reported
        #                                           "random first-scan rejected" bug)
        #   last_open_delta<block                -> a PC open (QR/TOTP/staff) started
        #                                           the device's interval
        # Telemetry only — no behaviour change.
        try:
            if door_id is not None:
                _re_now = time.monotonic()
                if not hasattr(self, "_reentry_last_accept"):
                    self._reentry_last_accept = {}
                if not hasattr(self, "_reentry_last_open_mono"):
                    self._reentry_last_open_mono = {}
                if is_allow:
                    self._reentry_last_accept[door_id] = (card_no, _re_now)
                elif event_type_int == 20:
                    _la_card, _la_mono = self._reentry_last_accept.get(door_id, ("", 0.0))
                    _lo_mono = self._reentry_last_open_mono.get(door_id, 0.0)
                    def _mask(c: str) -> str:
                        return (c[:2] + "*" * max(0, len(c) - 4) + c[-2:]) if c and len(c) > 4 else (c or "")
                    _tel.event(
                        "REENTRY_BLOCK", worker=self._tel_wid, door=door_id,
                        rejected_card=_mask(card_no),
                        last_accept_card=_mask(_la_card),
                        same_card=bool(_la_card and _la_card == card_no),
                        last_accept_delta_s=(round(_re_now - _la_mono, 1) if _la_mono else -1),
                        last_open_delta_s=(round(_re_now - _lo_mono, 1) if _lo_mono else -1),
                        event_id=event_id,
                    )
        except Exception:
            pass

        if is_allow:
            self._handle_allow(card_no, event_time, event_id, door_id, str(event_type_raw), raw_row)
        elif self._is_totp_format(card_no):
            self._handle_totp_rescue(card_no, event_time, event_id, door_id, raw_row, scan_epoch)
        else:
            # Denied, non-TOTP = a denied RFID card. If it is a VALID STAFF
            # member the PC re-opens (staff skip the device re-entry interval);
            # every other denied card stays denied (the device's decision —
            # including the punch-interval block — stands).
            self._handle_rfid_rescue(card_no, event_time, event_id, door_id, str(event_type_raw), raw_row)

        if (time.monotonic() - t0) * 1000 >= 250:
            _tel.warn("EVENT_PROCESS_SLOW", worker=self._tel_wid, dur_ms=round((time.monotonic() - t0) * 1000))

    def _record_event_age(self, scan_epoch: Optional[float]) -> None:
        """Track event age at processing (fix #2a) and warn (throttled) when the
        pipeline latency + clock skew grows large enough to threaten TOTP."""
        if scan_epoch is None:
            return
        age = time.time() - float(scan_epoch)
        # Ignore obviously bogus (future or absurdly old) timestamps for stats.
        if age < -_EVENT_TIME_SANITY_BOUND_SEC or age > _EVENT_TIME_SANITY_BOUND_SEC:
            return
        self._last_event_age_sec = age
        if age > self._max_event_age_sec:
            self._max_event_age_sec = age
        if age >= _CLOCK_SKEW_WARN_SEC:
            now_mono = time.monotonic()
            if (now_mono - self._last_skew_warn_mono) >= _CLOCK_SKEW_WARN_INTERVAL_SEC:
                self._last_skew_warn_mono = now_mono
                self._clock_skew_warns += 1
                logger.warning(
                    "%s CLOCK_SKEW/LATENCY: RTLog events are ~%.0fs old at processing "
                    "(latency + PC/device clock skew). The TOTP window is "
                    "drift=%s step / max_past_age=%ss — beyond ~45s of skew, valid QR "
                    "codes are rejected as DENY_NO_MATCH. Check the PC clock (NTP) and "
                    "the device clock.",
                    self._prefix, age,
                    self._settings.get("totp_drift_steps", 1),
                    self._settings.get("totp_max_past_age_seconds", 32),
                )

    def _maybe_discipline_device_clock(self) -> None:
        """Compare the device RTC to the PC clock (fix #2b).

        Always logs the device↔PC skew (read-only, the most precise clock-skew
        signal we can get). Corrects the device clock toward the PC clock ONLY
        when ``ultra_discipline_device_clock`` is enabled AND drift exceeds the
        threshold. Throttled to once/hour. The correction is only safe when the
        PC itself is NTP-synced — otherwise it would push a wrong time onto the
        device, so it is opt-in.
        """
        now_mono = time.monotonic()
        if (now_mono - self._last_clock_check_mono) < 3600.0:
            return
        self._last_clock_check_mono = now_mono

        sdk = self._sdk
        if sdk is None:
            return
        # get_device_time() is an SDK round-trip on the worker's connect path with
        # no timeout; time it and surface a slow read (throttled to once/hour).
        _gdt_t0 = time.monotonic()
        try:
            dev_epoch = sdk.get_device_time()
        except Exception:
            dev_epoch = None
        _gdt_ms = (time.monotonic() - _gdt_t0) * 1000.0
        if _gdt_ms >= 1000.0:
            _tel.warn("DEV_CLOCK_READ_SLOW", worker=self._tel_wid, dur_ms=round(_gdt_ms))
        if dev_epoch is None:
            return

        pc_now = time.time()
        skew = pc_now - float(dev_epoch)  # >0 => device clock is behind the PC
        self._device_pc_skew_sec = skew

        threshold = float(self._settings.get("ultra_device_clock_max_drift_sec", 10))
        if abs(skew) <= threshold:
            logger.info("%s device clock OK: device↔PC skew=%.1fs", self._prefix, skew)
            return

        if not bool(self._settings.get("ultra_discipline_device_clock", False)):
            logger.warning(
                "%s DEVICE CLOCK SKEW=%.1fs (>%.0fs) — TOTP codes may be rejected. "
                "Auto-correct is OFF (ultra_discipline_device_clock). Sync the PC "
                "clock (NTP) and the device clock, or enable auto-correct once the "
                "PC clock is trusted.",
                self._prefix, skew, threshold,
            )
            return

        logger.warning(
            "%s correcting device clock: skew=%.1fs (>%.0fs) -> setting device to PC time",
            self._prefix, skew, threshold,
        )
        try:
            if sdk.set_device_time(pc_now):
                self._device_pc_skew_sec = 0.0
        except Exception as e:
            logger.warning("%s device clock correction failed: %s", self._prefix, e)

    def _is_totp_format(self, code: str) -> bool:
        """Check if scanned code matches TOTP format: prefix + N digits."""
        if not self._settings.get("totp_enabled", True):
            return False
        if not self._settings.get("totp_validation", True):
            return False
        if not self._settings.get("ultra_totp_rescue_enabled", True):
            return False

        prefix = self._settings.get("totp_prefix", "9")
        digits = int(self._settings.get("totp_digits", 7))
        expected_len = len(prefix) + digits

        matched = (
            len(code) == expected_len
            and code.startswith(prefix)
            and code[len(prefix):].isdigit()
        )
        if not matched and len(code) > 0:
            logger.debug(
                f"{self._prefix} TOTP format check MISS: code_len={len(code)} "
                f"expected_len={expected_len} prefix_match={code[:len(prefix)] == prefix} "
                f"code_preview={code[:2]}***{code[-2:] if len(code) > 2 else ''}"
            )
        return matched

    # ------------------------------------------------------------------ #
    # ALLOW handler (passive observation, enrichment only)
    # ------------------------------------------------------------------ #

    def _handle_allow(
        self, card_no: str, event_time: str, event_id: str,
        door_id: Optional[int], event_type: str, raw_row: Dict[str, Any],
    ):
        """Device already opened door. Enrich with user data for popup/history."""
        t0 = time.monotonic()
        creds, users_by_am, users_by_card = self._get_cached_local_state()

        # Simple dict lookup -- no validation (device already decided)
        user = None
        hits = users_by_card.get(card_no) or []
        if hits:
            user = hits[0] if isinstance(hits, list) else hits

        # Fallback: for fingerprint scans the device sets cardNo=pin (F-004).
        # If card lookup missed, resolve the raw RTLog pin UNDER THIS DEVICE'S pinScheme.
        # users_by_am is keyed by activeMembershipId: on an ACCOUNT device that lookup names
        # nobody, or -- for the 110 colliding ids -- a stranger. guide §3.2b.
        if user is None and raw_row:
            pin_raw = str(raw_row.get("pin") or "").strip()
            if pin_raw.isdigit():
                try:
                    user = self._user_for_device_pin(pin_raw, users_by_am)
                except Exception:
                    pass

        user_name = ""
        user_image = ""
        user_membership_id: Optional[int] = None
        user_phone = ""
        user_valid_from = ""
        user_valid_to = ""
        image_source = ""
        user_image_status = ""
        user_profile_image = ""
        scan_mode = _scan_mode_for_event(raw_row)

        if isinstance(user, dict):
            user_name = str(user.get("fullName", user.get("full_name", user.get("name", ""))) or "")
            user_image = str(user.get("image", "") or "")
            raw_am_id = user.get("activeMembershipId")
            if raw_am_id is not None:
                try:
                    user_membership_id = int(str(raw_am_id).strip())
                except (ValueError, TypeError):
                    pass
            user_phone = str(user.get("phone", "") or "")
            user_valid_from = str(user.get("validFrom", user.get("valid_from", "")) or "")
            user_valid_to = str(user.get("validTo", user.get("valid_to", "")) or "")
            image_source = str(user.get("imageSource", "") or "")
            user_image_status = str(user.get("userImageStatus", "") or "")
            user_profile_image = str(user.get("userProfileImage", "") or "")

        if not user_name:
            logger.warning(
                f"{self._prefix} rtlog ALLOW: card={card_no!r} — "
                f"user NOT found in local cache (card not in sync_users)"
            )
        logger.info(
            f"{self._prefix} rtlog ALLOW: card={card_no!r} user={user_name!r} "
            f"door={door_id} event_id={event_id}"
        )

        self._enqueue_notification(
            event_id=event_id,
            allowed=True,
            reason="DEVICE_ALLOWED",
            scan_mode=scan_mode,
            user_full_name=user_name,
            user_image=user_image,
            user_membership_id=user_membership_id,
            user_membership_plan_id=(user.get("membershipId") if isinstance(user, dict) else None),
            user_phone=user_phone,
            user_valid_from=user_valid_from,
            user_valid_to=user_valid_to,
            user_birthday=(str(user.get("birthday") or "") if isinstance(user, dict) else ""),
            image_source=image_source,
            user_image_status=user_image_status,
            user_profile_image=user_profile_image,
            # for the frequent-pass visual alert only
            user_id=_uid_for_alert(user),
            door_id=door_id,
        )
        self._enqueue_history(
            event_id=event_id,
            allowed=True,
            reason="DEVICE_ALLOWED",
            event_type=event_type,
            card_no=card_no,
            event_time=event_time,
            door_id=door_id,
            raw=raw_row,
        )

        if (time.monotonic() - t0) * 1000 >= 250:
            _tel.warn("ALLOW_HANDLE_SLOW", worker=self._tel_wid, dur_ms=round((time.monotonic() - t0) * 1000))

    def _user_for_device_pin(self, pin: str, users_by_am: Dict[int, Any]) -> Optional[Dict[str, Any]]:
        """The member a pin reported by THIS device names, under its pinScheme.

        MEMBERSHIP: ``users_by_am[int(pin)]`` exactly as before (that index also carries the
        userId fallback pins). ACCOUNT: the collapsed per-person row
        ``_filter_users_for_device`` builds for this device -- the same derivation the push
        used, over the same local-state users -- so an event names the membership the device
        row represents. Cached per local-state snapshot and device dict.
        """
        from app.core.device_sync import PIN_SCHEME_ACCOUNT, device_pin_scheme

        if device_pin_scheme(self._device) != PIN_SCHEME_ACCOUNT:
            return users_by_am.get(int(pin))
        cached = getattr(self, "_account_pin_index_cache", None)
        if cached is not None and cached[0] is users_by_am and cached[1] is self._device:
            index = cached[2]
        else:
            from app.core.device_sync import DeviceSyncEngine

            seen: set[int] = set()
            users: list[Dict[str, Any]] = []
            for candidate in (users_by_am or {}).values():
                if isinstance(candidate, dict) and id(candidate) not in seen:
                    seen.add(id(candidate))
                    users.append(candidate)
            index = DeviceSyncEngine(cfg=self._cfg or SimpleNamespace(), logger=logger)._filter_users_for_device(
                users=users, device=dict(self._device or {}), default_door_id=1,
            )
            self._account_pin_index_cache = (users_by_am, self._device, index)
        return index.get(str(int(pin)))

    # ------------------------------------------------------------------ #
    # TOTP Rescue handler (active: verify + open door)
    # ------------------------------------------------------------------ #

    def _handle_totp_rescue(
        self, code: str, event_time: str, event_id: str,
        door_id: Optional[int], raw_row: Dict[str, Any],
        scan_epoch: Optional[float] = None,
    ):
        """Device denied a TOTP code. Verify locally, open door if valid.

        ``scan_epoch`` is the UTC epoch of the moment the device read the code
        (from the RTLog eventTime). verify_totp_resilient accepts the code if it
        is valid against either the scan time (removes RTLog poll/sync latency
        from the window) or the wall clock (covers a skewed device clock), so
        neither a processing delay nor a single bad clock alone can reject it.
        """
        # The refresh thread stores _cached_state, THEN _cached_state_gen, with no
        # lock. Reading the generation before and after the state and keeping the
        # lower one never labels this list newer than it is (the roster check below
        # would trust an old list); a refresh landing mid-read can only make it look
        # older -- roster_behind, i.e. no refusal -- for that one scan.
        _gen_before = self._cached_state_gen
        creds, users_by_am, users_by_card = self._get_cached_local_state()
        own_list_gen = min(_gen_before, self._cached_state_gen)

        # Use the precomputed O(1) index ONLY when it was built from the exact
        # Use the shared index if it was built from a credential generation that
        # is AT LEAST AS FRESH as ours (>=, not ==). A newer index is a SUBSET of
        # eligible creds (revocations already applied via the same
        # _iter_eligible_totp_creds filter), so verifying against it is STRICTER on
        # revocation, never looser — a removed member is absent from a newer index
        # and cannot match. Using >= (instead of ==) stops the two workers, which
        # sit at different _cached_state_gen, from perpetually rejecting each
        # other's shared index (the ~700 builds/hr gen-thrash). SAFETY RESTS ON
        # bump_local_state_generation() being MONOTONIC (db.py) — never reset/
        # decrement it, or a stale index could be accepted as "newer".
        _idx, _idx_gen = _get_shared_totp_index()
        totp_index = _idx if (_idx is not None and _idx_gen >= self._cached_state_gen) else None

        # A newer index carries grants from a newer credential generation than this
        # worker's member list. The roster check (verify_totp) compares the two, so a
        # member added since this worker last refreshed would read as "not on the
        # list". Check against the process-wide member list when it is at least as
        # new as the index; it is published before the index is built from it.
        # Never adopt an EMPTY shared list: load_local_state turns a failed users read
        # into [] and the refresh still publishes it, so an empty list there says
        # nothing about the members -- keeping our own list keeps names and the check.
        roster_gen = own_list_gen
        if totp_index is not None and _idx_gen > own_list_gen:
            _shared, _shared_gen = _get_shared_local_state()
            if (
                _shared_gen >= _idx_gen
                and isinstance(_shared, (tuple, list))
                and len(_shared) >= 3
                and _shared[1]
            ):
                users_by_am = _shared[1]
                roster_gen = _shared_gen
        # No list at least as new as the index (e.g. the newest refresh failed its
        # users read): a "not listed" verdict could be a member newer than the list,
        # so it is recorded as roster_behind and never refused.
        roster_current = totp_index is None or roster_gen >= _idx_gen

        t0 = time.monotonic()
        result = verify_totp_resilient(
            scanned=code,
            settings=self._settings,
            creds_payload=creds,
            users_by_am=users_by_am,
            users_by_card=users_by_card,
            scan_epoch=scan_epoch,
            totp_index=totp_index,
            roster_current=roster_current,
        )
        decision_ms = (time.monotonic() - t0) * 1000
        record_totp_roster_check(result, source=self._tel_wid)

        allowed = result.get("allowed", False)
        reason = result.get("reason", "DENY_TOTP_FAILED")
        user = result.get("user")
        user_name = ""
        user_image = ""
        user_membership_id: Optional[int] = None
        user_phone = ""
        user_valid_from = ""
        user_valid_to = ""
        image_source = ""
        user_image_status = ""
        user_profile_image = ""

        if isinstance(user, dict):
            user_name = str(user.get("fullName", user.get("full_name", user.get("name", ""))) or "")
            user_image = str(user.get("image", "") or "")
            raw_am_id = user.get("activeMembershipId")
            if raw_am_id is not None:
                try:
                    user_membership_id = int(str(raw_am_id).strip())
                except (ValueError, TypeError):
                    pass
            user_phone = str(user.get("phone", "") or "")
            user_valid_from = str(user.get("validFrom", user.get("valid_from", "")) or "")
            user_valid_to = str(user.get("validTo", user.get("valid_to", "")) or "")
            image_source = str(user.get("imageSource", "") or "")
            user_image_status = str(user.get("userImageStatus", "") or "")
            user_profile_image = str(user.get("userProfileImage", "") or "")

        cmd_ms = 0.0
        cmd_ok: Optional[bool] = None
        cmd_error = ""

        masked_code = code[0] + "*" * (len(code) - 2) + code[-1] if len(code) > 2 else code
        logger.info(
            f"{self._prefix} TOTP_RESCUE: code={masked_code} "
            f"allowed={allowed} reason={reason} user={user_name!r} "
            f"decision_ms={decision_ms:.1f} event_id={event_id}"
        )

        if allowed:
            # Staff exemption: mark this code so a re-scan only pays the debounce
            # floor, not the re-entry delay. Resolved from the member's plan id
            # (cached set, no per-scan DB read). RFID is opened by the device
            # itself, so it can't be exempted this way — TOTP only.
            try:
                plan_id = user.get("membershipId") if isinstance(user, dict) else None
                if plan_id is not None and int(plan_id) in get_staff_membership_ids_cached():
                    now_m = time.monotonic()
                    self._staff_codes[code] = now_m + _ULTRA_STAFF_CODE_TTL_SEC
                    if len(self._staff_codes) > 500:
                        self._staff_codes = {k: v for k, v in self._staff_codes.items() if v > now_m}
                    logger.debug(
                        f"{self._prefix} staff re-entry exemption: plan={plan_id} code={masked_code}"
                    )
            except Exception:
                pass
            # Open door
            logger.info(
                f"{self._prefix} TOTP_RESCUE opening door: door_id={door_id} "
                f"user={user_name!r} code={masked_code}"
            )
            t_cmd = time.monotonic()
            door_opened = self._open_door_with_retry(door_id=door_id)
            cmd_ms = (time.monotonic() - t_cmd) * 1000
            cmd_ok = door_opened

            if door_opened:
                self._totp_rescues += 1
                logger.info(
                    f"{self._prefix} TOTP_RESCUE door OPENED: code={masked_code} "
                    f"user={user_name!r} decision={decision_ms:.0f}ms cmd={cmd_ms:.0f}ms"
                )
            else:
                allowed = False
                reason = "DOOR_CMD_FAILED"
                cmd_error = "door open failed after valid TOTP"
                self._door_cmd_failures += 1
                logger.error(
                    f"{self._prefix} TOTP_RESCUE door FAILED to open: code={masked_code} "
                    f"user={user_name!r} cmd_ms={cmd_ms:.0f}ms door_cmd_failures={self._door_cmd_failures}"
                )
        else:
            self._totp_failures += 1
            logger.info(
                f"{self._prefix} TOTP_RESCUE DENY: code={masked_code} reason={reason} "
                f"user={user_name!r} totp_failures={self._totp_failures}"
            )

        self._enqueue_notification(
            event_id=event_id,
            allowed=allowed,
            reason=reason,
            scan_mode="QR_TOTP",
            user_full_name=user_name,
            user_image=user_image,
            user_membership_id=user_membership_id,
            user_membership_plan_id=(user.get("membershipId") if isinstance(user, dict) else None),
            user_phone=user_phone,
            user_valid_from=user_valid_from,
            user_valid_to=user_valid_to,
            user_birthday=(str(user.get("birthday") or "") if isinstance(user, dict) else ""),
            image_source=image_source,
            user_image_status=user_image_status,
            user_profile_image=user_profile_image,
            # for the frequent-pass visual alert only
            user_id=_uid_for_alert(user),
            door_id=door_id,
        )
        # Persist the resolved member + tag the raw with scanMode so the backend
        # uploader can (a) classify this as QR_CODE and (b) re-resolve the member.
        # A TOTP row's card_no is a rotating token (absent from users_by_card, no
        # PIN), so without the persisted user_id/active_membership_id the backend
        # drops the row from member-filtered door-history and, without the scanMode
        # tag, labels it CARD. Mirrors the AGENT path (realtime_agent.py).
        _resolved_user_id: Optional[int] = None
        _resolved_am_id: Optional[int] = None
        try:
            if isinstance(user, dict) and user.get("userId") not in (None, ""):
                _resolved_user_id = int(str(user.get("userId")).strip())
        except (ValueError, TypeError):
            _resolved_user_id = None
        try:
            _am_src = result.get("activeMembershipId")
            if _am_src in (None, "") and isinstance(user, dict):
                _am_src = user.get("activeMembershipId")
            if _am_src not in (None, ""):
                _resolved_am_id = int(str(_am_src).strip())
        except (ValueError, TypeError):
            _resolved_am_id = None
        _hist_raw = (
            {**dict(raw_row), "scanMode": "QR_TOTP"}
            if isinstance(raw_row, dict)
            else {"scanMode": "QR_TOTP"}
        )

        self._enqueue_history(
            event_id=event_id,
            allowed=allowed,
            reason=reason,
            event_type="QR_TOTP",
            card_no=code,
            event_time=event_time,
            door_id=door_id,
            raw=_hist_raw,
            decision_ms=decision_ms,
            cmd_ms=cmd_ms,
            cmd_ok=cmd_ok,
            cmd_error=cmd_error,
            user_id=_resolved_user_id,
            active_membership_id=_resolved_am_id,
        )

    def _open_door_with_retry(self, *, door_id: Optional[int] = None) -> bool:
        """Open door via PullSDK. Retry once on failure. Returns True if succeeded."""
        resolved_door_id = int(self._settings.get("door_entry_id", 1))
        try:
            candidate = int(door_id) if door_id is not None else 0
            if candidate > 0:
                resolved_door_id = candidate
        except Exception:
            pass

        # Per-door pulse from doorPresets (set in dashboard), fallback to device-level pulseTimeMs.
        pulse_ms = int(self._settings.get("pulse_time_ms", 3000))
        for p in (self._settings.get("door_presets") or []):
            if not isinstance(p, dict):
                continue
            dn = p.get("doorNumber") or p.get("door_number")
            if dn is not None and int(dn) == resolved_door_id:
                ps = p.get("pulseSeconds") or p.get("pulse_seconds")
                if ps is not None and int(ps) > 0:
                    pulse_ms = int(ps) * 1000
                break

        logger.debug(
            f"{self._prefix} open_door_with_retry: resolved_door_id={resolved_door_id} "
            f"pulse_ms={pulse_ms} sdk_connected={bool(self._sdk and self._connected)}"
        )
        for attempt in range(2):
            try:
                if self._sdk is None:
                    logger.error(f"{self._prefix} open_door attempt {attempt + 1}: sdk is None (not connected)")
                    break
                ok = self._sdk.open_door(door_id=resolved_door_id, pulse_time_ms=pulse_ms, timeout_ms=4000)
                if ok:
                    logger.debug(f"{self._prefix} open_door succeeded on attempt {attempt + 1}")
                    # Stamp this PC-initiated open so a later EVENT=20 rejection can
                    # be attributed to it (the device may start DoorNIntertime on
                    # ANY open, incl. a PC/QR/TOTP/staff open — see REENTRY_BLOCK).
                    try:
                        if not hasattr(self, "_reentry_last_open_mono"):
                            self._reentry_last_open_mono = {}
                        self._reentry_last_open_mono[resolved_door_id] = time.monotonic()
                    except Exception:
                        pass
                    return True
                else:
                    logger.warning(
                        f"{self._prefix} open_door attempt {attempt + 1} returned False"
                    )
            except Exception as e:
                logger.warning(
                    f"{self._prefix} open_door attempt {attempt + 1} EXCEPTION: {e}"
                )
            if attempt == 0:
                time.sleep(0.1)
        logger.error(f"{self._prefix} open_door_with_retry: all attempts failed for door_id={resolved_door_id}")
        return False

    # ------------------------------------------------------------------ #
    # DENY handler (passive observation)
    # ------------------------------------------------------------------ #

    def _handle_rfid_rescue(
        self, card_no: str, event_time: str, event_id: str,
        door_id: Optional[int], event_type: str, raw_row: Dict[str, Any],
    ):
        """PC-side STAFF rescue for a denied RFID card.

        The device denied this card (unknown, or — the common case — its
        punch-interval re-entry block fired). If the card is a VALID member whose
        plan is STAFF, the PC re-opens the door so staff skip the re-entry delay.
        Every other denied card falls through to _handle_deny, so the device's
        decision (including the interval block) stands for non-staff.

        SECURITY: opens ONLY when verify_card validates the card (RFID enabled,
        format/length, exactly one active-member match) AND the member's plan is
        in the cached STAFF set. Never opens a non-staff, unknown, or invalid card.
        Runs on the worker thread; opens via the held SDK socket (no 2nd Connect).
        """
        if not bool(self._settings.get("ultra_rfid_staff_rescue_enabled", True)):
            self._handle_deny(card_no, event_time, event_id, door_id, event_type, raw_row)
            return

        t0 = time.monotonic()
        _creds, _uam, users_by_card = self._get_cached_local_state()
        vr = verify_card(scanned=card_no, settings=self._settings, users_by_card=users_by_card)
        user = vr.get("user") if vr.get("allowed") else None
        plan_id = user.get("membershipId") if isinstance(user, dict) else None
        is_staff = False
        staff_n = -1
        try:
            staff_ids = get_staff_membership_ids_cached()
            staff_n = len(staff_ids)
            is_staff = plan_id is not None and int(plan_id) in staff_ids
        except Exception:
            is_staff = False

        # Observability for the staff blind spot (rare — only on RFID deny events):
        # valid=is the card a recognised active member, staff_n=size of the STAFF
        # plan set (0 => backend membersType not deployed), staff=matched. Lets the
        # next gym test tell "backend not deployed" (staff_n=0) from "plan mismatch"
        # (staff_n>0, valid=1, staff=0) from "unknown card" (valid=0).
        _tel.event(
            "RFID_RESCUE_EVAL", worker=self._tel_wid, valid=bool(vr.get("allowed")),
            staff=is_staff, staff_n=staff_n, plan=plan_id, event_id=event_id,
        )

        if not (vr.get("allowed") and is_staff):
            # Not a valid staff card — respect the device's deny.
            self._handle_deny(card_no, event_time, event_id, door_id, event_type, raw_row)
            return

        masked = card_no[0] + "*" * (len(card_no) - 2) + card_no[-1] if len(card_no) > 2 else card_no
        user_name = str(user.get("fullName", user.get("full_name", user.get("name", ""))) or "")
        logger.info(
            f"{self._prefix} RFID_STAFF_RESCUE opening: card={masked} user={user_name!r} "
            f"plan={plan_id} door={door_id} event_id={event_id}"
        )
        t_cmd = time.monotonic()
        door_opened = self._open_door_with_retry(door_id=door_id)
        cmd_ms = (time.monotonic() - t_cmd) * 1000
        _tel.event(
            "RFID_STAFF_RESCUE", worker=self._tel_wid, ok=door_opened,
            plan=plan_id, cmd_ms=round(cmd_ms), event_id=event_id,
        )

        # Enrich popup/history from the member (mirror _handle_allow).
        user_image = str(user.get("image", "") or "")
        user_profile_image = str(user.get("userProfileImage", "") or "")
        image_source = str(user.get("imageSource", "") or "")
        user_image_status = str(user.get("userImageStatus", "") or "")
        user_phone = str(user.get("phone", "") or "")
        user_valid_from = str(user.get("validFrom", user.get("valid_from", "")) or "")
        user_valid_to = str(user.get("validTo", user.get("valid_to", "")) or "")
        user_membership_id: Optional[int] = None
        raw_am_id = user.get("activeMembershipId")
        if raw_am_id is not None:
            try:
                user_membership_id = int(str(raw_am_id).strip())
            except (ValueError, TypeError):
                pass

        reason = "ALLOW_STAFF_RFID" if door_opened else "DOOR_CMD_FAILED"
        self._enqueue_notification(
            event_id=event_id,
            allowed=door_opened,
            reason=reason,
            scan_mode=_scan_mode_for_event(raw_row),
            user_full_name=user_name,
            user_image=user_image,
            user_membership_id=user_membership_id,
            user_membership_plan_id=plan_id,
            user_phone=user_phone,
            user_valid_from=user_valid_from,
            user_valid_to=user_valid_to,
            user_birthday=(str(user.get("birthday") or "") if isinstance(user, dict) else ""),
            image_source=image_source,
            user_image_status=user_image_status,
            user_profile_image=user_profile_image,
            # for the frequent-pass visual alert only
            user_id=_uid_for_alert(user),
            door_id=door_id,
        )
        self._enqueue_history(
            event_id=event_id,
            allowed=door_opened,
            reason=reason,
            event_type=event_type,
            card_no=card_no,
            event_time=event_time,
            door_id=door_id,
            raw=raw_row,
        )
        if (time.monotonic() - t0) * 1000 >= 250:
            _tel.warn("RFID_RESCUE_SLOW", worker=self._tel_wid, dur_ms=round((time.monotonic() - t0) * 1000))

    def _handle_deny(
        self, card_no: str, event_time: str, event_id: str,
        door_id: Optional[int], event_type: str, raw_row: Dict[str, Any],
    ):
        """Device denied a non-TOTP code. Log and notify."""
        t0 = time.monotonic()
        logger.info(
            f"{self._prefix} rtlog DENY: card={card_no!r} reason=DEVICE_DENIED "
            f"event_type={event_type!r} door={door_id} event_id={event_id}"
        )
        self._enqueue_notification(
            event_id=event_id,
            allowed=False,
            reason="DEVICE_DENIED",
            scan_mode=_scan_mode_for_event(raw_row),
            user_full_name="",
            user_image="",
            user_membership_id=None,
            user_phone="",
            user_valid_from="",
            user_valid_to="",
            user_profile_image="",
        )
        self._enqueue_history(
            event_id=event_id,
            allowed=False,
            reason="DEVICE_DENIED",
            event_type=event_type,
            card_no=card_no,
            event_time=event_time,
            door_id=door_id,
            raw=raw_row,
        )

        if (time.monotonic() - t0) * 1000 >= 250:
            _tel.warn("DENY_HANDLE_SLOW", worker=self._tel_wid, dur_ms=round((time.monotonic() - t0) * 1000))

    # ------------------------------------------------------------------ #
    # Notification and history helpers
    # ------------------------------------------------------------------ #

    def _enqueue_notification(
        self,
        *,
        event_id: str,
        allowed: bool,
        reason: str,
        scan_mode: str,
        user_full_name: str,
        user_image: str,
        user_membership_id: Optional[int],
        user_phone: str,
        user_valid_from: str,
        user_valid_to: str,
        # Drives the popup's birthday screen. ULTRA never populated it, so that
        # screen could not fire at all on an ULTRA gym -- only the AGENT engine
        # set it (realtime_agent.py). The value is already in the local user
        # cache (sync_users.birthday); it just never reached the event.
        user_birthday: str = "",
        image_source: str = "",
        user_image_status: str = "",
        user_profile_image: str = "",
        user_membership_plan_id: Optional[int] = None,
        user_id: Optional[int] = None,
        door_id: Optional[int] = None,
    ):
        t0 = time.monotonic()
        popup_enabled = self._settings.get("popup_enabled", True)
        if not popup_enabled:
            return

        # Resolve membership plan name + type for the scan-popup badge (best-effort).
        user_membership_title = ""
        user_members_type = ""
        if user_membership_plan_id is not None:
            try:
                # Cached badge lookup (no per-scan DB read on the live loop; was
                # NOTIF_ENQUEUE_SLOW up to ~1.1s/scan on the AV-slow gym PC).
                brief = get_membership_brief_index_cached().get(int(user_membership_plan_id), {})
                user_membership_title = str(brief.get("title") or "")
                user_members_type = str(brief.get("membersType") or "")
            except Exception:
                pass

        # Kick the image fetch onto a background pool the moment we know we'll
        # display this card. By the time the popup window mounts the <img>
        # tag (5-50ms later for SSE delivery, 50-200ms for browser layout),
        # the bytes are usually already on disk and the local API answers
        # from the cache. Without this, the popup waits on a synchronous
        # backend fetch — slow on Tunisian 4G — and shows the no-image
        # placeholder for 1-3s before the image finally loads.
        if bool(self._settings.get("popup_show_image", True)):
            try:
                if user_image:
                    _prefetch_popup_image(user_image)
                if user_profile_image and user_profile_image != user_image:
                    _prefetch_popup_image(user_profile_image)
            except Exception:
                logger.debug(
                    "%s popup image prefetch failed (non-fatal)",
                    self._prefix,
                    exc_info=True,
                )

        # User-facing message for error states
        message = ""
        if reason == "DOOR_CMD_FAILED":
            message = "Valid code but door did not open -- try again or use card"

        # ── Frequent-pass VISUAL alert (X passages inside Y minutes) ──
        # Tells the entry screen that this member already came through recently, so
        # the front desk can compare the face to the photo.
        #
        # THIS NEVER BLOCKS. `allowed`, the door pulse and the access decision were
        # all settled by the caller before we got here; nothing below is read back
        # into the decision. Blocking re-entry remains anti_fraude_duration only.
        _rep_count = 0
        _rep_limit = 0
        _rep_window = 0
        _prev_at = ""
        try:
            _rep_limit = int(self._settings.get("frequent_pass_limit") or 0)
            _rep_window = int(self._settings.get("frequent_pass_window_minutes") or 0)
            if (
                allowed
                and _rep_limit > 1
                and _rep_window > 0
                and user_id is not None
                and door_id is not None
            ):
                _prior, _prev_raw = count_recent_for_user_door(
                    user_id=int(user_id),
                    device_id=int(self._device_id),
                    door_id=int(door_id),
                    window_minutes=_rep_window,
                )
                # ULTRA persists history asynchronously (_enqueue_history is drained
                # on a later tick), so the scan being handled right now is NOT in
                # access_history yet. Count it explicitly.
                _total = int(_prior) + 1
                if _total >= _rep_limit:
                    _rep_count = _total
                    _prev_at = str(_prev_raw or "")
        except Exception as exc:
            _rep_count, _prev_at = 0, ""
            logger.warning(f"{self._prefix} frequent-pass alert check failed: {exc}")

        try:
            req = NotificationRequest(
                event_id=event_id,
                title="Acces",
                message=message,
                image_path="",
                popup_show_image=bool(self._settings.get("popup_show_image", True)),
                user_full_name=user_full_name,
                user_image=user_image,
                user_valid_from=user_valid_from,
                user_valid_to=user_valid_to,
                user_birthday=user_birthday,
                user_membership_id=user_membership_id,
                user_membership_title=user_membership_title,
                user_members_type=user_members_type,
                user_phone=user_phone,
                device_id=self._device_id,
                device_name=self._device_name,
                allowed=allowed,
                reason=reason,
                scan_mode=scan_mode,
                image_source=image_source,
                user_image_status=user_image_status,
                user_profile_image=user_profile_image,
                popup_duration_sec=int(self._settings.get("popup_duration_sec", 3)),
                popup_enabled=True,
                win_notify_enabled=bool(self._settings.get("win_notify_enabled", False)),
                repeat_count=_rep_count,
                repeat_limit=(_rep_limit if _rep_count else 0),
                repeat_window_min=(_rep_window if _rep_count else 0),
                previous_entry_at=_prev_at,
            )
            self._popup_q.put_nowait(req)
            logger.debug(
                f"{self._prefix} popup enqueued: allowed={allowed} reason={reason} "
                f"user={user_full_name!r} scan_mode={scan_mode} event_id={event_id}"
            )
            _tel.event(
                "POPUP_ENQUEUE", worker=self._tel_wid, allowed=allowed, reason=reason,
                scan_mode=scan_mode, qsize=self._popup_q.qsize(), event_id=event_id,
            )
        except queue.Full:
            logger.warning(
                f"{self._prefix} popup queue FULL — dropping notification "
                f"(allowed={allowed} user={user_full_name!r} event_id={event_id})"
            )
            _tel.warn(
                "POPUP_QUEUE_FULL", worker=self._tel_wid, allowed=allowed,
                reason=reason, event_id=event_id,
            )

        if (time.monotonic() - t0) * 1000 >= 100:
            _tel.warn("NOTIF_ENQUEUE_SLOW", worker=self._tel_wid, dur_ms=round((time.monotonic() - t0) * 1000))

    def _enqueue_history(
        self,
        *,
        event_id: str,
        allowed: bool,
        reason: str,
        event_type: str,
        card_no: str,
        event_time: str,
        door_id: Optional[int] = None,
        raw: Optional[Dict[str, Any]] = None,
        decision_ms: float = 0.0,
        cmd_ms: float = 0.0,
        cmd_ok: Optional[bool] = None,
        cmd_error: str = "",
        user_id: Optional[int] = None,
        active_membership_id: Optional[int] = None,
    ):
        """Hand the access event to the OFF-LOOP history writer (non-blocking).

        The DB insert (insert_access_history, INSERT OR IGNORE) and the
        backend-sync enqueue now run on a dedicated writer thread, NOT the live
        worker loop. A sync flooding the DbWriter previously stalled the loop for
        seconds per event (HIST_INSERT_SLOW), delaying scans / door-opens / popups
        — the recurring ~30-min "freeze". Enqueueing is O(1); on overflow the
        OLDEST queued record is dropped so the worker never blocks (history is a
        best-effort audit record, and the device's own log retains the event).
        """
        item = {
            "event_id": event_id,
            "door_id": door_id,
            "card_no": card_no,
            "event_time": event_time,
            "event_type": event_type,
            "allowed": allowed,
            "reason": reason,
            "poll_ms": self._poll_ema_ms,
            "decision_ms": decision_ms,
            "cmd_ms": cmd_ms,
            "cmd_ok": cmd_ok,
            "cmd_error": cmd_error,
            "raw": raw or {},
            "user_id": user_id,
            "active_membership_id": active_membership_id,
        }
        t = getattr(self, "_history_writer_thread", None)
        if t is None or not t.is_alive():
            # No live off-loop writer: persist inline. In production the writer is
            # started in run() before the poll loop, so this branch covers unit
            # tests (which drive _process_event directly) and the rare case of a
            # writer that has died — in both, recording the audit row matters more
            # than the (test-only / degraded) inline cost. The hot path in
            # production always takes the async branch below and never blocks.
            self._write_history_item(item)
            return
        wq = self._get_history_write_q()
        try:
            wq.put_nowait(item)
        except queue.Full:
            # Writer is behind (DbWriter flooded by a sync). Drop the OLDEST so the
            # worker never blocks; better to lose one audit row than to freeze.
            try:
                wq.get_nowait()
                wq.put_nowait(item)
            except (queue.Empty, queue.Full):
                pass
            _tel.warn("HIST_WRITE_Q_FULL", worker=self._tel_wid)

    def _get_history_write_q(self) -> "queue.Queue":
        """Return the history write queue, lazily creating it.

        Lazy-init keeps test harnesses that build the worker via __new__ (bypassing
        __init__) working without extra setup.
        """
        wq = getattr(self, "_history_write_q", None)
        if wq is None:
            wq = queue.Queue(maxsize=5000)
            self._history_write_q = wq
        return wq

    def _ensure_history_writer(self) -> None:
        """Start the dedicated history-writer thread (idempotent).

        Called from run() at worker start so the writer drains events that the loop
        enqueues. Daemon thread; exits when _stop_evt is set.
        """
        t = getattr(self, "_history_writer_thread", None)
        if t is not None and t.is_alive():
            return
        try:
            t = threading.Thread(
                target=self._history_writer_loop,
                name=f"hist-writer-{self._device_id}",
                daemon=True,
            )
            t.start()
            self._history_writer_thread = t
        except Exception as e:
            self._history_writer_thread = None
            _tel.warn("HIST_WRITER_SPAWN_FAIL", worker=self._tel_wid, err=type(e).__name__)

    def _history_writer_loop(self) -> None:
        """Dedicated thread: run the synchronous history DB insert + backend-sync
        enqueue OFF the live worker loop, so DbWriter contention (e.g. while a sync
        floods the writer) never stalls scans / door-opens."""
        wq = self._get_history_write_q()
        while not self._stop_evt.is_set():
            try:
                item = wq.get(timeout=1.0)
            except queue.Empty:
                continue
            if not item:
                continue
            try:
                self._write_history_item(item)
            except Exception as e:
                logger.error(f"{self._prefix} history writer error: {e}")

    def _flush_history_writes(self) -> None:
        """Drain and persist all currently-queued history items synchronously.

        Used by tests (no writer thread) and as a best-effort flush on shutdown so
        queued audit rows are not lost. Safe to run alongside the writer thread:
        each item is consumed once by whichever side grabs it.
        """
        wq = self._get_history_write_q()
        while True:
            try:
                item = wq.get_nowait()
            except queue.Empty:
                return
            if not item:
                continue
            try:
                self._write_history_item(item)
            except Exception as e:
                logger.error(f"{self._prefix} history flush error: {e}")

    def _write_history_item(self, item: Dict[str, Any]) -> None:
        """Persist one history item (DB insert + backend-sync enqueue).

        Runs on the writer thread (or the synchronous flush), never the live loop.
        Insert uses INSERT OR IGNORE for DB-level dedup; only rowcount==1 (a genuine
        new row) is forwarded to the backend-sync queue.
        """
        _hist_t0 = time.monotonic()
        try:
            rowcount = insert_access_history(
                event_id=item["event_id"],
                device_id=self._device_id,
                door_id=item["door_id"],
                card_no=item["card_no"],
                event_time=item["event_time"],
                event_type=item["event_type"],
                allowed=item["allowed"],
                reason=item["reason"],
                poll_ms=item["poll_ms"],
                decision_ms=item["decision_ms"],
                cmd_ms=item["cmd_ms"],
                cmd_ok=item["cmd_ok"],
                cmd_error=item["cmd_error"],
                raw=item["raw"],
                history_source="ULTRA",
                user_id=item["user_id"],
                active_membership_id=item["active_membership_id"],
            )
            inserted = rowcount == 1
        except Exception as e:
            logger.error(f"{self._prefix} history DB insert failed: {e}")
            inserted = False  # treat as duplicate to avoid bypass of dedup gate
        finally:
            _hist_ms = (time.monotonic() - _hist_t0) * 1000.0
            if _hist_ms >= 250.0:
                # Now OFF the live loop — this still surfaces DbWriter contention
                # for diagnostics, but no longer blocks scans/door-opens.
                _tel.warn("HIST_INSERT_SLOW", worker=self._tel_wid, dur_ms=round(_hist_ms))

        if not inserted:
            return  # duplicate, already processed

        try:
            rec = HistoryRecord(
                event_id=item["event_id"],
                device_id=self._device_id,
                door_id=item["door_id"],
                card_no=item["card_no"],
                event_time=item["event_time"],
                event_type=item["event_type"],
                allowed=item["allowed"],
                reason=item["reason"],
                poll_ms=item["poll_ms"],
                decision_ms=item["decision_ms"],
                cmd_ms=item["cmd_ms"],
                cmd_ok=item["cmd_ok"] is True,
                cmd_error=item["cmd_error"],
                raw=item["raw"],
            )
            self._history_q.put_nowait(rec)
        except queue.Full:
            logger.warning(f"{self._prefix} history queue full, dropping record")

    # ------------------------------------------------------------------ #
    # Local state caching (avoid per-event DB reads)
    # ------------------------------------------------------------------ #

    def _trigger_bg_cache_refresh(self) -> None:
        """Signal the persistent refresh thread to reload local state (non-blocking).

        The refresh runs on ONE long-lived thread (not a fresh thread per call), so
        its SQLite connection's page cache stays warm across refreshes — measured
        ~1.5s warm vs ~6.4s cold-per-thread on the gym PC. Reusing the thread also
        REDUCES thread churn (safer for the 32-bit thread ceiling). The worker is
        never blocked: it just sets an event.
        """
        evt = getattr(self, "_refresh_evt", None)
        if evt is None:
            evt = threading.Event()
            self._refresh_evt = evt
            self._refresh_thread_lock = threading.Lock()
            self._refresh_thread = None
        self._ensure_refresh_thread()
        evt.set()

    def _ensure_refresh_thread(self) -> None:
        with self._refresh_thread_lock:
            t = getattr(self, "_refresh_thread", None)
            if t is not None and t.is_alive():
                return
            try:
                t = threading.Thread(
                    target=self._refresh_loop, daemon=True,
                    name=f"cache-refresh-{self._device_id}",
                )
                self._refresh_thread = t
                t.start()
            except RuntimeError as _exc:
                self._refresh_thread = None
                _tel.thread_spawn_failure(
                    "ultra._ensure_refresh_thread", worker=self._tel_wid, err=str(_exc),
                )

    def _refresh_loop(self) -> None:
        """Persistent local-state refresh worker. One per device; reused so its
        DB connection cache stays warm. Exits when the worker stops."""
        while not self._stop_evt.is_set():
            triggered = self._refresh_evt.wait(timeout=5.0)
            if self._stop_evt.is_set():
                break
            if triggered:
                self._refresh_evt.clear()
                _bg_t0 = time.monotonic()
                try:
                    _gen_at_load = get_local_state_generation()
                    result = load_local_state()
                    if result and isinstance(result, (tuple, list)) and len(result) >= 3:
                        self._cached_state = result
                        self._cached_state_ts = time.monotonic()
                        self._cached_state_gen = _gen_at_load
                        _set_shared_local_state(result, _gen_at_load)
                        creds, uam, ucard = result
                        _tel.event(
                            "CACHE_BG_REFRESH_DONE", worker=self._tel_wid,
                            dur_ms=round((time.monotonic() - _bg_t0) * 1000), creds=len(creds),
                        )
                        # Warm the popup-image cache for ALL members NOW (on this bg
                        # thread), so a member's avatar is already downloaded before
                        # they scan — fixes "image black on first scan" (the on-scan
                        # prefetch lost the race against the 3s popup + ~3s fetch).
                        self._prefetch_member_images(uam)
                except Exception as e:
                    logger.warning(f"{self._prefix} bg cache refresh failed: {e}")
                    _tel.warn("CACHE_BG_REFRESH_FAILED", worker=self._tel_wid, err=type(e).__name__)
            # Every tick (≤5s), reload or not: keep the precomputed TOTP index
            # covering the current counter window so QR verification stays O(1)
            # across period rolls. Always built here (bg thread), never on a scan.
            try:
                self._maybe_rebuild_totp_index()
            except Exception:
                pass
            # Hourly QR roster-check totals (§3.1b); a no-op until due.
            maybe_log_totp_roster_summary()
            # Every tick (≤5s): pre-warm the staff-ids + membership-brief caches
            # HERE on the bg thread (warm connection) so their 60s-TTL/gen DB
            # reload never fires INLINE on a scan's door/popup path. The hot path
            # reads the *_cached() peeks (no SQLite). This is what removed the
            # ~1.1s STAFF_IDS_REFRESH stall on the TOTP door-open path and the
            # NOTIF_ENQUEUE_SLOW badge stall.
            try:
                get_staff_membership_ids()
                get_membership_brief_index()
            except Exception:
                pass

    def _prefetch_member_images(self, users_by_am) -> None:
        """Submit ALL members' avatar/face images to the popup-image prefetch pool
        so they are downloaded and cached BEFORE the member scans. prefetch() is
        idempotent (skips already-cached files via a cheap stat), so re-running is
        safe. Throttled to once / 5 min to avoid re-iterating the full roster on
        every refresh. Runs on the bg refresh thread — never blocks the worker.
        """
        try:
            now = time.monotonic()
            if (now - getattr(self, "_last_img_prefetch_mono", 0.0)) < 300.0:
                return
            self._last_img_prefetch_mono = now
            submitted = 0
            for u in (users_by_am or {}).values():
                if not isinstance(u, dict):
                    continue
                for key in ("userProfileImage", "image"):
                    img = u.get(key)
                    if img:
                        try:
                            _prefetch_popup_image(str(img))
                            submitted += 1
                        except Exception:
                            pass
            if submitted:
                _tel.event("MEMBER_IMG_PREFETCH", worker=self._tel_wid, submitted=submitted)
        except Exception:
            pass

    def _maybe_rebuild_totp_index(self) -> None:
        """Keep the process-wide {code -> hits} TOTP index covering the current
        counter window so QR verification is O(1) instead of HMAC-ing every
        credential (~350ms on the gym roster).

        Rebuilds only when the creds changed (generation moved) or the index no
        longer covers / matches the current window+params — the SAME conditions
        verify_totp uses to accept it. A miss is harmless: verify_totp falls back
        to the full loop, so this is a pure latency optimization. Tagged with the
        local-state generation so a worker never verifies against a stale index.
        Runs on the bg refresh thread; never blocks a scan.
        """
        try:
            if not bool(self._settings.get("totp_enabled", True)):
                return
            if not bool(self._settings.get("ultra_totp_index_enabled", True)):
                return
            state = self._cached_state
            if not state or not isinstance(state, (tuple, list)) or len(state) < 1:
                return
            creds = state[0]
            gen = self._cached_state_gen
            now = time.time()
            period, drift, digits, prefix = _totp_params(self._settings)
            cur = _totp_counter(int(now), period)
            needed = set(range(cur - drift, cur + drift + 1))
            cur_struct, cur_gen = _get_shared_totp_index()
            if (
                isinstance(cur_struct, dict)
                # >= (not ==): accept a shared index at least as fresh as our creds.
                # This is what stops the two workers (at different _cached_state_gen)
                # from perpetually restamping each other's index — the ~700 builds/hr
                # gen-thrash. A newer index is a subset of eligible creds (stricter
                # on revocation), so it is safe to reuse. Rests on the generation
                # being MONOTONIC (db.bump_local_state_generation only increments).
                and cur_gen >= gen
                and cur_struct.get("params") == (period, drift, digits, prefix)
                and needed.issubset(cur_struct.get("counters") or set())
            ):
                return  # still fresh — covers the current window
            _t0 = time.monotonic()
            # margin=1 (small window). The rebuild frequency is now bounded by the
            # counter window rolling (~every couple of periods), NOT by the gen-
            # thrash (fixed above via the >= gate + monotonic _set_shared_totp_index),
            # so only ONE worker rebuilds per roll and the other reuses it.
            struct = build_totp_index(creds, self._settings, now, margin=1)
            _set_shared_totp_index(struct, gen)
            _tel.event(
                "TOTP_INDEX_BUILD", worker=self._tel_wid,
                dur_ms=round((time.monotonic() - _t0) * 1000),
                creds=struct.get("credCount", 0), codes=len(struct.get("index") or {}),
                gen=gen,
            )
        except Exception as e:
            _tel.warn("TOTP_INDEX_BUILD_FAILED", worker=self._tel_wid, err=type(e).__name__)

    def _get_cached_local_state(self):
        """Return (creds, users_by_am, users_by_card) without ever blocking the
        worker on the slow load_local_state() (78s on the gym PC).

        Order of preference: fresh per-worker cache → stale per-worker cache (+bg
        refresh) → process-wide last-good snapshot (+bg refresh) → ONE synchronous
        load (first-ever load in the process only, at startup).
        """
        now = time.monotonic()
        try:
            current_gen = get_local_state_generation()
        except Exception:
            current_gen = self._cached_state_gen
        # Reload only when: no data, the data actually changed (generation moved),
        # or the long TTL safety net elapsed. This stops the every-~60s full re-read
        # of the 1798-row users table when nothing changed.
        gen_changed = self._cached_state_gen != current_gen
        needs_refresh = (
            self._cached_state is None
            or gen_changed
            or (now - self._cached_state_ts) > self._CACHE_TTL_SEC
        )

        if not needs_refresh:
            return self._cached_state

        # Stale-but-usable per-worker data: serve it, refresh in the background.
        if self._cached_state is not None:
            self._trigger_bg_cache_refresh()
            return self._cached_state

        # No per-worker data. Adopt the process-wide last-good snapshot so we do
        # NOT freeze the worker for the full synchronous load. Refresh in the bg
        # only if the snapshot is itself behind the current generation.
        shared_value, shared_gen = _get_shared_local_state()
        if shared_value is not None and isinstance(shared_value, (tuple, list)) and len(shared_value) >= 3:
            self._cached_state = shared_value
            self._cached_state_ts = now
            self._cached_state_gen = shared_gen
            try:
                _tel.event("CACHE_ADOPTED_SHARED", worker=self._tel_wid, creds=len(shared_value[0]))
            except Exception:
                pass
            # Also refresh when the adopted snapshot has no members: that is a failed
            # users read, not "no members", and at the current generation nothing else
            # would reload it before the TTL.
            if shared_gen != current_gen or not _snapshot_has_members(shared_value):
                self._trigger_bg_cache_refresh()
            return self._cached_state

        # First-ever load in the whole process — block ONCE (startup only).
        logger.debug(f"{self._prefix} refreshing local state cache from DB (sync, first load)")
        _tel.set_state(self._tel_wid, "cache_load", "sync")
        _cl_t0 = time.monotonic()
        _gen_at_load = current_gen
        result = load_local_state()
        if result is None or not isinstance(result, (tuple, list)) or len(result) < 3:
            logger.warning(f"{self._prefix} load_local_state() returned invalid data: {type(result)}")
            self._cached_state = ({}, {}, {})
        else:
            self._cached_state = result
            _set_shared_local_state(result, _gen_at_load)
        self._cached_state_ts = now
        self._cached_state_gen = _gen_at_load
        creds, users_by_am, users_by_card = self._cached_state
        _tel.event(
            "CACHE_SYNC_LOAD_DONE", worker=self._tel_wid,
            dur_ms=round((time.monotonic() - _cl_t0) * 1000), creds=len(creds),
        )
        return self._cached_state

    # ------------------------------------------------------------------ #
    # Status snapshot
    # ------------------------------------------------------------------ #

    def get_snapshot(self) -> Dict[str, Any]:
        return {
            "device_id": self._device_id,
            "device_name": self._device_name,
            "mode": "ULTRA",
            "rtlog_polling": bool(self._settings.get("ultra_rtlog_enabled", True)),
            "totp_rescue_enabled": bool(self._settings.get("ultra_totp_rescue_enabled", True)),
            "connected": self._connected,
            # Whether this driver may command the door at all. None = unknown (no
            # driver built yet) so a UI keeps the control live rather than hiding
            # one that may work; False is a definite "this cannot open a door".
            # NOTE: read from the DRIVER, not the protocol -- on the standalone
            # family it is a persisted per-device switch (env override > local
            # switch > family default ON, zk_standalone.resolve_open_door_switch),
            # so protocol is the wrong thing to gate a UI on. open_door_source
            # names which of those decided (None on drivers without the switch).
            "supports_open_door": (
                bool(getattr(self._sdk, "supports_open_door", True))
                if getattr(self, "_sdk", None) is not None else None
            ),
            "open_door_source": (
                getattr(self._sdk, "_open_door_source", None)
                if getattr(self, "_sdk", None) is not None else None
            ),
            "events_processed": self._events_processed,
            "totp_rescues": self._totp_rescues,
            "totp_failures": self._totp_failures,
            "door_cmd_failures": self._door_cmd_failures,
            "poll_ema_ms": round(self._poll_ema_ms, 1),
            # Clock-skew / latency telemetry (fix #2a): how stale RTLog events are
            # at processing. Large values mean TOTP codes are validated late and
            # will start failing as DENY_NO_MATCH. Watch this to catch clock drift.
            "event_age_sec": round(self._last_event_age_sec, 1),
            "event_age_max_sec": round(self._max_event_age_sec, 1),
            "clock_skew_warns": int(self._clock_skew_warns),
            "device_pc_skew_sec": (
                round(self._device_pc_skew_sec, 1)
                if self._device_pc_skew_sec is not None else None
            ),
            "connect_failures": int(self._connect_failures or 0),
            "connect_retry_wait_ms": round(self._connect_wait_remaining() * 1000.0, 1),
            "connect_down_since": self._connect_down_since_iso,
            "connect_down_for_sec": round(self._down_for_seconds(), 1),
            "last_connect_error": self._last_connect_error,
            "last_connect_attempt_at": self._last_connect_attempt_at,
            "last_connect_success_at": self._last_connect_success_at,
            "full_sync_running": self._full_sync_running,
            "full_sync_reason": self._current_full_sync_reason,
            "last_full_sync_started_at": self._last_full_sync_started_at,
            "last_full_sync_finished_at": self._last_full_sync_finished_at,
            "last_full_sync_duration_ms": round(self._last_full_sync_duration_ms, 1),
            "last_full_sync_error": self._last_full_sync_error,
        }

    def get_progress_snapshot(self) -> tuple[Optional[Dict[str, Any]], int]:
        with self._active_sync_lock:
            engine = self._active_sync_engine
        if engine and hasattr(engine, "get_progress_snapshot"):
            try:
                return engine.get_progress_snapshot()
            except Exception:
                return None, 0
        return None, 0


# ---------------------------------------------------------------------------
# UltraSyncScheduler
# ---------------------------------------------------------------------------

class UltraSyncScheduler:
    """Periodically pushes user data to ULTRA-mode devices using DeviceSyncEngine logic."""

    def __init__(self, cfg: Any, logger_inst: logging.Logger):
        self._cfg = cfg
        self._logger = logger_inst
        self._stop = threading.Event()
        self._wake_sync = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._devices: List[Dict[str, Any]] = []
        self._last_hash: Dict[int, str] = {}  # device_id -> payload hash
        self._last_fp_detail: Dict[Any, Dict[str, Any]] = {}  # device_id -> fingerprint breakdown (diagnostic)
        self._last_sync_at: Dict[int, str] = {}
        self._next_sync_at: Dict[int, str] = {}
        self._workers: Dict[int, "UltraDeviceWorker"] = {}
        self._active_sync_lock = threading.Lock()
        self._active_sync_engine: Optional[Any] = None
        self._pending_sync_lock = threading.Lock()
        self._pending_sync_requested = False
        self._pending_full_sync = False
        self._pending_changed_ids: Set[int] = set()
        self._pending_revoked_ids: Set[int] = set()
        self._pending_all_devices = False
        self._pending_device_ids: Set[int] = set()
        self._pending_reason = "manual"
        self._pending_full_reconcile = False

    def set_workers(self, workers: Dict[int, "UltraDeviceWorker"]):
        """Register per-device worker references so sync requests stay worker-owned."""
        self._workers = workers
        self.wake_pending_sync()

    def wake_pending_sync(self) -> None:
        with self._pending_sync_lock:
            pending = self._pending_sync_requested
        if pending:
            self._wake_sync.set()

    def _merge_pending_sync_request(
        self,
        *,
        changed_ids: set[int] | None,
        revoked_ids: set[int],
        device_ids: set[int] | None,
        reason: str,
        full_reconcile: bool = False,
    ) -> None:
        with self._pending_sync_lock:
            self._pending_sync_requested = True
            self._pending_reason = reason
            # OR, never assignment: an automatic tick coalescing into a pending
            # operator reconcile must not downgrade it to an ordinary push.
            if full_reconcile:
                self._pending_full_reconcile = True
            if changed_ids is None:
                self._pending_full_sync = True
                self._pending_changed_ids.clear()
            elif not self._pending_full_sync:
                self._pending_changed_ids.update(changed_ids)
            self._pending_revoked_ids.update(revoked_ids)
            self._pending_changed_ids.difference_update(self._pending_revoked_ids)
            if device_ids is None:
                self._pending_all_devices = True
                self._pending_device_ids.clear()
            elif not self._pending_all_devices:
                self._pending_device_ids.update(device_ids)

    def _preserve_sync_request_for_retry(
        self,
        *,
        changed_ids: set[int] | None,
        revoked_ids: set[int],
        device_ids: set[int],
        reason: str,
        full_reconcile: bool = False,
    ) -> None:
        self._merge_pending_sync_request(
            changed_ids=changed_ids,
            revoked_ids=revoked_ids,
            device_ids=device_ids,
            reason=reason,
            full_reconcile=bool(full_reconcile),
        )
        self._logger.warning(
            "[UltraSyncScheduler] preserved sync for worker retry: reason=%s changed_ids=%s revoked_ids=%d device_ids=%s",
            reason,
            "all" if changed_ids is None else len(changed_ids),
            len(revoked_ids),
            sorted(device_ids),
        )

    def _handle_worker_full_sync_started(self, *, device_id: int, reason: str) -> None:
        self._logger.info(
            "[ULTRA:%s] full sync started on live worker: reason=%s",
            device_id,
            str(reason or "manual"),
        )

    def _handle_worker_full_sync_finished(
        self,
        *,
        device_id: int,
        reason: str,
        ok: bool,
        fingerprint_hash: str | None,
        duration_ms: float,
        error: str,
        revoked_ids: set[int] | None = None,
    ) -> None:
        if ok and fingerprint_hash:
            self._last_hash[int(device_id)] = str(fingerprint_hash)
            self._last_sync_at[int(device_id)] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if ok:
            self._logger.info(
                "[ULTRA:%s] full sync finished on live worker in %.0fms: reason=%s",
                device_id,
                max(0.0, float(duration_ms or 0.0)),
                str(reason or "manual"),
            )
            return
        self._logger.warning(
            "[ULTRA:%s] full sync failed on live worker: reason=%s err=%s",
            device_id,
            str(reason or "manual"),
            str(error or "sync failed"),
        )
        normalized_revoked_ids = {
            int(member_id)
            for member_id in (revoked_ids or set())
            if member_id is not None
        }
        if normalized_revoked_ids:
            self._preserve_sync_request_for_retry(
                changed_ids=None,
                revoked_ids=normalized_revoked_ids,
                device_ids={int(device_id)},
                reason=str(reason or "manual"),
            )

    def force_resync(self, device_id: int):
        """F-015: Clear in-memory hash for a device to force re-push on next cycle."""
        self._last_hash.pop(device_id, None)
        self._last_fp_detail.pop(device_id, None)
        self._logger.info("[UltraSyncScheduler] force_resync: cleared hash for device_id=%s", device_id)

    def _log_fingerprint_delta(
        self,
        device_id: Any,
        prev_detail: Dict[str, Any] | None,
        cur_detail: Dict[str, Any] | None,
        *,
        reason: str = "timer",
    ) -> None:
        """Diagnostic: a changed device-sync fingerprint forces a full ~10s blocking
        live-worker read (RTLog polling + door commands stall → popups freeze then
        burst). Often the change is spurious — the read finds to_sync=0. This logs
        WHICH users/fields flipped the fingerprint so it can be paired with the
        FULL_SYNC_DEVICE to_sync=N line to confirm a spurious flip and stabilise it.
        Best-effort: never raises, never affects sync behaviour."""
        try:
            if not isinstance(cur_detail, dict):
                return
            if not isinstance(prev_detail, dict) or not prev_detail.get("users"):
                self._logger.info(
                    "[ULTRA:%s] FP_DELTA reason=%s no_prev_detail=1 (first observed fingerprint)",
                    device_id, reason,
                )
                return
            prev_users = prev_detail.get("users") or {}
            cur_users = cur_detail.get("users") or {}
            prev_pins = set(prev_users.keys())
            cur_pins = set(cur_users.keys())
            added = sorted(cur_pins - prev_pins)
            removed = sorted(prev_pins - cur_pins)
            field_counts: Dict[str, int] = {}
            changed: List[Any] = []
            for pin in (cur_pins & prev_pins):
                pf = prev_users.get(pin) or {}
                cf = cur_users.get(pin) or {}
                if pf.get("h") == cf.get("h"):
                    continue
                # "tvo" is the per-device template-version override. Without it the
                # one-time re-push after that dropdown changes logs as
                # field_change_counts={'tplh': N}, which a field engineer reads as
                # "N members' fingerprints changed" -- false, and alarming.
                diff_fields = [k for k in ("name", "card", "doors", "tz", "tplh", "tvo")
                               if pf.get(k) != cf.get(k)]
                changed.append((pin, diff_fields, pf, cf))
                for k in diff_fields:
                    field_counts[k] = field_counts.get(k, 0) + 1
            header_changed = prev_detail.get("header") != cur_detail.get("header")
            self._logger.info(
                "[ULTRA:%s] FP_DELTA reason=%s header_changed=%s users_added=%d users_removed=%d "
                "users_changed=%d field_change_counts=%s",
                device_id, reason, header_changed, len(added), len(removed), len(changed), field_counts,
            )
            try:
                _tel.event(
                    "FP_DELTA", device_id=device_id, reason=reason,
                    header_changed=header_changed, added=len(added),
                    removed=len(removed), changed=len(changed), fields=field_counts,
                )
            except Exception:
                pass
            if header_changed:
                # Device-level inputs (allowedMemberships/doorIds/doorBitmask/
                # authorizeTimezoneId/policy/fingerprintEnabled) flipped the fingerprint;
                # log both so the specific culprit is identifiable, not just "True".
                self._logger.info(
                    "[ULTRA:%s] FP_DELTA_HEADER prev=%r cur=%r",
                    device_id, prev_detail.get("header"), cur_detail.get("header"),
                )
            for pin, diff_fields, pf, cf in changed[:8]:
                sample = {k: {"prev": pf.get(k), "cur": cf.get(k)} for k in diff_fields}
                self._logger.info(
                    "[ULTRA:%s] FP_DELTA_USER pin=%s fields=%s %s", device_id, pin, diff_fields, sample,
                )
            if added:
                self._logger.info(
                    "[ULTRA:%s] FP_DELTA_ADDED count=%d sample=%s", device_id, len(added), added[:8],
                )
            if removed:
                self._logger.info(
                    "[ULTRA:%s] FP_DELTA_REMOVED count=%d sample=%s", device_id, len(removed), removed[:8],
                )
        except Exception as exc:
            self._logger.warning("[ULTRA:%s] FP_DELTA logging failed: %s", device_id, exc)

    def update_devices(self, devices: List[Dict[str, Any]]) -> None:
        """Replace the scheduler's device list with the latest payload.

        Used together with UltraEngine.refresh_devices() so the scheduler's
        loops (interval computation, _sync_all iteration) see the same data
        the workers see.
        """
        self._devices = list(devices)
        # Drop the (comparatively large) diagnostic fingerprint snapshots for any
        # device no longer in the list so removed devices don't leak their breakdown.
        live_ids = {d.get("id") for d in self._devices}
        for _stale in [k for k in self._last_fp_detail if k not in live_ids]:
            self._last_fp_detail.pop(_stale, None)

    def start(self, devices: List[Dict[str, Any]]):
        self._devices = devices
        self._stop.clear()
        self._wake_sync.clear()
        self._logger.info(
            "[UltraSyncScheduler] starting: %d device(s), ids=%s",
            len(devices), [d.get("id") for d in devices],
        )
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="UltraSyncScheduler"
        )
        self._thread.start()

    def stop(self):
        self._logger.info("[UltraSyncScheduler] stopping")
        self._stop.set()
        self._wake_sync.set()
        if self._thread:
            self._thread.join(timeout=10)
        self._logger.info("[UltraSyncScheduler] stopped")

    def request_sync_now(
        self,
        *,
        changed_ids: set[int] | None = None,
        revoked_ids: set[int] | None = None,
        device_ids: set[int] | None = None,
        reason: str = "manual",
        full_reconcile: bool = False,
    ) -> None:
        normalized_reason = str(reason or "manual").strip().lower() or "manual"
        normalized_changed_ids = (
            None if changed_ids is None else {
                int(member_id)
                for member_id in changed_ids
                if member_id is not None
            }
        )
        normalized_revoked_ids = {
            int(member_id)
            for member_id in (revoked_ids or set())
            if member_id is not None
        }
        if normalized_changed_ids is not None:
            normalized_changed_ids.difference_update(normalized_revoked_ids)
        normalized_device_ids = (
            None if device_ids is None else {
                int(device_id)
                for device_id in device_ids
                if device_id is not None
            }
        )
        if (
            normalized_changed_ids is not None
            and not normalized_changed_ids
            and not normalized_revoked_ids
        ):
            self._logger.info(
                "[UltraSyncScheduler] request_sync_now skipped: reason=%s changed_ids=0 revoked_ids=0",
                normalized_reason,
            )
            return
        self._merge_pending_sync_request(
            changed_ids=normalized_changed_ids,
            revoked_ids=normalized_revoked_ids,
            device_ids=normalized_device_ids,
            reason=normalized_reason,
            full_reconcile=bool(full_reconcile),
        )
        self._logger.info(
            "[UltraSyncScheduler] request_sync_now: reason=%s changed_ids=%s revoked_ids=%d device_ids=%s",
            normalized_reason,
            "all" if normalized_changed_ids is None else len(normalized_changed_ids),
            len(normalized_revoked_ids),
            "all" if normalized_device_ids is None else len(normalized_device_ids),
        )
        self._wake_sync.set()

    def _drain_pending_sync_request(
        self,
    ) -> tuple[set[int] | None, set[int], set[int] | None, str, bool] | None:
        with self._pending_sync_lock:
            if not self._pending_sync_requested:
                return None
            reason = self._pending_reason
            full_reconcile = bool(self._pending_full_reconcile)
            changed_ids = None if self._pending_full_sync else set(self._pending_changed_ids)
            revoked_ids = set(self._pending_revoked_ids)
            device_ids = None if self._pending_all_devices else set(self._pending_device_ids)
            self._pending_sync_requested = False
            self._pending_full_sync = False
            self._pending_changed_ids.clear()
            self._pending_revoked_ids.clear()
            self._pending_all_devices = False
            self._pending_device_ids.clear()
            self._pending_reason = "manual"
            self._pending_full_reconcile = False
            return changed_ids, revoked_ids, device_ids, reason, full_reconcile

    @staticmethod
    def _manual_sync_mode() -> bool:
        """True when the gym enabled manual sync. In that mode the ULTRA scheduler must NOT
        auto-push to devices (startup / periodic timer). Explicit syncs still flow through
        request_sync_now (gated by the app layer's _should_push) and are honored."""
        try:
            from app.core.settings_reader import get_backend_global_settings
            return bool((get_backend_global_settings() or {}).get("manual_sync_mode", False))
        except Exception:
            return False

    def _run(self):
        """Sync loop: push data to each ULTRA device on its configured interval."""
        # Immediate first sync — suppressed in manual sync mode. The worker still connects and
        # observes RTLog; the device keeps its last-synced credentials until an explicit sync
        # (the "Sync data" button / daily 22:00 / hard reset) routed via request_sync_now.
        if not self._manual_sync_mode():
            self._sync_all(reason="startup")

        while not self._stop.is_set():
            # Find the shortest interval among all ULTRA devices
            min_interval = 15 * 60  # default 15 min
            for d in self._devices:
                settings = d.get("_settings", {})
                interval = int(settings.get("ultra_sync_interval_minutes", 30)) * 60
                min_interval = min(min_interval, interval)

            woke_for_sync = self._wake_sync.wait(min_interval)
            if self._stop.is_set():
                break
            if woke_for_sync:
                self._wake_sync.clear()
                pending = self._drain_pending_sync_request()
                if pending is None:
                    continue
                changed_ids, revoked_ids, device_ids, reason, full_reconcile = pending
                self._sync_all(
                    changed_ids=changed_ids,
                    revoked_ids=revoked_ids,
                    device_ids=device_ids,
                    reason=reason,
                    full_reconcile=full_reconcile,
                )
                continue
            # A request preserved for a dead standalone worker must survive until
            # the watchdog replaces it. Retry it on the normal interval even if
            # no explicit wake arrived; manual mode suppresses only automatic
            # timer pushes, never an already-authorized explicit request.
            pending = self._drain_pending_sync_request()
            if pending is not None:
                changed_ids, revoked_ids, device_ids, reason, full_reconcile = pending
                self._sync_all(
                    changed_ids=changed_ids,
                    revoked_ids=revoked_ids,
                    device_ids=device_ids,
                    reason=reason,
                    full_reconcile=full_reconcile,
                )
            elif not self._manual_sync_mode():
                self._sync_all(reason="timer")

    def _check_worker_health(self):
        """Deprecated: worker restarts are handled exclusively by the watchdog thread.
        Kept as no-op for backward compat in case external code calls it."""
        pass

    def _sync_all(
        self,
        *,
        changed_ids: set[int] | None = None,
        revoked_ids: set[int] | None = None,
        device_ids: set[int] | None = None,
        reason: str = "timer",
        full_reconcile: bool = False,
    ):
        """Push user data to all ULTRA devices (with hash-based skip)."""
        normalized_revoked_ids = {
            int(member_id)
            for member_id in (revoked_ids or set())
            if member_id is not None
        }
        normalized_changed_ids = (
            None
            if changed_ids is None
            else {
                int(member_id)
                for member_id in changed_ids
                if member_id is not None
            } - normalized_revoked_ids
        )
        devices = self._devices if device_ids is None else [
            device for device in self._devices
            if device.get("id") is not None and int(device.get("id")) in device_ids
        ]
        self._logger.info(
            "[UltraSyncScheduler] _sync_all: starting cycle for %d device(s) reason=%s changed_ids=%s revoked_ids=%d device_ids=%s",
            len(devices),
            reason,
            "all" if normalized_changed_ids is None else len(normalized_changed_ids),
            len(normalized_revoked_ids),
            "all" if device_ids is None else len(device_ids),
        )
        t0 = time.time()
        # Check worker health before each sync cycle
        try:
            self._check_worker_health()
        except Exception as e:
            self._logger.warning("[ULTRA] _check_worker_health error: %s", e)
        synced = 0
        skipped = 0
        failed = 0
        for d in devices:
            device_id = d.get("id")
            try:
                routed = False
                did_sync = False
                worker = self._workers.get(int(device_id)) if device_id is not None else None
                target_handled = False
                if worker is not None and _worker_is_usable(worker):
                    try:
                        commands_handled = True
                        # A delta names only the members that changed; an explicit
                        # reconcile is about the rows the TERMINAL holds and the roster
                        # no longer names, which targeted member syncs never see. So a
                        # reconcile always takes the full route -- exactly like
                        # UltraEngine.request_sync_now. Without the second condition a
                        # request that reached this scheduler as the FALLBACK (dead or
                        # refusing worker) lost its reconcile. guide §3.2c.
                        if normalized_changed_ids is not None and not full_reconcile:
                            for member_id in sorted(normalized_revoked_ids):
                                commands_handled = (
                                    _worker_member_revoke_accepted_or_covered(
                                        worker, member_id
                                    )
                                    and commands_handled
                                )
                            for member_id in sorted(normalized_changed_ids):
                                commands_handled = (
                                    _worker_request_accepted_or_pending(
                                        worker,
                                        request_method="request_member_sync",
                                        pending_method="has_pending_member_sync",
                                        member_id=member_id,
                                    )
                                    and commands_handled
                                )
                            target_handled = commands_handled
                            routed = target_handled
                        else:
                            from app.core.device_sync import DeviceSyncEngine

                            cache = load_sync_cache()
                            if cache is None:
                                self._logger.warning(
                                    "[ULTRA:%s] sync skip: no sync cache available",
                                    device_id,
                                )
                            else:
                                cache = _sync_cache_without_revoked_ids(
                                    cache, normalized_revoked_ids
                                )
                                users = getattr(cache, "users", []) or []
                                engine = DeviceSyncEngine(cfg=self._cfg, logger=self._logger)
                                cur_detail: Dict[str, Any] = {}
                                current_hash, desired_users = engine.build_device_sync_fingerprint(
                                    device=d,
                                    users=list(users),
                                    detail_out=cur_detail,
                                )
                                if (
                                    not normalized_revoked_ids
                                    # A reconcile targets rows the TERMINAL holds and
                                    # the roster does not -- which never moves the
                                    # roster hash. Skipping here would make the
                                    # operator's click unreachable all over again.
                                    and not full_reconcile
                                    and self._last_hash.get(device_id) == current_hash
                                ):
                                    self._logger.info(
                                        "[ULTRA:%s] sync skip: fingerprint unchanged (desired_users=%d hash=%s)",
                                        device_id,
                                        desired_users,
                                        current_hash[:12],
                                    )
                                    self._last_fp_detail[device_id] = cur_detail
                                    target_handled = commands_handled
                                else:
                                    self._log_fingerprint_delta(
                                        device_id,
                                        self._last_fp_detail.get(device_id),
                                        cur_detail,
                                        reason=str(reason or "manual"),
                                    )
                                    full_sync_handled = _worker_full_sync_accepted_or_pending(
                                        worker,
                                        reason=reason,
                                        fingerprint_hash=current_hash,
                                        revoked_ids=normalized_revoked_ids,
                                        require_full_refresh=True,
                                        full_reconcile=bool(full_reconcile),
                                    )
                                    target_handled = commands_handled and full_sync_handled
                                    routed = target_handled
                                    if target_handled:
                                        self._logger.info(
                                            "[ULTRA:%s] queued live-worker full sync: desired_users=%d prev_hash=%s new_hash=%s reason=%s",
                                            device_id,
                                            desired_users,
                                            (self._last_hash.get(device_id) or "none")[:12],
                                            current_hash[:12],
                                            str(reason or "manual"),
                                        )
                                    did_sync = target_handled
                    except Exception as exc:
                        self._logger.warning(
                            "[ULTRA:%s] live-worker sync enqueue failed; using fallback: %s",
                            device_id,
                            exc,
                        )
                        target_handled = False

                if not target_handled:
                    # A roster push can add/update data, but under additive policy
                    # it cannot prove deletion (and an untracked PIN is invisible
                    # to stale-record cleanup). Only a live worker's targeted
                    # absent-member path can confirm an authoritative revoke.
                    if normalized_revoked_ids:
                        self._preserve_sync_request_for_retry(
                            changed_ids=normalized_changed_ids,
                            revoked_ids=normalized_revoked_ids,
                            device_ids={int(device_id)},
                            reason=str(reason or "manual"),
                            full_reconcile=bool(full_reconcile),
                        )
                    else:
                        sync_kwargs: Dict[str, Any] = {
                            # A reconcile is never narrowed to the delta's members.
                            "changed_ids": None if full_reconcile else normalized_changed_ids,
                        }
                        did_sync = self._sync_device(d, **sync_kwargs)
                interval = int(
                    d.get("_settings", {}).get("ultra_sync_interval_minutes", 30)
                ) * 60
                next_t = time.time() + interval
                self._next_sync_at[device_id] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_t)
                )
                if did_sync:
                    self._last_sync_at[device_id] = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                    )
                    synced += 1
                elif routed:
                    synced += 1
                else:
                    skipped += 1
            except Exception as e:
                failed += 1
                self._logger.error("[ULTRA:%s] sync failed: %s", device_id, e)
        elapsed = time.time() - t0
        self._logger.info(
            "[UltraSyncScheduler] _sync_all: cycle done in %.1fs — synced=%d skipped=%d failed=%d reason=%s",
            elapsed, synced, skipped, failed, reason,
        )

    def _sync_device(
        self,
        device: Dict[str, Any],
        *,
        changed_ids: set[int] | None = None,
        revoked_ids: set[int] | None = None,
    ) -> bool:
        """Push data to a single device with hash-based change detection.

        Reuses DeviceSyncEngine by temporarily treating this ULTRA device
        as a DEVICE-mode device for the push operation.
        """
        from app.core.device_sync import DeviceSyncEngine

        device_id = device.get("id")
        cache = load_sync_cache()
        if cache is None:
            self._logger.warning("[ULTRA:%s] sync skip: no sync cache available", device_id)
            return False

        normalized_revoked_ids = {
            int(member_id)
            for member_id in (revoked_ids or set())
            if member_id is not None
        }
        cache = _sync_cache_without_revoked_ids(cache, normalized_revoked_ids)
        users = getattr(cache, "users", []) or []
        engine = DeviceSyncEngine(cfg=self._cfg, logger=self._logger)
        cur_detail: Dict[str, Any] = {}
        current_hash, desired_users = engine.build_device_sync_fingerprint(
            device=device,
            users=list(users),
            detail_out=cur_detail,
        )

        if not normalized_revoked_ids and self._last_hash.get(device_id) == current_hash:
            self._logger.info(
                "[ULTRA:%s] sync skip: fingerprint unchanged (desired_users=%d hash=%s)",
                device_id, desired_users, current_hash[:12],
            )
            self._last_fp_detail[device_id] = cur_detail
            return False

        # Diff against the last-SYNCED baseline; refresh _last_fp_detail only AFTER a
        # successful push (below), so a failed push leaves the real delta visible on retry.
        self._log_fingerprint_delta(
            device_id, self._last_fp_detail.get(device_id), cur_detail, reason="ultra_sync",
        )
        self._logger.info(
            "[ULTRA:%s] sync push started: desired_users=%d prev_hash=%s new_hash=%s",
            device_id, desired_users,
            (self._last_hash.get(device_id) or "none")[:12], current_hash[:12],
        )

        device_copy = dict(device or {})
        device_copy["accessDataMode"] = "DEVICE"
        filtered_cache_attrs = dict(getattr(cache, "__dict__", {}))
        filtered_cache_attrs["users"] = list(users)
        filtered_cache_attrs["devices"] = [device_copy]
        filtered_cache = SimpleNamespace(**filtered_cache_attrs)

        # Pause the RTLog worker so it releases the single TCP connection to this device
        worker = self._workers.get(int(device_id)) if device_id is not None else None
        if worker:
            self._logger.info(
                "[ULTRA:%s] sync: pausing RTLog worker for TCP handoff", device_id
            )
            acked = worker.pause_for_sync(timeout=20.0)
            self._logger.info(
                "[ULTRA:%s] sync: worker pause acked=%s — connecting for sync", device_id, acked
            )
        else:
            self._logger.warning(
                "[ULTRA:%s] sync: no worker found — proceeding without pause "
                "(risk: dual TCP connection on C3-200)", device_id
            )

        try:
            with self._active_sync_lock:
                self._active_sync_engine = engine
            did_run = engine.run_one_device_blocking(
                cache=filtered_cache,
                device=device_copy,
                source="ultra_sync",
                changed_ids=changed_ids,
            )
            if not did_run:
                self._logger.warning("[ULTRA:%s] sync push failed or was skipped", device_id)
                return False
            self._last_hash[device_id] = current_hash
            self._last_fp_detail[device_id] = cur_detail  # baseline now matches synced state
            self._logger.info("[ULTRA:%s] sync push complete", device_id)
            return True
        finally:
            with self._active_sync_lock:
                if self._active_sync_engine is engine:
                    self._active_sync_engine = None
            if worker:
                worker.resume_from_sync()
                self._logger.info(
                    "[ULTRA:%s] sync: worker resumed - will reconnect for RTLog polling", device_id
                )

    def get_sync_status(self) -> Dict[int, Dict[str, Any]]:
        return {
            did: {
                "last_sync_at": self._last_sync_at.get(did, ""),
                "next_sync_at": self._next_sync_at.get(did, ""),
            }
            for did in [d.get("id") for d in self._devices]
        }

    def get_active_progress_snapshot(self) -> tuple[Optional[Dict[str, Any]], int]:
        for worker in list(self._workers.values()):
            if hasattr(worker, "get_progress_snapshot"):
                progress, seq = worker.get_progress_snapshot()
                if progress and bool(progress.get("running")):
                    return progress, seq
        with self._active_sync_lock:
            engine = self._active_sync_engine
        if engine and hasattr(engine, "get_progress_snapshot"):
            try:
                return engine.get_progress_snapshot()
            except Exception:
                return None, 0
        return None, 0


# ---------------------------------------------------------------------------
# UltraEngine (orchestrator)
# ---------------------------------------------------------------------------


def _scan_mode_for_event(raw_row: Any, default: str = "RFID_CARD") -> str:
    """Popup/history scan_mode for one device event.

    ZK_STANDALONE (zkemkeeper / MB2000) reports the verify modality per punch and
    the driver publishes it as rawRow["scan_mode_hint"] (app/sdk/zk_standalone.py).
    PullSDK/C3 rows carry no such key, so C2-400 behaviour is byte-identical.

    CONFIDENT OVERRIDE ONLY: only FINGERPRINT is honoured. PASSWORD/UNKNOWN have no
    branch in the popup's method mapper and would render as "Carte" anyway, so
    emitting them buys nothing while leaking unmapped values into the scan_mode
    space that /door-history also consumes.
    """
    try:
        if isinstance(raw_row, dict):
            if str(raw_row.get("scan_mode_hint") or "").strip().upper() == "FINGERPRINT":
                return "FINGERPRINT"
    except Exception:
        pass
    return default


def _uid_for_alert(user: Any) -> Optional[int]:
    """userId out of a cached member dict, for the frequent-pass VISUAL alert only.

    Returns None whenever the member could not be resolved, which switches the
    alert off for that scan. Never raises and never participates in the access
    decision.
    """
    try:
        if isinstance(user, dict) and user.get("userId") not in (None, ""):
            return int(str(user.get("userId")).strip())
    except (ValueError, TypeError):
        pass
    return None


class UltraEngine:
    """Orchestrates ULTRA mode: sync scheduler + per-device RTLog workers."""

    def __init__(self, cfg: Any, logger_inst: logging.Logger):
        self._cfg = cfg
        self._logger = logger_inst
        # Telemetry id for the orchestrator (distinct from the per-device
        # "ULTRA:<id>" workers). Without this, the POPUP_CAPTURE event in the
        # popup-drain path (which fires exactly when a freeze-induced backlog is
        # flushed, i.e. drained>0) raised AttributeError: '_tel_wid' and crashed
        # the drain — a latent bug surfaced by the audit instrumentation.
        self._tel_wid = "ULTRA:engine"
        self._workers: Dict[int, UltraDeviceWorker] = {}
        self._sync_scheduler: Optional[UltraSyncScheduler] = None
        self._stop_event = threading.Event()
        # M-001: Queue sizes read from backend settings (consistent with AGENT mode).
        from app.core.settings_reader import get_backend_global_settings
        _g = get_backend_global_settings() or {}
        self._popup_q: "queue.Queue[NotificationRequest]" = queue.Queue(
            maxsize=int(_g.get("popup_queue_max", _g.get("notification_queue_max", 5000)))
        )
        self._history_q: "queue.Queue[HistoryRecord]" = queue.Queue(
            maxsize=int(_g.get("history_queue_max", 5000))
        )
        popup_replay_size = max(
            16,
            min(
                int(_g.get("popup_queue_max", _g.get("notification_queue_max", 5000)) or 5000),
                1000,
            ),
        )
        self._popup_capture_lock = threading.Lock()
        self._popup_events_lock = threading.Lock()
        self._popup_events_seq = 0
        self._popup_events_replay: Deque[tuple[int, Dict[str, Any]]] = deque(maxlen=popup_replay_size)
        self._running = False
        self._watchdog_thread: Optional[threading.Thread] = None
        # How often the watchdog checks worker liveness (seconds).
        # Short interval for fast recovery of dead workers.
        self._watchdog_interval_sec: float = 10.0
        # Lock to prevent concurrent worker replacement by watchdog / other threads.
        self._worker_restart_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def popup_q(self) -> "queue.Queue[NotificationRequest]":
        return self._popup_q

    @property
    def history_q(self) -> "queue.Queue[HistoryRecord]":
        return self._history_q

    def capture_popup_events(self, limit: int = 50) -> int:
        drained = 0
        target = max(1, int(limit or 1))
        from app.core.realtime_agent import _popup_payload_from_request

        with self._popup_capture_lock:
            while drained < target:
                try:
                    req = self._popup_q.get_nowait()
                except queue.Empty:
                    break
                except Exception:
                    break
                payload = _popup_payload_from_request(req)
                with self._popup_events_lock:
                    self._popup_events_seq += 1
                    self._popup_events_replay.append((self._popup_events_seq, payload))
                drained += 1
        if drained:
            # A large drain here = the popup backlog that built up while the
            # worker was blocked, now flushed to the SSE replay buffer.
            _tel.event(
                "POPUP_CAPTURE", worker=self._tel_wid, drained=drained,
                latest_seq=self._popup_events_seq, qsize=self._popup_q.qsize(),
            )
        return drained

    def get_latest_popup_event_seq(self) -> int:
        self.capture_popup_events(limit=100)
        with self._popup_events_lock:
            return int(self._popup_events_seq)

    def get_popup_events_since(self, seq: int, limit: int = 10) -> List[tuple[int, Dict[str, Any]]]:
        target = max(1, int(limit or 1))
        self.capture_popup_events(limit=max(target * 2, 10))
        with self._popup_events_lock:
            rows = [
                (event_seq, dict(payload))
                for event_seq, payload in self._popup_events_replay
                if int(event_seq) > int(seq)
            ]
        return rows[:target]

    def start(self, devices: List[Dict[str, Any]]):
        """Start ULTRA engine for the given devices."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        def _adm(d):
            return str(d.get("accessDataMode") or d.get("access_data_mode") or "").strip().upper()

        ultra_devices = [d for d in devices if _adm(d) == "ULTRA"]

        all_device_count = len(devices)
        non_ultra = [d for d in devices if _adm(d) != "ULTRA"]
        self._logger.info(
            "[ULTRA] start: total_devices=%d ultra_devices=%d skipped=%d",
            all_device_count, len(ultra_devices), len(non_ultra),
        )
        for d in non_ultra:
            self._logger.info(
                "[ULTRA] device id=%s name=%r skipped (accessDataMode=%r / access_data_mode=%r)",
                d.get("id"), d.get("name"), d.get("accessDataMode"), d.get("access_data_mode"),
            )

        if not ultra_devices:
            self._logger.info("[ULTRA] No ULTRA-mode devices found — engine not starting")
            self._running = False
            return

        self._logger.info("[ULTRA] Starting with %d device(s)", len(ultra_devices))

        # TOTP diagnostic: log credential count and system time at startup
        try:
            from app.core.db import list_sync_gym_access_credentials
            creds = list_sync_gym_access_credentials()
            enabled_with_secret = sum(
                1 for c in creds if isinstance(c, dict)
                and c.get("enabled") and (c.get("secretHex") or c.get("secret_hex", "")).strip()
            )
            self._logger.info(
                "[ULTRA] TOTP credentials: total=%d enabled_with_secret=%d system_time=%d",
                len(creds), enabled_with_secret, int(time.time()),
            )
            if enabled_with_secret == 0:
                self._logger.warning(
                    "[ULTRA] WARNING: No enabled TOTP credentials with valid secretHex — "
                    "TOTP rescue will NEVER work until credentials are synced!"
                )
        except Exception as _e:
            self._logger.warning("[ULTRA] Could not check TOTP credentials: %s", _e)

        from app.core.settings_reader import normalize_device_settings

        prepared_devices: List[tuple[Dict[str, Any], Dict[str, Any]]] = []
        for d in ultra_devices:
            settings = normalize_device_settings(d)
            d["_settings"] = settings
            prepared_devices.append((d, settings))
            self._logger.info(
                "[ULTRA] device id=%s name=%r ip=%s port=%s totp_rescue=%s rtlog=%s",
                d.get("id"), d.get("name"),
                d.get("ipAddress", "?"), d.get("portNumber", "?"),
                settings.get("ultra_totp_rescue_enabled", True),
                settings.get("ultra_rtlog_enabled", True),
            )

        self._sync_scheduler = UltraSyncScheduler(self._cfg, self._logger)

        # Start per-device workers first so scheduler can route work to them
        for d, settings in prepared_devices:
            device_id = int(d.get("id", 0))

            worker = UltraDeviceWorker(
                device=d,
                settings=settings,
                popup_q=self._popup_q,
                history_q=self._history_q,
                stop_event=self._stop_event,
                cfg=self._cfg,
                on_full_sync_started=self._sync_scheduler._handle_worker_full_sync_started,
                on_full_sync_finished=self._sync_scheduler._handle_worker_full_sync_finished,
            )
            self._workers[device_id] = worker
            try:
                worker.start()
                self._logger.info("[ULTRA] Worker thread started for device id=%s name=%r", device_id, d.get("name"))
            except Exception as _w_exc:
                self._logger.error("[ULTRA] Worker thread start FAILED for device id=%s: %s", device_id, _w_exc)

        # Start sync scheduler with worker references so it can route timed work
        self._sync_scheduler.set_workers(self._workers)
        self._sync_scheduler.start([d for d, _settings in prepared_devices])

        # Start the watchdog — monitors worker liveness every 30 s, independent
        # of the sync interval, so a crashed worker is restarted promptly.
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            daemon=True,
            name="UltraWatchdog",
        )
        self._watchdog_thread.start()

    def refresh_devices(self, devices: List[Dict[str, Any]]) -> int:
        """Refresh each running ULTRA worker's device snapshot in place.

        Workers cache the device dict at construction (self._device), which is
        used to filter members against allowedMemberships at push time. When
        the dashboard edits a device (adds memberships, changes doorIds, etc.)
        a sync brings the new payload into local SQLite — but the in-memory
        worker snapshots stay stale, so newly-allowed members get filtered out
        and pin-deleted instead of pushed. Call this after every sync that
        returned a refreshed devices section.

        Returns the number of workers refreshed.
        """
        if not self._running:
            return 0

        from app.core.settings_reader import normalize_device_settings

        def _adm(d):
            return str(d.get("accessDataMode") or d.get("access_data_mode") or "").strip().upper()

        ultra_devices = [d for d in (devices or []) if _adm(d) == "ULTRA"]

        refreshed = 0
        for d in ultra_devices:
            try:
                device_id = int(d.get("id", 0))
            except (TypeError, ValueError):
                continue
            if device_id <= 0:
                continue
            worker = self._workers.get(device_id)
            if worker is None:
                continue
            try:
                settings = normalize_device_settings(d)
                d["_settings"] = settings
                worker.update_device(d, settings)
                refreshed += 1
            except Exception as exc:
                self._logger.warning(
                    "[ULTRA:%s] refresh_devices failed: %s", device_id, exc
                )

        if refreshed > 0:
            self._logger.info(
                "[ULTRA] refreshed %d worker device snapshot(s) in place", refreshed
            )

        if self._sync_scheduler is not None:
            try:
                self._sync_scheduler.update_devices(ultra_devices)
            except Exception as exc:
                self._logger.warning(
                    "[ULTRA] sync_scheduler.update_devices failed: %s", exc
                )

        return refreshed

    def _watchdog_loop(self):
        """Restart dead UltraDeviceWorker threads every _watchdog_interval_sec seconds.

        This is the SOLE restart mechanism.  UltraSyncScheduler._check_worker_health
        is now a no-op — all restarts go through this watchdog to avoid race conditions.
        """
        self._logger.info("[ULTRA] Watchdog started (interval=%.0fs)", self._watchdog_interval_sec)
        while not self._stop_event.wait(self._watchdog_interval_sec):
            for device_id, worker in list(self._workers.items()):
                if worker.is_alive():
                    continue
                with self._worker_restart_lock:
                    # Double-check inside lock: another thread may have restarted it
                    current = self._workers.get(device_id)
                    if current is not None and current.is_alive():
                        continue
                    self._logger.error(
                        "[ULTRA:%s] watchdog: worker thread is dead — restarting", device_id
                    )
                    try:
                        new_worker = UltraDeviceWorker(
                            device=worker._device,
                            settings=worker._settings,
                            popup_q=self._popup_q,
                            history_q=self._history_q,
                            stop_event=self._stop_event,
                            cfg=self._cfg,
                            on_full_sync_started=(
                                self._sync_scheduler._handle_worker_full_sync_started
                                if self._sync_scheduler
                                else None
                            ),
                            on_full_sync_finished=(
                                self._sync_scheduler._handle_worker_full_sync_finished
                                if self._sync_scheduler
                                else None
                            ),
                        )
                        new_worker.start()
                        self._workers[device_id] = new_worker
                        if self._sync_scheduler is not None:
                            self._sync_scheduler.wake_pending_sync()
                        self._logger.info("[ULTRA:%s] watchdog: worker restarted OK", device_id)
                    except Exception as exc:
                        self._logger.error(
                            "[ULTRA:%s] watchdog: worker restart FAILED: %s", device_id, exc
                        )
        self._logger.info("[ULTRA] Watchdog stopped")

    def stop(self):
        """Stop all workers and sync scheduler."""
        if not self._running:
            return
        self._logger.info("[ULTRA] Stopping engine")
        self._stop_event.set()

        # Stop sync scheduler
        if self._sync_scheduler:
            self._sync_scheduler.stop()

        # Stop watchdog (stop_event already set; just wait for it to exit)
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=5)

        # Stop workers
        for device_id, worker in self._workers.items():
            worker.join(timeout=10)
            if worker.is_alive():
                self._logger.warning("[ULTRA:%s] worker did not stop in time", device_id)

        self._workers.clear()
        self._running = False
        self._logger.info("[ULTRA] Engine stopped")

    def get_status(self) -> Dict[str, Any]:
        """Return full ULTRA engine status for /api/v2/ultra/status."""
        devices: Dict[str, Any] = {}
        sync_status = self._sync_scheduler.get_sync_status() if self._sync_scheduler else {}

        for device_id, worker in self._workers.items():
            snap = worker.get_snapshot()
            ss = sync_status.get(device_id, {})
            snap["last_sync_at"] = ss.get("last_sync_at", "")
            snap["next_sync_at"] = ss.get("next_sync_at", "")
            snap["sync_interval_minutes"] = int(
                worker._settings.get("ultra_sync_interval_minutes", 30)
            )
            devices[str(device_id)] = snap

        return {
            "running": self._running,
            "devices": devices,
        }

    def get_sync_progress_snapshot(self) -> tuple[Optional[Dict[str, Any]], int]:
        if not self._sync_scheduler:
            return None, 0
        return self._sync_scheduler.get_active_progress_snapshot()

    def reset_fast_patch_caches(self) -> None:
        for worker in list(getattr(self, "_workers", {}).values()):
            try:
                if hasattr(worker, "reset_fast_patch_caches"):
                    worker.reset_fast_patch_caches()
            except Exception:
                self._logger.warning("[ULTRA] failed to reset worker cache", exc_info=True)

    def defer_reconnects(self, *, duration_sec: float, reason: str = "sync") -> int:
        deferred = 0
        for worker in list(getattr(self, "_workers", {}).values()):
            try:
                if hasattr(worker, "defer_reconnect") and worker.defer_reconnect(duration_sec, reason=str(reason or "sync")):
                    deferred += 1
            except Exception:
                self._logger.debug("[ULTRA] failed to defer worker reconnect", exc_info=True)
        if deferred > 0:
            self._logger.info(
                "[ULTRA] deferred reconnects: workers=%d duration_sec=%.1f reason=%s",
                deferred,
                float(duration_sec or 0.0),
                str(reason or "sync"),
            )
        return deferred

    def request_sync_now(
        self,
        *,
        changed_ids: set[int] | None = None,
        revoked_ids: set[int] | None = None,
        device_ids: set[int] | None = None,
        reason: str = "manual",
        full_reconcile: bool = False,
    ) -> bool:
        if not self._running or not self._sync_scheduler:
            return False
        normalized_full_reconcile = bool(full_reconcile)
        normalized_changed_ids = (
            None
            if changed_ids is None
            else {
                int(member_id)
                for member_id in changed_ids
                if member_id is not None
            }
        )
        normalized_revoked_ids = {
            int(member_id)
            for member_id in (revoked_ids or set())
            if member_id is not None
        }
        if normalized_changed_ids is not None:
            normalized_changed_ids.difference_update(normalized_revoked_ids)
        broadcast_devices = device_ids is None
        if broadcast_devices:
            normalized_device_ids = {int(device_id) for device_id in self._workers}
            for device in list(getattr(self._sync_scheduler, "_devices", []) or []):
                if not isinstance(device, dict) or device.get("id") is None:
                    continue
                try:
                    normalized_device_ids.add(int(device["id"]))
                except (TypeError, ValueError):
                    continue
        else:
            normalized_device_ids = {
                int(device_id)
                for device_id in device_ids
                if device_id is not None
            }
        if (
            normalized_changed_ids is not None
            and not normalized_changed_ids
            and not normalized_revoked_ids
        ):
            self._logger.info(
                "[ULTRA] skip sync request: empty changed_ids and revoked_ids reason=%s",
                str(reason or "manual"),
            )
            return False
        handled_device_ids: set[int] = set()
        for device_id in sorted(normalized_device_ids):
            worker = self._workers.get(int(device_id))
            if worker is None or not _worker_is_usable(worker):
                if worker is not None:
                    self._logger.warning(
                        "[ULTRA:%s] sync request found a dead worker; using scheduler fallback",
                        device_id,
                    )
                continue
            try:
                commands_handled = True
                # A delta answer names only the members that changed, but an explicit
                # reconcile is about the ones the terminal still holds and the roster
                # no longer names. Targeted member syncs can never see those, so an
                # operator's reconcile always takes the full-sync route.
                if normalized_changed_ids is None or normalized_full_reconcile:
                    commands_handled = (
                        _worker_full_sync_accepted_or_pending(
                            worker,
                            reason=reason,
                            revoked_ids=normalized_revoked_ids,
                            require_full_refresh=True,
                            full_reconcile=normalized_full_reconcile,
                        )
                        and commands_handled
                    )
                else:
                    for member_id in sorted(normalized_revoked_ids):
                        commands_handled = (
                            _worker_member_revoke_accepted_or_covered(
                                worker, member_id
                            )
                            and commands_handled
                        )
                    for member_id in sorted(normalized_changed_ids):
                        commands_handled = (
                            _worker_request_accepted_or_pending(
                                worker,
                                request_method="request_member_sync",
                                pending_method="has_pending_member_sync",
                                member_id=member_id,
                            )
                            and commands_handled
                        )
                if commands_handled:
                    handled_device_ids.add(int(device_id))
                else:
                    self._logger.warning(
                        "[ULTRA:%s] worker did not accept the complete sync request; using scheduler fallback",
                        device_id,
                    )
            except Exception as exc:
                self._logger.warning(
                    "[ULTRA:%s] worker sync enqueue failed; using scheduler fallback: %s",
                    device_id,
                    exc,
                )

        unresolved_device_ids = normalized_device_ids - handled_device_ids
        needs_scheduler = bool(unresolved_device_ids)
        if broadcast_devices and not normalized_device_ids:
            needs_scheduler = True
        scheduled = False
        if needs_scheduler:
            fallback_device_ids = None if broadcast_devices else unresolved_device_ids
            try:
                self._sync_scheduler.request_sync_now(
                    changed_ids=normalized_changed_ids,
                    revoked_ids=normalized_revoked_ids,
                    device_ids=fallback_device_ids,
                    reason=reason,
                    full_reconcile=normalized_full_reconcile,
                )
                scheduled = True
            except Exception as exc:
                self._logger.warning(
                    "[ULTRA] scheduler fallback rejected sync request: %s",
                    exc,
                )

        if handled_device_ids:
            self._logger.info(
                "[ULTRA] routed sync to live workers: devices=%d members=%s revoked=%d reason=%s",
                len(handled_device_ids),
                "all" if normalized_changed_ids is None else len(normalized_changed_ids),
                len(normalized_revoked_ids),
                str(reason or "manual"),
            )
        return bool(handled_device_ids or scheduled)
