# monclub_access_python/app/core/device_sync.py
from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Set, Tuple

from app.core.db import (
    list_device_pin_scheme_switches,
    list_fingerprints,
    list_fingerprints_by_pins,
    list_sync_users_by_active_membership_ids,
    list_device_sync_hashes,
    list_device_sync_hashes_and_status,
    list_device_sync_retry_state,
    get_device_sync_hash_for_pin,
    get_device_sync_ownership_for_pin,
    record_push_intents,
    list_push_intents,
    get_push_intent,
    promote_push_intents,
    drop_push_intents,
    note_push_intent_misses,
    save_device_sync_state,
    save_device_sync_state_batch,
    delete_device_sync_state,
    clear_device_revocation_state,
    prune_device_sync_state,
    prune_fingerprint_push_status,
    upsert_fingerprint_push_status,
    upsert_device_mirror_pin,
    upsert_device_mirror_batch,
    delete_device_mirror_pin,
    insert_push_batch,
    insert_push_pin,
    insert_push_pin_batch,
    update_push_batch,
)
from app.core.settings_reader import (  # ✅ NEW: backend-driven settings (SQLite)
    get_backend_global_settings,
    parse_fingerprint_template_version,
)
from app.core import telemetry as _tel
from app.core import push_safety as _push_safety
from app.core.utils import from_b64, from_hex, to_b64
from app.sdk.pullsdk import STRUCTURAL_ERROR_CODES
from app.sdk.pullsdk import PullSDK, PullSDKError
from app.sdk.device_driver import DeviceProtocol, resolve_device_protocol


@dataclass
class FirmwareProfile:
    """
    Records which SDK field-name pattern works for a specific ZKTeco device firmware.
    Populated from SQLite on first use, updated on successful discovery.

    Fields:
        template_table       — "templatev10" or "template"
        template_body_index  — index into the bodies list in _push_templates (0-4)
        authorize_body_index — index into the patterns list in _push_userauthorize (0-3)
        name_supported       — None=unknown, True=OK, False=rc=-101 on Name field
        insert_strategy      — None/"upsert" (try bulk upsert first)
                             — "delete_then_insert" (pre-delete pins, then bulk insert)
                             — "one_by_one" (per-pin delete+insert)
        delete_strategy      — None/"bulk" (bulk DeleteDeviceData) | "one_by_one" (per-pin)
    """
    template_table: str | None = None
    template_body_index: int | None = None
    authorize_body_index: int | None = None
    name_supported: bool | None = None
    insert_strategy: str | None = None
    delete_strategy: str | None = None
    # The template-version bias the cached (template_table, body_index) combo was
    # learned under. 0 = no override. Appended last: every field has a default, so
    # this stays a safe addition for any positional construction.
    template_version_bias: int = 0


# Strategy constants (P0)
_INSERT_UPSERT              = "upsert"
_INSERT_DELETE_THEN_INSERT  = "delete_then_insert"
_INSERT_ONE_BY_ONE          = "one_by_one"
_DELETE_BULK                = "bulk"
_DELETE_ONE_BY_ONE          = "one_by_one"

# Tables affected by a stale-pin removal. Order matters: dependent rows before the user row,
# so if a table is unavailable (e.g. fingerprintEnabled=false) the user row still gets removed.
_STALE_DELETE_TABLES = ("templatev10", "template", "userauthorize", "user")


# Fallback if a device has no doorIds configured (will be overridden by backend global settings if present)
DEFAULT_AUTHORIZE_DOOR_ID_FALLBACK = 15

# ── Pushing policy constants ──────────────────────────────────────────────────
# Resolved from device.pushingToDevicePolicy (backend enum value).
# Controls HOW member data is pushed to a ZKTeco device during sync.
_PUSH_POLICY_INCREMENTAL   = "INCREMENTAL"    # delta: hash-based, delete stale + changed-then-insert
_PUSH_POLICY_FULL_REPLACE  = "FULL_REPLACE"   # nuke all tables then push entire desired roster
_PUSH_POLICY_ADDITIVE_ONLY = "ADDITIVE_ONLY"  # push changed/new (delete-then-insert), never remove stale

# Bounded retry for a pin that keeps failing on UNCHANGED content.
#
# Without this, marking a refused template as FAILED (which is the whole point
# of the fix) would re-select that pin on EVERY sync run forever:
# save_device_sync_state deliberately does NOT store desired_hash when ok=0, so
# a permanently-refused pin is doubly re-selected (stale hash AND last_ok=0).
# Each retry costs a firmware-cache clear plus a 10-call probe per finger,
# inline on the ULTRA worker with RTLog and door commands blocked.
#
# New content always changes the desired hash, so a re-enrolment is NEVER
# delayed by this. FULL_REPLACE / nuke reset pins_to_sync wholesale, so a
# force-resync always defeats it.
# Outcome of the last sync_member_on_connected_sdk call (engine._last_member_sync_outcome).
# The bool it returns means "revocation done"; these say WHY it is False. P3a-2.
MEMBER_SYNC_DELETED = "DELETED"
MEMBER_SYNC_DELETE_FAILED = "DELETE_FAILED"
MEMBER_SYNC_SKIPPED_NOT_OWNED = "SKIPPED_NOT_OWNED"      # final: never ours to delete
MEMBER_SYNC_OWNERSHIP_UNREADABLE = "OWNERSHIP_UNREADABLE"  # retry: cannot tell yet
MEMBER_SYNC_DEFERRED = "DEFERRED"   # cannot be decided now (incomplete roster, unnameable
                                    # pin); a fast retry changes nothing (review R2-23)

_SYNC_RETRY_FREE_ATTEMPTS = 3      # first 3 failures retry every run (unchanged behaviour)
_SYNC_RETRY_BASE_SEC      = 900    # then 15 min, doubling
# Capped at 6 h (was 24 h; P3a-2 item 2). The PC is on roughly 06:00-23:00 (door
# history, 2026-09-12 study) and off overnight, so a 24 h cap could leave a refused
# member without a single retry for two operating days. At 6 h a permanently refused
# pin costs at most 4 retries a day -- one member write (~0.45 s on the MB2000, field
# 928 members / 419 s) or, on PullSDK, a firmware-cache clear plus a <=10-call probe
# per finger -- while new content still bypasses the backoff entirely.
_SYNC_RETRY_MAX_SEC       = 21600
# Removals do NOT use this backoff: a failed removal is retried by the ULTRA worker
# within 300 s (ultra_engine._REMOVAL_RETRY_*), independent of the roster hash.


def _parse_dt_any(s: str) -> datetime | None:
    if not s:
        return None
    s = str(s).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1]
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return datetime.fromisoformat(s + "T00:00:00").replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def _pin_str(v) -> str:
    if v is None:
        return ""
    return str(v).strip()


# ── PIN SCHEME ──────────────────────────────────────────────────────────────────────────
#
# Which id a device user's PIN is, decided PER DEVICE (GymDeviceDto.pinScheme) and never by a
# client upgrade. The constants and the scheme normalisation live in app.core.pin_scheme so
# the storage layer (which this module imports) can use them too; they are re-exported here.
# derive_member_pin below is THE derivation. See guide_for_agents_and_dev.md §3.2b.
from app.core.pin_scheme import (  # noqa: E402  (re-exported)
    PIN_SCHEME_ACCOUNT,
    PIN_SCHEME_MEMBERSHIP,
    PIN_SOURCE_ACCOUNT,
    PIN_SOURCE_MEMBERSHIP,
    PIN_SOURCE_USER,
    device_pin_scheme,
    normalize_pin_scheme,
)


def derive_member_pin(user: Dict[str, Any], scheme: str) -> Tuple[str, str | None]:
    """THE derivation: ``(pin, source)`` for one roster row under ``scheme``.

    ``("", None)`` means the row has no pin under this scheme. Under ACCOUNT that is a row
    without ``mainAccountId`` (e.g. a cache row written before the column existed) and the
    caller must WITHHOLD it -- falling back to the membership id would mix schemes on one
    terminal. The returned pin is not validated as digits; callers skip non-digit pins.
    """
    if not isinstance(user, dict):
        return "", None
    if normalize_pin_scheme(scheme) == PIN_SCHEME_ACCOUNT:
        acct = _pin_str(user.get("mainAccountId"))
        return (acct, PIN_SOURCE_ACCOUNT) if acct else ("", None)
    am = _pin_str(user.get("activeMembershipId"))
    if am:
        return am, PIN_SOURCE_MEMBERSHIP
    uid = _pin_str(user.get("userId"))
    return (uid, PIN_SOURCE_USER) if uid else ("", None)


def account_pins_for_memberships(
    member_ids: Iterable[Any] | None,
    users: List[Dict[str, Any]] | None = None,
) -> Dict[int, str]:
    """membership id -> the ACCOUNT device pin (mainAccountId) of its person.

    Every sync request, delta hint, fast-patch impact and revocation names MEMBERSHIPS
    (activeMembershipId). Under pinScheme=ACCOUNT a device row is keyed by the person, so
    each of those sites must translate before touching a pin -- comparing a membership id
    to an account pin is exactly the 110-id collision.

    Looks in ``users`` first (the roster in hand), then ``member_account_link``, which still
    answers after a revocation has deleted the member's row. A membership that cannot be
    mapped is ABSENT from the result: callers must not fall back to the membership number.
    """
    wanted: Set[int] = set()
    for raw in member_ids or ():
        try:
            wanted.add(int(raw))
        except (TypeError, ValueError):
            continue
    out: Dict[int, str] = {}
    if not wanted:
        return out
    for u in users or []:
        if not isinstance(u, dict):
            continue
        am = _to_int(u.get("activeMembershipId"), default=None)
        if am is None or int(am) not in wanted:
            continue
        acct = _pin_str(u.get("mainAccountId"))
        if acct.isdigit():
            out[int(am)] = acct
    missing = wanted - set(out)
    if missing:
        try:
            from app.core import db as _db  # attribute lookup at call time (patchable)

            for am, acct in (_db.get_main_account_ids_for_memberships(missing) or {}).items():
                out.setdefault(int(am), str(int(acct)))
        except Exception:
            pass  # unknown stays unknown
    return out


def device_pins_for_members(
    member_ids: Iterable[Any] | None,
    *,
    scheme: str,
    users: List[Dict[str, Any]] | None = None,
) -> Dict[int, str]:
    """membership id -> device pin under ``scheme``.

    MEMBERSHIP: ``str(int(id))`` -- the membership IS the pin, byte-identical to every
    pre-existing ``str(int(member_id))``. ACCOUNT: ``account_pins_for_memberships`` (an
    unmappable membership is absent)."""
    if normalize_pin_scheme(scheme) != PIN_SCHEME_ACCOUNT:
        out: Dict[int, str] = {}
        for raw in member_ids or ():
            if raw is None:
                continue
            out[int(raw)] = str(int(raw))
        return out
    return account_pins_for_memberships(member_ids, users)


def person_rows_for_membership(member_id: int) -> Tuple[str | None, List[Dict[str, Any]]]:
    """(ACCOUNT pin, every cached row of that person) for one membership id.

    The targeted paths need ALL of a person's rows: the device row is the collapse of every
    membership the device accepts, so a push built from the one membership that changed
    would carry the wrong validity window and drop the other plans' fingers. ``(None, rows)``
    when the person cannot be named; the caller must then neither push nor delete.
    """
    from app.core import db as _db  # attribute lookup at call time (patchable)

    mid = int(member_id)
    rows = list(_db.list_sync_users_by_active_membership_ids({mid}) or [])
    acct = account_pins_for_memberships({mid}, rows).get(mid)
    if acct is None:
        return None, rows
    return acct, list(_db.list_sync_users_by_main_account_ids({int(acct)}) or [])


def account_roster_withheld_for_device(engine: "DeviceSyncEngine", device: Dict[str, Any]) -> int:
    """How many cached rows this ACCOUNT device would carry but cannot name (no mainAccountId).

    A TARGETED removal of an account pin sees only one person's rows; it must not remove
    while this is non-zero, for the same reason the full syncs refuse removals on an
    incomplete roster. Unreadable -> treated as incomplete (returns 1).
    """
    try:
        from app.core import db as _db  # attribute lookup at call time (patchable)

        rows = list(_db.list_sync_users_missing_main_account() or [])
    except Exception:
        return 1
    if not rows:
        return 0
    stats: Dict[str, Any] = {}
    engine._filter_users_for_device(
        users=rows, device=dict(device or {}), default_door_id=1, stats_out=stats,
    )
    return int(stats.get("withheld_missing_account") or 0)


# ── RENEWAL ORDERING (P3b-1, plan §7) ───────────────────────────────────────────────────
#
# Under pinScheme=MEMBERSHIP a person who bought ANOTHER plan gets a new activeMembershipId,
# hence a new pin, and P3b-1's date flip makes the old pin leave and the new one arrive in the
# SAME full-sync pass. Removals run first (guide §3.4b), so the old pin was deleted before the
# new one was written, and a failed write left the person with neither (guide §7 R3-21). Both
# full syncs now HOLD such a pin: removed only after the push confirmed every desired pin of
# that person, kept otherwise. ACCOUNT never holds: a renewal keeps the account pin.


def renewal_person_id(value: Any) -> int | None:
    """A userId as an int, None when absent or not a number."""
    if value is None or str(value).strip() == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def renewal_holds(
    departed_pins: Iterable[Any],
    *,
    pending_persons: Iterable[int],
    exempt: Iterable[str] = (),
) -> Dict[str, int]:
    """{departed pin: person} of the MEMBERSHIP pins a full sync must HOLD this pass.

    ``departed_pins``: pins this pass would remove (they left the desired roster).
    ``pending_persons``: the userIds of the desired pins NOT confirmed on the device at the
    start of the pass (new, changed, last push failed, or held back by the retry backoff).
    A departed pin is held when ``member_person_link`` names its person -- under MEMBERSHIP
    the pin is the activeMembershipId, whose row is usually gone by now -- and that person is
    pending. Not held, i.e. removed exactly as before: an ``exempt`` pin (an explicit
    revocation of this pass), a pin with no link row, or every pin when the link cannot be
    read (``get_member_person_user_ids`` answers {} then).
    """
    pending = {int(p) for p in (pending_persons or ()) if p is not None}
    if not pending:
        return {}
    skip = {str(p).strip() for p in (exempt or ())}
    cands = [
        pin for pin in (str(p if p is not None else "").strip() for p in (departed_pins or ()))
        if pin.isdigit() and pin not in skip
    ]
    if not cands:
        return {}
    try:
        from app.core import db as _db  # attribute lookup at call time (patchable)

        person_of = _db.get_member_person_user_ids([int(p) for p in cands]) or {}
    except Exception:
        return {}
    out: Dict[str, int] = {}
    for pin in cands:
        who = renewal_person_id(person_of.get(int(pin)))
        if who is not None and who in pending:
            out[pin] = who
    return out


def renewal_hold_released(
    person: int | None,
    *,
    person_by_pin: Dict[str, Any],
    unconfirmed: Iterable[str],
    confirmed_now: Iterable[str],
) -> bool:
    """True when every desired pin of ``person`` is confirmed on the device now: either it
    was not pending at the start of the pass, or this pass pushed it successfully.
    ``person_by_pin`` maps each DESIRED pin to its userId."""
    if person is None:
        return False
    pending = {str(p) for p in (unconfirmed or ())}
    done = {str(p) for p in (confirmed_now or ())}
    return all(
        pin not in pending or pin in done
        for pin, who in (person_by_pin or {}).items()
        if renewal_person_id(who) == person
    )


def reach_of(u: Dict[str, Any]):
    """How far into the future a roster row stays valid — the tie-break when several
    memberships collapse onto one device pin.

    A missing or unparseable ``validTo`` sorts FURTHEST, because that is how "no end date"
    is expressed on the wire. Treating an unknown as "expires now" would revoke members we
    simply cannot date.

    Public and shared on purpose: the device push (``_merge_same_pin_entries``) and the
    inbound door-event resolver (``device_attendance``) MUST agree on which membership a
    person's single device row represents. If they drift, a door event is attributed to a
    different membership than the one that opened the door.
    """
    vt = _parse_dt_any(u.get("validTo") or "")
    return vt or datetime.max.replace(tzinfo=timezone.utc)


def pin_row_rank(u: Dict[str, Any]):
    """The TOTAL order both collapse sides rank a person's memberships by:
    ``(reach_of(u), activeMembershipId)``.

    The id is the tie-break. Before it was shared, the push (``_merge_same_pin_entries``)
    kept the FIRST row on equal reach while the inbound resolver (``furthest_reach``) kept
    the LARGER id -- so for two memberships ending the same day the device row carried one
    membership's name and cards while its door events were attributed to the other.
    A pairwise max over a total order is also independent of payload order.
    """
    return (reach_of(u), _to_int(u.get("activeMembershipId"), default=0) or 0)


def furthest_reach(rows: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    """The row a collapsed device pin represents: the furthest-reaching membership.

    Ranked by ``pin_row_rank`` -- the same key ``_merge_same_pin_entries`` uses -- so the
    choice is deterministic and agrees with the push.
    """
    best = None
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        if best is None:
            best = r
            continue
        if pin_row_rank(r) > pin_row_rank(best):
            best = r
    return best


def _merge_same_pin_entries(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Collapse two roster rows that resolve to the same device pin into one row.

    Only reachable under ``pinScheme=ACCOUNT`` (``mainAccountId``): under MEMBERSHIP two
    rows cannot collide and this is never called. One human holding a 3-month gym
    plan and a 1-month spa plan is now one device row, and a device row carries exactly one
    validity window, one name and -- on the terminal -- one card.

    **Validity: the furthest reach wins.** Both rows have already passed
    ``allowedMemberships`` and (when enabled) the validity filter, so both are memberships
    this device accepts and honours right now. Keeping the shorter would lock a paid-up
    member out on the day their *other* plan lapses. A ``None``/unparseable ``validTo``
    counts as furthest -- it is how "no end date" is expressed, and treating an unknown as
    "expires immediately" would revoke people we simply cannot date.

    **Fingerprints: unioned, never taken from the winner.**
    ``_collect_templates_for_pin`` treats ``user['fingerprints']`` as the whole answer, and
    the backend attaches each template to the membership it was enrolled under. So keeping
    only the winner's list silently deletes every finger scanned on the losing plan. De-dupe
    by fingerprint id where present, else by (fingerId, templateVersion), because the same
    account-level template legitimately arrives on both rows.

    **Cards: the winner's, with the loser's kept only to fill an empty slot.** Every device push
    writes ONE card per user -- PullSDK ``CardNo`` and the standalone entry's ``card``, both from
    ``firstCardId``; ``secondCardId`` is never pushed -- so only ``firstCardId`` reaches the
    terminal and a losing membership's different card is dropped there.
    ``_filter_users_for_device`` counts and logs those (``stats_out["dropped_cards"]``).
    Whether a record could hold a second card is [UNVERIFIED -- HARDWARE-GATED].
    """
    winner, loser = (a, b) if pin_row_rank(a) >= pin_row_rank(b) else (b, a)
    merged = dict(winner)

    # Deterministic order (review #7): _collect_templates_for_pin keeps the LAST template per
    # fingerId, so when one finger was enrolled under two memberships the list order decided
    # which bytes -- and which desired hash -- the device got, and that order followed the
    # payload. Sorted by (fingerId, templateVersion, id, data), the largest template id wins a
    # finger whatever order the rows arrive in.
    def _fp_order(fp: Dict[str, Any]):
        def _n(v):
            n = _to_int(v, default=None)
            return (0, int(n)) if n is not None else (1, str(v or ""))
        return (_n(fp.get("fingerId")), _n(fp.get("templateVersion")), _n(fp.get("id")),
                str(fp.get("templateData") or ""))

    candidates = [fp for src in (winner, loser) for fp in (src.get("fingerprints") or [])
                  if isinstance(fp, dict)]
    seen: Set[Any] = set()
    fingerprints: List[Dict[str, Any]] = []
    for fp in sorted(candidates, key=_fp_order):
        key = fp.get("id")
        if key is None:
            key = (fp.get("fingerId"), fp.get("templateVersion"))
        if key in seen:
            continue
        seen.add(key)
        fingerprints.append(fp)
    if fingerprints or winner.get("fingerprints") is not None:
        merged["fingerprints"] = fingerprints

    # Fill an empty card slot from the loser rather than discarding a card the member
    # actually carries. Never overwrite a card the winner already has.
    for slot in ("firstCardId", "secondCardId"):
        if not _pin_str(merged.get(slot)) and _pin_str(loser.get(slot)):
            merged[slot] = loser.get(slot)

    return merged


def _normalize_device_card(raw) -> str:
    """The card value the ZKTeco device can actually store: digits only (strips
    admin markers like the '99999+' anti-abuse prefix), within the 4-byte CardNo
    range (1..4294967295, i.e. <= 10 digits). Returns '' if empty or out of range
    (caller then omits CardNo). Used by BOTH the device push AND the desired-state
    hash so a card edit only forces a re-sync when the value the DEVICE receives
    truly changes — otherwise a non-numeric / too-long marker flips the sync
    checksum forever while to_sync stays 0 (the wasted, popup-freezing sync)."""
    digits = "".join(ch for ch in str(raw or "") if ch.isdigit())
    if not digits:
        return ""
    try:
        n = int(digits)
    except ValueError:
        return ""
    return str(n) if 1 <= n <= 4294967295 else ""


def _safe_one_line(s: str) -> str:
    if not s:
        return ""
    return str(s).replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def _safe_template_text(s: str) -> str:
    if not s:
        return ""
    return str(s).replace("\r", "").replace("\n", "").replace("\t", "").strip()


def _is_structural_sdk_error(ex: BaseException) -> bool:
    """True when a PullSDK write failure is a genuine schema/table REJECTION.

    Distinguishes "this firmware does not have that table/field layout" (rc=-100..
    -103) from a transient or connection failure. Only the former justifies
    discarding a learned firmware profile: clearing the cache on a network blip
    throws away an expensively-probed combination and forces ten more SDK calls per
    finger, on a device that was answering correctly a second ago.

    `[UNVERIFIED heuristic]` -- the rc-code set is observed, not documented, and a
    driver that failed to embed "rc=" at all is treated as TRANSIENT. That default
    is deliberate: keeping a stale cache costs one wasted call and a fall-through to
    the full probe, whereas clearing a good one costs every subsequent push.
    [TEST: tests/test_firmware_profile_cache.py]
    """
    msg = str(ex)
    return any(code in msg for code in STRUCTURAL_ERROR_CODES)


def _decoded_template_len(text: str) -> int:
    """Byte length of an encoded template, for the rare row that omits templateSize.

    ``len(text)`` is the ENCODED length -- roughly 1.33x for base64 and exactly 2x
    for hex -- and it used to be sent to the device as ``Size=``, describing a
    payload it disagreed with. A 512-byte template reported 684.

    Decoded LAZILY, only when ``templateSize`` is genuinely absent: backend rows
    carry a NOT NULL templateSize, so this is near-unreachable, and the caller runs
    inside the hash loop over the FULL roster on every sync.

    Falls back to ``len(text)`` when the text will not decode at all -- a wrong Size
    beats dropping a template that might otherwise work.
    [TEST: tests/test_template_wire_encoding.py]
    """
    try:
        return len(from_b64(text))
    except Exception:
        return len(text)


def _template_wire(text: str, encoding: Any) -> "Tuple[str, int | None]":
    """Return (BASE64-ASCII template, decoded byte count or None).

    BOTH device wires take base64 ASCII: PullSDK ``Template=`` in
    templatev10/template, and zkemkeeper ``SetUserTmpExStr``. The backend may STORE
    a row as TemplateEncoding.HEX (the GMS legacy migration writes those) and,
    before the matching backend release, delivers it as hex TEXT. Pushing that
    unconverted writes a template the terminal can never match: the member is
    refused at the door while Access reports the push as done -- and the standalone
    driver misdiagnoses it as "store full" or "version mismatch", never encoding.

    Anything that is not HEX is returned untouched. That is the historical contract
    for every already-deployed row and for templates carrying no encoding at all,
    and it is why deployment order is free: once the backend emits
    templateEncoding="BASE64", this passes the data straight through, so double
    conversion cannot happen.

    The decode is deliberately as tolerant as the BACKEND's own hex decoder, which
    accepts a "0x" prefix and embedded whitespace
    (GmsMigrationService.decodeFingerprintTemplate, pinned by its
    GmsFingerprintDecodeTest). ``bytes.fromhex`` accepts neither, and rejecting
    what the backend accepted would drop a template it considered valid.

    Raises when encoding is HEX but the text will not decode; the caller drops that
    template rather than occupying a finger slot with something unmatchable.
    [TEST: tests/test_template_wire_encoding.py]
    """
    enc = str(encoding or "").strip().upper()
    if enc != "HEX":
        return text, None
    cleaned = "".join(str(text).split())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    raw = from_hex(cleaned)
    return to_b64(raw), len(raw)


def _batch_row_field(row: str, key: str) -> str:
    prefix = f"{key}="
    for part in str(row or "").split("\t"):
        if part.startswith(prefix):
            return part[len(prefix):]
    return ""


def _to_int(v, default: int | None = None) -> int | None:
    try:
        if v is None:
            return default
        x = str(v).strip()
        if x == "":
            return default
        return int(x)
    except Exception:
        return default


def _to_float(v, default: float | None = None) -> float | None:
    try:
        if v is None:
            return default
        x = str(v).strip()
        if x == "":
            return default
        return float(x)
    except Exception:
        return default


def _boolish(v, default: bool = True) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    try:
        s = str(v).strip().lower()
        if s in ("1", "true", "yes", "y", "on"):
            return True
        if s in ("0", "false", "no", "n", "off"):
            return False
    except Exception:
        pass
    return default


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return []


def _sha1_hex(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", errors="ignore")).hexdigest()


def _norm_int_list(xs: List[Any]) -> List[int]:
    out: List[int] = []
    for x in xs or []:
        xi = _to_int(x, default=None)
        if xi is None:
            continue
        if int(xi) > 0:
            out.append(int(xi))
    out = sorted(set(out))
    return out


@dataclass
class _OneShotDeviceSyncSession:
    device: Dict[str, Any]
    users: List[Dict[str, Any]]
    local_fp_index: Dict[str, List[Any]]
    default_door_id: int
    changed_ids: Set[int] | None
    sync_run_id: int | None
    pending: bool = True

    def has_pending_work(self) -> bool:
        return bool(self.pending)


class _DeviceSyncActorAdapter:
    def __init__(self, *, engine: "DeviceSyncEngine", device: Dict[str, Any]) -> None:
        self._engine = engine
        self._device = dict(device or {})

    def update_device(self, device: Dict[str, Any]) -> None:
        self._device = dict(device or {})

    def build_full_sync_session(self, *, device_id: int) -> _OneShotDeviceSyncSession:
        return self._build_session(changed_ids=None)

    def build_targeted_sync_session(
        self,
        *,
        device_id: int,
        member_ids: set[int],
    ) -> _OneShotDeviceSyncSession:
        return self._build_session(changed_ids=set(int(member_id) for member_id in member_ids))

    def run_sync_chunk(self, session: _OneShotDeviceSyncSession) -> bool:
        if not session.pending:
            return False
        session.pending = False
        self._engine._sync_one_device(
            device=dict(session.device),
            users=list(session.users),
            local_fp_index=session.local_fp_index,
            default_door_id=int(session.default_door_id),
            changed_ids=None if session.changed_ids is None else set(session.changed_ids),
            sync_run_id=session.sync_run_id,
            report_progress=False,
        )
        return True

    def on_sync_finished(self, *, device_id: int) -> None:
        self._engine._finish_actor_dispatch_progress(device_id=int(device_id))

    def _build_session(self, *, changed_ids: Set[int] | None) -> _OneShotDeviceSyncSession:
        context = self._engine._get_actor_dispatch_context()
        return _OneShotDeviceSyncSession(
            device=self._engine._normalize_device(dict(self._device)),
            users=list(context.get("users") or []),
            local_fp_index={
                str(pin): list(rows)
                for pin, rows in (context.get("local_fp_index") or {}).items()
            },
            default_door_id=int(context.get("default_door_id") or DEFAULT_AUTHORIZE_DOOR_ID_FALLBACK),
            changed_ids=None if changed_ids is None else set(changed_ids),
            sync_run_id=context.get("sync_run_id"),
        )


class DeviceSyncEngine:
    """
    Synchronizes ZKTeco controllers (PullSDK) from cached backend payload.

    IMPORTANT CHANGE (Mar 2026):
    - accessDataMode is PER DEVICE.
    - This engine only syncs devices where accessDataMode == DEVICE.
    - Global defaults (default_authorize_door_id, sdk_read_initial_bytes, etc.) come from
      GymAccessSoftwareSettingsDto cached in SQLite, via settings_reader.get_backend_global_settings().

    IMPORTANT CHANGE (Apr 2026):
    - Per-device actors replace the old ThreadPool/worker-manager approach.
    - _sync_all_devices dispatches to DeviceActorRegistry (non-blocking).
    - Each device keeps one serialized actor inbox for full and targeted sync work.
    """

    def __init__(self, *, cfg, logger, feedback_callback: Callable[[str, Dict[str, Any]], None] | None = None):
        from app.core.device_actor_registry import DeviceActorRegistry
        self.cfg = cfg
        self.logger = logger
        self._feedback_callback = feedback_callback
        # Optional hook the ULTRA worker sets so this engine can service queued
        # door-open commands BETWEEN device-push chunks. A full/member sync runs
        # inline on the worker over the single device TCP connection; without this
        # a door-open queued mid-push waits for the whole push (seconds→minutes)
        # and the member is stuck at the turnstile. Called between SetDeviceData
        # chunks, when the connection is idle — safe and serialized on the worker.
        self._door_yield_cb: "Callable[[], None] | None" = None
        # Sibling hook: poll+process RTLog scans between chunks so member scans
        # (and the popup) stay live during a long inline push, not just queued
        # door-opens. Gated/throttled on the worker side; None when unset.
        self._rtlog_yield_cb: "Callable[[], None] | None" = None
        self._run_lock = threading.Lock()
        self._running = False
        self._progress_cond = threading.Condition()
        self._progress_seq = 0
        # Live progress readable by the status API (dict value assignments are
        # atomic under CPython GIL — safe across worker threads).
        self._sync_progress: Dict[str, Any] = {
            "running": False,
            "deviceName": "",
            "deviceId": None,
            "current": 0,
            "total": 0,
        }
        # Phase 2: in-session firmware profile cache (device_id -> FirmwareProfile).
        # L1 cache (memory) backed by L2 (SQLite via db.py).
        # Keyed by device_id (stable integer), not IP (DHCP can reassign IPs).
        self._firmware_profiles: dict[int, FirmwareProfile] = {}
        self._dispatch_context_lock = threading.Lock()
        self._actor_dispatch_context: Dict[str, Any] = {
            "users": [],
            "local_fp_index": {},
            "default_door_id": self._default_authorize_door_id(),
            "sync_run_id": None,
        }
        self._actor_registry = DeviceActorRegistry(
            adapter_factory=self._build_actor_adapter,
        )
        # P9: captured by _run_single_device_sync on exception so the ULTRA
        # worker (or any other caller) can surface it as last_full_sync_error
        # instead of silently treating a failed sync as successful.
        self._last_single_device_error: str = ""

    def _build_actor_adapter(self, device: Dict[str, Any]) -> "_DeviceSyncActorAdapter":
        return _DeviceSyncActorAdapter(engine=self, device=device)

    def _set_actor_dispatch_context(
        self,
        *,
        users: List[Dict[str, Any]],
        local_fp_index: Dict[str, List[Any]],
        default_door_id: int,
        sync_run_id: int | None,
    ) -> None:
        with self._dispatch_context_lock:
            self._actor_dispatch_context = {
                "users": list(users),
                "local_fp_index": {
                    str(pin): list(rows)
                    for pin, rows in (local_fp_index or {}).items()
                },
                "default_door_id": int(default_door_id),
                "sync_run_id": sync_run_id,
            }

    def _get_actor_dispatch_context(self) -> Dict[str, Any]:
        with self._dispatch_context_lock:
            context = dict(self._actor_dispatch_context)
        context["users"] = list(context.get("users") or [])
        context["local_fp_index"] = {
            str(pin): list(rows)
            for pin, rows in (context.get("local_fp_index") or {}).items()
        }
        return context

    def _emit_feedback_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        if not self._feedback_callback:
            return
        try:
            self._feedback_callback(event_type, dict(payload))
        except Exception:
            self.logger.debug("[DeviceSync] feedback callback failed for %s", event_type, exc_info=True)

    def _resolve_template_version_override(self, device: Dict[str, Any]) -> "int | None":
        """The per-device fingerprint template-version bias (9 or 10), else None.

        SINGLE source of truth, used by the push path AND by both desired-hash
        paths. They must agree: if the push applies an override the hash does not,
        the stored device_sync_state hash never matches what the push produced, and
        the pin thrashes -- re-pushed on every cycle, forever.

        Reads the already-parsed key that _normalize_device puts on the dict, and
        falls back to re-parsing the raw capabilities JSON (belt and braces for
        callers that hand over an unnormalised device).
        """
        v = (device or {}).get("fingerprintTemplateVersion")
        if v is None:
            v = parse_fingerprint_template_version(
                (device or {}).get("deviceCapabilities")
                or (device or {}).get("device_capabilities")
            )
        return v if v in (9, 10) else None

    def _get_firmware_profile(self, device_id: int) -> FirmwareProfile:
        """
        Returns the FirmwareProfile for this device, loading from SQLite if not in session cache.
        Creates an empty profile if none exists yet (discovery happens on first push attempt).
        """
        if device_id not in self._firmware_profiles:
            from app.core.db import load_firmware_profile
            persisted = load_firmware_profile(device_id=device_id)
            if persisted:
                tt = persisted.get("template_table")
                self._firmware_profiles[device_id] = FirmwareProfile(
                    template_table=tt if tt else None,
                    template_body_index=persisted.get("template_body_index"),
                    authorize_body_index=persisted.get("authorize_body_index"),
                    name_supported=persisted.get("name_supported"),
                    insert_strategy=persisted.get("insert_strategy"),
                    delete_strategy=persisted.get("delete_strategy"),
                    template_version_bias=int(persisted.get("template_version_bias") or 0),
                )
            else:
                self._firmware_profiles[device_id] = FirmwareProfile()
        return self._firmware_profiles[device_id]

    def _save_firmware_profile(self, profile: FirmwareProfile, device_id: int) -> None:
        """Persist the firmware profile to SQLite (L2 cache)."""
        from app.core.db import save_firmware_profile
        save_firmware_profile(
            device_id=device_id,
            template_table=profile.template_table,
            template_body_index=profile.template_body_index,
            authorize_body_index=profile.authorize_body_index,
            name_supported=profile.name_supported,
            insert_strategy=profile.insert_strategy,
            delete_strategy=profile.delete_strategy,
            template_version_bias=profile.template_version_bias,
        )

    def _set_progress(self, **changes: Any) -> None:
        with self._progress_cond:
            changed = False
            for key, value in changes.items():
                if self._sync_progress.get(key) != value:
                    self._sync_progress[key] = value
                    changed = True
            if changed:
                self._progress_seq += 1
                self._progress_cond.notify_all()

    def _begin_actor_dispatch_progress(self, *, dispatched: int) -> None:
        dispatched = int(dispatched or 0)
        if dispatched <= 0:
            return
        with self._progress_cond:
            current = int(self._sync_progress.get("current") or 0)
            total = int(self._sync_progress.get("total") or 0)
            running = bool(self._sync_progress.get("running"))
            reset = (not running) or total <= current
            next_current = 0 if reset else current
            next_total = dispatched if reset else total + dispatched

            changed = False
            for key, value in {
                "running": True,
                "deviceName": "",
                "deviceId": None,
                "current": next_current,
                "total": next_total,
            }.items():
                if self._sync_progress.get(key) != value:
                    self._sync_progress[key] = value
                    changed = True
            if changed:
                self._progress_seq += 1
                self._progress_cond.notify_all()

    def _finish_actor_dispatch_progress(self, *, device_id: int) -> None:
        with self._progress_cond:
            total = int(self._sync_progress.get("total") or 0)
            current = int(self._sync_progress.get("current") or 0)
            if total <= 0 or current >= total:
                return

            next_current = min(total, current + 1)
            changes = {
                "current": next_current,
            }
            if next_current >= total:
                changes.update({
                    "running": False,
                    "deviceName": "",
                    "deviceId": None,
                })

            changed = False
            for key, value in changes.items():
                if self._sync_progress.get(key) != value:
                    self._sync_progress[key] = value
                    changed = True
            if changed:
                self._progress_seq += 1
                self._progress_cond.notify_all()

    def get_progress_snapshot(self) -> tuple[Dict[str, Any], int]:
        with self._progress_cond:
            return dict(self._sync_progress), self._progress_seq

    def wait_for_progress_change(self, last_seq: int, timeout: float = 1.0) -> tuple[Dict[str, Any], int]:
        with self._progress_cond:
            if self._progress_seq == last_seq:
                self._progress_cond.wait(timeout=max(0.0, float(timeout)))
            return dict(self._sync_progress), self._progress_seq

    def stop_workers(self) -> None:
        """Stop all per-device worker threads. Call on logout / shutdown."""
        self._actor_registry.stop_all()
        self._set_progress(running=False, deviceName="", deviceId=None, current=0, total=0)

    def run_blocking(
        self,
        *,
        cache,
        source: str = "timer",
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
    ) -> bool:
        with self._run_lock:
            if self._running:
                self.logger.info(f"[DeviceSync] Skip ({source}): already running")
                return False
            self._running = True

        try:
            self._sync_all_devices(cache=cache, changed_ids=changed_ids, sync_run_id=sync_run_id)
            return True
        except Exception as e:
            self.logger.exception(f"[DeviceSync] Failed: {e}")
            return True
        finally:
            with self._run_lock:
                self._running = False

    def run_one_device_blocking(
        self,
        *,
        cache,
        device: Dict[str, Any],
        source: str = "timer",
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
    ) -> bool:
        """
        Synchronously push a single device on the current thread.

        ULTRA mode needs this direct path because the regular run_blocking()
        dispatches to persistent background workers and returns immediately.
        For RTLog TCP handoff we must keep the worker paused until the actual
        device push has completed.
        """
        return self._run_single_device_sync(
            cache=cache,
            device=device,
            source=source,
            changed_ids=changed_ids,
            sync_run_id=sync_run_id,
            sdk=None,
        )

    def run_one_device_on_connected_sdk(
        self,
        *,
        sdk: PullSDK,
        cache,
        device: Dict[str, Any],
        source: str = "timer",
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
    ) -> bool:
        """Synchronously push a single device using an already-connected SDK."""
        return self._run_single_device_sync(
            cache=cache,
            device=device,
            source=source,
            changed_ids=changed_ids,
            sync_run_id=sync_run_id,
            sdk=sdk,
        )

    def _maybe_yield_doors(self) -> None:
        """Service the worker's queued door-opens (if a hook is set) between
        device-push chunks, so a member scanning mid-sync is let in within ~one
        chunk instead of waiting for the entire inline push. Never raises."""
        cb = self._door_yield_cb
        if cb is None:
            return
        try:
            cb()
        except Exception:
            pass

    def _maybe_yield_rtlog(self) -> None:
        """Poll+process RTLog scans (if a hook is set) between device-push
        chunks, so a member scanning mid-sync is seen — and PC-verified QR/TOTP
        members are let in — within ~a second instead of waiting for the whole
        inline push. Gating/throttling lives in the worker hook. Never raises."""
        cb = self._rtlog_yield_cb
        if cb is None:
            return
        try:
            cb()
        except Exception:
            pass

    def _run_single_device_sync(
        self,
        *,
        cache,
        device: Dict[str, Any],
        source: str,
        changed_ids: set | None,
        sync_run_id: int | None,
        sdk: PullSDK | None,
    ) -> bool:
        with self._run_lock:
            if self._running:
                self.logger.info(f"[DeviceSync] Skip single-device ({source}): already running")
                return False
            self._running = True

        try:
            if not cache:
                self.logger.info("[DeviceSync] No cache -> skip single-device sync")
                return False

            normalized_device = self._normalize_device(device if isinstance(device, dict) else {})
            dev_id = normalized_device.get("id")
            dev_name = normalized_device.get("name", "")

            if not _boolish(normalized_device.get("active"), default=True):
                self.logger.info(
                    "[DeviceSync] Skip single-device id=%s name=%r: active=False",
                    dev_id, dev_name,
                )
                return False
            if not _boolish(normalized_device.get("accessDevice"), default=True):
                self.logger.info(
                    "[DeviceSync] Skip single-device id=%s name=%r: accessDevice=False",
                    dev_id, dev_name,
                )
                return False

            users = getattr(cache, "users", []) or []

            local_fp_index: Dict[str, List[Any]] = {}
            raw_fingerprint_enabled = normalized_device.get("fingerprintEnabled")
            if raw_fingerprint_enabled is None:
                raw_fingerprint_enabled = normalized_device.get("fingerprint_enabled")
            fingerprint_enabled = _boolish(
                raw_fingerprint_enabled,
                default=True,
            )
            if fingerprint_enabled:
                try:
                    recs = list_fingerprints()
                    for r in recs:
                        pin = _pin_str(getattr(r, "pin", "") or "")
                        if not pin:
                            continue
                        local_fp_index.setdefault(pin, []).append(r)
                except Exception:
                    local_fp_index = {}

            default_door_id = self._default_authorize_door_id()
            self._set_progress(
                running=True,
                deviceName=str(dev_name or ""),
                deviceId=dev_id,
                current=0,
                total=1,
            )
            sync_kwargs = {
                "device": normalized_device,
                "users": users,
                "local_fp_index": local_fp_index,
                "default_door_id": default_door_id,
                "changed_ids": changed_ids,
                "sync_run_id": sync_run_id,
            }
            if sdk is not None:
                sync_kwargs["sdk"] = sdk
            # Push to device runs over the single device TCP connection. When it
            # is invoked on the live ULTRA worker (sdk is not None) it blocks
            # RTLog polling for its full duration — trace start/duration/result.
            _push_t0 = time.monotonic()
            _tel.event(
                "PUSH_DEVICE_START", device_id=dev_id, source=source,
                users=len(users), changed=(len(changed_ids) if changed_ids else 0),
                mode=("connected_sdk" if sdk is not None else "own_conn"),
            )
            self._sync_one_device(
                **sync_kwargs,
            )
            self._set_progress(current=1)
            self._last_single_device_error = ""
            _tel.event(
                "PUSH_DEVICE_DONE", device_id=dev_id, source=source,
                dur_ms=round((time.monotonic() - _push_t0) * 1000), users=len(users),
            )
            return True
        except Exception as e:
            # P9: capture the error so the ULTRA worker can surface it via
            # last_full_sync_error. Previously the exception was logged here
            # and swallowed; the ULTRA worker then reported the sync as
            # successful because it only inspected the absence of an exception
            # *at its own call site*. Production logs showed PullSDKError
            # (table=user rc=-2) silently failing user-table refresh while
            # the UI's full-sync status showed green.
            self._last_single_device_error = str(e) or e.__class__.__name__
            self.logger.exception(f"[DeviceSync] Single-device sync failed: {e}")
            _tel.warn("PUSH_DEVICE_FAILED", source=source, err=type(e).__name__)
            return False
        finally:
            self._set_progress(
                running=False,
                deviceName="",
                deviceId=None,
                current=0,
                total=0,
            )
            with self._run_lock:
                self._running = False

    # ---------------- internal ----------------

    def _build_local_fp_index_for_pins(
        self,
        *,
        pins: set[str],
        fingerprint_enabled: bool,
    ) -> Dict[str, List[Any]]:
        if not fingerprint_enabled or not pins:
            return {}
        try:
            records = list_fingerprints_by_pins(pins=pins)
        except Exception:
            return {}

        local_fp_index: Dict[str, List[Any]] = {}
        for record in records:
            pin = _pin_str(getattr(record, "pin", "") or "")
            if not pin:
                continue
            local_fp_index.setdefault(pin, []).append(record)
        return local_fp_index

    def _push_pin_to_connected_sdk(
        self,
        *,
        sdk: PullSDK,
        device_id: int,
        device_name: str,
        pin: str,
        user: Dict[str, Any],
        desired_hash: str,
        door_ids: List[int],
        door_bitmask: int,
        authorize_timezone_id: int,
        templates: List[Dict[str, Any]],
        fingerprint_enabled: bool = True,
        template_version_override: int | None = None,
        pin_source: str | None = None,
    ) -> bool:
        full_name = _safe_one_line(user.get("fullName") or "") or f"U{pin}"
        card = _pin_str(user.get("firstCardId") or "")
        auth_err: str | None = None

        try:
            # WRITE-AHEAD (P3a-2): durable before the first device write below; if it
            # cannot be recorded this raises into the failure path and nothing is written.
            record_push_intents(
                device_id=device_id, protocol="ZK_PULLSDK",
                rows=[(pin, full_name, _normalize_device_card(card), desired_hash)],
            )
            self._delete_pin_unconditional(
                sdk=sdk, pin=pin, fingerprint_enabled=fingerprint_enabled,
            )

            card_valid = _normalize_device_card(card)
            if card and not card_valid:
                self.logger.warning(
                    "[DeviceSync] Device id=%s Pin=%s CardNo=%r is not numeric - skipping CardNo",
                    device_id,
                    pin,
                    card,
                )

            profile = self._get_firmware_profile(device_id)
            use_name = profile.name_supported is not False
            pairs = [f"Pin={pin}"]
            if use_name:
                pairs.append(f"Name={full_name}")
            if card_valid:
                pairs.append(f"CardNo={card_valid}")

            try:
                sdk.set_device_data(table="user", data="\t".join(pairs) + "\r\n", options="")
                if profile.name_supported is None and use_name:
                    profile.name_supported = True
                    self._save_firmware_profile(profile, device_id)
            except PullSDKError as set_err:
                if "rc=-101" not in str(set_err):
                    raise
                self.logger.warning(
                    "[DeviceSync] Device id=%s Pin=%s SetDeviceData rc=-101 - retrying without Name",
                    device_id,
                    pin,
                )
                self._delete_auth_and_templates_best_effort(
                    sdk=sdk, pin=pin, fingerprint_enabled=fingerprint_enabled,
                )
                try:
                    sdk.delete_device_data(table="user", data=f"Pin={pin}", options="")
                except Exception:
                    pass
                minimal_pairs = [f"Pin={pin}"]
                if card_valid:
                    minimal_pairs.append(f"CardNo={card_valid}")
                sdk.set_device_data(
                    table="user",
                    data="\t".join(minimal_pairs) + "\r\n",
                    options="",
                )
                if use_name and profile.name_supported is None:
                    profile.name_supported = False
                    self._save_firmware_profile(profile, device_id)

            auth_complete = True
            auth_ok_count, auth_err = self._push_userauthorize(
                sdk,
                pin=pin,
                door_bitmask=door_bitmask,
                authorize_timezone_id=int(authorize_timezone_id),
                device_id=device_id,
            )
            if auth_err:
                auth_complete = (auth_ok_count == len(door_ids))
                self.logger.warning(
                    "[DeviceSync] Device id=%s Pin=%s authorize %s: %s/%s doors - %s",
                    device_id,
                    pin,
                    "PARTIAL" if not auth_complete else "warn",
                    auth_ok_count,
                    len(door_ids),
                    auth_err,
                )

            tpl_err: str | None = None
            if templates:
                _ok_count, errs = self._push_templates(
                    sdk,
                    pin=pin,
                    templates=templates,
                    device_id=device_id,
                    template_version_override=template_version_override,
                    pin_source=pin_source,
                )
                if errs:
                    # See _sync_one_device Phase C. This path previously ignored
                    # templates ENTIRELY when deciding ok: a targeted member sync
                    # returned True on a fingerprint that never reached the door.
                    tpl_err = f"template push failed ({len(errs)}): {errs[0]}"
                    self.logger.warning(
                        "[DeviceSync] Device id=%s Pin=%s template errors (%d): %s",
                        device_id,
                        pin,
                        len(errs),
                        errs[:5],
                    )

            push_ok = bool(auth_complete) and tpl_err is None
            save_device_sync_state(
                device_id=device_id,
                pin=pin,
                desired_hash=desired_hash,
                ok=push_ok,
                error=None if push_ok else ((auth_err or "authorize incomplete")
                                            if not auth_complete else tpl_err),
            )
            try:
                upsert_device_mirror_pin(
                    device_id=device_id,
                    pin=pin,
                    full_name=full_name,
                    card_no=card or None,
                    door_bitmask=door_bitmask,
                    authorize_tz_id=int(authorize_timezone_id),
                    fp_count=len(templates),
                    push_ok=push_ok,
                )
            except Exception:
                pass

            self.logger.info(
                "[DeviceSync] targeted member sync: device_id=%s device_name=%r pin=%s ok=%s",
                device_id,
                device_name,
                pin,
                push_ok,
            )
            return push_ok
        except Exception as exc:
            save_device_sync_state(
                device_id=device_id,
                pin=pin,
                desired_hash=desired_hash,
                ok=False,
                error=str(exc),
            )
            try:
                upsert_device_mirror_pin(
                    device_id=device_id,
                    pin=pin,
                    full_name=full_name,
                    card_no=card or None,
                    door_bitmask=door_bitmask,
                    authorize_tz_id=int(authorize_timezone_id),
                    fp_count=len(templates),
                    push_ok=False,
                )
            except Exception:
                pass
            self.logger.warning(
                "[DeviceSync] targeted member sync failed: device_id=%s device_name=%r pin=%s err=%s",
                device_id,
                device_name,
                pin,
                exc,
            )
            return False

    @_tel.timed("MEMBER_SYNC_DEVICE", slow_ms=0, warn_ms=3000)
    def sync_member_on_connected_sdk(
        self,
        *,
        sdk: PullSDK,
        device: Dict[str, Any],
        member_id: int,
        source: str = "targeted_member_sync",
        revocation: bool = False,
    ) -> bool:
        self._last_member_sync_outcome = None
        normalized_device = self._normalize_device(device if isinstance(device, dict) else {})
        dev_id = normalized_device.get("id")
        dev_name = normalized_device.get("name", "")
        if dev_id is None:
            return False
        did = int(_to_int(dev_id, default=0) or 0)
        if did <= 0:
            return False
        if not _boolish(normalized_device.get("active"), default=True):
            return False
        if not _boolish(normalized_device.get("accessDevice"), default=True):
            return False

        # The request names a MEMBERSHIP; the device row is keyed by the device's pinScheme.
        # Under MEMBERSHIP they are the same number (unchanged). Under ACCOUNT the pin is the
        # person's, and a membership id used as a pin names -- for 110 ids -- ANOTHER
        # person's device user: the old `desired.get(pin)` then missed and the branch below
        # DELETED that stranger. guide §3.2b.
        pin_scheme = device_pin_scheme(normalized_device)
        account_rows: List[Dict[str, Any]] | None = None
        if pin_scheme == PIN_SCHEME_ACCOUNT:
            acct, account_rows = person_rows_for_membership(int(member_id))
            if acct is None:
                self.logger.warning(
                    "[DeviceSync] targeted member sync: device_id=%s device_name=%r "
                    "pinScheme=ACCOUNT cannot name the device pin of membership %s (no cached "
                    "or linked mainAccountId) -- nothing pushed, nothing deleted; the next "
                    "full sync reconciles. source=%s",
                    did, dev_name, member_id, source,
                )
                self._last_member_sync_outcome = MEMBER_SYNC_DEFERRED
                return False
            pin = acct
        else:
            pin = _pin_str(member_id)
        if not pin or not pin.isdigit():
            return False

        default_door_id = self._default_authorize_door_id()
        door_ids, door_bitmask, authorize_timezone_id, fingerprint_enabled = self._resolve_push_context(
            device=normalized_device,
            default_door_id=default_door_id,
        )

        if account_rows is not None:
            # Every row of the person: the collapse needs all of them.
            target_users = account_rows
        else:
            target_users = list_sync_users_by_active_membership_ids({int(member_id)})
        filter_stats: Dict[str, Any] = {}
        desired = self._filter_users_for_device(
            users=target_users,
            device=normalized_device,
            default_door_id=default_door_id,
            stats_out=filter_stats,
        )
        desired_user = desired.get(pin)

        if (
            not isinstance(desired_user, dict)
            and pin_scheme == PIN_SCHEME_ACCOUNT
            and (
                filter_stats.get("withheld_missing_account")
                or account_roster_withheld_for_device(self, normalized_device)
            )
        ):
            # Not provably "departed": some row this device would carry has no
            # mainAccountId, and it may be this person's other membership. Never delete on
            # an incomplete roster; the full sync skips removals for the same reason.
            self.logger.warning(
                "[DeviceSync] targeted member sync: device_id=%s pin=%s pinScheme=ACCOUNT "
                "roster incomplete (rows without mainAccountId) -- not deleting. source=%s",
                did, pin, source,
            )
            self._last_member_sync_outcome = MEMBER_SYNC_DEFERRED
            return False

        if not isinstance(desired_user, dict):
            # OWNERSHIP GATE (P3a-2, guide §3.4). This deleted the pin from four tables
            # with no check at all -- under ACCOUNT, for the 110 account ids that equal
            # another person's membership id, that is a stranger's device user. Only a
            # pin MonClub affirmatively wrote (ownership_confirmed=1) is deleted, under
            # EITHER scheme: "never delete an unowned user" is not conditional on a
            # setting. Unreadable ownership is a retry, never read as "not owned".
            try:
                owned = get_device_sync_ownership_for_pin(device_id=did, pin=pin)
            except Exception as ex:
                self._last_member_sync_outcome = MEMBER_SYNC_OWNERSHIP_UNREADABLE
                self.logger.warning(
                    "[DeviceSync] targeted member delete: device_id=%s pin=%s ownership "
                    "unreadable (%s) -- nothing deleted, retried later. source=%s",
                    did, pin, ex, source,
                )
                return False
            if not owned:
                # A push MonClub never got to confirm (crash, refused authorize) leaves a
                # write-ahead intent; the card on the panel proves it (P3a-2 item 3).
                proof = self._prove_pullsdk_intent(sdk=sdk, did=did, pin=pin)
                if proof is None:
                    # The proof could not be read (intent row or panel read failed): the
                    # same "cannot tell" as unreadable ownership -- a retry, never the
                    # FINAL skip (review R1-12).
                    self._last_member_sync_outcome = MEMBER_SYNC_OWNERSHIP_UNREADABLE
                    self.logger.warning(
                        "[DeviceSync] targeted member delete: device_id=%s pin=%s intent "
                        "proof unreadable -- nothing deleted, retried later. source=%s",
                        did, pin, source,
                    )
                    return False
                owned = proof
            if not owned:
                self._last_member_sync_outcome = MEMBER_SYNC_SKIPPED_NOT_OWNED
                self.logger.critical(
                    "[DeviceSync] targeted member delete SKIPPED_NOT_OWNED: device_id=%s "
                    "device_name=%r pin=%s membership=%s pinScheme=%s -- MonClub has no "
                    "proof it wrote this device user, so it is never deleted. source=%s",
                    did, dev_name, pin, member_id, pin_scheme, source,
                )
                try:
                    _tel.warn(
                        "MEMBER_REVOKE_SKIPPED_NOT_OWNED", device_id=did, member_id=member_id,
                        pin=pin, pin_scheme=pin_scheme or None, protocol="ZK_PULLSDK",
                        source=source,
                    )
                except Exception:
                    pass
                return False
            deleted = self._delete_pin_unconditional(
                sdk=sdk, pin=pin, fingerprint_enabled=fingerprint_enabled,
            )
            if deleted:
                self._last_member_sync_outcome = MEMBER_SYNC_DELETED
                # State, mirror and push intent, in one transaction.
                clear_device_revocation_state(device_id=did, pin=pin)
            else:
                # KEEP the row: it is the ownership proof the retry needs. It used to be
                # deleted regardless, so every retry then read "not owned".
                self._last_member_sync_outcome = MEMBER_SYNC_DELETE_FAILED
            self.logger.info(
                "[DeviceSync] targeted member delete: device_id=%s device_name=%r pin=%s deleted=%s source=%s",
                did,
                dev_name,
                pin,
                bool(deleted),
                source,
            )
            return bool(deleted)

        local_fp_index = self._build_local_fp_index_for_pins(
            pins={pin},
            fingerprint_enabled=fingerprint_enabled,
        )
        templates = self._collect_templates_for_pin(
            user=desired_user,
            pin=pin,
            local_fp_index=local_fp_index,
            fingerprint_enabled=fingerprint_enabled,
        )
        desired_hash = self._compute_desired_hash(
            pin=pin,
            user=desired_user,
            door_bitmask=door_bitmask,
            templates=templates,
            authorize_timezone_id=authorize_timezone_id,
            template_version_override=self._resolve_template_version_override(normalized_device),
        )

        # Targeted: fetch ONLY this pin's stored hash (PK lookup ~ms) instead of
        # reading the whole device_sync_state table (~1798 rows, 11-20s on the gym PC).
        prev_hash, prev_ok = get_device_sync_hash_for_pin(device_id=did, pin=pin)
        if prev_hash == desired_hash and prev_ok and revocation and pin_scheme == PIN_SCHEME_ACCOUNT:
            # Revoking ONE of a person's memberships while another still admits them: the
            # collapsed row stays, and its hash (no validity window) cannot move, so "unchanged"
            # here would read as "revocation not done" to both ULTRA consumers and fail every
            # full sync. Re-push the merged entry -- the revoked plan's validity and fingers leave
            # with it -- and let that push be the revoke's outcome, as _account_member_revoke
            # does on the standalone path (review #11, guide §3.2b).
            self.logger.info(
                "[DeviceSync] targeted member revoke: device_id=%s pin=%s pinScheme=ACCOUNT person "
                "still deliverable -- re-pushing the collapsed row as the revoke outcome "
                "(membership %s) source=%s",
                did, pin, member_id, source,
            )
        elif prev_hash == desired_hash and prev_ok:
            self.logger.info(
                "[DeviceSync] targeted member sync skip: device_id=%s device_name=%r pin=%s unchanged source=%s",
                did,
                dev_name,
                pin,
                source,
            )
            return False

        return self._push_pin_to_connected_sdk(
            sdk=sdk,
            device_id=did,
            device_name=str(dev_name or ""),
            pin=pin,
            user=desired_user,
            desired_hash=desired_hash,
            door_ids=door_ids,
            door_bitmask=door_bitmask,
            authorize_timezone_id=authorize_timezone_id,
            templates=templates,
            fingerprint_enabled=fingerprint_enabled,
            template_version_override=self._resolve_template_version_override(normalized_device),
            pin_source=(filter_stats.get("pin_sources") or {}).get(pin),
        )

    # ---------------------------------------------------------------- #
    # P3a-2 write-ahead intents on the PullSDK path (guide §3.4a)
    # ---------------------------------------------------------------- #
    @staticmethod
    def _same_card(want: str, got: str) -> bool:
        """Card equality as the panel stores it: digits, leading zeros ignored.

        An empty intent card proves nothing (a C3-400 card turnstile cannot admit a
        card-less member anyway), so it never matches. [UNVERIFIED] how the C3-400
        returns CardNo (padding, leading zeros) -- FIELD-TEST."""
        w = "".join(ch for ch in str(want or "") if ch.isdigit()).lstrip("0")
        g = "".join(ch for ch in str(got or "") if ch.isdigit()).lstrip("0")
        return bool(w) and w == g

    def _read_panel_cards(self, sdk: PullSDK, *, pin: str | None = None) -> Dict[str, str] | None:
        """{pin: CardNo} from the panel's user table (one pin, or all). None = read failed."""
        try:
            rows = sdk.get_device_data_rows(
                table="user", fields="Pin\tCardNo",
                filter_expr=(f"Pin={pin}" if pin else ""), options="",
                initial_size=self._sdk_read_initial_bytes(),
            )
        except Exception as ex:
            self.logger.warning("[DeviceSync] intent read-back: user table read failed: %s", ex)
            return None
        out: Dict[str, str] = {}
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            p = _pin_str(r.get("Pin") or r.get("pin") or "")
            if p:
                out[p] = _pin_str(r.get("CardNo") or r.get("cardno") or "")
        return out

    def _settle_pullsdk_intents(
        self, *, sdk: PullSDK, did: int, desired_pins: Set[str], device_pins: Set[str],
    ) -> Set[str]:
        """Settle the intents of pins that LEFT the roster; return the pins proven ours.

        Absent from the panel (the full Pin read just done): the write never landed,
        the intent is dropped. Present with the card MonClub wrote: promoted to
        ownership. Present with another card: another user holds that pin -- intent
        kept, miss counted, never deleted. One extra read (Pin + CardNo), only when
        such an intent is present on the panel.
        """
        try:
            intents = list_push_intents(device_id=did) or {}
        except Exception:
            self.logger.warning("[DeviceSync] Device id=%s intents unreadable", did, exc_info=True)
            return set()
        cands = {
            p: it for p, it in intents.items()
            if p not in desired_pins and str(it.get("protocol") or "") in ("", "ZK_PULLSDK")
        }
        if not cands:
            return set()
        # An EMPTY whole-table read cannot tell an empty panel from a read that returned
        # nothing: drop no intent on it (review R1-30).
        absent = sorted(p for p in cands if p not in device_pins) if device_pins else []
        present = {p: it for p, it in cands.items() if p in device_pins}
        promoted: List[str] = []
        mismatched: List[str] = []
        if present:
            cards = self._read_panel_cards(sdk)
            if cards is not None:
                for p, it in sorted(present.items()):
                    if p not in cards:
                        continue
                    if self._same_card(it.get("card") or "", cards.get(p) or ""):
                        promoted.append(p)
                    elif str(it.get("card") or "").strip():
                        mismatched.append(p)
        try:
            if absent:
                drop_push_intents(device_id=did, pins=absent)
            if promoted:
                promote_push_intents(device_id=did, pins=promoted)
            if mismatched:
                note_push_intent_misses(device_id=did, pins=mismatched)
        except Exception:
            self.logger.warning("[DeviceSync] Device id=%s intent settlement not recorded", did,
                                exc_info=True)
            return set()
        try:
            _tel.event("PUSH_INTENT_READBACK", device_id=did, protocol="ZK_PULLSDK", ok=True,
                       candidates=len(cands), promoted=len(promoted), dropped=len(absent),
                       mismatched=len(mismatched))
        except Exception:
            pass
        return set(promoted)

    def _prove_pullsdk_intent(self, *, sdk: PullSDK, did: int, pin: str) -> "bool | None":
        """A targeted revoke found no ownership: is this pin a push MonClub never got to
        confirm (an intent) whose card is on the panel? One filtered read.

        True = proven (promoted); False = not proven; None = CANNOT TELL (the intent or
        the panel could not be read) -- the caller retries instead of skipping for good
        (review R1-12). An empty answer is "not proven" but does NOT drop the intent: a
        one-pin read that answers nothing is not proof of absence; the full sync's
        whole-table read settles it (review R1-30)."""
        try:
            intent = get_push_intent(device_id=did, pin=pin)
        except Exception:
            return None
        if not intent or str(intent.get("protocol") or "") not in ("", "ZK_PULLSDK"):
            return False
        if not str(intent.get("card") or "").strip():
            return False
        cards = self._read_panel_cards(sdk, pin=pin)
        if cards is None:
            return None
        try:
            if pin not in cards:
                return False
            if self._same_card(intent.get("card") or "", cards.get(pin) or ""):
                promote_push_intents(device_id=did, pins=[pin])
                self.logger.warning(
                    "[DeviceSync] Device id=%s Pin=%s proven MonClub's by read-back (write-ahead "
                    "intent, card on the panel) -- removal proceeds", did, pin,
                )
                return True
            note_push_intent_misses(device_id=did, pins=[pin])
        except Exception:
            # The card matched but the promotion could not be written: "cannot tell yet",
            # a retry -- never the final skip (review R2-18).
            self.logger.warning("[DeviceSync] Device id=%s Pin=%s intent proof not recorded",
                                did, pin, exc_info=True)
            return None
        return False

    def _global_defaults(self) -> Dict[str, Any]:
        """
        Backend-driven global settings (snake_case). Never raises.
        """
        try:
            g = get_backend_global_settings() or {}
            return g if isinstance(g, dict) else {}
        except Exception:
            return {}

    def _default_authorize_door_id(self) -> int:
        g = self._global_defaults()
        v = _to_int(g.get("default_authorize_door_id"), default=DEFAULT_AUTHORIZE_DOOR_ID_FALLBACK)
        if v is None or int(v) < 1:
            return int(DEFAULT_AUTHORIZE_DOOR_ID_FALLBACK)
        return int(v)

    def _resolve_push_policy(self, device: Dict[str, Any]) -> str:
        """
        Map device.pushingToDevicePolicy (backend enum string) to one of the three
        canonical push-policy constants.  Defaults to INCREMENTAL.

        Backend enum → policy mapping:
          DELETE_ALL_BEFORE_PUSHING                             → FULL_REPLACE
          DELETE_ALL_KNOWING_PINS_BUT_NO_LONGER_DESIRED_*      → INCREMENTAL (default)
          DELETE_ALL_NOT_DESIRED_PINS_BEFORE_PUSHING           → INCREMENTAL
          PUSH_WITHOUT_DELETING                                → ADDITIVE_ONLY
          DELETE_ALL_NOT_KNOWING_PINS_AND_DONT_PUSH            → FULL_REPLACE (clear, no push — treated as reset)
        """
        raw = str(device.get("pushingToDevicePolicy") or "").strip().upper()
        if not raw:
            return _PUSH_POLICY_INCREMENTAL
        # Explicit FULL_REPLACE triggers
        if raw in ("DELETE_ALL_BEFORE_PUSHING", "FULL_REPLACE",
                   "DELETE_ALL_NOT_KNOWING_PINS_AND_DONT_PUSH"):
            return _PUSH_POLICY_FULL_REPLACE
        # Explicit ADDITIVE_ONLY triggers
        if raw in ("PUSH_WITHOUT_DELETING", "ADDITIVE_ONLY"):
            return _PUSH_POLICY_ADDITIVE_ONLY
        # Everything else: INCREMENTAL (safe default)
        return _PUSH_POLICY_INCREMENTAL

    def _resolve_push_context(
        self,
        *,
        device: Dict[str, Any],
        default_door_id: int,
    ) -> Tuple[List[int], int, int, bool]:
        authorize_timezone_id = _to_int(device.get("authorizeTimezoneId"), default=1) or 1
        if authorize_timezone_id < 1:
            authorize_timezone_id = 1

        raw_fingerprint_enabled = device.get("fingerprintEnabled")
        if raw_fingerprint_enabled is None:
            raw_fingerprint_enabled = device.get("fingerprint_enabled")
        fingerprint_enabled = _boolish(raw_fingerprint_enabled, default=False)

        # Resolve AuthorizeDoorId bitmask for userauthorize.
        # AuthorizeDoorId is a bitmask: door1=1, door2=2, door3=4, door4=8.
        #
        # Priority: use doorIds from the backend (already bitmask values set in
        # the dashboard, e.g. [1, 2, 4, 8]). OR them to get combined bitmask.
        # Fallback: compute bitmask from doorPresets physical door numbers.
        door_ids_raw = device.get("doorIds") or []
        door_ids_list = _norm_int_list(door_ids_raw)

        if door_ids_list:
            door_bitmask = 0
            for v in door_ids_list:
                door_bitmask |= int(v)
            door_ids = door_ids_list
        else:
            presets = device.get("doorPresets") or []
            physical_doors = sorted(set(
                int(p.get("doorNumber") or p.get("door_number") or 0)
                for p in presets if isinstance(p, dict)
                and (p.get("doorNumber") or p.get("door_number"))
            ))
            physical_doors = [d for d in physical_doors if d > 0]

            if physical_doors:
                door_bitmask = 0
                for d in physical_doors:
                    door_bitmask |= 1 << (int(d) - 1)
                door_ids = physical_doors
            else:
                door_bitmask = int(default_door_id)
                door_ids = [int(default_door_id)]

        return door_ids, door_bitmask, authorize_timezone_id, fingerprint_enabled

    def _sdk_read_initial_bytes(self) -> int:
        """
        Backend-driven knob used when reading device data (PullSDK initial_size).
        Falls back to 1 MiB.
        """
        g = self._global_defaults()
        v = _to_int(g.get("sdk_read_initial_bytes"), default=1_048_576) or 1_048_576
        # clamp: [64KiB, 16MiB]
        if v < 64 * 1024:
            v = 64 * 1024
        if v > 16 * 1024 * 1024:
            v = 16 * 1024 * 1024
        return int(v)

    def _resolve_connect_timeout_ms(self, device: Dict[str, Any]) -> int:
        timeout_ms = _to_int(
            (
                device.get("timeoutMs")
                or device.get("timeout_ms")
                or device.get("timeout")
                or device.get("connectTimeoutMs")
                or device.get("connect_timeout_ms")
            ),
            default=None,
        )
        if timeout_ms is None or int(timeout_ms) <= 0:
            timeout_ms = _to_int(getattr(self.cfg, "timeout_ms", None), default=None)
        if timeout_ms is None or int(timeout_ms) <= 0:
            timeout_ms = 3000
        # Keep connect waits bounded when a device is offline so one bad controller
        # does not stall the whole local runtime for long stretches.
        return max(500, min(int(timeout_ms), 15000))

    def _normalize_device(self, d: Dict[str, Any]) -> Dict[str, Any]:
        def g(*keys, default=None):
            for k in keys:
                if isinstance(d, dict) and k in d:
                    return d.get(k)
            return default

        allowed = g("allowedMemberships", "allowed_memberships", default=None)
        doors = g("doorIds", "door_ids", default=None)

        # accessDataMode: per-device mode (DEVICE or AGENT)
        adm_raw = g("accessDataMode", "access_data_mode", default="DEVICE")
        adm = str(adm_raw or "").strip().upper()
        if adm not in ("DEVICE", "AGENT", "ULTRA"):
            adm = "DEVICE"

        # per-device timezone/policy (used for userauthorize)
        tz_id = _to_int(g("authorizeTimezoneId", "authorize_timezone_id", default=1), default=1) or 1
        if tz_id < 1:
            tz_id = 1

        pushing_policy = g("pushingToDevicePolicy", "pushing_to_device_policy", default=None)

        return {
            "id": g("id"),
            "name": g("name", default=""),
            "active": _boolish(g("active", default=True), default=True),
            "accessDevice": _boolish(g("accessDevice", "access_device", default=True), default=True),
            "accessDataMode": adm,
            "ipAddress": g("ipAddress", "ip_address", default=""),
            "portNumber": g("portNumber", "port_number", default=4370),
            "password": g("password", default=""),
            # PROTOCOL ROUTING: this normalized dict is the ONLY thing every
            # _sync_one_device caller receives. Dropping deviceProtocol here made
            # resolve_device_protocol() answer ZK_PULLSDK/"default" for an MB2000,
            # so a protocol guard placed downstream could never fire. Inert for
            # PullSDK gyms: absent or "ZK_PULLSDK" resolves exactly as before.
            "deviceProtocol": g("deviceProtocol", "device_protocol", default=None),
            "model": g("model", default=""),
            "allowedMemberships": _as_list(allowed),
            "doorIds": _as_list(doors),
            "timeoutMs": _to_int(
                g("timeoutMs", "timeout_ms", "timeout", "connectTimeoutMs", "connect_timeout_ms", default=None),
                default=None,
            ),

            # NEW (from backend/device DTO)
            "authorizeTimezoneId": int(tz_id),
            "pushingToDevicePolicy": pushing_policy,
            # PIN SCHEME: this normalized dict is what _sync_one_device, the targeted
            # member sync and build_device_sync_fingerprint hand to
            # _filter_users_for_device. Dropping the key here would silently derive
            # MEMBERSHIP pins for a device the backend switched to ACCOUNT.
            "pinScheme": g("pinScheme", "pin_scheme", default=None),
            "doorPresets": list(g("doorPresets", "door_presets", default=None) or []),
            "fingerprintEnabled": _boolish(g("fingerprintEnabled", "fingerprint_enabled", default=False), False),
            # Per-device fingerprint template-version override (9 or 10) parsed
            # from the opaque deviceCapabilities JSON; None when absent/malformed.
            # Consumed by _push_templates to bias which template table is tried
            # FIRST — the probe fallback still tries both tables.
            "fingerprintTemplateVersion": parse_fingerprint_template_version(
                g("deviceCapabilities", "device_capabilities")
            ),

            # Anti-fraud settings (per-device)
            "anti_fraude_card":             _boolish(g("anti_fraude_card",             "antiFraudeCard",             default=True), True),
            "anti_fraude_qr_code":          _boolish(g("anti_fraude_qr_code",          "antiFraudeQrCode",           default=True), True),
            "anti_fraude_duration":         _to_int(g("anti_fraude_duration",          "antiFraudeDuration",         default=30), default=30) or 30,
            "anti_fraude_daily_pass_limit": _to_int(g("anti_fraude_daily_pass_limit",  "antiFraudeDailyPassLimit",   default=0),  default=0)  or 0,
            # Frequent-pass VISUAL alert (never blocks; independent of the daily cap).
            "frequent_pass_limit":          _to_int(g("frequent_pass_limit",          "frequentPassLimit",          default=0),  default=0)  or 0,
            "frequent_pass_window_minutes": _to_int(g("frequent_pass_window_minutes", "frequentPassWindowMinutes",  default=0),  default=0)  or 0,
        }

    @_tel.timed("SYNC_FILTER_USERS", slow_ms=100)
    def _filter_users_for_device(
        self,
        *,
        users: List[Dict[str, Any]],
        device: Dict[str, Any],
        default_door_id: int,
        stats_out: Dict[str, Any] | None = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Returns dict(pin -> user).

        Filters:
        - allowedMemberships (if provided) uses user.membershipId
        - validFrom/validTo ONLY when pushingToDevicePolicy == "VALID_ONLY"
          (default: push ALL members with an activeMembershipId regardless of
          expiry — the PC/ULTRA engine handles real-time validity at scan time)
        - pin must be digits (controllers expect numeric Pin)

        PIN: ``derive_member_pin`` under the DEVICE's ``pinScheme`` (``device_pin_scheme``).
        MEMBERSHIP is byte-identical to the derivation before account pins existed (last row
        wins a pin, a userId-fallback row never displaces a membership row). ACCOUNT keys by
        ``mainAccountId`` only, collapses one person's memberships with
        ``_merge_same_pin_entries``, and WITHHOLDS a deliverable row that has no
        mainAccountId (counted in ``stats_out["withheld_missing_account"]``).

        ``stats_out`` (optional) receives ``pin_scheme``, ``pin_sources`` (pin -> which field
        produced it) and ``withheld_missing_account`` / ``withheld_sample``. A caller that
        REMOVES pins not in this result must treat ``withheld_missing_account > 0`` as an
        incomplete roster -- the withheld person's account pin cannot be named, so it cannot
        be kept.

        Also ensures device has a usable doorIds list (fallback to default_door_id).
        """
        allowed_raw = device.get("allowedMemberships") or []
        allowed_set: Set[int] = set()
        for x in allowed_raw:
            xi = _to_int(x, default=None)
            if xi is not None:
                allowed_set.add(int(xi))

        door_ids = _norm_int_list(device.get("doorIds") or [])
        if not door_ids:
            door_ids = [int(default_door_id)]
        device["doorIds"] = door_ids  # keep for downstream use

        # Validity-date filter: ONLY apply when explicitly opted in via
        # pushingToDevicePolicy="VALID_ONLY".  The default (null / any other
        # value) pushes every member so the full roster is on the device and
        # the PC-side logic decides access at scan time.
        policy = str(device.get("pushingToDevicePolicy") or "").strip().upper()
        filter_by_validity = (policy == "VALID_ONLY")

        scheme = device_pin_scheme(device)
        now = datetime.now(tz=timezone.utc)
        out: Dict[str, Dict[str, Any]] = {}
        sources: Dict[str, str] = {}
        withheld = 0
        offline_projections = 0
        withheld_sample: List[Dict[str, Any]] = []
        cards_by_pin: Dict[str, Dict[str, Any]] = {}
        dropped_cards = 0
        dropped_sample: List[Dict[str, Any]] = []

        def _deliverable(u: Dict[str, Any]) -> bool:
            mid = _to_int(u.get("membershipId"), default=None)
            if allowed_set and (mid is None or int(mid) not in allowed_set):
                return False
            if filter_by_validity:
                vf = _parse_dt_any(u.get("validFrom") or "")
                vt = _parse_dt_any(u.get("validTo") or "")
                if vf and now < vf:
                    return False
                if vt and now > vt:
                    return False
            return True

        if scheme != PIN_SCHEME_ACCOUNT:
            for u in users or []:
                if not isinstance(u, dict):
                    continue

                # MEMBERSHIP: activeMembershipId, else userId for a member with no
                # membership record (activeMembershipId=null). mainAccountId is IGNORED
                # here, even when present -- that is what keeps a terminal that holds
                # membership pins from ever receiving an account pin.
                pin, source = derive_member_pin(u, PIN_SCHEME_MEMBERSHIP)
                if not pin:
                    continue
                if not pin.isdigit():
                    continue

                # Collision guard: a userId-fallback pin must not overwrite an
                # activeMembershipId-based entry already placed in the output.
                if pin in out and source != PIN_SOURCE_MEMBERSHIP:
                    continue

                if not _deliverable(u):
                    continue

                out[pin] = u
                sources[pin] = str(source)
        else:
            for u in users or []:
                if not isinstance(u, dict):
                    continue

                # Deliverability first, so "withheld" counts only people this device
                # would actually have carried.
                if not _deliverable(u):
                    continue

                pin, _source = derive_member_pin(u, PIN_SCHEME_ACCOUNT)
                if not pin or not pin.isdigit():
                    # NEVER fall back to activeMembershipId/userId here: on an ACCOUNT
                    # terminal that number may be another person's account pin.
                    if u.get("offlinePending"):
                        # A projection of a queued offline creation (db.list_projected_offline_users),
                        # not a sync_users row: no roster refresh can ever give it a
                        # mainAccountId, and under MEMBERSHIP its negative synthetic id is never
                        # pushed either. Not emitted, and NOT counted as withheld -- counting it
                        # froze every removal on the device for as long as the item stayed
                        # queued (review #12, guide §3.2b).
                        offline_projections += 1
                        continue
                    withheld += 1
                    if len(withheld_sample) < 10:
                        withheld_sample.append({
                            "userId": u.get("userId"),
                            "activeMembershipId": u.get("activeMembershipId"),
                        })
                    continue

                # Every push writes ONE card per device user (PullSDK CardNo / the standalone
                # entry's "card", both from firstCardId), so a collapsed row carries one card.
                # Remember each membership's card to report the ones that no longer reach the
                # terminal (review #5).
                card = _pin_str(u.get("firstCardId"))
                if card:
                    cards_by_pin.setdefault(pin, {}).setdefault(card, u.get("activeMembershipId"))

                prior = out.get(pin)
                if prior is None:
                    out[pin] = u
                    sources[pin] = PIN_SOURCE_ACCOUNT
                    continue

                # Two memberships, one person, one device row.
                #
                # The device row carries ONE validity window, so we keep the membership
                # that reaches furthest -- among those this device accepts and that
                # survived the filters above, which is exactly the set still standing at
                # this point. Keeping the shorter one would lock a paid-up member out;
                # `out[pin] = u` (last-wins) would make it depend on payload order, which
                # is worse than either.
                #
                # CRITICAL: the credentials are UNIONED, not taken from the winner.
                # _collect_templates_for_pin states that "user['fingerprints'] is the whole
                # answer", so keeping only the winner's entry would silently drop every
                # finger enrolled under the losing membership -- a member whose finger was
                # scanned on his spa plan would lose it the moment his longer gym plan won
                # the row.
                out[pin] = _merge_same_pin_entries(prior, u)

            for pin, cards in cards_by_pin.items():
                if len(cards) < 2 or pin not in out:
                    continue
                pushed_card = _pin_str(out[pin].get("firstCardId"))
                lost = {c: am for c, am in cards.items() if c != pushed_card}
                if not lost:
                    continue
                dropped_cards += len(lost)
                if len(dropped_sample) < 10:
                    dropped_sample.append({"pin": pin, "droppedFromMemberships": sorted(
                        {str(am) for am in lost.values()})})
            if dropped_cards:
                (self.logger or logging.getLogger("zkapp")).warning(
                    "[DeviceSync] device id=%s pinScheme=ACCOUNT: %d card(s) do not reach the "
                    "terminal -- a device user holds ONE card (firstCardId) and a person's "
                    "memberships carry different ones; the furthest-reaching membership's card is "
                    "pushed (sample=%s). Those cards are refused at the terminal.",
                    device.get("id"), dropped_cards, dropped_sample,
                )

            if withheld:
                log = self.logger or logging.getLogger("zkapp")
                log.warning(
                    "[DeviceSync] device id=%s pinScheme=ACCOUNT: WITHHELD %d deliverable "
                    "member row(s) that carry no mainAccountId (sample=%s). They are NOT "
                    "pushed under a membership pin (that would mix schemes on one terminal), "
                    "and callers that remove pins must treat this roster as INCOMPLETE. "
                    "A full member refresh fills the column.",
                    device.get("id"), withheld, withheld_sample,
                )
                try:
                    _tel.warn("PIN_SCHEME_ACCOUNT_WITHHELD", device_id=device.get("id"),
                              withheld=withheld)
                except Exception:
                    pass

        if stats_out is not None:
            stats_out["pin_scheme"] = scheme
            stats_out["pin_sources"] = sources
            stats_out["withheld_missing_account"] = withheld
            stats_out["withheld_sample"] = withheld_sample
            stats_out["skipped_offline_projections"] = offline_projections
            stats_out["dropped_cards"] = dropped_cards

        return out

    def _collect_templates_for_pin(
        self,
        *,
        user: Dict[str, Any],
        pin: str,
        local_fp_index: Dict[str, List[Any]],
        fingerprint_enabled: bool = True,
    ) -> List[Dict[str, Any]]:
        """The sync cache is the SOLE authority for a member's templates.

        ``user['fingerprints']`` is the whole answer. What it does not list --
        because the gym deleted the finger, because the backend sent
        ``enabled: false``, or because the member never enrolled -- must NOT reach
        the device. An empty result is a real answer ("this member has no
        templates"), never a cue to look elsewhere.

        SECURITY (F12): this used to read the local SQLite ``fingerprints`` table
        whenever the collected list came out empty, so a revoked or DISABLED finger
        re-pushed its stale local copy and restored access the gym believed it had
        removed. The emptiness produced by the ``enabled is False`` filter below was
        itself the trigger.

        Nothing justified the fallback: ``db.insert_fingerprint`` has no caller,
        local enrol is refused (``local_access_api_v2._handle_enroll_start``),
        dashboard enrol POSTs to the backend and returns through the roster, and
        offline enrolment defers into ``offline_creation_queue`` -- a different
        table. Rows can only exist on a PC upgraded from a pre-split install
        (``shared/storage_migration`` ACCESS_OWNED_TABLES), and are enumerable
        out-of-band via ``db.list_unconfirmed_fingerprints()`` / ``GET /fingerprints``.

        ``local_fp_index`` stays in the signature -- callers and tests bind it by
        keyword -- but is deliberately NOT read.
        [TEST: tests/test_device_sync_template_authority.py]

        Shared with the standalone path (``ultra_engine._build_standalone_roster``),
        so this covers both device families.

        Output items:
          { fingerId:int, templateVersion:int, templateData:str, templateSize:int }
        """
        if not fingerprint_enabled:
            return []

        out: List[Dict[str, Any]] = []

        fps = user.get("fingerprints")
        if isinstance(fps, list):
            for fp in fps:
                if not isinstance(fp, dict):
                    continue
                # `is False` matched ONLY the bool singleton, so enabled=0,
                # "false", "0" and "off" all sailed through as ENABLED. Java
                # serialises a real bool today, so this is defence in depth --
                # but the client is the ONLY enforcement point: no backend path
                # filters disabled templates out of the outgoing payload.
                # default=True is deliberate: most payloads omit the key, and an
                # absent flag means enabled.
                if not _boolish(fp.get("enabled"), default=True):
                    continue
                fid = _to_int(fp.get("fingerId"), default=None)
                if fid is None:
                    continue
                tv = _to_int(fp.get("templateVersion"), default=10) or 10
                td = _safe_template_text(fp.get("templateData") or "")
                if not td:
                    continue
                try:
                    td, td_bytes = _template_wire(td, fp.get("templateEncoding"))
                except Exception as ex:
                    # Dropped, not pushed: occupying the slot with something the
                    # terminal can never match is worse than having no template.
                    # Never log template bytes -- only the failure reason.
                    self.logger.warning(
                        "[DeviceSync] Pin=%s FingerID=%s template DROPPED: "
                        "templateEncoding=HEX but templateData is not decodable hex (%s)",
                        pin, fid, ex,
                    )
                    continue
                ts = _to_int(fp.get("templateSize"), default=None)
                if ts is None:
                    # len(td) would be the ENCODED length -- ~1.33x for base64 and
                    # 2x for hex. The device's Size field wants the byte count.
                    # td_bytes is already the decoded count on the HEX path; the
                    # base64 path decodes lazily, only when we get here.
                    ts = td_bytes if td_bytes is not None else _decoded_template_len(td)

                out.append(
                    {
                        "fingerId": int(fid),
                        "templateVersion": int(tv),
                        "templateData": td,
                        "templateSize": int(ts),
                    }
                )

        # No `if out:` guard: an empty list is the ANSWER, not a fallback cue.
        # Deleting the local-SQLite fallback here is the whole of F12.
        best: Dict[int, Dict[str, Any]] = {}
        for x in out:
            best[int(x["fingerId"])] = x
        return [best[k] for k in sorted(best.keys())]

    def _push_userauthorize(
        self,
        sdk: PullSDK,
        *,
        pin: str,
        door_bitmask: int,
        authorize_timezone_id: int,
        device_id: int,
    ) -> Tuple[int, str | None]:
        """Push a single userauthorize record with a pre-computed bitmask.

        Tries the cached firmware pattern first (1 SDK call). Falls back to the
        full retry loop on cache miss or if the cached pattern stopped working
        (e.g., after a firmware upgrade). Caches the winning pattern on success.

        door_bitmask is the OR of individual door bits (1=door1, 2=door2, 4=door3, 8=door4).
        For all 4 doors on a C3-400: bitmask = 1|2|4|8 = 15.
        """
        if door_bitmask <= 0:
            door_bitmask = self._default_authorize_door_id()

        tz = int(authorize_timezone_id or 1)
        if tz < 1:
            tz = 1

        # Pattern list — order matters: preferred (AuthorizeDoorId) first, legacy fallbacks after.
        patterns = [
            f"Pin={pin}\tAuthorizeTimezoneId={tz}\tAuthorizeDoorId={door_bitmask}\r\n",
            f"Pin={pin}\tAuthorizeDoorId={door_bitmask}\tAuthorizeTimezoneId={tz}\r\n",
            f"Pin={pin}\tDoorID={door_bitmask}\tTimeZoneID={tz}\r\n",
            f"Pin={pin}\tDoorID={door_bitmask}\tTimeZone={tz}\r\n",
        ]

        profile = self._get_firmware_profile(device_id)

        # L1: try cached pattern first (1 SDK call)
        if profile.authorize_body_index is not None:
            cached_data = patterns[profile.authorize_body_index]
            try:
                sdk.set_device_data(table="userauthorize", data=cached_data, options="")
                self.logger.debug("[DeviceSync] Pin=%s userauthorize OK (cached pattern=%d)",
                                  pin, profile.authorize_body_index)
                return 1, None
            except Exception as ex:
                if _is_structural_sdk_error(ex):
                    # Firmware rejected the payload shape (upgraded?). Clear and probe.
                    self.logger.warning(
                        "[DeviceSync] Pin=%s userauthorize cached pattern=%d REJECTED "
                        "(structural: %s), clearing cache for device_id=%d",
                        pin, profile.authorize_body_index, ex, device_id,
                    )
                    profile.authorize_body_index = None
                    from app.core.db import clear_firmware_profile
                    clear_firmware_profile(device_id=device_id)
                else:
                    # Transient: keep the learned pattern, fall through and retry.
                    self.logger.warning(
                        "[DeviceSync] Pin=%s userauthorize cached pattern=%d failed "
                        "non-structurally (transient?: %s), KEEPING cache for device_id=%d",
                        pin, profile.authorize_body_index, ex, device_id,
                    )

        # L2: retry loop — discover working pattern and cache it
        last_err = None
        for i, data in enumerate(patterns):
            try:
                sdk.set_device_data(table="userauthorize", data=data, options="")
                self.logger.debug("[DeviceSync] Pin=%s userauthorize OK (pattern=%d)", pin, i)
                # Cache discovery
                profile.authorize_body_index = i
                from app.core.db import save_firmware_profile
                save_firmware_profile(
                    device_id=device_id,
                    template_table=profile.template_table or "templatev10",
                    template_body_index=profile.template_body_index if profile.template_body_index is not None else 0,
                    authorize_body_index=i,
                )
                return 1, None
            except Exception as ex:
                last_err = str(ex)

        self.logger.error(
            "[DeviceSync] Pin=%s userauthorize FAILED all patterns: bitmask=%d err=%s",
            pin, door_bitmask, last_err,
        )
        return 0, last_err or "userauthorize: no compatible field pattern worked"

    def _push_templates(
        self,
        sdk: PullSDK,
        *,
        pin: str,
        templates: List[Dict[str, Any]],
        device_id: int,
        template_version_override: int | None = None,
        pin_source: str | None = None,
    ) -> Tuple[int, List[str]]:
        """Push fingerprint templates to device.

        ``pin_source`` (device_sync.PIN_SOURCE_*) is which field produced ``pin``. It is
        recorded with every finger's outcome so the upstream report names the right id:
        the digits alone cannot say (guide §3.2b).

        Tries the cached (table, body_index) combo first for each template (1 SDK call).
        Falls back to the full retry loop on cache miss or if the cached combo fails.
        Caches the winning combo on first successful discovery for the session.

        ``template_version_override`` (9 or 10, from the device's deviceCapabilities
        fingerprintTemplateVersion) wins over the per-record templateVersion for the
        PREFERRED table order ONLY — the cached-combo fast path and the probe loop
        (which still tries both tables) are unchanged.
        """
        failed_fp_errs: List[str] = []
        ok = 0

        def try_set(table: str, body: str) -> "Tuple[bool, bool]":
            """Attempt the SDK call.

            Returns (success, is_structural_failure). The second element is only
            meaningful when success is False: it says whether the firmware REJECTED
            the payload shape (so a cached combo is genuinely wrong) or whether the
            call failed for some other reason (so the cache is probably still good).
            """
            try:
                sdk.set_device_data(table=table, data=body + "\r\n", options="")
                return True, False
            except Exception as ex:
                return False, _is_structural_sdk_error(ex)

        profile = self._get_firmware_profile(device_id)

        # The cached (table, body_index) combo was learned under ONE bias, and that
        # cached table is precisely what made a changed
        # deviceCapabilities.fingerprintTemplateVersion inert: L1 below reuses it
        # without ever consulting the override. So drop the combo ONCE when the bias
        # moves, and let the probe re-learn under the new preference.
        #
        # This cannot re-probe every sync: the reset persists the new bias, and the
        # winning combo is saved with it, so the next call compares equal. A device
        # with no override has bias 0 on both sides and is untouched.
        bias = int(template_version_override) if template_version_override in (9, 10) else 0
        if int(profile.template_version_bias or 0) != bias:
            if profile.template_table is not None or profile.template_body_index is not None:
                self.logger.info(
                    "[DeviceSync] device_id=%d template-version bias %s -> %s: dropping "
                    "cached template combo (%s, idx=%s) for one re-probe",
                    device_id, profile.template_version_bias, bias,
                    profile.template_table, profile.template_body_index,
                )
            profile.template_table = None
            profile.template_body_index = None
            profile.template_version_bias = bias
            from app.core.db import reset_firmware_template_combo
            reset_firmware_template_combo(device_id=device_id, template_version_bias=bias)

        for t in templates:
            # A malformed record must not abort the OTHER templates for this pin.
            # These two were bare int() calls: a None fingerId raises TypeError and
            # a truthy non-numeric templateVersion raises ValueError (`or 10` does
            # NOT guard that -- a non-empty string is truthy). Either one escaped
            # _push_templates entirely, so every VALID template later in the list
            # was never attempted. Matches the guard ultra_engine and
            # _compute_desired_hash already had for the same fields.
            try:
                fid = int(t.get("fingerId"))
            except (TypeError, ValueError):
                # Reported, not silently dropped: fingerId is the slot to write, so
                # there is nothing sane to default to. Goes through the SAME errs
                # list as a real push failure, which is what lets the caller count
                # it as a failed sync instead of stamping the pin SUCCESS.
                # Never log template bytes -- only the malformed id itself.
                failed_fp_errs.append(
                    f"FingerID={t.get('fingerId')!r}: invalid fingerId - skipped"
                )
                continue
            try:
                tv = int(t.get("templateVersion") or 10)
            except (TypeError, ValueError):
                # NOT fatal: tv only biases which table is probed FIRST, and the
                # retry loop tries both tables anyway. Dropping the fingerprint
                # over it would be an over-reaction. Same fallback as ultra_engine.
                tv = 10
            if template_version_override in (9, 10):
                tv = int(template_version_override)
            size = int(t.get("templateSize") or 0)
            tpl = _safe_template_text(str(t.get("templateData") or ""))

            if not tpl:
                continue

            preferred_tables = ["templatev10", "template"] if tv >= 10 else ["template", "templatev10"]

            bodies = [
                lambda fid=fid, size=size, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTemplate={tpl}",
                lambda fid=fid, size=size, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tValid=1\tSize={size}\tTmp={tpl}",
                lambda fid=fid, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tValid=1\tTemplate={tpl}",
                lambda fid=fid, size=size, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tSize={size}\tTemplate={tpl}",
                lambda fid=fid, tpl=tpl: f"Pin={pin}\tFingerID={fid}\tTemplate={tpl}",
            ]

            pushed = False

            # L1: try cached combo (1 SDK call)
            if profile.template_table is not None and profile.template_body_index is not None:
                cached_body = bodies[profile.template_body_index]()
                _set_ok, _structural = try_set(profile.template_table, cached_body)
                if _set_ok:
                    ok += 1
                    pushed = True
                elif _structural:
                    # The firmware REJECTED this payload shape, so the cached combo is
                    # genuinely wrong. Clear it and fall through to the probe.
                    self.logger.warning(
                        "[DeviceSync] Pin=%s FingerID=%d cached template combo (%s, idx=%d) "
                        "REJECTED (structural) — clearing firmware cache for device_id=%d",
                        pin, fid, profile.template_table, profile.template_body_index, device_id,
                    )
                    profile.template_table = None
                    profile.template_body_index = None
                    from app.core.db import clear_firmware_profile
                    clear_firmware_profile(device_id=device_id)
                else:
                    # Transient (network/timeout/auth). KEEP the cache: it was learned
                    # over ten probe calls and the device was answering a moment ago.
                    # The probe below still runs, so this costs nothing but a retry.
                    self.logger.warning(
                        "[DeviceSync] Pin=%s FingerID=%d cached template combo (%s, idx=%d) "
                        "failed non-structurally (transient?) — KEEPING firmware cache "
                        "for device_id=%d",
                        pin, fid, profile.template_table, profile.template_body_index, device_id,
                    )

            # L2: retry loop (runs on cache miss or after cache clear)
            if not pushed:
                for table in preferred_tables:
                    for i, bfn in enumerate(bodies):
                        if try_set(table, bfn())[0]:
                            pushed = True
                            ok += 1
                            # Cache winning combo
                            profile.template_table = table
                            profile.template_body_index = i
                            from app.core.db import save_firmware_profile
                            save_firmware_profile(
                                device_id=device_id,
                                template_table=table,
                                template_body_index=i,
                                authorize_body_index=profile.authorize_body_index
                                    if profile.authorize_body_index is not None else 0,
                                # Record WHICH bias this combo was learned under, so
                                # the check above compares equal next time.
                                template_version_bias=bias,
                            )
                            break
                    if pushed:
                        break

            if not pushed:
                failed_fp_errs.append(f"FingerID={fid}: failed to push template (no compatible schema/table)")

            # F11: one hook covers both success paths (L1 cached combo and the L2
            # probe) and the failure path. This is what finally puts a value into the
            # dashboard's lastPushError, which has been rendered but never written.
            self._record_finger_push_status(
                pin=pin, finger_id=fid, device_id=device_id, pin_source=pin_source,
                status="OK" if pushed else "FAILED",
                error_message=None if pushed
                else "failed to push template (no compatible schema/table)",
            )

        return ok, failed_fp_errs

    def _record_finger_push_status(
        self, *, pin: str, finger_id: int, device_id: int,
        status: str, error_message: "str | None",
        pin_source: "str | None" = None,
    ) -> None:
        """Remember whether ONE finger reached ONE device.

        device_sync_state is per-PIN, but the dashboard's lastPushError is per-FINGER,
        so the outcome has to be recorded at this granularity -- and `fid` is only in
        scope here, inside the push loop.

        NEVER raises. This is instrumentation on the live worker path: a bookkeeping
        failure must not turn a successful push into a failed one. It goes through the
        same DbWriter queue save_device_sync_state already uses in this loop, so it
        adds no new blocking mechanism.
        """
        try:
            if int(device_id or 0) <= 0:
                return
            upsert_fingerprint_push_status(
                pin=pin, finger_id=int(finger_id), device_id=int(device_id),
                status=status, error_message=error_message, pin_source=pin_source,
            )
        except Exception:
            self.logger.debug(
                "[DeviceSync] could not record push status pin=%s finger=%s", pin, finger_id,
                exc_info=True,
            )

    def _bulk_delete_pins(
        self,
        *,
        sdk: PullSDK,
        pins: list,
        device_id: int,
        fingerprint_enabled: bool = True,
    ) -> tuple:
        """
        Delete a list of pins across all relevant ZKTeco tables in bulk.

        Strategy cascade per device (cached in FirmwareProfile.delete_strategy):
          - None/"bulk" → try delete_device_data_batch (chunk_size=100) per table.
            On ANY table failing even after per-pin fallback, downgrade cache to
            "one_by_one" for NEXT sync but still attempt per-pin cleanup NOW.
          - "one_by_one" → directly issue per-pin DeleteDeviceData calls.

        Template tables are skipped when fingerprint_enabled=False (C3 panels).

        Returns (ok_count, failed_pins) — same shape as sdk.delete_device_data_batch.
        failed_pins is the union of pins that couldn't be deleted from ANY table
        after all fallbacks (used by caller to leave sync-state marker intact).
        """
        if not pins:
            return (0, [])

        if not sdk.supports_delete_device_data():
            self.logger.warning("[DeviceSync] DeleteDeviceData not available — cannot bulk delete")
            return (0, list(pins))

        profile = self._get_firmware_profile(device_id)
        strategy = profile.delete_strategy or _DELETE_BULK

        tables: list = []
        for t in _STALE_DELETE_TABLES:
            if t in ("templatev10", "template") and not fingerprint_enabled:
                continue
            tables.append(t)

        pins_list = [str(p) for p in pins]
        all_failed: Set[str] = set()

        if strategy == _DELETE_BULK:
            bulk_downgrade = False
            for table in tables:
                try:
                    ok, failed = sdk.delete_device_data_batch(
                        table=table, pins=pins_list, chunk_size=100,
                    )
                    if failed:
                        # per-pin fallback was already tried inside delete_device_data_batch
                        # and still failed for some pins. Only mark "user" table failures
                        # as truly failed (auxiliary tables may simply have no matching row).
                        if table == "user":
                            all_failed.update(str(p) for p in failed)
                        # If bulk chunk failed but per-pin worked, ok < len(pins_list) is fine.
                        # If bulk AND per-pin both failed on this table → downgrade cache.
                        if ok == 0:
                            bulk_downgrade = True
                except Exception as ex:
                    self.logger.warning(
                        "[DeviceSync] bulk delete failed for table=%s device_id=%s: %s",
                        table, device_id, ex,
                    )
                    bulk_downgrade = True
                    # Fall back to per-pin delete right now for this table
                    for pin in pins_list:
                        try:
                            sdk.delete_device_data(table=table, data=f"Pin={pin}", options="")
                        except Exception:
                            if table == "user":
                                all_failed.add(str(pin))

            if bulk_downgrade and profile.delete_strategy != _DELETE_ONE_BY_ONE:
                profile.delete_strategy = _DELETE_ONE_BY_ONE
                self._save_firmware_profile(profile, device_id)
                self.logger.info(
                    "[DeviceSync] Device id=%s: delete_strategy downgraded to one_by_one",
                    device_id,
                )
            elif profile.delete_strategy is None and not bulk_downgrade:
                profile.delete_strategy = _DELETE_BULK
                self._save_firmware_profile(profile, device_id)
        else:
            # one_by_one path
            for pin in pins_list:
                deleted_user = False
                for table in tables:
                    try:
                        sdk.delete_device_data(table=table, data=f"Pin={pin}", options="")
                        if table == "user":
                            deleted_user = True
                    except Exception as ex:
                        self.logger.debug(
                            "[DeviceSync] per-pin delete table=%s Pin=%s ignored: %s",
                            table, pin, ex,
                        )
                if not deleted_user:
                    all_failed.add(str(pin))

        total_ok = len(pins_list) - len(all_failed)
        return (total_ok, sorted(all_failed))

    def _delete_pin_if_exists(
        self,
        *,
        sdk: PullSDK,
        pin: str,
        device_pins: Set[str],
        fingerprint_enabled: bool = True,
    ) -> bool:
        if pin not in device_pins:
            return False

        if not sdk.supports_delete_device_data():
            self.logger.warning(f"[DeviceSync] DeleteDeviceData not available. Cannot delete Pin={pin}")
            return False

        cond = f"Pin={pin}"

        # P1: skip fingerprint tables on devices without biometric storage (e.g. C3-400 panels).
        # Without this gate every delete would issue 2 calls that always return rc=-100
        # ("table structure missing"), which accounted for ~40% of the delete waste in logs.
        if fingerprint_enabled:
            try:
                sdk.delete_device_data(table="templatev10", data=cond, options="")
            except Exception as ex:
                self.logger.debug(f"[DeviceSync] Delete templatev10 Pin={pin} ignored: {ex}")

            try:
                sdk.delete_device_data(table="template", data=cond, options="")
            except Exception as ex:
                self.logger.debug(f"[DeviceSync] Delete template Pin={pin} ignored: {ex}")

        try:
            sdk.delete_device_data(table="userauthorize", data=cond, options="")
        except Exception as ex:
            self.logger.debug(f"[DeviceSync] Delete userauthorize Pin={pin} ignored: {ex}")

        try:
            sdk.delete_device_data(table="user", data=cond, options="")
        except Exception as ex:
            self.logger.warning(f"[DeviceSync] Delete user Pin={pin} ignored: {ex}")
            return False
        return True

    def _delete_pin_unconditional(
        self,
        *,
        sdk: PullSDK,
        pin: str,
        fingerprint_enabled: bool = True,
    ) -> bool:
        """
        Delete a pin from ALL tables WITHOUT consulting device_pins first.
        ZKTeco DeleteDeviceData is idempotent — deleting a non-existent record
        returns success (or a benign error) on all known firmware versions.

        Use this for pins_to_sync pre-delete (ensures clean insert even when
        device_pins is stale or the read step returned an empty set).
        Do NOT use for the stale-pins pass — use _delete_pin_if_exists there so
        that we confirm the pin is on the device before issuing SDK calls.
        """
        cond = f"Pin={pin}"
        if fingerprint_enabled:
            for table in ("templatev10", "template"):
                try:
                    sdk.delete_device_data(table=table, data=cond, options="")
                except Exception as ex:
                    self.logger.debug(
                        "[DeviceSync] _delete_pin_unconditional %s Pin=%s (non-fatal): %s", table, pin, ex)
        try:
            sdk.delete_device_data(table="userauthorize", data=cond, options="")
        except Exception as ex:
            self.logger.debug(
                "[DeviceSync] _delete_pin_unconditional userauthorize Pin=%s (non-fatal): %s", pin, ex)
        try:
            sdk.delete_device_data(table="user", data=cond, options="")
            return True
        except Exception as ex:
            self.logger.warning(
                "[DeviceSync] _delete_pin_unconditional user Pin=%s FAILED: %s", pin, ex)
            return False

    def _delete_auth_and_templates_best_effort(
        self,
        *,
        sdk: PullSDK,
        pin: str,
        fingerprint_enabled: bool = True,
    ) -> None:
        if not sdk.supports_delete_device_data():
            return

        cond = f"Pin={pin}"
        if fingerprint_enabled:
            try:
                sdk.delete_device_data(table="templatev10", data=cond, options="")
            except Exception:
                pass
            try:
                sdk.delete_device_data(table="template", data=cond, options="")
            except Exception:
                pass
        try:
            sdk.delete_device_data(table="userauthorize", data=cond, options="")
        except Exception:
            pass

    @staticmethod
    def _retry_due(*, fail_streak: int, updated_at: "str | None",
                   now: "datetime | None" = None) -> bool:
        """Is a repeatedly-failing pin due for another attempt?

        Fails OPEN in every ambiguous case -- an unparseable or future
        timestamp, or a clock that moved backwards, yields True. Stranding a
        member's fingerprint is worse than one wasted push.
        """
        if int(fail_streak or 0) <= _SYNC_RETRY_FREE_ATTEMPTS:
            return True
        # now_iso()/format_ts() is LOCAL and NAIVE ("YYYY-MM-DD HH:MM:SS").
        # Do NOT route it through a tz-aware parser: that would stamp UTC on a
        # naive value and the comparison would be wrong by the local offset.
        try:
            last = datetime.strptime(str(updated_at or ""), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return True
        elapsed = ((now or datetime.now()) - last).total_seconds()
        if elapsed < 0:
            return True
        delay = min(
            _SYNC_RETRY_BASE_SEC * (2 ** (int(fail_streak) - _SYNC_RETRY_FREE_ATTEMPTS - 1)),
            _SYNC_RETRY_MAX_SEC,
        )
        return elapsed >= delay

    def _compute_desired_hash(
        self,
        *,
        pin: str,
        user: Dict[str, Any],
        door_bitmask: int,
        templates: List[Dict[str, Any]],
        authorize_timezone_id: int,
        template_version_override: "int | None" = None,
        fields_out: Dict[str, Any] | None = None,
    ) -> str:
        full_name = _safe_one_line(user.get("fullName") or "") or f"U{pin}"
        # Hash the DEVICE-effective card (digits-only, marker stripped, 10-digit
        # clamped) — the same value the push sends — so toggling a '99999+' marker
        # no longer flips the checksum without a real device change.
        card = _normalize_device_card(user.get("firstCardId"))
        doors_norm = str(door_bitmask)
        tz = int(authorize_timezone_id or 1)

        tpl_parts: List[str] = []
        for t in templates or []:
            try:
                fid = int(t.get("fingerId"))
            except Exception:
                continue
            # EFFECTIVE version -- must mirror _push_templates exactly, including
            # its guard form. Hashing the RECORD version alone is what made
            # deviceCapabilities.fingerprintTemplateVersion inert: flipping the
            # dropdown never moved any pin's stored hash, so no pin was ever
            # selected for re-push and the setting did nothing at all.
            try:
                tv = int(t.get("templateVersion") or 10)
            except (TypeError, ValueError):
                tv = 10
            if template_version_override in (9, 10):
                tv = int(template_version_override)
            ts = int(t.get("templateSize") or 0)
            td = _safe_template_text(str(t.get("templateData") or ""))
            if not td:
                continue
            tpl_parts.append(f"{fid}:{tv}:{ts}:{td}")
        tpl_blob = "|".join(tpl_parts)

        payload = (
            f"pin={pin}\nname={full_name}\ncard={card}\n"
            f"doors={doors_norm}\nauthorizeTimezoneId={tz}\n"
            f"templates={tpl_blob}\n"
        )
        # Diagnostic breakdown (only when a caller asks for it — zero cost otherwise).
        # Lets the scheduler log WHICH field flips the device-sync fingerprint.
        if fields_out is not None:
            fields_out["name"] = full_name
            fields_out["card"] = card
            fields_out["doors"] = doors_norm
            fields_out["tz"] = str(tz)
            fields_out["tplh"] = _sha1_hex(tpl_blob)[:12] if tpl_blob else ""
            fields_out["tpln"] = len(tpl_parts)
            # Read by ultra_engine's FP_DELTA diff_fields. Without it the one-time
            # re-push logs as {'tplh': N}, which a field engineer reads as
            # "N members' fingerprints changed" -- false, and alarming.
            fields_out["tvo"] = str(template_version_override or "")
        return _sha1_hex(payload)

    def build_device_sync_fingerprint(
        self,
        *,
        device: Dict[str, Any],
        users: List[Dict[str, Any]],
        local_fp_index: Dict[str, List[Any]] | None = None,
        detail_out: Dict[str, Any] | None = None,
    ) -> Tuple[str, int]:
        normalized_device = self._normalize_device(device if isinstance(device, dict) else {})
        default_door_id = self._default_authorize_door_id()
        door_ids, door_bitmask, authorize_timezone_id, fingerprint_enabled = self._resolve_push_context(
            device=normalized_device,
            default_door_id=default_door_id,
        )
        desired = self._filter_users_for_device(
            users=users,
            device=normalized_device,
            default_door_id=default_door_id,
        )

        if local_fp_index is None:
            local_fp_index = {}
            try:
                recs = list_fingerprints()
                for r in recs:
                    pin = _pin_str(getattr(r, "pin", "") or "")
                    if not pin:
                        continue
                    local_fp_index.setdefault(pin, []).append(r)
            except Exception:
                local_fp_index = {}

        policy = str(normalized_device.get("pushingToDevicePolicy") or "").strip().upper()
        allowed_memberships = _norm_int_list(normalized_device.get("allowedMemberships") or [])
        # Resolved once, outside the per-user loop. NOT added to fingerprint_parts:
        # the header must not change, or every device with the setting would take a
        # full roster re-push even where nothing behavioural moved. The override
        # reaches the checksum through the per-user hashes instead, which is also
        # exactly the set of pins that genuinely need re-pushing.
        _tv_override = self._resolve_template_version_override(normalized_device)
        fingerprint_parts = [
            f"allowedMemberships={','.join(str(v) for v in allowed_memberships)}",
            f"doorIds={','.join(str(v) for v in door_ids)}",
            f"doorBitmask={door_bitmask}",
            f"authorizeTimezoneId={authorize_timezone_id}",
            f"policy={policy}",
            f"fingerprintEnabled={1 if fingerprint_enabled else 0}",
        ]
        # The pin scheme joins the header ONLY for ACCOUNT. A MEMBERSHIP device keeps the
        # exact header it had before pinScheme existed, so upgrading the client does not
        # move any roster hash; a device switched to ACCOUNT gets a new hash even in the
        # degenerate case where every per-user part happens to be unchanged.
        if device_pin_scheme(normalized_device) == PIN_SCHEME_ACCOUNT:
            fingerprint_parts.append(f"pinScheme={PIN_SCHEME_ACCOUNT}")

        if detail_out is not None:
            # Header (device-level) part of the fingerprint, before per-user parts.
            detail_out["header"] = "\n".join(fingerprint_parts)
            detail_out["users"] = {}

        for pin in sorted(desired):
            user = desired.get(pin)
            if not isinstance(user, dict):
                continue
            templates = self._collect_templates_for_pin(
                user=user,
                pin=pin,
                local_fp_index=local_fp_index,
                fingerprint_enabled=fingerprint_enabled,
            )
            _fo: Dict[str, Any] | None = {} if detail_out is not None else None
            comp = self._compute_desired_hash(
                pin=pin,
                user=user,
                door_bitmask=door_bitmask,
                templates=templates,
                authorize_timezone_id=authorize_timezone_id,
                template_version_override=_tv_override,
                fields_out=_fo,
            )
            fingerprint_parts.append(comp)
            if detail_out is not None and _fo is not None:
                _fo["h"] = comp[:12]
                detail_out["users"][pin] = _fo

        payload = "\n".join(fingerprint_parts)
        return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest(), len(desired)

    def _sync_one_device(
        self,
        *,
        device: Dict[str, Any],
        users: List[Dict[str, Any]],
        local_fp_index: Dict[str, List[Any]],
        default_door_id: int,
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
        sdk: PullSDK | None = None,
        report_progress: bool = True,
    ) -> None:
        dev_id = device.get("id")
        dev_name = device.get("name") or ""
        ip = (device.get("ipAddress") or "").strip()
        port = _to_int(device.get("portNumber"), default=4370) or 4370
        pwd = device.get("password") or ""
        batch_id: int | None = None
        batch_started_iso: str | None = None
        batch_started_perf = time.perf_counter()
        pins_sorted: List[str] = []
        pin_outcomes: Dict[str, Dict[str, Any]] = {}
        batch_error: str | None = None
        # P3a-2 removal outcome of this pass: pins a refused removal step kept on the
        # device (REVOKE_ABORTED), pins whose delete failed (kept for the retry), and
        # the push-batch notes that carry both to /api/v2/push-history.
        removal_aborted = 0
        # A caller (the ULTRA worker's revoke pre-pass) may hand over notes of its own,
        # e.g. SKIPPED_NOT_OWNED, so they land on the same push-batch row.
        removal_notes: List[str] = list(getattr(self, "_extra_batch_notes", None) or [])
        self._extra_batch_notes = []
        failed_stale: List[str] = []
        # "complete" is set only when the pass reaches its end: a pass that stopped
        # early must not clear the worker's removal retry (review R1-06).
        self._last_removal_report = {"aborted": 0, "failed": [], "complete": False}

        def _maybe_set_progress(**changes: Any) -> None:
            if report_progress:
                self._set_progress(**changes)

        door_ids, door_bitmask, authorize_timezone_id, fingerprint_enabled = self._resolve_push_context(
            device=device,
            default_door_id=default_door_id,
        )

        # Per-device template-table bias (deviceCapabilities.fingerprintTemplateVersion).
        # Both callers pass a _normalize_device() dict (which carries the parsed key);
        # the raw-capabilities re-parse is a belt-and-braces fallback.
        # One resolver for the push AND both hash paths -- a divergence at any site
        # makes the stored per-pin hash disagree with what the push produced, and
        # the pin is then re-pushed on every cycle forever.
        template_version_override = self._resolve_template_version_override(device)

        if dev_id is None:
            self.logger.warning(f"[DeviceSync] Skip device name={dev_name!r}: missing id")
            return
        did = int(_to_int(dev_id, default=0) or 0)
        if did <= 0:
            self.logger.warning(f"[DeviceSync] Skip device name={dev_name!r}: invalid id={dev_id!r}")
            return

        if not ip:
            self.logger.warning(f"[DeviceSync] Skip device id={dev_id} name={dev_name!r}: missing ipAddress")
            return

        # ------------------------------------------------------------------ #
        # PROTOCOL GUARD
        #
        # Everything below this line speaks the LOW-LEVEL PullSDK DLL surface
        # (sdk.connect / set_device_data / delete_device_data / ...). No other
        # driver implements it, so this engine is PullSDK-only by construction.
        #
        # Without this guard a ZK_STANDALONE terminal (MB2000 over zkemkeeper)
        # was handed a plcommpro.dll socket: it cannot answer, so the connect
        # burned its full timeout and looked exactly like a cabling fault
        # (observed in the field as connect_ms=5110 on a healthy device).
        #
        # This is deliberately NOT a quiet `return`. A ZK_STANDALONE device that
        # is in DEVICE mode gets its roster from NO engine at all -- the
        # standalone push lives only on the ULTRA worker
        # (ultra_engine._run_standalone_full_sync) -- so a silent skip would
        # look like a successful sync while the device received nothing.
        # ------------------------------------------------------------------ #
        protocol = resolve_device_protocol(device)
        if protocol != DeviceProtocol.ZK_PULLSDK:
            self.logger.error(
                "[DeviceSync] Device id=%s name=%r NOT synced: protocol=%s is not driven by "
                "this engine (PullSDK only). Set accessDataMode=ULTRA on this device so the "
                "ULTRA worker pushes its roster; in DEVICE mode it receives nothing.",
                dev_id, dev_name, protocol.value,
            )
            try:
                _tel.event(
                    "DEVICE_SYNC_PROTOCOL_SKIP",
                    device_id=did,
                    protocol=protocol.value,
                    access_data_mode=str(device.get("accessDataMode") or ""),
                )
            except Exception:
                pass
            return

        # P1: resolve effective push policy for this device
        policy = self._resolve_push_policy(device)

        # Audit profile for the whole-device sync: accumulates the UNTIMED phases
        # (filter / prev_state / connect / predelete / userauthorize) and emits ONE
        # FULL_SYNC_DEVICE summary line. Phases already wrapped by their own spans
        # (SYNC_READBACK / SYNC_HASH_DESIRED / SYNC_PHASE_C_TEMPLATES / SYNC_PHASE_D_MIRROR)
        # are NOT re-timed here to avoid duplication. Named _fsp (not p) because p is
        # reused as a loop variable below.
        _fsp = _tel.profile("FULL_SYNC_DEVICE", device_id=dev_id)

        filter_stats: Dict[str, Any] = {}
        with _fsp.step("filter"):
            desired = self._filter_users_for_device(
                users=users, device=device, default_door_id=default_door_id,
                stats_out=filter_stats,
            )
        desired_pins = set(desired.keys())
        pin_scheme = filter_stats.get("pin_scheme") or device_pin_scheme(device)
        # A withheld ACCOUNT row (no mainAccountId) has a pin we cannot name, so it cannot be
        # kept: every REMOVAL below (stale-pin delete, nuke, prune) is skipped this pass.
        roster_incomplete = bool(filter_stats.get("withheld_missing_account"))

        known_server_pins: Set[str] = set()
        for u in users or []:
            if pin_scheme == PIN_SCHEME_ACCOUNT:
                p, _src = derive_member_pin(u, PIN_SCHEME_ACCOUNT)
            else:
                # MEMBERSHIP: exactly the pre-existing set (activeMembershipId only).
                p = _pin_str(u.get("activeMembershipId"))
            if p and p.isdigit():
                known_server_pins.add(p)

        # changed_ids are MEMBERSHIP ids (backend delta, fast-patch impact). Under ACCOUNT
        # they are translated to the person pins they touch; under MEMBERSHIP the original
        # `int(pin) in changed_ids` test is kept verbatim.
        changed_account_pins: Set[str] | None = None
        if changed_ids is not None and pin_scheme == PIN_SCHEME_ACCOUNT:
            changed_account_pins = set(account_pins_for_memberships(changed_ids, users).values())

        def _pin_in_changed(pin: str) -> bool:
            if changed_account_pins is not None:
                return pin in changed_account_pins
            return int(pin) in changed_ids

        with _fsp.step("prev_state"):
            prev_state = list_device_sync_retry_state(device_id=did)
        # Also keep a simple hash dict for backward compat with prune logic
        prev_hashes = {p: t[0] for p, t in prev_state.items()}
        deletion_only_delta = changed_ids is not None and len(changed_ids) == 0

        pins_to_sync: Set[str] = set()
        desired_hashes: Dict[str, str] = {}
        templates_for_sync: Dict[str, List[Dict[str, Any]]] = {}

        # NOTE: this desired-hash loop runs over the FULL desired roster on EVERY
        # sync, even when only one member changed (changed_ids prunes pins_to_sync
        # AFTER, at line ~1868, but the hashing itself is unconditional). It is the
        # CPU half of the steady-state freeze — measure it so a 1-member change
        # that stalls minutes names its own cost instead of leaving us to infer it.
        _backoff_skipped = 0
        with _tel.span("SYNC_HASH_DESIRED", device_id=dev_id, n=len(desired)):
            _hash_i = 0
            for pin, u in desired.items():
                templates = self._collect_templates_for_pin(
                    user=u, pin=pin, local_fp_index=local_fp_index,
                    fingerprint_enabled=fingerprint_enabled,
                )
                dh = self._compute_desired_hash(
                    pin=pin,
                    user=u,
                    door_bitmask=door_bitmask,
                    templates=templates,
                    authorize_timezone_id=authorize_timezone_id,
                    template_version_override=template_version_override,
                )
                desired_hashes[pin] = dh
                prev_hash, prev_ok, prev_streak, prev_attempt_hash, prev_seen = \
                    prev_state.get(pin, ("", True, 0, None, None))
                # Sync if: hash changed OR previous attempt failed
                needs_push = prev_hash != dh or not prev_ok
                # ... except a pin that has already failed repeatedly on THIS
                # EXACT desired state. prev_attempt_hash == dh is what proves
                # "same content, already tried and refused" -- if the member was
                # re-enrolled, dh differs and the push goes through immediately.
                if (needs_push and not prev_ok and prev_attempt_hash == dh
                        and not self._retry_due(fail_streak=prev_streak,
                                                updated_at=prev_seen)):
                    needs_push = False
                    _backoff_skipped += 1
                if needs_push:
                    pins_to_sync.add(pin)
                    templates_for_sync[pin] = templates
                # This loop hashes the WHOLE roster even for a 1-member change and
                # no SDK call is in flight here, so periodically let the worker open
                # any door queued mid-reconcile (keeps the turnstile alive during the
                # CPU phase, not just the push phase).
                _hash_i += 1
                if (_hash_i & 0x7F) == 0:  # every 128 users
                    self._maybe_yield_doors()
                    self._maybe_yield_rtlog()

        # Delta hint: when the backend reported only a subset of users changed,
        # prune pins_to_sync to those users + any with a failed/missing prev sync.
        # Stale-pin deletion is unaffected (uses desired_pins, not pins_to_sync).
        # Skip delta pruning for FULL_REPLACE - that policy always pushes everything.
        if deletion_only_delta and policy != _PUSH_POLICY_FULL_REPLACE:
            # Deletion-only deltas should only remove stale pins; they should not
            # retry or re-push the full desired roster.
            pins_to_sync = set()
            templates_for_sync = {}
        elif changed_ids is not None and policy != _PUSH_POLICY_FULL_REPLACE:
            pins_to_sync = {
                pin for pin in pins_to_sync
                if (
                    _pin_in_changed(pin)             # changed per backend delta
                    or not prev_state.get(pin, ("", True))[0]   # no stored hash (new)
                    or not prev_state.get(pin, ("", True))[1]   # previous push failed
                )
            }

        self.logger.info(
            f"[DeviceSync] Device id={dev_id} name={dev_name!r} ip={ip}:{port} "
            f"desired={len(desired_pins)} to_sync={len(pins_to_sync)} "
            f"backoff_skipped={_backoff_skipped} "
            f"door_bitmask={door_bitmask} doorIds={door_ids} tz={authorize_timezone_id} policy={policy}"
        )
        # A silently skipped pin must never be invisible: without this, a member
        # in backoff looks identical to a member who is genuinely in sync.
        if _backoff_skipped:
            try:
                _tel.event("SYNC_RETRY_BACKOFF", device_id=did, pins=_backoff_skipped)
            except Exception:
                pass

        batch_started_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        batch_id = insert_push_batch(
            sync_run_id=sync_run_id,
            device_id=did,
            device_name=dev_name or f"Device {did}",
            policy=policy,
            status="IN_PROGRESS",
            created_at=batch_started_iso,
        )

        disconnect_when_done = sdk is None
        if sdk is None:
            sdk = PullSDK(self.cfg.plcomm_dll_path, logger=self.logger)
        try:
            if disconnect_when_done:
                import time as _time

                t_connect = _time.time()
                connect_timeout_ms = self._resolve_connect_timeout_ms(device)
                self.logger.info(
                    "[DeviceSync] Device id=%s name=%r connecting: ip=%s port=%s timeout_ms=%s",
                    dev_id,
                    dev_name,
                    ip,
                    port,
                    connect_timeout_ms,
                )
                with _fsp.step("connect"):
                    sdk.connect(
                        ip=ip,
                        port=int(port),
                        timeout_ms=connect_timeout_ms,
                        password=str(pwd),
                    )
                connect_ms = (_time.time() - t_connect) * 1000
                self.logger.info(
                    "[DeviceSync] Device id=%s name=%r connected OK: connect_ms=%.0f", dev_id, dev_name, connect_ms
                )

            # UNCONDITIONAL device read-back of ALL pins, every sync (network round
            # trip over the single connection that also polls RTLog / opens doors).
            # Independent of changed_ids — the network half of the steady-state
            # freeze. Time it so the 1-member-change stall is attributable.
            with _tel.span("SYNC_READBACK", device_id=dev_id):
                rows = sdk.get_device_data_rows(
                    table="user",
                    fields="Pin",
                    filter_expr="",
                    options="",
                    initial_size=self._sdk_read_initial_bytes(),  # ✅ backend-driven knob
                )
            device_pins: Set[str] = set()
            for r in rows:
                p = _pin_str(r.get("Pin") or r.get("pin") or "")
                if p:
                    device_pins.add(p)

            # F-011: Drift detection — desired pins missing from device despite having a stored hash
            # indicate external removal. Force re-sync for those pins.
            # In delta mode skip drift check for unchanged users; they'll be caught on the next full sync.
            for pin in desired_pins:
                if pin not in device_pins and prev_hashes.get(pin) and pin not in pins_to_sync:
                    if changed_ids is not None and not _pin_in_changed(pin):
                        continue  # skip drift detection for unchanged users in delta mode
                    self.logger.info(
                        f"[DeviceSync] Device id={dev_id} Pin={pin}: "
                        f"not on device but hash stored — external removal detected, forcing re-sync"
                    )
                    pins_to_sync.add(pin)
                    if pin not in templates_for_sync:
                        u = desired.get(pin)
                        if isinstance(u, dict):
                            templates_for_sync[pin] = self._collect_templates_for_pin(
                                user=u, pin=pin, local_fp_index=local_fp_index,
                                fingerprint_enabled=fingerprint_enabled,
                            )

            # P3a-2 write-ahead: an intent pin that LEFT the roster is settled here -- absent
            # from the panel: dropped; present with the card MonClub wrote: proven MonClub's,
            # so it joins the tracked set and leaves through the stale step (ceiling applies).
            promoted_intents = self._settle_pullsdk_intents(
                sdk=sdk, did=did, desired_pins=desired_pins, device_pins=device_pins,
            )
            # stale pins: only delete pins that are known-from-server but no longer desired for this device
            tracked_server_pins = set(known_server_pins) | set(prev_state.keys()) | promoted_intents
            stale_pins = sorted([p for p in device_pins if p in tracked_server_pins and p not in desired_pins])
            if roster_incomplete:
                if stale_pins:
                    self.logger.warning(
                        "[DeviceSync] Device id=%s pinScheme=ACCOUNT roster INCOMPLETE (%s row(s) "
                        "withheld, no mainAccountId): NOT removing %d stale pin(s) -- a withheld "
                        "member cannot be told apart from a departed one.",
                        dev_id, filter_stats.get("withheld_missing_account"), len(stale_pins),
                    )
                stale_pins = []
            self.logger.info(
                "[DeviceSync] Device id=%s: device_pins=%d desired=%d to_sync=%d "
                "stale=%d drift_resynced=%d door_bitmask=%d",
                dev_id, len(device_pins), len(desired_pins), len(pins_to_sync),
                len(stale_pins),
                sum(1 for p in desired_pins if p not in device_pins and prev_hashes.get(p)),
                door_bitmask,
            )

            # ── P1: Policy-driven removal decisions (P3a-2: ONE ceiling, no automatic wipe) ──
            # FULL_REPLACE  → clear all tables, but only when the rows on the panel fit
            #                 under the shared removal ceiling: a clear deletes EVERY row,
            #                 foreign users included. Above it the clear is refused
            #                 (REVOKE_ABORTED path=table_clear) and the pass degrades to
            #                 "push the whole roster, stale pins through the ceiling".
            # ADDITIVE_ONLY → never delete anything; skip stale-pin removal too.
            # INCREMENTAL   → stale pins removed one by one, through the ceiling.
            #
            # The INCREMENTAL "nuke-and-repave" heuristic (clear every table when
            # stale > desired and stale > 10) is GONE. That trigger is always above the
            # ceiling max(10, 25 % of desired) -- desired <= 40: ceiling 10 < stale;
            # desired > 40: 0.25 x desired < desired < stale -- so it could only ever run
            # as an automatic wipe of the terminal, and on gym 58 (INCREMENTAL, pinScheme
            # '' so no switch row) nothing suppressed it. guide §3.2g.
            nuke_mode = False
            stale_before_clear = list(stale_pins)
            if policy == _PUSH_POLICY_FULL_REPLACE:
                pins_to_sync = set(desired.keys())  # push entire roster
                if roster_incomplete:
                    # Clearing the tables and re-pushing a roster that is missing people
                    # would take those people off the device.
                    self.logger.warning(
                        "[DeviceSync] Device id=%s: FULL_REPLACE clear suppressed -- "
                        "pinScheme=ACCOUNT roster is incomplete (%s row(s) withheld)", dev_id,
                        filter_stats.get("withheld_missing_account"),
                    )
                else:
                    _clear_verdict = _push_safety.check_bulk_removal(
                        count=len(device_pins), roster_count=len(desired_pins),
                        path="table_clear", device_id=did, protocol="ZK_PULLSDK",
                    )
                    if _clear_verdict.allowed:
                        nuke_mode = True
                        stale_pins = []                      # tables will be cleared anyway
                        self.logger.info(
                            "[DeviceSync] Device id=%s: FULL_REPLACE policy — "
                            "clearing all tables (%d row(s), within the ceiling), pushing all %d members",
                            dev_id, len(device_pins), len(pins_to_sync),
                        )
                    else:
                        removal_aborted += _clear_verdict.count
                        removal_notes.append(_push_safety.outcome_note(
                            _push_safety.REVOKE_ABORTED, _clear_verdict.count,
                            f"table_clear; ceiling {_clear_verdict.ceiling:.0f}",
                        ))
            elif policy == _PUSH_POLICY_ADDITIVE_ONLY:
                nuke_mode = False
                _ignored_stale = len(stale_pins)
                stale_pins = []  # never remove stale pins in ADDITIVE_ONLY
                if _ignored_stale > 0:
                    self.logger.info(
                        "[DeviceSync] Device id=%s: ADDITIVE_ONLY policy — "
                        "%d stale pin(s) left on device intentionally",
                        dev_id, _ignored_stale,
                    )
            if nuke_mode:
                self.logger.info(
                    "[DeviceSync] Device id=%s: FULL_REPLACE table clear — %d row(s) on the "
                    "panel, re-pushing %d desired",
                    dev_id, len(device_pins), len(desired_pins),
                )
                # Template tables are optional (templatev10 vs template depends on firmware).
                # P1 gate: skip entirely on devices without biometric storage (C3 panels)
                # so we don't waste two guaranteed-failing SDK calls per nuke.
                if fingerprint_enabled:
                    for tbl in ("templatev10", "template"):
                        try:
                            sdk.clear_device_table(table=tbl)
                        except PullSDKError:
                            self.logger.debug(
                                "[DeviceSync] Device id=%s: clear %s skipped (table may not exist)",
                                dev_id, tbl,
                            )
                # Critical tables: userauthorize then user. Abort nuke if these fail.
                for tbl in ("userauthorize", "user"):
                    try:
                        sdk.clear_device_table(table=tbl)
                    except PullSDKError as ex:
                        self.logger.warning("[DeviceSync] Device id=%s: clear %s failed: %s — falling back to individual delete", dev_id, tbl, ex)
                        nuke_mode = False
                        # The stale pins go through the ceiling one by one instead.
                        stale_pins = list(stale_before_clear)
                        break
                if nuke_mode:
                    # Device is now empty — push ALL desired users
                    pins_to_sync = set(desired_pins)
                    stale_pins = []
                    device_pins = set()
                    # Collect templates for pins that weren't in the original pins_to_sync
                    for pin in desired_pins:
                        if pin not in templates_for_sync:
                            u = desired.get(pin)
                            if isinstance(u, dict):
                                templates_for_sync[pin] = self._collect_templates_for_pin(
                                    user=u, pin=pin, local_fp_index=local_fp_index,
                                    fingerprint_enabled=fingerprint_enabled,
                                )

            # ── Delete stale pins in BULK (skipped when nuke mode cleared everything) ──
            # P0-bulk: collapse 4 × N per-pin DeleteDeviceData calls into 4 bulk calls
            # (one per table), chunked at 100 pins/call. Falls back to per-pin inside
            # the SDK on chunk failure.
            deleted = 0
            with _fsp.step("predelete"):
                if stale_pins:
                    # ONE ceiling for every bulk removal (P3a-2, guide §3.2g). Refused:
                    # nothing is removed, the per-pin state is kept (the prune below is
                    # skipped too) and the rest of the pass still runs.
                    _stale_verdict = _push_safety.check_bulk_removal(
                        count=len(stale_pins), roster_count=len(desired_pins),
                        path="stale", device_id=did, protocol="ZK_PULLSDK",
                        sample=stale_pins,
                    )
                    if not _stale_verdict.allowed:
                        removal_aborted += _stale_verdict.count
                        removal_notes.append(_push_safety.outcome_note(
                            _push_safety.REVOKE_ABORTED, _stale_verdict.count,
                            f"stale; ceiling {_stale_verdict.ceiling:.0f}",
                        ))
                        stale_pins = []
                if stale_pins:
                    failed_del: List[str] = list(stale_pins)
                    try:
                        ok_del, failed_del = self._bulk_delete_pins(
                            sdk=sdk,
                            pins=stale_pins,
                            device_id=int(did) if did is not None else 0,
                            fingerprint_enabled=fingerprint_enabled,
                        )
                        deleted = ok_del
                        if failed_del:
                            self.logger.warning(
                                "[DeviceSync] Device id=%s: %d stale pin(s) failed to delete: %s",
                                dev_id, len(failed_del), failed_del[:10],
                            )
                    except Exception as ex:
                        self.logger.warning(f"[DeviceSync] Bulk delete of stale pins failed: {ex}")
                    failed_stale = sorted({str(p) for p in (failed_del or [])})
                    # Forget local state ONLY for pins actually removed. It used to be
                    # erased "regardless of SDK outcome", which left a failed delete with
                    # no row -- so once the member had left the roster nothing ever tried
                    # again, and the credential stayed on the panel. The kept row (with
                    # its ownership bit) is what the retry and the prune below need.
                    _failed_set = set(failed_stale)
                    for p in stale_pins:
                        if str(p) in _failed_set:
                            continue
                        try:
                            clear_device_revocation_state(device_id=did, pin=p)
                        except Exception:
                            pass
                    if failed_stale:
                        removal_notes.append(f"REMOVAL_FAILED={len(failed_stale)}")
                    # Published NOW, not only at the end of the pass: a later step that
                    # raises must not lose a refused delete (review R2-21).
                    self._last_removal_report = {"aborted": int(removal_aborted),
                                                 "failed": list(failed_stale),
                                                 "complete": False}

            pushed_users = 0
            pushed_templates = 0
            warn_templates_users = 0
            ok_synced = 0
            failed_synced = 0
            # Bound here, not inside the Phase C span: the terminal batch tick
            # reads it, and an early return added between the two later would
            # otherwise NameError on a live sync.
            _tpl_done = 0

            # ── Batch push: user + authorize rows in chunks of 50 ──────────
            # In nuke mode the device is clear — no pre-delete needed.
            # In normal mode we pre-delete pins individually before batch push.
            use_batch = nuke_mode or len(pins_to_sync) > 5
            pins_sorted = sorted(pins_to_sync)

            # WRITE-AHEAD (P3a-2 item 3, guide §3.4a): durable BEFORE the first write of
            # this pass. Phase D records state (and clears these) only after phases A-C,
            # so a crash between Phase A and D used to leave users on the panel with no
            # row at all. Raises -- failing the pass before any write -- when it cannot
            # be recorded: no record, no write.
            if pins_sorted:
                record_push_intents(
                    device_id=did, protocol="ZK_PULLSDK",
                    rows=[
                        (
                            _p,
                            _safe_one_line((desired.get(_p) or {}).get("fullName") or "") or f"U{_p}",
                            _normalize_device_card(_pin_str((desired.get(_p) or {}).get("firstCardId") or "")),
                            desired_hashes.get(_p, ""),
                        )
                        for _p in pins_sorted
                    ],
                )

            # Expose live progress for the frontend banner.
            # Phase C pushes templates in a SECOND pass over the same pins, so the
            # bar must budget for it too. With `total` covering only the user push,
            # `current` reached `total` the moment that push ended and the bar sat
            # pinned at 100% for the entire fingerprint phase - on screen that is
            # indistinguishable from a frozen sync.
            # Counted from `pins_sorted` (the set Phase C actually walks), not from
            # `templates_for_sync`, which is also populated for desired pins outside
            # `pins_to_sync`.
            _template_pins = (
                sum(1 for _p in pins_sorted if templates_for_sync.get(_p))
                if use_batch else 0
            )
            _maybe_set_progress(
                deviceName=dev_name or "",
                deviceId=did,
                current=0,
                total=len(pins_to_sync) + _template_pins,
            )

            if use_batch and pins_sorted:
                # P0-bulk: strategy-driven pre-delete.
                #   upsert (default)        — skip pre-delete entirely, trust SetDeviceData upsert.
                #                             Failed rows fall through to the per-row force-delete retry
                #                             below (preserves correctness on edge-case firmware).
                #   delete_then_insert      — ONE bulk delete across the 4 tables (pinned via cache for
                #                             devices where silent-upsert-failure was observed).
                #   one_by_one              — legacy per-pin delete loop (ultimate safety net).
                profile = self._get_firmware_profile(int(dev_id) if dev_id is not None else 0)
                insert_strategy = profile.insert_strategy or _INSERT_UPSERT

                if not nuke_mode:
                    if insert_strategy == _INSERT_UPSERT:
                        # No-op. SetDeviceData below will upsert in place.
                        pass
                    elif insert_strategy == _INSERT_DELETE_THEN_INSERT:
                        # Bulk pre-delete (reuses stale-delete helper: 4 calls total, not 4×N).
                        try:
                            self._bulk_delete_pins(
                                sdk=sdk,
                                pins=pins_sorted,
                                device_id=int(did) if did is not None else 0,
                                fingerprint_enabled=fingerprint_enabled,
                            )
                        except Exception as ex:
                            self.logger.warning(
                                "[DeviceSync] Device id=%s: bulk pre-delete failed, falling through to upsert: %s",
                                dev_id, ex,
                            )
                    else:  # _INSERT_ONE_BY_ONE
                        predelete_progress_cap = max(0, len(pins_sorted) - 1)
                        predelete_progress_step = max(1, len(pins_sorted) // 100)
                        for idx, pin in enumerate(pins_sorted, start=1):
                            self._delete_pin_unconditional(
                                sdk=sdk, pin=pin, fingerprint_enabled=fingerprint_enabled,
                            )
                            if (
                                predelete_progress_cap > 0
                                and (idx == len(pins_sorted) or idx % predelete_progress_step == 0)
                            ):
                                _maybe_set_progress(current=min(predelete_progress_cap, idx))

                # Record the strategy choice after first successful run (informational; no-op if already cached).
                if profile.insert_strategy is None:
                    profile.insert_strategy = _INSERT_UPSERT
                    self._save_firmware_profile(profile, int(dev_id) if dev_id is not None else 0)

                # Phase A: Batch push user rows
                # Use cached name_supported flag to skip Name field on firmware that rejects it.
                profile = self._get_firmware_profile(int(dev_id) if dev_id is not None else 0)
                use_name = profile.name_supported is not False  # True or None (unknown) → include Name

                user_rows = []
                pin_to_user = {}
                for pin in pins_sorted:
                    u = desired.get(pin)
                    if not isinstance(u, dict):
                        continue
                    full_name = _safe_one_line(u.get("fullName") or "") or f"U{pin}"
                    card = _pin_str(u.get("firstCardId") or "")
                    card_valid = _normalize_device_card(card)
                    pairs = [f"Pin={pin}"]
                    if use_name:
                        pairs.append(f"Name={full_name}")
                    if card_valid:
                        pairs.append(f"CardNo={card_valid}")
                    user_rows.append("\t".join(pairs))
                    pin_to_user[pin] = u

                if user_rows:
                    _total_pins = len(pins_sorted)

                    def _user_progress_cb(ok_so_far: int, _batch_total: int) -> None:
                        # Map user-phase progress to 0..total: the user push is the
                        # dominant wall-clock phase, so tracking it drives the bar.
                        _maybe_set_progress(current=min(_total_pins, ok_so_far))
                        # Let the worker open any door queued mid-push (door-not-open fix)
                        # and poll+process RTLog scans (popup-live-during-sync fix).
                        self._maybe_yield_doors()
                        self._maybe_yield_rtlog()

                    ok_u, failed_u = sdk.set_device_data_batch(
                        table="user", rows=user_rows, chunk_size=50,
                        progress_cb=_user_progress_cb,
                    )
                    pushed_users = ok_u

                    if not failed_u and profile.name_supported is None and use_name:
                        # Name field accepted — cache this discovery
                        profile.name_supported = True
                        self._save_firmware_profile(profile, int(dev_id) if dev_id is not None else 0)
                        self.logger.info("[DeviceSync] Device id=%s: Name field supported — cached", dev_id)

                    if failed_u and use_name:
                        # Name field likely rejected (rc=-101). Retry WITHOUT Name and cache the result.
                        self.logger.warning(
                            "[DeviceSync] Device id=%s: %d user rows failed with Name field, "
                            "retrying without Name", dev_id, len(failed_u))
                        retry_rows = []
                        for row in failed_u:
                            parts = {p.split("=", 1)[0]: p.split("=", 1)[1]
                                     for p in row.split("\t") if "=" in p}
                            rp = [f"Pin={parts.get('Pin', '')}"]
                            if parts.get("CardNo"):
                                rp.append(f"CardNo={parts['CardNo']}")
                            retry_rows.append("\t".join(rp))
                        # Continue advancing the same user-phase progress bar on the
                        # retry-without-Name path (same pins, different payload).
                        _retry_total = len(pins_sorted)
                        _retry_baseline = pushed_users  # already-successful carry-over

                        def _retry_progress_cb(ok_so_far: int, _batch_total: int) -> None:
                            _maybe_set_progress(
                                current=min(_retry_total, _retry_baseline + ok_so_far)
                            )
                            self._maybe_yield_doors()
                            self._maybe_yield_rtlog()

                        ok_r, failed_r = sdk.set_device_data_batch(
                            table="user", rows=retry_rows, chunk_size=50,
                            progress_cb=_retry_progress_cb,
                        )
                        pushed_users += ok_r
                        if ok_r > 0:
                            # Confirmed: Name field not supported on this firmware
                            profile.name_supported = False
                            self._save_firmware_profile(profile, int(dev_id) if dev_id is not None else 0)
                            self.logger.info(
                                "[DeviceSync] Device id=%s: Name field NOT supported — cached (won't retry next time)",
                                dev_id)
                        if failed_r:
                            # Even without Name, some rows failed — try individual with force-delete
                            for row in failed_r:
                                pin = _batch_row_field(row, "Pin")
                                card_valid = _batch_row_field(row, "CardNo")
                                if not pin:
                                    continue
                                try:
                                    self._delete_pin_if_exists(
                                        sdk=sdk, pin=pin, device_pins=device_pins,
                                        fingerprint_enabled=fingerprint_enabled,
                                    )
                                    mp = [f"Pin={pin}"]
                                    if card_valid:
                                        mp.append(f"CardNo={card_valid}")
                                    sdk.set_device_data(table="user", data="\t".join(mp) + "\r\n", options="")
                                    pushed_users += 1
                                except Exception as ex:
                                    pin_outcomes[pin] = {
                                        "full_name": _safe_one_line((pin_to_user.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                        "status": "FAILED",
                                        "error_message": str(ex),
                                        "duration_ms": 0,
                                    }
                                    self.logger.warning(
                                        "[DeviceSync] Device id=%s Pin=%s force-delete retry FAILED: %s",
                                        dev_id, pin, ex)
                    elif failed_u and not use_name:
                        # Already using minimal fields but still failing — individual force-delete
                        for row in failed_u:
                            pin = _batch_row_field(row, "Pin")
                            card_valid = _batch_row_field(row, "CardNo")
                            if not pin:
                                continue
                            try:
                                self._delete_pin_if_exists(
                                    sdk=sdk, pin=pin, device_pins=device_pins,
                                    fingerprint_enabled=fingerprint_enabled,
                                )
                                mp = [f"Pin={pin}"]
                                if card_valid:
                                    mp.append(f"CardNo={card_valid}")
                                sdk.set_device_data(table="user", data="\t".join(mp) + "\r\n", options="")
                                pushed_users += 1
                            except Exception as ex:
                                pin_outcomes[pin] = {
                                    "full_name": _safe_one_line((pin_to_user.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                    "status": "FAILED",
                                    "error_message": str(ex),
                                    "duration_ms": 0,
                                }
                                self.logger.warning(
                                    "[DeviceSync] Device id=%s Pin=%s force-delete retry FAILED: %s",
                                    dev_id, pin, ex)

                # Phase B: Batch push authorize rows
                # Discover firmware profile if not cached (push 1 pin individually first)
                with _fsp.step("userauthorize"):
                    profile = self._get_firmware_profile(int(dev_id) if dev_id is not None else 0)
                    if profile.authorize_body_index is None and pins_sorted:
                        # No cached pattern — discover by pushing first user individually
                        first_pin = pins_sorted[0]
                        self._push_userauthorize(
                            sdk, pin=first_pin, door_bitmask=door_bitmask,
                            authorize_timezone_id=int(authorize_timezone_id),
                            device_id=int(dev_id) if dev_id is not None else 0,
                        )
                        profile = self._get_firmware_profile(int(dev_id) if dev_id is not None else 0)
                        remaining_pins = pins_sorted[1:]
                    else:
                        remaining_pins = pins_sorted

                    if profile.authorize_body_index is not None and remaining_pins:
                        tz = int(authorize_timezone_id)
                        patterns = [
                            lambda p: f"Pin={p}\tAuthorizeTimezoneId={tz}\tAuthorizeDoorId={door_bitmask}",
                            lambda p: f"Pin={p}\tAuthorizeDoorId={door_bitmask}\tAuthorizeTimezoneId={tz}",
                            lambda p: f"Pin={p}\tDoorID={door_bitmask}\tTimeZoneID={tz}",
                            lambda p: f"Pin={p}\tDoorID={door_bitmask}\tTimeZone={tz}",
                        ]
                        pattern_fn = patterns[profile.authorize_body_index]
                        auth_rows = [pattern_fn(p) for p in remaining_pins if desired.get(p)]
                        if auth_rows:
                            # Authorize phase runs after user push is at 100%; keep the
                            # bar pinned at `total` but still emit a heartbeat per chunk
                            # so the dashboard knows the sync is alive.
                            _auth_total = len(pins_sorted)

                            def _auth_progress_cb(_ok_so_far: int, _batch_total: int) -> None:
                                _maybe_set_progress(current=_auth_total)
                                self._maybe_yield_doors()
                                self._maybe_yield_rtlog()

                            ok_a, failed_a = sdk.set_device_data_batch(
                                table="userauthorize", rows=auth_rows, chunk_size=50,
                                progress_cb=_auth_progress_cb,
                            )
                            if failed_a:
                                for row in failed_a:
                                    pin = _batch_row_field(row, "Pin")
                                    if not pin:
                                        continue
                                    pin_outcomes[pin] = {
                                        "full_name": _safe_one_line((desired.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                        "status": "FAILED",
                                        "error_message": "authorize batch failed",
                                        "duration_ms": 0,
                                    }
                                self.logger.warning(
                                    "[DeviceSync] Device id=%s: %d authorize rows failed in batch", dev_id, len(failed_a))
                    elif remaining_pins:
                        # No cached pattern available — fall back to per-pin authorize
                        for pin in remaining_pins:
                            try:
                                self._push_userauthorize(
                                    sdk, pin=pin, door_bitmask=door_bitmask,
                                    authorize_timezone_id=int(authorize_timezone_id),
                                    device_id=int(dev_id) if dev_id is not None else 0,
                                )
                            except Exception as ex:
                                pin_outcomes[pin] = {
                                    "full_name": _safe_one_line((desired.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                    "status": "FAILED",
                                    "error_message": str(ex),
                                    "duration_ms": 0,
                                }
                                self.logger.warning(f"[DeviceSync] Device id={dev_id} Pin={pin} authorize FAILED: {ex}")

                # Phase C: Push templates individually (binary data — too large to batch)
                with _tel.span("SYNC_PHASE_C_TEMPLATES", device_id=dev_id, pins=len(pins_sorted)):
                    for pin in pins_sorted:
                        templates = templates_for_sync.get(pin) or []
                        if templates:
                            try:
                                ok_count, errs = self._push_templates(
                                    sdk, pin=pin, templates=templates,
                                    device_id=int(dev_id) if dev_id is not None else 0,
                                    template_version_override=template_version_override,
                                    pin_source=(filter_stats.get("pin_sources") or {}).get(pin))
                                pushed_templates += ok_count
                                if errs:
                                    warn_templates_users += 1
                                    # A refused template is a FAILED sync, not a warning.
                                    # Phase D derives last_ok from pin_outcomes, so leaving
                                    # this as a log line is what stamped a non-working
                                    # fingerprint "synced" and stopped it ever being
                                    # retried -- while the dashboard showed the member green.
                                    # Mirrors app/sdk/zk_standalone.py, which already does this.
                                    pin_outcomes[pin] = {
                                        "full_name": _safe_one_line((pin_to_user.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                        "status": "FAILED",
                                        "error_message": f"template push failed ({len(errs)}): {errs[0]}",
                                        "duration_ms": 0,
                                    }
                                    self.logger.warning(
                                        f"[DeviceSync] Device id={dev_id} Pin={pin} template errors ({len(errs)}): "
                                        f"{errs[:5]}{'...' if len(errs) > 5 else ''}")
                                    try:
                                        _tel.warn("PULLSDK_PUSH_TPL_REFUSED", device_id=dev_id,
                                                  pin=pin, fingers=len(templates), errs=len(errs))
                                    except Exception:
                                        pass
                            except Exception as ex:
                                warn_templates_users += 1
                                pin_outcomes[pin] = {
                                    "full_name": _safe_one_line((pin_to_user.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                    "status": "FAILED",
                                    "error_message": f"template push failed: {ex}",
                                    "duration_ms": 0,
                                }
                                self.logger.warning(f"[DeviceSync] Device id={dev_id} Pin={pin} template FAILED: {ex}")
                            # Phase C is a second pass over the same pins: keep the bar moving
                            # through it instead of leaving it pinned at the user-push total.
                            _tpl_done += 1
                            _maybe_set_progress(current=len(pins_sorted) + _tpl_done)
                        # ULTRA runs this sync INLINE on the live worker, so release it between
                        # pins: open doors queued mid-push and poll RTLog. Both helpers are
                        # no-ops when no hook is installed (DEVICE mode) and are throttled by
                        # the worker, so this costs a clock compare per pin.
                        self._maybe_yield_doors()
                        self._maybe_yield_rtlog()

                # Phase D: Save device sync state + write-through mirror for all pushed pins.
                # Build all state + mirror rows first (pure Python), then flush each to DB in
                # ONE batch transaction instead of one DbWriter round-trip per pin. The mirror
                # write previously called upsert_device_mirror_pin() — which opens its own
                # connection and commit()s PER pin — inside this loop. Over a full roster
                # (1784 pins × 2 devices on a fresh install) that was thousands of individual
                # fsync commits contending on the SQLite write lock: measured in prod as a
                # ~23 min worker-thread freeze AFTER the device push had already finished, with
                # BOTH turnstiles unable to poll RTLog or open doors the whole time. Now batched
                # into a single executemany transaction (like save_device_sync_state_batch),
                # and wrapped in a span so the cost is measured on the next cold start.
                with _tel.span("SYNC_PHASE_D_MIRROR", device_id=dev_id, pins=len(pins_sorted)):
                    _batch_state_rows: list[tuple[str, str | None, bool, str | None]] = []
                    _batch_mirror_rows: list[tuple] = []
                    for pin in pins_sorted:
                        u = desired.get(pin)
                        if u:
                            _u_name = _safe_one_line(u.get("fullName") or "") or f"U{pin}"
                            _u_card = _pin_str(u.get("firstCardId") or "")
                            _u_fps = len(templates_for_sync.get(pin) or [])
                            pin_error = pin_outcomes.get(pin, {}).get("error_message")
                            pin_ok = not pin_error
                            _batch_state_rows.append((
                                pin,
                                desired_hashes.get(pin) or "",
                                pin_ok,
                                None if pin_ok else str(pin_error),
                            ))
                            pin_outcomes[pin] = {
                                "full_name": _u_name,
                                "status": "SUCCESS" if pin_ok else "FAILED",
                                "error_message": None if pin_ok else str(pin_error),
                                "duration_ms": 0,
                            }
                            if pin_ok:
                                ok_synced += 1
                            else:
                                failed_synced += 1
                            # P7: device content mirror (write-through) — collected, batched below.
                            _batch_mirror_rows.append((
                                pin, _u_name, _u_card or None, door_bitmask,
                                int(authorize_timezone_id), _u_fps, pin_ok,
                            ))
                    # One DbWriter transaction each for state + mirror (replaces N round-trips).
                    if _batch_state_rows:
                        try:
                            save_device_sync_state_batch(device_id=did, rows=_batch_state_rows)
                        except Exception as _batch_err:
                            self.logger.warning(
                                "[DeviceSync] Device id=%s save_device_sync_state_batch failed "
                                "(%d rows): %s", dev_id, len(_batch_state_rows), _batch_err
                            )
                    if _batch_mirror_rows:
                        try:
                            upsert_device_mirror_batch(device_id=did, rows=_batch_mirror_rows)
                        except Exception as _mirror_err:
                            self.logger.warning(
                                "[DeviceSync] Device id=%s upsert_device_mirror_batch failed "
                                "(%d rows): %s", dev_id, len(_batch_mirror_rows), _mirror_err
                            )
                # Terminal tick for the batch branch: include the Phase C templates so
                # the bar finishes full against the widened `total`.
                _maybe_set_progress(current=ok_synced + _tpl_done)
                self.logger.info(
                    "[DeviceSync] Device id=%s batch push complete: users=%d auth=%d templates=%d",
                    dev_id, pushed_users, len(pins_sorted), pushed_templates,
                )

            else:
                # ── Per-pin push (small sync ≤5 pins, or batch not applicable) ──
                for pin in pins_sorted:
                    u = desired.get(pin)
                    if not isinstance(u, dict):
                        continue

                    pin_started_perf = time.perf_counter()
                    full_name = _safe_one_line(u.get("fullName") or "") or f"U{pin}"
                    card = _pin_str(u.get("firstCardId") or "")
                    templates = templates_for_sync.get(pin) or []

                    self.logger.debug(
                        "[DeviceSync] Device id=%s syncing Pin=%s name=%r card=%r templates=%d",
                        dev_id, pin, full_name, card, len(templates),
                    )

                    try:
                        # P0 fix: unconditional delete — never rely on device_pins
                        # being accurate (it may be empty/stale if the read failed or
                        # returned no rows). See _delete_pin_unconditional docstring.
                        self._delete_pin_unconditional(
                            sdk=sdk, pin=pin, fingerprint_enabled=fingerprint_enabled,
                        )

                        card_valid = _normalize_device_card(card)
                        if card and not card_valid:
                            self.logger.warning(
                                "[DeviceSync] Device id=%s Pin=%s CardNo=%r is not numeric — skipping CardNo",
                                dev_id, pin, card,
                            )

                        _did = int(dev_id) if dev_id is not None else 0
                        _profile = self._get_firmware_profile(_did)
                        _use_name = _profile.name_supported is not False
                        pairs = [f"Pin={pin}"]
                        if _use_name:
                            pairs.append(f"Name={full_name}")
                        if card_valid:
                            pairs.append(f"CardNo={card_valid}")
                        _user_data = "\t".join(pairs) + "\r\n"
                        try:
                            sdk.set_device_data(table="user", data=_user_data, options="")
                            if _profile.name_supported is None and _use_name:
                                _profile.name_supported = True
                                self._save_firmware_profile(_profile, _did)
                        except PullSDKError as _set_err:
                            if "rc=-101" not in str(_set_err):
                                raise
                            self.logger.warning(
                                "[DeviceSync] Device id=%s Pin=%s SetDeviceData rc=-101 "
                                "— force-delete + retry without Name", dev_id, pin)
                            self._delete_auth_and_templates_best_effort(
                                sdk=sdk, pin=pin, fingerprint_enabled=fingerprint_enabled,
                            )
                            try:
                                sdk.delete_device_data(table="user", data=f"Pin={pin}", options="")
                            except Exception:
                                pass
                            minimal_pairs = [f"Pin={pin}"]
                            if card_valid:
                                minimal_pairs.append(f"CardNo={card_valid}")
                            sdk.set_device_data(table="user", data="\t".join(minimal_pairs) + "\r\n", options="")
                            if _use_name and _profile.name_supported is None:
                                _profile.name_supported = False
                                self._save_firmware_profile(_profile, _did)
                                self.logger.info(
                                    "[DeviceSync] Device id=%s: Name field NOT supported — cached", dev_id)
                        pushed_users += 1

                        auth_complete = True
                        try:
                            auth_ok_count, auth_err = self._push_userauthorize(
                                sdk, pin=pin, door_bitmask=door_bitmask,
                                authorize_timezone_id=int(authorize_timezone_id),
                                device_id=int(dev_id) if dev_id is not None else 0,
                            )
                            if auth_err:
                                auth_complete = (auth_ok_count == len(door_ids))
                                self.logger.warning(
                                    f"[DeviceSync] Device id={dev_id} Pin={pin} authorize "
                                    f"{'PARTIAL' if not auth_complete else 'warn'}: "
                                    f"{auth_ok_count}/{len(door_ids)} doors — {auth_err}")
                        except Exception as ex:
                            auth_complete = False
                            self.logger.warning(f"[DeviceSync] Device id={dev_id} Pin={pin} authorize FAILED: {ex}")

                        tpl_err: str | None = None
                        if templates:
                            ok_count, errs = self._push_templates(
                                sdk, pin=pin, templates=templates,
                                device_id=int(dev_id) if dev_id is not None else 0,
                                template_version_override=template_version_override,
                                pin_source=(filter_stats.get("pin_sources") or {}).get(pin))
                            pushed_templates += ok_count
                            if errs:
                                warn_templates_users += 1
                                # See Phase C: a refused template is a failed sync.
                                tpl_err = f"template push failed ({len(errs)}): {errs[0]}"
                                self.logger.warning(
                                    f"[DeviceSync] Device id={dev_id} Pin={pin} template errors ({len(errs)}): "
                                    f"{errs[:5]}{'...' if len(errs) > 5 else ''}")
                                try:
                                    _tel.warn("PULLSDK_PUSH_TPL_REFUSED", device_id=dev_id,
                                              pin=pin, fingers=len(templates), errs=len(errs))
                                except Exception:
                                    pass

                        push_ok = auth_complete and tpl_err is None
                        if push_ok:
                            save_device_sync_state(
                                device_id=did, pin=pin,
                                desired_hash=desired_hashes.get(pin) or "",
                                ok=True, error=None,
                            )
                            pin_outcomes[pin] = {
                                "full_name": full_name,
                                "status": "SUCCESS",
                                "error_message": None,
                                "duration_ms": int((time.perf_counter() - pin_started_perf) * 1000),
                            }
                            ok_synced += 1
                            # P7: write-through device content mirror
                            try:
                                upsert_device_mirror_pin(
                                    device_id=did, pin=pin,
                                    full_name=full_name, card_no=card or None,
                                    door_bitmask=door_bitmask,
                                    authorize_tz_id=int(authorize_timezone_id),
                                    fp_count=len(templates), push_ok=True,
                                )
                            except Exception:
                                pass
                        else:
                            # Authorize failure takes precedence in the message; a
                            # template refusal is reported when authorize succeeded.
                            _pin_err = ((auth_err or "authorize incomplete")
                                        if not auth_complete else tpl_err)
                            save_device_sync_state(
                                device_id=did, pin=pin,
                                desired_hash=desired_hashes.get(pin) or "",
                                ok=False, error=_pin_err,
                            )
                            pin_outcomes[pin] = {
                                "full_name": full_name,
                                "status": "FAILED",
                                "error_message": _pin_err,
                                "duration_ms": int((time.perf_counter() - pin_started_perf) * 1000),
                            }
                            failed_synced += 1
                            # P7: record failed push in mirror so dashboard can show drift
                            try:
                                upsert_device_mirror_pin(
                                    device_id=did, pin=pin,
                                    full_name=full_name, card_no=card or None,
                                    door_bitmask=door_bitmask,
                                    authorize_tz_id=int(authorize_timezone_id),
                                    fp_count=len(templates), push_ok=False,
                                )
                            except Exception:
                                pass
                        _maybe_set_progress(current=ok_synced + failed_synced)

                    except Exception as ex:
                        failed_synced += 1
                        _maybe_set_progress(current=ok_synced + failed_synced)
                        save_device_sync_state(
                            device_id=did, pin=pin,
                            desired_hash=None, ok=False, error=str(ex),
                        )
                        pin_outcomes[pin] = {
                            "full_name": full_name,
                            "status": "FAILED",
                            "error_message": str(ex),
                            "duration_ms": int((time.perf_counter() - pin_started_perf) * 1000),
                        }
                        self.logger.warning(
                            "[DeviceSync] Device id=%s Pin=%s sync FAILED: %s", dev_id, pin, ex)

            if roster_incomplete or removal_aborted:
                # roster_incomplete: the withheld people's pins are not in desired_pins;
                # pruning would forget them (and their ownership evidence) while they may
                # still be on the device. removal_aborted (P3a-2): the ceiling refused a
                # removal step, so the pins it kept ARE still on the device -- pruning
                # their rows would strand them there for good (guide §3.2c).
                pruned = 0
            else:
                # A pin whose delete FAILED is still on the device: keep its row.
                # + every pin still on the panel: its row is MonClub's only proof of
                # ownership there (ADDITIVE_ONLY never removes it; review R3-06).
                _keep = set(desired_pins) | set(failed_stale) | set(device_pins)
                pruned = prune_device_sync_state(device_id=did, keep_pins=_keep)
                # Same keep-set: a removed or revoked member must not linger in the push
                # status cache and keep being reported upstream forever.
                try:
                    prune_fingerprint_push_status(device_id=did, keep_pins=_keep)
                except Exception:
                    pass

            # ── Write door timing to controller firmware ──
            # Without this, the C3 keeps its factory/old defaults and the
            # turnstile relay stays active too long (allows a second person).
            presets = device.get("doorPresets") or []
            for p in presets:
                if not isinstance(p, dict):
                    continue
                dn = p.get("doorNumber") or p.get("door_number")
                ps = p.get("pulseSeconds") or p.get("pulse_seconds")
                if dn is not None and ps is not None and int(ps) > 0:
                    param_str = f"Door{int(dn)}Drivertime={int(ps)}"
                    try:
                        sdk.set_device_param(items=param_str)
                        self.logger.info(
                            "[DeviceSync] Device id=%s SetDeviceParam %s OK",
                            dev_id, param_str,
                        )
                    except Exception as ex:
                        self.logger.warning(
                            "[DeviceSync] Device id=%s SetDeviceParam %s failed: %s",
                            dev_id, param_str, ex,
                        )

            # [Anti-fraud] Push DoorIntertime (Punch Interval) to C3 controller.
            # DoorXIntertime=N prevents the same card from being accepted on
            # door X within N seconds (range 0-255). This is the correct C3
            # parameter for re-entry prevention — NOT AntiPassback (which is
            # about in/out tracking). Failure is non-fatal — the software
            # AntiFraudGuard and ULTRA _card_cooldown remain backup enforcers.
            _af_card = bool(device.get("anti_fraude_card", True))
            _af_duration = min(int(device.get("anti_fraude_duration") or 30), 255)
            _af_params = []
            if _af_card and _af_duration > 0:
                for p in presets:
                    if not isinstance(p, dict):
                        continue
                    dn = p.get("doorNumber") or p.get("door_number")
                    if dn is not None:
                        _af_params.append(f"Door{int(dn)}Intertime={_af_duration}")
            _af_param = ",".join(_af_params) if _af_params else "AntiPassback=0"
            try:
                sdk.set_device_param(items=_af_param)
                self.logger.info(
                    "[DeviceSync] Device id=%s anti-fraud param OK (%s)",
                    dev_id, _af_param,
                )
            except Exception as _af_ex:
                self.logger.warning(
                    "[DeviceSync] Device id=%s anti-passback param FAILED (non-fatal): %s",
                    dev_id, _af_ex,
                )

            self._last_removal_report = {"aborted": int(removal_aborted),
                                         "failed": list(failed_stale),
                                         "complete": True,
                                         "stale_skipped": bool(roster_incomplete)}
            self.logger.info(
                f"[DeviceSync] Device id={dev_id} name={dev_name!r} DONE: stale_deleted={deleted} synced_ok={ok_synced} synced_fail={failed_synced} pushed_users={pushed_users} pushed_templates={pushed_templates} warn_templates_users={warn_templates_users} state_pruned={pruned} removal_aborted={removal_aborted} removal_failed={len(failed_stale)}"
            )

        except Exception as ex:
            batch_error = str(ex)
            raise
        finally:
            if batch_id is not None:
                if batch_error and pins_sorted:
                    for pin in pins_sorted:
                        if pin not in pin_outcomes:
                            pin_outcomes[pin] = {
                                "full_name": _safe_one_line((desired.get(pin) or {}).get("fullName") or "") or f"U{pin}",
                                "status": "FAILED",
                                "error_message": batch_error,
                                "duration_ms": 0,
                            }
                # Batch all pin history rows in one DbWriter transaction
                # (replaces N individual insert_push_pin round-trips).
                _pin_batch_rows = [
                    (
                        pin,
                        pin_outcomes[pin].get("full_name"),
                        "UPSERT",
                        pin_outcomes[pin].get("status") or "FAILED",
                        pin_outcomes[pin].get("error_message"),
                        int(pin_outcomes[pin].get("duration_ms") or 0),
                    )
                    for pin in sorted(pin_outcomes.keys())
                ]
                if _pin_batch_rows:
                    try:
                        insert_push_pin_batch(batch_id=batch_id, rows=_pin_batch_rows)
                    except Exception as _pin_batch_err:
                        self.logger.warning(
                            "[DeviceSync] Device id=%s insert_push_pin_batch failed "
                            "(%d rows): %s", dev_id, len(_pin_batch_rows), _pin_batch_err
                        )
                pins_attempted = len(pins_sorted)
                pins_success = sum(1 for outcome in pin_outcomes.values() if outcome.get("status") == "SUCCESS")
                pins_failed = max(pins_attempted - pins_success, 0)
                duration_ms = int((time.perf_counter() - batch_started_perf) * 1000)
                if batch_error and pins_success == 0:
                    batch_status = "FAILED"
                elif batch_error or pins_failed > 0:
                    batch_status = "PARTIAL" if pins_success > 0 else "FAILED"
                else:
                    batch_status = "SUCCESS"
                update_push_batch(
                    id=batch_id,
                    pins_attempted=pins_attempted,
                    pins_success=pins_success,
                    pins_failed=pins_failed,
                    status=batch_status,
                    duration_ms=duration_ms,
                    # P3a-2: removal outcomes ride in the same note the push-history
                    # page already shows (REVOKE_ABORTED=n, REMOVAL_FAILED=n, ...).
                    error_message=(
                        _push_safety.join_notes(batch_error or "", *removal_notes) or None
                    ),
                )
                # One FULL_SYNC_DEVICE summary line for the whole device sync, emitted
                # on every outcome (success/partial/failed) so the audit trail always
                # has the per-phase breakdown. desired_pins/pins_to_sync are assigned
                # before the try, so they are always in scope in this finally block.
                _fsp.done(desired=len(desired_pins), to_sync=len(pins_to_sync))
                if batch_status == "SUCCESS":
                    self._emit_feedback_event(
                        "device_push_success",
                        {
                            "syncRunId": sync_run_id,
                            "batchId": batch_id,
                            "deviceId": did,
                            "deviceName": dev_name,
                        },
                    )
            if disconnect_when_done:
                try:
                    sdk.disconnect()
                except Exception:
                    pass

    def _sync_all_devices(
        self,
        *,
        cache,
        changed_ids: set | None = None,
        sync_run_id: int | None = None,
    ) -> None:
        if not cache:
            self.logger.info("[DeviceSync] No cache -> skip")
            return

        # Users are already normalized to payload-ish dicts by db.load_sync_cache()
        users = getattr(cache, "users", []) or []

        # Devices may be snake_case rows (from normalized table) OR camelCase (fallback payload)
        devices_raw = getattr(cache, "devices", []) or []
        devices = [self._normalize_device(d) for d in devices_raw if isinstance(d, dict)]

        if not devices:
            self._actor_registry.update_devices([])
            self.logger.info("[DeviceSync] No devices in cache -> skip")
            return

        device_mode_devices: List[Dict[str, Any]] = []
        for d in devices:
            dev_id = d.get("id")
            dev_name = d.get("name", "")
            if not _boolish(d.get("active"), default=True):
                self.logger.info(
                    "[DeviceSync] Skip device id=%s name=%r: active=False", dev_id, dev_name
                )
                continue
            if not _boolish(d.get("accessDevice"), default=True):
                self.logger.info(
                    "[DeviceSync] Skip device id=%s name=%r: accessDevice=False", dev_id, dev_name
                )
                continue

            # Only sync DEVICE-mode devices; AGENT-mode devices are handled by AgentRealtimeEngine
            adm = str(d.get("accessDataMode", "DEVICE")).strip().upper()
            if adm != "DEVICE":
                self.logger.info(
                    "[DeviceSync] Skip device id=%s name=%r: accessDataMode=%r (not DEVICE)",
                    dev_id, dev_name, adm,
                )
                continue

            device_mode_devices.append(d)

        self.logger.info(
            "[DeviceSync] device_mode_devices to sync: %d", len(device_mode_devices)
        )

        self._actor_registry.update_devices(device_mode_devices)
        if not device_mode_devices:
            return

        normalized_changed_ids = (
            None
            if changed_ids is None
            else {
                int(member_id)
                for member_id in changed_ids
                if member_id is not None
            }
        )
        if normalized_changed_ids is not None and not normalized_changed_ids:
            progress, _ = self.get_progress_snapshot()
            if not progress.get("running"):
                self._set_progress(running=False, deviceName="", deviceId=None, current=0, total=0)
            self.logger.info("[DeviceSync] delta sync no-op: changed_ids empty -> skip actor dispatch")
            return

        local_fp_index: Dict[str, List[Any]] = {}
        uses_fingerprints = any(
            _boolish(
                d.get("fingerprintEnabled", d.get("fingerprint_enabled")),
                default=False,
            )
            for d in device_mode_devices
        )
        if uses_fingerprints:
            try:
                recs = list_fingerprints()
                for r in recs:
                    pin = _pin_str(getattr(r, "pin", "") or "")
                    if not pin:
                        continue
                    local_fp_index.setdefault(pin, []).append(r)
            except Exception:
                local_fp_index = {}

        default_door_id = self._default_authorize_door_id()
        self._set_actor_dispatch_context(
            users=list(users),
            local_fp_index=local_fp_index,
            default_door_id=default_door_id,
            sync_run_id=sync_run_id,
        )
        self.logger.info(
            "[DeviceSync] _sync_all_devices: total_devices=%d users=%d fp_index_pins=%d "
            "default_door_id=%s changed_ids=%s",
            len(device_mode_devices),
            len(users),
            len(local_fp_index),
            default_door_id,
            len(normalized_changed_ids) if normalized_changed_ids is not None else "all",
        )

        device_ids = {
            int(d.get("id"))
            for d in device_mode_devices
            if d.get("id") is not None
        }
        if normalized_changed_ids is None:
            dispatched = self._actor_registry.enqueue_full_reconcile(device_ids=device_ids)
        else:
            dispatched = self._actor_registry.enqueue_targeted_sync(
                device_ids=device_ids,
                member_ids=set(normalized_changed_ids),
            )
        self._begin_actor_dispatch_progress(dispatched=dispatched)
        self.logger.info(
            "[DeviceSync] dispatched actor sync to %d device workers (changed_ids=%s)",
            dispatched,
            len(normalized_changed_ids) if normalized_changed_ids is not None else "all",
        )
