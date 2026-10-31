"""Optional display-only directory for refused card and QR scans."""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from typing import AbstractSet, Any, Dict, Iterable, Mapping, Optional

from app.core import db

_log = logging.getLogger(__name__)
_lock = threading.RLock()
_refresh_lock = threading.Lock()
_enabled: Optional[bool] = None
_index: Optional[DirectoryIndex] = None
_generation = 0
_wake = threading.Event()
_roster_ready = threading.Event()
_thread: Optional[threading.Thread] = None


@dataclass(frozen=True)
class DirectoryEntry:
    user_id: int
    account_id: Optional[int]
    active_membership_id: Optional[int]
    full_name: str
    image: str
    plan_title: str
    reason_code: Optional[str]
    reason_date: str


@dataclass(frozen=True)
class DirectoryIndex:
    by_card: Dict[str, Optional[DirectoryEntry]]
    by_account: Dict[int, DirectoryEntry]


def normalize_card(raw: Any) -> str:
    card = str(raw if raw is not None else "").strip()
    return card if card.isdigit() else ""


def _build_index(rows) -> DirectoryIndex:
    cards, accounts = {}, {}
    for entry, card_ids in rows:
        for raw in card_ids:
            card = normalize_card(raw)
            if not card:
                continue
            if card not in cards:
                cards[card] = entry
            elif cards[card] is not None and cards[card].user_id != entry.user_id:
                cards[card] = None
        if entry.account_id is not None:
            accounts[entry.account_id] = entry
    return DirectoryIndex(cards, accounts)


def is_enabled() -> bool:
    global _enabled, _index
    if _enabled is None:
        with _lock:
            if _enabled is None:
                enabled = False
                try:
                    with db.get_conn() as conn:
                        state = conn.execute("SELECT enabled FROM refused_info_state WHERE id=1").fetchone()
                        enabled = bool(state and state[0] == 1)
                        if enabled:
                            rows = conn.execute("SELECT * FROM refused_directory").fetchall()
                            _index = _build_index((DirectoryEntry(
                                r["user_id"], r["account_id"], r["active_membership_id"], r["full_name"],
                                r["image"], r["plan_title"], r["reason_code"], r["reason_date"]),
                                json.loads(r["card_ids_json"])) for r in rows)
                except Exception:
                    _index = None
                    enabled = False
                    _log.warning("Refused info state unreadable; defaulting off", exc_info=True)
                _enabled = enabled
    return _enabled is True


def current_index() -> Optional[DirectoryIndex]:
    return _index


def on_heartbeat_response(resp: Mapping[str, Any]) -> None:
    set_enabled(resp.get("refusedInfoEnabled") is True)


def set_enabled(enabled: bool) -> None:
    global _enabled, _index, _generation
    enabled = enabled is True
    with _lock:
        previous = is_enabled()
        # Every heartbeat (5 min) reports the switch; only a change touches the database.
        if enabled == previous:
            return
        def write(conn, _profile):
            conn.execute("INSERT INTO refused_info_state(id, enabled) VALUES(1, ?) "
                         "ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled", (int(enabled),))
            if not enabled:
                conn.execute("DELETE FROM refused_directory")
                conn.execute("UPDATE refused_info_state SET directory_fetched_at=NULL WHERE id=1")
        db._run_db_write_sync("refused_info_switch", write, wait_until_done=True)
        _enabled = enabled
        if not enabled:
            _generation += 1
            _index = None
        if enabled and not previous:
            _wake.set()


def _fetch_directory() -> Mapping[str, Any]:
    from access.config import build_access_api_endpoints
    from app.api.monclub_api import MonClubApi
    from app.core.app_const import API_REFUSED_DIRECTORY_URL
    auth = db.load_auth_token()
    if not auth or not auth.token:
        raise RuntimeError("No gym token for refused directory")
    api = MonClubApi(build_access_api_endpoints(), _log)
    try:
        return api._get_json_dict(url=API_REFUSED_DIRECTORY_URL, token=auth.token,
                                  operation_name="refused_directory", timeout=30)
    finally:
        api._session.close()


def _parse_rows(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
        raise ValueError("Invalid refused directory response")
    rows, seen = [], set()
    for r in payload["rows"]:
        if not isinstance(r, dict) or not isinstance(r.get("userId"), int) or not isinstance(r.get("cardIds"), list):
            raise ValueError("Invalid refused directory row")
        entry = DirectoryEntry(r["userId"], int(r["accountId"]) if r.get("accountId") is not None else None,
                               int(r["activeMembershipId"]) if r.get("activeMembershipId") is not None else None,
                               str(r.get("fullName") or ""), str(r.get("image") or ""),
                               str(r.get("planTitle") or ""), r.get("reasonCode"), str(r.get("reasonDate") or ""))
        if entry.user_id in seen:
            raise ValueError("Duplicate refused directory user")
        seen.add(entry.user_id)
        rows.append((entry, [c for raw in r["cardIds"] if (c := normalize_card(raw))]))
    return rows


def refresh_directory() -> bool:
    global _index
    if not is_enabled():
        return False
    with _refresh_lock:
        with _lock:
            if not is_enabled():
                return False
            generation = _generation
        try:
            payload = _fetch_directory()
            rows = _parse_rows(payload)
            index = _build_index(rows)
            with _lock:
                if not is_enabled() or generation != _generation:
                    return False
                def replace(conn, _profile):
                    conn.execute("DELETE FROM refused_directory")
                    conn.executemany("INSERT INTO refused_directory VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [
                        (e.user_id, e.account_id, e.active_membership_id, e.full_name, e.image,
                         json.dumps(cards), e.plan_title, e.reason_code, e.reason_date) for e, cards in rows])
                    conn.execute("UPDATE refused_info_state SET directory_fetched_at=? WHERE id=1",
                                 (str(payload.get("generatedAt") or ""),))
                db._run_db_write_sync("refused_directory_replace", replace, wait_until_done=True)
                _index = index
            return True
        except Exception:
            _log.warning("Refused directory refresh failed; keeping previous directory", exc_info=True)
            return False


def roster_sync_finished() -> None:
    _roster_ready.set()


def start_background_refresher() -> None:
    global _thread
    with _lock:
        is_enabled()  # Load the persisted switch and directory before scanners start.
        if _thread is not None:
            return
        def run():
            _roster_ready.wait()
            while True:
                _wake.clear()
                if is_enabled():
                    refresh_directory()
                _wake.wait(24 * 60 * 60)
        _thread = threading.Thread(target=run, name="refused-directory", daemon=True)
        _thread.start()


@dataclass(frozen=True)
class HeldIndex:
    by_card: Dict[str, Optional[Mapping[str, Any]]]
    by_account: Dict[int, Mapping[str, Any]]
    entry_limit_held: AbstractSet[int]


@dataclass(frozen=True)
class RefusedInfo:
    reason: str
    reason_date: str
    fields: Dict[str, Any]
    card_no: str


_DIRECTORY_REASONS = frozenset({"MEMBERSHIP_EXPIRED", "MEMBERSHIP_NOT_STARTED", "MEMBERSHIP_FROZEN",
                                "DEBT_DUE_PASSED", "FEE_DUE_PASSED", "PLAN_NO_ENTRY", "PHOTO_REQUIRED",
                                "NOT_ALLOWED_NOW"})


def _int(raw):
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _same_user(a, b):
    return a.get("userId") is not None and a.get("userId") == b.get("userId")


def build_held_index(held_rows: Iterable[Mapping[str, Any]], entry_limit_held: AbstractSet[int]) -> HeldIndex:
    cards, accounts = {}, {}
    for raw in held_rows:
        # Accept the stored columns as well as the existing payload projection.
        row = dict(raw)
        for src, dst in (("user_id", "userId"), ("active_membership_id", "activeMembershipId"),
                         ("main_account_id", "mainAccountId"), ("full_name", "fullName"),
                         ("membership_id", "membershipId"), ("valid_from", "validFrom"), ("valid_to", "validTo"),
                         ("first_card_id", "firstCardId"), ("second_card_id", "secondCardId"), ("held_reason", "heldReason")):
            if src in row:
                row[dst] = row[src]
        for raw_card in (row.get("firstCardId"), row.get("secondCardId")):
            card = normalize_card(raw_card)
            if card:
                if card not in cards:
                    cards[card] = row
                elif cards[card] is not None and not _same_user(cards[card], row):
                    cards[card] = None
        account = _int(row.get("mainAccountId", row.get("accountId")))
        if account is not None:
            accounts[account] = row
    return HeldIndex(cards, accounts, frozenset(entry_limit_held))


def load_held_index() -> HeldIndex:
    """Called only by the ULTRA background cache refresher."""
    rows = db._list_held_users_for_roster(set())
    snap = db.load_access_days_snapshot()
    return build_held_index(rows, snap.entry_limit_held if snap is not None else frozenset())


def _collision() -> RefusedInfo:
    return RefusedInfo("DENY_CARD_COLLISION", "", {}, "")


def _roster_info(rows, current_reason):
    from app.core.ultra_pc_entry import member_popup_fields
    if isinstance(rows, Mapping):
        rows = [rows]
    if not rows:
        return None
    first = rows[0]
    if any(not _same_user(first, row) for row in rows[1:]):
        return _collision()
    return RefusedInfo(current_reason, "", member_popup_fields(first), "")


def _directory_for_held(row):
    index = current_index()
    if index:
        candidates = (index.by_account.get(_int(row.get("mainAccountId", row.get("accountId")))),
                      index.by_card.get(normalize_card(row.get("firstCardId"))),
                      index.by_card.get(normalize_card(row.get("secondCardId"))))
        for entry in candidates:
            if entry is not None and entry.user_id == row.get("userId"):
                return entry
    return None


def _held_info(row, index):
    from app.core.ultra_pc_entry import member_popup_fields
    reason = row.get("heldReason")
    date = ""
    if reason == "expired":
        code, date = "MEMBERSHIP_EXPIRED", str(row.get("validTo") or "")[:10]
    elif reason == "not_started":
        code, date = "MEMBERSHIP_NOT_STARTED", str(row.get("validFrom") or "")[:10]
    elif reason == "frozen":
        code = "MEMBERSHIP_FROZEN"
        entry = _directory_for_held(row)
        if entry is not None and entry.reason_code == code:
            date = entry.reason_date
    elif reason == "off_hours":
        code = "ENTRY_LIMIT" if _int(row.get("activeMembershipId")) in index.entry_limit_held else "OFF_HOURS"
    else:
        return None
    return RefusedInfo(code, date, member_popup_fields(dict(row)), "")


def _directory_info(entry):
    return RefusedInfo(entry.reason_code if entry.reason_code in _DIRECTORY_REASONS else "NOT_ALLOWED_NOW",
                       entry.reason_date,
                       dict(user_full_name=entry.full_name, user_image=entry.image, user_membership_title=entry.plan_title,
                            user_id=entry.user_id, user_membership_id=entry.active_membership_id), "")


def resolve_card(card_no: str, *, users_by_card, held_index, current_reason: str) -> Optional[RefusedInfo]:
    if not is_enabled() or not (card := normalize_card(card_no)):
        return None
    info = _roster_info(users_by_card.get(card), current_reason)
    if info is not None:
        return info
    if held_index and card in held_index.by_card:
        row = held_index.by_card[card]
        if row is None:
            return _collision()
        info = _held_info(row, held_index)
        if info is not None:
            return info
    index = current_index()
    if index and card in index.by_card:
        entry = index.by_card[card]
        return _collision() if entry is None else _directory_info(entry)
    return RefusedInfo("DENY_NO_CARD_MATCH", "", {}, card)


def resolve_account(account_id: Any, *, users_by_am, held_index, current_reason: str) -> Optional[RefusedInfo]:
    if not is_enabled() or (account := _int(account_id)) is None:
        return None
    info = _roster_info([u for u in users_by_am.values()
                         if _int(u.get("mainAccountId", u.get("accountId"))) == account], current_reason)
    if info is not None:
        return info
    if held_index and account in held_index.by_account:
        info = _held_info(held_index.by_account[account], held_index)
        if info is not None:
            return info
    index = current_index()
    entry = index.by_account.get(account) if index else None
    return _directory_info(entry) if entry is not None else None


def is_card_scan(card_no, raw_row) -> bool:
    from app.core.ultra_pc_entry import reported_card
    hint = str((raw_row or {}).get("scan_mode_hint") or "").upper()
    return hint in ("", "CARD", "RFID_CARD") and bool(reported_card(card_no, raw_row))


def verification_account(result, creds, totp_index, code):
    """Recover display identity from a matched refusal; never reverify a QR or change its verdict."""
    account = _int(result.get("accountId"))
    if account is not None:
        return account
    cred_id = result.get("credId")
    if isinstance(totp_index, dict) and (cred_id is not None or result.get("reason") == "DENY_AMBIGUOUS_COUNTER"):
        digits = totp_index.get("params", (30, 1, 7, "9"))[2]
        hits = (totp_index.get("index") or {}).get(str(code)[-digits:], [])
        matches = [h for h in hits if cred_id is None or str(h.get("credId")) == str(cred_id)]
        if len({str(h.get("credId")) for h in matches}) == 1:
            accounts = {_int(h.get("accountId")) for h in matches}
            if len(accounts) == 1:
                return next(iter(accounts))
    if cred_id is not None:
        accounts = {_int(c.get("accountId")) for c in creds
                    if isinstance(c, Mapping) and str(c.get("id")) == str(cred_id)}
        if len(accounts) == 1:
            return next(iter(accounts))
    return None
