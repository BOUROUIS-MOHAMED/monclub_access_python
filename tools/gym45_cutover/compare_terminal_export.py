"""Compare MB2000 terminal exports with what MonClub knows -- read-only, aggregates first.

Inputs (every one is read, nothing is ever written back):

* one or more terminal exports made by
  ``tools/mb2000_scripts/14_export_terminal_readonly.ps1`` (``--export 8=FILE``,
  ``--export 10=FILE``: the number is the MonClub device id of that terminal);
* optionally a COPY of the driver PC's ``access.db`` (``--access-db``). The file is
  copied again into a temporary folder and opened there with ``PRAGMA query_only``,
  so the copy you pass is not touched either. It gives the roster MonClub delivers to
  that PC (``sync_users``, with the templates MonClub would push), and which pins
  MonClub can prove it wrote (``device_sync_state.ownership_confirmed``);
* optionally a MySQL copy of the backend database (``--mysql-*``), queried inside a
  ``READ ONLY`` transaction with SELECT statements only. ``wigo-db`` is refused by
  name: it is the unscrubbed production copy.

Output: aggregate counts only, on stdout (and ``--json-out``). ``--detail-csv`` adds
one row per affected person or leftover terminal user, with names -- personal data,
so it is off unless asked for, and the file stays on the machine it was run on.

What the numbers mean is in tools/gym45_cutover/README.md. The questions it answers:

1. Which terminal users are MonClub members under the terminal's current pin scheme,
   which are MonClub pins no longer on the roster, and which are leftovers.
2. Which current members have a finger ONLY on the terminal (not in MonClub) -- they
   would lose it in a wipe -- and whether each such finger can be tied to the person.
3. For an ACCOUNT switch without a wipe: how many account pins would land on a pin the
   terminal already holds (the reason the wipe comes first).
4. Which current members have a card on the terminal that MonClub will not push -- they
   are refused by card after an erase until their card is sorted out at the desk. Only a
   row's first card (firstCardId) reaches a terminal, so that is the card compared, in
   the form each device type is sent it:
   - a PullSDK panel (C3): device_sync._normalize_device_card -- digits only, and nothing
     outside 1..4294967295 (the 4-byte CardNo) -- see ``wire_card``;
   - an MB2000: the standalone roster passes firstCardId raw
     (ultra_engine._build_standalone_roster) and the driver keeps its digits with no range
     check (zk_standalone._digits_only before SetStrCardNumber) -- see ``mb2000_card``.
     What an MB2000 stores for a value above the 4-byte range is not proven anywhere.
   Whether a panel returns CardNo in the form it was written is not proven either, so
   the report measures it first (``card self-check``) on the pins MonClub owns, the way
   the ``sha self-check`` measures templates. A low rate means the cards list is an
   artefact and must not be acted on.

It reads the MB2000 export (tools/mb2000_scripts/14_export_terminal_readonly.ps1) and the
PullSDK panel export (tools/c3_panel_scripts/export_c3_panel_readonly.ps1, no finger slots).

Template identity is SHA-256 of the decoded template bytes on both sides. Whether an
MB2000 returns, byte for byte, the template MonClub wrote is not proven anywhere; the
report therefore measures it first (``sha self-check``) on pins MonClub owns, and a
low rate means the per-finger answers fall back to finger numbers only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

EXPORT_SCHEMA = "monclub.mb2000.terminal_export/1"
PANEL_EXPORT_SCHEMA = "monclub.pullsdk.panel_export/1"
EXPORT_SCHEMAS = (EXPORT_SCHEMA, PANEL_EXPORT_SCHEMA)
REFUSED_DATABASES = {"wigo-db"}
SCHEMES = ("MEMBERSHIP", "ACCOUNT")


# --------------------------------------------------------------------------- helpers

def template_sha256(text: Any, encoding: Any = None) -> Optional[str]:
    """SHA-256 of a template's DECODED bytes, or None when it does not decode.

    HEX is decoded as tolerantly as ``device_sync._template_wire`` (``0x`` prefix and
    embedded whitespace accepted); anything else is treated as base64, which is what
    both device wires carry. Mirrors the export script's ``Get-TemplateDigest`` for the
    base64 case, so the two sides hash the same bytes.
    """
    if text is None:
        return None
    s = str(text)
    if not s.strip():
        return None
    enc = str(encoding or "").strip().upper()
    try:
        if enc == "HEX":
            cleaned = "".join(s.split())
            if cleaned[:2].lower() == "0x":
                cleaned = cleaned[2:]
            raw = binascii.unhexlify(cleaned)
        else:
            raw = base64.b64decode("".join(s.split()), validate=True)
    except (binascii.Error, ValueError):
        return None
    return hashlib.sha256(raw).hexdigest()


def norm_card(card: Any) -> str:
    """Digits only, leading zeros dropped; '' for no card (the terminal says '0')."""
    digits = re.sub(r"\D", "", str(card or ""))
    digits = digits.lstrip("0")
    return digits


def wire_card(card: Any) -> str:
    """The card MonClub writes to a terminal for this value: device_sync._normalize_device_card
    (digits only, 1..4294967295), in norm_card's form; '' when nothing is written."""
    digits = "".join(ch for ch in str(card or "") if ch.isdigit())  # str.isdigit, as the push
    if not digits:
        return ""
    try:
        n = int(digits)
    except ValueError:                  # e.g. superscript digits: isdigit() but not int()
        return ""
    return str(n) if 1 <= n <= 4294967295 else ""


def mb2000_card(card: Any) -> str:
    """The card MonClub writes to an MB2000 for this value: zk_standalone._digits_only on the
    raw firstCardId (no range check), in norm_card's form (leading zeros dropped); '' when
    nothing is written."""
    return "".join(ch for ch in str(card or "") if ch.isdigit()).lstrip("0")  # str.isdigit, as the driver


def card_rule(schema: Optional[str]):
    """The function that gives, for a MonClub firstCardId, the card that export's device type
    is sent: ``mb2000_card`` for an MB2000 export, ``wire_card`` for a PullSDK panel export."""
    return mb2000_card if schema == EXPORT_SCHEMA else wire_card


def no_monclub_card(card: Any) -> bool:
    """True when MonClub holds no card at all in this slot: empty, blank, or only zeros."""
    return str(card or "").strip().strip("0") == ""


def norm_pin(pin: Any) -> str:
    """A terminal pin or a GMS card id as a comparable key: digits without leading
    zeros when it is numeric, else the trimmed text."""
    s = str(pin or "").strip()
    return str(int(s)) if s.isdigit() else s


def norm_name(name: Any) -> str:
    s = unicodedata.normalize("NFKD", str(name or ""))
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^0-9a-z]+", " ", s.casefold())
    return " ".join(s.split())


def names_match(terminal_name: str, monclub_name: str) -> bool:
    """Weak evidence only. MonClub writes name[:24] to the MB2000, so a 24-character
    terminal name may be the start of a longer MonClub name."""
    t, m = norm_name(terminal_name), norm_name(monclub_name)
    if len(t) < 5 or not m:
        return False
    if t == m:
        return True
    return len(str(terminal_name or "")) >= 24 and m.startswith(t)


def _int_or_none(v: Any) -> Optional[int]:
    try:
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        return int(v)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- inputs

@dataclass(frozen=True)
class Slot:
    finger_id: int
    sha256: Optional[str]
    size: Optional[int]
    hashed_as: Optional[str]


@dataclass
class TerminalUser:
    pin: str                     # as the terminal returned it (shown in the detail CSV)
    name: str
    card: str
    privilege: int
    enabled: bool
    has_password: bool
    slots: Optional[List[Slot]]  # None = finger slots were not read

    @property
    def key(self) -> str:
        """The pin as every comparison uses it (norm_pin), whatever padding the terminal
        returned it with."""
        return norm_pin(self.pin)


@dataclass
class TerminalExport:
    device_id: int
    label: str
    path: str
    complete: bool
    fingers_read: bool
    fp_version: Optional[str]
    counters: Dict[int, int]
    users: List[TerminalUser]
    taken_at: str
    schema: str = EXPORT_SCHEMA  # which export tool wrote it: decides the card rule (card_rule)


def load_export(path: str, device_id: int) -> TerminalExport:
    with open(path, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    if doc.get("schema") not in EXPORT_SCHEMAS:
        raise ValueError(f"{path}: not a terminal export (schema={doc.get('schema')!r})")
    fingers_read = bool((doc.get("options") or {}).get("fingers"))
    users: List[TerminalUser] = []
    for u in doc.get("users") or []:
        slots = None
        if fingers_read:
            slots = []
            for s in u.get("slots") or []:
                slots.append(Slot(
                    finger_id=int(s["fingerId"]),
                    sha256=s.get("sha256") if s.get("hashedAs") == "base64" else None,
                    size=_int_or_none(s.get("size")),
                    hashed_as=s.get("hashedAs"),
                ))
        users.append(TerminalUser(
            pin=str(u.get("pin") or "").strip(),
            name=str(u.get("name") or ""),
            card=str(u.get("card") or ""),
            privilege=int(u.get("privilege") or 0),
            enabled=bool(u.get("enabled", True)),
            has_password=bool(u.get("hasPassword", False)),
            slots=slots,
        ))
    counters = {}
    for k, v in (doc.get("counters") or {}).items():
        val = v.get("value") if isinstance(v, dict) else v
        if _int_or_none(k) is not None and _int_or_none(val) is not None:
            counters[int(k)] = int(val)
    return TerminalExport(
        device_id=device_id,
        label=str((doc.get("device") or {}).get("label") or ""),
        path=path,
        complete=bool(doc.get("complete")),
        fingers_read=fingers_read,
        fp_version=(doc.get("device") or {}).get("fpVersion"),
        counters=counters,
        users=users,
        taken_at=str(doc.get("takenAt") or ""),
        schema=str(doc.get("schema")),
    )


@dataclass(frozen=True)
class MonClubTemplate:
    finger_id: int
    sha256: Optional[str]
    template_version: Optional[int]


@dataclass
class MonClubRow:
    """One deliverable membership row, as the driver PC holds it (sync_users)."""
    membership_id: Optional[int]
    main_account_id: Optional[int]
    user_id: Optional[int]
    name: str
    cards: Set[str]
    templates: List[MonClubTemplate]
    first_card: str = ""         # wire_card(firstCardId): the one card MonClub pushes to a PullSDK panel
    first_card_raw: str = ""     # firstCardId as MonClub holds it (card_rule turns it into what a device gets)

    def person_key(self) -> str:
        if self.main_account_id is not None:
            return f"A{self.main_account_id}"
        if self.user_id is not None:
            return f"U{self.user_id}"
        return f"M{self.membership_id}"

    def pin(self, scheme: str) -> Optional[str]:
        """device_sync.derive_member_pin, for the two schemes."""
        if scheme == "ACCOUNT":
            return str(self.main_account_id) if self.main_account_id is not None else None
        if self.membership_id is not None:
            return str(self.membership_id)
        return str(self.user_id) if self.user_id is not None else None


@dataclass
class OwnState:
    ownership_confirmed: bool
    pushed_finger_ids: Optional[str]
    last_ok: bool


@dataclass
class AccessDb:
    rows: List[MonClubRow]
    ownership: Optional[Dict[int, Dict[str, OwnState]]]  # None: this client version records none
    intents: Dict[int, Set[str]]
    pin_scheme: Dict[int, Optional[str]]
    rows_without_account: int


def _open_copy(path: str) -> Tuple[sqlite3.Connection, str]:
    """Copy the database (and its -wal/-shm) into a temp folder and open THAT copy
    query-only, so neither the gym PC's file nor the copy handed to us is modified."""
    tmp = tempfile.mkdtemp(prefix="gym45_accessdb_")
    base = Path(path)
    dst = Path(tmp) / base.name
    shutil.copy2(base, dst)
    for suffix in ("-wal", "-shm"):
        side = Path(str(base) + suffix)
        if side.exists():
            shutil.copy2(side, Path(str(dst) + suffix))
    conn = sqlite3.connect(str(dst))
    conn.execute("PRAGMA query_only = ON")
    return conn, tmp


def _columns(conn: sqlite3.Connection, table: str) -> Set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def load_access_db(path: str) -> AccessDb:
    conn, tmp = _open_copy(path)
    try:
        cols = _columns(conn, "sync_users")
        mac = "main_account_id" if "main_account_id" in cols else "NULL"
        rows: List[MonClubRow] = []
        without_account = 0
        for user_id, am_id, main_acc, full_name, c1, c2, fps_json in conn.execute(
            f"SELECT user_id, active_membership_id, {mac}, full_name, first_card_id, "
            f"second_card_id, fingerprints_json FROM sync_users"
        ):
            templates: List[MonClubTemplate] = []
            try:
                fps = json.loads(fps_json or "[]")
            except ValueError:
                fps = []
            for fp in fps if isinstance(fps, list) else []:
                if not isinstance(fp, dict):
                    continue
                if str(fp.get("enabled", True)).strip().lower() in ("false", "0", "off", "no"):
                    continue
                fid = _int_or_none(fp.get("fingerId"))
                if fid is None:
                    continue
                templates.append(MonClubTemplate(
                    finger_id=fid,
                    sha256=template_sha256(fp.get("templateData"), fp.get("templateEncoding")),
                    template_version=_int_or_none(fp.get("templateVersion")),
                ))
            main_acc = _int_or_none(main_acc)
            if main_acc is None:
                without_account += 1
            rows.append(MonClubRow(
                membership_id=_int_or_none(am_id),
                main_account_id=main_acc,
                user_id=_int_or_none(user_id),
                name=str(full_name or ""),
                cards={c for c in (norm_card(c1), norm_card(c2)) if c},
                templates=templates,
                first_card=wire_card(c1),
                first_card_raw=str(c1 or "").strip(),
            ))
        # A client older than the ownership bit (ownership_confirmed) records none: that is
        # "unknown", never "nobody owns anything".
        ownership: Optional[Dict[int, Dict[str, OwnState]]] = None
        dcols = _columns(conn, "device_sync_state")
        if "ownership_confirmed" in dcols:
            ownership = defaultdict(dict)
            pf = "pushed_finger_ids" if "pushed_finger_ids" in dcols else "NULL"
            for dev, pin, owned, pushed, last_ok in conn.execute(
                f"SELECT device_id, pin, ownership_confirmed, {pf}, last_ok FROM device_sync_state"
            ):
                ownership[int(dev)][norm_pin(pin)] = OwnState(bool(owned), pushed, bool(last_ok))
            ownership = dict(ownership)
        intents: Dict[int, Set[str]] = defaultdict(set)
        if "device_id" in _columns(conn, "device_push_intent"):
            for dev, pin in conn.execute("SELECT device_id, pin FROM device_push_intent"):
                intents[int(dev)].add(norm_pin(pin))
        pin_scheme: Dict[int, Optional[str]] = {}
        if "pin_scheme" in _columns(conn, "sync_devices"):
            for dev, scheme in conn.execute("SELECT id, pin_scheme FROM sync_devices"):
                if dev is not None:
                    pin_scheme[int(dev)] = scheme
        return AccessDb(rows, ownership, dict(intents), pin_scheme, without_account)
    finally:
        conn.close()
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- backend

@dataclass
class BackendSnapshot:
    """What the backend database knows about the gym (SELECT-only, see load_backend_snapshot).

    ``deliverable_rows`` approximates the roster the backend delivers on ``day``: the
    date/status/plan/permission/freeze filters of findAllValidForAccessByGym* and
    AccessDeliverability, WITHOUT the photo and unpaid-due rules (gym 45 had both off
    on 2026-09-12) and without the per-gym fingerprint enrolment gate. A copy of the
    driver PC's access.db (--access-db) is the exact roster; this is the fallback.
    """
    gym_id: int
    day: str
    deliverable_rows: List[MonClubRow]
    membership_ids: Set[int]                   # every membership sold on the gym's plans
    account_of_membership: Dict[int, Optional[int]]
    templates_by_sha: Dict[str, Set[int]]      # sha256 of template bytes -> account ids
    gms_person_account: Dict[str, int]         # GMS card id (migration link) -> account id
    notes: List[str] = field(default_factory=list)


_SQL_MEMBERSHIPS = """
SELECT am.id, um.account_id
FROM active_membership am
JOIN membership_model mm ON mm.id = am.membership_id
JOIN gym_agent ga ON ga.id = mm.gym_agent_id
LEFT JOIN user_model um ON um.id = am.user_id
WHERE ga.gym = %(gym)s
"""

_SQL_DELIVERABLE = """
SELECT am.id, um.account_id, am.user_id, am.card_id, am.second_card_id
FROM active_membership am
JOIN membership_model mm ON mm.id = am.membership_id
JOIN gym_agent ga ON ga.id = mm.gym_agent_id
JOIN gym_model g ON g.id = ga.gym
LEFT JOIN user_model um ON um.id = am.user_id
WHERE (ga.gym = %(gym)s
       OR (g.gym_family_id IS NOT NULL
           AND g.gym_family_id = (SELECT g2.gym_family_id FROM gym_model g2 WHERE g2.id = %(gym)s)))
  AND am.available = 1 AND am.status = 'ACTIVE' AND mm.available = 1
  AND am.start_date <= %(day)s AND COALESCE(am.effective_end_date, am.end_date) >= %(day)s
  AND am.user_id IS NOT NULL
  AND (ga.gym = %(gym)s
       OR (mm.gym_family_access = 1 AND EXISTS (
            SELECT 1 FROM membership_shared_gyms msg
            WHERE msg.membership_id = mm.id AND msg.gym_id = %(gym)s)))
  AND NOT EXISTS (
       SELECT 1 FROM active_membership_freeze f
       WHERE f.active_membership_id = am.id AND f.cancelled = 0
         AND f.start_freeze_date <= %(day)s AND %(day)s < f.end_freeze_date)
"""

# The template is hashed INSIDE MySQL: template bytes never leave the database.
_SQL_TEMPLATES = """
SELECT uf.finger_id, uf.template_version, uf.enabled + 0, uf.active_membership_id,
       COALESCE(uf.main_account_id, um.account_id), LOWER(SHA2(uf.template_bytes, 256))
FROM user_fingerprint uf
LEFT JOIN active_membership am ON am.id = uf.active_membership_id
LEFT JOIN user_model um ON um.id = am.user_id
WHERE uf.template_bytes IS NOT NULL
  AND (uf.active_membership_id IN (
         SELECT am2.id FROM active_membership am2
         JOIN membership_model mm2 ON mm2.id = am2.membership_id
         JOIN gym_agent ga2 ON ga2.id = mm2.gym_agent_id
         WHERE ga2.gym = %(gym)s)
       OR uf.main_account_id IN (
         SELECT um3.account_id FROM active_membership am3
         JOIN membership_model mm3 ON mm3.id = am3.membership_id
         JOIN gym_agent ga3 ON ga3.id = mm3.gym_agent_id
         JOIN user_model um3 ON um3.id = am3.user_id
         WHERE ga3.gym = %(gym)s))
"""

_SQL_GMS_PERSONS = """
SELECT l.source_key, um.account_id
FROM migration_entity_link_gms l
JOIN user_model um ON um.id = l.target_id
WHERE l.gym_id = %(gym)s AND l.entity_type = 'PERSON'
"""


def _select(cur: Any, sql: str, params: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    """The only way this tool sends a query: SELECT or nothing."""
    if not sql.lstrip().upper().startswith("SELECT"):
        raise ValueError("refused: this tool only runs SELECT statements")
    cur.execute(sql, params)
    return list(cur.fetchall())


def snapshot_from_rows(
    gym_id: int,
    day: str,
    memberships: Iterable[Tuple[Any, ...]],
    deliverable: Iterable[Tuple[Any, ...]],
    templates: Iterable[Tuple[Any, ...]],
    gms_persons: Iterable[Tuple[Any, ...]],
) -> BackendSnapshot:
    """Turn the four result sets into a snapshot (pure, so it is testable without MySQL)."""
    membership_ids: Set[int] = set()
    account_of: Dict[int, Optional[int]] = {}
    for am_id, acct in memberships:
        membership_ids.add(int(am_id))
        account_of[int(am_id)] = _int_or_none(acct)
    by_am: Dict[int, List[MonClubTemplate]] = defaultdict(list)
    by_acct: Dict[int, List[MonClubTemplate]] = defaultdict(list)
    templates_by_sha: Dict[str, Set[int]] = defaultdict(set)
    for fid, version, enabled, am_id, acct, sha in templates:
        t = MonClubTemplate(finger_id=int(fid), sha256=(str(sha).lower() if sha else None),
                            template_version=_int_or_none(version))
        if t.sha256 and _int_or_none(acct) is not None:
            templates_by_sha[t.sha256].add(int(acct))
        if not int(enabled or 0):
            continue
        if _int_or_none(am_id) is not None:
            by_am[int(am_id)].append(t)
        if _int_or_none(acct) is not None:
            by_acct[int(acct)].append(t)
    rows: List[MonClubRow] = []
    for am_id, acct, user_id, c1, c2 in deliverable:
        am_id, acct = int(am_id), _int_or_none(acct)
        seen: Set[Tuple[int, Optional[str]]] = set()
        tpl: List[MonClubTemplate] = []
        for t in by_am.get(am_id, []) + (by_acct.get(acct, []) if acct is not None else []):
            if (t.finger_id, t.sha256) not in seen:
                seen.add((t.finger_id, t.sha256))
                tpl.append(t)
        rows.append(MonClubRow(
            membership_id=am_id, main_account_id=acct, user_id=_int_or_none(user_id), name="",
            cards={c for c in (norm_card(c1), norm_card(c2)) if c}, templates=tpl,
            first_card=wire_card(c1), first_card_raw=str(c1 or "").strip(),
        ))
    gms = {norm_pin(k): int(a) for k, a in gms_persons if k is not None and _int_or_none(a) is not None}
    notes = [
        "deliverable roster approximated in SQL: no photo rule, no unpaid-due rule, no per-gym "
        "fingerprint enrolment gate; --access-db gives the exact roster",
    ]
    return BackendSnapshot(gym_id, day, rows, membership_ids, account_of, dict(templates_by_sha), gms, notes)


def load_backend_snapshot(*, host: str, port: int, db: str, user: str, password: str,
                          gym_id: int, day: str) -> BackendSnapshot:
    """SELECT-only, inside a READ ONLY transaction that is rolled back. Needs pymysql."""
    if (db or "").strip().lower() in REFUSED_DATABASES:
        raise ValueError(f"refused: {db} is the unscrubbed production copy")
    import pymysql  # optional dependency, only for this path

    conn = pymysql.connect(host=host, port=port, user=user, password=password, database=db,
                           charset="utf8mb4", autocommit=False)
    try:
        with conn.cursor() as cur:
            cur.execute("SET SESSION TRANSACTION READ ONLY")
            cur.execute("START TRANSACTION READ ONLY")
            params = {"gym": gym_id, "day": day}
            snap = snapshot_from_rows(
                gym_id, day,
                _select(cur, _SQL_MEMBERSHIPS, params),
                _select(cur, _SQL_DELIVERABLE, params),
                _select(cur, _SQL_TEMPLATES, params),
                _select(cur, _SQL_GMS_PERSONS, params),
            )
        conn.rollback()
        return snap
    finally:
        conn.close()


# --------------------------------------------------------------------------- analysis

@dataclass
class DetailRow:
    kind: str
    device_id: Optional[int]
    pin: Optional[str]
    person: Optional[str]
    name: str
    fingers: str
    link: str
    note: str


def _persons(rows: Iterable[MonClubRow]) -> Dict[str, List[MonClubRow]]:
    out: Dict[str, List[MonClubRow]] = defaultdict(list)
    for r in rows:
        out[r.person_key()].append(r)
    return dict(out)


SHA_TRUST_THRESHOLD = 0.9
# The ways a terminal user that is not a MonClub pin can be tied to a current member,
# strongest first. Only the first four are used to count lost fingers; a name is a hint.
LINK_KINDS = ("template", "gms_id", "card", "pin_is_card", "name_only")
STRONG_LINKS = ("template", "gms_id", "card", "pin_is_card")


def sha_self_check(
    exports: List[TerminalExport],
    rows: List[MonClubRow],
    ownership: Optional[Dict[int, Dict[str, OwnState]]],
    scheme: str,
) -> Counter:
    """On member pins -- the ones MonClub OWNS, when ownership is known -- how many
    terminal slots carry exactly the template bytes MonClub holds for that finger.
    It is what licenses matching fingers by template hash at all."""
    out: Counter = Counter()
    by_pin: Dict[str, Dict[int, Optional[str]]] = defaultdict(dict)
    for r in rows:
        p = r.pin(scheme)
        if p is None:
            continue
        for t in r.templates:
            by_pin[p][t.finger_id] = t.sha256
    for ex in exports:
        own = ownership.get(ex.device_id, {}) if ownership is not None else None
        for u in ex.users:
            if u.key not in by_pin:
                continue
            if own is not None:
                st = own.get(u.key)
                if not (st and st.ownership_confirmed):
                    continue
            for s in u.slots or []:
                mine = by_pin[u.key].get(s.finger_id)
                if s.sha256 and mine:
                    out["compared"] += 1
                    out["equal"] += int(s.sha256 == mine)
    return out


CARD_TRUST_THRESHOLD = 0.9


def card_self_check(
    exports: List[TerminalExport],
    rows: List[MonClubRow],
    ownership: Optional[Dict[int, Dict[str, OwnState]]],
    scheme: str,
) -> Counter:
    """On member pins -- the ones MonClub OWNS, when ownership is known -- that MonClub sends
    a card, how many terminal users carry exactly that card (norm_card of what the device
    returned == the card_rule value of firstCardId). It is what licenses reading the ``cards``
    section as losses at all: a device that returns CardNo in another form than the decimal
    MonClub wrote (hex, a facility/card split, another width) would make every member with a
    card look like one."""
    out: Counter = Counter()
    for ex in exports:
        rule = card_rule(ex.schema)
        want: Dict[str, Set[str]] = defaultdict(set)
        for r in rows:
            p = r.pin(scheme)
            c = rule(r.first_card_raw)
            if p is not None and c:
                want[p].add(c)
        own = ownership.get(ex.device_id, {}) if ownership is not None else None
        for u in ex.users:
            if u.key not in want:
                continue
            if own is not None:
                st = own.get(u.key)
                if not (st and st.ownership_confirmed):
                    continue
            out["compared"] += 1
            out["equal"] += int(norm_card(u.card) in want[u.key])
    return out


def analyse(
    exports: List[TerminalExport],
    access: Optional[AccessDb],
    backend: Optional[BackendSnapshot] = None,
    *,
    scheme: str = "MEMBERSHIP",
    match_by: str = "auto",
) -> Tuple[Dict[str, Any], List[DetailRow]]:
    if scheme not in SCHEMES:
        raise ValueError(scheme)
    kinds = sorted({ex.schema for ex in exports})
    if len(kinds) > 1:
        # the card rule differs by device type; the people counts are gym-wide
        raise ValueError(f"exports of two kinds in one run ({', '.join(kinds)}): compare each kind separately")
    rule = card_rule(kinds[0] if kinds else None)
    device_word = "a panel" if rule is wire_card else "the terminal"
    report: Dict[str, Any] = {"scheme_assumed_on_terminal": scheme, "devices": {}, "notes": []}
    details: List[DetailRow] = []

    if access is not None:
        rows, ownership, roster_source = access.rows, access.ownership, "access.db"
    elif backend is not None:
        rows, ownership, roster_source = backend.deliverable_rows, None, f"backend SQL on {backend.day}"
    else:
        rows, ownership, roster_source = [], None, "none"
    report["roster_source"] = roster_source
    report["ownership_known"] = ownership is not None

    check = sha_self_check(exports, rows, ownership, scheme)
    rate = (check["equal"] / check["compared"]) if check["compared"] else None
    if match_by == "auto":
        match_by = "sha" if rate is not None and rate >= SHA_TRUST_THRESHOLD else "finger"
    report["sha_self_check"] = {"compared": check["compared"], "equal": check["equal"],
                                "rate": None if rate is None else round(rate, 4)}
    report["finger_match_mode"] = match_by
    use_sha = match_by == "sha"

    persons = _persons(rows)
    pin_to_person: Dict[str, str] = {}
    for key, prow in persons.items():
        for r in prow:
            p = r.pin(scheme)
            if p is not None:
                pin_to_person[p] = key
    person_shas: Dict[str, Set[str]] = {
        k: {t.sha256 for r in v for t in r.templates if t.sha256} for k, v in persons.items()
    }
    person_fingers: Dict[str, Set[int]] = {
        k: {t.finger_id for r in v for t in r.templates} for k, v in persons.items()
    }
    sha_to_persons: Dict[str, Set[str]] = defaultdict(set)
    for k, shas in person_shas.items():
        for s in shas:
            sha_to_persons[s].add(k)
    card_to_persons: Dict[str, Set[str]] = defaultdict(set)
    for k, v in persons.items():
        for r in v:
            for c in r.cards:
                card_to_persons[c].add(k)
    names = {k: v[0].name for k, v in persons.items() if v[0].name}
    gms = backend.gms_person_account if backend is not None else {}
    all_shas = backend.templates_by_sha if backend is not None else {}

    # per person, across all terminals: fingers seen on a terminal and where
    linked_slots: Dict[str, List[Tuple[int, str, int, Optional[str], str]]] = defaultdict(list)
    # ... and cards seen on a terminal, and where
    linked_cards: Dict[str, List[Tuple[int, str, str, str]]] = defaultdict(list)

    for ex in exports:
        dev: Dict[str, Any] = {
            "label": ex.label,
            "complete": ex.complete,
            "fingers_read": ex.fingers_read,
            "fp_version": ex.fp_version,
            "counters": {str(k): v for k, v in sorted(ex.counters.items())},
            "terminal_users": len(ex.users),
            "privileged": sum(1 for u in ex.users if u.privilege > 0),
            "disabled": sum(1 for u in ex.users if not u.enabled),
            "with_card": sum(1 for u in ex.users if norm_card(u.card)),
            "with_password": sum(1 for u in ex.users if u.has_password),
        }
        if ex.fingers_read:
            dev["users_with_slots"] = sum(1 for u in ex.users if u.slots)
            dev["slots"] = sum(len(u.slots or []) for u in ex.users)
            dev["slots_not_base64"] = sum(1 for u in ex.users for s in (u.slots or []) if s.hashed_as != "base64")
        if access is not None:
            # what this PC last recorded for the device: None = the column or the value is
            # absent (an old client, or a backend that does not send pinScheme)
            dev["pc_pin_scheme"] = access.pin_scheme.get(ex.device_id)
        own = ownership.get(ex.device_id, {}) if ownership is not None else None
        intents = access.intents.get(ex.device_id, set()) if access is not None else set()
        classes: Counter = Counter()
        leftover = Counter()
        pins_on_terminal = {u.key for u in ex.users}
        dev["pins_not_in_canonical_form"] = sum(1 for u in ex.users if u.key != u.pin.strip())
        for u in ex.users:
            person = pin_to_person.get(u.key)
            if own is None:
                owned = None
                cls = "member" if person is not None else None
            else:
                st = own.get(u.key)
                owned = bool(st and st.ownership_confirmed)
                if person is not None:
                    cls = "member_owned" if owned else "member_not_owned"
                elif owned:
                    cls = "departed_owned"
                elif u.key in intents:
                    cls = "intent_only"
                else:
                    cls = None
            if cls is None:
                if (backend is not None and scheme == "MEMBERSHIP"
                        and _int_or_none(u.key) in backend.membership_ids):
                    cls = "past_membership"
                else:
                    cls = "leftover"
            classes[cls] += 1

            slots = u.slots or []
            if person is not None:
                for s in slots:
                    linked_slots[person].append((ex.device_id, u.pin, s.finger_id, s.sha256, "own_pin"))
                if norm_card(u.card):
                    linked_cards[person].append((ex.device_id, u.pin, norm_card(u.card), "own_pin"))
                continue
            if cls in ("departed_owned", "intent_only"):
                continue

            # not a current member's pin: can it be tied to a current member?
            found: Dict[str, Set[str]] = {}
            if use_sha:
                found["template"] = set().union(*[sha_to_persons.get(s.sha256, set()) for s in slots if s.sha256]) \
                    if slots else set()
            acct = gms.get(u.key) if gms else None
            found["gms_id"] = {f"A{acct}"} & set(persons) if acct is not None else set()
            c = norm_card(u.card)
            found["card"] = set(card_to_persons.get(c, set())) if c else set()
            pc = norm_card(u.key)
            found["pin_is_card"] = set(card_to_persons.get(pc, set())) if pc else set()
            strong = {k: v for k, v in found.items() if v}
            if not strong and names:
                nm = {k for k, n in names.items() if names_match(u.name, n)}
                if nm:
                    strong["name_only"] = nm
            leftover[f"{cls}_users"] += 1
            leftover[f"{cls}_with_slots"] += int(bool(slots))
            leftover[f"{cls}_slots"] += len(slots)
            if gms and acct is not None:
                leftover[f"{cls}_pin_is_a_gms_card_id"] += 1
            primary = next((k for k in LINK_KINDS if k in strong), "none")
            targets = strong.get(primary, set())
            leftover[f"{cls}_linked_by_{primary}"] += 1
            if len(targets) > 1:
                leftover[f"{cls}_linked_ambiguous"] += 1
            single = [next(iter(v)) for k, v in strong.items() if k in STRONG_LINKS and len(v) == 1]
            if len(single) >= 2:
                leftover[f"{cls}_links_agree" if len(set(single)) == 1 else f"{cls}_links_conflict"] += 1
            if primary in STRONG_LINKS and len(targets) == 1:
                (target,) = tuple(targets)
                for s in slots:
                    linked_slots[target].append((ex.device_id, u.pin, s.finger_id, s.sha256, f"leftover_by_{primary}"))
                if norm_card(u.card):
                    linked_cards[target].append((ex.device_id, u.pin, norm_card(u.card), f"leftover_by_{primary}"))
            details.append(DetailRow(
                kind=cls, device_id=ex.device_id, pin=u.pin,
                person=",".join(sorted(targets)) or None, name=u.name,
                fingers=",".join(str(s.finger_id) for s in slots),
                link="+".join(k for k in LINK_KINDS if k in strong) or "none",
                note=("privileged " if u.privilege > 0 else "") + ("disabled" if not u.enabled else ""),
            ))
        dev["classes"] = dict(sorted(classes.items()))
        dev["leftovers"] = dict(sorted(leftover.items()))

        # ACCOUNT without a wipe: account pins that would land on a user the terminal
        # already holds. Harmless only when that user is the same person's own row.
        acc_pins = {str(r.main_account_id) for r in rows if r.main_account_id is not None}
        hit = acc_pins & pins_on_terminal
        foreign = {p for p in hit if pin_to_person.get(p) != f"A{p}"}
        dev["account_pins_already_on_terminal"] = len(hit)
        dev["account_pins_on_someone_elses_user"] = len(foreign)
        report["devices"][str(ex.device_id)] = dev

    # --- people: who would lose a finger in a wipe
    fingers_read = any(ex.fingers_read for ex in exports)
    ppl: Counter = Counter()
    ppl["deliverable_rows"] = len(rows)
    ppl["deliverable_people"] = len(persons)
    ppl["rows_without_main_account"] = sum(1 for r in rows if r.main_account_id is None)
    ppl["people_with_monclub_template"] = sum(1 for k in persons if person_fingers[k])
    ppl["people_without_monclub_template"] = sum(1 for k in persons if not person_fingers[k])
    # what MonClub will push, by algorithm version -- compare with each terminal's fp_version
    for v, n in Counter(t.template_version for r in rows for t in r.templates).items():
        ppl[f"delivered_templates_version_{v}"] += n
    if fingers_read:
        for key, slots in linked_slots.items():
            mine_sha = person_shas.get(key, set())
            mine_fid = person_fingers.get(key, set())
            only: List[Tuple[int, str, int, Optional[str], str]] = []
            for dev_id, pin, fid, sha, where in slots:
                if use_sha and sha:
                    # the exact template is delivered by MonClub, or it is not
                    if sha not in mine_sha:
                        only.append((dev_id, pin, fid, sha, where))
                elif fid not in mine_fid:
                    # finger numbers only: a re-scanned finger reads as covered
                    only.append((dev_id, pin, fid, sha, where))
            if not only:
                continue
            ppl["people_with_terminal_only_finger"] += 1
            ppl["terminal_only_slots"] += len(only)
            distinct = {(fid, sha) for _, _, fid, sha, _ in only}
            ppl["terminal_only_distinct_fingers"] += len(distinct)
            if use_sha and all_shas:
                ppl["terminal_only_but_template_in_monclub"] += sum(
                    1 for fid, sha in distinct if sha and sha in all_shas)
            if not mine_fid:
                ppl["people_losing_every_finger"] += 1
            for where in {w for *_, w in only}:
                ppl[f"terminal_only_via_{where}"] += 1
            details.append(DetailRow(
                kind="member_terminal_only_finger", device_id=None, pin=None, person=key,
                name=names.get(key, ""),
                fingers=";".join(f"{d}:{p}:f{f}" for d, p, f, _, _ in only),
                link=",".join(sorted({w for *_, w in only})),
                note="no MonClub template at all" if not mine_fid else "",
            ))
        on_terminal = {k for k, v in linked_slots.items() if v}
        ppl["people_with_monclub_template_but_none_on_any_terminal"] = sum(
            1 for k in persons if person_fingers[k] and k not in on_terminal
        )
    report["people"] = dict(sorted(ppl.items()))

    # --- cards: who would be refused by card after an erase (the card is only on the terminal)
    ccheck = card_self_check(exports, rows, ownership, scheme)
    crate = (ccheck["equal"] / ccheck["compared"]) if ccheck["compared"] else None
    report["card_self_check"] = {"compared": ccheck["compared"], "equal": ccheck["equal"],
                                 "rate": None if crate is None else round(crate, 4),
                                 "threshold": CARD_TRUST_THRESHOLD}
    crd: Counter = Counter()
    pushed_cards = {k: {rule(r.first_card_raw) for r in v} - {""} for k, v in persons.items()}
    # what MonClub holds in firstCardId, whether or not a device can be sent it
    held_cards = {k: sorted({r.first_card_raw for r in v if not no_monclub_card(r.first_card_raw)})
                  for k, v in persons.items()}
    crd["people_with_writable_monclub_card"] = sum(1 for k in persons if pushed_cards[k])
    crd["people_without_monclub_card"] = sum(1 for k in persons if not held_cards[k])
    crd["people_with_unwritable_monclub_card"] = sum(
        1 for k in persons if held_cards[k] and not pushed_cards[k])
    # under ACCOUNT one row per person reaches the terminal, so only one of these cards does
    crd["people_with_several_monclub_cards"] = sum(1 for k in persons if len(pushed_cards[k]) > 1)
    for key, seen in linked_cards.items():
        only = [(d, p, c, w) for d, p, c, w in seen if c not in pushed_cards.get(key, set())]
        if not only:
            continue
        crd["people_with_terminal_only_card"] += 1
        held = held_cards.get(key, [])
        marker = any(re.sub(r"\D", "", c).startswith("99999") for c in held)
        if not held:
            crd["people_with_terminal_only_card_and_no_monclub_card"] += 1
            tail = "; no card in MonClub"
        elif not pushed_cards.get(key):
            crd["people_with_terminal_only_card_and_unwritable_monclub_card"] += 1
            tail = f"; MonClub card {'/'.join(held)} cannot be written to {device_word} -- do not overwrite it"
        else:
            crd["people_with_terminal_only_card_and_another_monclub_card"] += 1
            tail = f"; MonClub card {'/'.join(held)} -- do not overwrite it"
        if marker:
            crd["people_with_terminal_only_card_and_99999_monclub_card"] += 1
            tail += " (it starts with 99999: ask the owner first)"
        for where in {w for *_, w in only}:
            crd[f"terminal_only_card_via_{where}"] += 1
        details.append(DetailRow(
            kind="member_terminal_only_card", device_id=None, pin=None, person=key,
            name=names.get(key, ""),
            fingers="",
            link=",".join(sorted({w for *_, w in only})),
            note="cards " + ";".join(f"{d}:{p}:card {c}" for d, p, c, _ in only) + tail,
        ))
    report["cards"] = dict(sorted(crd.items()))
    if crd["people_with_terminal_only_card"] and (crate is None or crate < CARD_TRUST_THRESHOLD):
        report["notes"].append(
            "card self-check " + ("not measured" if crate is None else f"{crate:.0%}")
            + f" (below {CARD_TRUST_THRESHOLD:.0%}): the cards list may only show that the device returns "
              "cards in another form than MonClub writes them -- do not act on it, call the developer")
    if access is None and backend is None:
        report["notes"].append("no --access-db and no backend: members and finger coverage are not evaluated")
    if ownership is None and (access is not None or backend is not None):
        report["notes"].append("ownership unknown (no --access-db, or a client version that records none): "
                               "members are not split into owned / not owned")
    if ppl["rows_without_main_account"] and scheme == "ACCOUNT":
        report["notes"].append(
            f"{ppl['rows_without_main_account']} delivered rows have no main_account_id: under ACCOUNT they are withheld"
        )
    if not fingers_read:
        report["notes"].append("no export read finger slots (-Fingers): finger coverage is not evaluated")
    if backend is not None:
        report["backend"] = {
            "gym_id": backend.gym_id,
            "day": backend.day,
            "memberships_on_gym_plans": len(backend.membership_ids),
            "deliverable_rows_sql": len(backend.deliverable_rows),
            "distinct_template_shas": len(backend.templates_by_sha),
            "gms_person_links": len(backend.gms_person_account),
            "notes": backend.notes,
        }
    return report, details


# --------------------------------------------------------------------------- output

def render(report: Dict[str, Any]) -> str:
    sc = report.get("sha_self_check", {})
    lines = [
        f"Terminal scheme assumed: {report['scheme_assumed_on_terminal']}   roster from: {report.get('roster_source')}"
        f"   ownership known: {report.get('ownership_known')}",
        f"sha self-check (member pins): {sc.get('equal', 0)}/{sc.get('compared', 0)} slots carry MonClub's exact "
        f"template -> fingers matched by {report.get('finger_match_mode')}",
    ]
    for dev_id, d in report["devices"].items():
        lines.append("")
        lines.append(f"== device {dev_id} ({d['label']})  complete={d['complete']}  fingers_read={d['fingers_read']}  fpVersion={d['fp_version']}")
        lines.append(f"   terminal users {d['terminal_users']}  privileged {d['privileged']}  disabled {d['disabled']}  with card {d['with_card']}")
        if d.get("fingers_read"):
            lines.append(f"   users with slots {d['users_with_slots']}  slots {d['slots']}  (not base64: {d['slots_not_base64']})")
        if "pc_pin_scheme" in d:
            lines.append(f"   pin scheme recorded by the PC: {d['pc_pin_scheme']}")
        lines.append(f"   counters {d['counters']}")
        lines.append(f"   classes {d['classes']}")
        lines.append(f"   leftovers {d['leftovers']}")
        lines.append(f"   ACCOUNT without wipe: {d['account_pins_already_on_terminal']} account pins already on the terminal, "
                     f"{d['account_pins_on_someone_elses_user']} of them another person's user")
    lines.append("")
    lines.append(f"== people {report['people']}")
    if "cards" in report:
        lines.append(f"== cards {report['cards']}")
        cc = report.get("card_self_check", {})
        rate, thr = cc.get("rate"), cc.get("threshold", CARD_TRUST_THRESHOLD)
        if rate is None:
            verdict = "NOT MEASURED -- the cards list is unchecked: do not act on it"
        elif rate >= thr:
            verdict = f"at or above {thr:.0%} -- the cards list can be used"
        else:
            verdict = f"BELOW {thr:.0%} -- STOP: do not act on the cards list, call the developer"
        lines.append(f"   card self-check (member pins): {cc.get('equal', 0)}/{cc.get('compared', 0)} device cards "
                     f"equal the card MonClub writes ({'-' if rate is None else f'{rate:.1%}'}) -> {verdict}")
    for n in report.get("notes", []):
        lines.append(f"note: {n}")
    if "backend" in report:
        lines.append(f"backend: {report['backend']}")
    return "\n".join(lines)


def write_details(path: str, details: List[DetailRow]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["kind", "device_id", "pin", "person", "name", "fingers", "link", "note"])
        for d in details:
            w.writerow([d.kind, d.device_id, d.pin, d.person, d.name, d.fingers, d.link, d.note])


# --------------------------------------------------------------------------- cli

def _parse_export_arg(v: str) -> Tuple[int, str]:
    if "=" not in v:
        raise argparse.ArgumentTypeError("use DEVICE_ID=FILE, e.g. 8=terminal_device8_....json")
    dev, path = v.split("=", 1)
    return int(dev), path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--export", action="append", type=_parse_export_arg, required=True,
                    help="DEVICE_ID=FILE, one per terminal")
    ap.add_argument("--access-db", help="a COPY of the driver PC's access.db")
    ap.add_argument("--scheme", choices=SCHEMES, default="MEMBERSHIP",
                    help="the pin scheme the terminals were filled under (default MEMBERSHIP)")
    ap.add_argument("--gym-id", type=int, default=45)
    ap.add_argument("--mysql-host")
    ap.add_argument("--mysql-port", type=int, default=3306)
    ap.add_argument("--mysql-db")
    ap.add_argument("--mysql-user")
    ap.add_argument("--day", default=None,
                    help="date the SQL roster is computed for (YYYY-MM-DD, default today)")
    ap.add_argument("--mysql-password-env", default="MYSQL_PWD",
                    help="name of the environment variable holding the password")
    ap.add_argument("--match-by", choices=("auto", "sha", "finger"), default="auto",
                    help="auto = by template hash when the self-check reaches "
                         f"{SHA_TRUST_THRESHOLD:.0%}, else by finger number")
    ap.add_argument("--json-out")
    ap.add_argument("--detail-csv", help="per-person rows WITH NAMES - personal data")
    args = ap.parse_args(argv)

    exports = [load_export(path, dev) for dev, path in args.export]
    access = load_access_db(args.access_db) if args.access_db else None
    backend = None
    if args.mysql_host:
        if (args.mysql_db or "").strip().lower() in REFUSED_DATABASES:
            print(f"refused: {args.mysql_db} is the unscrubbed production copy", file=sys.stderr)
            return 2
        import datetime
        backend = load_backend_snapshot(
            host=args.mysql_host, port=args.mysql_port, db=args.mysql_db,
            user=args.mysql_user, password=os.environ.get(args.mysql_password_env, ""),
            gym_id=args.gym_id, day=args.day or datetime.date.today().isoformat(),
        )
    try:
        report, details = analyse(exports, access, backend, scheme=args.scheme, match_by=args.match_by)
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(render(report))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
    if args.detail_csv:
        write_details(args.detail_csv, details)
        print(f"\nper-person detail (personal data) written to {args.detail_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
