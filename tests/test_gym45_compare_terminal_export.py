"""tools/gym45_cutover/compare_terminal_export.py -- the cutover comparison.

It decides, from a terminal export and a copy of the driver PC's access.db, which
terminal users are MonClub members, which are leftovers, and which current members
would lose a finger in a wipe. Every number in the gym-45 plan's "who is affected"
section comes from it, so its classification is pinned here on a small synthetic gym
whose right answers are known by construction.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import sqlite3
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "compare_terminal_export", REPO / "tools" / "gym45_cutover" / "compare_terminal_export.py"
)
cte = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = cte  # dataclasses resolve annotations through sys.modules
_SPEC.loader.exec_module(cte)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


A0, A1, A5, B3, C2 = b"alpha-f0", b"alpha-f1", b"alpha-f5-terminal", b"beta-f3-gms", b"gamma-f2"


# ------------------------------------------------------------------ template hashing

class TestTemplateHash:
    def test_hex_and_base64_of_the_same_bytes_hash_the_same(self):
        raw = bytes(range(40))
        assert cte.template_sha256(_b64(raw)) == cte.template_sha256(raw.hex(), "HEX") == _sha(raw)

    def test_hex_is_decoded_as_tolerantly_as_the_push_path(self):
        raw = b"\x01\x02\xfe"
        assert cte.template_sha256("0x01 02\nfe", "hex") == _sha(raw)

    def test_the_hash_is_of_what_the_push_path_puts_on_the_wire(self):
        from app.core.device_sync import _template_wire
        raw = bytes(range(7, 90))
        wire, _ = _template_wire("0x" + raw.hex(), "HEX")
        assert cte.template_sha256(wire) == cte.template_sha256("0x" + raw.hex(), "HEX")

    @pytest.mark.parametrize("bad", ["", "   ", "not base64!", None])
    def test_undecodable_is_none(self, bad):
        assert cte.template_sha256(bad) is None

    def test_undecodable_hex_is_none(self):
        assert cte.template_sha256("zz", "HEX") is None


class TestNormalisation:
    def test_card_digits_without_leading_zeros_and_zero_is_no_card(self):
        assert cte.norm_card(" 000777 ") == "777"
        assert cte.norm_card("0") == ""
        assert cte.norm_card(None) == ""

    def test_names_match_accents_case_and_the_24_char_cut(self):
        assert cte.names_match("ELODIE  Benaissa", "Élodie Benaïssa")
        long_name = "Mohamed Amine Ben Youssef Trabelsi"
        assert cte.names_match(long_name[:24], long_name)
        assert not cte.names_match("Mo", "Mo")  # too short to mean anything
        assert not cte.names_match("Mohamed Amine", "Mohamed Amine Ben Youssef")


# ------------------------------------------------------------------ synthetic gym

def _access_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE sync_users (user_id INTEGER, active_membership_id INTEGER, membership_id INTEGER,
            full_name TEXT, phone TEXT, email TEXT, valid_from TEXT, valid_to TEXT, first_card_id TEXT,
            second_card_id TEXT, image TEXT, fingerprints_json TEXT, face_id TEXT,
            account_username_id TEXT, qr_code_payload TEXT, birthday TEXT, main_account_id INTEGER);
        CREATE TABLE device_sync_state (device_id INTEGER NOT NULL, pin TEXT NOT NULL, desired_hash TEXT,
            last_ok INTEGER NOT NULL DEFAULT 1, last_error TEXT, updated_at TEXT NOT NULL,
            pushed_finger_ids TEXT, ownership_confirmed INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (device_id, pin));
        CREATE TABLE device_push_intent (device_id INTEGER NOT NULL, pin TEXT NOT NULL,
            PRIMARY KEY (device_id, pin));
        CREATE TABLE sync_devices (id INTEGER, name TEXT, pin_scheme TEXT);
        """
    )
    fp = lambda fid, raw, enc=None: {"fingerId": fid, "templateVersion": 10,  # noqa: E731
                                     "templateData": raw.hex() if enc == "HEX" else _b64(raw),
                                     **({"templateEncoding": enc} if enc else {})}
    users = [
        # user, membership, name, card, fingers, account
        (1, 11, "Alpha Person", "", [fp(0, A0), fp(1, A1, "HEX")], 500),
        (2, 12, "Beta Person", "777", [], 600),
        (3, 13, "Gamma Person", "", [fp(2, C2)], 700),
        (3, 14, "Gamma Person", "", [], 700),  # a second plan of the same person
    ]
    for uid, am, name, card, fps, acc in users:
        conn.execute(
            "INSERT INTO sync_users (user_id, active_membership_id, full_name, first_card_id, "
            "fingerprints_json, main_account_id) VALUES (?,?,?,?,?,?)",
            (uid, am, name, card, json.dumps(fps), acc),
        )
    for pin in ("11", "13", "14", "99"):
        conn.execute("INSERT INTO device_sync_state (device_id, pin, updated_at, ownership_confirmed, "
                     "pushed_finger_ids) VALUES (8, ?, 'x', 1, '')", (pin,))
    conn.execute("INSERT INTO device_sync_state (device_id, pin, updated_at, ownership_confirmed) "
                 "VALUES (8, '12', 'x', 0)")
    conn.execute("INSERT INTO device_push_intent VALUES (8, '98')")
    conn.execute("INSERT INTO sync_devices VALUES (8, 'Sortie', 'MEMBERSHIP')")
    conn.commit()
    conn.close()


def _slot(fid: int, raw: bytes):
    return {"fingerId": fid, "size": len(raw), "sha256": _sha(raw), "decodedBytes": len(raw), "hashedAs": "base64"}


def _export(path: Path, users, *, fingers=True) -> Path:
    doc = {
        "schema": cte.EXPORT_SCHEMA, "complete": True, "takenAt": "2026-09-19T07:00:00",
        "options": {"fingers": fingers}, "device": {"label": "device8", "fpVersion": "10"},
        "counters": {"2": {"name": "users", "value": len(users)}},
        "users": users,
    }
    path.write_text(json.dumps(doc), encoding="utf-8-sig")
    return path


def _u(pin, name="", card="", slots=(), priv=0):
    return {"pin": pin, "name": name, "card": card, "privilege": priv, "enabled": True,
            "hasPassword": False, "slots": list(slots)}


TERMINAL = [
    _u("11", "Alpha Person", slots=[_slot(0, A0), _slot(1, A1), _slot(5, A5)]),  # f5 only on the terminal
    _u("12", "Beta Person"),                                                      # member, not owned
    _u("13", "Gamma Person", slots=[_slot(2, C2)]),
    _u("14", "Gamma Person"),
    _u("99", "Gone Member"),                                                      # owned, left the roster
    _u("98", "Crash Member"),                                                     # intent only
    _u("5000", "B PERSON OLD", card="00777", slots=[_slot(3, B3)]),                # leftover, Beta's card
    _u("6000", "Somebody", slots=[_slot(0, A0)]),                                 # leftover, Alpha's exact finger
    _u("7000", "Nobody Known", slots=[_slot(4, b"stranger")], priv=3),            # leftover, no link
    _u("700", "Collides With Gamma's Account"),                                   # leftover AT account id 700
]


@pytest.fixture
def gym(tmp_path: Path):
    db = tmp_path / "access.db"
    _access_db(db)
    ex = _export(tmp_path / "t8.json", TERMINAL)
    return db, ex


class TestAccessDbIsReadOnly:
    def test_the_copy_handed_in_is_not_modified(self, gym, tmp_path):
        db, _ = gym
        before = db.read_bytes()
        acc = cte.load_access_db(str(db))
        assert db.read_bytes() == before
        assert not (tmp_path / "access.db-wal").exists() and not (tmp_path / "access.db-shm").exists()
        assert len(acc.rows) == 4 and acc.rows_without_account == 0
        assert acc.ownership[8]["11"].ownership_confirmed and not acc.ownership[8]["12"].ownership_confirmed
        assert acc.intents[8] == {"98"} and acc.pin_scheme[8] == "MEMBERSHIP"

    def test_the_opened_copy_refuses_writes(self, gym, monkeypatch):
        db, _ = gym
        seen = {}
        real = cte._open_copy

        def spy(path):
            conn, tmp = real(path)
            seen["conn"] = conn
            with pytest.raises(sqlite3.OperationalError):
                conn.execute("DELETE FROM device_sync_state")
            return conn, tmp

        monkeypatch.setattr(cte, "_open_copy", spy)
        cte.load_access_db(str(db))
        assert "conn" in seen

    def test_a_database_without_the_later_columns_still_loads(self, tmp_path):
        db = tmp_path / "old.db"
        conn = sqlite3.connect(db)
        conn.executescript(
            "CREATE TABLE sync_users (user_id INTEGER, active_membership_id INTEGER, full_name TEXT,"
            " first_card_id TEXT, second_card_id TEXT, fingerprints_json TEXT);"
            "CREATE TABLE device_sync_state (device_id INTEGER, pin TEXT, desired_hash TEXT, last_ok INTEGER,"
            " last_error TEXT, updated_at TEXT);"
            "CREATE TABLE device_push_intent (x INTEGER); CREATE TABLE sync_devices (id INTEGER);"
            "INSERT INTO sync_users VALUES (1, 11, 'A', '', '', '[]');"
        )
        conn.commit(); conn.close()
        acc = cte.load_access_db(str(db))
        assert acc.rows[0].main_account_id is None and acc.rows_without_account == 1


class TestClassification:
    def test_every_terminal_user_lands_in_exactly_one_class(self, gym):
        db, ex = gym
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)))
        dev = report["devices"]["8"]
        assert dev["classes"] == {
            "departed_owned": 1, "intent_only": 1, "leftover": 4,
            "member_not_owned": 1, "member_owned": 3,
        }
        assert sum(dev["classes"].values()) == dev["terminal_users"] == len(TERMINAL)
        assert dev["privileged"] == 1

    def test_the_self_check_licenses_matching_by_template(self, gym):
        db, ex = gym
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)))
        # pin 11: f0 and f1 (HEX in MonClub, base64 on the terminal) ; pin 13: f2
        assert report["sha_self_check"] == {"compared": 3, "equal": 3, "rate": 1.0}
        assert report["finger_match_mode"] == "sha"

    def test_leftovers_are_tied_to_members_by_template_or_card(self, gym):
        db, ex = gym
        report, details = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)))
        lo = report["devices"]["8"]["leftovers"]
        assert lo["leftover_users"] == 4
        assert lo["leftover_linked_by_template"] == 1   # 6000 carries Alpha's exact f0
        assert lo["leftover_linked_by_card"] == 1       # 5000 carries Beta's card
        assert lo["leftover_linked_by_none"] == 2       # 7000, 700
        by_pin = {d.pin: d for d in details if d.kind == "leftover"}
        assert by_pin["6000"].person == "A500" and by_pin["5000"].person == "A600"

    def test_members_who_would_lose_a_finger(self, gym):
        db, ex = gym
        report, details = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)))
        ppl = report["people"]
        assert ppl["deliverable_people"] == 3 and ppl["deliverable_rows"] == 4
        assert ppl["delivered_templates_version_10"] == 3
        # Alpha: f5 only on the terminal, under Alpha's own pin. Beta: f3 only under the
        # old leftover pin 5000 (tied by card) - and Beta has no MonClub template at all.
        assert ppl["people_with_terminal_only_finger"] == 2
        assert ppl["people_losing_every_finger"] == 1
        assert ppl["terminal_only_via_own_pin"] == 1 and ppl["terminal_only_via_leftover_by_card"] == 1
        rows = {d.person: d for d in details if d.kind == "member_terminal_only_finger"}
        assert rows["A500"].fingers == "8:11:f5"
        assert rows["A600"].fingers == "8:5000:f3" and rows["A600"].note == "no MonClub template at all"

    def test_the_account_hazard_of_switching_without_a_wipe(self, gym):
        db, ex = gym
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)))
        dev = report["devices"]["8"]
        assert dev["account_pins_already_on_terminal"] == 1      # 700 is on the terminal
        assert dev["account_pins_on_someone_elses_user"] == 1     # ... and it is not Gamma's row


class TestWhenTemplatesDoNotRoundTrip:
    def test_a_failed_self_check_falls_back_to_finger_numbers(self, tmp_path):
        db = tmp_path / "access.db"
        _access_db(db)
        mangled = [dict(u) for u in TERMINAL]
        mangled[0] = _u("11", slots=[_slot(0, b"other bytes"), _slot(1, b"x"), _slot(5, A5)])
        mangled[2] = _u("13", slots=[_slot(2, b"y")])
        ex = _export(tmp_path / "t8.json", mangled)
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)))
        assert report["sha_self_check"]["rate"] == 0.0
        assert report["finger_match_mode"] == "finger"
        # no template links without trustworthy hashes; Alpha's f5 is still found by number
        assert report["devices"]["8"]["leftovers"].get("leftover_linked_by_template", 0) == 0
        assert report["people"]["terminal_only_via_own_pin"] == 1


class TestInputsAndCli:
    def test_an_export_without_finger_slots_says_so(self, gym, tmp_path):
        db, _ = gym
        ex = _export(tmp_path / "quick.json", [{k: v for k, v in u.items() if k != "slots"} for u in TERMINAL],
                     fingers=False)
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)))
        assert "people_with_terminal_only_finger" not in report["people"]
        assert any("-Fingers" in n for n in report["notes"])
        assert report["devices"]["8"]["classes"]["member_owned"] == 3

    def test_not_an_export_is_refused(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"schema": "something else"}))
        with pytest.raises(ValueError):
            cte.load_export(str(p), 8)

    def test_the_cli_prints_aggregates_and_no_names(self, gym, capsys):
        db, ex = gym
        assert cte.main(["--export", f"8={ex}", "--access-db", str(db)]) == 0
        out = capsys.readouterr().out
        assert "member_owned" in out and "people_with_terminal_only_finger" in out
        for u in TERMINAL:
            assert u["name"] not in out, "names only ever go to --detail-csv"

    def test_the_detail_csv_is_opt_in(self, gym, tmp_path):
        db, ex = gym
        csv_path = tmp_path / "detail.csv"
        assert cte.main(["--export", f"8={ex}", "--access-db", str(db), "--detail-csv", str(csv_path)]) == 0
        text = csv_path.read_text(encoding="utf-8")
        assert "Nobody Known" in text and "member_terminal_only_finger" in text

    def test_the_unscrubbed_production_copy_is_refused_before_any_connection(self, gym, capsys):
        _, ex = gym
        rc = cte.main(["--export", f"8={ex}", "--mysql-host", "127.0.0.1", "--mysql-db", "wigo-db"])
        assert rc == 2
        assert "refused" in capsys.readouterr().err


# ------------------------------------------------------------------ the backend (MySQL) path

def _snapshot(**over):
    """Backend rows for the same synthetic gym. Beta (account 600) was imported from the
    old system under GMS card id 5000; a former member (account 900, membership 77) is
    not deliverable any more."""
    memberships = [(11, 500), (12, 600), (13, 700), (14, 700), (77, 900)]
    deliverable = [(11, 500, 1, "", None), (12, 600, 2, "777", None), (13, 700, 3, "", None),
                   (14, 700, 3, "", None)]
    templates = [
        (0, 10, 1, 11, 500, _sha(A0)), (1, 10, 1, 11, 500, _sha(A1)),
        (2, 10, 1, 13, 700, _sha(C2)),
        (3, 10, 0, None, 600, _sha(B3)),         # Beta's old finger: in MonClub, disabled
        (6, 10, 1, 77, 900, _sha(b"former")),
    ]
    gms = [("5000", 600), ("0042", 900)]
    args = dict(memberships=memberships, deliverable=deliverable, templates=templates, gms_persons=gms)
    args.update(over)
    return cte.snapshot_from_rows(45, "2026-09-19", **args)


class TestBackendSnapshot:
    def test_rows_carry_their_own_and_their_accounts_enabled_templates(self):
        snap = _snapshot()
        rows = {r.membership_id: r for r in snap.deliverable_rows}
        assert {t.finger_id for t in rows[11].templates} == {0, 1}
        assert rows[12].templates == [] and rows[12].cards == {"777"}
        # Gamma's second plan carries the finger scanned under the first (same account)
        assert {t.finger_id for t in rows[14].templates} == {2}
        assert snap.membership_ids == {11, 12, 13, 14, 77}
        assert snap.templates_by_sha[_sha(B3)] == {600}   # disabled, still known
        assert snap.gms_person_account == {"5000": 600, "42": 900}

    def test_only_select_statements_are_sent(self):
        class Cur:
            def __init__(self):
                self.sent = []

            def execute(self, sql, params=None):
                self.sent.append(sql)

            def fetchall(self):
                return []

        cur = Cur()
        assert cte._select(cur, "  select 1", {}) == []
        for bad in ("DELETE FROM user_fingerprint", "UPDATE x SET y=1", "SET SESSION x=1",
                    "WITH a AS (SELECT 1) DELETE"):
            with pytest.raises(ValueError):
                cte._select(cur, bad, {})
        assert cur.sent == ["  select 1"]
        for sql in (cte._SQL_MEMBERSHIPS, cte._SQL_DELIVERABLE, cte._SQL_TEMPLATES, cte._SQL_GMS_PERSONS):
            assert sql.lstrip().upper().startswith("SELECT")
            assert not re.search(r"\b(INSERT|UPDATE|DELETE|REPLACE|ALTER|DROP|CREATE|TRUNCATE|GRANT)\b", sql, re.I)
        # template bytes are only ever hashed inside MySQL, never selected
        assert "template_bytes" not in cte._SQL_TEMPLATES.replace("SHA2(uf.template_bytes, 256)", "") \
            .replace("uf.template_bytes IS NOT NULL", "")

    def test_the_session_is_read_only_and_rolled_back(self, monkeypatch):
        sent, events = [], []

        class Cur:
            def execute(self, sql, params=None):
                sent.append(sql.strip().split("\n")[0])

            def fetchall(self):
                return []

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class Conn:
            def cursor(self):
                return Cur()

            def rollback(self):
                events.append("rollback")

            def commit(self):
                events.append("COMMIT")

            def close(self):
                events.append("close")

        def connect(**kw):
            events.append(("connect", kw["database"], kw["autocommit"]))
            return Conn()

        fake = type(sys)("pymysql")
        fake.connect = connect
        monkeypatch.setitem(sys.modules, "pymysql", fake)
        cte.load_backend_snapshot(host="h", port=1, db="wigo-demo", user="u", password="p",
                                  gym_id=45, day="2026-09-19")
        assert sent[:2] == ["SET SESSION TRANSACTION READ ONLY", "START TRANSACTION READ ONLY"]
        assert len(sent) == 6 and all(s.upper().startswith("SELECT") for s in sent[2:])
        assert events == [("connect", "wigo-demo", False), "rollback", "close"]

    def test_the_production_copy_is_refused_before_connecting(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "pymysql", None)  # an import would raise
        with pytest.raises(ValueError, match="refused"):
            cte.load_backend_snapshot(host="h", port=1, db=" WIGO-DB ", user="u", password="p",
                                      gym_id=45, day="d")


class TestBackendOnlyAndTheNewLinks:
    def test_without_access_db_the_roster_comes_from_sql_and_ownership_is_unknown(self, tmp_path):
        ex = _export(tmp_path / "t8.json", TERMINAL)
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], None, _snapshot())
        assert report["roster_source"] == "backend SQL on 2026-09-19" and report["ownership_known"] is False
        # 11, 12, 13, 14 are members; 99, 98, 5000, 6000, 7000, 700 are not
        assert report["devices"]["8"]["classes"] == {"leftover": 6, "member": 4}
        assert report["sha_self_check"]["compared"] == 3 and report["finger_match_mode"] == "sha"

    def test_a_leftover_pin_that_is_a_gms_card_id_is_tied_to_the_person(self, tmp_path):
        db = tmp_path / "access.db"
        _access_db(db)
        ex = _export(tmp_path / "t8.json", TERMINAL)
        report, details = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)), _snapshot())
        lo = report["devices"]["8"]["leftovers"]
        # 5000 is Beta's GMS card id AND carries Beta's card: two links, same person
        assert lo["leftover_pin_is_a_gms_card_id"] == 1
        assert lo["leftover_linked_by_gms_id"] == 1
        assert lo["leftover_links_agree"] == 1
        row = next(d for d in details if d.pin == "5000")
        assert row.person == "A600" and row.link == "gms_id+card"

    def test_a_terminal_only_finger_whose_template_monclub_holds_is_counted(self, tmp_path):
        db = tmp_path / "access.db"
        _access_db(db)
        ex = _export(tmp_path / "t8.json", TERMINAL)
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)), _snapshot())
        # Beta's f3 on the old pin is not delivered (disabled) but MonClub has the template
        assert report["people"]["terminal_only_but_template_in_monclub"] == 1

    def test_a_leftover_pin_equal_to_a_members_card_is_tied(self, tmp_path):
        db = tmp_path / "access.db"
        _access_db(db)
        ex = _export(tmp_path / "t8.json", [_u("777", "Someone", slots=[_slot(8, b"x8")])])
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)))
        assert report["devices"]["8"]["leftovers"]["leftover_linked_by_pin_is_card"] == 1
        assert report["people"]["terminal_only_via_leftover_by_pin_is_card"] == 1


class TestNormPin:
    def test_numeric_pins_lose_leading_zeros(self):
        assert cte.norm_pin("0042") == "42" and cte.norm_pin(" 5000 ") == "5000"
        assert cte.norm_pin("A1") == "A1"


class TestVerifyingThePushUnderAccount:
    """The plan's post-push check runs the comparison with --scheme ACCOUNT against the
    terminal MonClub has just filled with account pins. It must read them as members --
    run with the default MEMBERSHIP it would call every one of them a leftover."""

    def _after_the_switch(self, tmp_path):
        db = tmp_path / "access.db"
        _access_db(db)
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM device_sync_state")                 # the retire
        for pin in ("500", "600", "700"):                               # the ACCOUNT push
            conn.execute("INSERT INTO device_sync_state (device_id, pin, updated_at, ownership_confirmed, "
                         "pushed_finger_ids) VALUES (8, ?, 'x', 1, '')", (pin,))
        conn.execute("UPDATE sync_devices SET pin_scheme = 'ACCOUNT'")
        conn.commit()
        conn.close()
        terminal = [
            _u("500", "Alpha Person", slots=[_slot(0, A0), _slot(1, A1)]),
            _u("600", "Beta Person"),
            _u("700", "Gamma Person", slots=[_slot(2, C2)]),           # two plans, one pin
            _u("1", "Admin", priv=14),                                  # an admin the wipe kept
        ]
        return db, _export(tmp_path / "after.json", terminal)

    def test_account_pins_read_as_owned_members(self, tmp_path):
        db, ex = self._after_the_switch(tmp_path)
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)), scheme="ACCOUNT")
        dev = report["devices"]["8"]
        assert dev["classes"] == {"leftover": 1, "member_owned": 3}
        assert dev["privileged"] == 1
        assert report["sha_self_check"] == {"compared": 3, "equal": 3, "rate": 1.0}
        assert "people_with_terminal_only_finger" not in report["people"]
        assert report["people"]["deliverable_people"] == 3

    def test_the_same_terminal_read_under_membership_looks_like_leftovers(self, tmp_path):
        db, ex = self._after_the_switch(tmp_path)
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)), scheme="MEMBERSHIP")
        assert report["devices"]["8"]["classes"].get("member_owned", 0) == 0

    def test_the_report_shows_the_scheme_the_pc_recorded(self, tmp_path):
        db, ex = self._after_the_switch(tmp_path)
        report, _ = cte.analyse([cte.load_export(str(ex), 8)], cte.load_access_db(str(db)), scheme="ACCOUNT")
        assert report["devices"]["8"]["pc_pin_scheme"] == "ACCOUNT"
