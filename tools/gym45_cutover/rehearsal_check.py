"""Rehearse compare_terminal_export.py against a real backend copy -- read-only.

There is no terminal export yet (making one needs the gym). This builds a SYNTHETIC one
from the backend copy, whose right answers are known by construction, runs the
comparison on it, and checks every count:

* every deliverable membership sits on the terminal at its MonClub pin, carrying
  exactly its MonClub templates (what a clean MonClub push leaves);
* ``--duplicates`` people ALSO sit at their old-system pin (their GMS card id, from
  migration_entity_link_gms) carrying the same templates -- the "same finger enrolled
  twice" case script 13's comment describes for this gym;
* ``--unknown`` leftovers nobody knows, with fingers MonClub does not have;
* ``--extra-fingers`` members get one finger that exists only on the terminal;
* ``--past`` memberships of the gym that are no longer deliverable.

It prints aggregates only and writes nothing except the synthetic export file, which it
deletes unless ``--keep`` is given (it holds membership ids and template hashes, never a
template, a name or a card). The backend is read through the tool's own SELECT-only,
READ ONLY loader, and ``wigo-db`` is refused there by name.

    set MYSQL_PWD=...
    python tools/gym45_cutover/rehearsal_check.py --mysql-host 127.0.0.1 --mysql-port 3307 \
        --mysql-db wigo-demo --mysql-user root --day 2026-09-12
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compare_terminal_export as cte  # noqa: E402


def _fake_sha(tag: str) -> str:
    return hashlib.sha256(("rehearsal:" + tag).encode()).hexdigest()


def _slot(fid: int, sha: str) -> dict:
    return {"fingerId": fid, "size": 0, "sha256": sha, "decodedBytes": 0, "hashedAs": "base64"}


def build(snap: cte.BackendSnapshot, *, duplicates: int, unknown: int, extra_fingers: int, past: int):
    users, truth = [], {}
    rows = sorted(snap.deliverable_rows, key=lambda r: r.membership_id)
    persons = cte._persons(rows)
    for r in rows:
        users.append({"pin": str(r.membership_id), "name": f"member {r.membership_id}", "card": "",
                      "privilege": 0, "enabled": True, "hasPassword": False,
                      "slots": [_slot(t.finger_id, t.sha256) for t in r.templates if t.sha256]})
    # a finger only the terminal has, on members whose templates are all known
    with_tpl = [u for u in users if u["slots"]]
    for u in with_tpl[:extra_fingers]:
        used = {s["fingerId"] for s in u["slots"]}
        fid = next(f for f in range(10) if f not in used)
        u["slots"].append(_slot(fid, _fake_sha("extra" + u["pin"])))
    # old-system duplicates: current people, at their GMS card id, same templates
    member_pins = {u["pin"] for u in users}
    dup = []
    for key, acct in sorted(snap.gms_person_account.items(), key=lambda kv: kv[0]):
        pkey = f"A{acct}"
        if pkey not in persons or key in member_pins or key in snap_ids(snap):
            continue
        shas = [(t.finger_id, t.sha256) for r in persons[pkey] for t in r.templates if t.sha256]
        if not shas:
            continue
        users.append({"pin": key, "name": "old system", "card": "", "privilege": 0, "enabled": True,
                      "hasPassword": False, "slots": [_slot(f, s) for f, s in dict(shas).items()]})
        dup.append(key)
        if len(dup) >= duplicates:
            break
    for i in range(unknown):
        users.append({"pin": str(990000 + i), "name": "unknown", "card": "", "privilege": 0,
                      "enabled": True, "hasPassword": False, "slots": [_slot(0, _fake_sha(f"unk{i}"))]})
    deliverable = {r.membership_id for r in rows}
    gone = sorted(m for m in snap.membership_ids if m not in deliverable)[:past]
    for m in gone:
        users.append({"pin": str(m), "name": "past", "card": "", "privilege": 0, "enabled": True,
                      "hasPassword": False, "slots": []})
    truth.update(members=len(rows), duplicates=len(dup), unknown=unknown, past=len(gone),
                 extra=min(extra_fingers, len(with_tpl)), people=len(persons))
    return users, truth


def snap_ids(snap: cte.BackendSnapshot) -> set:
    return {str(m) for m in snap.membership_ids}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mysql-host", required=True)
    ap.add_argument("--mysql-port", type=int, default=3306)
    ap.add_argument("--mysql-db", required=True)
    ap.add_argument("--mysql-user", required=True)
    ap.add_argument("--mysql-password-env", default="MYSQL_PWD")
    ap.add_argument("--gym-id", type=int, default=45)
    ap.add_argument("--day", required=True)
    ap.add_argument("--duplicates", type=int, default=50)
    ap.add_argument("--unknown", type=int, default=40)
    ap.add_argument("--extra-fingers", type=int, default=12)
    ap.add_argument("--past", type=int, default=15)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)

    snap = cte.load_backend_snapshot(host=a.mysql_host, port=a.mysql_port, db=a.mysql_db, user=a.mysql_user,
                                     password=os.environ.get(a.mysql_password_env, ""), gym_id=a.gym_id, day=a.day)
    users, truth = build(snap, duplicates=a.duplicates, unknown=a.unknown,
                         extra_fingers=a.extra_fingers, past=a.past)
    doc = {"schema": cte.EXPORT_SCHEMA, "complete": True, "takenAt": "rehearsal",
           "options": {"fingers": True}, "device": {"label": "synthetic", "fpVersion": "10"},
           "counters": {}, "users": users}
    fd, path = tempfile.mkstemp(prefix="gym45_rehearsal_", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    try:
        report, _ = cte.analyse([cte.load_export(path, 8)], None, snap)
    finally:
        if not a.keep:
            os.remove(path)
    dev, ppl = report["devices"]["8"], report["people"]
    lo = dev["leftovers"]
    checks = {
        "members on their MonClub pin": (dev["classes"].get("member"), truth["members"]),
        "past memberships recognised": (dev["classes"].get("past_membership", 0), truth["past"]),
        "leftovers": (dev["classes"].get("leftover", 0), truth["duplicates"] + truth["unknown"]),
        "duplicates tied by template": (lo.get("leftover_linked_by_template", 0), truth["duplicates"]),
        "duplicates also tied by GMS id (agree)": (lo.get("leftover_links_agree", 0), truth["duplicates"]),
        "unknown leftovers tied to nobody": (lo.get("leftover_linked_by_none", 0), truth["unknown"]),
        "sha self-check": (report["sha_self_check"]["rate"], 1.0),
        "people with a terminal-only finger": (ppl.get("people_with_terminal_only_finger", 0), truth["extra"]),
        "deliverable people": (ppl["deliverable_people"], truth["people"]),
    }
    print(f"backend copy {a.mysql_db}, gym {a.gym_id}, day {a.day}: {report['backend']}")
    print(f"people: {ppl}")
    ok = True
    for name, (got, want) in checks.items():
        good = got == want
        ok &= good
        print(f"  {'OK  ' if good else 'FAIL'} {name}: got {got}, expected {want}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
