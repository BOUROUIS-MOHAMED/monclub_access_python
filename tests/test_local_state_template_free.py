"""`load_local_state()` and `list_members_roster()` must not read fingerprint templates.

WHY THIS FILE EXISTS
--------------------
Field measurement, OXYGENE_FIT PC, v1.4.26 (2026-08-30): every ULTRA worker reloads
`access_verification.load_local_state()` after each sync (generation bump) and on a
300 s TTL, and that reload was 0.7-6.8 s per worker
(``DB_READ_users_split rows=934 select_ms=6828 coerce_ms=47``) because
``list_sync_users()`` pulls ``fingerprints_json`` -- ~90 % of the row bytes -- although the
state only indexes activeMembershipId / userId and the card fields. The same applies to
the Utilisateurs roster (``list_members_roster``), whose enrich loop never looks at
fingerprints and whose UI contract (tauri-ui UsersPage ``MemberRosterRow``) has no
fingerprint field.

The risk the CAUTION on ``list_sync_users_page`` names -- a stripped template set is
INDISTINGUISHABLE from "this member has no fingerprints" -- is what the static guard at
the bottom pins: no consumer of the local state may read ``fingerprints`` from it. The
push path takes templates from ``load_sync_cache()`` /
``DeviceSyncEngine._collect_templates_for_pin``, never from this state.

Every test patches ``app.core.db._DB_PATH`` to a temp file.
"""

from __future__ import annotations

import pathlib
import re

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


_TEMPLATE = {
    "id": 166,
    "fingerId": 0,
    "templateVersion": 10,
    "templateEncoding": "BASE64",
    "templateData": "ShtTUzIxAAADWFsECAUHCc7QAAAvWXYB" * 24,
    "templateSize": 856,
    "enabled": True,
}


def _user(am_id, user_id, *, card, second_card=None, fps=None, valid_to="2026-12-31", membership_id=50):
    return {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": membership_id,
        "fullName": f"Member {user_id}",
        "phone": "0600000000",
        "email": f"m{user_id}@example.com",
        "accountUsernameId": f"user{user_id}",
        "validFrom": "2026-01-01",
        "validTo": valid_to,
        "firstCardId": card,
        "secondCardId": second_card,
        "image": None,
        "fingerprints": fps if fps is not None else [],
        "birthday": None,
        "imageSource": None,
    }


@pytest.fixture
def seeded(db):
    db.upsert_delta_users([
        _user(1, 100, card="1001", fps=[_TEMPLATE]),
        _user(2, 200, card="1002", second_card="2002"),
        _user(3, 300, card="1003", valid_to="2020-01-31"),  # expired
    ])
    # A membership title so the roster enrichment has something to resolve.
    db.save_sync_cache_delta(
        {
            "users": [],
            "membersDeltaMode": True,
            "validMemberIds": [1, 2, 3],
            "devices": [],
            "gymAccessCredentials": [],
            "infrastructures": [],
            "membership": [{"id": 50, "title": "Gold", "description": "", "price": 99.0, "durationInDays": 30}],
            "contractStatus": True,
            "contractEndDate": "2026-12-31",
            "accessSoftwareSettings": {},
        },
        {"members": False, "devices": False, "credentials": False, "settings": True},
    )
    return db


# --------------------------------------------------------------------------- 3a

class TestLoadLocalState:
    def test_reads_the_template_free_projection(self, seeded, monkeypatch):
        import app.core.access_verification as av

        real = av.list_sync_users_page
        seen: dict = {}

        def _recording(**kwargs):
            seen.update(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(av, "list_sync_users_page", _recording)

        av.load_local_state()

        assert seen == {"limit": 0, "offset": 0, "include_templates": False}

    def test_indexes_match_a_template_bearing_build_except_fingerprints(self, seeded):
        import app.core.access_verification as av

        creds, by_am, by_card = av.load_local_state()

        # What the state was built from before this change: templates included.
        reference = {u["userId"]: u for u in seeded.list_sync_users()}
        assert len(reference[100]["fingerprints"]) == 1, "seed must carry a real template"

        assert set(by_am) == {1, 2, 3}
        assert by_card["1001"][0]["userId"] == 100
        assert by_card["1002"][0]["userId"] == 200
        assert by_card["2002"][0]["userId"] == 200
        assert by_card["1003"][0]["userId"] == 300

        for amid, u in by_am.items():
            ref = reference[u["userId"]]
            assert set(ref) == set(u), "key set changed"
            differing = {k for k in ref if ref[k] != u[k]}
            assert differing <= {"fingerprints"}, f"am {amid}: unexpected fields changed: {differing}"

        # The CAUTION made concrete: the DB row has a template, the state does not.
        assert by_am[1]["fingerprints"] == []

    def test_user_without_membership_ids_is_still_indexed_by_user_id(self, db):
        """The userId fallback (device pin = userId when activeMembershipId is null) is
        unchanged by the projection switch."""
        import app.core.access_verification as av

        db.upsert_delta_users([_user(None, 400, card="1004", membership_id=None)])

        _creds, by_am, by_card = av.load_local_state()

        assert by_am[400]["userId"] == 400
        assert by_card["1004"][0]["userId"] == 400

    def test_no_local_state_consumer_reads_fingerprints(self):
        """Static guard for the CAUTION on list_sync_users_page: the three modules that
        build or consume the local state never index `fingerprints` on a user dict. If
        this fails, the new reader must switch load_local_state() back to a
        template-bearing read (or take templates from load_sync_cache())."""
        import app.core.access_verification as av
        import app.core.realtime_agent as ra
        import app.core.ultra_engine as ue

        reader = re.compile(r"""(\.get\(\s*["']fingerprints["']|\[\s*["']fingerprints["']\s*\])""")
        for mod in (av, ra, ue):
            src = pathlib.Path(mod.__file__).read_text(encoding="utf-8", errors="replace")
            hits = [
                (n, line.strip())
                for n, line in enumerate(src.splitlines(), start=1)
                if reader.search(line)
            ]
            assert hits == [], (
                f"{mod.__name__} reads user['fingerprints'] but the local state is "
                f"template-free (see list_sync_users_page CAUTION): {hits}"
            )


# --------------------------------------------------------------------------- 3b

class TestMembersRoster:
    def test_reads_the_template_free_projection(self, seeded, monkeypatch):
        import app.core.db as db_module

        real = db_module.list_sync_users_page
        seen: dict = {}

        def _recording(**kwargs):
            seen.update(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(db_module, "list_sync_users_page", _recording)

        db_module.list_members_roster()

        assert seen == {"limit": 0, "offset": 0, "include_templates": False}

    def test_rows_status_title_and_counts_are_unchanged(self, seeded):
        rows, total, counts = seeded.list_members_roster()

        assert total == 3
        assert counts == {"all": 3, "active": 2, "expired": 1, "pending": 0}
        by_id = {r["userId"]: r for r in rows}
        assert by_id[100]["status"] == "active"
        assert by_id[100]["membershipTitle"] == "Gold"
        assert by_id[100]["firstCardId"] == "1001"
        assert by_id[200]["secondCardId"] == "2002"
        assert by_id[300]["status"] == "expired"
        assert all(r["fingerprints"] == [] for r in rows), (
            "roster rows are template-free by design; nothing in the roster contract reads them"
        )

    def test_search_filter_sort_and_paging_are_unchanged(self, seeded):
        rows, total, _ = seeded.list_members_roster(q="member 2")
        assert total == 1 and rows[0]["userId"] == 200

        rows, total, _ = seeded.list_members_roster(status="expired")
        assert total == 1 and rows[0]["userId"] == 300

        rows, total, _ = seeded.list_members_roster(q="1003")
        assert total == 1 and rows[0]["userId"] == 300

        page1, total1, _ = seeded.list_members_roster(limit=2, offset=0, sort_by="name", sort_dir="desc")
        page2, total2, _ = seeded.list_members_roster(limit=2, offset=2, sort_by="name", sort_dir="desc")
        assert total1 == total2 == 3
        assert [r["userId"] for r in page1] == [300, 200]
        assert [r["userId"] for r in page2] == [100]
