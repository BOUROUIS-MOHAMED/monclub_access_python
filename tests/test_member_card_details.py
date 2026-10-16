"""The Utilisateurs member card's extra data (Access v5 Card M).

GET /api/v2/members/{activeMembershipId}/card reads ONE membership when the card opens:

* 7a -- the fingerprint count, from that one row's ``fingerprints_json``. The roster itself
  stays template-free (tests/test_local_state_template_free.py); the card never returns a
  template.

Every test patches ``app.core.db._DB_PATH`` to a temp file.
"""

from __future__ import annotations

import json

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module

    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    yield db_module
    if hasattr(db_module, "_shutdown_db_writer_for_tests"):
        db_module._shutdown_db_writer_for_tests()


_TEMPLATE_DATA = "ShtTUzIxAAADWFsECAUHCc7QAAAvWXYB" * 24


def _fp(finger_id, *, enabled=True, label=None):
    d = {
        "id": 160 + finger_id,
        "fingerId": finger_id,
        "templateVersion": 10,
        "templateEncoding": "BASE64",
        "templateData": _TEMPLATE_DATA,
        "templateSize": 856,
        "enabled": enabled,
    }
    if label is not None:
        d["label"] = label
    return d


def _user(am_id, user_id, *, card, fps=None, valid_to="2026-12-31", membership_id=50):
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
        "secondCardId": None,
        "image": None,
        "fingerprints": fps if fps is not None else [],
        "birthday": None,
        "imageSource": None,
    }


def _hold(db, am_id, *, reason="frozen", for_date="2026-10-16"):
    """Move a sync_users row into sync_users_held the way the date flip does (column copy)."""
    cols = ", ".join(db._SYNC_USER_COLUMNS)
    with db.get_conn() as conn:
        conn.execute(
            f"INSERT INTO sync_users_held ({cols}, held_reason, held_for_date, held_at) "
            f"SELECT {cols}, ?, ?, ? FROM sync_users WHERE active_membership_id = ?",
            (reason, for_date, "2026-10-16 00:00:05", am_id),
        )
        conn.execute("DELETE FROM sync_users WHERE active_membership_id = ?", (am_id,))
        conn.commit()


class _Ctx:
    def __init__(self, params=None, query=None, app=None):
        self.params = params or {}
        self._q = query or {}
        self.app = app
        self.sent = None

    def param_int(self, name, default=0):
        try:
            return int(self.params.get(name, ""))
        except Exception:
            return default

    def q_int(self, *names, default=0):
        for n in names:
            if n in self._q:
                try:
                    return int(self._q[n])
                except Exception:
                    return default
        return default

    def send_json(self, status, payload):
        # Through json like the real handler, so a non-serialisable value fails here too.
        self.sent = (status, json.loads(json.dumps(payload)))


# --------------------------------------------------------------------------- 7a

class TestFingerprintCount:
    def test_counts_the_prints_of_the_row_without_returning_a_template(self, db):
        db.upsert_delta_users([
            _user(1, 100, card="1001", fps=[_fp(0), _fp(3, enabled=False, label="index")]),
            _user(2, 200, card="1002"),
        ])

        d = db.get_member_card_details(1)

        assert d["fingerprintCount"] == 2
        assert d["fingerprints"] == [
            {"fingerId": 0, "label": None, "enabled": True},
            {"fingerId": 3, "label": "index", "enabled": False},
        ]
        assert d["userId"] == 100 and d["held"] is False
        assert _TEMPLATE_DATA not in json.dumps(d)
        assert "templateData" not in json.dumps(d)

        none = db.get_member_card_details(2)
        assert none["fingerprintCount"] == 0 and none["fingerprints"] == []

    def test_a_held_row_is_read_from_sync_users_held(self, db):
        db.upsert_delta_users([_user(7, 700, card="1007", fps=[_fp(1)])])
        _hold(db, 7)

        d = db.get_member_card_details(7)

        assert d["held"] is True
        assert d["fingerprintCount"] == 1

    def test_unknown_or_invalid_ids_give_none(self, db):
        assert db.get_member_card_details(999) is None
        assert db.get_member_card_details(0) is None
        assert db.get_member_card_details("x") is None

    def test_the_roster_stays_template_free(self, db, monkeypatch):
        """The card's per-row read must not have leaked into the roster (the 8.8 s trap)."""
        real = db.list_sync_users_page
        seen = {}

        def _recording(**kwargs):
            seen.update(kwargs)
            return real(**kwargs)

        monkeypatch.setattr(db, "list_sync_users_page", _recording)
        db.list_members_roster()
        assert seen.get("include_templates") is False


class TestCardEndpoint:
    def test_route_is_registered(self):
        from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS

        assert ("GET", "/api/v2/members/{activeMembershipId}/card", "_handle_member_card") in ACCESS_LOCAL_ROUTE_SPECS

    def test_router_matches_the_card_path_and_not_the_post_routes(self):
        from app.api.local_access_api_v2 import _Router

        r = _Router()
        r.add("GET", "/api/v2/members/{activeMembershipId}/card", lambda c: "card")
        r.add("POST", "/api/v2/members/photo", lambda c: "photo")
        h, params = r.match("GET", "/api/v2/members/42/card")
        assert h is not None and params == {"activeMembershipId": "42"}
        h, _ = r.match("GET", "/api/v2/members/photo")
        assert h is None

    def test_handler_answers_200_404_400(self, db):
        from app.api.local_access_api_v2 import _handle_member_card

        db.upsert_delta_users([_user(1, 100, card="1001", fps=[_fp(0)])])

        ctx = _Ctx(params={"activeMembershipId": "1"})
        _handle_member_card(ctx)
        status, body = ctx.sent
        assert status == 200 and body["ok"] is True and body["fingerprintCount"] == 1
        assert "templateData" not in json.dumps(body)

        ctx = _Ctx(params={"activeMembershipId": "5"})
        _handle_member_card(ctx)
        assert ctx.sent[0] == 404

        ctx = _Ctx(params={"activeMembershipId": "abc"})
        _handle_member_card(ctx)
        assert ctx.sent[0] == 400
