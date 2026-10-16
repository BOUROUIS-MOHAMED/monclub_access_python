"""The Utilisateurs member card's extra data (Access v5 Card M).

GET /api/v2/members/{activeMembershipId}/card reads ONE membership when the card opens:

* 7a -- the fingerprint count, from that one row's ``fingerprints_json``. The roster itself
  stays template-free (tests/test_local_state_template_free.py); the card never returns a
  template.
* 7b -- the QR (TOTP) credentials whose granted ids contain the membership: state only, the
  secret never leaves the database.
* 7c -- GET /api/v2/members/{activeMembershipId}/history: the latest door events this PC stored
  for the person behind the membership, newest first, capped.

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


# --------------------------------------------------------------------------- 7b

_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def _cred(db, *, account_id, granted, enabled=1, secret=_SECRET):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO sync_gym_access_credentials (id, gym_id, account_id, secret_hex, enabled, "
            "rotated_at, created_at, updated_at, granted_active_membership_ids_json) "
            "VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)",
            (account_id, account_id, secret, enabled, "2026-09-01T10:00:00", "2026-01-01T00:00:00",
             "2026-09-01T10:00:00", json.dumps(granted)),
        )
        conn.commit()


class TestQrCredential:
    def test_a_granting_credential_is_reported_without_its_secret(self, db):
        db.upsert_delta_users([_user(12, 100, card="1012")])
        _cred(db, account_id=900, granted=[12, 40])

        d = db.get_member_card_details(12)

        assert d["qrCredentials"] == [
            {"enabled": True, "rotatedAt": "2026-09-01T10:00:00", "updatedAt": "2026-09-01T10:00:00"},
        ]
        assert _SECRET not in json.dumps(d)
        assert "secret" not in json.dumps(d).lower()

    def test_ids_are_compared_parsed_not_as_text(self, db):
        """12 must not match a credential granting 123 (a LIKE on the JSON text would)."""
        db.upsert_delta_users([_user(12, 100, card="1012")])
        _cred(db, account_id=901, granted=[123, 112])

        assert db.get_member_card_details(12)["qrCredentials"] == []

    def test_a_disabled_credential_is_reported_disabled(self, db):
        db.upsert_delta_users([_user(12, 100, card="1012")])
        _cred(db, account_id=902, granted=[12], enabled=0)

        assert [c["enabled"] for c in db.get_member_card_details(12)["qrCredentials"]] == [False]

    def test_the_endpoint_never_carries_the_secret(self, db):
        from app.api.local_access_api_v2 import _handle_member_card

        db.upsert_delta_users([_user(12, 100, card="1012")])
        _cred(db, account_id=903, granted=[12])

        ctx = _Ctx(params={"activeMembershipId": "12"})
        _handle_member_card(ctx)
        assert ctx.sent[0] == 200
        assert _SECRET not in json.dumps(ctx.sent[1])


# --------------------------------------------------------------------------- 7c

def _event(db, eid, *, created, user_id, amid, allowed=1, reason="", device_id=3, door_id=1,
           event_time=None, raw=None):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO access_history (created_at, event_id, device_id, door_id, card_no, event_time, "
            "event_type, allowed, reason, raw_json, history_source, user_id, active_membership_id) "
            "VALUES (?, ?, ?, ?, '1001', ?, 'CARD', ?, ?, ?, 'ULTRA', ?, ?)",
            (created, eid, device_id, door_id, event_time, allowed, reason,
             json.dumps(raw) if raw is not None else None, user_id, amid),
        )
        conn.commit()


class TestMemberHistory:
    def test_lists_the_persons_events_newest_first_and_capped(self, db):
        db.upsert_delta_users([_user(1, 100, card="1001"), _user(2, 200, card="1002")])
        for i in range(5):
            _event(db, f"e{i}", created=f"2026-10-1{i} 08:00:00", user_id=100, amid=1)
        _event(db, "other-person", created="2026-10-15 09:00:00", user_id=200, amid=2)
        _event(db, "unresolved", created="2026-10-15 10:00:00", user_id=None, amid=None)

        res = db.list_member_access_history(1, limit=3)

        assert res["userId"] == 100 and res["limit"] == 3
        assert [r["created_at"] for r in res["rows"]] == [
            "2026-10-14 08:00:00", "2026-10-13 08:00:00", "2026-10-12 08:00:00",
        ]

    def test_another_plan_of_the_same_person_is_listed_with_its_own_id(self, db):
        db.upsert_delta_users([_user(1, 100, card="1001"), _user(9, 100, card="1009", membership_id=51)])
        _event(db, "a", created="2026-10-10 08:00:00", user_id=100, amid=9)

        rows = db.list_member_access_history(1)["rows"]
        assert [r["active_membership_id"] for r in rows] == [9]

    def test_the_limit_is_bounded_and_unknown_ids_give_none(self, db):
        db.upsert_delta_users([_user(1, 100, card="1001")])
        assert db.list_member_access_history(1, limit=10_000)["limit"] == db.MEMBER_HISTORY_LIMIT_MAX
        assert db.list_member_access_history(1, limit=0)["limit"] == 20
        assert db.list_member_access_history(404) is None
        assert db.list_member_access_history(-1) is None

    def test_a_held_member_is_reached(self, db):
        db.upsert_delta_users([_user(7, 700, card="1007")])
        _event(db, "h", created="2026-10-10 08:00:00", user_id=700, amid=7)
        _hold(db, 7)

        assert len(db.list_member_access_history(7)["rows"]) == 1

    def test_the_query_uses_the_user_index(self, db):
        with db.get_conn() as conn:
            plan = " ".join(str(tuple(r)) for r in conn.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM access_history WHERE user_id = ? "
                "ORDER BY created_at DESC, id DESC LIMIT 10", (1,),
            ).fetchall())
        assert "ix_access_history_user_door_day" in plan

    def test_the_endpoint_shapes_rows_like_the_dashboard_feed(self, db, monkeypatch):
        import app.core.settings_reader as sr
        from app.api.local_access_api_v2 import _handle_member_history

        db.upsert_delta_users([_user(1, 100, card="1001")])
        _event(db, "ok", created="2026-10-10 08:00:05", event_time="2026-10-10 08:00:00",
               user_id=100, amid=1, raw={"scanMode": "QR"})
        _event(db, "no", created="2026-10-11 09:00:00", user_id=100, amid=1, allowed=0,
               reason="DENY_EXPIRED", door_id=2)
        monkeypatch.setattr(sr, "get_backend_global_settings", lambda: {"history_retention_days": 45})

        ctx = _Ctx(params={"activeMembershipId": "1"}, query={"limit": "5"})
        _handle_member_history(ctx)
        status, body = ctx.sent

        assert status == 200 and body["retentionDays"] == 45 and body["limit"] == 5
        refused, granted = body["rows"]
        assert refused["allowed"] is False and refused["reason"] == "DENY_EXPIRED" and refused["doorId"] == 2
        assert refused["at"] == "2026-10-11T09:00:00"          # no event time: the receive time
        assert granted["allowed"] is True and granted["method"] == "QR_CODE"
        assert granted["at"] == "2026-10-10T08:00:00"          # the event time first
        assert granted["activeMembershipId"] == 1

        ctx = _Ctx(params={"activeMembershipId": "77"})
        _handle_member_history(ctx)
        assert ctx.sent[0] == 404


class TestCardEndpoint:
    def test_route_is_registered(self):
        from access.local_api_routes import ACCESS_LOCAL_ROUTE_SPECS

        assert ("GET", "/api/v2/members/{activeMembershipId}/card", "_handle_member_card") in ACCESS_LOCAL_ROUTE_SPECS
        assert ("GET", "/api/v2/members/{activeMembershipId}/history", "_handle_member_history") in ACCESS_LOCAL_ROUTE_SPECS

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
