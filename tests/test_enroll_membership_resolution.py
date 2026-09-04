"""Enrolment must never guess which membership a fingerprint belongs to.

FIELD INCIDENT — OXYGENE_FIT, 2026-08-30, v1.4.27
-------------------------------------------------
The ZK9500 captured all three samples correctly and the enrolment then failed on the
backend save::

    createUserFingerprint failed: HTTP 403 -> {"status":false,
      "errorMsg":"You can only manage fingerprints for memberships in your own gym.",
      "code":"FORBIDDEN", ... } | traceId=d09bb4958ccb4de9

`POST /api/v2/enroll/start` accepted only `userId`, so the desktop re-derived the
membership from its local cache. Two defects in that derivation, both provable from the
gym's own sync payload (934 users):

1. **Plan-id fallback.** `_find_user_membership` fell back to `membershipId` when
   `activeMembershipId` was absent. Those are different id spaces — plan ids span
   30..396 (71 distinct), activeMembershipId spans 7..34418 (934 distinct), and the two
   sets have **zero overlap**. The fallback could therefore only ever name a row the
   backend would refuse, producing exactly the 403 above.

2. **First-match wins.** One person can hold several active memberships in the SAME gym:
   `userId=35` maps to both `activeMembershipId=29849` and `30008`. Returning the first
   silently wrote the fingerprint to an arbitrary one and reported success.

These tests pin the fixes: no plan-id substitution, no silent pick on ambiguity, and an
explicit `activeMembershipId` from the caller is honoured and forwarded.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest


def _main_app():
    try:
        from app.ui.app import MainApp
    except Exception as e:  # heavy module (Tkinter/scanner) — fine to skip
        pytest.skip(f"MainApp import unavailable: {e}")
    return MainApp


def _user(user_id, am_id, membership_id, name="Member"):
    return {
        "userId": user_id,
        "activeMembershipId": am_id,
        "membershipId": membership_id,
        "fullName": name,
    }


def _resolve(monkeypatch, users, user_id):
    """Call the real _find_user_membership against a faked sync cache."""
    MainApp = _main_app()
    import app.ui.app as app_module

    monkeypatch.setattr(
        app_module, "load_sync_cache", lambda: SimpleNamespace(users=users), raising=False
    )
    self_obj = SimpleNamespace(logger=logging.getLogger("test-enroll-resolution"))
    return MainApp._find_user_membership(self_obj, user_id)


class TestNoPlanIdFallback:
    """`membershipId` is a PLAN id and must never stand in for a membership."""

    def test_missing_active_membership_returns_none_not_the_plan_id(self, monkeypatch):
        users = [_user(35, None, 30, "malek Djait")]
        am, _obj = _resolve(monkeypatch, users, 35)
        assert am is None, "fell back to the plan id — this is what produced the 403"

    def test_empty_string_active_membership_also_returns_none(self, monkeypatch):
        users = [_user(35, "", 306, "malek Djait")]
        am, _obj = _resolve(monkeypatch, users, 35)
        assert am is None

    def test_plan_id_is_never_returned_for_any_row(self, monkeypatch):
        """Guards the whole id space, not just one example."""
        plan_ids = {30, 306, 396}
        users = [_user(35, None, 30), _user(36, "", 306), _user(37, None, 396)]
        for uid in (35, 36, 37):
            am, _ = _resolve(monkeypatch, users, uid)
            assert am not in plan_ids
            assert am is None


class TestMultipleMembershipsPickTheNewest:
    """Measured on the OXYGENE_FIT payload (2026-08-31): 20 of 914 members carry two
    activeMembershipIds and BOTH rows are date-valid, so refusing would block real
    members. 18 of those 20 pairs share an identical validFrom, so only the ascending
    id can break the tie. The one case cross-checkable against the dashboard
    (userId=35 -> 29849 / 30008) shows 30008 there, which is what this rule picks."""

    def test_two_memberships_resolve_to_the_newest(self, monkeypatch):
        """The exact shape observed in the field: userId=35 -> 29849 AND 30008."""
        users = [
            _user(35, 29849, 30, "malek Djait"),
            _user(35, 30008, 306, "malek Djait"),
        ]
        am, obj = _resolve(monkeypatch, users, 35)
        assert am == 30008, "must pick the newest membership, not block and not guess low"
        assert obj is not None and obj.get("membershipId") == 306, (
            "the returned member object must be the row that was CHOSEN"
        )

    def test_choice_is_independent_of_row_order(self, monkeypatch):
        """Cache order must not decide which membership gets the fingerprint."""
        a = _user(35, 29849, 30, "malek Djait")
        b = _user(35, 30008, 306, "malek Djait")
        assert _resolve(monkeypatch, [a, b], 35)[0] == 30008
        assert _resolve(monkeypatch, [b, a], 35)[0] == 30008

    def test_identical_validfrom_still_resolves(self, monkeypatch):
        """18 of the 20 real pairs share a validFrom — dates cannot break that tie."""
        users = [
            dict(_user(68853, 30320, 285), validFrom="2026-04-21", validTo="2026-10-20"),
            dict(_user(68853, 32317, 355), validFrom="2026-04-21", validTo="2026-10-20"),
        ]
        am, _ = _resolve(monkeypatch, users, 68853)
        assert am == 32317

    def test_the_choice_is_logged_with_all_candidates(self, monkeypatch, caplog):
        """A silent pick is the thing to avoid — the log must name what it chose."""
        users = [_user(35, 29849, 30), _user(35, 30008, 306)]
        with caplog.at_level(logging.WARNING, logger="test-enroll-resolution"):
            _resolve(monkeypatch, users, 35)
        assert "has 2 active memberships" in caplog.text
        assert "29849" in caplog.text and "30008" in caplog.text
        assert "using the newest" in caplog.text.lower()

    def test_single_membership_still_resolves(self, monkeypatch):
        """The ordinary case must be untouched."""
        users = [_user(68294, 29848, 30, "Malek Djait"), _user(35, 30008, 306)]
        am, obj = _resolve(monkeypatch, users, 68294)
        assert am == 29848
        assert obj["fullName"] == "Malek Djait"

    def test_unknown_user_returns_none(self, monkeypatch):
        am, obj = _resolve(monkeypatch, [_user(1, 100, 30)], 999)
        assert am is None and obj is None

    def test_duplicate_rows_with_the_SAME_membership_are_not_ambiguous(self, monkeypatch):
        """A repeated identical row is not a real conflict — do not block on it."""
        users = [_user(35, 29849, 30), _user(35, 29849, 30)]
        am, _ = _resolve(monkeypatch, users, 35)
        assert am == 29849


class TestEndpointAcceptsExplicitMembership:
    """The dashboard knows the membership; the endpoint must accept and forward it."""

    def _ctx(self, body):
        sent = {}

        class _Ctx:
            def body(self_inner):
                return body

            def send_json(self_inner, status, payload):
                sent["status"] = status
                sent["payload"] = payload

        return _Ctx(), sent

    def _run(self, monkeypatch, body):
        import app.api.local_access_api_v2 as v2

        captured = {}

        def _begin(**kw):
            captured.update(kw)
            return {"ok": True}

        ctx, sent = self._ctx(body)
        ctx.app = SimpleNamespace(begin_remote_enroll=_begin)
        monkeypatch.setattr(v2, "_enroll_set_start_meta", lambda meta: captured.setdefault("meta", meta))
        monkeypatch.setattr(v2, "_enroll_add_log", lambda *_a, **_k: None)
        v2._handle_enroll_start(ctx)
        return captured, sent

    def test_active_membership_id_is_forwarded(self, monkeypatch):
        captured, sent = self._run(monkeypatch, {
            "target": "backend", "userId": "35", "fingerId": "1",
            "fullName": "malek Djait", "activeMembershipId": 30008,
        })
        assert captured["active_membership_id"] == "30008"
        assert sent["status"] == 202

    def test_snake_case_spelling_is_accepted(self, monkeypatch):
        captured, _ = self._run(monkeypatch, {
            "target": "backend", "userId": "35", "fingerId": "1",
            "active_membership_id": 30008,
        })
        assert captured["active_membership_id"] == "30008"

    def test_absent_membership_keeps_old_behaviour(self, monkeypatch):
        """Omitting it must not change anything for existing callers."""
        captured, sent = self._run(monkeypatch, {
            "target": "backend", "userId": "35", "fingerId": "1",
        })
        assert captured["active_membership_id"] == ""
        assert sent["status"] == 202

    def test_start_meta_exposes_the_membership(self, monkeypatch):
        """SSE clients should be able to see which membership is being enrolled."""
        captured, _ = self._run(monkeypatch, {
            "target": "backend", "userId": "35", "fingerId": "1",
            "activeMembershipId": 30008,
        })
        assert captured["meta"]["activeMembershipId"] == "30008"


class TestBeginRemoteEnrollValidatesTheOverride:
    def _app(self):
        MainApp = _main_app()
        import threading
        return MainApp, SimpleNamespace(
            logger=logging.getLogger("test-enroll-resolution"),
            _enroll_state_lock=threading.Lock(),
            _enroll_running=False,
            _enroll_cancel_event=threading.Event(),
        )

    def test_non_numeric_membership_is_rejected_with_400(self):
        MainApp, self_obj = self._app()
        res = MainApp.begin_remote_enroll(
            self_obj, user_id="35", finger_id="1", active_membership_id="not-a-number",
        )
        assert res["ok"] is False
        assert res["status"] == 400
        assert "activeMembershipId" in res["error"]

    def test_rejection_happens_before_claiming_the_enroll_lock(self):
        """A bad argument must not leave the app stuck in 'enroll running'."""
        MainApp, self_obj = self._app()
        MainApp.begin_remote_enroll(
            self_obj, user_id="35", finger_id="1", active_membership_id="oops",
        )
        assert self_obj._enroll_running is False
