"""`list_sync_users_page(include_templates=False)` must drop ONLY the template blobs.

WHY THIS FILE EXISTS
--------------------
Field measurement, OXYGENE_FIT PC, v1.4.26 (2026-08-30): the Utilisateurs / Base locale
pages took up to 8.8s to render 934 members. The existing DB_READ_users_split telemetry
localised it precisely — the cost is disk I/O, not parsing::

    DB_READ_users_split rows=934 select_ms=6828 coerce_ms=47  projected_ms=562
    DB_READ_users_split rows=934 select_ms=6062 coerce_ms=266 projected_ms=469

Those 934 members carry 999 base64 fingerprint templates in `sync_users.fingerprints_json`,
which is the bulk of every row. `SELECT *` read all of it on every page load even though
the FK-chip consumer only wants ids and card numbers.

The risk this introduces — and what these tests pin — is that an omitted template set is
INDISTINGUISHABLE from a member who genuinely has no fingerprints. So: the flag must
default to including them, every non-template field must survive, and the endpoint must
say which mode it answered in.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "_DB_PATH", str(tmp_path / "test.db"), raising=False)
    db_module.init_db()
    return db_module


def _user(am_id: int, user_id: int, *, card: str, fps: list | None = None) -> dict:
    return {
        "activeMembershipId": am_id,
        "userId": user_id,
        "membershipId": 50,
        "fullName": f"Member {user_id}",
        "phone": "0600000000",
        "email": f"m{user_id}@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": card,
        "secondCardId": None,
        "image": None,
        "fingerprints": fps if fps is not None else [],
        "birthday": None,
        "imageSource": None,
    }


_TEMPLATE = {
    "id": 166,
    "fingerId": 0,
    "templateVersion": 10,
    "templateEncoding": "BASE64",
    "templateData": "ShtTUzIxAAADWFsECAUHCc7QAAAvWXYB" * 24,  # ~= a real 856-byte blob
    "templateSize": 856,
    "enabled": True,
}


@pytest.fixture
def seeded(db):
    db.upsert_delta_users([
        _user(1, 100, card="1001", fps=[_TEMPLATE]),
        _user(2, 200, card="1002", fps=[]),
    ])
    return db


class TestDefaultIsUnchanged:
    def test_default_includes_templates(self, seeded):
        users, total = seeded.list_sync_users_page()
        assert total == 2
        by_id = {u["userId"]: u for u in users}
        assert len(by_id[100]["fingerprints"]) == 1
        assert by_id[100]["fingerprints"][0]["templateData"] == _TEMPLATE["templateData"]

    def test_explicit_true_matches_default(self, seeded):
        a, _ = seeded.list_sync_users_page()
        b, _ = seeded.list_sync_users_page(include_templates=True)
        assert a == b

    def test_list_sync_users_still_carries_templates(self, seeded):
        """The roster/push path must never lose templates."""
        users = seeded.list_sync_users()
        by_id = {u["userId"]: u for u in users}
        assert len(by_id[100]["fingerprints"]) == 1


class TestExcludingTemplates:
    def test_templates_are_omitted(self, seeded):
        users, total = seeded.list_sync_users_page(include_templates=False)
        assert total == 2
        assert all(u["fingerprints"] == [] for u in users)

    def test_every_other_field_survives(self, seeded):
        """Only fingerprints may differ — a dropped column would be a silent data loss."""
        full, _ = seeded.list_sync_users_page(include_templates=True)
        lean, _ = seeded.list_sync_users_page(include_templates=False)
        assert len(full) == len(lean)
        for f, l in zip(full, lean):
            assert set(f.keys()) == set(l.keys()), "key set changed"
            differing = {k for k in f if f[k] != l[k]}
            assert differing <= {"fingerprints"}, f"unexpected fields changed: {differing}"

    def test_identity_fields_the_fk_map_needs_are_intact(self, seeded):
        """The one caller that opts in builds FK chips from these."""
        lean, _ = seeded.list_sync_users_page(include_templates=False)
        by_id = {u["userId"]: u for u in lean}
        assert set(by_id) == {100, 200}
        assert by_id[100]["firstCardId"] == "1001"
        assert by_id[200]["firstCardId"] == "1002"

    def test_paging_still_works(self, seeded):
        page, total = seeded.list_sync_users_page(limit=1, offset=0, include_templates=False)
        assert total == 2 and len(page) == 1

    def test_projection_is_introspected_not_hardcoded(self, seeded):
        """A literal column list would silently drop columns added by a migration."""
        with seeded.get_conn() as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(sync_users)").fetchall()}
        # Prove the table really does carry the blob column we are excluding.
        assert "fingerprints_json" in cols
        users, _ = seeded.list_sync_users_page(include_templates=False)
        assert users, "introspected projection returned no rows"


class TestEndpointReportsItsMode:
    """A stripped response must never be mistakable for a roster with no fingerprints."""

    def test_handler_flags_the_mode(self, seeded, monkeypatch):
        import app.api.local_access_api_v2 as v2

        captured: dict = {}

        class _Ctx:
            def q_int(self, *_a, **kw):
                return kw.get("default", 0)

            def q(self, *_names, default=None):
                return self._templates

            def send_json(self, status, payload):
                captured["status"] = status
                captured["payload"] = payload

        ctx = _Ctx()
        ctx._templates = "0"
        v2._handle_sync_cache_users(ctx)
        assert captured["status"] == 200
        assert captured["payload"]["templatesIncluded"] is False
        assert all(u["fingerprints"] == [] for u in captured["payload"]["users"])

        ctx._templates = "1"
        v2._handle_sync_cache_users(ctx)
        assert captured["payload"]["templatesIncluded"] is True
        assert any(u["fingerprints"] for u in captured["payload"]["users"])

    @pytest.mark.parametrize("raw", ["0", "false", "FALSE", "no", "off"])
    def test_falsy_spellings_all_disable(self, seeded, raw):
        import app.api.local_access_api_v2 as v2
        captured: dict = {}

        class _Ctx:
            def q_int(self, *_a, **kw): return kw.get("default", 0)
            def q(self, *_names, default=None): return raw
            def send_json(self, status, payload): captured["payload"] = payload

        v2._handle_sync_cache_users(_Ctx())
        assert captured["payload"]["templatesIncluded"] is False

    def test_absent_param_keeps_templates(self, seeded):
        """Omitting ?templates must behave exactly as before this change."""
        import app.api.local_access_api_v2 as v2
        captured: dict = {}

        class _Ctx:
            def q_int(self, *_a, **kw): return kw.get("default", 0)
            def q(self, *_names, default=None): return default
            def send_json(self, status, payload): captured["payload"] = payload

        v2._handle_sync_cache_users(_Ctx())
        assert captured["payload"]["templatesIncluded"] is True
