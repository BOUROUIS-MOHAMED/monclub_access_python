"""The sync cache is the SOLE authority for a member's fingerprint templates (F12).

THE SECURITY DEFECT THIS PINS
-----------------------------
``_collect_templates_for_pin`` used to treat the local SQLite ``fingerprints``
table as a FALLBACK whenever the collected list came out empty::

    if out:
        ...
        return [...]
    recs = local_fp_index.get(pin) or []     # <-- stale local copy

The emptiness produced by the ``enabled is False`` filter, a few lines above, was
itself the trigger. So disabling a finger did not merely fail to be honoured -- it
ACTIVELY CAUSED the stale local template to be pushed back to the door, restoring
access the gym believed it had removed. Same for deleting the finger outright: the
backend sends an empty list, and the empty list summons the old copy.

FIVE inputs empty the collected list, and every one of them used to reach the
fallback:

  1. the gym deleted the fingerprint      -> backend sends ``fingerprints: []``
  2. the gym disabled it                  -> ``enabled: false``
  3. the member never enrolled            -> ``[]``
  4. the key is absent entirely           -> defensive; cannot occur in production
  5. ``templateData`` is blank/whitespace  -> the row is skipped by the loop

WHY DELETION, NOT A SMARTER FALLBACK
------------------------------------
The fallback had no live writer. ``db.insert_fingerprint`` has no caller anywhere
in the repo, local enrol is refused by the API, and offline enrolment defers into
``offline_creation_queue`` -- a different table. Rows can only exist on a PC
upgraded from a pre-split install, carried by the one-time table copy in
``shared/storage_migration`` (``fingerprints`` is in ACCESS_OWNED_TABLES).

So there is no producer that could ever mean "the backend has no opinion about
this member", and teaching the payload to express that distinction would have
changed ``_coerce_user_row_to_payload`` -- which every roster consumer depends on
-- to feed a branch nothing can trigger.

``local_fp_index`` stays in the signature: callers and several tests bind it by
keyword. It is simply never read. ``_build_local_fp_index_for_pins`` also stays --
tests/test_standalone_incremental_sync.py and tests/test_zk_standalone_driver.py
monkeypatch it with an exact keyword signature.

KNOWN, DELIBERATE CONSEQUENCE
-----------------------------
A member whose template exists ONLY as a never-uploaded legacy local row loses
fingerprint access and must re-enrol. Card and PIN are unaffected. Enumerate them
per site BEFORE rollout with ``db.list_unconfirmed_fingerprints()`` or
``GET /fingerprints``.

This function is shared with the standalone path
(``ultra_engine._build_standalone_roster``), so the fix covers both device families.
"""
from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from app.core.device_sync import DeviceSyncEngine


CURRENT = "Q1VSUkVOVA=="
STALE = "U1RBTEU="


class _LegacyRow:
    """A row as it survives on a PC upgraded from a pre-split install."""

    def __init__(self, finger_id=6, data=STALE, version=10, size=512):
        self.id = 1
        self.pin = "1001"
        self.finger_id = finger_id
        self.template_data = data
        self.template_version = version
        self.template_size = size


@pytest.fixture()
def engine():
    return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))


def _collect(engine, user, *, legacy=True):
    return engine._collect_templates_for_pin(
        user=user,
        pin="1001",
        local_fp_index={"1001": [_LegacyRow()]} if legacy else {},
        fingerprint_enabled=True,
    )


def _fp(**over):
    base = {"fingerId": 6, "templateVersion": 10, "templateSize": 512,
            "templateData": CURRENT, "enabled": True}
    base.update(over)
    return base


class TestTheSyncCacheIsAuthoritative:
    def test_a_live_fingerprint_is_pushed(self, engine):
        """The control: normal members must be unaffected."""
        got = _collect(engine, {"fingerprints": [_fp()]})
        assert len(got) == 1
        assert got[0]["templateData"] == CURRENT

    def test_a_deleted_fingerprint_does_not_resurrect(self, engine):
        """Gym deleted it -> backend sends []. Nothing may be pushed."""
        assert _collect(engine, {"fingerprints": []}) == []

    def test_a_disabled_fingerprint_does_not_resurrect(self, engine):
        """The sharp one: `enabled is False` empties the list, and that emptiness
        was itself what summoned the stale local copy."""
        assert _collect(engine, {"fingerprints": [_fp(enabled=False)]}) == []

    def test_an_absent_fingerprints_key_does_not_resurrect(self, engine):
        """Defensive -- this shape cannot occur in production today."""
        assert _collect(engine, {}) == []

    def test_a_blank_template_does_not_resurrect(self, engine):
        """The fifth trigger: a present row whose templateData is whitespace."""
        assert _collect(engine, {"fingerprints": [_fp(templateData="   ")]}) == []

    def test_a_non_list_fingerprints_value_does_not_resurrect(self, engine):
        assert _collect(engine, {"fingerprints": None}) == []

    def test_the_backend_wins_even_when_a_legacy_row_disagrees(self, engine):
        """Both present: the cache's template is pushed, never the local one."""
        got = _collect(engine, {"fingerprints": [_fp()]})
        assert [g["templateData"] for g in got] == [CURRENT]
        assert all(g["templateData"] != STALE for g in got)

    def test_a_partial_revocation_leaves_only_the_live_finger(self, engine):
        """Finger 6 disabled, finger 2 live -> only finger 2 is pushed, and the
        disabled slot does NOT fall back."""
        got = _collect(engine, {"fingerprints": [
            _fp(fingerId=6, enabled=False),
            _fp(fingerId=2, templateData=CURRENT),
        ]})
        assert [g["fingerId"] for g in got] == [2]

    def test_disabling_is_honoured_with_no_legacy_rows_present(self, engine):
        """Same expectation on a clean PC -- the outcome must not depend on
        whether legacy rows happen to exist."""
        assert _collect(engine, {"fingerprints": [_fp(enabled=False)]}, legacy=False) == []

    @pytest.mark.parametrize("disabled", [False, 0, "false", "False", "0", "no", "off"])
    def test_every_spelling_of_disabled_is_honoured(self, engine, disabled):
        """F6: `is False` matched only the bool singleton, so enabled=0 / "false" /
        "0" / "off" all sailed through as ENABLED.

        Java serialises a real bool today, so this is defence in depth -- but the
        client is the ONLY enforcement point: no backend path filters disabled
        templates out of the outgoing payload.
        """
        assert _collect(engine, {"fingerprints": [_fp(enabled=disabled)]}) == []

    @pytest.mark.parametrize("enabled", [True, 1, "true", "yes", "on", None])
    def test_enabled_and_absent_values_still_push(self, engine, enabled):
        """default=True is load-bearing: most payloads omit the key entirely, and an
        absent flag must mean ENABLED, not revoked."""
        got = _collect(engine, {"fingerprints": [_fp(enabled=enabled)]})
        assert [g["templateData"] for g in got] == [CURRENT]

    def test_a_missing_enabled_key_pushes(self, engine):
        fp = _fp()
        del fp["enabled"]
        assert len(_collect(engine, {"fingerprints": [fp]})) == 1

    def test_f6_and_f12_compose(self, engine):
        """The pair that matters: a falsy-string disable must empty the list AND the
        emptiness must not summon the stale local row. Before F6 it was not filtered
        at all; before F12 filtering it caused the resurrection."""
        got = _collect(engine, {"fingerprints": [_fp(enabled="false")]}, legacy=True)
        assert got == []

    def test_fingerprint_disabled_device_still_short_circuits(self, engine):
        """The fingerprint_enabled gate is untouched by this change."""
        got = engine._collect_templates_for_pin(
            user={"fingerprints": [_fp()]}, pin="1001",
            local_fp_index={"1001": [_LegacyRow()]}, fingerprint_enabled=False,
        )
        assert got == []
