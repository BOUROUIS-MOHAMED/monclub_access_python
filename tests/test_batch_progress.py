"""Regression tests for live batch sync progress reporting."""

import logging
from unittest.mock import MagicMock, patch


def make_engine(tmp_path, monkeypatch):
    import app.core.db as db_module

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "_DB_PATH", db_path, raising=False)
    db_module.init_db()

    from app.core.device_sync import DeviceSyncEngine

    return DeviceSyncEngine(cfg=MagicMock(), logger=logging.getLogger("test"))


def make_device(dev_id=1):
    return {
        "id": dev_id,
        "name": "TestDevice",
        "ipAddress": "10.0.0.1",
        "portNumber": 4370,
        "password": "",
        "active": True,
        "accessDevice": True,
        "accessDataMode": "DEVICE",
        "fingerprintEnabled": False,
        "authorizeTimezoneId": 1,
        "doorIds": [15],
        "doorPresets": [],
        "pushingToDevicePolicy": "ALL",
    }


def make_user(am_id):
    return {
        "activeMembershipId": am_id,
        "userId": am_id + 1000,
        "membershipId": am_id,
        "fullName": f"User {am_id}",
        "phone": "0600000000",
        "email": f"u{am_id}@example.com",
        "validFrom": "2026-01-01",
        "validTo": "2026-12-31",
        "firstCardId": str(am_id * 100),
        "secondCardId": None,
        "image": None,
        "fingerprints": [],
        "faceId": None,
        "accountUsernameId": None,
        "qrCodePayload": None,
        "birthday": None,
        "imageSource": None,
        "userImageStatus": None,
    }


def test_batch_push_reports_final_progress(tmp_path, monkeypatch):
    """
    Batch sync exposes final progress = total on completion.

    P0-bulk: per-pin pre-delete is skipped under the default "upsert" strategy,
    so intermediate progress ticks during pre-delete no longer exist. The
    observable contract is that the terminal snapshot reports current == total.
    """
    svc = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 21)]

    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    sdk_inst.get_device_data_rows.return_value = []
    sdk_inst.set_device_data.return_value = 0
    sdk_inst.set_device_data_batch.return_value = (20, [])
    sdk_inst.clear_device_table.return_value = 0
    sdk_inst.delete_device_data.return_value = 0
    sdk_inst.__enter__ = lambda s: s
    sdk_inst.__exit__ = MagicMock(return_value=False)

    progress_updates = []
    orig_set_progress = svc._set_progress

    def record_progress(**changes):
        orig_set_progress(**changes)
        progress_updates.append(svc.get_progress_snapshot()[0])

    monkeypatch.setattr(svc, "_set_progress", record_progress)

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    assert progress_updates, "Expected at least one progress snapshot"
    assert progress_updates[-1]["current"] == len(users)
    assert progress_updates[-1]["total"] == len(users)


def test_batch_push_emits_intermediate_progress_ticks(tmp_path, monkeypatch):
    """
    Under the upsert strategy the per-pin predelete loop is gone — which
    previously caused the dashboard to be stuck at 0% for the full duration
    of a multi-minute sync because no progress ticks fired.

    Regression guard: during the batch phase, set_device_data_batch must emit
    progress updates per chunk via the progress_cb hook, and the engine must
    wire the hook so the dashboard sees current moving from 0 towards total.
    """
    svc = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 126)]  # 125 users -> 3 chunks of 50

    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    sdk_inst.get_device_data_rows.return_value = []
    sdk_inst.clear_device_table.return_value = 0
    sdk_inst.delete_device_data.return_value = 0
    sdk_inst.supports_delete_device_data.return_value = True
    sdk_inst.__enter__ = lambda s: s
    sdk_inst.__exit__ = MagicMock(return_value=False)

    # Forward to the real implementation so progress_cb actually fires per chunk.
    from app.sdk.pullsdk import PullSDK as RealPullSDK

    def real_batch(*, table, rows, chunk_size=50, progress_cb=None):
        ok = 0
        for i in range(0, len(rows), chunk_size):
            chunk = rows[i:i + chunk_size]
            ok += len(chunk)
            if progress_cb is not None:
                progress_cb(ok, len(rows))
        return (ok, [])

    sdk_inst.set_device_data_batch.side_effect = real_batch
    sdk_inst.set_device_data.return_value = 0

    progress_snapshots: list = []
    orig_set_progress = svc._set_progress

    def record(**changes):
        orig_set_progress(**changes)
        snap, _ = svc.get_progress_snapshot()
        progress_snapshots.append(dict(snap))

    monkeypatch.setattr(svc, "_set_progress", record)

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    # Collect intermediate currents strictly between 0 and total (excludes the
    # initial 0 and the final terminal value).
    currents_over_time = [s.get("current", 0) for s in progress_snapshots]
    intermediate = [c for c in currents_over_time if 0 < c < len(users)]
    assert intermediate, (
        "Expected per-chunk progress ticks during batch phase; got only "
        f"{sorted(set(currents_over_time))}"
    )
    assert progress_snapshots[-1].get("current") == len(users)


def test_batch_push_predelete_skipped_under_upsert_strategy(tmp_path, monkeypatch):
    """
    P0-bulk: under default "upsert" insert_strategy, no per-pin DeleteDeviceData
    calls should fire before the batch insert (saves 4×N SDK round-trips).
    """
    svc = make_engine(tmp_path, monkeypatch)
    users = [make_user(am_id=i) for i in range(1, 21)]

    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    sdk_inst.get_device_data_rows.return_value = []
    sdk_inst.set_device_data.return_value = 0
    sdk_inst.set_device_data_batch.return_value = (20, [])
    sdk_inst.clear_device_table.return_value = 0
    sdk_inst.delete_device_data.return_value = 0
    sdk_inst.supports_delete_device_data.return_value = True
    sdk_inst.__enter__ = lambda s: s
    sdk_inst.__exit__ = MagicMock(return_value=False)

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    # No per-pin delete_device_data calls for pins_to_sync (only stale-pin bulk).
    # Since device_pins is empty in this test, there are no stale pins either.
    assert sdk_inst.delete_device_data.call_count == 0, (
        f"Expected zero per-pin delete calls under upsert; got "
        f"{sdk_inst.delete_device_data.call_count}"
    )


# ── Phase C (per-pin template push) ───────────────────────────────────────────
# ULTRA runs the whole device sync INLINE on the live worker, so every long
# phase has to (a) move the progress bar and (b) release the worker so queued
# doors open and RTLog keeps being polled. Phase C did neither.


def make_user_with_fingerprints(am_id, fingers=2):
    u = make_user(am_id)
    u["fingerprints"] = [
        {
            "fingerId": f,
            "templateVersion": 10,
            "templateData": f"TEMPLATE-{am_id}-{f}" * 4,
            "templateSize": 64,
            "enabled": True,
        }
        for f in range(fingers)
    ]
    return u


def make_fingerprint_device(dev_id=1):
    d = make_device(dev_id)
    d["fingerprintEnabled"] = True
    return d


def _fp_sdk():
    sdk_cls = MagicMock()
    sdk_inst = MagicMock()
    sdk_cls.return_value = sdk_inst
    sdk_inst.get_device_data_rows.return_value = []
    sdk_inst.set_device_data.return_value = 0
    sdk_inst.set_device_data_batch.return_value = (20, [])
    sdk_inst.clear_device_table.return_value = 0
    sdk_inst.delete_device_data.return_value = 0
    sdk_inst.supports_delete_device_data.return_value = True
    sdk_inst.__enter__ = lambda s: s
    sdk_inst.__exit__ = MagicMock(return_value=False)
    return sdk_cls, sdk_inst


def test_template_phase_is_budgeted_in_total_and_advances_current(tmp_path, monkeypatch):
    """
    Phase C must be counted in `total` and must tick `current` while it runs.

    Before this guard `total` covered only the user push, so `current` hit
    `total` the moment the user push finished and the bar sat pinned at 100%
    for the whole fingerprint push — the longest phase on a real gym (853
    sequential per-pin round-trips). On screen that is indistinguishable from
    a frozen sync.
    """
    svc = make_engine(tmp_path, monkeypatch)
    users = [make_user_with_fingerprints(am_id=i) for i in range(1, 21)]

    sdk_cls, _ = _fp_sdk()

    # Deterministic template push: report every template as pushed.
    monkeypatch.setattr(
        svc, "_push_templates",
        lambda sdk, *, pin, templates, device_id, template_version_override=None:
            (len(templates), []),
    )

    snapshots = []
    orig_set_progress = svc._set_progress

    def record_progress(**changes):
        orig_set_progress(**changes)
        snapshots.append(svc.get_progress_snapshot()[0])

    monkeypatch.setattr(svc, "_set_progress", record_progress)

    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_fingerprint_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    assert snapshots, "Expected at least one progress snapshot"

    # `total` budgets the user push AND the per-pin template pass.
    assert snapshots[-1]["total"] == 2 * len(users), (
        f"total should budget {len(users)} user pins + {len(users)} template "
        f"pins, got {snapshots[-1]['total']}"
    )

    # The bar keeps moving after the user push ends, instead of pinning at 100%.
    assert any(s["current"] > len(users) for s in snapshots), (
        "no progress tick fired during the template phase — the bar is pinned"
    )

    # And it still finishes full.
    assert snapshots[-1]["current"] == snapshots[-1]["total"]


def test_template_phase_yields_to_doors_and_rtlog(tmp_path, monkeypatch):
    """
    ULTRA installs `_door_yield_cb` / `_rtlog_yield_cb` so a long inline push
    still opens doors queued mid-sync and keeps polling RTLog. Every other push
    phase calls them between chunks; Phase C called them zero times, so for the
    entire fingerprint push a member badging in got no response.
    """
    svc = make_engine(tmp_path, monkeypatch)
    users = [make_user_with_fingerprints(am_id=i) for i in range(1, 21)]

    counts = {"doors": 0, "rtlog": 0}
    svc._door_yield_cb = lambda: counts.__setitem__("doors", counts["doors"] + 1)
    svc._rtlog_yield_cb = lambda: counts.__setitem__("rtlog", counts["rtlog"] + 1)

    # Snapshot the yield counters at each template push, so we measure Phase C
    # specifically rather than yields the earlier user-push phase already did.
    seen = []

    def spy_push(sdk, *, pin, templates, device_id, template_version_override=None):
        seen.append((counts["doors"], counts["rtlog"]))
        return (len(templates), [])

    monkeypatch.setattr(svc, "_push_templates", spy_push)

    sdk_cls, _ = _fp_sdk()
    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_fingerprint_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
        )

    assert len(seen) >= 2, f"expected several template pushes, got {len(seen)}"

    first_doors, first_rtlog = seen[0]
    last_doors, last_rtlog = seen[-1]

    assert last_doors > first_doors, (
        "Phase C never yielded to queued door-opens: door-yield count stayed at "
        f"{first_doors} across {len(seen)} template pushes"
    )
    assert last_rtlog > first_rtlog, (
        "Phase C never yielded to RTLog polling: rtlog-yield count stayed at "
        f"{first_rtlog} across {len(seen)} template pushes"
    )


def test_template_phase_progress_is_suppressed_on_the_actor_path(tmp_path, monkeypatch):
    """
    Characterization guard (not a new behaviour): DEVICE-mode fan-out calls
    `_sync_one_device(report_progress=False)` because many device actors share
    one `_sync_progress` dict. The Phase C ticks go through the same
    `_maybe_set_progress` gate, so they must stay suppressed there — otherwise
    concurrent actors would fight over the dashboard bar.
    """
    svc = make_engine(tmp_path, monkeypatch)
    users = [make_user_with_fingerprints(am_id=i) for i in range(1, 21)]

    monkeypatch.setattr(
        svc, "_push_templates",
        lambda sdk, *, pin, templates, device_id, template_version_override=None:
            (len(templates), []),
    )

    writes = []
    orig_set_progress = svc._set_progress
    monkeypatch.setattr(
        svc, "_set_progress",
        lambda **changes: (writes.append(changes), orig_set_progress(**changes))[1],
    )

    sdk_cls, _ = _fp_sdk()
    with patch("app.core.device_sync.PullSDK", sdk_cls):
        svc._sync_one_device(
            device=make_fingerprint_device(),
            users=users,
            local_fp_index={},
            default_door_id=15,
            report_progress=False,
        )

    assert writes == [], f"actor path must not write progress, got {len(writes)} writes"
