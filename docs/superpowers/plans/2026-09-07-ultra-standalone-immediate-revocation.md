# ULTRA Standalone Immediate Revocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver every authoritative membership revocation immediately to connected, MonClub-owned ULTRA standalone/MB2000 pins while retaining full reconciliation as the retry path.

**Architecture:** Keep ordinary member changes and authoritative revocations as separate ID sets from `MainApp` through `UltraEngine` and `UltraSyncScheduler`. ULTRA workers coalesce commands with revocation precedence; standalone workers delete an owned pin immediately and neutralize it on delete failure, while unowned pins are protected and escalated to a full reconcile.

**Tech Stack:** Python 3, Tkinter application runtime, SQLite, threaded ULTRA workers, standalone `zkemkeeper` driver abstraction, pytest.

---

## File map

- Modify `app/ui/app.py`: classify fast-patch deletes, preserve shadow-deleted IDs, and dispatch `revoked_ids` separately to ULTRA.
- Modify `app/core/ultra_engine.py`: add typed revocation queueing, routing, standalone execution, telemetry, and retry behavior.
- Modify `tests/test_fast_patch_runtime.py`: prove fast-patch delete classification and revocation precedence.
- Modify `tests/test_ultra_sync_scheduler.py`: prove engine/scheduler propagation and live-worker routing.
- Modify `tests/test_standalone_revoked_pin_removal.py`: prove immediate owned-pin deletion, fallback neutralization, ownership protection, and retry-state retention.
- Create `tests/test_authoritative_revocation_pipeline.py`: prove delta/full shadow deletion classification and H-006 behavior at the `MainApp` boundary.
- Modify `guide_for_agents_and_dev.md`: record the new `[CODE][TEST]` behavior without claiming field validation.

No backend or Dashboard files change in this plan.

### Task 1: Give worker member commands explicit revocation semantics

**Files:**
- Modify: `app/core/ultra_engine.py:386-390,912-930,1091-1155`
- Test: `tests/test_ultra_sync_scheduler.py`

- [ ] **Step 1: Write failing queue-precedence tests**

Import `deque` from `collections`, then add:

```python
def _command_worker():
    return SimpleNamespace(
        _member_sync_lock=threading.Lock(),
        _pending_member_syncs=deque(),
        _pending_member_sync_ids=set(),
        _pending_member_revoke_ids=set(),
        _wake_evt=threading.Event(),
    )


def test_worker_revocation_upgrades_pending_member_sync():
    import app.core.ultra_engine as ultra_module
    worker = _command_worker()

    assert ultra_module.UltraDeviceWorker.request_member_sync(worker, 41) is True
    assert ultra_module.UltraDeviceWorker.request_member_revoke(worker, 41) is True
    assert list(worker._pending_member_syncs) == [41]
    assert worker._pending_member_revoke_ids == {41}


def test_worker_member_sync_cannot_downgrade_pending_revocation():
    import app.core.ultra_engine as ultra_module
    worker = _command_worker()

    assert ultra_module.UltraDeviceWorker.request_member_revoke(worker, 41) is True
    assert ultra_module.UltraDeviceWorker.request_member_sync(worker, 41) is False
    assert list(worker._pending_member_syncs) == [41]
    assert worker._pending_member_revoke_ids == {41}
```

- [ ] **Step 2: Run the tests and confirm the intended failure**

```powershell
python -m pytest tests/test_ultra_sync_scheduler.py::test_worker_revocation_upgrades_pending_member_sync tests/test_ultra_sync_scheduler.py::test_worker_member_sync_cannot_downgrade_pending_revocation -q
```

Expected: FAIL because `request_member_revoke` does not exist.

- [ ] **Step 3: Implement queue state and APIs**

In `UltraDeviceWorker.__init__` add:

```python
self._pending_member_revoke_ids: Set[int] = set()
```

Replace the request methods with:

```python
def request_member_sync(self, member_id: int) -> bool:
    member_id = int(member_id)
    with self._member_sync_lock:
        if member_id in self._pending_member_revoke_ids:
            return False
        if member_id in self._pending_member_sync_ids:
            return False
        self._pending_member_sync_ids.add(member_id)
        self._pending_member_syncs.append(member_id)
    self._wake_evt.set()
    return True

def request_member_revoke(self, member_id: int) -> bool:
    member_id = int(member_id)
    with self._member_sync_lock:
        already_revoke = member_id in self._pending_member_revoke_ids
        self._pending_member_revoke_ids.add(member_id)
        if member_id not in self._pending_member_sync_ids:
            self._pending_member_sync_ids.add(member_id)
            self._pending_member_syncs.append(member_id)
    self._wake_evt.set()
    return not already_revoke
```

In `_drain_member_sync_commands`, determine the action inside the existing lock:

```python
member_id = int(self._pending_member_syncs.popleft())
is_revocation = member_id in self._pending_member_revoke_ids
self._pending_member_sync_ids.discard(member_id)
self._pending_member_revoke_ids.discard(member_id)
```

Route standalone commands as:

```python
if getattr(self._sdk, "owns_event_source", False):
    if is_revocation:
        self._run_standalone_member_revoke(member_id)
    else:
        self._run_standalone_member_sync(member_id)
    drained += 1
    continue
```

PullSDK commands continue through `sync_member_on_connected_sdk`; an authoritative local deletion activates its existing absent-member delete branch.

- [ ] **Step 4: Run the queue tests**

Run the Step 2 command again. Expected: 2 passed.

- [ ] **Step 5: Commit**

```powershell
git add app/core/ultra_engine.py tests/test_ultra_sync_scheduler.py
git commit -m "feat(access): add authoritative member revoke commands"
```

### Task 2: Delete owned standalone pins immediately

**Files:**
- Modify: `app/core/ultra_engine.py:1660-1910`
- Test: `tests/test_standalone_revoked_pin_removal.py`

- [ ] **Step 1: Write failing targeted-revocation tests**

Use the existing `RevokeDriver`, `_worker`, `_revoked_push`, and `FingerState` fixtures:

```python
def test_targeted_revoke_deletes_owned_pin_immediately(monkeypatch, fstate):
    drv = RevokeDriver()
    worker, _cache = _worker(monkeypatch, driver=drv, users=[])
    fstate.rows["34439"] = ("old-hash", True, {0, 2})

    assert worker._run_standalone_member_revoke(34439) is True
    assert drv.delete_calls == [["34439"]]
    assert _revoked_push(drv) is None
    assert "34439" not in fstate.rows


def test_targeted_revoke_neutralises_when_delete_fails(monkeypatch, fstate):
    drv = RevokeDriver(fail_delete={"34439"})
    worker, _cache = _worker(monkeypatch, driver=drv, users=[])
    fstate.rows["34439"] = ("old-hash", True, {0, 2})

    assert worker._run_standalone_member_revoke(34439) is True
    call = _revoked_push(drv)
    assert call["users"] == [{"pin": "34439", "name": "", "card": "", "enabled": False}]
    assert call["removals"] == {"34439": [0, 2]}
    assert "34439" not in fstate.rows


def test_targeted_revoke_never_touches_unowned_pin(monkeypatch, fstate):
    drv = RevokeDriver()
    worker, _cache = _worker(monkeypatch, driver=drv, users=[])
    worker.request_full_sync = MagicMock(return_value=True)

    assert worker._run_standalone_member_revoke(34439) is False
    assert drv.delete_calls == []
    assert drv.push_calls == []
    worker.request_full_sync.assert_called_once_with(reason="revoke-ownership-missing")
```

Add `FailingFallbackDriver`, overriding `push_roster` to return `{"ok": False}`, and assert state remains when delete and neutralization both fail.

- [ ] **Step 2: Run the test file and verify the new tests fail**

```powershell
python -m pytest tests/test_standalone_revoked_pin_removal.py -q
```

Expected: new tests FAIL because `_run_standalone_member_revoke` does not exist.

- [ ] **Step 3: Extract the shared removal primitive**

Add a helper and reuse it from the existing full revocation pass:

```python
def _remove_standalone_pins(
    self,
    *,
    pins: list[str],
    pushed_fingers: dict[str, set[int] | None],
) -> tuple[set[str], set[str]]:
    requested = [str(pin).strip() for pin in pins if str(pin).strip()]
    deleter = getattr(self._sdk, "delete_users", None)
    result = deleter(requested) if callable(deleter) else {}
    reported = result.get("failed_pins")
    failed = set(requested if reported is None and not result.get("ok") else (reported or []))
    removed = set(requested) - failed
    if failed:
        removals = {
            pin: sorted(pushed_fingers.get(pin) or ())
            for pin in failed
            if pushed_fingers.get(pin)
        }
        users = [{"pin": pin, "name": "", "card": "", "enabled": False} for pin in sorted(failed)]
        fallback = self._sdk.push_roster(users, {}, remove_fingers_by_pin=removals) or {}
        if fallback.get("ok"):
            removed.update(failed)
            failed.clear()
    return removed, failed
```

When no `delete_users` method exists, initialize `failed` with every requested pin so older drivers enter the neutralization fallback. Preserve the current `REVOKE_DONE` fields in `_neutralise_revoked_pins`.

- [ ] **Step 4: Implement targeted ownership and retry behavior**

Add:

```python
def _run_standalone_member_revoke(self, member_id: int) -> bool:
    pin = str(int(member_id))
    _tel.event("MEMBER_REVOKE_REQUESTED", worker=self._tel_wid, member_id=member_id, pin=pin)
    state = list_device_sync_hashes_and_status(device_id=self._device_id) or {}
    if pin not in state:
        _tel.warn("MEMBER_REVOKE_OWNERSHIP_MISSING", worker=self._tel_wid, member_id=member_id, pin=pin)
        self.request_full_sync(reason="revoke-ownership-missing")
        return False
    removed, failed = self._remove_standalone_pins(
        pins=[pin],
        pushed_fingers=self._load_pushed_fingers(),
    )
    if pin in removed:
        delete_device_sync_state(device_id=self._device_id, pin=pin)
        try:
            delete_device_mirror_pin(device_id=self._device_id, pin=pin)
        except Exception:
            logger.debug("%s could not clear mirror pin %s", self._prefix, pin, exc_info=True)
        _tel.event("MEMBER_REVOKE_DONE", worker=self._tel_wid, member_id=member_id, pin=pin, ok=True)
        return True
    _tel.warn("MEMBER_REVOKE_FAILED", worker=self._tel_wid, member_id=member_id, pin=pin)
    self.request_full_sync(reason="revoke-failed")
    return False
```

Use the file's existing module-level DB imports. Refactor `_neutralise_revoked_pins` to invoke `_remove_standalone_pins` only after its existing empty-roster, ownership, grace-window, and bulk-safety checks.

- [ ] **Step 5: Run standalone tests**

```powershell
python -m pytest tests/test_standalone_revoked_pin_removal.py -q
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```powershell
git add app/core/ultra_engine.py tests/test_standalone_revoked_pin_removal.py
git commit -m "feat(access): revoke owned standalone pins immediately"
```

### Task 3: Propagate revoked IDs through ULTRA engine and scheduler

**Files:**
- Modify: `app/core/ultra_engine.py:4030-4270,4885-4960`
- Test: `tests/test_ultra_sync_scheduler.py`

- [ ] **Step 1: Write failing routing tests**

Add:

```python
def test_ultra_engine_routes_revocations_immediately_and_revocation_wins():
    import app.core.ultra_engine as ultra_module
    worker = SimpleNamespace(
        request_member_sync=MagicMock(return_value=True),
        request_member_revoke=MagicMock(return_value=True),
    )
    scheduler = SimpleNamespace(request_sync_now=MagicMock())
    engine = SimpleNamespace(_running=True, _sync_scheduler=scheduler, _workers={5: worker}, _logger=MagicMock())

    started = ultra_module.UltraEngine.request_sync_now(
        engine,
        changed_ids={11, 13},
        revoked_ids={13, 17},
        device_ids={5},
        reason="fast_patch_bundle",
    )

    assert started is True
    assert [c.args[0] for c in worker.request_member_sync.call_args_list] == [11]
    assert [c.args[0] for c in worker.request_member_revoke.call_args_list] == [13, 17]
    scheduler.request_sync_now.assert_not_called()
```

Add a scheduler test calling `request_sync_now(changed_ids={11}, revoked_ids={17})`, then assert `_drain_pending_sync_request()` returns `({11}, {17}, device_ids, reason)`.

- [ ] **Step 2: Run scheduler tests and confirm signature failures**

```powershell
python -m pytest tests/test_ultra_sync_scheduler.py -q
```

Expected: new tests FAIL because `revoked_ids` is not accepted.

- [ ] **Step 3: Extend scheduler state and tuples**

Add `_pending_revoked_ids: Set[int]`. Extend `request_sync_now`, `_drain_pending_sync_request`, `_run`, and `_sync_all` with `revoked_ids`.

Normalize and apply precedence:

```python
normalized_revoked_ids = {
    int(member_id) for member_id in (revoked_ids or set()) if member_id is not None
}
if normalized_changed_ids is not None:
    normalized_changed_ids.difference_update(normalized_revoked_ids)
```

A request is empty only when `changed_ids` is an empty set and `revoked_ids` is empty. Drain tuples in this order:

```python
(changed_ids, revoked_ids, device_ids, reason)
```

In `_sync_all`, call `request_member_revoke` before `request_member_sync`.

- [ ] **Step 4: Extend `UltraEngine.request_sync_now`**

Add `revoked_ids: set[int] | None = None`, normalize it, subtract it from non-null `changed_ids`, and route live workers:

```python
for member_id in sorted(normalized_revoked_ids):
    worker.request_member_revoke(member_id)
for member_id in sorted(normalized_changed_ids or set()):
    worker.request_member_sync(member_id)
```

If no matching live worker exists, pass both sets to the scheduler. Preserve `changed_ids=None` as the full-refresh signal.

- [ ] **Step 5: Run scheduler tests**

```powershell
python -m pytest tests/test_ultra_sync_scheduler.py -q
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```powershell
git add app/core/ultra_engine.py tests/test_ultra_sync_scheduler.py
git commit -m "feat(access): route authoritative revocations through ULTRA"
```

### Task 4: Classify fast-patch deletes in MainApp

**Files:**
- Modify: `app/ui/app.py:874-927,1376-1460`
- Test: `tests/test_fast_patch_runtime.py`

- [ ] **Step 1: Write a failing fast-patch deletion test**

Add:

```python
def test_fast_patch_routes_membership_delete_as_authoritative_revocation(monkeypatch):
    import app.ui.app as app_module
    monkeypatch.setattr("app.core.db.apply_fast_patch_bundle", lambda bundle: {"applied": 1, "skipped": 0, "ignored": None})
    monkeypatch.setattr("app.core.db.invalidate_sync_cache", MagicMock())
    app = SimpleNamespace(
        logger=MagicMock(),
        reset_runtime_fast_patch_caches=MagicMock(),
        _request_running_ultra_sync=MagicMock(return_value=True),
        _defer_ultra_reconnects=MagicMock(),
        request_sync_now=MagicMock(),
    )
    bundle = {
        "bundleId": "revoke-9",
        "requiresReconcile": True,
        "items": [
            {
                "kind": "ENTITY_DELETE",
                "entityType": "ACTIVE_MEMBERSHIP",
                "entityId": 9,
                "impact": {"affectedMemberIds": [9], "affectedDeviceIds": [7]},
            },
            {
                "kind": "SECTION_REPLACE",
                "entityType": "CREDENTIALS",
                "payload": {"mergeMode": "UPSERT_ONLY", "gymAccessCredentials": []},
                "impact": {"affectedMemberIds": [9], "affectedDeviceIds": []},
            },
        ],
    }

    app_module.MainApp.apply_fast_patch_bundle(app, bundle)

    app._request_running_ultra_sync.assert_called_once_with(
        refresh={"members": True, "devices": False},
        changed_ids=set(),
        revoked_ids={9},
        device_ids={7},
        reason="FAST_PATCH_BUNDLE",
    )
```

Update existing upsert and device-rescope assertions to expect `revoked_ids=set()`.

- [ ] **Step 2: Run fast-patch tests and verify failure**

```powershell
python -m pytest tests/test_fast_patch_runtime.py -q
```

Expected: FAIL because impacted delete IDs currently enter ordinary `changed_ids` and the helper has no `revoked_ids` parameter.

- [ ] **Step 3: Classify delete items**

In `apply_fast_patch_bundle`, after `items` and impacted IDs are built, add:

```python
revoked_member_ids = {
    int(item.get("entityId"))
    for item in items
    if str(item.get("kind") or "").strip().upper() == "ENTITY_DELETE"
    and str(item.get("entityType") or "").strip().upper() == "ACTIVE_MEMBERSHIP"
    and item.get("entityId") is not None
}
affected_member_ids.difference_update(revoked_member_ids)
```

Pass `revoked_ids=revoked_member_ids` to `_request_running_ultra_sync`.

- [ ] **Step 4: Extend the MainApp ULTRA helper**

Add `revoked_ids: set[int] | None = None` to `_request_running_ultra_sync`. Normalize it, remove those IDs from non-null `requested_changed_ids`, and skip only when both targeted sets are empty:

```python
requested_revoked_ids = {
    int(member_id) for member_id in (revoked_ids or set()) if member_id is not None
}
if requested_changed_ids is not None:
    requested_changed_ids.difference_update(requested_revoked_ids)
if requested_changed_ids == set() and not requested_revoked_ids:
    return False
```

Pass `revoked_ids=requested_revoked_ids` to `self._ultra_engine.request_sync_now`. A device refresh remains a full request with `changed_ids=None` and an empty revocation set.

- [ ] **Step 5: Run fast-patch tests**

```powershell
python -m pytest tests/test_fast_patch_runtime.py -q
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```powershell
git add app/ui/app.py tests/test_fast_patch_runtime.py
git commit -m "feat(access): preserve fast-patch revocation intent"
```

### Task 5: Preserve deletions from delta and full roster responses

**Files:**
- Modify: `app/ui/app.py:779-872,2180-2465,2479-2555`
- Create: `tests/test_authoritative_revocation_pipeline.py`

- [ ] **Step 1: Create failing shadow-outcome tests**

Use an isolated SQLite fixture following `tests/test_delta_user_cache.py`, then add:

```python
def test_delta_shadow_returns_revoked_ids_separately(db):
    import app.ui.app as app_module
    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])
    app = SimpleNamespace(logger=MagicMock())

    changed, revoked = app_module.MainApp._apply_member_shadow_sync(
        app,
        data={"membersDeltaMode": True, "users": [_make_user(1)], "validMemberIds": [1]},
        refresh={"members": True},
        delta_changed_ids={1},
    )

    assert changed == {1}
    assert revoked == {2}


def test_full_shadow_returns_revoked_ids_separately(db):
    import app.ui.app as app_module
    db.upsert_member_shadow(users=[_make_user(1), _make_user(2)])
    app = SimpleNamespace(logger=MagicMock())

    _changed, revoked = app_module.MainApp._apply_member_shadow_sync(
        app,
        data={"membersDeltaMode": False, "users": [_make_user(1)]},
        refresh={"members": True},
        delta_changed_ids=None,
    )

    assert revoked == {2}


def test_h006_refusal_emits_no_revocations(db):
    import app.ui.app as app_module
    db.upsert_member_shadow(users=[_make_user(i) for i in range(1, 12)])
    app = SimpleNamespace(logger=MagicMock())

    _changed, revoked = app_module.MainApp._apply_member_shadow_sync(
        app,
        data={"membersDeltaMode": True, "users": [], "validMemberIds": []},
        refresh={"members": True},
        delta_changed_ids=set(),
    )

    assert revoked == set()
```

Define `_make_user(am_id)` locally with `activeMembershipId`, `userId`, `membershipId`, names, card fields, dates, and an empty fingerprint list. Do not import another module's fixture.

- [ ] **Step 2: Run the new file and verify tuple-unpack failure**

```powershell
python -m pytest tests/test_authoritative_revocation_pipeline.py -q
```

Expected: FAIL because `_apply_member_shadow_sync` returns only `changed_ids`.

- [ ] **Step 3: Return changed and revoked sets separately**

Change `_apply_member_shadow_sync` to return:

```python
tuple[set[int] | None, set[int]]
```

Initialize `revoked_ids: set[int] = set()`. Return `(delta_changed_ids, revoked_ids)` on every path.

In delta mode:

```python
revoked_ids = {
    int(member_id) for member_id in (_shadow_deleted or []) if member_id is not None
}
if delta_changed_ids is not None:
    delta_changed_ids = set(delta_changed_ids) - revoked_ids
return delta_changed_ids, revoked_ids
```

In full mode, populate `revoked_ids` from `_diff["deleted"]`, subtract it from any non-null changed set, keep existing shadow writes/deletes, and return both values. On an exception return `(delta_changed_ids, set())`, because no deletion was safely established.

- [ ] **Step 4: Dispatch roster revocations**

At sync-work initialization add:

```python
_delta_revoked_ids: set[int] = set()
```

Unpack the result:

```python
_delta_changed_ids, _delta_revoked_ids = self._apply_member_shadow_sync(
    data=data,
    refresh=refresh,
    delta_changed_ids=_delta_changed_ids,
)
```

Pass `revoked_ids=_delta_revoked_ids` to every member-related `_request_running_ultra_sync` call.

Preserve existing DEVICE behavior by passing the union to `DeviceSyncEngine.run_blocking`:

```python
device_changed_ids = _delta_changed_ids
if device_changed_ids is not None and _delta_revoked_ids:
    device_changed_ids = set(device_changed_ids) | set(_delta_revoked_ids)
```

Use `device_changed_ids` only for the DEVICE engine. ULTRA continues to receive separate sets.

- [ ] **Step 5: Run pipeline and cache tests**

```powershell
python -m pytest tests/test_authoritative_revocation_pipeline.py tests/test_delta_user_cache.py tests/test_fast_patch_runtime.py -q
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```powershell
git add app/ui/app.py tests/test_authoritative_revocation_pipeline.py
git commit -m "feat(access): classify roster removals as revocations"
```

### Task 6: Documentation and complete verification

**Files:**
- Modify: `guide_for_agents_and_dev.md`
- Test: focused suites and the repository's documented complete suite

- [ ] **Step 1: Update the source-of-truth guide**

Add these claims to the ULTRA standalone synchronization section:

```markdown
- `[CODE][TEST]` Authoritative revocations are routed separately from ordinary member changes.
- `[CODE][TEST]` A connected ULTRA standalone worker immediately deletes a MonClub-owned revoked pin and neutralizes it when deletion fails.
- `[CODE][TEST]` Missing ownership proof causes no destructive device call; it emits critical telemetry and requests full reconciliation.
- `[CODE][TEST]` Full reconciliation remains the retry path, not the primary revocation path.
- `[FIELD]` remains unset until this path is exercised against Gym T's installed MB2000 build.
```

- [ ] **Step 2: Run focused regression suites**

```powershell
python -m pytest tests/test_fast_patch_runtime.py tests/test_authoritative_revocation_pipeline.py tests/test_ultra_sync_scheduler.py tests/test_standalone_revoked_pin_removal.py tests/test_standalone_incremental_sync.py tests/test_differential_device_push.py -q
```

Expected: all selected tests pass. If the known process-global SQLite fixture isolation issue appears when DB-heavy modules share one process, run each affected file in a fresh pytest process and report both outcomes rather than hiding the combined failure.

- [ ] **Step 3: Run the complete documented test command**

Read the current command from `guide_for_agents_and_dev.md` and run it exactly. Record the exit code and passed, failed, skipped, and warning counts. A non-zero exit code must be reported as a failure.

- [ ] **Step 4: Inspect diff and workspace state**

```powershell
git diff --check HEAD~5..HEAD
git status --short
git log -6 --oneline
```

Expected: no whitespace errors; only the user's pre-existing binary and metadata modifications remain uncommitted.

- [ ] **Step 5: Commit the guide**

```powershell
git add guide_for_agents_and_dev.md
git commit -m "docs(access): document immediate standalone revocation"
```

- [ ] **Step 6: Report limits without overstating field proof**

The final report must state that source and automated tests prove the command path, the local HTTP response still confirms dispatch rather than physical completion, disconnected devices retry during recovery, unowned pins are deliberately protected, and Gym T hardware validation is still required before assigning a production latency SLA.
