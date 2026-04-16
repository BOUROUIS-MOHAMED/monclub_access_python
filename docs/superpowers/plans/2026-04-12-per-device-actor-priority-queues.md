# Per-Device Actor With Priority Queues Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace split device ownership with one generic per-device actor runtime that gives urgent door and access actions priority over background sync work for every device type from day one.

**Architecture:** Introduce a generic actor core made of message types, a priority mailbox, a resumable sync session model, and a registry that owns one actor per device. Then adapt both existing device execution paths (`app/core/device_worker.py` sync workers and `app/core/ultra_engine.py` ULTRA workers) behind actor adapters so open-door, targeted member push/delete, and reconcile all flow through the same per-device control loop.

**Tech Stack:** Python 3.11+, threading, queue/heapq, pytest, existing PullSDK/ZKTeco runtime

**Spec:** `docs/superpowers/specs/2026-04-12-per-device-actor-priority-queues-design.md`

---

## File Map

| Action | File | Responsibility |
|---|---|---|
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_actor_mailbox.py` | Generic actor message model, priority ordering, and coalescing |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_sync_session.py` | Chunked sync session state and phase cursor helpers |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_actor_runtime.py` | Generic device actor thread/loop and adapter protocol |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_actor_registry.py` | Actor lifecycle, routing, and restart handling |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_worker.py` | Re-route current sync workers through the actor shell for DEVICE/AGENT mode |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_sync.py` | Build targeted/full sync sessions instead of direct latest-wins jobs |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\ultra_engine.py` | Replace RTLog pause/handoff with ULTRA actor adapter ownership |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\core\realtime_agent.py` | Route open-door/device commands through actor registry instead of direct worker selection |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\app\ui\app.py` | Wire fast patch and reconcile requests to the actor registry |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_actor_mailbox.py` | Mailbox priority and coalescing tests |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_sync_session.py` | Fixed-chunk cursor and resume tests |
| Create | `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_actor_runtime.py` | Generic actor runtime behavior with fake adapters |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_ultra_sync_scheduler.py` | Regression coverage for the removed RTLog pause/handoff path |
| Modify | `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_differential_device_push.py` | Fast-patch-targeted actor routing assertions |

---

## Task 1: Generic Mailbox Contract

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_actor_mailbox.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_actor_mailbox.py`

- [ ] **Step 1: Write the failing mailbox tests**

Create `tests/test_device_actor_mailbox.py`:

```python
from app.core.device_actor_mailbox import ActorMessage, DeviceActorMailbox


def test_open_door_outranks_sync_chunk():
    mailbox = DeviceActorMailbox()
    mailbox.put(ActorMessage.full_sync_start(device_id=7))
    mailbox.put(ActorMessage.sync_next_chunk(device_id=7))
    mailbox.put(ActorMessage.open_door(device_id=7, door_id=2, pulse_ms=1200))

    first = mailbox.get_nowait()
    second = mailbox.get_nowait()

    assert first.kind == "OPEN_DOOR"
    assert second.kind == "SYNC_NEXT_CHUNK"


def test_delete_replaces_older_upsert_for_same_member():
    mailbox = DeviceActorMailbox()
    mailbox.put(ActorMessage.member_upsert(device_id=7, member_id=22))
    mailbox.put(ActorMessage.member_delete(device_id=7, member_id=22))

    only = mailbox.get_nowait()

    assert only.kind == "MEMBER_DELETE"
    assert only.member_id == 22
    assert mailbox.empty()


def test_targeted_sync_merges_member_ids():
    mailbox = DeviceActorMailbox()
    mailbox.put(ActorMessage.targeted_sync_start(device_id=7, member_ids={1, 2}))
    mailbox.put(ActorMessage.targeted_sync_start(device_id=7, member_ids={2, 3}))

    msg = mailbox.get_nowait()

    assert msg.kind == "TARGETED_SYNC_START"
    assert msg.member_ids == {1, 2, 3}
    assert mailbox.empty()
```

- [ ] **Step 2: Run the mailbox tests to verify RED**

Run:

```bash
pytest tests/test_device_actor_mailbox.py -q
```

Expected: FAIL with `ModuleNotFoundError` or missing `ActorMessage` / `DeviceActorMailbox`.

- [ ] **Step 3: Write the minimal mailbox implementation**

Create `app/core/device_actor_mailbox.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field
import heapq
import itertools
import threading
from typing import FrozenSet, Optional


_PRIORITY = {
    "OPEN_DOOR": 1,
    "RTLOG_REACTION": 2,
    "MEMBER_DELETE": 3,
    "MEMBER_UPSERT": 4,
    "DEVICE_CONFIG_REFRESH": 5,
    "TARGETED_SYNC_START": 6,
    "SYNC_NEXT_CHUNK": 7,
    "RTLOG_TICK": 8,
    "FULL_SYNC_START": 9,
    "RECONNECT": 10,
    "SHUTDOWN": 11,
}


@dataclass(frozen=True)
class ActorMessage:
    kind: str
    device_id: int
    member_id: Optional[int] = None
    member_ids: FrozenSet[int] = field(default_factory=frozenset)
    door_id: Optional[int] = None
    pulse_ms: Optional[int] = None

    @property
    def priority(self) -> int:
        return _PRIORITY[self.kind]

    @classmethod
    def open_door(cls, *, device_id: int, door_id: int, pulse_ms: int) -> "ActorMessage":
        return cls(kind="OPEN_DOOR", device_id=device_id, door_id=door_id, pulse_ms=pulse_ms)

    @classmethod
    def full_sync_start(cls, *, device_id: int) -> "ActorMessage":
        return cls(kind="FULL_SYNC_START", device_id=device_id)

    @classmethod
    def sync_next_chunk(cls, *, device_id: int) -> "ActorMessage":
        return cls(kind="SYNC_NEXT_CHUNK", device_id=device_id)

    @classmethod
    def member_upsert(cls, *, device_id: int, member_id: int) -> "ActorMessage":
        return cls(kind="MEMBER_UPSERT", device_id=device_id, member_id=member_id)

    @classmethod
    def member_delete(cls, *, device_id: int, member_id: int) -> "ActorMessage":
        return cls(kind="MEMBER_DELETE", device_id=device_id, member_id=member_id)

    @classmethod
    def targeted_sync_start(cls, *, device_id: int, member_ids: set[int]) -> "ActorMessage":
        return cls(kind="TARGETED_SYNC_START", device_id=device_id, member_ids=frozenset(member_ids))


class DeviceActorMailbox:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._heap: list[tuple[int, int, ActorMessage]] = []
        self._seq = itertools.count()
        self._member_ops: dict[int, ActorMessage] = {}
        self._targeted_sync: Optional[ActorMessage] = None
        self._full_sync_pending = False

    def put(self, message: ActorMessage) -> None:
        with self._lock:
            if message.kind in {"MEMBER_UPSERT", "MEMBER_DELETE"} and message.member_id is not None:
                existing = self._member_ops.get(message.member_id)
                if existing and existing.kind == "MEMBER_DELETE":
                    return
                if message.kind == "MEMBER_DELETE":
                    self._member_ops[message.member_id] = message
                else:
                    self._member_ops[message.member_id] = message
                heapq.heappush(self._heap, (message.priority, next(self._seq), message))
                return

            if message.kind == "TARGETED_SYNC_START":
                merged = set(self._targeted_sync.member_ids) if self._targeted_sync else set()
                merged.update(message.member_ids)
                self._targeted_sync = ActorMessage.targeted_sync_start(
                    device_id=message.device_id,
                    member_ids=merged,
                )
                heapq.heappush(self._heap, (self._targeted_sync.priority, next(self._seq), self._targeted_sync))
                return

            if message.kind == "FULL_SYNC_START":
                if self._full_sync_pending:
                    return
                self._full_sync_pending = True

            heapq.heappush(self._heap, (message.priority, next(self._seq), message))

    def get_nowait(self) -> ActorMessage:
        with self._lock:
            while self._heap:
                _, _, message = heapq.heappop(self._heap)
                if message.kind in {"MEMBER_UPSERT", "MEMBER_DELETE"} and message.member_id is not None:
                    current = self._member_ops.get(message.member_id)
                    if current != message:
                        continue
                    self._member_ops.pop(message.member_id, None)
                    return message
                if message.kind == "TARGETED_SYNC_START":
                    if self._targeted_sync != message:
                        continue
                    self._targeted_sync = None
                    return message
                if message.kind == "FULL_SYNC_START":
                    self._full_sync_pending = False
                return message
            raise IndexError("mailbox empty")

    def empty(self) -> bool:
        with self._lock:
            return not self._heap
```

- [ ] **Step 4: Run the mailbox tests to verify GREEN**

Run:

```bash
pytest tests/test_device_actor_mailbox.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_device_actor_mailbox.py app/core/device_actor_mailbox.py
git commit -m "feat: add device actor mailbox"
```

---

## Task 2: Sync Session Cursor Model

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_sync_session.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_sync_session.py`

- [ ] **Step 1: Write the failing sync-session tests**

Create `tests/test_device_sync_session.py`:

```python
from app.core.device_sync_session import DeviceSyncSession


def test_delete_phase_uses_fixed_chunk_of_20():
    session = DeviceSyncSession.full(device_id=9, delete_pins=[str(i) for i in range(45)])

    first = session.next_chunk()
    second = session.next_chunk()
    third = session.next_chunk()

    assert first.phase == "DELETE"
    assert len(first.items) == 20
    assert len(second.items) == 20
    assert len(third.items) == 5


def test_resume_advances_to_user_phase_after_deletes():
    session = DeviceSyncSession.full(
        device_id=9,
        delete_pins=["1"],
        user_rows=[{"pin": "7"}],
        authorize_rows=[{"pin": "7"}],
    )

    first = session.next_chunk()
    second = session.next_chunk()

    assert first.phase == "DELETE"
    assert second.phase == "USER_UPSERT"
```

- [ ] **Step 2: Run the tests to verify RED**

Run:

```bash
pytest tests/test_device_sync_session.py -q
```

Expected: FAIL with missing `DeviceSyncSession`.

- [ ] **Step 3: Write the minimal sync-session implementation**

Create `app/core/device_sync_session.py` with fixed chunk constants:

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence


DELETE_CHUNK_SIZE = 20
USER_UPSERT_CHUNK_SIZE = 25
AUTHORIZE_CHUNK_SIZE = 25
TEMPLATE_USER_CHUNK_SIZE = 5


@dataclass(frozen=True)
class SyncChunk:
    phase: str
    items: list[Any]


class DeviceSyncSession:
    def __init__(
        self,
        *,
        device_id: int,
        delete_pins: Sequence[str],
        user_rows: Sequence[dict[str, Any]],
        authorize_rows: Sequence[dict[str, Any]],
        template_rows: Sequence[dict[str, Any]],
    ) -> None:
        self.device_id = int(device_id)
        self._phases = [
            ("DELETE", list(delete_pins), DELETE_CHUNK_SIZE),
            ("USER_UPSERT", list(user_rows), USER_UPSERT_CHUNK_SIZE),
            ("AUTHORIZE", list(authorize_rows), AUTHORIZE_CHUNK_SIZE),
            ("TEMPLATE", list(template_rows), TEMPLATE_USER_CHUNK_SIZE),
        ]
        self._phase_index = 0
        self._offset = 0

    @classmethod
    def full(
        cls,
        *,
        device_id: int,
        delete_pins: Sequence[str] = (),
        user_rows: Sequence[dict[str, Any]] = (),
        authorize_rows: Sequence[dict[str, Any]] = (),
        template_rows: Sequence[dict[str, Any]] = (),
    ) -> "DeviceSyncSession":
        return cls(
            device_id=device_id,
            delete_pins=delete_pins,
            user_rows=user_rows,
            authorize_rows=authorize_rows,
            template_rows=template_rows,
        )

    def next_chunk(self) -> SyncChunk:
        while self._phase_index < len(self._phases):
            phase, rows, chunk_size = self._phases[self._phase_index]
            if self._offset >= len(rows):
                self._phase_index += 1
                self._offset = 0
                continue
            start = self._offset
            end = min(len(rows), start + chunk_size)
            self._offset = end
            return SyncChunk(phase=phase, items=rows[start:end])
        raise StopIteration
```

- [ ] **Step 4: Run the tests to verify GREEN**

Run:

```bash
pytest tests/test_device_sync_session.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_device_sync_session.py app/core/device_sync_session.py
git commit -m "feat: add device sync session cursors"
```

---

## Task 3: Generic Actor Runtime With Fake Adapter

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_actor_runtime.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_actor_runtime.py`

- [ ] **Step 1: Write the failing actor runtime tests**

Create `tests/test_device_actor_runtime.py`:

```python
import threading
import time

from app.core.device_actor_mailbox import ActorMessage
from app.core.device_actor_runtime import DeviceActor


class FakeAdapter:
    def __init__(self):
        self.calls = []

    def open_door(self, *, door_id: int, pulse_ms: int):
        self.calls.append(("OPEN_DOOR", door_id, pulse_ms))

    def run_sync_chunk(self, session):
        chunk = session.next_chunk()
        self.calls.append(("SYNC", chunk.phase, len(chunk.items)))
        return True


def test_open_door_preempts_pending_sync_chunk():
    adapter = FakeAdapter()
    actor = DeviceActor(device_id=5, adapter=adapter)
    actor.start()
    actor.enqueue(ActorMessage.sync_next_chunk(device_id=5))
    actor.enqueue(ActorMessage.open_door(device_id=5, door_id=1, pulse_ms=1000))

    deadline = time.time() + 2
    while len(adapter.calls) < 1 and time.time() < deadline:
        time.sleep(0.01)

    actor.stop()

    assert adapter.calls[0][0] == "OPEN_DOOR"
```

- [ ] **Step 2: Run the tests to verify RED**

Run:

```bash
pytest tests/test_device_actor_runtime.py -q
```

Expected: FAIL with missing actor runtime types.

- [ ] **Step 3: Write the minimal actor runtime**

Create `app/core/device_actor_runtime.py`:

```python
from __future__ import annotations

import threading
from typing import Any, Optional

from app.core.device_actor_mailbox import ActorMessage, DeviceActorMailbox


class DeviceActor:
    def __init__(self, *, device_id: int, adapter: Any) -> None:
        self.device_id = int(device_id)
        self.adapter = adapter
        self.mailbox = DeviceActorMailbox()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name=f"DeviceActor-{self.device_id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def enqueue(self, message: ActorMessage) -> None:
        self.mailbox.put(message)
        self._wake_event.set()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=0.1)
            self._wake_event.clear()
            while True:
                try:
                    message = self.mailbox.get_nowait()
                except IndexError:
                    break
                if message.kind == "OPEN_DOOR":
                    self.adapter.open_door(door_id=int(message.door_id or 1), pulse_ms=int(message.pulse_ms or 1000))
                elif message.kind == "SYNC_NEXT_CHUNK" and hasattr(self.adapter, "run_sync_chunk"):
                    self.adapter.run_sync_chunk(getattr(self, "_session", None))
```

- [ ] **Step 4: Refine the runtime after GREEN**

Extend the runtime once the minimal test passes so the actor can hold a sync session reference and route `TARGETED_SYNC_START` / `FULL_SYNC_START` into session builders without touching SDK code yet.

- [ ] **Step 5: Run the actor runtime tests to verify GREEN**

Run:

```bash
pytest tests/test_device_actor_runtime.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add tests/test_device_actor_runtime.py app/core/device_actor_runtime.py
git commit -m "feat: add generic device actor runtime"
```

---

## Task 4: Route Existing Sync Workers Through Actor Registry

**Files:**
- Create: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_actor_registry.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_worker.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\device_sync.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_differential_device_push.py`

- [ ] **Step 1: Write the failing registry-routing test**

Add a test that replaces `DeviceWorkerManager` dispatch with registry enqueue behavior:

```python
def test_targeted_sync_dispatches_actor_messages(monkeypatch):
    captured = []

    class FakeRegistry:
        def enqueue_member_upsert(self, *, device_ids, member_id):
            captured.append((set(device_ids), member_id))

    engine = DeviceSyncEngine(cfg=DummyCfg(), logger=DummyLogger())
    engine._actor_registry = FakeRegistry()

    engine._dispatch_targeted_actor_updates(device_ids={8, 9}, changed_ids={12})

    assert captured == [({8, 9}, 12)]
```

- [ ] **Step 2: Run the targeted routing test to verify RED**

Run:

```bash
pytest tests/test_differential_device_push.py -q
```

Expected: FAIL because `DeviceSyncEngine` still only knows `DeviceWorkerManager`.

- [ ] **Step 3: Implement the registry and sync-engine hook**

Key code shape:

```python
class DeviceActorRegistry:
    def enqueue_member_upsert(self, *, device_ids: set[int], member_id: int) -> int:
        ...

    def enqueue_full_reconcile(self, *, device_ids: set[int] | None = None) -> int:
        ...
```

Then in `app/core/device_sync.py` add a thin dispatch helper:

```python
def _dispatch_targeted_actor_updates(self, *, device_ids: set[int], changed_ids: set[int]) -> int:
    count = 0
    registry = getattr(self, "_actor_registry", None)
    if not registry:
        return 0
    for member_id in sorted(changed_ids):
        count += registry.enqueue_member_upsert(device_ids=device_ids, member_id=int(member_id))
    return count
```

- [ ] **Step 4: Run the focused tests to verify GREEN**

Run:

```bash
pytest tests/test_differential_device_push.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/core/device_actor_registry.py app/core/device_worker.py app/core/device_sync.py tests/test_differential_device_push.py
git commit -m "feat: route targeted sync through actor registry"
```

---

## Task 5: Replace ULTRA Pause/Handoff With Actor Ownership

**Files:**
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\ultra_engine.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\core\realtime_agent.py`
- Modify: `C:\Users\mohaa\Desktop\monclub_access_python\app\ui\app.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_ultra_sync_scheduler.py`
- Test: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_fast_patch_runtime.py`

- [ ] **Step 1: Write the failing ULTRA regression test**

Add a test that proves a member delete or door-open enqueue does not call `pause_for_sync()`:

```python
def test_ultra_targeted_update_does_not_pause_rtlog_worker(monkeypatch):
    calls = []

    class FakeWorker:
        def pause_for_sync(self, timeout=20.0):
            calls.append("pause")
            return True

    scheduler = UltraSyncScheduler(cfg=DummyCfg(), logger=DummyLogger())
    scheduler._workers = {7: FakeWorker()}
    scheduler._actor_registry = FakeRegistry()

    scheduler.request_sync_now(reason="FAST_PATCH", changed_ids={33})

    assert calls == []
```

- [ ] **Step 2: Run the ULTRA regression test to verify RED**

Run:

```bash
pytest tests/test_ultra_sync_scheduler.py -q
```

Expected: FAIL because sync still uses `pause_for_sync()` / `resume_from_sync()`.

- [ ] **Step 3: Implement ULTRA actor routing**

Remove the handoff path and route sync/open-door to the actor registry:

```python
if self._actor_registry:
    self._actor_registry.enqueue_full_reconcile(device_ids={device_id})
    return True
```

Then expose actor-backed `open_door()` for realtime/ULTRA command producers.

- [ ] **Step 4: Run the focused ULTRA and fast-patch tests to verify GREEN**

Run:

```bash
pytest tests/test_ultra_sync_scheduler.py tests/test_fast_patch_runtime.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/core/ultra_engine.py app/core/realtime_agent.py app/ui/app.py tests/test_ultra_sync_scheduler.py tests/test_fast_patch_runtime.py
git commit -m "feat: route ULTRA runtime through device actors"
```

---

## Task 6: Final Regression Pass

**Files:**
- Verify only: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_actor_mailbox.py`
- Verify only: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_sync_session.py`
- Verify only: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_device_actor_runtime.py`
- Verify only: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_fast_patch_runtime.py`
- Verify only: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_differential_device_push.py`
- Verify only: `C:\Users\mohaa\Desktop\monclub_access_python\tests\test_ultra_sync_scheduler.py`

- [ ] **Step 1: Run the actor-focused regression suite**

```bash
pytest tests/test_device_actor_mailbox.py tests/test_device_sync_session.py tests/test_device_actor_runtime.py tests/test_fast_patch_runtime.py tests/test_differential_device_push.py tests/test_ultra_sync_scheduler.py -q
```

Expected: PASS.

- [ ] **Step 2: Run the existing fast-path suite**

```bash
pytest tests/test_sync_hot_path_optimizations.py tests/test_fast_patch_api.py tests/test_fast_patch_db.py -q
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add app/core/device_actor_mailbox.py app/core/device_sync_session.py app/core/device_actor_runtime.py app/core/device_actor_registry.py app/core/device_worker.py app/core/device_sync.py app/core/ultra_engine.py app/core/realtime_agent.py app/ui/app.py tests/test_device_actor_mailbox.py tests/test_device_sync_session.py tests/test_device_actor_runtime.py tests/test_differential_device_push.py tests/test_ultra_sync_scheduler.py
git commit -m "feat: implement per-device actor runtime"
```

---

## Self-Review

- The plan covers the full spec arc: generic actor shell, mailbox priority/coalescing, fixed sync chunking, restart/rebuild behavior, same actor model for all device types, and removal of the ULTRA socket handoff path.
- The riskiest migration point is Task 5. Do not begin there before Tasks 1-4 are green.
- Keep the first implementation slice small: mailbox first, then sync session, then runtime shell. That keeps the initial code independent from the device SDK and lets the later migration land on a tested core.
