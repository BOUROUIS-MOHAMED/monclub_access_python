import threading
import time

from app.core.device_actor_mailbox import ActorMessage
from app.core.device_actor_runtime import DeviceActor
from app.core.device_sync_session import DeviceSyncSession


class FakeAdapter:
    def __init__(self):
        self.calls = []
        self.wait_for_sync = threading.Event()
        self.allow_sync = threading.Event()

    def open_door(self, *, door_id: int, pulse_ms: int) -> None:
        self.calls.append(("OPEN_DOOR", door_id, pulse_ms))

    def build_full_sync_session(self, *, device_id: int):
        return DeviceSyncSession.full(
            device_id=device_id,
            user_rows=[{"pin": "1"}, {"pin": "2"}],
        )

    def build_targeted_sync_session(self, *, device_id: int, member_ids: set[int]):
        self.calls.append(("TARGETED_SYNC", tuple(sorted(member_ids))))
        return DeviceSyncSession.full(
            device_id=device_id,
            user_rows=[{"pin": str(member_id)} for member_id in sorted(member_ids)],
        )

    def run_sync_chunk(self, session):
        self.wait_for_sync.set()
        self.allow_sync.wait(timeout=1)
        chunk = session.next_chunk()
        self.calls.append(("SYNC", chunk.phase, tuple(item["pin"] for item in chunk.items)))
        return True


def test_open_door_preempts_pending_sync_chunk():
    adapter = FakeAdapter()
    actor = DeviceActor(device_id=5, adapter=adapter)
    actor.start()
    actor.enqueue(ActorMessage.full_sync_start(device_id=5))

    assert adapter.wait_for_sync.wait(timeout=1)

    actor.enqueue(ActorMessage.open_door(device_id=5, door_id=1, pulse_ms=1000))
    adapter.allow_sync.set()

    deadline = time.time() + 2
    while len(adapter.calls) < 2 and time.time() < deadline:
        time.sleep(0.01)

    actor.stop()

    assert adapter.calls[0][0] == "SYNC"
    assert adapter.calls[1] == ("OPEN_DOOR", 1, 1000)


def test_targeted_sync_builds_session_once_and_runs_chunks():
    adapter = FakeAdapter()
    actor = DeviceActor(device_id=7, adapter=adapter)
    actor.start()

    actor.enqueue(ActorMessage.targeted_sync_start(device_id=7, member_ids={11, 13}))
    assert adapter.wait_for_sync.wait(timeout=1)
    adapter.allow_sync.set()

    deadline = time.time() + 2
    while len(adapter.calls) < 2 and time.time() < deadline:
        time.sleep(0.01)

    actor.stop()

    assert adapter.calls[0] == ("TARGETED_SYNC", (11, 13))
    assert adapter.calls[1][0] == "SYNC"
    assert actor.get_status()["current_sync_kind"] is None
