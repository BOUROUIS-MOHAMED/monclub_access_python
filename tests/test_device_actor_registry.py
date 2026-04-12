from app.core.device_actor_registry import DeviceActorRegistry


class FakeActor:
    def __init__(self, *, device_id, adapter):
        self.device_id = device_id
        self.adapter = adapter
        self.messages = []
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def enqueue(self, message):
        self.messages.append(message)


def test_update_devices_creates_and_removes_actors():
    created = {}

    def actor_factory(*, device_id, adapter):
        actor = FakeActor(device_id=device_id, adapter=adapter)
        created[device_id] = actor
        return actor

    registry = DeviceActorRegistry(
        adapter_factory=lambda device: {"device": device},
        actor_factory=actor_factory,
    )

    registry.update_devices([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    registry.update_devices([{"id": 2, "name": "B"}])

    assert created[1].started is True
    assert created[1].stopped is True
    assert created[2].started is True
    assert registry.active_device_ids() == [2]


def test_enqueue_helpers_route_messages_to_selected_actors():
    actors = {}

    def actor_factory(*, device_id, adapter):
        actor = FakeActor(device_id=device_id, adapter=adapter)
        actors[device_id] = actor
        return actor

    registry = DeviceActorRegistry(
        adapter_factory=lambda device: {"device": device},
        actor_factory=actor_factory,
    )
    registry.update_devices([{"id": 7}, {"id": 8}])

    routed = registry.enqueue_member_upsert(device_ids={7}, member_id=33)
    registry.enqueue_full_reconcile(device_ids={8})

    assert routed == 1
    assert [message.kind for message in actors[7].messages] == ["MEMBER_UPSERT"]
    assert [message.kind for message in actors[8].messages] == ["FULL_SYNC_START"]
