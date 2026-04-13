from app.core.device_actor_mailbox import ActorMessage, DeviceActorMailbox


def test_open_door_outranks_sync_chunk():
    mailbox = DeviceActorMailbox()
    mailbox.put(ActorMessage.full_sync_start(device_id=7))
    mailbox.put(ActorMessage.sync_next_chunk(device_id=7))
    mailbox.put(ActorMessage.open_door(device_id=7, door_id=2, pulse_ms=1200))

    first = mailbox.get_nowait()
    second = mailbox.get_nowait()
    third = mailbox.get_nowait()

    assert first.kind == "OPEN_DOOR"
    assert second.kind == "SYNC_NEXT_CHUNK"
    assert third.kind == "FULL_SYNC_START"


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
    assert msg.member_ids == frozenset({1, 2, 3})
    assert mailbox.empty()
