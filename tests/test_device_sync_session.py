from app.core.device_sync_session import (
    AUTHORIZE_CHUNK_SIZE,
    DELETE_CHUNK_SIZE,
    TEMPLATE_USER_CHUNK_SIZE,
    USER_UPSERT_CHUNK_SIZE,
    DeviceSyncSession,
)


def test_delete_phase_uses_fixed_chunk_of_20():
    session = DeviceSyncSession.full(device_id=9, delete_pins=[str(i) for i in range(45)])

    first = session.next_chunk()
    second = session.next_chunk()
    third = session.next_chunk()

    assert DELETE_CHUNK_SIZE == 20
    assert first.phase == "DELETE"
    assert len(first.items) == 20
    assert len(second.items) == 20
    assert len(third.items) == 5


def test_resume_advances_to_user_phase_after_deletes():
    session = DeviceSyncSession.full(
        device_id=9,
        delete_pins=["1"],
        user_rows=[{"pin": str(i)} for i in range(30)],
        authorize_rows=[{"pin": str(i)} for i in range(26)],
        template_rows=[{"pin": str(i)} for i in range(7)],
    )

    first = session.next_chunk()
    second = session.next_chunk()
    third = session.next_chunk()
    fourth = session.next_chunk()
    fifth = session.next_chunk()
    sixth = session.next_chunk()

    assert USER_UPSERT_CHUNK_SIZE == 25
    assert AUTHORIZE_CHUNK_SIZE == 25
    assert TEMPLATE_USER_CHUNK_SIZE == 5
    assert first.phase == "DELETE"
    assert second.phase == "USER_UPSERT"
    assert len(second.items) == 25
    assert third.phase == "USER_UPSERT"
    assert len(third.items) == 5
    assert fourth.phase == "AUTHORIZE"
    assert len(fourth.items) == 25
    assert fifth.phase == "AUTHORIZE"
    assert len(fifth.items) == 1
    assert sixth.phase == "TEMPLATE"
    assert len(sixth.items) == 5
