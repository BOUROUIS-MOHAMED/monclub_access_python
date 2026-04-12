from __future__ import annotations

from dataclasses import dataclass, field
import heapq
import itertools
import threading
from typing import FrozenSet, Optional


_MESSAGE_PRIORITY = {
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
        return int(_MESSAGE_PRIORITY[self.kind])

    @classmethod
    def open_door(cls, *, device_id: int, door_id: int, pulse_ms: int) -> "ActorMessage":
        return cls(
            kind="OPEN_DOOR",
            device_id=int(device_id),
            door_id=int(door_id),
            pulse_ms=int(pulse_ms),
        )

    @classmethod
    def full_sync_start(cls, *, device_id: int) -> "ActorMessage":
        return cls(kind="FULL_SYNC_START", device_id=int(device_id))

    @classmethod
    def sync_next_chunk(cls, *, device_id: int) -> "ActorMessage":
        return cls(kind="SYNC_NEXT_CHUNK", device_id=int(device_id))

    @classmethod
    def member_upsert(cls, *, device_id: int, member_id: int) -> "ActorMessage":
        return cls(
            kind="MEMBER_UPSERT",
            device_id=int(device_id),
            member_id=int(member_id),
        )

    @classmethod
    def member_delete(cls, *, device_id: int, member_id: int) -> "ActorMessage":
        return cls(
            kind="MEMBER_DELETE",
            device_id=int(device_id),
            member_id=int(member_id),
        )

    @classmethod
    def targeted_sync_start(
        cls,
        *,
        device_id: int,
        member_ids: set[int] | FrozenSet[int],
    ) -> "ActorMessage":
        return cls(
            kind="TARGETED_SYNC_START",
            device_id=int(device_id),
            member_ids=frozenset(int(member_id) for member_id in member_ids),
        )


class DeviceActorMailbox:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._heap: list[tuple[int, int, ActorMessage]] = []
        self._sequence = itertools.count()
        self._latest_member_messages: dict[int, ActorMessage] = {}
        self._latest_targeted_sync: Optional[ActorMessage] = None
        self._full_sync_pending = False

    def put(self, message: ActorMessage) -> None:
        with self._lock:
            if message.kind in {"MEMBER_UPSERT", "MEMBER_DELETE"} and message.member_id is not None:
                current = self._latest_member_messages.get(message.member_id)
                if current is not None and current.kind == "MEMBER_DELETE" and message.kind == "MEMBER_UPSERT":
                    return
                self._latest_member_messages[message.member_id] = message
                self._push(message)
                return

            if message.kind == "TARGETED_SYNC_START":
                merged_ids = set(self._latest_targeted_sync.member_ids) if self._latest_targeted_sync else set()
                merged_ids.update(int(member_id) for member_id in message.member_ids)
                merged = ActorMessage.targeted_sync_start(
                    device_id=message.device_id,
                    member_ids=merged_ids,
                )
                self._latest_targeted_sync = merged
                self._push(merged)
                return

            if message.kind == "FULL_SYNC_START":
                if self._full_sync_pending:
                    return
                self._full_sync_pending = True

            self._push(message)

    def get_nowait(self) -> ActorMessage:
        with self._lock:
            while self._heap:
                _, _, message = heapq.heappop(self._heap)

                if message.kind in {"MEMBER_UPSERT", "MEMBER_DELETE"} and message.member_id is not None:
                    latest = self._latest_member_messages.get(message.member_id)
                    if latest != message:
                        continue
                    self._latest_member_messages.pop(message.member_id, None)
                    return message

                if message.kind == "TARGETED_SYNC_START":
                    if self._latest_targeted_sync != message:
                        continue
                    self._latest_targeted_sync = None
                    return message

                if message.kind == "FULL_SYNC_START":
                    self._full_sync_pending = False

                return message

        raise IndexError("mailbox empty")

    def empty(self) -> bool:
        with self._lock:
            return not self._has_live_entries_locked()

    def _push(self, message: ActorMessage) -> None:
        heapq.heappush(
            self._heap,
            (message.priority, next(self._sequence), message),
        )

    def _has_live_entries_locked(self) -> bool:
        for _, _, message in self._heap:
            if message.kind in {"MEMBER_UPSERT", "MEMBER_DELETE"} and message.member_id is not None:
                if self._latest_member_messages.get(message.member_id) == message:
                    return True
                continue
            if message.kind == "TARGETED_SYNC_START":
                if self._latest_targeted_sync == message:
                    return True
                continue
            if message.kind == "FULL_SYNC_START" and not self._full_sync_pending:
                continue
            return True
        return False
