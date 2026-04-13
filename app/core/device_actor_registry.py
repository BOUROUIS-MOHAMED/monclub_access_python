from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Iterable, Optional

from app.core.device_actor_mailbox import ActorMessage
from app.core.device_actor_runtime import DeviceActor


class DeviceActorRegistry:
    def __init__(
        self,
        *,
        adapter_factory: Callable[[dict[str, Any]], Any],
        actor_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._adapter_factory = adapter_factory
        self._actor_factory = actor_factory or self._build_actor
        self._actors: Dict[int, Any] = {}
        self._lock = threading.Lock()

    def update_devices(self, devices: list[dict[str, Any]]) -> None:
        seen_ids: set[int] = set()

        for device in devices:
            raw_id = device.get("id")
            if raw_id is None:
                continue
            device_id = int(raw_id)
            seen_ids.add(device_id)
            with self._lock:
                actor = self._actors.get(device_id)
                if actor is None:
                    actor = self._actor_factory(
                        device_id=device_id,
                        adapter=self._adapter_factory(device),
                    )
                    self._actors[device_id] = actor
                    actor.start()
                else:
                    adapter = getattr(actor, "adapter", None)
                    if adapter is not None and hasattr(adapter, "update_device"):
                        adapter.update_device(device)

        with self._lock:
            removed_ids = sorted(set(self._actors) - seen_ids)

        for device_id in removed_ids:
            with self._lock:
                actor = self._actors.pop(device_id, None)
            if actor is not None:
                actor.stop()

    def enqueue_member_upsert(self, *, device_ids: set[int], member_id: int) -> int:
        return self._enqueue_many(
            device_ids=device_ids,
            builder=lambda device_id: ActorMessage.member_upsert(
                device_id=device_id,
                member_id=member_id,
            ),
        )

    def enqueue_member_delete(self, *, device_ids: set[int], member_id: int) -> int:
        return self._enqueue_many(
            device_ids=device_ids,
            builder=lambda device_id: ActorMessage.member_delete(
                device_id=device_id,
                member_id=member_id,
            ),
        )

    def enqueue_targeted_sync(self, *, device_ids: set[int], member_ids: set[int]) -> int:
        return self._enqueue_many(
            device_ids=device_ids,
            builder=lambda device_id: ActorMessage.targeted_sync_start(
                device_id=device_id,
                member_ids=member_ids,
            ),
        )

    def enqueue_full_reconcile(self, *, device_ids: Optional[set[int]] = None) -> int:
        target_ids = device_ids if device_ids is not None else set(self.active_device_ids())
        return self._enqueue_many(
            device_ids=target_ids,
            builder=lambda device_id: ActorMessage.full_sync_start(device_id=device_id),
        )

    def active_device_ids(self) -> list[int]:
        with self._lock:
            return sorted(self._actors.keys())

    def stop_all(self) -> None:
        with self._lock:
            actors = list(self._actors.values())
            self._actors.clear()
        for actor in actors:
            actor.stop()

    def _enqueue_many(
        self,
        *,
        device_ids: Iterable[int],
        builder: Callable[[int], ActorMessage],
    ) -> int:
        count = 0
        for raw_device_id in sorted(set(int(device_id) for device_id in device_ids)):
            with self._lock:
                actor = self._actors.get(raw_device_id)
            if actor is None:
                continue
            actor.enqueue(builder(raw_device_id))
            count += 1
        return count

    @staticmethod
    def _build_actor(*, device_id: int, adapter: Any) -> DeviceActor:
        return DeviceActor(device_id=device_id, adapter=adapter)
