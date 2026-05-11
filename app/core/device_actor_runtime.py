from __future__ import annotations

import threading
from typing import Any, Optional

from app.core.device_actor_mailbox import ActorMessage, DeviceActorMailbox
from app.core.device_sync_session import DeviceSyncSession


class DeviceActor:
    def __init__(self, *, device_id: int, adapter: Any) -> None:
        self.device_id = int(device_id)
        self.adapter = adapter
        self.mailbox = DeviceActorMailbox()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._state_lock = threading.Lock()
        self._current_sync_session: Optional[DeviceSyncSession] = None
        self._current_sync_kind: Optional[str] = None
        self._last_error: str = ""

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run,
            name=f"DeviceActor-{self.device_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def enqueue(self, message: ActorMessage) -> None:
        self.mailbox.put(message)
        self._wake_event.set()

    def get_status(self) -> dict[str, Any]:
        with self._state_lock:
            return {
                "device_id": self.device_id,
                "running": bool(self._thread and self._thread.is_alive()),
                "current_sync_kind": self._current_sync_kind,
                "has_pending_sync_work": bool(
                    self._current_sync_session and self._current_sync_session.has_pending_work()
                ),
                "last_error": self._last_error,
            }

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=0.1)
            self._wake_event.clear()

            while not self._stop_event.is_set():
                try:
                    message = self.mailbox.get_nowait()
                except IndexError:
                    break
                try:
                    self._handle_message(message)
                except Exception as exc:
                    with self._state_lock:
                        self._last_error = str(exc)
                    if message.kind in {"FULL_SYNC_START", "TARGETED_SYNC_START", "SYNC_NEXT_CHUNK"}:
                        self._finish_current_sync(force_notify=True)

    def _finish_current_sync(self, *, force_notify: bool = False) -> None:
        should_notify = bool(force_notify)
        with self._state_lock:
            if self._current_sync_session is not None or self._current_sync_kind is not None:
                should_notify = True
            self._current_sync_session = None
            self._current_sync_kind = None
        if not should_notify:
            return
        callback = getattr(self.adapter, "on_sync_finished", None)
        if not callable(callback):
            return
        try:
            callback(device_id=self.device_id)
        except TypeError:
            callback(self.device_id)

    def _handle_message(self, message: ActorMessage) -> None:
        if message.kind == "OPEN_DOOR":
            self.adapter.open_door(
                door_id=int(message.door_id or 1),
                pulse_ms=int(message.pulse_ms or 1000),
            )
            return

        if message.kind == "FULL_SYNC_START":
            builder = getattr(self.adapter, "build_full_sync_session", None)
            if builder is None:
                return
            session = builder(device_id=self.device_id)
            with self._state_lock:
                self._current_sync_session = session
                self._current_sync_kind = "FULL_SYNC"
            if session and session.has_pending_work():
                self.enqueue(ActorMessage.sync_next_chunk(device_id=self.device_id))
            else:
                self._finish_current_sync()
            return

        if message.kind == "TARGETED_SYNC_START":
            builder = getattr(self.adapter, "build_targeted_sync_session", None)
            if builder is None:
                return
            session = builder(
                device_id=self.device_id,
                member_ids=set(message.member_ids),
            )
            with self._state_lock:
                self._current_sync_session = session
                self._current_sync_kind = "TARGETED_SYNC"
            if session and session.has_pending_work():
                self.enqueue(ActorMessage.sync_next_chunk(device_id=self.device_id))
            else:
                self._finish_current_sync()
            return

        if message.kind == "SYNC_NEXT_CHUNK":
            with self._state_lock:
                session = self._current_sync_session
            if session is None:
                return
            self.adapter.run_sync_chunk(session)
            if session.has_pending_work():
                self.enqueue(ActorMessage.sync_next_chunk(device_id=self.device_id))
            else:
                self._finish_current_sync()
            return
