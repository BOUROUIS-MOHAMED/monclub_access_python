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
        self._phases: list[tuple[str, list[Any], int]] = [
            ("DELETE", list(delete_pins), DELETE_CHUNK_SIZE),
            ("USER_UPSERT", list(user_rows), USER_UPSERT_CHUNK_SIZE),
            ("AUTHORIZE", list(authorize_rows), AUTHORIZE_CHUNK_SIZE),
            ("TEMPLATE", list(template_rows), TEMPLATE_USER_CHUNK_SIZE),
        ]
        self._phase_index = 0
        self._phase_offset = 0

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
            phase_name, rows, chunk_size = self._phases[self._phase_index]
            if self._phase_offset >= len(rows):
                self._phase_index += 1
                self._phase_offset = 0
                continue

            start = self._phase_offset
            end = min(len(rows), start + chunk_size)
            self._phase_offset = end
            return SyncChunk(phase=phase_name, items=rows[start:end])

        raise StopIteration("sync session exhausted")

    def has_pending_work(self) -> bool:
        phase_index = self._phase_index
        phase_offset = self._phase_offset

        while phase_index < len(self._phases):
            _, rows, _ = self._phases[phase_index]
            if phase_offset < len(rows):
                return True
            phase_index += 1
            phase_offset = 0
        return False
