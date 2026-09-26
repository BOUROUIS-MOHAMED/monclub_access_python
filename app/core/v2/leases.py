"""Driver leases on the PC (P2c-1 contract; owner decisions 1, 4, 8).

* ``refresh()`` reads ``GET /pc/assignment`` and installs the lease gate snapshot.
  - 2xx: install it and cache the body on disk, so a cold power-on without internet (most gyms
    cut the power overnight) starts with the same roles: a reader stays a reader offline.
  - backend 404 ``NOT_FOUND`` (the server switch is off): clear the cache and allow every
    turnstile — exactly the pre-v2 behaviour.
  - anything else (offline, proxy error, 5xx, no token): keep what is installed.
* The cache is tied to the PC installation (``pcUuid``): a re-registered or adopted PC ignores
  another installation's roles.
* add-only: a DRIVE turnstile is add-only while its lease says ``handoverForced`` or while this
  PC has not restored the ownership backup for the lease generation it holds (see ownership.py).
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, Iterable, Optional

from app.core.v2 import lease_gate
from app.core.v2.api import V2Api, V2ApiError

_log = logging.getLogger("zkapp.v2.leases")

CACHE_KEY = "assignment_cache"
RESTORE_KEY_PREFIX = "restored:"

ON, OFF, UNREACHABLE = "ON", "OFF", "UNREACHABLE"


class LeaseManager:
    def __init__(self, *, api: V2Api, pc_uuid_provider: Callable[[], Optional[str]],
                 identity_state_provider: Optional[Callable[[], Optional[str]]] = None,
                 on_change: Optional[Callable[[lease_gate.LeaseSnapshot, lease_gate.LeaseSnapshot], None]] = None,
                 kv_get: Optional[Callable[[str], Any]] = None, kv_put: Optional[Callable[..., None]] = None,
                 kv_delete: Optional[Callable[[str], None]] = None, wall: Callable[[], float] = time.time) -> None:
        from app.core.v2 import store
        self._api = api
        self._pc_uuid = pc_uuid_provider
        self._identity_state = identity_state_provider or (lambda: None)
        self._on_change = on_change
        self._get = kv_get or store.kv_get
        self._put = kv_put or store.kv_put
        self._delete = kv_delete or store.kv_delete
        self._wall = wall
        self._lock = threading.Lock()
        self.last_body: Optional[Dict[str, Any]] = None
        self.last_result: Optional[str] = None
        self.last_error: Optional[str] = None
        self.last_refresh_at: Optional[float] = None

    # ------------------------------------------------------------------ restore records
    def restored_generation(self, device_id: int) -> Optional[int]:
        rec = self._get(f"{RESTORE_KEY_PREFIX}{int(device_id)}")
        try:
            return int((rec or {}).get("leaseGeneration"))
        except (TypeError, ValueError):
            return None

    def mark_restored(self, device_id: int, lease_generation: int, **extra: Any) -> None:
        rec = {"leaseGeneration": int(lease_generation), "at": self._wall()}
        rec.update(extra)
        self._put(f"{RESTORE_KEY_PREFIX}{int(device_id)}", rec)
        self._reinstall()

    def _not_restored(self, body: Dict[str, Any]) -> Iterable[int]:
        out = []
        for item in body.get("drive") or []:
            if not isinstance(item, dict) or item.get("state") != "DRIVE":
                continue
            try:
                did, gen = int(item.get("gymDeviceId")), int(item.get("generation"))
            except (TypeError, ValueError):
                continue
            if self.restored_generation(did) != gen:
                out.append(did)
        return out

    # ------------------------------------------------------------------ install
    def _build(self, body: Dict[str, Any], source: str, fetched_at: Optional[float]) -> lease_gate.LeaseSnapshot:
        add_only = self._not_restored(body) if body.get("gymUsesAssignments") else ()
        return lease_gate.snapshot_from_assignment(body, source=source, add_only=add_only,
                                                   fetched_at=fetched_at)

    def _install(self, snap: lease_gate.LeaseSnapshot) -> None:
        previous = lease_gate.install(snap)
        if self._on_change is not None and _material(previous) != _material(snap):
            try:
                self._on_change(previous, snap)
            except Exception as exc:
                _log.warning("[V2] lease change callback failed: %s", exc)

    def _reinstall(self) -> None:
        with self._lock:
            body = self.last_body
            if body is None:
                return
            cur = lease_gate.current()
            self._install(self._build(body, cur.source, cur.fetched_at))

    def _revoked(self, exc: V2ApiError) -> bool:
        """The server says this installation is no longer an ACTIVE PC (review R2)."""
        if exc.backend and exc.code in ("ACCESS_PC_REVOKED", "ACCESS_PC_ADOPTED"):
            return True
        if exc.code == "NO_PC_TOKEN":
            try:
                return self._identity_state() in ("revoked", "invalid_credentials", "invalid_token")
            except Exception:
                return False
        return False

    def _drop_leases(self, why: str) -> None:
        """A revoked or adopted PC drives nothing while the gym uses leases: the server already
        gave its turnstiles to another PC (forced, add-only there), so this PC writing on would
        be a second writer -- and the only one that removes. In a gym without leases it keeps
        today's behaviour (every PC drives every turnstile). The dropped roles are cached too,
        so a cold start does not bring them back."""
        with self._lock:
            cur = lease_gate.current()
            if cur.mode != lease_gate.MODE_LEASED:
                return
            body = {"gymUsesAssignments": True, "role": "REVOKED", "drive": [], "release": [],
                    "readerOf": []}
            self.last_body = body
            self._install(self._build(body, "revoked", self._wall()))
        _log.warning("[V2] this PC is %s: it drives no turnstile any more", why)
        try:
            self._put(CACHE_KEY, {"body": body, "pcUuid": self._pc_uuid(), "fetchedAt": self._wall()})
        except Exception:
            pass

    def load_cache(self) -> bool:
        """At start-up: install the cached roles (before any worker starts)."""
        cached = self._get(CACHE_KEY)
        if not isinstance(cached, dict) or not isinstance(cached.get("body"), dict):
            return False
        uuid = None
        try:
            uuid = self._pc_uuid()
        except Exception:
            uuid = None
        if not uuid or cached.get("pcUuid") != uuid:
            _log.info("[V2] cached assignment ignored: it belongs to another PC installation")
            return False
        with self._lock:
            self.last_body = cached["body"]
            self._install(self._build(cached["body"], "cache", cached.get("fetchedAt")))
        _log.info("[V2] roles loaded from the local cache: role=%s", lease_gate.current().role)
        return True

    def refresh(self) -> str:
        try:
            body = self._api.assignment()
        except V2ApiError as exc:
            self.last_error = str(exc)
            if exc.switched_off:
                with self._lock:
                    self.last_body = None
                    self.last_result = OFF
                    self._install(lease_gate.LeaseSnapshot())
                try:
                    self._delete(CACHE_KEY)
                except Exception:
                    pass
                return OFF
            if self._revoked(exc):
                self._drop_leases("revoked or adopted")
            self.last_result = UNREACHABLE
            return UNREACHABLE
        now = self._wall()
        with self._lock:
            self.last_body = body
            self.last_result = ON
            self.last_error = None
            self.last_refresh_at = now
            self._install(self._build(body, "server", now))
        try:
            self._put(CACHE_KEY, {"body": body, "pcUuid": self._pc_uuid(), "fetchedAt": now})
        except Exception as exc:
            _log.warning("[V2] could not cache the assignment: %s", exc)
        return ON


def _material(snap: lease_gate.LeaseSnapshot) -> tuple:
    """What changes the engines: the allowed set, the frozen set and the add-only set."""
    drive = tuple(sorted((d, e.generation, e.state) for d, e in snap.drive.items()))
    release = tuple(sorted((d, e.generation) for d, e in snap.release.items()))
    return (snap.mode, drive, release, tuple(sorted(snap.add_only)))
