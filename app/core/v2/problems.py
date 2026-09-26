"""Per-turnstile problem signals, and the one-shot "Confirm removal" approvals (P2c-2 §2-3).

A leaf module (standard library only): ``push_safety``, ``ultra_engine`` and ``device_sync``
record into it from the places that already detect each problem; the v2 runtime reads a
snapshot per turnstile and posts it to ``/pc/turnstile-problems``.

Codes (the server's closed set; an unknown one is ignored there):
* ``REVOKE_ABORTED`` — a removal step refused by the shared ceiling (``above_ceiling``) or an
  empty roster (``empty_roster``), with EVERY refused pin (the list a Confirm-removal binds
  to). Only the standalone revoke pass and the PullSDK stale step are recorded: a table clear
  deletes foreign users too, and a renewal release is a composite, so neither is confirmable.
  An add-only or handover deferral is NOT a ``REVOKE_ABORTED`` (it would offer a Confirm button
  for something that is only waiting).
* ``SKIPPED_NOT_OWNED`` — a revocation MonClub could not prove it owned (final).
* ``CAPACITY_FULL`` — members not pushed / fingers withheld for lack of slots.
* ``TEMPLATE_VERSION_MISMATCH`` — templates not uploaded (algorithm version).
* ``MISSING_OWNED`` — owned pins absent from a trusted read-back.

Each code is resolved where its own step runs: a removal step that runs with nothing refused
clears its ``REVOKE_ABORTED``; a capacity check that admits everything clears
``CAPACITY_FULL``; a push removes the pins it wrote without a version mismatch from
``TEMPLATE_VERSION_MISMATCH``; each trusted read-back replaces ``MISSING_OWNED``;
``SKIPPED_NOT_OWNED`` entries expire after ``SKIPPED_TTL_SEC``.

The pin-set hash is the server's canonical one (``AccessPinSets.canonicalHash``): trimmed,
de-duplicated, sorted as strings, joined by ``\\n``, SHA-256, lower-case hex.
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

REVOKE_ABORTED = "REVOKE_ABORTED"
SKIPPED_NOT_OWNED = "SKIPPED_NOT_OWNED"
CAPACITY_FULL = "CAPACITY_FULL"
TEMPLATE_VERSION_MISMATCH = "TEMPLATE_VERSION_MISMATCH"
MISSING_OWNED = "MISSING_OWNED"

CONFIRMABLE_PATHS = ("standalone_revoke", "stale")
SKIPPED_TTL_SEC = 7 * 86400.0
MAX_OTHER_PINS = 500
MAX_REMOVAL_PINS = 5000


def canonical_hash(pins: Iterable[Any]) -> str:
    uniq = sorted({str(p).strip() for p in pins if p is not None})
    return hashlib.sha256("\n".join(uniq).encode("utf-8")).hexdigest()


class _Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # device -> path -> (pins tuple, reason, observed_at)
        self._aborted: Dict[int, Dict[str, Tuple[tuple, str, float]]] = {}
        # device -> code -> (pins set, count, observed_at)
        self._other: Dict[int, Dict[str, Tuple[set, int, float]]] = {}
        self._skipped: Dict[int, Dict[str, float]] = {}
        self._changed_at: Dict[int, float] = {}
        self._approvals: Dict[int, Tuple[str, int, float]] = {}   # device -> (hash, count, expires_wall)
        self.approvals_used: List[Tuple[int, str]] = []

    # ------------------------------------------------------------------ recording
    def revoke_aborted(self, device_id: Any, path: str, pins: Iterable[Any], reason: str) -> None:
        did = _did(device_id)
        if did is None or path not in CONFIRMABLE_PATHS or reason not in ("above_ceiling", "empty_roster"):
            return
        with self._lock:
            key = tuple(sorted({str(p).strip() for p in pins}))
            prev = self._aborted.setdefault(did, {}).get(path)
            if prev is None or prev[0] != key or prev[1] != reason:
                self._aborted[did][path] = (key, reason, time.time())
                self._changed_at[did] = time.time()

    def removal_allowed(self, device_id: Any, path: str) -> None:
        did = _did(device_id)
        if did is None:
            return
        with self._lock:
            if self._aborted.get(did, {}).pop(path, None) is not None or did not in self._changed_at:
                # (also the first time a step runs in this process: the report then tells the
                # server what this PC sees now, replacing a snapshot from before a restart)
                self._changed_at[did] = time.time()

    def set_code(self, device_id: Any, code: str, pins: Iterable[Any], count: Optional[int] = None) -> None:
        did = _did(device_id)
        if did is None:
            return
        pin_set = {str(p).strip() for p in pins if str(p).strip()}
        n = int(count if count is not None else len(pin_set))
        with self._lock:
            prev = self._other.setdefault(did, {}).get(code)
            if prev is None or prev[0] != pin_set or prev[1] != n:
                self._other[did][code] = (pin_set, n, time.time())
                self._changed_at[did] = time.time()

    def clear_code(self, device_id: Any, code: str) -> None:
        did = _did(device_id)
        if did is None:
            return
        with self._lock:
            if self._other.get(did, {}).pop(code, None) is not None or did not in self._changed_at:
                self._changed_at[did] = time.time()

    def skipped_not_owned(self, device_id: Any, pins: Iterable[Any]) -> None:
        did = _did(device_id)
        if did is None:
            return
        now = time.time()
        with self._lock:
            cur = self._skipped.setdefault(did, {})
            for p in pins:
                s = str(p).strip()
                if s and s not in cur:
                    cur[s] = now
                    self._changed_at[did] = now

    def update_code_pins(self, device_id: Any, code: str, *, add: Iterable[Any] = (),
                         remove: Iterable[Any] = ()) -> None:
        """Add pins that show the problem and drop pins now shown to be fine."""
        did = _did(device_id)
        if did is None:
            return
        add_s = {str(p).strip() for p in add if str(p).strip()}
        rem_s = {str(p).strip() for p in remove if str(p).strip()} - add_s
        with self._lock:
            cur = self._other.setdefault(did, {}).get(code)
            pins = set(cur[0]) if cur else set()
            new = (pins | add_s) - rem_s
            if new == pins:
                return
            if new:
                self._other[did][code] = (new, len(new), time.time())
            else:
                self._other[did].pop(code, None)
            self._changed_at[did] = time.time()

    # ------------------------------------------------------------------ reading
    def devices(self) -> List[int]:
        with self._lock:
            return sorted(set(self._aborted) | set(self._other) | set(self._skipped) | set(self._changed_at))

    def changed_at(self, device_id: int) -> float:
        with self._lock:
            return self._changed_at.get(int(device_id), 0.0)

    def current_removal_list(self, device_id: Any) -> Optional[Tuple[List[str], str]]:
        """The ONE refused removal list of a turnstile: every pin of every confirmable path."""
        did = _did(device_id)
        with self._lock:
            entries = dict(self._aborted.get(did, {})) if did is not None else {}
        if not entries:
            return None
        pins = sorted({p for key, _r, _t in entries.values() for p in key})
        reasons = {r for _k, r, _t in entries.values()}
        reason = "empty_roster" if "empty_roster" in reasons else "above_ceiling"
        return pins, reason

    def snapshot(self, device_id: int) -> List[Dict[str, Any]]:
        did = int(device_id)
        now = time.time()
        with self._lock:
            aborted = dict(self._aborted.get(did, {}))
            other = dict(self._other.get(did, {}))
            skipped = {p: t for p, t in self._skipped.get(did, {}).items() if now - t < SKIPPED_TTL_SEC}
            self._skipped[did] = dict(skipped)
        out: List[Dict[str, Any]] = []
        if aborted:
            pins = sorted({p for key, _r, _t in aborted.values() for p in key})[:MAX_REMOVAL_PINS]
            reasons = {r for _k, r, _t in aborted.values()}
            paths = sorted(aborted)
            out.append({"code": REVOKE_ABORTED, "count": len(pins), "pins": pins,
                        "reason": "empty_roster" if "empty_roster" in reasons else "above_ceiling",
                        "path": paths[0] if len(paths) == 1 else "mixed",
                        "pinSetHash": canonical_hash(pins)})
        if skipped:
            pins = sorted(skipped)
            out.append({"code": SKIPPED_NOT_OWNED, "count": len(pins), "pins": pins[:MAX_OTHER_PINS]})
        for code in (CAPACITY_FULL, TEMPLATE_VERSION_MISMATCH, MISSING_OWNED):
            if code in other:
                pins, n, _t = other[code]
                ps = sorted(pins)
                out.append({"code": code, "count": max(int(n), len(ps)), "pins": ps[:MAX_OTHER_PINS]})
        return out

    # ------------------------------------------------------------------ approvals
    def approve_removal(self, device_id: Any, pin_hash: str, count: int, expires_wall: float) -> None:
        did = _did(device_id)
        if did is None:
            return
        with self._lock:
            self._approvals[did] = (str(pin_hash), int(count), float(expires_wall))

    def consume_approval(self, device_id: Any, pins: Iterable[Any]) -> bool:
        """True (and the approval is spent) only for EXACTLY the approved pin set, in time."""
        did = _did(device_id)
        if did is None:
            return False
        pin_list = list(pins)
        with self._lock:
            appr = self._approvals.get(did)
            if appr is None:
                return False
            h, n, exp = appr
            if time.time() > exp:
                self._approvals.pop(did, None)
                return False
            if len({str(p).strip() for p in pin_list}) != n or canonical_hash(pin_list) != h:
                return False
            self._approvals.pop(did, None)
            self.approvals_used.append((did, h))
            return True

    def approval_pending(self, device_id: Any) -> bool:
        did = _did(device_id)
        with self._lock:
            appr = self._approvals.get(did) if did is not None else None
            return appr is not None and time.time() <= appr[2]

    def withdraw_approval(self, device_id: Any) -> None:
        did = _did(device_id)
        with self._lock:
            if did is not None:
                self._approvals.pop(did, None)

    def reset_for_tests(self) -> None:
        self.__init__()


def _did(value: Any) -> Optional[int]:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


registry = _Registry()
