"""A stateful fake MB2000 (zkemkeeper COM object) for the P3a-2 push-engine tests.

Not a test module (no ``test_`` prefix): imported by several test files. It keeps
the terminal's user table and finger slots so a test can ask what is ON the device
after a push, a crash, a sweep or a removal -- not only which calls were made.

Semantics it models, each from this repo's evidence:
- ``SetStrCardNumber`` then ``SSR_SetUserInfo`` writes/overwrites (auto-creates) the
  user with that card (zkemkeeper_guide.md §4, the push order).
- ``SSR_DelUserTmpExt`` returns True when the slot was occupied and False when it was
  already empty (zkemkeeper_guide.md §3, field-measured 2026-09-05/06).
- ``SSR_DeleteEnrollData(1, pin, 12)`` deletes the whole user (§3, backup 12).
- ``per_call_sleep`` makes every write call take that long (door-wait measurements).
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Set, Tuple

from tests.test_zk_standalone_driver import FakeZkem


class TerminalZkem(FakeZkem):
    def __init__(self, *, per_call_sleep: float = 0.0):
        super().__init__()
        self.users: Dict[str, Dict[str, Any]] = {}
        self.fingers: Set[Tuple[str, int]] = set()
        self._pending_card = ""
        self.per_call_sleep = float(per_call_sleep)
        self.call_times: List[Tuple[str, float, tuple]] = []
        self.status: Dict[int, int] = {}       # GetDeviceStatus idx -> value
        self.fp_version = ""                    # ~ZKFPVersion ("" = unreadable)
        self.lock = threading.Lock()

    # ---- helpers for tests -------------------------------------------------
    def add_user(self, pin, name, card, fingers=()):
        self.users[str(pin)] = {"pin": str(pin), "name": str(name), "card": str(card),
                                "enabled": True}
        for f in fingers:
            self.fingers.add((str(pin), int(f)))

    def fingers_of(self, pin) -> Set[int]:
        return {f for p, f in self.fingers if p == str(pin)}

    def _slow(self, name, *args):
        self.call_times.append((name, time.monotonic(), args))
        if self.per_call_sleep:
            time.sleep(self.per_call_sleep)

    # ---- roster push -------------------------------------------------------
    def SetStrCardNumber(self, card):
        self._slow("SetStrCardNumber", card)
        self._rec("SetStrCardNumber", card)
        self._pending_card = str(card or "")
        return True

    def SSR_SetUserInfo(self, machine, pin, name, pw, priv, enabled):
        self._slow("SSR_SetUserInfo", pin)
        self._rec("SSR_SetUserInfo", machine, pin, name, pw, priv, enabled)
        if not self.setuserinfo_ok:
            return False
        self.users[str(pin)] = {"pin": str(pin), "name": str(name),
                                "card": self._pending_card, "enabled": bool(enabled)}
        return True

    def SSR_DelUserTmpExt(self, machine, pin, finger_id):
        self._slow("SSR_DelUserTmpExt", pin, finger_id)
        self._rec("SSR_DelUserTmpExt", machine, pin, finger_id)
        self.deleted.append((str(pin), int(finger_id)))
        key = (str(pin), int(finger_id))
        if key in self.fingers:
            self.fingers.discard(key)
            return True
        return False

    def SetUserTmpExStr(self, machine, pin, finger, flag, tmp):
        self._slow("SetUserTmpExStr", pin, finger)
        self._rec("SetUserTmpExStr", machine, pin, finger, flag, tmp)
        if not self.settmp_ok:
            return False
        self.fingers.add((str(pin), int(finger)))
        return True

    def SSR_DeleteEnrollData(self, machine, pin, backup):
        self._slow("SSR_DeleteEnrollData", pin, backup)
        self._rec("SSR_DeleteEnrollData", machine, pin, backup)
        self.deleted.append((str(pin), int(backup)))
        if int(backup) == 12:
            self.users.pop(str(pin), None)
            self.fingers = {(p, f) for p, f in self.fingers if p != str(pin)}
        return True

    def ACUnlock(self, machine, delay):
        self.call_times.append(("ACUnlock", time.monotonic(), (delay,)))
        return super().ACUnlock(machine, delay)

    # ---- enumeration reads the live table ----------------------------------
    def ReadAllUserID(self, machine):
        self.device_users = [dict(u) for u in self.users.values()]
        return super().ReadAllUserID(machine)

    # ---- diagnostics -------------------------------------------------------
    # The driver tries a ByRef VARIANT first, then the returned-tuple shape. Both are
    # honoured: the VARIANT gets its .value, the tuple carries it.
    def GetDeviceStatus(self, machine, idx, box):
        self._rec("GetDeviceStatus", int(idx))
        if int(idx) in self.status:
            v = int(self.status[int(idx)])
            if hasattr(box, "value"):
                try:
                    box.value = v
                    return True
                except Exception:
                    pass
            return (True, v)
        return False if hasattr(box, "value") else (False, 0)

    def GetSysOption(self, machine, name, out):
        self._rec("GetSysOption", name)
        if name == "~ZKFPVersion" and self.fp_version:
            if hasattr(out, "value"):
                try:
                    out.value = self.fp_version
                    return True
                except Exception:
                    pass
            return (True, self.fp_version)
        return False if hasattr(out, "value") else (False, "")
