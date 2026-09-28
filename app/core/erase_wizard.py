"""The "Erase content" wizard: erase chosen tables of ONE turnstile (owner design, 2026-09-27).

Guide §3.2h. The manual wipe the pin-scheme cutover needs (§3.2c, §3.2e), as an Access feature
instead of a script. Two SDK families, two table sets (branching on the PROTOCOL, never on the
model -- guide §2):

* ZK_PULLSDK (C3-400): ``user``, ``userauthorize``, ``templatev10``, ``template``, each erased by
  ``DeleteDeviceData(h, table, "", "")`` (``PullSDKDevice.erase_table``). Never a parameter,
  timezone or holiday table: they are not in the list.
* ZK_STANDALONE (MB2000): ``users`` -- every NON-ADMIN user row with its card, password and
  fingers, by ``SSR_DeleteEnrollData(1, pin, 12)`` (``delete_users``, backup number 12, field-proven
  2026-09-06, zkemkeeper guide §3); ``fingerprints`` -- the templates of non-admin users only, by
  ``SSR_DelUserTmpExt`` per slot (``sweep_finger_slots``). Never the finger-index
  ``SSR_DeleteEnrollData`` that hangs this firmware. Administrators (privilege > 0) are kept, as
  script 13 keeps them.
* Door logs (the C3 ``transaction`` table, the MB2000 attendance log) are SHOWN with their count and
  cannot be chosen: the rule is "send every event not yet uploaded, then erase", and this PC cannot
  prove which panel rows it already sent -- the server de-duplicates on (device, eventId) and a panel
  row's id differs from the live-captured one, so re-sending would duplicate every event, and no real
  C3 transaction row or MB2000 attendance-log call has been read in this repo [UNVERIFIED]. Nor is
  there a documented MB2000 log clear (``ClearGLog`` is only in script 13, marked unverified).

Order of one run (each step logged, and written to the run's ``run.json``):
  hold (phase ERASE_PREP; nothing is written to the turnstile from here: device_hold) -> idle (no
  pass running) -> counts before -> BACKUP of the chosen tables to a file, re-read and hash-checked
  (a failure stops everything: nothing erased, hold released) -> [MB2000: no kept admin pin in the
  refill roster] -> the erase RECORDED (hold phase ERASE, every recorded pin's last push result
  unknown; one durable write, or no erase) -> erase -> counts after -> VERIFY -> records (forget /
  keep) -> refill. An erase that started and did not end verified (INCOMPLETE, a crash) keeps the
  hold, forgets nothing and makes every recorded pin "not in sync", so the refill writes everything
  again (review round 1). The lease and the handover freeze are checked again on the worker thread
  just before every erase command, and before the records. Before any of it (lane 1b): every other
  Access PC of the gym confirmed closed, and a refill that can put the members back.

Every device call goes through the ULTRA worker's own connection (``request_run_sdk``) -- never a
second session -- one command at a time, and the worker serves the door and the scans BETWEEN
commands only: a whole-table C3 read or delete, or an MB2000 listing, blocks the door for its
whole duration (guide §3.2h "What the wizard does to the door").
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.core import device_hold
from app.core import telemetry as _tel
from app.core.v2 import lease_gate

_log = logging.getLogger("zkapp.erase")

PROTO_PULLSDK = "ZK_PULLSDK"
PROTO_STANDALONE = "ZK_STANDALONE"

# C3 (PullSDK): the tables shown, in display order, and the ones that may be erased.
C3_TABLES = ("user", "userauthorize", "templatev10", "template", "transaction")
C3_ERASE_ORDER = ("templatev10", "template", "userauthorize", "user")
# MB2000 (zkemkeeper): its "tables" are the GetDeviceStatus counters.
MB_TABLES = ("users", "fingerprints", "attendance")
DOOR_LOG_TABLES = frozenset({"transaction", "attendance"})
USERS_TABLE = {PROTO_PULLSDK: "user", PROTO_STANDALONE: "users"}
FINGER_TABLES = frozenset({"templatev10", "template", "fingerprints"})

REFILL_NOW, REFILL_AUTO, REFILL_HOLD = "now", "auto", "hold"
REFILL_OPTIONS = (REFILL_NOW, REFILL_AUTO, REFILL_HOLD)

PREVIEW_TTL_SEC = 900.0
IDLE_WAIT_SEC = 120.0
# Device command budgets (request_run_sdk: the caller waits this long, then as long again once
# the worker has taken the command, guide §3.1a). Chosen, not measured on hardware.
T_COUNT = 30.0
T_READ = 120.0
T_ERASE = 120.0
# The DRIVER's own timeout of each MB2000 command, below its budget above so the driver's
# timeout fires first (a request_run_sdk timeout abandons the STA thread). Chosen, not measured.
TD_STATUS = 20.0
TD_LIST = 60.0
TD_TEMPLATES = 90.0
TD_DELETE = 90.0
TD_SWEEP = 30.0
MB_TEMPLATE_PINS_PER_CALL = 2      # 20 SSR_GetUserTmpStr per STA command
MB_DELETE_PINS_PER_CALL = 20       # 20 SSR_DeleteEnrollData(…, 12) per STA command
MB_SWEEP_SLOTS_PER_CALL = 3        # as the daily finger sweep (§3.4c)


class StepError(Exception):
    """A step failed. ``uncertain``: a device command was taken and gave no answer, so it may
    have acted (``sent, no answer``) -- never treated as "nothing happened"."""

    def __init__(self, code: str, message: str, *, uncertain: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.uncertain = uncertain


def _default_backup_root() -> Path:
    from app.core.utils import ACCESS_DATA_DIR
    return Path(ACCESS_DATA_DIR) / "erase_backups"


def _now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _corrected_epoch() -> Tuple[float, bool]:
    """(epoch, corrected): the server-corrected time when this process has a measurement of the
    server's clock (``server_clock.corrected_now``, the removal log's time), else the PC's. The
    run folders are dated with it, so the 30-day prune does not rest on the PC clock alone where
    a measurement exists (lane 1c, review F2)."""
    try:
        from app.core.v2.server_clock import corrected_now
        at, corrected = corrected_now()
        return float(at), bool(corrected)
    except Exception:
        return time.time(), False


def _chunks(items: List[Any], n: int) -> List[List[Any]]:
    return [items[i:i + n] for i in range(0, len(items), max(1, n))]


def _protocol_of(device: Dict[str, Any]) -> Optional[str]:
    from app.sdk.device_driver import DeviceProtocol, resolve_device_protocol
    try:
        proto = resolve_device_protocol(device)
    except Exception:
        return None
    if proto == DeviceProtocol.ZK_PULLSDK:
        return PROTO_PULLSDK
    if proto == DeviceProtocol.ZK_STANDALONE:
        return PROTO_STANDALONE
    return None


def _device_identity(device: Dict[str, Any], proto: Optional[str]) -> Dict[str, Any]:
    return {
        "id": device.get("id"),
        "name": str(device.get("name") or "").strip(),
        "ip": str(device.get("ipAddress") or device.get("ip_address") or "").strip(),
        "port": str(device.get("portNumber") or device.get("port_number") or "").strip(),
        "protocol": proto,
    }


PIN_SCHEME_ACCOUNT = "ACCOUNT"

# The member list's age limit (owner decision 2026-09-27, lane 1c): stale when the last SUCCESSFUL
# getSyncData is older than max(3 x the effective sync interval, 10 min).
SYNC_MAX_AGE_INTERVALS = 3
SYNC_MAX_AGE_FLOOR_SEC = 600

# A run folder holding this file is never pruned (lane 1c, review C0): its erase removed people the
# refill does not put back (not in its roster), and the backup is their only copy.
KEEP_MARK = "keep_not_refilled.txt"


def _pin_key(pin: str) -> Tuple[int, int, str]:
    return (0, int(pin), "") if pin.isdigit() else (1, 0, pin)


def terminal_people(proto: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The people on a terminal, from its user listing: ``{pin, name, admin}``, one per pin. C3:
    the ``user`` table's rows (``Pin`` / ``Name``, as device_sync reads them), no administrator
    notion -- a users erase clears the whole table. MB2000: the listing, an administrator being
    an integer privilege > 0 (the erase keeps them); a privilege that did not read counts as a
    member, so it is counted, never hidden."""
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        if proto == PROTO_PULLSDK:
            pin = str(r.get("Pin") or r.get("pin") or "").strip()
            name = r.get("Name") if r.get("Name") is not None else r.get("name")
            admin = False
        else:
            pin = str(r.get("pin") or "").strip()
            name = r.get("name")
            priv = r.get("privilege")
            admin = isinstance(priv, int) and not isinstance(priv, bool) and priv > 0
        if pin and pin not in out:
            out[pin] = {"pin": pin, "name": None if name is None else str(name), "admin": admin}
    return [out[p] for p in sorted(out, key=_pin_key)]


def not_refilled(people: List[Dict[str, Any]], roster_pins: Any) -> List[Dict[str, Any]]:
    """The people an erase removes that the refill does NOT write back (lane 1c, review C0):
    every non-administrator whose pin is not in the refill roster under the scheme recorded now
    -- staff or cleaners enrolled on the terminal, another system's users, a member no longer in
    this PC's roster. A pin is a person under the scheme it was written with, which is the
    scheme recorded now until the cutover's switch; a turnstile switched BEFORE its erase lists
    everyone (every old pin differs from the new ones): conservative, and visible."""
    roster = {str(p) for p in (roster_pins or ())}
    return [{"pin": p["pin"], "name": p["name"]} for p in people
            if not p["admin"] and p["pin"] not in roster]


def refill_roster(device: Dict[str, Any], cache: Any, *,
                  scheme: Optional[str] = None) -> Dict[str, Any]:
    """What a refill pass would write to this turnstile (lane 1b, review C1).

    The SAME source and filter both refill passes use: the sync cache's member rows through
    ``DeviceSyncEngine._filter_users_for_device`` (the MB2000 full sync's
    ``_build_standalone_roster`` and the PullSDK pass's ``_sync_one_device``), on a COPY of the
    device row (the filter writes ``doorIds`` into it) and quietly (no withheld WARNING, no
    ``PIN_SCHEME_ACCOUNT_WITHHELD`` event: this only measures). ``scheme`` forces a pin scheme --
    what the refill would write after a switch. Before the pass's own exclusions (members an
    explicit revocation or the recently-removed guard leaves out), so it can only be higher.
    {scheme, members, withheld, pins}."""
    from app.core.device_sync import DeviceSyncEngine

    dev = dict(device or {})
    if scheme is not None:
        dev.pop("pin_scheme", None)
        dev["pinScheme"] = scheme
    stats: Dict[str, Any] = {}
    engine = DeviceSyncEngine(cfg=SimpleNamespace(), logger=_log)
    by_pin = engine._filter_users_for_device(
        users=list(getattr(cache, "users", None) or []), device=dev, default_door_id=1,
        stats_out=stats, quiet=True,
    )
    return {"scheme": stats.get("pin_scheme"), "members": len(by_pin),
            "withheld": int(stats.get("withheld_missing_account") or 0),
            "pins": frozenset(str(p) for p in by_pin)}


# The verifier's text when this PC has no gym token, or when the server refused it
# (local_access_api_v2._erase_password_verifier).
NOT_SIGNED_IN = "this PC is not signed in to MonClub"
# The verifier's text when the TLS handshake failed on the certificate's dates (``tls_kind`` "clock").
TLS_CLOCK_TEXT = "the secure connection to MonClub was refused: the certificate is not yet valid or expired"


def _password_refusal(status: int, error: str) -> Tuple[int, Dict[str, Any]]:
    """The refusal of a password check, with a code the page translates. A 401 is a wrong password
    (``validate_statistics_password`` answers False on the backend's own "Wrong password" 401; a
    gym login its JWT filter refuses -- a 401 whose JSON ``code`` is ``UNAUTHORIZED`` -- raises
    ``MonClubTokenRejectedError`` since lane 1e, which the verifier sends as ``NOT_SIGNED_IN``); a
    503 is "could not be asked" (offline) or, with the verifier's ``NOT_SIGNED_IN`` text, a PC with
    no gym token or a refused one; a 400 is no password; the verifier's ``TLS_CLOCK_TEXT`` is a
    certificate not yet valid or expired (this PC's clock, lane 1e); any other status is the server
    failing the check (a proxy's 502/504, a 5xx) -- never "wrong password" (lane 1b review rounds
    1-2)."""
    code = {401: "ADMIN_PASSWORD", 400: "ADMIN_PASSWORD_REQUIRED",
            503: "ADMIN_PASSWORD_UNCHECKABLE"}.get(int(status or 0), "ADMIN_PASSWORD_CHECK_FAILED")
    if code == "ADMIN_PASSWORD_UNCHECKABLE" and str(error or "").startswith(NOT_SIGNED_IN):
        code = "PC_NOT_SIGNED_IN"                  # not "no internet": the PC has no gym token
    if str(error or "").startswith(TLS_CLOCK_TEXT):
        code = "TLS_CLOCK"                         # not "try again": this PC's date and time
    return int(status or 503), {"ok": False, "code": code, "error": error}


# OpenSSL's X509_V_ERR_CERT_NOT_YET_VALID and X509_V_ERR_CERT_HAS_EXPIRED: what a PC clock that is
# wrong by more than the certificate's margin gives -- and also a server certificate that really
# expired, which this PC cannot tell apart.
_CLOCK_VERIFY_CODES = frozenset({9, 10})
_CLOCK_TEXTS = ("certificate is not yet valid", "certificate has expired")
_EOF_TEXTS = ("eof occurred in violation of protocol", "unexpected_eof_while_reading")


def _exception_chain(exc: BaseException, limit: int = 16) -> List[BaseException]:
    """``exc`` and what it wraps: ``__cause__``, ``__context__``, urllib3's ``MaxRetryError.reason``
    and exception ``args`` -- ``requests`` raises its SSLError around urllib3's MaxRetryError around
    urllib3's SSLError around the ``ssl`` exception, and ``MonClubApi`` wraps that ``from`` it."""
    out: List[BaseException] = []
    seen: set = set()
    todo: List[Any] = [exc]
    while todo and len(out) < limit:
        err = todo.pop(0)
        if not isinstance(err, BaseException) or id(err) in seen:
            continue
        seen.add(id(err))
        out.append(err)
        todo.extend([getattr(err, "__cause__", None), getattr(err, "__context__", None),
                     getattr(err, "reason", None)])
        todo.extend(a for a in getattr(err, "args", ()) if isinstance(a, BaseException))
    return out


def tls_kind(exc: BaseException) -> Optional[str]:
    """What kind of TLS failure ``exc`` is, read through the whole chain (``_exception_chain``);
    None when it is not one (lane 1e, master review nits):

    * ``"eof"`` -- the connection was cut during the handshake (``ssl.SSLEOFError``, "EOF occurred
      in violation of protocol"): a network drop, so "check the internet" (``_no_answer``);
    * ``"clock"`` -- the certificate is not yet valid or has expired (verify codes 9 / 10): this
      PC's date and time, or a server certificate that expired -- "check the clock", never "try
      again in a moment";
    * ``"other"`` -- any other TLS failure: something answered with a certificate that does not
      check out -- the server's check failed, not "no internet" (lane 1d)."""
    import ssl
    kinds: List[type] = [ssl.SSLError]
    for mod, name in (("requests.exceptions", "SSLError"), ("urllib3.exceptions", "SSLError")):
        try:
            kinds.append(getattr(__import__(mod, fromlist=[name]), name))
        except Exception:
            pass
    chain = _exception_chain(exc)
    if not any(isinstance(err, tuple(kinds)) for err in chain):
        return None
    if any(isinstance(err, ssl.SSLCertVerificationError)
           and getattr(err, "verify_code", None) in _CLOCK_VERIFY_CODES for err in chain):
        return "clock"
    if any(isinstance(err, ssl.SSLEOFError) for err in chain):
        return "eof"
    text = " ".join(str(err) for err in chain).lower()
    if any(t in text for t in _CLOCK_TEXTS):
        return "clock"
    if any(t in text for t in _EOF_TEXTS):
        return "eof"
    return "other"


def is_tls_failure(exc: BaseException) -> bool:
    """The exception, or anything it wraps, is a TLS failure (``tls_kind``): ``ssl``'s own SSLError
    (an OSError), ``requests``' or urllib3's SSLError (lane 1d, review nits; the whole chain since
    lane 1e)."""
    return tls_kind(exc) is not None


def _no_answer(exc: BaseException) -> bool:
    """A request that got no answer at all -- the exception or its cause is a connection that
    failed or timed out: ``requests``' ConnectionError / Timeout, or a socket error. Any other
    ``requests`` error (they all derive from OSError: a body that is not JSON, a redirect loop)
    DID get an answer. A TLS failure (``requests``' SSLError, a ConnectionError, or ``ssl``'s own,
    an OSError) is not "no answer" either: something answered with a certificate that does not
    check out -- "check the internet" would send the technician the wrong way (lane 1d, review
    nit, ``is_tls_failure``) -- EXCEPT a handshake the network cut (``tls_kind`` "eof", lane 1e),
    which is no answer. A proxy that does not answer (ProxyError) stays no answer."""
    kind = tls_kind(exc)
    if kind == "eof":
        return True
    if kind is not None:
        return False
    try:
        from requests.exceptions import ConnectionError as _ConnErr, RequestException, Timeout
    except Exception:
        _ConnErr = RequestException = Timeout = None         # type: ignore[assignment]
    for err in (exc, getattr(exc, "__cause__", None)):
        if err is None:
            continue
        if RequestException is not None and isinstance(err, RequestException):
            return isinstance(err, (_ConnErr, Timeout))
        if isinstance(err, OSError):
            return True
    return False


def check_erase_switch(app: Any) -> Tuple[bool, Optional[str], str]:
    """Is the Erase wizard switched on for this gym, on the server? (owner decision 2026-09-27,
    guide §3.2h). ``(enabled, code, why)``: ONLY a 200 whose JSON ``enabled`` is the boolean
    ``true`` enables. ``false`` is ``ERASE_NOT_ENABLED``. The refusals say why (lane 1c, review
    F4): a 404 or 405 is ``ERASE_SWITCH_MISSING`` -- a backend without the route, which retrying
    cannot change; no answer at all (a failed connection, a timeout, a handshake the network cut)
    is ``ERASE_SWITCH_UNREACHABLE``; a certificate not yet valid or expired is ``TLS_CLOCK`` (this
    PC's date and time, lane 1e); anything else -- no token, 401/403, 5xx, another TLS failure, a
    body that is not JSON or not that boolean (the string ``"true"`` included) -- is
    ``ERASE_SWITCH_UNCHECKED``. Never raises."""
    try:
        from access.store import load_auth_token
        auth = load_auth_token()
        if not auth or not getattr(auth, "token", None):
            return False, "ERASE_SWITCH_UNCHECKED", "no gym token on this PC"
        body = app._api().get_erase_wizard_switch(token=auth.token, timeout=15)
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        if status in (404, 405):
            return False, "ERASE_SWITCH_MISSING", str(exc)[:200]
        if status is None and tls_kind(exc) == "clock":
            # A certificate not yet valid or expired: this PC's date and time (lane 1e).
            return False, "TLS_CLOCK", str(exc)[:200]
        if status is None and _no_answer(exc):
            return False, "ERASE_SWITCH_UNREACHABLE", str(exc)[:200]
        return False, "ERASE_SWITCH_UNCHECKED", str(exc)[:200]
    enabled = body.get("enabled") if isinstance(body, dict) else None
    if enabled is True:
        return True, None, ""
    if enabled is False:
        return False, "ERASE_NOT_ENABLED", "the erase is not enabled for this gym"
    return False, "ERASE_SWITCH_UNCHECKED", "the server's answer carries no boolean 'enabled'"


def held_waiting_count(device_id: Any) -> Optional[int]:
    """For the heartbeat of a HELD turnstile (lane 1b, review F0/F7/F14/F26): how many members
    its refill would write -- all of them wait while it is held. In memory only (the heartbeat's
    rule): the sync cache already loaded, never a load. None when it cannot be told."""
    try:
        from app.core.db import _coerce_device_row_to_payload, peek_sync_cache

        cache = peek_sync_cache()
        if cache is None:
            return None
        did = int(device_id)
        row = next((d for d in (getattr(cache, "devices", None) or [])
                    if isinstance(d, dict) and str(d.get("id")) == str(did)), None)
        if row is None:
            return None
        # The cache holds the DB row (snake_case: ``allowed_memberships``, ``pin_scheme``); the
        # passes filter the payload shape (``allowedMemberships``) -- the same coercion they get.
        return int(refill_roster(_coerce_device_row_to_payload(row), cache)["members"])
    except Exception:
        return None


class EraseWizard:
    """One per app (``get_wizard``). One run at a time, on its own thread."""

    def __init__(self, app: Any, *, backup_root: Optional[Path] = None,
                 spawn: Optional[Callable[[Callable[[], None]], None]] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 mono: Callable[[], float] = time.monotonic) -> None:
        self.app = app
        self._backup_root = backup_root
        self._spawn = spawn or (lambda fn: threading.Thread(
            target=fn, name="erase-wizard", daemon=True).start())
        self._sleep = sleep
        self._mono = mono
        self._lock = threading.Lock()
        self._previews: Dict[str, Dict[str, Any]] = {}
        self._run: Optional[Dict[str, Any]] = None       # the current or last run record
        self._running = False
        # The refill roster's pins as step 1 saw them, for the current run (lane 1c): a member who
        # leaves the roster since is not "someone the operator was not shown" (_bind_not_refilled).
        # Kept here, not in the run record: it can hold ~1,800 pins, and the page polls the record.
        self._run_step1_roster: frozenset = frozenset()
        self._run_step1_scheme: Optional[str] = None     # the scheme that roster was read under
        # Turnstiles whose Refill is between its checks and its release: no erase may start on
        # them (review round 2, R2-1 -- the password round trip is a network call).
        self._refilling: set = set()

    # ------------------------------------------------------------------ plumbing
    def backup_root(self) -> Path:
        return Path(self._backup_root) if self._backup_root is not None else _default_backup_root()

    def _device(self, device_id: int) -> Optional[Dict[str, Any]]:
        from app.core.db import get_sync_device_payload
        try:
            return get_sync_device_payload(int(device_id))
        except Exception:
            _log.warning("[ERASE] device %s payload unreadable", device_id, exc_info=True)
            return None

    def _worker(self, device_id: int) -> Any:
        eng = getattr(self.app, "_ultra_engine", None)
        if eng is None or not getattr(eng, "running", False):
            return None
        return (getattr(eng, "_workers", None) or {}).get(int(device_id))

    def _refusal(self, device_id: int, *, need_writes: bool) -> Optional[Tuple[int, Dict[str, Any]]]:
        """The lease and worker conditions every call needs. None = go on."""
        if not lease_gate.device_allowed(device_id):
            return 409, {"ok": False, "code": "NOT_DRIVER", "notDriver": True,
                         "error": "this PC does not drive this turnstile"}
        if need_writes:
            if lease_gate.writes_frozen(device_id):
                return 409, {"ok": False, "code": "HANDOVER_IN_PROGRESS",
                             "error": "this turnstile is being handed over to another PC"}
            blocked = lease_gate.removals_blocked(device_id)
            if blocked:
                return 409, {"ok": False, "code": "ADD_ONLY",
                             "error": f"removals are not allowed on this turnstile ({blocked})"}
        worker = self._worker(device_id)
        if worker is None:
            return 409, {"ok": False, "code": "NO_WORKER",
                         "error": "no running ULTRA worker drives this turnstile on this PC"}
        if not getattr(worker, "_connected", False):
            return 503, {"ok": False, "code": "NOT_CONNECTED", "error": "turnstile not connected"}
        return None

    @staticmethod
    def _norm_addr(ip: Any, port: Any) -> Tuple[str, str]:
        text = str(port if port is not None else "").strip()
        try:
            text = str(int(text)) if text else "4370"         # both drivers default to 4370
        except ValueError:
            pass
        return str(ip or "").strip(), text

    def _address_refusal(self, worker: Any, ident: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        """The worker must be connected to the address MonClub records for this turnstile. After
        an IP edit the worker keeps its socket to the OLD address until it reconnects (up to the
        30-min refresh): erasing through it would erase the turnstile at that address -- maybe
        another one (review round 2)."""
        addr = getattr(worker, "_connected_addr", None)
        if not addr:
            return ("ADDRESS_UNKNOWN",
                    "the turnstile's worker does not report the address it is connected to")
        have = self._norm_addr(addr[0], addr[1] if len(addr) > 1 else None)
        want = self._norm_addr(ident.get("ip"), ident.get("port"))
        if have != want:
            return ("ADDRESS_CHANGED",
                    f"the worker is connected to {have[0]}:{have[1]} but MonClub records "
                    f"{want[0]}:{want[1]} -- the old connection is still open: wait for the "
                    "worker to reconnect, or restart Access")
        return None

    @staticmethod
    def _write_refusal(device_id: int) -> Optional[Tuple[str, str]]:
        """The lease conditions a WRITE needs, read again at the moment of the write."""
        if not lease_gate.device_allowed(device_id):
            return "NOT_DRIVER", "this PC no longer drives this turnstile"
        if lease_gate.writes_frozen(device_id):
            return "HANDOVER_IN_PROGRESS", "this turnstile is being handed over to another PC"
        blocked = lease_gate.removals_blocked(device_id)
        if blocked:
            return "ADD_ONLY", f"removals are not allowed on this turnstile ({blocked})"
        return None

    def _write_call(self, worker: Any, did: int, fn: Callable[[Any], Any], *, label: str,
                    timeout: float) -> Any:
        """A device WRITE: the lease -- and the worker's connected address -- are checked here and
        again on the worker thread, just before ``fn`` runs: the command waits in the worker's
        queue, and the lease can move or the worker reconnect meanwhile."""
        with self._lock:
            ident = dict(((self._run or {}).get("device")) or {})
        refused = self._write_refusal(did) or self._address_refusal(worker, ident)
        if refused:
            raise StepError(*refused)
        seen: Dict[str, Tuple[str, str]] = {}

        def _guarded(drv):
            why = self._write_refusal(did) or self._address_refusal(worker, ident)
            if why:
                seen["refused"] = why
                return None
            return fn(drv)

        out = self._call(worker, _guarded, label=label, timeout=timeout)
        if "refused" in seen:
            raise StepError(*seen["refused"])
        return out

    def running_device(self) -> Optional[int]:
        """The turnstile a run is working on now (a handover's final upload waits for it)."""
        with self._lock:
            if self._running and self._run:
                return int(self._run.get("deviceId") or 0) or None
            return None

    @staticmethod
    def _call(worker: Any, fn: Callable[[Any], Any], *, label: str, timeout: float) -> Any:
        res = worker.request_run_sdk(fn, label=f"erase_{label}", timeout=timeout) or {}
        if res.get("ok"):
            return res.get("result")
        err = str(res.get("error") or "device command failed")
        if err == "sent, no answer":
            raise StepError("NO_ANSWER", f"{label}: sent, no answer", uncertain=True)
        if err in ("timeout", "device not connected", "expired (not executed)"):
            raise StepError("NOT_SENT", f"{label}: {err}")
        raise StepError("DEVICE_ERROR", f"{label}: {err}")

    # ------------------------------------------------------------------ counts
    def _counts(self, worker: Any, proto: str) -> Dict[str, Any]:
        """{"tables": {key: count | None}, "extra": {...}}. None = the table did not answer."""
        if proto == PROTO_PULLSDK:
            def _fn(drv):
                out: Dict[str, Optional[int]] = {}
                for t in C3_TABLES:
                    try:
                        out[t] = int(drv.count_table_strict(table=t))
                    except Exception:
                        out[t] = None
                return out
            return {"tables": self._call(worker, _fn, label="count", timeout=T_COUNT), "extra": {}}

        def _fn_mb(drv):
            return drv.read_device_status(timeout_sec=TD_STATUS)
        res = self._call(worker, _fn_mb, label="status", timeout=T_COUNT) or {}
        if not res.get("ok"):
            raise StepError("STATUS_UNREADABLE",
                            f"terminal counters unreadable: {res.get('error') or 'no answer'}")
        st = dict(res.get("status") or {})
        return {
            "tables": {"users": st.get("users"), "fingerprints": st.get("fingerprints"),
                       "attendance": st.get("attendance_records")},
            "extra": {"admins": st.get("admins"), "faces": st.get("faces"),
                      "passwords": st.get("passwords")},
        }

    def _read_people(self, worker: Any, proto: str) -> Optional[List[Dict[str, Any]]]:
        """The terminal's users (``terminal_people``), one device command: C3, the ``user``
        table's rows (the whole table, as the backup reads it); MB2000, the user listing. None
        when it does not read -- then who the refill leaves out cannot be told."""
        try:
            if proto == PROTO_PULLSDK:
                rows = self._call(worker, lambda drv: drv.read_table_strict(table="user"),
                                  label="read_user_list", timeout=T_READ)
            else:
                res = self._call(worker, lambda drv: drv.list_device_users(timeout_sec=TD_LIST),
                                 label="list_users_step1", timeout=T_READ) or {}
                if not res.get("ok"):
                    return None
                rows = res.get("users")
        except StepError as exc:
            _log.warning("[ERASE] the terminal's user list did not read: %s", exc.message)
            return None
        except Exception:
            # Any other failure (a worker gone mid-call) is "unread" too, never a raw error: the
            # start then refuses NOT_REFILLED_UNKNOWN (lane 1d, review nit).
            _log.warning("[ERASE] the terminal's user list did not read", exc_info=True)
            return None
        return terminal_people(proto, list(rows or []))

    @staticmethod
    def _table_rows(proto: str, counts: Dict[str, Any]) -> List[Dict[str, Any]]:
        keys = C3_TABLES if proto == PROTO_PULLSDK else MB_TABLES
        rows = []
        for key in keys:
            n = (counts.get("tables") or {}).get(key)
            row: Dict[str, Any] = {"key": key, "count": n, "erasable": True}
            if key in DOOR_LOG_TABLES:
                row.update(erasable=False, reason="DOOR_LOG_NOT_SUPPORTED")
            elif n is None:
                row.update(erasable=False, reason="UNREADABLE")
            rows.append(row)
        return rows

    # ------------------------------------------------------------------ preview
    def preview(self, device_id: int) -> Tuple[int, Dict[str, Any]]:
        did = int(device_id)
        device = self._device(did)
        if not device:
            return 404, {"ok": False, "code": "NO_DEVICE", "error": "unknown turnstile"}
        proto = _protocol_of(device)
        if proto is None:
            return 409, {"ok": False, "code": "UNSUPPORTED_PROTOCOL", "unsupported": True,
                         "error": "this turnstile's SDK family is not supported by the wizard"}
        refused = self._refusal(did, need_writes=False)
        if refused:
            return refused
        # The worker looked up once (lane 1d, review nit): one that leaves the engine after the
        # check above is never dereferenced as None -- its commands fail as device errors instead.
        worker = self._worker(did)
        if worker is None:
            return 409, {"ok": False, "code": "NO_WORKER",
                         "error": "no running ULTRA worker drives this turnstile on this PC"}
        ident = _device_identity(device, proto)
        moved = self._address_refusal(worker, ident)
        if moved:
            return 409, {"ok": False, "code": moved[0], "error": moved[1]}
        try:
            counts = self._counts(worker, proto)
        except StepError as exc:
            return 503, {"ok": False, "code": exc.code, "error": exc.message}
        # Who the refill will not put back (lane 1c, review C0): the terminal's users against the
        # refill roster -- read here so steps 3 and 4 can name them before anything starts.
        people = self._read_people(worker, proto)
        check = self._refill_check(did, device)
        pins_now = (check.get("_pins") or {}).get("now")
        left_out = None if people is None or pins_now is None else not_refilled(people, pins_now)
        preview_id = uuid.uuid4().hex
        with self._lock:
            now = self._mono()
            for k in [k for k, v in self._previews.items() if now - v["at"] > PREVIEW_TTL_SEC]:
                self._previews.pop(k, None)
            self._previews[preview_id] = {
                "device": ident, "counts": counts, "at": now,
                "notRefilled": None if left_out is None else frozenset(p["pin"] for p in left_out),
                "rosterPins": frozenset(pins_now or ()), "rosterScheme": check.get("scheme")}
        return 200, {
            "ok": True, "previewId": preview_id, "device": ident,
            "pinScheme": self._pin_scheme(did),
            "tables": self._table_rows(proto, counts),
            "extra": counts.get("extra") or {},
            "hold": self._hold_of(did),
            "run": self.status().get("run"),
            "limits": {"doorLogs": "DOOR_LOG_NOT_SUPPORTED",
                       "mbPinsPerPass": self._pins_per_pass(proto)},
            # What the refill would write (step 3 and 4 show it; start() refuses on a problem).
            "refill": self._public_refill(check),
            # The people it would NOT write back, by pin and name (the page only: never logged,
            # never in run.json -- review F29); None when the user list did not read.
            "notRefilled": None if left_out is None else {
                "count": len(left_out), "scheme": check.get("scheme"), "people": left_out},
        }

    @staticmethod
    def _pins_per_pass(proto: str) -> Optional[int]:
        if proto != PROTO_STANDALONE:
            return None
        try:
            from app.core.ultra_engine import _FULL_SYNC_MAX_PINS_PER_PASS
            return int(_FULL_SYNC_MAX_PINS_PER_PASS)
        except Exception:
            return None

    @staticmethod
    def _pin_scheme(did: int) -> Optional[str]:
        """For display only: None when unreadable."""
        try:
            from app.core.db import get_device_pin_scheme
            return get_device_pin_scheme(did)
        except Exception:
            return None

    @staticmethod
    def _pin_scheme_strict(did: int) -> Optional[str]:
        """For a decision: a read error propagates (None = the device has no row)."""
        from app.core import db as _db
        return _db.get_device_pin_scheme(did)

    def _sync_max_age_sec(self) -> int:
        """max(3 x the effective sync interval, 10 min) (owner decision 2026-09-27). The interval
        is the app's own (``MainApp._sync_base_interval_sec``: the server's
        ``agentSyncBackendRefreshMin`` if any, else ``cfg.sync_interval_sec``) -- the one the
        sync timer uses. Unreadable: the 10-min floor, the strictest limit."""
        try:
            interval = int(self.app._sync_base_interval_sec())
        except Exception:
            interval = 0
        return max(SYNC_MAX_AGE_INTERVALS * max(0, interval), SYNC_MAX_AGE_FLOOR_SEC)

    def _sync_staleness(self) -> Dict[str, Any]:
        """Is this PC's member list recent enough to refill from? (lane 1c) ``staleWhy``:
        ``NO_SYNC_YET`` (no successful getSyncData recorded since Access started),
        ``LAST_SYNC_FAILED`` (the last one failed), ``TOO_OLD`` (the last success is older than
        ``_sync_max_age_sec`` -- a sync that hangs records no failure), else None. The age is
        read on the monotonic clock ``app.py`` stamps it with (``_last_sync_ok_mono``) -- never
        this wizard's injectable ``_mono``, never the PC's wall clock."""
        limit = self._sync_max_age_sec()
        stamp = getattr(self.app, "_last_sync_ok_mono", None)
        age: Optional[int] = None
        if isinstance(stamp, (int, float)) and not isinstance(stamp, bool):
            age = max(0, int(time.monotonic() - float(stamp)))
        if getattr(self.app, "_last_sync_ok", None) is not True:
            ran = getattr(self.app, "_last_sync_at", None) is not None or age is not None
            why: Optional[str] = "LAST_SYNC_FAILED" if ran else "NO_SYNC_YET"
        elif age is None:
            why = "NO_SYNC_YET"
        elif age > limit:
            why = "TOO_OLD"
        else:
            why = None
        return {"staleWhy": why, "lastSyncAgeSec": age, "syncMaxAgeSec": limit}

    def _refill_check(self, did: int, device: Optional[Dict[str, Any]] = None
                      ) -> Dict[str, Any]:
        """Can the refill really refill this turnstile? (lane 1b, review C1)

        Everything an erase removes comes back only from the refill pass, which writes the
        members of THIS PC's sync cache (``refill_roster``). A pass finds no cache: it is skipped
        and the emptied terminal stays empty; ACCOUNT rows without ``mainAccountId`` are withheld
        and never written, and the "N waiting" count cannot name them. So, before any erase:
        ``problem`` for the refill under the scheme recorded now, ``accountProblem`` for one
        under "Par personne" (ACCOUNT) after a switch -- the cutover's "hold, switch, Refill".
        ``lastSyncOk``: the app's last getSyncData succeeded (False until the first sync of this
        process) -- a cache a failed or missing sync left behind may miss members. ``staleWhy``
        (``_sync_staleness``): why the list is stale -- that flag, or the age of the last success
        past the owner's limit (lane 1c)."""
        out: Dict[str, Any] = {
            "scheme": None, "members": None, "withheld": None,
            "lastSyncOk": getattr(self.app, "_last_sync_ok", None) is True,
            "cacheUpdatedAt": None, "problem": None, "accountProblem": None,
        }
        out.update(self._sync_staleness())
        device = device if device is not None else self._device(did)
        try:
            from app.core import db as _db
            cache = _db.load_sync_cache()
        except Exception:
            _log.warning("[ERASE] sync cache unreadable for the refill check", exc_info=True)
            cache = None
        if cache is None or not device:
            out["problem"] = out["accountProblem"] = "REFILL_SOURCE_MISSING"
            return out
        out["cacheUpdatedAt"] = str(getattr(cache, "updated_at", "") or "") or None
        try:
            now = refill_roster(device, cache)
            acct = (now if now["scheme"] == PIN_SCHEME_ACCOUNT
                    else refill_roster(device, cache, scheme=PIN_SCHEME_ACCOUNT))
        except Exception:
            _log.warning("[ERASE] refill roster not computed", exc_info=True)
            out["problem"] = out["accountProblem"] = "REFILL_SOURCE_MISSING"
            return out
        out.update(scheme=now["scheme"], members=now["members"], withheld=now["withheld"])
        if now["scheme"] != PIN_SCHEME_ACCOUNT:
            out["ifAccount"] = {"members": acct["members"], "withheld": acct["withheld"]}
        out["_pins"] = {"now": now["pins"], "account": acct["pins"]}

        def _problem(roster: Dict[str, Any]) -> Optional[str]:
            if out["staleWhy"]:
                return "REFILL_SOURCE_STALE"
            if not roster["members"]:
                return "REFILL_SOURCE_EMPTY"
            if roster["withheld"]:
                return "REFILL_WITHHELD"
            return None

        out["problem"] = _problem(now)
        out["accountProblem"] = _problem(acct)
        return out

    @staticmethod
    def _public_refill(check: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in check.items() if not k.startswith("_")}

    @staticmethod
    def _refill_refusal(check: Dict[str, Any], refill: Optional[str]
                        ) -> Optional[Tuple[int, Dict[str, Any]]]:
        """The refusal of an erase whose refill could not put the members back. For "hold" the
        scheme at Refill is not known yet: both the scheme now and ACCOUNT must be refillable."""
        code, under = check.get("problem"), check.get("scheme")
        if not code and refill == REFILL_HOLD and check.get("accountProblem"):
            code, under = check["accountProblem"], PIN_SCHEME_ACCOUNT
        if not code:
            return None
        members = check.get("members") if under == check.get("scheme") else (
            (check.get("ifAccount") or {}).get("members"))
        withheld = check.get("withheld") if under == check.get("scheme") else (
            (check.get("ifAccount") or {}).get("withheld"))
        stale = {
            "TOO_OLD": f"the member list is not recent: the last successful sync with MonClub was "
                       f"{check.get('lastSyncAgeSec')} s ago, the limit is "
                       f"{check.get('syncMaxAgeSec')} s -- wait for the next sync",
            "LAST_SYNC_FAILED": "the last sync with MonClub did not succeed: the member list may "
                                "be out of date",
        }.get(str(check.get("staleWhy")), "no sync with MonClub has succeeded since Access "
                                         "started: the member list may be out of date")
        why = {
            "REFILL_SOURCE_MISSING": "this PC has no member list (sync cache) to refill the "
                                     "turnstile from",
            "REFILL_SOURCE_STALE": stale,
            "REFILL_SOURCE_EMPTY": f"the refill would write no member under {under}",
            "REFILL_WITHHELD": f"{withheld} member row(s) have no account number (mainAccountId): "
                               f"under {under} the refill would not write them",
        }.get(str(code), str(code))
        return 409, {"ok": False, "code": code, "pinScheme": under, "members": members,
                     "withheld": withheld, "staleWhy": check.get("staleWhy"),
                     "lastSyncAgeSec": check.get("lastSyncAgeSec"),
                     "syncMaxAgeSec": check.get("syncMaxAgeSec"),
                     "error": f"nothing erased: {why} -- the refill could not put everyone back"}

    @staticmethod
    def _hold_of(did: int) -> Optional[Dict[str, Any]]:
        if not device_hold.is_held(did):
            return None
        try:
            return dict(device_hold.holds_detail().get(did) or {"reason": "erase"})
        except Exception:
            return {"reason": "erase"}

    def holds_state(self) -> Dict[str, Any]:
        """The holds, and whether the start-up load failed (then EVERY turnstile is held)."""
        return {"holds": self.holds(), "loadFailed": bool(device_hold.load_failed())}

    def holds(self) -> List[Dict[str, Any]]:
        out = []
        try:
            detail = device_hold.holds_detail()
        except Exception:
            detail = {}
        for did in sorted(device_hold.held_ids()):
            item = {"deviceId": did, "pinScheme": self._pin_scheme(did)}
            item.update(detail.get(did) or {})
            out.append(item)
        return out

    # ------------------------------------------------------------------ status
    def status(self) -> Dict[str, Any]:
        with self._lock:
            run = json.loads(json.dumps(self._run)) if self._run is not None else None
            return {"ok": True, "running": self._running, "run": run}

    # ------------------------------------------------------------------ start
    def start(self, device_id: int, body: Dict[str, Any], *,
              verify_password: Callable[[str], Tuple[bool, int, str]]) -> Tuple[int, Dict[str, Any]]:
        """Validate everything, then run the erase on its own thread. 202 {runId}."""
        did = int(device_id)
        body = dict(body or {})
        backup_only = bool(body.get("backupOnly"))
        if device_hold.load_failed():
            # Every turnstile reads as held: a run would treat its own hold as an earlier one
            # and never release it (review round 2, R2-4).
            return 503, {"ok": False, "code": "HOLDS_UNKNOWN",
                         "error": "the erase holds could not be read: no erase until they are"}
        with self._lock:
            if self._running:
                return 409, {"ok": False, "code": "RUN_IN_PROGRESS",
                             "error": "an erase is already running"}
            if did in self._refilling:
                return 409, {"ok": False, "code": "REFILL_IN_PROGRESS",
                             "error": "this turnstile is being refilled"}
            preview = self._previews.get(str(body.get("previewId") or ""))
        if preview is None or self._mono() - preview["at"] > PREVIEW_TTL_SEC:
            return 409, {"ok": False, "code": "PREVIEW_EXPIRED",
                         "error": "read the tables again (step 1): the preview is missing or too old"}
        if preview["device"]["id"] != did and str(preview["device"]["id"]) != str(did):
            return 409, {"ok": False, "code": "WRONG_DEVICE",
                         "error": "this preview was read on another turnstile"}
        device = self._device(did)
        if not device:
            return 404, {"ok": False, "code": "NO_DEVICE", "error": "unknown turnstile"}
        proto = _protocol_of(device)
        ident = _device_identity(device, proto)
        if ident != preview["device"]:
            return 409, {"ok": False, "code": "DEVICE_CHANGED",
                         "error": "the turnstile's name, address or SDK changed since step 1: read "
                                  "the tables again"}
        name = ident["name"]
        if not name:
            return 409, {"ok": False, "code": "NO_DEVICE_NAME",
                         "error": "this turnstile has no name in MonClub: name it before erasing"}
        if str(body.get("typedName") or "").strip() != name:
            return 400, {"ok": False, "code": "NAME_MISMATCH",
                         "error": "the typed name is not this turnstile's name"}
        tables = body.get("tables")
        if not isinstance(tables, list) or not tables or len(set(map(str, tables))) != len(tables):
            return 400, {"ok": False, "code": "NO_TABLES", "error": "choose at least one table"}
        tables = [str(t) for t in tables]
        rows = {r["key"]: r for r in self._table_rows(proto, preview["counts"])}
        for t in tables:
            row = rows.get(t)
            if row is None:
                return 400, {"ok": False, "code": "UNKNOWN_TABLE", "error": f"unknown table {t!r}"}
            if not row["erasable"]:
                return 400, {"ok": False, "code": row.get("reason") or "NOT_ERASABLE",
                             "error": f"table {t!r} cannot be erased by the wizard"}
        users_table = USERS_TABLE[proto]
        forget = body.get("forget")
        refill = body.get("refill")
        if not backup_only:
            if not isinstance(forget, bool):
                return 400, {"ok": False, "code": "FORGET_REQUIRED",
                             "error": "choose whether MonClub forgets its records"}
            if forget and users_table not in tables:
                # Forgetting pins that are still on the terminal would strand them (§3.2c).
                return 400, {"ok": False, "code": "FORGET_NEEDS_USERS",
                             "error": f"'forget' needs the {users_table!r} table erased too"}
            if proto == PROTO_PULLSDK and users_table in tables:
                # The user rows gone, their door rights and fingers would stay on the panel and
                # belong to whoever gets the same pin next (ACCOUNT pins reuse membership
                # numbers, §3.2e) -- with or without "forget" (review round 1).
                required = [t for t in C3_ERASE_ORDER
                            if t != users_table and rows.get(t, {}).get("erasable")]
                missing = [t for t in required if t not in tables]
                if missing:
                    return 400, {"ok": False, "code": "USER_NEEDS_RIGHTS_AND_FINGERS",
                                 "required": required, "missing": missing,
                                 "error": f"erasing {users_table!r} needs {missing} erased too"}
            if proto == PROTO_STANDALONE and users_table in tables and forget is False:
                # Kept records of deleted members: the next pass deletes pins that are gone, and
                # a refused delete writes a blank disabled user instead (§3.4, review round 1).
                return 400, {"ok": False, "code": "USERS_ERASE_NEEDS_FORGET",
                             "error": "erasing the terminal's users needs 'forget'"}
            if refill not in REFILL_OPTIONS:
                return 400, {"ok": False, "code": "REFILL_REQUIRED",
                             "error": "choose when the turnstile is refilled"}
            if body.get("otherPcsClosed") is not True:
                # The hold binds THIS PC only. Without driver assignments (v2 off, the cutover
                # night) every Access PC of the gym runs a worker for every ULTRA turnstile and
                # would keep writing to it during the erase, and refill it right after, under
                # its own records (lane 1b, review C0). No local check can see them.
                # Quitting is not enough (lane 1c, review C1): the watchdog task relaunches a quit
                # Access within minutes, and the start with Windows at the next logon -- the
                # runbook's C1 / D1 order.
                return 400, {"ok": False, "code": "OTHER_PCS_NOT_CONFIRMED",
                             "error": "confirm that MonClub Access is closed on every other PC of "
                                      "this gym -- on each: 'Ouvrir MonClub Access avec Windows' "
                                      "unticked, the watchdog switched off (Disable-ScheduledTask "
                                      "-TaskName 'MonClub Access Watchdog'), then Quit -- and "
                                      "stays closed until Refill"}
            if refill in (REFILL_NOW, REFILL_AUTO) and device_hold.is_held(did):
                # An earlier erase left it on hold: only the Refill button -- which shows and
                # checks the pin scheme -- releases it, never a second run (review F2).
                return 409, {"ok": False, "code": "HELD_USE_REFILL",
                             "error": "this turnstile is on hold after an earlier erase: choose "
                                      "'hold until Refill', then press Refill"}
        extra = preview["counts"].get("extra") or {}
        if (proto == PROTO_STANDALONE and users_table in tables and not backup_only
                and not body.get("acceptFaceLoss")):
            faces = extra.get("faces")
            if faces is None:
                # Status 21 did not answer: faces may be there, and no backup exists for one.
                return 409, {"ok": False, "code": "FACES_UNKNOWN",
                             "error": "the terminal did not report its face count: faces may be "
                                      "lost (no backup exists for a face); confirm to go on"}
            if int(faces) > 0:
                return 409, {"ok": False, "code": "FACES_PRESENT",
                             "error": f"{faces} face template(s) on the terminal: no backup "
                                      "exists for a face; confirm their loss to go on"}
        refused = self._refusal(did, need_writes=not backup_only)
        if refused:
            return refused
        moved = self._address_refusal(self._worker(did), ident)
        if moved:
            return 409, {"ok": False, "code": moved[0], "error": moved[1]}
        try:
            scheme = self._pin_scheme_strict(did)
        except Exception as exc:
            return 503, {"ok": False, "code": "PIN_SCHEME_UNREADABLE",
                         "error": f"the turnstile's pin scheme could not be read: {exc}"}
        if not backup_only:
            # The device row read again, AFTER the strict scheme read above: a switch landing
            # between the two would otherwise pass the step-1 comparison below on the old row while
            # the run's start scheme is already the new one (lane 1c review round 5).
            check = self._refill_check(did)
            # Compared only when both were computed: no roster now (REFILL_SOURCE_MISSING) or at
            # step 1 (NOT_REFILLED_UNKNOWN) has its own refusal below.
            if ("_pins" in check and preview.get("rosterScheme") is not None
                    and check.get("scheme") != preview.get("rosterScheme")):
                # A switch saved since step 1 (the operator on steps 2-4): step 1's list of who the
                # refill would not put back was read under the other scheme, and the run's start
                # scheme would already be the new one -- nothing could see the move later (lane 1c
                # review round 4). Nothing held yet: read step 1 again.
                return 409, {"ok": False, "code": "PIN_SCHEME_CHANGED",
                             "pinScheme": check.get("scheme"),
                             "previewScheme": preview.get("rosterScheme"),
                             "error": f"the pin scheme is {check.get('scheme')} now, step 1 was read "
                                      f"under {preview.get('rosterScheme')}: read step 1 again"}
            # Every erasable table is something only the refill puts back: no erase the refill
            # could not undo (lane 1b, review C1).
            refused = self._refill_refusal(check, refill)
            if refused:
                return refused
            # The people the erase removes and the refill does not write back (lane 1c, review
            # C0): named at step 1, accepted by their own tick -- never erased unseen.
            left_out = preview.get("notRefilled")
            if left_out is None:
                return 409, {"ok": False, "code": "NOT_REFILLED_UNKNOWN",
                             "error": "the terminal's user list did not read at step 1, so who the "
                                      "refill would not put back is unknown: read step 1 again"}
            if left_out and body.get("acceptNotRefilled") is not True:
                return 409, {"ok": False, "code": "NOT_REFILLED_UNCONFIRMED",
                             "count": len(left_out),
                             "error": f"{len(left_out)} person(s) on this turnstile are not in the "
                                      "refill roster: the refill will NOT put them back -- "
                                      "confirm it (step 4)"}
        ok, status, error = verify_password(str(body.get("password") or ""))
        if not ok:
            return _password_refusal(status, error)
        # The gym's server switch (owner decision 2026-09-27), after the password so a wrong
        # password still reads as one. Starts only -- never the preview, never Refill.
        enabled, code, why = check_erase_switch(self.app)
        if not enabled:
            error = {
                "ERASE_NOT_ENABLED": "the erase is not enabled for this gym: the owner can enable "
                                     "it in the dashboard (access PCs page)",
                "ERASE_SWITCH_MISSING": f"the MonClub server does not offer the erase switch yet "
                                        f"({why}): the erase is not available until the server "
                                        "is updated -- retrying will not help",
                "ERASE_SWITCH_UNREACHABLE": f"the MonClub server did not answer the switch check "
                                            f"({why}): check the internet, then try again",
                "TLS_CLOCK": f"the secure connection to MonClub was refused -- the certificate is "
                             f"not yet valid or expired ({why}): check this PC's date and time; if "
                             "they are right, call the developer",
            }.get(str(code), f"whether the erase is enabled for this gym could not be checked: "
                             f"{why}")
            return (403 if code == "ERASE_NOT_ENABLED" else 503), {
                "ok": False, "code": code, "error": error}
        run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        started_at, corrected = _corrected_epoch()
        run = {
            # The run's date for the 30-day prune (lane 1c, review F2): server-corrected when
            # the PC has a measurement (clockCorrected), else the PC clock, as the run id.
            "startedAtEpoch": started_at, "clockCorrected": corrected,
            "runId": run_id, "deviceId": did, "device": ident, "protocol": proto,
            "tables": tables, "forget": None if backup_only else forget,
            "refill": None if backup_only else refill, "backupOnly": backup_only,
            "acceptFaceLoss": bool(body.get("acceptFaceLoss")),
            "otherPcsClosed": None if backup_only else True,
            # The pins accepted as "not put back" at step 1 (pins only, never a name); the run
            # binds them to its backup before the first delete (_bind_not_refilled).
            "notRefilledAccepted": None if backup_only else sorted(
                preview.get("notRefilled") or (), key=_pin_key),
            "notRefilled": None,
            "state": "RUNNING", "step": "start", "startedAt": _now_text(), "finishedAt": None,
            "steps": [], "countsBefore": None, "countsAfter": None, "backup": None,
            "progress": None, "error": None, "holdKept": None, "erased": False,
            "pinScheme": scheme,
        }
        with self._lock:
            if self._running:
                return 409, {"ok": False, "code": "RUN_IN_PROGRESS",
                             "error": "an erase is already running"}
            if did in self._refilling:
                return 409, {"ok": False, "code": "REFILL_IN_PROGRESS",
                             "error": "this turnstile is being refilled"}
            self._running = True
            self._run = run
            self._run_step1_roster = frozenset(preview.get("rosterPins") or ())
            self._run_step1_scheme = preview.get("rosterScheme")
            self._previews.pop(str(body.get("previewId")), None)
        try:
            self._spawn(lambda: self._execute(run_id))
        except Exception as exc:
            # No thread, nothing held yet: never leave a RUNNING run with nobody running it
            # (every later start, the Refill and the handover would wait on it -- round 3).
            _log.error("[ERASE] run %s not started", run_id, exc_info=True)
            with self._lock:
                self._running = False
                if self._run is not None and self._run.get("runId") == run_id:
                    self._run.update(state="FAILED", finishedAt=_now_text(),
                                     error=f"RUN_NOT_STARTED: {exc} -- nothing was erased")
            return 503, {"ok": False, "code": "RUN_NOT_STARTED",
                         "error": f"the erase could not start: {exc}"}
        return 202, {"ok": True, "runId": run_id}

    # ------------------------------------------------------------------ the run
    def _update(self, **changes: Any) -> Dict[str, Any]:
        with self._lock:
            assert self._run is not None
            self._run.update(changes)
            return json.loads(json.dumps(self._run))

    def _step(self, name: str, ok: bool, **detail: Any) -> None:
        with self._lock:
            assert self._run is not None
            run = self._run
            run["step"] = name
            run["steps"].append({"step": name, "ok": bool(ok), "at": _now_text(), **detail})
            run_id, did = run["runId"], run["deviceId"]
            snapshot = json.loads(json.dumps(run))
        _log.warning("[ERASE] run=%s device=%s step=%s ok=%s %s", run_id, did, name, ok,
                     json.dumps(detail, ensure_ascii=False, default=str)[:600])
        try:
            _tel.event("ERASE_STEP", run=run_id, device_id=did, step=name, ok=bool(ok),
                       **{k: v for k, v in detail.items() if isinstance(v, (int, str, bool))})
        except Exception:
            pass
        self._write_run_file(snapshot)

    def _run_dir(self, run: Dict[str, Any]) -> Path:
        return self.backup_root() / f"{run['runId']}_device{run['deviceId']}"

    def _write_run_file(self, run: Dict[str, Any]) -> None:
        try:
            d = self._run_dir(run)
            d.mkdir(parents=True, exist_ok=True)
            # The last write's time, on the corrected clock where there is one: what the prune
            # dates the folder by (lane 1c, review F2), not the files' mtimes.
            at, _corrected = _corrected_epoch()
            record = dict(run, writtenAtEpoch=at)
            _write_file_durably(d / "run.json", json.dumps(record, ensure_ascii=False, indent=1)
                                .encode("utf-8"))
        except Exception:
            _log.warning("[ERASE] run record not written", exc_info=True)

    def _execute(self, run_id: str) -> None:
        try:
            self._execute_run(run_id)
        finally:
            # Whatever happened -- even a failure inside _finish itself -- the run is over: never
            # leave "running" standing, which would refuse every later start and Refill.
            with self._lock:
                if self._run is not None and self._run.get("runId") == run_id:
                    self._running = False
            # Erase backups older than 30 days go, after each run (and at start-up: app.py).
            prune_erase_backups(self.backup_root(), keep_run_id=run_id)

    def _execute_run(self, run_id: str) -> None:
        run = self.status()["run"] or {}
        did, proto = int(run["deviceId"]), run["protocol"]
        tables, backup_only = list(run["tables"]), bool(run["backupOnly"])
        held_before = device_hold.is_held(did)
        erase_started = False
        try:
            # 1. HOLD: from here MonClub writes nothing to this turnstile (door and scans go on).
            # Phase ERASE_PREP: no delete issued yet -- a restart before the first delete
            # releases it (review F1). A turnstile already held for a real erase keeps ERASE.
            # A rehearsal on a turnstile already held leaves its hold row as it is: the row names
            # the run that may have erased (review round 1, finding 4). A real erase takes it over
            # (its first delete must find ITS run id there, db.begin_device_erase).
            # A new row records the scheme the terminal's pins are under: the run's start scheme
            # (lane 1e, master review C0) -- a row taken over keeps the one it recorded.
            if not (held_before and backup_only):
                device_hold.hold(did, reason=device_hold.REASON_ERASE_PREP, run_id=run_id,
                                 pin_scheme=run.get("pinScheme"))
            self._step("hold", True, heldBefore=held_before)
            worker = self._wait_idle(did)
            moved = self._address_refusal(worker, run["device"])
            if moved:
                raise StepError(*moved)
            self._step("idle", True)
            before = self._counts(worker, proto)
            self._update(countsBefore=before)
            self._step("counts_before", True, **_flat(before))
            backup = self._backup(worker, proto, tables, before)
            self._update(backup=backup["summary"])
            self._step("backup", True, path=backup["summary"]["path"],
                       sha256=backup["summary"]["sha256"], rows=backup["summary"]["rows"])
            if backup_only:
                self._finish("DONE", release=not held_before, note="backup only: nothing erased")
                return
            kept = self._kept_admins(proto, backup)
            check = self._recheck_before_delete(did, str(run["refill"]), kept)
            # Who the refill will not put back, from the backup: only the people accepted at
            # step 1, and their backup kept for good (lane 1c, review C0).
            left = self._bind_not_refilled(worker, run, proto, tables, backup, check)
            # The erase record, durable: the hold moves to ERASE (a restart keeps it from here)
            # and every recorded pin's last push result becomes unknown -- the erase is an attempt
            # start for all of them (review F12). No write, no erase.
            try:
                reset = _begin_erase(did, run_id, kept)
            except Exception as exc:
                raise StepError("RESULTS_NOT_RESET",
                                f"the erase could not be recorded before its first delete: {exc}")
            self._step("erase_recorded", True, resultsReset=int(reset), kept=len(kept))
            erase_started = True
            self._update(erased=True)
            # The keep mark, AFTER the erase record (lane 1e, master review F8): a mark on disk now
            # means "a delete may have run", as the ERASE row does. Written before it, a run cut
            # between the two kept a biometric backup for good although it erased nobody -- and on
            # a turnstile already held at ``erase`` no start-up could tell (the row never was
            # ``erase-prep``). The last durable write before the first delete.
            self._write_keep_mark(run, left)
            erase_error = None
            try:
                self._erase(worker, did, proto, tables, backup, before)
            except StepError as exc:
                erase_error = exc
                self._step("erase", False, code=exc.code, error=exc.message,
                           uncertain=exc.uncertain)
            else:
                self._step("erase", True)
            after = self._counts(worker, proto)
            self._update(countsAfter=after)
            verified, why = self._verify(worker, proto, tables, backup, after)
            self._step("counts_after", verified, verified=verified, why=why, **_flat(after))
            if erase_error is not None:
                raise erase_error                 # its own code: NOT_DRIVER, ERASE_FAILED, ...
            if not verified:
                raise StepError("NOT_VERIFIED", why or "the erase could not be verified")
            self._records(worker, did, proto, tables, bool(run["forget"]), backup)
            self._refill(worker, did, str(run["refill"]), run.get("pinScheme"),
                         held_before=held_before)
        except StepError as exc:
            if erase_started:
                # Something may have been erased: keep the hold, forget nothing (an unverified
                # erase followed by a forget is the stranded-pin failure, §3.2c), and make every
                # recorded pin "not in sync" so the refill writes it again.
                self._invalidate(did)
                self._finish("INCOMPLETE", release=False, error=f"{exc.code}: {exc.message}")
            else:
                # Nothing erased: nobody lost, the backup is prunable as any other.
                self._drop_keep_mark(run)
                note = self._scheme_moved_note(did, run.get("pinScheme"))
                if note:
                    # Held before or not (lane 1e, master review F7): a row this run took over at
                    # ``erase-prep`` is released by the next start like its own.
                    note = self._keep_hold_across_restarts(did, run_id, note)
                # Not on a worker the run just saw connected to ANOTHER address: no pass through it.
                self._finish("FAILED", release=not (held_before or note),
                             error=f"{exc.code}: {exc.message} -- nothing was erased",
                             ask_pass=exc.code not in ("ADDRESS_CHANGED", "ADDRESS_UNKNOWN"),
                             note=note)
        except Exception as exc:  # noqa: BLE001 - a bug must never leave the run "RUNNING"
            _log.error("[ERASE] run %s crashed", run_id, exc_info=True)
            note = None
            if erase_started:
                self._invalidate(did)
            else:
                self._drop_keep_mark(run)
                note = self._scheme_moved_note(did, run.get("pinScheme"))
                if note:
                    note = self._keep_hold_across_restarts(did, run_id, note)
            self._finish("INCOMPLETE" if erase_started else "FAILED",
                         release=(not erase_started and not held_before and not note),
                         error=f"UNEXPECTED: {type(exc).__name__}: {exc}", note=note)

    def _scheme_moved_note(self, did: int, run_scheme: Optional[str]) -> Optional[str]:
        """For a run that stops before its first delete: None when the pin scheme is still the one
        the run started under; else the finish note of a run that keeps its hold and asks no pass
        (lane 1c review rounds 3-4) -- the terminal may hold every pin of the old scheme, and a pass
        released now would write the new scheme's pins beside them (``_refill``'s own end-of-run
        rule). Their own codes, not PIN_SCHEME_CHANGED: that note (a run that DID erase) says
        "press Refill", which after a move here would write the new scheme beside every old pin.
        ``start()`` refuses a switch saved between step 1 and START, so the run's start scheme is
        step 1's.

        The scheme the terminal holds -- the one Refill accepts -- is the hold ROW's
        (``terminalScheme``: a run that took an earlier hold over keeps the first run's), else the
        run's start scheme (review round 1 of lane 1e). One recovery sentence, the runbook's: set
        that scheme back, then erase again with 'hold' (or Refill to release it, erasing nothing)."""
        terminal = run_scheme
        unrecorded = False
        try:
            row = device_hold.holds_detail().get(did) or {}
            if row.get("terminalScheme") is not None:
                terminal = row["terminalScheme"]
            else:
                # A row an earlier build wrote at erase-scheme-moved records none: Refill refuses it
                # whatever the scheme (review round 2 of lane 1e, nit).
                unrecorded = row.get("reason") == device_hold.REASON_SCHEME_MOVED
        except Exception:
            pass
        what = ("Refill is refused: which scheme the terminal's pins were written under is not "
                "recorded -- erase it again with 'hold'" if unrecorded else
                f"Refill is accepted only under {terminal} -- set the scheme back to {terminal}, then "
                "erase it again with 'hold' (or Refill to release it, erasing nothing)")
        try:
            now = self._pin_scheme_strict(did)
        except Exception:
            return ("HELD_SCHEME_UNREADABLE: the pin scheme could not be read after the stop, "
                    f"before any delete -- kept on hold, the terminal holds the {terminal} scheme's "
                    f"pins: {what}")
        if now == run_scheme:
            return None
        return (f"HELD_SCHEME_MOVED: the pin scheme moved from {run_scheme} to {now} during the run, "
                f"before any delete -- kept on hold, the terminal still holds the {terminal} "
                f"scheme's pins: {what}")

    @staticmethod
    def _device_gone(did: int) -> bool:
        """The turnstile's row was read and is not there any more (deleted in MonClub). A row
        that does not read is NOT gone: the caller then keeps the hold durable (fail closed)."""
        try:
            from app.core.db import get_sync_device_payload
            return get_sync_device_payload(int(did)) is None
        except Exception:
            return False

    @staticmethod
    def _keep_hold_across_restarts(did: int, run_id: str, note: str) -> str:
        """The hold a scheme-moved stop keeps must outlive a restart (lane 1d, master review F0):
        its row is still at ``erase-prep``, which the next start releases -- and the gyms power
        off every night. Moved durably to ``erase-scheme-moved`` (``db.
        keep_erase_hold_after_scheme_move``: that run's own row only; a row already at ``erase``
        or ``erase-scheme-moved`` stays as it is, and the note is the plain one).

        A turnstile whose row is gone (deleted in MonClub, ``_device_gone``) keeps no durable
        hold -- no Refill could be pressed for it (review round 1 of lane 1d) -- and its note is
        ``HELD_DEVICE_GONE``: nothing to do, the next start releases it (lane 1e, master review
        nit: the session note told the operator to erase again or press Refill, impossible there).

        A write that fails keeps the hold for this session, and the note says so under its own
        code, ``HELD_SCHEME_MOVED_SESSION`` / ``HELD_SCHEME_UNREADABLE_SESSION``: the page's line
        for the plain code promises a hold that outlives a restart. Since lane 1e the next start
        still keeps that row when the turnstile's scheme then differs from the one it records
        (``db.release_unstarted_erase_holds``) -- hence "may not last", not "will not"."""
        from app.core import db as _db
        try:
            row_reason = (device_hold.holds_detail().get(did) or {}).get("reason")
        except Exception:
            row_reason = None
        # Only a row this run held at ``erase-prep`` (review round 1 of lane 1e): one at ``erase``
        # or ``erase-scheme-moved`` may come from an earlier run that erased, and no start
        # releases it -- "nothing was erased" would be false there.
        if row_reason == _db.HOLD_REASON_ERASE_PREP and EraseWizard._device_gone(did):
            _log.warning("[ERASE] run %s: turnstile %s was deleted in MonClub during the run -- "
                         "nothing was erased; held for this session only, a restart releases it",
                         run_id, did)
            return ("HELD_DEVICE_GONE: the turnstile was deleted in MonClub during the run, before "
                    "any delete -- nothing was erased; it stays held until Access restarts, "
                    "nothing to do")
        try:
            reason = _db.keep_erase_hold_after_scheme_move(device_id=did, run_id=run_id)
        except Exception:
            _log.error("[ERASE] run %s: the hold of turnstile %s could not be made durable",
                       run_id, did, exc_info=True)
            reason = None
        if reason == _db.HOLD_REASON_ERASE:
            # Held at ``erase`` by an earlier run that may have deleted (lane 1e): « Remplir »
            # is the normal next step there (it is refused on ``erase-scheme-moved`` rows only),
            # so not a note that says it is refused -- ``_refill``'s own HELD_BEFORE.
            return ("HELD_BEFORE: on hold since an earlier erase that may have deleted -- this run "
                    "stopped before any delete, after the pin scheme moved: press Refill")
        if reason and reason != _db.HOLD_REASON_ERASE_PREP:
            return note
        _log.error("[ERASE] run %s: the hold of turnstile %s was not recorded as kept -- a restart "
                   "of Access may release it", run_id, did)
        code, sep, rest = note.partition(":")
        return (f"{code}_SESSION{sep}{rest} -- the hold could not be recorded as kept: it may NOT "
                "last through a restart of Access; do not restart Access before it is done")

    @staticmethod
    def _kept_admins(proto: str, backup: Dict[str, Any]) -> List[str]:
        """The users the erase leaves on the terminal: the MB2000 administrators (privilege > 0,
        from the verified backup). None on a C3 (no such notion there)."""
        if proto != PROTO_STANDALONE:
            return []
        return [str(u["pin"]) for u in (backup.get("content") or {}).get("users") or []
                if int(u.get("privilege") or 0) > 0]

    def _recheck_before_delete(self, did: int, refill: str, kept: List[str]) -> Dict[str, Any]:
        """Right before the first delete (the backup can take long): the refill must still be able
        to refill (start()'s check, minus STALE -- one failed sync during a long MB2000 backup
        leaves the member list as it was, while a SUCCESSFUL one can empty it or bring withheld
        rows; lane 1b review round 1, finding 1), and an MB2000
        administrator the erase keeps must not also be a member the refill writes -- the push writes
        ``SSR_SetUserInfo(1, pin, name, "", 0, enabled)``, privilege 0, password emptied, so the
        refill would demote the admin to that member (review C4). Both under the scheme now and,
        for "hold", under ACCOUNT too (the scheme at Refill is not known yet). Raised before any
        delete: FAILED, nothing erased. Returns the check (its roster pins bind the people the
        refill leaves out, ``_bind_not_refilled``)."""
        check = self._refill_check(did)
        if "_pins" not in check:
            raise StepError("REFILL_SOURCE_MISSING", "the refill roster could not be read any more: "
                                                     "nothing erased")
        # From the counts, not ``problem``: a STALE there would mask an emptied roster.
        rosters_now = [(check.get("scheme"), check.get("members"), check.get("withheld"))]
        if refill == REFILL_HOLD and check.get("ifAccount"):
            acct = check["ifAccount"]
            rosters_now.append((PIN_SCHEME_ACCOUNT, acct.get("members"), acct.get("withheld")))
        for under, members, withheld in rosters_now:
            code = ("REFILL_SOURCE_EMPTY" if not members
                    else "REFILL_WITHHELD" if withheld else None)
            if code:
                raise StepError(code, f"the refill could not put everyone back any more (under "
                                      f"{under}: {members} member(s), {withheld} withheld): "
                                      "nothing erased")
        if not kept:
            return check
        pins = check["_pins"]
        rosters = [("now", check.get("scheme"))]
        if refill == REFILL_HOLD:
            rosters.append(("account", PIN_SCHEME_ACCOUNT))
        for key, scheme in rosters:
            clash = sorted(set(kept) & set(pins.get(key) or ()))
            if clash:
                raise StepError("ADMIN_PIN_IN_ROSTER",
                                f"{len(clash)} terminal administrator pin(s) are also member pins "
                                f"under {scheme} (e.g. {clash[:3]}): the refill would overwrite "
                                "them as members -- change those administrators' pins on the "
                                "terminal first")
        return check

    def _bind_not_refilled(self, worker: Any, run: Dict[str, Any], proto: str,
                           tables: List[str], backup: Dict[str, Any],
                           check: Dict[str, Any]) -> List[str]:
        """Right before the first delete (lane 1c, review C0): the people this erase removes and
        the refill does not write back, from the BACKUP (what is really erased) against the roster
        now. Only the pins the operator accepted at step 1 may be among them -- or a member step 1
        saw in the roster who left it since (a right that ended at the midnight date flip during a
        long MB2000 backup: a normal pass would remove them too; review round 1 of lane 1c). Anyone
        else -- a user enrolled on the terminal since step 1 -- stops the run
        (``NOT_REFILLED_CHANGED``, FAILED, nothing erased). Returns their pins: when some remain,
        the run folder gets ``KEEP_MARK`` after the erase record (``_write_keep_mark``, lane 1e):
        the backup is their only copy, and the prune never deletes a marked folder. A C3 erase
        without the ``user`` table has no user rows in its backup: the list is read once more here.
        Pins only -- never a name -- in the run record, the mark and the log (review F29)."""
        with self._lock:
            step1_roster = set(self._run_step1_roster)
            step1_scheme = self._run_step1_scheme
        if check.get("scheme") != step1_scheme:
            # A switch saved since step 1 (during the backup): the terminal's pins are the old
            # scheme's, the roster the new one's -- nobody can be compared, and excusing the step-1
            # roster would count every member "not put back". Before any delete: the cheap exit
            # (lane 1c review round 2).
            raise StepError("PIN_SCHEME_CHANGED",
                            f"the pin scheme moved from {step1_scheme} at step 1 to "
                            f"{check.get('scheme')} before the first delete: who the refill would "
                            "not put back cannot be told -- read step 1 again")
        content = backup.get("content") or {}
        if proto == PROTO_PULLSDK and "user" not in (content.get("rows") or {}):
            people = self._read_people(worker, proto)
            if people is None:
                raise StepError("NOT_REFILLED_UNKNOWN",
                                "the terminal's user list could not be read before the first "
                                "delete: who the refill would not put back is unknown")
        elif proto == PROTO_PULLSDK:
            people = terminal_people(proto, content["rows"]["user"])
        else:
            people = terminal_people(proto, content.get("users") or [])
        left = sorted({p["pin"] for p in not_refilled(people, (check.get("_pins") or {})
                                                      .get("now"))}, key=_pin_key)
        unseen = sorted(set(left) - set(run.get("notRefilledAccepted") or ()) - step1_roster,
                        key=_pin_key)
        if unseen:
            raise StepError("NOT_REFILLED_CHANGED",
                            f"{len(unseen)} person(s) on the terminal are not in the refill roster "
                            f"and were not shown at step 1 (pins e.g. {unseen[:5]}): the refill "
                            "would not put them back -- read step 1 again")
        self._update(notRefilled={"count": len(left), "pins": left})
        self._step("not_refilled", True, count=len(left))
        return left

    def _write_keep_mark(self, run: Dict[str, Any], left: List[str]) -> None:
        """The run folder's ``KEEP_MARK`` when the erase removes people the refill does not put
        back (lane 1c, review C0), written durably AFTER the erase record and before the first
        delete command (lane 1e, master review F8). A failure raises before any delete -- with
        the erase already recorded the run ends INCOMPLETE: held, every record to be written again
        (lane 1c ended it FAILED and released, when the mark came first)."""
        if not left:
            return
        try:
            _write_file_durably(self._run_dir(run) / KEEP_MARK, json.dumps(
                {"count": len(left), "pins": left, "at": _now_text()}).encode("utf-8"))
        except Exception as exc:
            raise StepError("KEEP_MARK_NOT_WRITTEN",
                            f"the mark that keeps this backup for good could not be written "
                            f"({exc}): the backup is the only copy of the people the refill does "
                            "not put back -- nothing was erased; the erase was already recorded, "
                            "so the turnstile stays held and Refill writes every member again")

    def _drop_keep_mark(self, run: Dict[str, Any]) -> None:
        """A run that failed before any delete removed nobody: its backup is prunable as usual."""
        try:
            (self._run_dir(run) / KEEP_MARK).unlink(missing_ok=True)
        except Exception:
            _log.warning("[ERASE] keep mark of run %s not removed: its backup stays", run.get("runId"),
                         exc_info=True)

    def _invalidate(self, did: int) -> None:
        """After an erase that did not end verified: the hard-reset UPDATE (hashes cleared,
        ``last_ok=0``; ownership, removal evidence and the recorded finger sets kept -- whether
        the fingers went is not known). Durable."""
        from app.core import db as _db
        try:
            n = _db.invalidate_device_records(device_id=did, fingers_erased=False)
            self._step("records_invalidated", True, invalidated=int(n))
        except Exception as exc:
            _log.error("[ERASE] records of turnstile %s NOT invalidated: Refill resets them", did,
                       exc_info=True)
            self._step("records_invalidated", False, error=str(exc)[:200])

    def _finish(self, state: str, *, release: bool, error: Optional[str] = None,
                note: Optional[str] = None, ask_pass: bool = True) -> None:
        run = self.status()["run"] or {}
        did = int(run.get("deviceId") or 0)
        if release:
            try:
                device_hold.release(did)
            except Exception:
                _log.error("[ERASE] hold of turnstile %s NOT released", did, exc_info=True)
            else:
                # A pass the hold cut short may have reported success with its roster stamp:
                # without this the scheduler skips the turnstile until the roster changes.
                try:
                    self._force_scheduler(did)
                except Exception:
                    _log.warning("[ERASE] scheduler not forced for turnstile %s", did,
                                 exc_info=True)
                # ... and ask for that pass again now: dropping the stamp alone leaves it to the
                # scheduler's next timer (up to 15 min; never on a manual-sync gym, review F8).
                try:
                    worker = self._worker(did) if ask_pass else None
                    if worker is not None:
                        worker.request_full_sync(reason="erase-released")
                except Exception:
                    _log.warning("[ERASE] pass not requested after the release of turnstile %s",
                                 did, exc_info=True)
        kept = device_hold.is_held(did)
        self._update(state=state, finishedAt=_now_text(), error=error, holdKept=kept)
        self._step("finish", state == "DONE", state=state, holdKept=kept,
                   **({"error": error} if error else {}), **({"note": note} if note else {}))
        with self._lock:
            self._running = False

    def _wait_idle(self, did: int) -> Any:
        """The hold stops new passes; wait for the one running (if any) to end."""
        deadline = self._mono() + IDLE_WAIT_SEC
        while True:
            worker = self._worker(did)
            if worker is None:
                raise StepError("NO_WORKER", "the turnstile's worker stopped")
            if not getattr(worker, "_connected", False):
                raise StepError("NOT_CONNECTED", "turnstile not connected")
            if not getattr(worker, "_full_sync_running", False):
                return worker
            if self._mono() > deadline:
                raise StepError("BUSY", "a sync pass is still running on this turnstile")
            self._sleep(0.25)

    # ------------------------------------------------------------------ backup
    def _backup(self, worker: Any, proto: str, tables: List[str],
                before: Dict[str, Any]) -> Dict[str, Any]:
        run = self.status()["run"] or {}
        if proto == PROTO_PULLSDK:
            content = self._backup_c3(worker, tables)
        else:
            content = self._backup_mb(worker, before)
        payload = {"runId": run["runId"], "device": run["device"], "protocol": proto,
                   "takenAt": _now_text(), "tables": tables, **content}
        data = json.dumps(payload, ensure_ascii=False, indent=1).encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        path = self._run_dir(run) / "backup.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _write_file_durably(path, data)
            _write_file_durably(path.with_suffix(".json.sha256"),
                                f"{digest}  backup.json\n".encode("ascii"))
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise StepError("BACKUP_WRITE", "the backup file read back differently")
        except StepError:
            raise
        except Exception as exc:
            raise StepError("BACKUP_WRITE", f"the backup file could not be written: {exc}")
        rows = content.get("rowCounts") or {}
        return {"content": content,
                "summary": {"path": str(path), "sha256": digest, "rows": sum(rows.values()),
                            "rowCounts": rows}}

    def _backup_c3(self, worker: Any, tables: List[str]) -> Dict[str, Any]:
        out: Dict[str, Any] = {"rows": {}, "rowCounts": {}, "redacted": {}}
        for t in tables:
            def _fn(drv, _t=t):
                n = int(drv.count_table_strict(table=_t))
                rows = drv.read_table_strict(table=_t)
                return n, rows
            n, rows = self._call(worker, _fn, label=f"read_{t}", timeout=T_READ)
            if len(rows) != n:
                raise StepError("BACKUP_INCOMPLETE",
                                f"table {t}: {len(rows)} row(s) read, the panel counts {n}")
            out["rows"][t] = _redact_passwords(t, rows, out["redacted"])
            out["rowCounts"][t] = n
        return out

    def _backup_mb(self, worker: Any, before: Dict[str, Any]) -> Dict[str, Any]:
        """Every user row (pin, name, card, privilege, enabled -- never a password value) and
        every template of every user, admins included. Verified against the terminal's own
        counters: users, admins and fingerprints must all agree, every pin must be numeric (a
        wrong out-param order would list names as pins: backing up -- and targeting -- garbage)."""
        res = self._call(worker, lambda drv: drv.list_device_users(timeout_sec=TD_LIST),
                         label="list_users", timeout=T_READ) or {}
        if not res.get("ok"):
            raise StepError("BACKUP_INCOMPLETE",
                            f"user listing failed: {res.get('error') or 'no answer'}")
        users = list(res.get("users") or [])
        tabs = before.get("tables") or {}
        extra = before.get("extra") or {}
        n_users, n_admins, n_fps = tabs.get("users"), extra.get("admins"), tabs.get("fingerprints")
        if n_users is None or n_admins is None or n_fps is None:
            raise StepError("BACKUP_UNVERIFIABLE",
                            "the terminal did not report its user, admin or fingerprint count")
        if len(users) != int(n_users):
            raise StepError("BACKUP_INCOMPLETE",
                            f"{len(users)} user(s) listed, the terminal counts {n_users}")
        bad = [str(u.get("pin")) for u in users
               if not (str(u.get("pin") or "").isdigit() and len(str(u.get("pin"))) <= 9)]
        if bad:
            # A count only: a wrong out-param order lists NAMES as pins, and this text reaches
            # the app log, telemetry and run.json (review F29).
            raise StepError("BACKUP_UNTRUSTED", f"{len(bad)} listed pin(s) are not numeric: "
                                                "the read cannot be trusted")
        if any(not isinstance(u.get("privilege"), int) for u in users):
            raise StepError("BACKUP_UNTRUSTED", "a user's privilege did not read: admins "
                                                "cannot be told apart")
        admins = [u for u in users if int(u["privilege"]) > 0]
        if len(admins) != int(n_admins):
            raise StepError("BACKUP_UNTRUSTED",
                            f"{len(admins)} admin(s) listed, the terminal counts {n_admins}")
        pins = [str(u["pin"]) for u in users]
        templates: Dict[str, List[Dict[str, Any]]] = {}
        chunks = _chunks(pins, MB_TEMPLATE_PINS_PER_CALL)
        for i, part in enumerate(chunks):
            self._update(progress={"phase": "backup_fingers", "done": i, "total": len(chunks)})
            got = self._call(worker, lambda drv, _p=part: drv.read_user_templates(
                _p, timeout_sec=TD_TEMPLATES), label="read_templates", timeout=T_READ) or {}
            if not got.get("ok"):
                raise StepError("BACKUP_INCOMPLETE",
                                f"fingerprint read failed: {got.get('error') or 'no answer'}")
            templates.update(got.get("templates") or {})
        self._update(progress=None)
        n_read = sum(len(v) for v in templates.values())
        if n_read != int(n_fps):
            raise StepError("BACKUP_INCOMPLETE",
                            f"{n_read} template(s) read, the terminal counts {n_fps}")
        users_out = [{"pin": str(u["pin"]), "name": u.get("name"), "card": u.get("card"),
                      "privilege": int(u["privilege"]), "enabled": bool(u.get("enabled"))}
                     for u in users]
        return {"users": users_out, "templates": templates, "counters": dict(extra, **tabs),
                "rowCounts": {"users": len(users_out), "fingerprints": n_read}}

    # ------------------------------------------------------------------ erase
    def _erase(self, worker: Any, did: int, proto: str, tables: List[str],
               backup: Dict[str, Any], before: Dict[str, Any]) -> None:
        if proto == PROTO_PULLSDK:
            counted = before.get("tables") or {}
            for t in C3_ERASE_ORDER:
                if t in tables:
                    if counted.get(t) == 0:
                        # Nothing to erase, and the call itself may be refused: a C3 without the
                        # v9 ``template`` table -- the FULL_REPLACE clear treats that refusal as
                        # "table may not exist" -- would end the run INCOMPLETE after
                        # templatev10 is gone (review C5). The verify still requires 0 after.
                        self._step(f"erase_{t}", True, skipped="empty")
                        continue
                    self._write_call(worker, did, lambda drv, _t=t: drv.erase_table(table=_t),
                                     label=f"erase_{t}", timeout=T_ERASE)
                    self._step(f"erase_{t}", True)
            return
        content = backup["content"]
        members = [u["pin"] for u in content["users"] if int(u["privilege"]) <= 0]
        if "users" in tables:
            chunks = _chunks(members, MB_DELETE_PINS_PER_CALL)
            for i, part in enumerate(chunks):
                self._update(progress={"phase": "erase_users", "done": i, "total": len(chunks)})
                res = self._write_call(
                    worker, did, lambda drv, _p=part: drv.delete_users(_p, timeout_sec=TD_DELETE),
                    label="delete_users", timeout=T_ERASE) or {}
                if not res.get("ok") or res.get("failed_pins"):
                    # Stop at the first chunk that did not fully go: a timeout reports every pin
                    # failed although some may have been deleted.
                    failed = [str(p) for p in (res.get("failed_pins") or [])]
                    raise StepError("ERASE_FAILED",
                                    f"user delete failed in chunk {i + 1}/{len(chunks)} "
                                    f"({len(failed)} pin(s), e.g. {failed[:5]}): "
                                    f"{res.get('errors') or res.get('error')}", uncertain=True)
            self._update(progress=None)
            self._step("erase_users", True, deleted=len(members))
            return
        # fingerprints only: the recorded slots of every non-admin user, never an admin's.
        slots = [(pin, [int(s["fingerId"]) for s in content["templates"].get(pin) or []])
                 for pin in members]
        slots = [(p, s) for p, s in slots if s]
        for i, (pin, fids) in enumerate(slots):
            self._update(progress={"phase": "erase_fingers", "done": i, "total": len(slots)})
            parts = _chunks(fids, MB_SWEEP_SLOTS_PER_CALL)
            for j, part in enumerate(parts):
                res = self._write_call(
                    worker, did, lambda drv, _pin=pin, _p=part, _last=(j == len(parts) - 1):
                    drv.sweep_finger_slots(_pin, _p, refresh=_last, timeout_sec=TD_SWEEP),
                    label="clear_fingers", timeout=T_ERASE) or {}
                if not res.get("ok"):
                    raise StepError("ERASE_FAILED",
                                    f"finger clear failed on pin {pin}: {res.get('error')}",
                                    uncertain=True)
        self._update(progress=None)
        self._step("erase_fingerprints", True, pins=len(slots))

    def _verify(self, worker: Any, proto: str, tables: List[str], backup: Dict[str, Any],
                after: Dict[str, Any]) -> Tuple[bool, str]:
        tabs = after.get("tables") or {}
        if proto == PROTO_PULLSDK:
            left = {t: tabs.get(t) for t in tables if tabs.get(t) != 0}
            return (not left), ("" if not left else f"rows left or unreadable: {left}")
        content = backup["content"]
        admins = [u for u in content["users"] if int(u["privilege"]) > 0]
        admin_fps = sum(len(content["templates"].get(u["pin"]) or []) for u in admins)
        if "users" in tables:
            res = self._call(worker, lambda drv: drv.list_device_users(timeout_sec=TD_LIST),
                             label="list_users_after", timeout=T_READ) or {}
            if not res.get("ok"):
                return False, "the user listing after the erase failed"
            left = [str(u.get("pin")) for u in res.get("users") or []
                    if not (isinstance(u.get("privilege"), int) and u["privilege"] > 0)]
            if left:
                return False, f"{len(left)} non-admin user(s) still listed (e.g. {left[:5]})"
            if tabs.get("users") != len(admins):
                return False, f"the terminal counts {tabs.get('users')} user(s), {len(admins)} admin(s) kept"
        if tabs.get("fingerprints") != admin_fps:
            return False, (f"the terminal counts {tabs.get('fingerprints')} template(s), the kept "
                           f"admins had {admin_fps}")
        return True, ""

    # ------------------------------------------------------------------ records + refill
    def _records(self, worker: Any, did: int, proto: str, tables: List[str], forget: bool,
                 backup: Dict[str, Any]) -> None:
        from app.core import db as _db
        refused = self._write_refusal(did)
        if refused:
            # The lease moved after the erase: this PC must not rewrite its record of the
            # turnstile as if it still drove it (INCOMPLETE: the hashes are invalidated).
            raise StepError(*refused)
        users_erased = USERS_TABLE[proto] in tables
        fingers_erased = users_erased or bool(FINGER_TABLES & set(tables))
        # The MB2000 administrators stay on the terminal with their fingers: their records stay.
        kept = self._kept_admins(proto, backup)
        if forget:
            out = _db.retire_device_records(device_id=did, keep_pins=kept)
            self._step("forget", True, **{k: int(v) for k, v in out.items()})
        else:
            n = _db.invalidate_device_records(device_id=did, fingers_erased=(
                proto == PROTO_STANDALONE and fingers_erased), keep_pins=kept)
            self._step("keep_records", True, invalidated=int(n), kept=len(kept))
        if users_erased:
            # The terminal's user table is empty now: the server's ownership record of it starts
            # a new generation (the same report a PullSDK table clear already makes, §3.9).
            try:
                from app.core.v2 import ownership as _v2_ownership
                _v2_ownership.note_wipe(did)
                self._step("wipe_reported", True)
            except Exception as exc:
                self._step("wipe_reported", False, error=str(exc)[:200])
        self._set_waiting(worker, did)

    def _set_waiting(self, worker: Any, did: int) -> None:
        """Every recorded pin was forgotten or reset: the "N waiting" figure is the whole roster
        the refill will write, until its pass counts again -- never None, which the heartbeat
        sends as 0 (review F0). A pass that never runs (no worker, a lease or scheme stop) keeps
        this figure. Unknown when the roster cannot be read."""
        members = self._refill_check(did).get("members")
        try:
            worker._waiting_pins = int(members) if isinstance(members, int) else None
        except Exception:
            pass

    def _force_scheduler(self, did: int) -> None:
        eng = getattr(self.app, "_ultra_engine", None)
        sched = getattr(eng, "_sync_scheduler", None) if eng is not None else None
        if sched is not None and hasattr(sched, "force_resync"):
            sched.force_resync(did)

    def _refill(self, worker: Any, did: int, refill: str, run_scheme: Optional[str], *,
                held_before: bool = False) -> None:
        if refill == REFILL_HOLD:
            self._finish("DONE", release=False, note="on hold until Refill is pressed")
            return
        if held_before:
            # An earlier erase's hold is released only by the Refill button, which shows the
            # pin scheme and checks it (review F2; start() already refuses now/auto then).
            self._finish("DONE", release=False,
                         note="HELD_BEFORE: on hold since an earlier erase -- press Refill")
            return
        # The pin scheme must still be the one the run started under: a switch recorded during
        # the run (or a stale answer reverting one, §3.2e) would refill the other numbering.
        try:
            scheme = self._pin_scheme_strict(did)
        except Exception as exc:
            self._finish("DONE", release=False,
                         note=f"PIN_SCHEME_UNREADABLE: kept on hold, press Refill ({exc})")
            return
        if scheme != run_scheme:
            self._finish("DONE", release=False,
                         note=f"PIN_SCHEME_CHANGED: {run_scheme} at the start, {scheme} now -- "
                              "kept on hold, press Refill")
            return
        device_hold.release(did)
        try:
            self._force_scheduler(did)
        except Exception:
            _log.warning("[ERASE] scheduler not forced for turnstile %s", did, exc_info=True)
        if refill == REFILL_NOW:
            # Released and verified: a pass that cannot be queued now is only late (the next
            # scheduled pass refills), never a reason to call the run INCOMPLETE.
            try:
                requested = bool(worker.request_full_sync(reason="erase-refill"))
            except Exception as exc:
                _log.warning("[ERASE] refill pass not requested on turnstile %s", did,
                             exc_info=True)
                requested, why = False, str(exc)[:200]
            else:
                why = ""
            self._step("refill", requested, mode="now", pinScheme=str(scheme),
                       **({"error": why} if why else {}))
        else:
            self._step("refill", True, mode="auto", pinScheme=str(scheme))
        self._finish("DONE", release=False)

    def refill(self, device_id: int, body: Dict[str, Any], *,
               verify_password: Callable[[str], Tuple[bool, int, str]]) -> Tuple[int, Dict[str, Any]]:
        """The Refill button: reset the turnstile's records, release its hold, push it now.

        The page sends the pin scheme it showed (``expectedPinScheme``, read from /erase/holds);
        a scheme that moved since is refused. A hold kept because the scheme moved before any
        delete (``erase-scheme-moved``) is refused (409 ``HELD_SCHEME_MOVED``) until the scheme
        recorded now is the one its row records for the terminal (lane 1e, master review C0). The
        records are ALWAYS reset first (the hard-reset UPDATE, durable): a hold can come from a run
        that ended INCOMPLETE or was cut by a restart, and then every pin must be written again. A
        reset that fails keeps the hold."""
        did = int(device_id)
        body = dict(body or {})
        if device_hold.load_failed():
            return 503, {"ok": False, "code": "HOLDS_UNKNOWN",
                         "error": "the erase holds could not be read: every turnstile stays held"}
        with self._lock:
            if self._running and self._run and int(self._run.get("deviceId") or 0) == did:
                return 409, {"ok": False, "code": "RUN_IN_PROGRESS",
                             "error": "an erase of this turnstile is still running"}
            if did in self._refilling:
                return 409, {"ok": False, "code": "REFILL_IN_PROGRESS",
                             "error": "this turnstile is already being refilled"}
            self._refilling.add(did)
        try:
            return self._refill_marked(did, body, verify_password)
        finally:
            with self._lock:
                self._refilling.discard(did)

    @staticmethod
    def _hold_run_id(did: int) -> Tuple[bool, Optional[str]]:
        detail = device_hold.holds_detail().get(did)
        return (detail is not None), (detail or {}).get("runId")

    def _refill_marked(self, did: int, body: Dict[str, Any],
                       verify_password: Callable[[str], Tuple[bool, int, str]]
                       ) -> Tuple[int, Dict[str, Any]]:
        """Refill with this turnstile marked: no erase can start until it returns."""
        if not device_hold.is_held(did):
            return 409, {"ok": False, "code": "NOT_ON_HOLD", "error": "this turnstile is not on hold"}
        if "expectedPinScheme" not in body:
            return 400, {"ok": False, "code": "PIN_SCHEME_REQUIRED",
                         "error": "send the pin scheme the page showed (expectedPinScheme)"}
        expected = body.get("expectedPinScheme")
        expected = None if expected is None else str(expected)
        try:
            held_row, hold_run = self._hold_run_id(did)
        except Exception as exc:
            return 503, {"ok": False, "code": "HOLDS_UNKNOWN",
                         "error": f"the erase holds could not be read: {exc}"}
        # No lease or worker condition: releasing a hold writes nothing by itself. A turnstile
        # this PC no longer drives stays unwritten by the lease gate; one with no running worker
        # is refilled by the first pass once its worker starts.
        ok, status, error = verify_password(str(body.get("password") or ""))
        if not ok:
            return _password_refusal(status, error)
        # The password was a network call: look again (review round 2, R2-1).
        with self._lock:
            if self._running and self._run and int(self._run.get("deviceId") or 0) == did:
                return 409, {"ok": False, "code": "RUN_IN_PROGRESS",
                             "error": "an erase of this turnstile started meanwhile"}
        try:
            still_row, still_run = self._hold_run_id(did)
        except Exception as exc:
            return 503, {"ok": False, "code": "HOLDS_UNKNOWN",
                         "error": f"the erase holds could not be read: {exc}"}
        if (still_row, still_run) != (held_row, hold_run) or not device_hold.is_held(did):
            return 409, {"ok": False, "code": "HOLD_CHANGED",
                         "error": "the turnstile's hold changed meanwhile: read the page again"}
        try:
            scheme = self._pin_scheme_strict(did)
        except Exception as exc:
            return 503, {"ok": False, "code": "PIN_SCHEME_UNREADABLE",
                         "error": f"the turnstile's pin scheme could not be read: {exc}"}
        if scheme != expected:
            return 409, {"ok": False, "code": "PIN_SCHEME_CHANGED", "pinScheme": scheme,
                         "error": f"the pin scheme is {scheme} now, the page showed {expected}"}
        # A hold kept because the scheme moved before any delete (lane 1e, master review C0): the
        # terminal still holds every pin of the scheme the row records, and a full pass under
        # another one would write its pins beside them. Only under that scheme again -- from the
        # row, which a restart keeps (the run's finish note that said so does not survive one).
        try:
            detail = dict(device_hold.holds_detail().get(did) or {})
        except Exception as exc:
            return 503, {"ok": False, "code": "HOLDS_UNKNOWN",
                         "error": f"the erase holds could not be read: {exc}"}
        # Also a row still at ``erase-prep`` (review round 1 of lane 1e): no run is running (checked
        # above), so it is a stop whose durable move failed -- held this session, and its terminal
        # holds the scheme it records. With no recorded scheme it refills as before.
        reason = detail.get("reason")
        terminal = detail.get("terminalScheme")
        if (reason == device_hold.REASON_SCHEME_MOVED
                or (reason == device_hold.REASON_ERASE_PREP and terminal is not None)):
            if terminal is None or terminal != scheme:
                held = (f"it still holds the pins of the {terminal} scheme, and {scheme} is recorded "
                        f"now: a refill would write {scheme} pins beside them -- set the scheme back "
                        f"to {terminal}, then erase it again with 'hold' (or Refill, erasing nothing)"
                        if terminal is not None else
                        "which scheme its pins were written under is not recorded -- erase it again "
                        "with 'hold'")
                return 409, {"ok": False, "code": "HELD_SCHEME_MOVED", "pinScheme": scheme,
                             "terminalScheme": terminal,
                             "error": f"nothing was erased on this turnstile since its hold: {held}"}
        # What this refill will write, under the scheme it pushes (lane 1c, review F1): the erase
        # was checked under the scheme of its start, and the switch's own sync, or a switch during
        # a now/auto run, can change the roster since. Reported, never refused -- refusing leaves
        # the turnstile empty anyway -- except a kept administrator the refill would overwrite.
        recheck = self._refill_recheck(did, scheme, hold_run)
        clash = recheck["adminPins"]
        confirmed = body.get("confirmAdminPins")
        confirmed = {str(p) for p in confirmed} if isinstance(confirmed, list) else set()
        if clash and not set(clash) <= confirmed:
            return 409, {"ok": False, "code": "ADMIN_PIN_IN_ROSTER", "adminPins": clash,
                         "pinScheme": scheme,
                         "error": f"{len(clash)} terminal administrator pin(s) in the erase's backup "
                                  f"are also member pins under {scheme} ({clash[:5]}): the refill "
                                  "would write those members over them, privilege 0 -- this reads "
                                  "the backup, not the terminal: confirm once their numbers were "
                                  "changed on the terminal, or to have them replaced"}
        from app.core import db as _db
        try:
            invalidated = int(_db.invalidate_device_records(device_id=did, fingers_erased=False))
        except Exception as exc:
            _log.error("[ERASE] Refill of turnstile %s: records not reset, hold kept", did,
                       exc_info=True)
            return 500, {"ok": False, "code": "RECORDS_NOT_RESET",
                         "error": f"MonClub's records of this turnstile could not be reset: {exc}"}
        # The backups' 30 days count from now (NEW 1): marked BEFORE the release (review round 3).
        marked = _mark_refilled(self.backup_root(), did)
        device_hold.release(did)
        self._force_scheduler(did)
        worker = self._worker(did)
        requested = False
        if worker is not None:
            # Released: the whole roster waits until the refill pass counts (review F0).
            self._set_waiting(worker, did)
            try:
                requested = bool(worker.request_full_sync(reason="erase-refill"))
            except Exception:
                _log.warning("[ERASE] refill pass not requested on turnstile %s", did, exc_info=True)
        _log.warning("[ERASE] turnstile %s released by Refill (pinScheme=%s, %d record(s) reset, "
                     "pass requested=%s)", did, scheme, invalidated, requested)
        try:
            _tel.event("ERASE_STEP", run="refill", device_id=did, step="refill_pressed", ok=True,
                       pin_scheme=str(scheme), requested=requested, invalidated=invalidated)
        except Exception:
            pass
        if recheck["refill"]["problem"] or clash or recheck["adminCheck"] == "UNREADABLE":
            _log.warning("[ERASE] Refill of turnstile %s under %s: %s member(s), %s withheld, "
                         "problem=%s, %d administrator pin(s) overwritten (confirmed), admins %s",
                         did, scheme, recheck["refill"]["members"], recheck["refill"]["withheld"],
                         recheck["refill"]["problem"], len(clash), recheck["adminCheck"])
        return 200, {"ok": True, "pinScheme": scheme, "passRequested": requested,
                     "invalidated": invalidated, "backupsMarked": marked,
                     "refill": recheck["refill"], "adminPins": clash,
                     "adminCheck": recheck["adminCheck"]}

    def _refill_recheck(self, did: int, scheme: Optional[str],
                        hold_run: Optional[str]) -> Dict[str, Any]:
        """Refill's own check (lane 1c, review F1), under ``scheme`` -- the scheme it verified
        and pushes. ``refill``: members and withheld rows of the refill roster, ``problem``
        (REFILL_SOURCE_MISSING / _STALE / _EMPTY, REFILL_WITHHELD) and the list's age -- to
        report. ``adminPins``: the MB2000 administrators the hold's run kept on the terminal
        (from its verified backup: Refill needs no connection) whose pin is also a member pin
        of that roster -- the push would write the member over them, privilege 0 (review C4).
        ``adminCheck``: CHECKED, NOT_APPLICABLE (a C3 has no administrators) or UNREADABLE (no
        backup to read them from, or no roster to compare)."""
        refill: Dict[str, Any] = {"scheme": scheme, "members": None, "withheld": None,
                                  "problem": None}
        refill.update(self._sync_staleness())
        device = self._device(did)
        roster = None
        try:
            from app.core import db as _db
            cache = _db.load_sync_cache()
            if cache is not None and device:
                roster = refill_roster(device, cache, scheme=scheme)
        except Exception:
            _log.warning("[ERASE] Refill of turnstile %s: refill roster not computed", did,
                         exc_info=True)
        if roster is None:
            refill["problem"] = "REFILL_SOURCE_MISSING"
        else:
            refill.update(members=roster["members"], withheld=roster["withheld"])
            refill["problem"] = ("REFILL_SOURCE_STALE" if refill["staleWhy"]
                                 else "REFILL_SOURCE_EMPTY" if not roster["members"]
                                 else "REFILL_WITHHELD" if roster["withheld"] else None)
        proto = _protocol_of(device) if device else None
        if proto == PROTO_PULLSDK:
            return {"refill": refill, "adminPins": [], "adminCheck": "NOT_APPLICABLE"}
        backup_proto, admins = self._held_run_admins(did, hold_run)
        if proto is None and backup_proto == PROTO_PULLSDK:
            # No device row any more: the backup says a C3 -- no administrators (review round 1).
            return {"refill": refill, "adminPins": [], "adminCheck": "NOT_APPLICABLE"}
        if admins is None or roster is None:
            return {"refill": refill, "adminPins": [], "adminCheck": "UNREADABLE"}
        return {"refill": refill, "adminPins": sorted(admins & set(roster["pins"]), key=_pin_key),
                "adminCheck": "CHECKED"}

    def _held_run_admins(self, did: int, run_id: Optional[str]
                         ) -> Tuple[Optional[str], Optional[set]]:
        """(protocol, administrators) from the hold's run's verified backup: the administrators
        (privilege > 0) an MB2000 users erase kept -- as the backup lists them, since Refill does
        not read the terminal (its cables may be out): an administrator whose number was changed
        on the terminal since still reads here, one enrolled since does not. Administrators None on
        a C3 backup, or when the backup cannot be read (protocol None then)."""
        if not run_id:
            return None, None
        try:
            path = self.backup_root() / f"{run_id}_device{int(did)}" / "backup.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            proto = data.get("protocol")
            if proto != PROTO_STANDALONE:
                return (str(proto) if proto else None), None
            return proto, {str(u["pin"]) for u in data.get("users") or []
                           if int(u.get("privilege") or 0) > 0}
        except Exception:
            _log.warning("[ERASE] backup of run %s (turnstile %s) not read for the Refill check",
                         run_id, did, exc_info=True)
            return None, None


BACKUP_KEEP_DAYS = 30
_RUN_DIR_NAME = re.compile(r"^(\d{8}-\d{6})-[0-9a-f]{6}_device(\d+)$")
# No run can predate the wizard (September 2026): a run id before this is a PC clock that was
# wrong at the time (a dead CMOS battery), and its age cannot be told -- never pruned
# automatically (lane 1b review round 2).
_NO_RUN_BEFORE = "20260901"
REFILLED_MARK = "refilled_at.txt"


def _mark_refilled(root: Path, device_id: int) -> bool:
    """Refill is about to release this turnstile: its run folders' 30 days count from NOW, not
    from the erase (a turnstile can stay held longer). Written BEFORE the release, so no prune can
    find the folder unheld and unmarked (review round 3). One small file per folder. Returns
    whether every folder of the turnstile got it; a failure is logged at ERROR and reported by
    Refill, never a reason to keep the turnstile empty."""
    ok = True
    try:
        if not root.is_dir():
            return True
        # When Refill released it, on the corrected clock where there is one (lane 1c, review
        # F2): the prune reads this, not the file's mtime.
        at, corrected = _corrected_epoch()
        stamp = json.dumps({"at": at, "corrected": corrected, "text": _now_text()}).encode("ascii")
        for folder in root.iterdir():
            m = _RUN_DIR_NAME.match(folder.name)
            if m and int(m.group(2)) == int(device_id) and folder.is_dir():
                try:
                    (folder / REFILLED_MARK).write_bytes(stamp)
                except Exception:
                    ok = False
                    _log.error("[ERASE] refill mark not written in %s: its backup may be "
                               "deleted 30 days after the erase, not after Refill", folder.name,
                               exc_info=True)
    except Exception:
        _log.error("[ERASE] refill marks not written for turnstile %s", device_id, exc_info=True)
        return False
    return ok


# The prune's clock guards (lane 1c, review F2), both at the owner's "more than one day".
PRUNE_MAX_CLOCK_OFFSET_SEC = 86400.0
PRUNE_FUTURE_TOLERANCE_SEC = 86400.0


def _prune_now() -> Tuple[Optional[float], str]:
    """(now, why) for the prune: the server-corrected time when this process has a measurement
    of the server's clock, else the PC's; None when that measurement puts the PC clock more than
    a day off the server's -- then no age can be trusted and nothing is pruned. With no
    measurement (v2 off: no sample ever) this is the PC clock alone [CODE]."""
    try:
        from app.core.v2 import server_clock as _sc
        clk = _sc.get_default()
        if clk is not None and clk.has_sample():
            off = clk.offset()
            if off is not None and abs(float(off)) > PRUNE_MAX_CLOCK_OFFSET_SEC:
                return None, f"the PC clock is {float(off):+.0f} s off the server's"
            return float(clk.now()), ""
    except Exception:
        _log.warning("[ERASE] server clock unreadable for the backup prune", exc_info=True)
    return time.time(), ""


def _recorded_epoch(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _folder_times(folder: Path, run_stamp: str) -> List[float]:
    """When a run folder was last dated. A run of lane 1c on: the epochs it recorded -- the run's
    start and last write (``run.json``) and the refill mark's ``at`` -- on the corrected clock
    where there was a measurement, never the files' mtimes. An earlier run (none recorded): its
    run id's local time and every file's mtime, the refill mark's included, as before."""
    times: List[float] = []
    try:
        rec = json.loads((folder / "run.json").read_text(encoding="utf-8"))
        for key in ("startedAtEpoch", "writtenAtEpoch"):
            at = _recorded_epoch(rec.get(key)) if isinstance(rec, dict) else None
            if at is not None:
                times.append(at)
    except Exception:
        pass
    mark = folder / REFILLED_MARK
    mark_at: Optional[float] = None
    if mark.is_file():
        try:
            mark_at = _recorded_epoch(json.loads(mark.read_text(encoding="utf-8")).get("at"))
        except Exception:
            mark_at = None                       # lane 1b's plain-text mark: its mtime
        if mark_at is None:
            mark_at = mark.stat().st_mtime
    if not times:
        times = [time.mktime(time.strptime(run_stamp, "%Y%m%d-%H%M%S"))]
        times += [f.stat().st_mtime for f in folder.iterdir() if f.is_file()]
    if mark_at is not None:
        times.append(mark_at)
    return times


def prune_erase_backups(root: Optional[Path] = None, *, now: Optional[float] = None,
                        keep_run_id: Optional[str] = None) -> List[str]:
    """Delete erase run folders (backup + run.json) older than ``BACKUP_KEEP_DAYS`` (owner decision
    2026-09-27, guide §3.2h). The age counts from the LATEST of: the run's start (its run id, local
    time) and the last write of any file in its folder -- the run's end, and the refill mark Refill
    writes -- so a backup stays 30 days after Refill was pressed. NEVER: a folder whose
    name is not a run's; a run id before ``_NO_RUN_BEFORE`` (a wrong clock); the run in progress
    (``keep_run_id``); any run of a turnstile still HELD -- while the holds cannot be read every
    turnstile reads held, so nothing goes. A run whose ``run.json`` is unreadable or still says
    ``RUNNING`` goes too once old enough and not held: no run of this process is that old, so it
    is a run a power cut or a crash ended -- its biometric copy is not kept forever (review round
    2). Logged by run id, turnstile and state only -- never a name, card or template. Returns the
    run ids deleted. Never raises."""
    deleted: List[str] = []
    try:
        base = Path(root) if root is not None else _default_backup_root()
        if not base.is_dir():
            return deleted
        if now is None:
            now, why = _prune_now()
            if now is None:
                _log.warning("[ERASE] erase backups not pruned: %s -- their ages cannot be told",
                             why)
                return deleted
        now = float(now)
        cutoff = now - BACKUP_KEEP_DAYS * 86400.0
        for folder in sorted(base.iterdir()):
            try:
                m = _RUN_DIR_NAME.match(folder.name)
                if not m or not folder.is_dir():
                    continue
                run_id = folder.name.split("_device")[0]
                did = int(m.group(2))
                if keep_run_id and run_id == keep_run_id:
                    continue
                if m.group(1)[:8] < _NO_RUN_BEFORE:
                    continue
                if (folder / KEEP_MARK).exists():
                    # It erased people the refill does not put back: their only copy (lane 1c).
                    continue
                # The hold before the times (review nit): Refill writes its mark BEFORE it
                # releases, so a folder seen unheld here already carries that mark.
                if device_hold.is_held(did):
                    continue
                newest = max(_folder_times(folder, m.group(1)))
                if newest > now + PRUNE_FUTURE_TOLERANCE_SEC:
                    # Dated by a clock ahead of this one (the PC clock went back since): its age
                    # cannot be told -- kept (lane 1c, review F2).
                    _log.warning("[ERASE] backup of run %s (turnstile %s) not pruned: dated %.0f s "
                                 "in the future of this clock", run_id, did, newest - now)
                    continue
                if newest >= cutoff:
                    continue
                if device_hold.is_held(did):
                    continue                     # held meanwhile: never delete a held turnstile's
                try:
                    state = str(json.loads((folder / "run.json").read_text(encoding="utf-8"))
                                .get("state") or "UNKNOWN")
                except Exception:
                    state = "UNREADABLE"
                shutil.rmtree(folder)
                deleted.append(run_id)
                _log.warning("[ERASE] backup of run %s (turnstile %s, %s) deleted: older than %d "
                             "days", run_id, did, state, BACKUP_KEEP_DAYS)
                try:
                    _tel.event("ERASE_STEP", run=run_id, device_id=did, step="backup_deleted",
                               ok=True, state=state)
                except Exception:
                    pass
            except Exception:
                _log.warning("[ERASE] erase backup folder %s not pruned", folder.name, exc_info=True)
    except Exception:
        _log.warning("[ERASE] erase backups not pruned", exc_info=True)
    return deleted


# The start-up prune waits this long, at most, for this process to measure the server's clock
# (lane 1d, master review F1). Chosen, not measured: the v2 runtime installs its clock 12 s after
# launch (access/runtime.py) and asks the server at once; a PC whose server never answers (v2 off --
# every gym today -- or no internet) prunes on its own clock after it, as the prune after a run does.
STARTUP_PRUNE_CLOCK_WAIT_SEC = 180.0
STARTUP_PRUNE_POLL_SEC = 5.0


def prune_erase_backups_at_startup(root: Optional[Path] = None, *,
                                   wait_sec: float = STARTUP_PRUNE_CLOCK_WAIT_SEC,
                                   poll_sec: float = STARTUP_PRUNE_POLL_SEC,
                                   sleep: Callable[[float], None] = time.sleep,
                                   mono: Callable[[], float] = time.monotonic) -> List[str]:
    """The prune ``app.py`` starts at every start-up, on its own thread (lane 1d, master review F1).

    The prune after a run judges the PC clock against the server's (``_prune_now``: nothing goes
    while the PC clock is more than a day off). At start-up there was no server clock yet -- the
    v2 runtime sets it about 12 s later -- so the prune that runs every morning after the power
    comes back used the PC clock alone, on v2 PCs too. It now waits, at most ``wait_sec``, until
    this process has a measurement of the server's clock (``server_clock.get_default()`` with a
    sample), then runs the same ``prune_erase_backups``. A PC that never gets one prunes on its own
    clock after the wait, exactly as the prune after a run does -- skipping it instead would keep
    biometric backups past the owner's 30 days at every gym today. Never raises."""
    try:
        deadline = mono() + max(0.0, float(wait_sec))
        while True:
            try:
                from app.core.v2 import server_clock as _sc
                clk = _sc.get_default()
                if clk is not None and clk.has_sample():
                    break
            except Exception:
                _log.warning("[ERASE] server clock unreadable before the start-up prune",
                             exc_info=True)
                break
            if mono() >= deadline:
                _log.info("[ERASE] start-up prune: no measurement of the server's clock after "
                          "%.0f s -- the PC clock alone, as after a run", float(wait_sec))
                break
            sleep(max(0.0, float(poll_sec)))
    except Exception:
        _log.warning("[ERASE] start-up prune: the wait for the server clock failed", exc_info=True)
    return prune_erase_backups(root)


def drop_keep_marks_of_unstarted_runs(released: Dict[int, Optional[str]],
                                      root: Optional[Path] = None) -> List[str]:
    """The start-up release of the holds (``device_hold.load``) names the runs that stopped before
    their first delete command -- their hold row was still ``erase-prep``, whether the start
    released it or kept it because the scheme moved (lane 1e). Such a run erased nobody, yet
    under lanes 1c-1d the keep mark came BEFORE the erase record (``_begin_erase``), and a power
    cut or a kill between the two left it; the prune never deletes a marked folder: a biometric
    backup kept for good for no one (lane 1d, master review F3). The mark goes; the 30 days apply
    as to any run. The release is the only proof that no delete ran -- never ``run.json``, whose
    writes are best effort. Since lane 1e the mark is written after the erase record
    (``_write_keep_mark``), so a run of this build leaves none there: this is for folders an
    earlier build wrote. Returns the run ids whose mark went. Never raises."""
    dropped: List[str] = []
    try:
        base = Path(root) if root is not None else _default_backup_root()
        for did, run_id in sorted((released or {}).items()):
            if not run_id:
                continue
            try:
                mark = base / f"{run_id}_device{int(did)}" / KEEP_MARK
                if mark.is_file():
                    mark.unlink()
                    dropped.append(str(run_id))
                    _log.warning("[ERASE] run %s (turnstile %s) stopped before any delete: its "
                                 "keep mark is removed, its backup goes after 30 days as usual",
                                 run_id, did)
            except Exception:
                _log.warning("[ERASE] keep mark of run %s not removed: its backup stays", run_id,
                             exc_info=True)
    except Exception:
        _log.warning("[ERASE] keep marks of the runs released at start-up not checked",
                     exc_info=True)
    return dropped


def _begin_erase(did: int, run_id: str, keep_pins: List[str]) -> int:
    """``db.begin_device_erase``: the hold to ERASE and the push results reset, one durable
    transaction (a module function so a test can make it fail)."""
    from app.core import db as _db
    return int(_db.begin_device_erase(device_id=did, run_id=run_id, keep_pins=keep_pins))


def _redact_passwords(table: str, rows: List[Dict[str, Any]],
                      redacted: Dict[str, int]) -> List[Dict[str, Any]]:
    """Copies of ``rows`` with every password value emptied (key kept, any case): the backup
    is for MonClub's own refill, which never needs one. Counts the values emptied."""
    out = []
    for row in rows or []:
        row = dict(row)
        for key in list(row):
            if str(key).lower() == "password":
                if str(row[key] or ""):
                    redacted[f"{table}.{key}"] = redacted.get(f"{table}.{key}", 0) + 1
                row[key] = ""
        out.append(row)
    return out


def _flat(counts: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (counts.get("tables") or {}).items():
        out[f"n_{k}"] = -1 if v is None else int(v)
    for k, v in (counts.get("extra") or {}).items():
        if v is not None:
            out[f"n_{k}"] = int(v)
    return out


def _write_file_durably(path: Path, data: bytes) -> None:
    """Write, flush and fsync a temp file, then rename it over ``path`` (atomic on Windows too)."""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


_WIZARDS_LOCK = threading.Lock()


def get_wizard(app: Any) -> EraseWizard:
    with _WIZARDS_LOCK:
        wiz = getattr(app, "_erase_wizard", None)
        if not isinstance(wiz, EraseWizard):
            wiz = EraseWizard(app)
            try:
                setattr(app, "_erase_wizard", wiz)
            except Exception:
                pass
        return wiz
