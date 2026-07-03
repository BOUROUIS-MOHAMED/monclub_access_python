"""MB2000 on-site hardware gate runner.

Scripted version of the hardware gates in docs/plans/mb2000_zk_standalone_driver_plan.md
(section 6). Run ON THE GYM PC with the same 32-bit Python runtime the Access app
uses — the whole point of GATE 1 is proving in-process COM works in that exact
environment, so every gate drives the REAL ZKStandaloneDevice driver, not a copy.

Prerequisites on the gym PC:
  * 32-bit Python (the app runtime) — `preflight` verifies.
  * zkemkeeper.dll registered: from an ADMIN 32-bit console:
        C:\\Windows\\SysWOW64\\regsvr32.exe <path>\\zkemkeeper.dll
    (SDK: github.com/ZKTeco/Standalone-SDK, 32-bit 6.2.4.11)
  * This repo present; run from the repo root:
        python tools\\mb2000_onsite_gates.py preflight
        python tools\\mb2000_onsite_gates.py g1 --ip 192.168.x.x
        ...

Gate order matters (see the plan): preflight -> g1 -> g2 -> g3 (BEFORE any mass
enrollment) -> g4 -> g5/g5b -> g6. Record every output — the values printed by g2
become the driver's mapping constants.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import threading
import time
from pathlib import Path

# Make the repo importable when run as `python tools/mb2000_onsite_gates.py`.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _hr(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def _result(gate: str, ok: bool, detail: str = "") -> None:
    print(f"\n>>> {gate}: {'PASS' if ok else 'FAIL'}{(' — ' + detail) if detail else ''}")


def _mk_driver(args, *, quiet: bool = False):
    from app.sdk.zk_standalone import ZKStandaloneDevice

    payload = {
        "id": getattr(args, "device_id", 0) or 0,
        "name": f"gate-{args.ip}",
        "ipAddress": args.ip,
        "portNumber": args.port,
        "password": getattr(args, "commkey", "") or "",
        "doorPresets": [{"doorNumber": 1, "direction": getattr(args, "direction", None)}],
    }
    drv = ZKStandaloneDevice(payload)
    if quiet:
        # gates print their own tables; silence the driver's info chatter
        import logging
        drv.logger = logging.getLogger("gate-quiet")
        drv.logger.setLevel(logging.ERROR)
    return drv


# --------------------------------------------------------------------------- #
# preflight — no device needed
# --------------------------------------------------------------------------- #

def cmd_preflight(args) -> int:
    _hr("PREFLIGHT — environment checks (no device needed)")
    ok = True

    bits = struct.calcsize("P") * 8
    print(f"[1] Python bitness: {bits}-bit  ({sys.version.split()[0]})")
    if bits != 32:
        ok = False
        print("    !! zkemkeeper.dll is 32-bit COM — run this with the app's 32-bit")
        print("       runtime or in-process COM cannot work (this is the prod env test).")

    try:
        import pythoncom  # noqa: F401
        import win32com.client  # noqa: F401
        print("[2] pywin32 import: OK")
    except Exception as exc:
        ok = False
        print(f"[2] pywin32 import FAILED: {exc}")

    print("[3] zkemkeeper ProgID creation (needs regsvr32 done):")
    created = False
    try:
        import pythoncom
        import win32com.client as w32
        pythoncom.CoInitialize()
        try:
            for prog_id in ("zkemkeeper.ZKEM", "zkemkeeper.CZKEM", "zkemkeeper.ZKEM.1"):
                try:
                    w32.Dispatch(prog_id)
                    print(f"    OK via ProgID {prog_id!r}")
                    created = True
                    break
                except Exception as exc:
                    print(f"    {prog_id!r}: {type(exc).__name__}")
        finally:
            pythoncom.CoUninitialize()
    except Exception as exc:
        print(f"    COM init failed: {exc}")
    if not created:
        ok = False
        print("    !! Register the DLL: C:\\Windows\\SysWOW64\\regsvr32.exe zkemkeeper.dll (admin)")

    _result("PREFLIGHT", ok)
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# G1 — in-process COM viability: connect + live events through the REAL driver
# --------------------------------------------------------------------------- #

def cmd_g1(args) -> int:
    _hr(f"GATE 1 — connect + live events via ZKStandaloneDevice ({args.ip}:{args.port})")
    drv = _mk_driver(args)
    t0 = time.monotonic()
    if not drv.connect():
        _result("G1", False, "Connect_Net failed (check IP/port/comm key, device COMM menu)")
        return 1
    print(f"connected in {time.monotonic() - t0:.1f}s — now PRESENT A FINGER and A CARD.")
    print(f"listening {args.seconds}s for OnAttTransactionEx events...\n")

    seen = 0
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline:
            for evt in drv.poll_rtlog_once():
                seen += 1
                print(f"  EVENT #{seen}: cardNo={evt['cardNo']!r} eventType={evt['eventType']!r} "
                      f"time={evt['eventTime']} raw={json.dumps(evt['rawRow'], default=str)}")
            time.sleep(0.2)
    finally:
        drv.disconnect()

    ok = seen > 0
    _result("G1", ok,
            f"{seen} event(s) received in-process" if ok else
            "connected but NO events — if punches were made, in-process COM sink is "
            "not delivering: fall back to the sidecar design (plan section 4.6)")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# G2 — event fidelity table (fills the driver's mapping constants)
# --------------------------------------------------------------------------- #

_G2_CHECKLIST = [
    "valid FINGERPRINT punch (enrolled finger)",
    "valid CARD punch (enrolled card)",
    "UNKNOWN card (not on the device)",
    "UNENROLLED finger",
    "same punch on an ENTRY unit vs the EXIT unit (run per terminal)",
]


def cmd_g2(args) -> int:
    _hr(f"GATE 2 — event fidelity recorder ({args.ip}) — perform each scenario:")
    for i, item in enumerate(_G2_CHECKLIST, 1):
        print(f"   {i}. {item}")
    print(f"\nrecording for {args.seconds}s; every event prints one table row.")
    print("RECORD THIS TABLE — it defines the production VerifyMethod/AttState maps.\n")

    drv = _mk_driver(args, quiet=True)
    if not drv.connect():
        _result("G2", False, "connect failed")
        return 1
    hdr = f"{'#':>3} {'pin':>10} {'invalid':>7} {'attState':>8} {'verifyMethod':>12} {'time':>20} mapped_scan_mode"
    print(hdr); print("-" * len(hdr))
    n = 0
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline:
            for evt in drv.poll_rtlog_once():
                n += 1
                raw = evt["rawRow"]
                print(f"{n:>3} {raw.get('pin', ''):>10} "
                      f"{str(evt['eventType'] != '0'):>7} {str(raw.get('attState')):>8} "
                      f"{str(raw.get('verifyMethod')):>12} {evt['eventTime']:>20} "
                      f"{raw.get('scan_mode_hint')}")
            time.sleep(0.2)
    finally:
        drv.disconnect()
    _result("G2", n > 0, f"{n} rows recorded — photograph/copy this table")
    return 0


# --------------------------------------------------------------------------- #
# G3 — template portability: desk-enrolled (ZK9500) template -> terminal match
# --------------------------------------------------------------------------- #

def cmd_g3(args) -> int:
    _hr("GATE 3 — TEMPLATE PORTABILITY (run BEFORE any mass enrollment!)")
    templates: list[dict] = []
    if args.template_file:
        data = Path(args.template_file).read_text(encoding="utf-8").strip()
        templates = [{"fingerId": args.finger, "templateVersion": 10,
                      "templateData": data, "templateSize": len(data)}]
        print(f"template: {args.template_file} ({len(data)} chars, finger {args.finger})")
    elif args.pin_from_db:
        from app.core.db import list_fingerprints_by_pins
        recs = list_fingerprints_by_pins(pins={str(args.pin)})
        for r in recs:
            templates.append({
                "fingerId": int(getattr(r, "finger_id", 0) or 0),
                "templateVersion": int(getattr(r, "template_version", 10) or 10),
                "templateData": str(getattr(r, "template_data", "") or ""),
                "templateSize": int(getattr(r, "template_size", 0) or 0),
            })
        print(f"loaded {len(templates)} template(s) for pin {args.pin} from the local DB")
    if not templates:
        _result("G3", False, "no template — enroll at the desk first (app EnrollDialog / "
                             "enroll_3_samples), then pass --pin-from-db or --template-file")
        return 1

    drv = _mk_driver(args)
    if not drv.connect():
        _result("G3", False, "connect failed")
        return 1
    try:
        res = drv.push_roster(
            [{"pin": str(args.pin), "name": args.name, "card": args.card or ""}],
            {str(args.pin): templates},
        )
        print(f"push result: {json.dumps(res)}")
        if not res.get("ok"):
            _result("G3", False, "upload failed — record the errors above")
            return 1
        print("\nNOW: place the ENROLLED FINGER on the terminal sensor.")
        print(f"listening {args.seconds}s for the verification event...")
        deadline = time.monotonic() + args.seconds
        matched = False
        while time.monotonic() < deadline:
            for evt in drv.poll_rtlog_once():
                raw = evt["rawRow"]
                print(f"  EVENT: pin={raw.get('pin')!r} verifyMethod={raw.get('verifyMethod')} "
                      f"invalid={evt['eventType'] != '0'}")
                if str(raw.get("pin")) == str(args.pin) and evt["eventType"] == "0":
                    matched = True
            if matched:
                break
            time.sleep(0.2)
    finally:
        drv.disconnect()

    _result("G3", matched,
            "desk-enrolled template MATCHES on the terminal — enrollment workflow stands" if matched
            else "no match — MB2000 may require ON-DEVICE enrollment (plan fallback: "
                 "StartEnrollEx); decide the desk workflow BEFORE enrolling members")
    return 0 if matched else 1


# --------------------------------------------------------------------------- #
# G4 — ACUnlock / relay wiring
# --------------------------------------------------------------------------- #

def cmd_g4(args) -> int:
    _hr(f"GATE 4 — ACUnlock relay test ({args.ip}) — listen for the relay click")
    drv = _mk_driver(args)
    if not drv.connect():
        _result("G4", False, "connect failed")
        return 1
    try:
        drv.supports_open_door = True  # gate-only override of the shipped default
        ok = drv.open_door(door_id=1, pulse_time_ms=args.pulse_ms)
        print(f"ACUnlock returned: {ok}")
        print("Did the relay click AND the turnstile release? (verify wiring too)")
    finally:
        drv.disconnect()
    _result("G4", bool(ok),
            "if the turnstile physically opened, flip supports_open_door=True in "
            "app/sdk/zk_standalone.py (or make it capability-driven) in the next build"
            if ok else "SDK refused or unsupported — leave open_door disabled (design degrades fine)")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# G5 — 3-terminal soak + leak watch;  G5b — second-connection probe
# --------------------------------------------------------------------------- #

def _proc_stats() -> str:
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        h = k32.GetCurrentProcess()
        count = wintypes.DWORD()
        k32.GetProcessHandleCount(h, ctypes.byref(count))

        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
        psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb)
        return (f"handles={count.value} ws_mb={pmc.WorkingSetSize / 1048576:.1f} "
                f"private_mb={pmc.PagefileUsage / 1048576:.1f}")
    except Exception as exc:  # pragma: no cover
        return f"stats unavailable: {exc}"


def cmd_g5(args) -> int:
    ips = [s.strip() for s in args.ips.split(",") if s.strip()]
    _hr(f"GATE 5 — soak: hold {len(ips)} connection(s) {args.minutes} min, watch for leaks")
    drivers = []
    counts = {}
    for ip in ips:
        ns = argparse.Namespace(ip=ip, port=args.port, commkey=args.commkey,
                                device_id=0, direction=None)
        drv = _mk_driver(ns, quiet=True)
        ok = drv.connect()
        print(f"  {ip}: {'connected' if ok else 'CONNECT FAILED'}")
        if ok:
            drivers.append((ip, drv))
            counts[ip] = 0
    if not drivers:
        _result("G5", False, "nothing connected")
        return 1
    print(f"\nbaseline: {_proc_stats()}")
    print("punch cards/fingers on all terminals during the soak.\n")
    t_end = time.monotonic() + args.minutes * 60
    next_report = time.monotonic() + 60
    try:
        while time.monotonic() < t_end:
            for ip, drv in drivers:
                counts[ip] += len(drv.poll_rtlog_once())
            if time.monotonic() >= next_report:
                next_report += 60
                alive = all(drv.is_connected for _, drv in drivers)
                print(f"[{time.strftime('%H:%M:%S')}] events={dict(counts)} "
                      f"alive={alive} {_proc_stats()}")
            time.sleep(0.2)
    finally:
        for _, drv in drivers:
            drv.disconnect()
    print(f"\nfinal:    {_proc_stats()}")
    _result("G5", True, "PASS only if handles/private_mb stayed FLAT and events flowed "
                        "on all terminals the whole soak — compare baseline vs final")
    return 0


def cmd_g5b(args) -> int:
    _hr(f"GATE 5b — second-connection probe ({args.ip}) — run while g1/g5 holds the 1st")
    drv = _mk_driver(args)
    ok = drv.connect()
    print(f"second Connect_Net: {'succeeded' if ok else 'failed/refused'}")
    if ok:
        print("check the FIRST console: did its event stream survive, or was it kicked?")
        time.sleep(args.seconds)
        drv.disconnect()
    _result("G5b", True, "record the outcome: coexists / refuses / KICKS the first "
                         "(if it kicks: hard rule — no other tool may ever connect directly)")
    return 0


# --------------------------------------------------------------------------- #
# G6 — card number space / reader type
# --------------------------------------------------------------------------- #

def cmd_g6(args) -> int:
    _hr(f"GATE 6 — card number space ({args.ip}) — scan ONE known gym card")
    drv = _mk_driver(args, quiet=True)
    if not drv.connect():
        _result("G6", False, "connect failed")
        return 1
    print(f"scan the card now (listening {args.seconds}s)...")
    values = []
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline and not values:
            for evt in drv.poll_rtlog_once():
                raw = evt["rawRow"]
                values.append((evt["cardNo"], raw.get("pin"), raw.get("verifyMethod")))
                print(f"  cardNo={evt['cardNo']!r} pin={raw.get('pin')!r} "
                      f"verifyMethod={raw.get('verifyMethod')}")
            time.sleep(0.2)
    finally:
        drv.disconnect()
    if not values:
        _result("G6", False, "no card event received")
        return 1
    if args.expect:
        got = values[0][0]
        match = str(got).lstrip("0") == str(args.expect).lstrip("0")
        _result("G6", match,
                f"device value {got!r} vs expected {args.expect!r} — "
                + ("same number space as the C3 pipeline" if match else
                   "MISMATCH: add a card normalization layer in the driver before roster push"))
        return 0 if match else 1
    _result("G6", True, "compare the value above against the card number stored by the "
                        "existing enrollment pipeline for the SAME card (pass --expect)")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _common(p: argparse.ArgumentParser, ip_required: bool = True) -> None:
    p.add_argument("--ip", required=ip_required)
    p.add_argument("--port", type=int, default=4370)
    p.add_argument("--commkey", default="", help="device COMM key/password if set")
    p.add_argument("--device-id", type=int, default=0)
    p.add_argument("--direction", default=None, help="IN|OUT lane label for events")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="mb2000_onsite_gates",
        description="MB2000 on-site hardware gates (see docs/plans/mb2000_zk_standalone_driver_plan.md §6)",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("preflight", help="bitness + pywin32 + zkemkeeper registration (no device)")

    p = sub.add_parser("g1", help="in-process COM: connect + live events"); _common(p)
    p.add_argument("--seconds", type=int, default=60)

    p = sub.add_parser("g2", help="event fidelity table recorder"); _common(p)
    p.add_argument("--seconds", type=int, default=300)

    p = sub.add_parser("g3", help="template portability (BEFORE mass enrollment)"); _common(p)
    p.add_argument("--pin", required=True, help="test user pin (numeric, <=9 digits)")
    p.add_argument("--name", default="GATE3 TEST")
    p.add_argument("--card", default="", help="optional test card number")
    p.add_argument("--finger", type=int, default=6)
    p.add_argument("--template-file", default=None, help="file containing the base64 template")
    p.add_argument("--pin-from-db", action="store_true",
                   help="load the template(s) for --pin from the local fingerprints DB")
    p.add_argument("--seconds", type=int, default=90, help="verify-listen window")

    p = sub.add_parser("g4", help="ACUnlock relay test"); _common(p)
    p.add_argument("--pulse-ms", type=int, default=1000)

    p = sub.add_parser("g5", help="multi-terminal soak + leak watch")
    p.add_argument("--ips", required=True, help="comma-separated terminal IPs")
    p.add_argument("--port", type=int, default=4370)
    p.add_argument("--commkey", default="")
    p.add_argument("--minutes", type=int, default=60)

    p = sub.add_parser("g5b", help="second-connection probe (run alongside g1/g5)"); _common(p)
    p.add_argument("--seconds", type=int, default=30)

    p = sub.add_parser("g6", help="card number space check"); _common(p)
    p.add_argument("--seconds", type=int, default=60)
    p.add_argument("--expect", default=None, help="card number the C3 pipeline stores for this card")

    args = ap.parse_args(argv)
    return {
        "preflight": cmd_preflight,
        "g1": cmd_g1, "g2": cmd_g2, "g3": cmd_g3,
        "g4": cmd_g4, "g5": cmd_g5, "g5b": cmd_g5b, "g6": cmd_g6,
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
