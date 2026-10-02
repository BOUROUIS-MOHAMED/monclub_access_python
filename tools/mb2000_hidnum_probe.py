"""MB2000 field probe F2 (ULTRA merge plan 3, spec D10 and section 12): does the terminal's
``OnHIDNum`` event carry the number of a card the terminal does NOT hold?

If it does, cards decided by the PC can open on MB2000 too (spec D10). Today the driver registers
only ``OnAttTransactionEx`` (``app/sdk/zk_standalone.py``: ``RegEvent(1, 1)``), and a card the
terminal does not hold arrives as a refused punch with no card number.

What this tool does, and only this: connect to ONE terminal over zkemkeeper, register
``OnAttTransactionEx`` AND ``OnHIDNum`` (mask ``1 | 2048``; the 2048 bit is from this repo's own
driver plan, ``docs/plans/mb2000_zk_standalone_driver_plan.md`` section 5 "add 2048 OnHIDNum only if
needed" -- [UNVERIFIED -- hardware]), print every event with its raw arguments, and write them to a
CSV. It writes nothing to the terminal. It is not imported by MonClub Access.

Run it ON THE GYM PC with the app's 32-bit Python, with MonClub Access CLOSED (a second zkemkeeper
connection to a held terminal is untested, driver plan gate G5):

    python tools\\mb2000_hidnum_probe.py --ip 192.168.1.247 --seconds 120 --out hidnum_probe.csv

The checklist is ``docs/field/ultra_merge_release1_field_tests.md`` section F2.
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from typing import Any, Callable, List, Optional, Tuple

REGEVENT_ATT_TRANSACTION = 1
REGEVENT_HID_NUM = 2048          # [UNVERIFIED -- hardware]: driver plan section 5
REGEVENT_MASK = REGEVENT_ATT_TRANSACTION | REGEVENT_HID_NUM
PROG_IDS = ("zkemkeeper.ZKEM", "zkemkeeper.CZKEM", "zkemkeeper.ZKEM.1")


class Recorder:
    """Every event the sink receives: (seconds since start, event name, raw arguments)."""

    def __init__(self, mono: Callable[[], float] = time.monotonic, echo: bool = True) -> None:
        self._mono = mono
        self._t0 = mono()
        self.echo = echo
        self.rows: List[Tuple[float, str, Tuple[Any, ...]]] = []

    def record(self, name: str, args: Tuple[Any, ...]) -> None:
        row = (round(self._mono() - self._t0, 3), name, tuple(args))
        self.rows.append(row)
        if self.echo:
            print(f"{row[0]:>9.3f}s  {name:<20} {list(row[2])}")

    def write_csv(self, path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["seconds", "event", "args"])
            for seconds, name, args in self.rows:
                writer.writerow([seconds, name, repr(list(args))])


def make_sink_class(recorder: Recorder) -> type:
    """The COM event sink. Raw arguments are kept whatever their count: the OnHIDNum signature on
    this firmware is what the probe finds out."""

    class _Sink:
        def OnAttTransactionEx(self, *args):
            recorder.record("OnAttTransactionEx", args)

        def OnHIDNum(self, *args):
            recorder.record("OnHIDNum", args)

    return _Sink


def run_probe(zk: Any, *, seconds: float, sleep: Callable[[float], None] = time.sleep,
              mono: Callable[[], float] = time.monotonic,
              pump: Optional[Callable[[], None]] = None) -> None:
    """Register both events, then poll as the driver does (ReadRTLog, GetRTLog until empty)."""
    zk.RegEvent(1, REGEVENT_MASK)
    deadline = mono() + float(seconds)
    while mono() < deadline:
        zk.ReadRTLog(1)
        for _ in range(256):
            if not zk.GetRTLog(1):
                break
        if pump is not None:
            pump()
        sleep(0.3)


def access_is_running() -> bool:
    """True when a MonClubAccess* process runs on this PC (tasklist, the name the C3 export script
    checks). Other PCs cannot be checked."""
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq MonClubAccess*"],
                             capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return False
    return "monclubaccess" in out.lower()


def main(argv: Optional[List[str]] = None) -> int:  # pragma: no cover - real COM only
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", type=int, default=4370)
    parser.add_argument("--commkey", default="")
    parser.add_argument("--seconds", type=float, default=120.0)
    parser.add_argument("--out", default="hidnum_probe.csv")
    args = parser.parse_args(argv)
    if access_is_running():
        print("MonClub Access is running on this PC: close it (tray icon > Quit) and run again.")
        return 1
    import pythoncom
    import win32com.client as w32

    recorder = Recorder()
    pythoncom.CoInitialize()
    try:
        zk = None
        for prog_id in PROG_IDS:
            try:
                zk = w32.DispatchWithEvents(prog_id, make_sink_class(recorder))
                break
            except Exception:
                continue
        if zk is None:
            print("zkemkeeper is not registered (regsvr32, driver plan section 6 G1).")
            return 1
        if args.commkey:
            zk.SetCommPassword(int(args.commkey) if args.commkey.isdigit() else args.commkey)
        if not zk.Connect_Net(args.ip, args.port):
            print(f"Connect_Net({args.ip}, {args.port}) failed.")
            return 1
        print(f"Connected. For {args.seconds:.0f} s present, in this order: a card the terminal "
              "HOLDS, a card it does NOT hold, an enrolled finger. Wait 5 s between them.")
        try:
            run_probe(zk, seconds=args.seconds, pump=pythoncom.PumpWaitingMessages)
        finally:
            zk.Disconnect()
    finally:
        pythoncom.CoUninitialize()
    recorder.write_csv(args.out)
    print(f"{len(recorder.rows)} event(s) written to {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
