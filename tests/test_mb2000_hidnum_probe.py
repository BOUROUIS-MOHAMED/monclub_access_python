"""The MB2000 OnHIDNum field probe (ULTRA merge plan 3, Task 8; spec D10): it registers both events,
polls as the driver does and records every raw argument. A fake zkemkeeper object; no COM."""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _probe():
    spec = importlib.util.spec_from_file_location("mb2000_hidnum_probe",
                                                  REPO / "tools" / "mb2000_hidnum_probe.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeZk:
    """GetRTLog fires the sink synchronously, as zkemkeeper does (zk_standalone._pump_events_once)."""

    def __init__(self, sink, script):
        self.sink = sink
        self.script = list(script)
        self.calls = []

    def RegEvent(self, machine, mask):
        self.calls.append(("RegEvent", machine, mask))
        return True

    def ReadRTLog(self, machine):
        self.calls.append(("ReadRTLog", machine))
        return True

    def GetRTLog(self, machine):
        if not self.script:
            return False
        name, args = self.script.pop(0)
        getattr(self.sink, name)(*args)
        return True


def test_the_probe_registers_both_events_and_records_their_raw_arguments(tmp_path):
    p = _probe()
    clock = iter(float(i) for i in range(1000))
    rec = p.Recorder(mono=lambda: next(clock), echo=False)
    zk = FakeZk(p.make_sink_class(rec)(), [
        ("OnHIDNum", (13604719,)),
        ("OnAttTransactionEx", ("0", 1, 0, 2, 2026, 10, 2, 10, 0, 0, 0)),
    ])
    ticks = iter(float(i) for i in range(1000))
    p.run_probe(zk, seconds=3, sleep=lambda s: None, mono=lambda: next(ticks))
    assert zk.calls[0] == ("RegEvent", 1, 2049)
    assert [(name, args) for _t, name, args in rec.rows] == [
        ("OnHIDNum", (13604719,)),
        ("OnAttTransactionEx", ("0", 1, 0, 2, 2026, 10, 2, 10, 0, 0, 0)),
    ]
    out = tmp_path / "probe.csv"
    rec.write_csv(str(out))
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "seconds,event,args" and "OnHIDNum,[13604719]" in lines[1]


def test_the_probe_is_never_imported_by_the_app():
    for path in (REPO / "app").rglob("*.py"):
        assert "hidnum_probe" not in path.read_text(encoding="utf-8", errors="ignore"), path
