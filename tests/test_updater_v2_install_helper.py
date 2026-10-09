"""Updater v2 (lane L2): installer/update_helper.ps1, the safe-swap helper Setup and the
watchdog run (design.md section 8).

Runs the real script with Windows PowerShell on a throw-away install root. The health-wait
cases start the test-only stub exe (tools/updater_e2e/stub_app.cs, compiled with the .NET
Framework csc.exe that ships with Windows); they are skipped where csc is absent.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only installer helper")

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "installer" / "update_helper.ps1"
STUB_SRC = REPO / "tools" / "updater_e2e" / "stub_app.cs"
CSC = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe"
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
EXE = "MonClubAccess.exe"


def run_helper(action: str, root: Path, *extra: str, timeout: float = 120) -> subprocess.CompletedProcess:
    cmd = [
        str(POWERSHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(HELPER), "-Action", action, "-InstallRoot", str(root),
        "-AppExe", EXE, "-UiExe", "monclub-access-ui.exe",
        "-FromVersion", "1.0.0", "-ToVersion", "2.0.0",
        "-LogPath", str(root / "helper.log"), *extra,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(root))


def write_payload(folder: Path, version: str, mode: str = "ok", exe_bytes: bytes | None = None) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / EXE).write_bytes(exe_bytes if exe_bytes is not None else b"not-a-real-exe " + version.encode())
    (folder / "version.json").write_text(json.dumps({"version": version}), encoding="utf-8")
    (folder / "stub_mode.txt").write_text(mode, encoding="ascii")
    nested = folder / "_internal" / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    (nested / "payload.txt").write_text(f"payload {version}", encoding="utf-8")


def tree(folder: Path) -> dict[str, bytes]:
    return {str(p.relative_to(folder)): p.read_bytes() for p in sorted(folder.rglob("*")) if p.is_file()}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="ascii"))


def utc(delta_minutes: float = 0) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=delta_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    r = tmp_path / "MonClubAccess"
    (r / "state").mkdir(parents=True)
    return r


@pytest.fixture(scope="module")
def stub_exe(tmp_path_factory) -> bytes:
    if not CSC.exists():
        pytest.skip("csc.exe (.NET Framework) not available")
    out = tmp_path_factory.mktemp("stub") / EXE
    r = subprocess.run([str(CSC), "/nologo", "/target:winexe", "/platform:x86", f"/out:{out}", str(STUB_SRC)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return out.read_bytes()


def kill_stubs(root: Path) -> None:
    ps = (f"Get-CimInstance Win32_Process -Filter \"Name='{EXE}'\" | "
          f"Where-Object {{ $_.ExecutablePath -and $_.ExecutablePath.StartsWith('{root}') }} | "
          "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }")
    subprocess.run([str(POWERSHELL), "-NoProfile", "-Command", ps], capture_output=True, timeout=60)


# ---------------------------------------------------------------- backup / restore


def test_backup_copies_current_to_previous_then_empties_current_but_keeps_the_folder(root: Path):
    write_payload(root / "current", "1.0.0")
    before = tree(root / "current")
    r = run_helper("backup", root)
    assert r.returncode == 0, r.stdout + r.stderr
    assert tree(root / "previous") == before
    assert (root / "current").is_dir() and list((root / "current").iterdir()) == []
    journal = read_json(root / "state" / "install_journal.json")
    assert journal["phase"] == "copying"
    assert journal["from"] == "1.0.0" and journal["to"] == "2.0.0"
    assert journal["at"].endswith("Z") and isinstance(journal["setupPid"], int)


def test_backup_replaces_a_stale_previous_completely(root: Path):
    write_payload(root / "previous", "0.9.0")
    (root / "previous" / "only-in-old-previous.txt").write_text("x")
    write_payload(root / "current", "1.0.0")
    before = tree(root / "current")
    assert run_helper("backup", root).returncode == 0
    assert tree(root / "previous") == before


def test_backup_works_while_another_process_has_its_working_directory_in_current(root: Path):
    """Design 8.0: the watchdog / the 1.4.35 client leave a process whose cwd is current\\.
    A rename of current\\ would fail; the copy-then-empty backup must not."""
    write_payload(root / "current", "1.0.0")
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], cwd=str(root / "current"))
    try:
        time.sleep(0.5)
        r = run_helper("backup", root)
        assert r.returncode == 0, r.stdout + r.stderr
        assert (root / "current").is_dir() and list((root / "current").iterdir()) == []
        assert (root / "previous" / EXE).exists()
    finally:
        holder.kill()
        holder.wait()


def test_backup_with_a_locked_file_gives_up_and_leaves_current_exactly_as_it_was(root: Path):
    write_payload(root / "current", "1.0.0")
    before = tree(root / "current")
    # CPython opens without FILE_SHARE_DELETE: the file cannot be deleted while held.
    with open(root / "current" / "_internal" / "nested" / "payload.txt", "rb"):
        r = run_helper("backup", root, "-LockedRetrySec", "2")
    assert r.returncode == 2, r.stdout + r.stderr
    assert tree(root / "current") == before
    assert not (root / "state" / "install_journal.json").exists()
    assert "still locked" in (root / "helper.log").read_text(encoding="utf-8-sig")


def test_backup_refuses_when_current_has_no_payload(root: Path):
    (root / "current").mkdir()
    r = run_helper("backup", root)
    assert r.returncode == 2
    assert not (root / "previous").exists()
    assert not (root / "state" / "install_journal.json").exists()


def test_restore_mirrors_previous_back_over_a_new_current(root: Path):
    write_payload(root / "previous", "1.0.0")
    write_payload(root / "current", "2.0.0")
    (root / "current" / "new-only.dll").write_bytes(b"new")
    r = run_helper("restore", root)
    assert r.returncode == 0, r.stdout + r.stderr
    assert tree(root / "current") == tree(root / "previous")
    assert read_json(root / "state" / "install_journal.json")["phase"] == "restoring"


def test_restore_without_a_complete_previous_fails_and_keeps_the_journal(root: Path):
    write_payload(root / "current", "2.0.0")
    (root / "previous").mkdir()
    r = run_helper("restore", root)
    assert r.returncode == 3
    assert (root / "state" / "install_journal.json").exists()


# ---------------------------------------------------------------- launch-wait / relaunch


@pytest.mark.parametrize(
    "mode, extra, expected",
    [
        ("ok", (), 0),
        ("crash", (), 10),
        ("noboot", ("-TimeoutSec", "8"), 11),
        ("ok", ("-TimeoutSec", "8", "-TestFail", "health"), 11),
        ("ok", ("-TestFail", "crash"), 10),
    ],
)
def test_launch_wait_tells_healthy_crash_and_timeout_apart(root: Path, stub_exe: bytes, mode, extra, expected):
    write_payload(root / "current", "2.0.0", mode=mode, exe_bytes=stub_exe)
    (root / "state" / "boot_ok.json").write_text('{"version":"2.0.0","pid":1,"at":"old"}')
    try:
        r = run_helper("launch-wait", root, *extra, timeout=180)
        assert r.returncode == expected, r.stdout + r.stderr
        log = (root / "logs" / "stub.log").read_text(encoding="utf-8")
        # Started from current\ with current\ as its working directory (the gyms' launch rule).
        assert f"cwd={root / 'current'}" in log
        if expected == 0:
            assert read_json(root / "state" / "boot_ok.json")["version"] == "2.0.0"
        if expected == 11:
            time.sleep(1)
            out = subprocess.run([str(POWERSHELL), "-NoProfile", "-Command",
                                  f"@(Get-CimInstance Win32_Process -Filter \"Name='{EXE}'\" | Where-Object "
                                  f"{{ $_.ExecutablePath -like '{root}*' }}).Count"],
                                 capture_output=True, text=True).stdout.strip()
            assert out == "0", "a timed-out process must be killed"
    finally:
        kill_stubs(root)


def test_launch_wait_ignores_a_boot_ok_of_another_version(root: Path, stub_exe: bytes):
    write_payload(root / "current", "2.0.0", mode="noboot", exe_bytes=stub_exe)
    (root / "state" / "boot_ok.json").write_text('{"version":"1.0.0","pid":1,"at":"x"}')
    try:
        r = run_helper("launch-wait", root, "-TimeoutSec", "6", timeout=120)
        assert r.returncode == 11
    finally:
        kill_stubs(root)


def test_relaunch_starts_once_and_then_sees_it_running(root: Path, stub_exe: bytes):
    write_payload(root / "current", "1.0.0", mode="noboot", exe_bytes=stub_exe)
    try:
        assert run_helper("relaunch", root).returncode == 0
        time.sleep(1.5)
        r = run_helper("relaunch", root)
        assert r.returncode == 0
        assert "already running" in r.stdout
    finally:
        kill_stubs(root)


# ---------------------------------------------------------------- recover (journal rule)


def write_journal(root: Path, phase: str, at: str, setup_pid: int = 0) -> None:
    (root / "state" / "install_journal.json").write_text(
        json.dumps({"phase": phase, "from": "1.0.0", "to": "2.0.0", "at": at, "setupPid": setup_pid}),
        encoding="ascii")


@pytest.mark.parametrize("phase", ["copying", "verifying", "restoring"])
def test_recover_restores_previous_from_a_stale_journal(root: Path, phase: str):
    write_payload(root / "previous", "1.0.0")
    (root / "current").mkdir()
    (root / "current" / "half-written.dll").write_bytes(b"x")
    (root / ".update-in-progress").write_text("x")
    write_journal(root, phase, utc(-30))
    r = run_helper("recover", root)
    assert r.returncode == 20, r.stdout + r.stderr
    assert tree(root / "current") == tree(root / "previous")
    assert not list((root / "state").glob("install_journal*"))
    assert not (root / ".update-in-progress").exists()
    last = read_json(root / "state" / "last_update.json")
    assert last["result"] == "ROLLED_BACK" and last["reason"] == "interrupted"
    assert last["from"] == "2.0.0" and last["to"] == "1.0.0"
    assert set(last) == {"result", "from", "to", "reason", "log", "at"}


def test_recover_drops_a_stale_backing_up_journal_without_touching_current(root: Path):
    write_payload(root / "current", "1.0.0")
    before = tree(root / "current")
    (root / "previous").mkdir()  # partial backup
    write_journal(root, "backing_up", utc(-30))
    r = run_helper("recover", root)
    assert r.returncode == 21, r.stdout + r.stderr
    assert tree(root / "current") == before
    assert not list((root / "state").glob("install_journal*"))
    assert read_json(root / "state" / "last_update.json")["result"] == "ABORTED"


def test_recover_stands_down_on_a_fresh_journal(root: Path):
    write_payload(root / "previous", "1.0.0")
    write_journal(root, "copying", utc(-1))
    r = run_helper("recover", root)
    assert r.returncode == 22
    assert (root / "state" / "install_journal.json").exists()


def test_recover_treats_a_fresh_journal_whose_setup_died_as_stale(root: Path):
    """Setup killed mid-swap without a reboot: its PID is gone, no 10-minute wait."""
    write_payload(root / "previous", "1.0.0")
    (root / "current").mkdir()
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    write_journal(root, "copying", utc(-1), setup_pid=dead.pid)
    r = run_helper("recover", root)
    assert r.returncode == 20, r.stdout + r.stderr


def test_recover_stands_down_while_the_journal_setup_pid_is_alive(root: Path):
    """A renamed installer is not matched by image name; its live PID still protects it."""
    write_payload(root / "previous", "1.0.0")
    alive = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        write_journal(root, "copying", utc(-1), setup_pid=alive.pid)
        assert run_helper("recover", root).returncode == 22
    finally:
        alive.kill()
        alive.wait()


def test_recover_treats_a_journal_written_before_the_last_boot_as_stale(root: Path):
    write_payload(root / "previous", "1.0.0")
    (root / "current").mkdir()
    boot = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-Command",
         "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"],
        capture_output=True, text=True).stdout.strip()
    boot_t = dt.datetime.strptime(boot, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    if dt.datetime.now(dt.timezone.utc) - boot_t < dt.timedelta(minutes=2):
        pytest.skip("booted too recently to place a journal before boot")
    # Before the boot, but inside the 10-minute window measured from... the boot itself is
    # older than 2 min, so pick boot - 1 min with a 10000-min staleness window: only the
    # "before last boot" rule can make it stale.
    at = (boot_t - dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_journal(root, "copying", at)
    r = run_helper("recover", root, "-StaleMinutes", "100000")
    assert r.returncode == 20, r.stdout + r.stderr


def test_recover_with_unparseable_journal_restores_only_when_previous_is_complete(root: Path):
    (root / "state" / "install_journal.json").write_text("{not json", encoding="ascii")
    old = time.time() - 3600
    os.utime(root / "state" / "install_journal.json", (old, old))
    write_payload(root / "current", "1.0.0")
    r = run_helper("recover", root)
    assert r.returncode == 21  # no previous\ -> nothing to restore, journal dropped
    assert not (root / "state" / "install_journal.json").exists()


def test_recover_stands_down_while_another_restorer_holds_a_live_claim(root: Path):
    write_payload(root / "previous", "1.0.0")
    # Restorers are PowerShell processes (update_helper, L3's wrapper / start-up restorer).
    alive = subprocess.Popen([str(POWERSHELL), "-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
    try:
        (root / "state" / f"install_journal.restoring-{alive.pid}.json").write_text("{}", encoding="ascii")
        r = run_helper("recover", root)
        assert r.returncode == 22, r.stdout
        assert "restore is in progress" in r.stdout
    finally:
        alive.kill()
        alive.wait()


def test_a_claim_whose_pid_was_reused_by_another_program_is_not_live(root: Path):
    """After a power cut mid-restore Windows may hand the claim's pid to any process."""
    write_payload(root / "previous", "1.0.0")
    (root / "current").mkdir()
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        (root / "state" / f"install_journal.restoring-{other.pid}.json").write_text(
            json.dumps({"phase": "copying", "from": "1.0.0", "to": "2.0.0", "at": utc(-30), "setupPid": 0}),
            encoding="ascii")
        r = run_helper("recover", root)
        assert r.returncode == 20, r.stdout + r.stderr
    finally:
        other.kill()
        other.wait()


def test_recover_takes_back_the_journal_of_a_restorer_that_died(root: Path):
    write_payload(root / "previous", "1.0.0")
    (root / "current").mkdir()
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    (root / "state" / f"install_journal.restoring-{dead.pid}.json").write_text(
        json.dumps({"phase": "restoring", "from": "1.0.0", "to": "2.0.0", "at": utc(-30), "setupPid": 0}),
        encoding="ascii")
    r = run_helper("recover", root)
    assert r.returncode == 20, r.stdout + r.stderr
    assert tree(root / "current") == tree(root / "previous")
    assert not list((root / "state").glob("install_journal*"))


def test_recover_without_journal_does_nothing(root: Path):
    assert run_helper("recover", root).returncode == 0
    assert not (root / "state" / "last_update.json").exists()


# ---------------------------------------------------------------- review fixes


def _helper_cmd(action: str, root: Path, *extra: str) -> list[str]:
    return [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(HELPER),
            "-Action", action, "-InstallRoot", str(root), "-AppExe", EXE, "-UiExe", "monclub-access-ui.exe",
            "-FromVersion", "1.0.0", "-ToVersion", "2.0.0", "-LogPath", str(root / f"helper-{action}.log"), *extra]


def test_a_live_restorers_claim_of_a_pre_boot_journal_is_seen_as_live(root: Path):
    """Review #4: a rename keeps the journal's LastWriteTime (before the boot after a power
    cut), so a second restorer judged the first one's claim dead and restored concurrently."""
    write_payload(root / "previous", "1.0.0")
    write_payload(root / "current", "2.0.0")
    locked = root / "current" / "_internal" / "nested" / "payload.txt"
    journal_path = root / "state" / "install_journal.json"
    write_journal(root, "copying", utc(-60 * 24 * 3))
    old = time.time() - 3 * 24 * 3600
    os.utime(journal_path, (old, old))
    # Hold a file that differs from previous\ with NO sharing for 8 s (robocopy retries 15 x 1 s).
    holder = subprocess.Popen([str(POWERSHELL), "-NoProfile", "-Command",
                               f"$f=[IO.File]::Open('{locked}','Open','Read','None'); Start-Sleep -Seconds 8; $f.Close()"])
    time.sleep(2)
    first = subprocess.Popen(_helper_cmd("recover", root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 20
        claims = []
        while time.time() < deadline and not claims:
            claims = list((root / "state").glob("install_journal.restoring-*.json"))
            time.sleep(0.3)
        assert claims, "the first restorer never claimed the journal"
        assert claims[0].stat().st_mtime > time.time() - 60, "claim kept the journal's old time"
        second = run_helper("recover", root)
        assert second.returncode == 22, second.stdout
        assert "restore is in progress" in second.stdout
    finally:
        holder.wait(timeout=60)
        first.communicate(timeout=240)
    assert first.returncode == 20  # the lock went away inside robocopy's retries
    assert tree(root / "current") == tree(root / "previous")


def test_journal_times_are_gregorian_utc_whatever_the_pc_culture(root: Path):
    """Review #7: under ar-SA the current culture writes a Hijri year."""
    write_payload(root / "current", "1.0.0")
    ps = (f"[Threading.Thread]::CurrentThread.CurrentCulture = 'ar-SA'; "
          f"& '{HELPER}' -Action backup -InstallRoot '{root}' -AppExe {EXE} -FromVersion 1.0.0 -ToVersion 2.0.0 "
          f"-LogPath '{root / 'h.log'}'; exit $LASTEXITCODE")
    r = subprocess.run([str(POWERSHELL), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    at = read_json(root / "state" / "install_journal.json")["at"]
    assert at.startswith(str(dt.datetime.now(dt.timezone.utc).year)), at


def test_a_boot_ok_without_pid_still_counts_as_healthy(root: Path, stub_exe: bytes):
    """Review #8: StrictMode threw on the missing property and turned success into a timeout."""
    write_payload(root / "current", "2.0.0", mode="noboot", exe_bytes=stub_exe)
    try:
        p = subprocess.Popen(_helper_cmd("launch-wait", root, "-TimeoutSec", "40"),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(6)
        (root / "state" / "boot_ok.json").write_text('{"version":"2.0.0"}', encoding="ascii")
        out, _err = p.communicate(timeout=60)
        assert p.returncode == 0, out
    finally:
        kill_stubs(root)


def test_recover_in_setup_treats_any_journal_as_left_by_a_dead_setup(root: Path):
    write_payload(root / "previous", "1.0.0")
    (root / "current").mkdir()
    alive = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        write_journal(root, "copying", utc(-1), setup_pid=alive.pid)  # fresh, "live" setupPid
        assert run_helper("recover", root).returncode == 22
        r = run_helper("recover", root, "-InSetup")
        assert r.returncode == 20, r.stdout + r.stderr
        assert tree(root / "current") == tree(root / "previous")
    finally:
        alive.kill()
        alive.wait()


def test_a_claim_older_than_its_powershell_process_is_a_reused_pid_not_a_live_restorer(root: Path):
    """After a Fast Startup boot LastBootUpTime does not move, so the boot rule alone would take
    a PowerShell that merely reuses a dead restorer's pid (e.g. the watchdog) for the restorer.
    A real restorer always started before it made (and touched) its claim."""
    write_payload(root / "previous", "1.0.0")
    (root / "current").mkdir()
    ps = subprocess.Popen([str(POWERSHELL), "-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
    try:
        time.sleep(1)
        claim = root / "state" / f"install_journal.restoring-{ps.pid}.json"
        claim.write_text(json.dumps({"phase": "copying", "from": "1.0.0", "to": "2.0.0",
                                     "at": utc(-30), "setupPid": 0}), encoding="ascii")
        made = time.time() - 120  # claim "made" 2 min before this PowerShell started
        os.utime(claim, (made, made))
        r = run_helper("recover", root)
        assert r.returncode == 20, r.stdout + r.stderr
    finally:
        ps.kill()
        ps.wait()


def test_other_setup_reports_another_installer_of_the_product_and_recover_ignores_it(root: Path, tmp_path: Path):
    """L4 reviews: a second installer run (by hand, during the morning auto-install) must not stop the app or
    touch current/ under the first. Setup asks `-Action other-setup` FIRST in PrepareToInstall; it matches the
    Setup IMAGE NAME (a reused pid never has it) and excludes our own Setup's ancestors -- here the helper's
    parent is pytest, so any monclub_access_* process is "another". recover -InSetup keeps L2's rule."""
    import shutil

    write_payload(root / "previous", "1.0.0")
    write_payload(root / "current", "2.0.0")
    write_journal(root, "copying", utc(-30))
    other = tmp_path / "monclub_access_9.9.9.exe"
    shutil.copy(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "PING.EXE", other)
    p = subprocess.Popen([str(other), "-n", "60", "127.0.0.1"], stdout=subprocess.DEVNULL)
    try:
        time.sleep(1)
        r = run_helper("other-setup", root)
        assert r.returncode == 22, r.stdout + r.stderr
        assert "another access Setup is running" in r.stdout
        assert (root / "state" / "install_journal.json").exists()
    finally:
        p.kill()
        p.wait()
    assert run_helper("other-setup", root).returncode == 0
    r = run_helper("recover", root, "-InSetup")
    assert r.returncode == 20, r.stdout + r.stderr

