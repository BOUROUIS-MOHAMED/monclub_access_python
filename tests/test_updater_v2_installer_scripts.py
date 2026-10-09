"""Updater v2 (lane L2): static and compile checks of the two installers and the build /
publish scripts (design.md section 8). The behaviour itself is proved by running the real
compiled installers (docs/access-updater-v2/e2e/L2) and by test_updater_v2_install_helper.py;
these tests keep the rules from silently regressing in a later edit."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ACCESS_ISS = REPO / "installer" / "MonClubAccess.iss"
TV_ISS = REPO / "installer" / "MonClubTV.iss"
SAFETY = REPO / "installer" / "update_safety.iss"
BUILD_RELEASE = REPO / "build_release.ps1"
BUILD_INSTALLER = REPO / "build_installer.ps1"
PUBLISH = REPO / "publish_github_release.ps1"
ISS_FILES = [ACCESS_ISS, TV_ISS, SAFETY]


def text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def section(src: str, name: str) -> str:
    m = re.search(r"^\[" + re.escape(name) + r"\]\s*$(.*?)(?=^\[[A-Za-z]+\]\s*$|\Z)", src, re.M | re.S)
    body = m.group(1) if m else ""
    return "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith(";"))


def _iscc() -> str | None:
    for c in (os.environ.get("INNO_ISCC"), r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
              r"C:\Program Files\Inno Setup 6\ISCC.exe", shutil.which("ISCC.exe")):
        if c and Path(c).is_file():
            return c
    return None


# ------------------------------------------------------------------ D21: never DelTree current


@pytest.mark.parametrize("iss", [ACCESS_ISS, TV_ISS])
def test_current_is_never_deleted_wholesale(iss):
    src = text(iss)
    assert "DeleteTreeIfExists" not in src
    assert not re.search(r"DelTree\([^)]*current", src, re.I)
    assert "UpdPrepareBackup()" in src  # backup through update_helper.ps1
    assert '#include "update_safety.iss"' in src
    assert re.search(r'^Source: "update_helper\.ps1"; Flags: dontcopy$', src, re.M)


def test_the_helper_never_renames_current():
    helper = text(REPO / "installer" / "update_helper.ps1")
    assert not re.search(r"Rename-Item|Move-Item[^\n]*current|Directory\]::Move", helper)


# ------------------------------------------------------------------ D22 / every box silent-safe


@pytest.mark.parametrize("iss", ISS_FILES)
def test_every_message_box_is_guarded_by_a_silent_check(iss):
    lines = text(iss).splitlines()
    for n, line in enumerate(lines):
        if re.search(r"\bMsgBox\(", line) and not line.lstrip().startswith("//"):
            window = "\n".join(lines[max(0, n - 8):n + 1])
            assert re.search(r"WizardSilent\(\)", window), f"{iss.name}:{n + 1} MsgBox without a silent guard"


@pytest.mark.parametrize("iss", [ACCESS_ISS, TV_ISS])
def test_same_version_no_longer_shows_a_box_from_initialize_setup(iss):
    src = text(iss)
    body = src[src.index("function InitializeSetup(): Boolean;"):src.index("procedure InitializeWizard();")]
    assert "MsgBox" not in body
    assert "UpdHandleSameVersion();" in body


def test_same_version_silent_path_records_aborted_and_relaunches():
    src = text(SAFETY)
    body = src[src.index("procedure UpdHandleSameVersion();"):src.index("function UpdPrepareBackup(): string;")]
    assert "'ABORTED'" in body and "'same_version'" in body and "UpdRelaunch(ExistingInstallRoot)" in body
    assert body.index("UpdWriteLastUpdate") < body.index("UpdRelaunch")


def test_needs_restart_is_never_set():
    for iss in ISS_FILES:
        assert not re.search(r"NeedsRestart\s*:=", text(iss)), iss.name


# ------------------------------------------------------------------ D23: no runas when silent


def test_zkemkeeper_registration_never_elevates_in_silent_mode():
    src = text(ACCESS_ISS)
    reg = src[src.index("procedure RegisterZkemkeeper();"):src.index("procedure UnregisterZkemkeeper();")]
    assert reg.index("if WizardSilent() then") < reg.index("ShellExec('runas'")
    unreg = src[src.index("procedure UnregisterZkemkeeper();"):src.index("function IsWebView2RuntimePresent")]
    assert unreg.index("if UninstallSilent() then") < unreg.index("ShellExec('runas'")
    assert "runas" not in text(TV_ISS)


def test_no_regsvr32_self_heal_exists_in_the_app():
    """D23 finding: the design assumed the app re-registers zkemkeeper itself. It does not --
    if someone adds such a path, revisit the silent-mode log text in MonClubAccess.iss."""
    hits = []
    for folder in ("app", "shared", "tv"):
        for p in (REPO / folder).rglob("*.py"):
            src = p.read_text(encoding="utf-8", errors="replace")
            if re.search(r"regsvr32|DllRegisterServer|'runas'|\"runas\"", src):
                if not all(ln.strip().startswith(("#", '"', "'")) or "must be REGISTERED" in ln
                           for ln in src.splitlines() if re.search(r"regsvr32|DllRegisterServer|runas", ln)):
                    hits.append(str(p))
    assert hits == []


# ------------------------------------------------------------------ launch / [Run]


@pytest.mark.parametrize("iss", [ACCESS_ISS, TV_ISS])
def test_run_entry_launches_only_interactive_installs(iss):
    run = section(text(iss), "Run")
    launch = [ln for ln in run.splitlines() if "{#MainExe}" in ln and ln.startswith("Filename")]
    assert len(launch) == 1 and "Check: not WizardSilent" in launch[0]


def test_post_install_health_wait_is_300_s_and_rollback_reasons_are_distinct():
    src = text(SAFETY)
    assert "' -TimeoutSec 300'" in src
    assert "UpdRollback('health_timeout')" in src and "UpdRollback('crash')" in src
    assert "UpdRollback('setup_failed')" in src
    # Result written BEFORE the old app is started (L3 reads it at its boot).
    rb = src[src.index("procedure UpdRollback("):src.index("procedure UpdPostInstall();")]
    assert rb.index("UpdWriteLastUpdate") < rb.index("UpdRelaunch(UpdInstallRoot)")


# ------------------------------------------------------------------ D26 uninstall data


def test_access_uninstall_keeps_tv_data_while_tv_is_installed():
    src = text(ACCESS_ISS)
    ud = section(src, "UninstallDelete")
    assert "{commonappdata}\\MonClub Access" not in ud and "{localappdata}\\MonClub Access" not in ud
    body = src[src.index("procedure RemoveAccessData("):]
    for sub in ("data", "access", "backups", "versions"):
        assert f"'{sub}'" in body
    assert "'tv'" not in body.split("end;")[0] and "'shared'" not in body.split("end;")[0]
    assert "{4A8D6A8A-7AC6-4C87-862D-2E5A6B644D27}_is1" in src  # TV's AppId


def test_tv_uninstall_deletes_only_its_own_data_folder():
    src = text(TV_ISS)
    ud = section(src, "UninstallDelete")
    assert "MonClub TV" not in ud  # the folders TV never used
    body = src[src.index("procedure RemoveTvData("):src.index("procedure CurUninstallStepChanged(")]
    assert "DeleteDataDir(AddBackslash(Root) + 'tv');" in body
    deletes = re.findall(r"DeleteDataDir\(AddBackslash\(Root\) \+ '([^']+)'\)", body)
    assert sorted(deletes) == ["shared", "tv"]
    assert "{9B77A9C2-2B97-4F62-A9E8-4B4C65F3A9B1}_is1" in src  # Access's AppId


def test_tv_data_paths_used_by_the_uninstallers_match_the_app():
    utils = text(REPO / "app" / "core" / "utils.py")
    assert 'APP_NAME = "MonClub Access"' in utils
    assert 'TV_DATA_DIR = DATA_ROOT / "tv"' in utils
    assert 'roots.append(Path(program_data) / APP_NAME)' in utils
    assert 'roots.append(Path(local_appdata) / APP_NAME)' in utils


@pytest.mark.parametrize("iss", [ACCESS_ISS, TV_ISS])
def test_uninstall_removes_previous_state_and_downloads(iss):
    ud = section(text(iss), "UninstallDelete")
    for sub in ("previous", "current.failed", "state", "downloads"):
        assert f'Name: "{{app}}\\{sub}"' in ud


# ------------------------------------------------------------------ D32 TV installer


def test_tv_installer_logs_and_does_not_untick_the_start_menu_task():
    src = text(TV_ISS)
    assert re.search(r"^SetupLogging=yes$", section(src, "Setup"), re.M)
    assert "checkedonce" not in section(src, "Tasks")


# ------------------------------------------------------------------ test-fail define


def test_test_fail_define_is_test_only_everywhere():
    for iss in (ACCESS_ISS, TV_ISS):
        assert '#define OutputBaseFilename OutputBaseFilename + "_TESTFAIL_" + UPDATER_TEST_FAIL' in text(iss)
    br = text(BUILD_RELEASE)
    assert 'if ($TestFail -and -not $E2ETestKeys)' in br
    assert "$publishable = -not ($SkipTests -or $SkipChecks -or $E2ETestKeys -or $TestFail" in br


@pytest.mark.skipif(_iscc() is None, reason="Inno Setup (ISCC.exe) not installed")
@pytest.mark.parametrize("iss, exe, define, ok", [
    (TV_ISS, "MonClubTV.exe", None, True),
    (ACCESS_ISS, "MonClubAccess.exe", "after_copy", True),
    (ACCESS_ISS, "MonClubAccess.exe", "bogus", False),
])
def test_installers_compile_and_refuse_an_unknown_test_fail_mode(tmp_path, iss, exe, define, ok):
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / exe).write_text("stub")
    (stage / "version.json").write_text('{"version": "0.0.0-test"}')  # every real payload has one
    (stage / "_internal").mkdir()
    (stage / "_internal" / "base_library.zip").write_text("stub")  # ... and an _internal\ tree
    args = [_iscc(), "/Q", f"/O{tmp_path / 'out'}", "/DAppVersion=0.0.0-test", f"/DStageDir={stage}",
            "/DOutputBaseFilename=compile_test"]
    if define:
        args.append(f"/DUPDATER_TEST_FAIL={define}")
    out = subprocess.run(args + [str(iss)], capture_output=True, text=True, timeout=300)
    assert (out.returncode == 0) is ok, out.stdout + out.stderr
    if ok and define:
        assert (tmp_path / "out" / f"compile_test_TESTFAIL_{define}.exe").is_file()


# ------------------------------------------------------------------ build / publish (D30 D31 D3 D20)


def test_build_release_gates_run_before_the_tauri_build_and_pyinstaller():
    br = text(BUILD_RELEASE)
    first_build_step = br.index("if ((-not $SkipTauriBuild)")
    for gate in ("Gate 1: the working tree must match HEAD", "Gate 2: no SQL statement",
                 "python $releaseSign check-trust", "python -m pytest tests/ -q --ignore=tests/_pydeps"):
        assert br.index(gate) < first_build_step, gate
    assert br.index("python -m pytest") < br.index("python -m PyInstaller")


def test_build_release_signs_the_compiled_installer_after_iscc():
    br = text(BUILD_RELEASE)
    assert br.index('"build_installer.ps1"') < br.index("$installerSha256 = Get-Sha256 $installerPath")
    assert br.index("& $SignTool $installerPath") < br.index("$installerSha256 = Get-Sha256")  # O2 hook
    assert '"sign", "--installer", $installerPath' in br
    assert '@("rev-parse","HEAD")' in br  # full SHA for publish --target


def test_build_release_restores_release_keys_after_an_e2e_build():
    br = text(BUILD_RELEASE)
    block = br[br.index("$releaseKeysOriginal = $null"):br.index("if ($meta.RequiresSdkDlls)")]
    assert "try {" in block and "} finally {" in block
    assert "WriteAllBytes($releaseKeysPath, $releaseKeysOriginal)" in block.split("} finally {")[1]


def test_e2e_prod_keys_regex_matches_exactly_the_single_line_form_lane_l3_uses():
    br = text(BUILD_RELEASE)
    m = re.search(r"\$re = \[regex\]'([^']+)'", br)
    assert m
    rx = re.compile(m.group(1).replace("(?m)", ""), re.M)
    sample = 'PROD_KEYS: dict[str, str] = {}\r\nTEST_KEYS: dict[str, str] = {\r\n    "a": "b",\r\n}\r\n'
    assert len(rx.findall(sample)) == 1
    assert len(rx.findall('PROD_KEYS: dict[str, str] = {\n  "x": "y"\n}\n')) == 0  # multi-line: refused


def test_publish_tags_the_built_commit_and_uploads_the_release_file():
    pub = text(PUBLISH)
    assert '"--target", $commit' in pub
    assert "gh release create $tag $InstallerPath $ReleaseFile @extraFlags" in pub
    assert "verify --release-file $ReleaseFile --installer $InstallerPath --require-publishable" in pub


def test_the_zip_updater_is_gone():
    assert not (REPO / "updater").exists()
    assert not (REPO / "installer" / "updater").exists()
    assert not (REPO / "build_updater.ps1").exists()
    for p in (ACCESS_ISS, TV_ISS, REPO / "packaging" / "desktop_components.ps1", BUILD_RELEASE,
              REPO / "packaging" / "watchdog" / "monclub_access_watchdog.ps1", REPO / ".gitignore"):
        assert not re.search(r"MonClubDesktopUpdater|MonClub(Access|TV)Updater|build_updater", text(p)), p.name


@pytest.mark.parametrize("iss", [ACCESS_ISS, TV_ISS])
def test_the_uninstall_log_is_overwritten_so_old_data_deletes_do_not_replay(iss):
    """D26, found by the E2E: Inno APPENDS uninstall logs across installs, so the 1.4.x entry
    '[UninstallDelete] {commonappdata}/MonClub Access' kept wiping TV's data."""
    src = text(iss)
    assert re.search(r"^UninstallLogMode=overwrite$", section(src, "Setup"), re.M)
    assert not re.search(r"^\[Registry\]", src, re.M)  # overwrite is only safe without them
    ud = section(src, "UninstallDelete")
    assert 'Type: filesandordirs; Name: "{app}"' in ud


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser")
def test_every_tracked_powershell_script_parses_and_has_no_lone_cr():
    """Review finding: an edit turned '\r' of 'release\release-' into a CR byte; PowerShell
    reads a lone CR as a line break and generate_installer.ps1 stopped parsing at all."""
    # The scripts that build, install or run MonClub (not third-party tooling under .specify/).
    files = [f for f in subprocess.run(["git", "ls-files", "*.ps1"], cwd=REPO, capture_output=True,
                                       text=True).stdout.split()
             if "/" not in f or f.split("/")[0] in ("installer", "packaging", "tools")]
    assert "generate_installer.ps1" in files and "installer/update_helper.ps1" in files
    for f in files:
        data = (REPO / f).read_bytes()
        assert data.replace(b"\r\n", b"").count(b"\r") == 0, f"{f}: lone CR byte"
    assert parse_errors([REPO / f for f in files]) == []


def parse_errors(paths) -> list[str]:
    import tempfile
    script = ("foreach ($f in $args) { $e = $null; "
              "[void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$e); "
              "if ($e.Count) { Write-Output (\"$f : \" + $e[0].Message + ' @ ' + $e[0].Extent.StartLineNumber) } }")
    with tempfile.TemporaryDirectory() as d:
        checker = Path(d) / "parse_check.ps1"
        checker.write_text(script, encoding="utf-8")
        out = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(checker),
                              *[str(p) for p in paths]], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return [ln for ln in out.stdout.splitlines() if ln.strip()]


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser")
def test_the_parse_check_itself_catches_a_broken_script(tmp_path):
    bad = tmp_path / "bad.ps1"
    # Exactly the broken generate_installer.ps1 comment: the "\r" of "release\release" became a CR.
    bad.write_bytes(b"# the signed release file (release" + bytes([13]) + b"elease-<component>.json)\r\n$x = 1\r\n")
    assert len(parse_errors([bad])) == 1


# ------------------------------------------------------------------ review fixes (#3 #5 #12)


@pytest.mark.parametrize("iss, exe", [(ACCESS_ISS, "{#MainExe}"), (TV_ISS, "{#MainExe}")])
def test_version_json_and_then_the_exe_are_the_last_payload_files(iss, exe):
    files = [ln for ln in section(text(iss), "Files").splitlines() if ln.startswith("Source:")]
    assert files[-2] == r'Source: "{#StageDir}\version.json"; DestDir: "{app}\current"; Flags: ignoreversion'
    assert files[-1] == rf'Source: "{{#StageDir}}\{exe}"; DestDir: "{{app}}\current"; Flags: ignoreversion'
    wildcard = [ln for ln in files if r'"{#StageDir}\*"' in ln]
    assert len(wildcard) == 1 and r'Excludes: "\{#MainExe},\version.json"' in wildcard[0]


def test_access_puts_the_journal_aware_watchdog_in_place_before_emptying_current():
    src = text(ACCESS_ISS)
    prep = src[src.index("function PrepareToInstall("):src.index("procedure CurStepChanged(")]
    assert prep.index("InstallWatchdogEarly(Root);") < prep.index("UpdPrepareBackup()")
    assert re.search(r'^Source: "\.\.\\packaging\\watchdog\\monclub_access_watchdog\.ps1"; Flags: dontcopy$', src, re.M)


def test_setup_recovers_a_leftover_journal_and_repairs_an_incomplete_current():
    src = text(SAFETY)
    prep = src[src.index("function UpdPrepareBackup(): string;"):src.index("procedure UpdRollback(")]
    assert prep.index("UpdRunHelper('recover', UpdInstallRoot, ' -InSetup')") < prep.index("UpdRunHelper('backup'")
    assert prep.index("UpdRepair := True;") < prep.index("UpdRunHelper('backup'")
    for iss in (ACCESS_ISS, TV_ISS):
        assert "if SameVersionInstalled() and UpdCurrentComplete(ExistingInstallRoot) then" in text(iss)


def test_a_failed_restore_is_retried_once_keeps_the_journal_and_still_relaunches():
    """Design 1 / D24: every silent path ends with the app started. The journal stays, and the
    watchdog's journal rule (run before its is-running check) recovers a half-restored tree."""
    src = text(SAFETY)
    rb = src[src.index("procedure UpdRollback("):src.index("procedure UpdPostInstall();")]
    assert rb.count("UpdRunHelper('restore'") == 2
    failed = rb[rb.index("'restore_failed'"):]
    assert "UpdRelaunch(UpdInstallRoot)" in failed and "UpdDeleteJournal" not in failed
    prep = src[src.index("function UpdPrepareBackup(): string;"):src.index("procedure UpdRollback(")]
    rf = prep[prep.index("'restore_failed'"):prep.index("'backup_failed'")]
    assert "UpdRelaunch(UpdInstallRoot)" in rf
    # Only a live restorer's claim skips the relaunch (that restorer starts the app).
    rip = prep[prep.index("'restore_in_progress'"):prep.index("if not PathHasInstalledPayload")]
    assert "UpdRelaunch" not in rip
