"""tools/c3_panel_scripts/export_c3_panel_readonly.ps1 must never write to a panel.

It is the tool the gym-58 cutover plan hands to the owner to read both C3-400 panels
before they are erased, so "read-only" is the property that matters. Checked two ways,
as tests/test_mb2000_export_readonly.py does for the MB2000 export:

  * statically - the P/Invoke helper declares only six plcommpro.dll entry points
    (Connect, Disconnect, GetDeviceData, GetDeviceDataCount, GetDeviceParam,
    PullLastError), no write entry point is named in either file outside a comment,
    the export script reaches the DLL only through ``$sdk.<Method>(`` calls on that
    list, and it dot-sources nothing but the helper;
  * by running the SHIPPED export script against a fake helper whose object has ONLY
    those six methods and logs every call.

What the firmware does inside a read is not something a fake can settle.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PACK = REPO / "tools" / "c3_panel_scripts"
SCRIPT = PACK / "export_c3_panel_readonly.ps1"
HELPER = PACK / "_pullsdk_read.ps1"

READ_CALLS = {"Connect", "Disconnect", "GetDeviceData", "GetDeviceDataCount", "GetDeviceParam", "PullLastError"}

# plcommpro.dll exports that change a panel or consume its live events. None may be named
# in either file outside a comment.
WRITE_OR_CONSUME = {
    "SetDeviceData", "DeleteDeviceData", "ControlDevice", "SetDeviceParam",
    "GetRTLog", "GetRTLogExt", "SetDeviceDataEx", "DeleteDeviceDataEx",
    "SearchDevice", "ModifyIPAddress", "SetAppData",
}

_SDK_CALL = re.compile(r"\$sdk\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_EXTERN = re.compile(r"public\s+static\s+extern\s+\S+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _code_lines(path: Path) -> list[str]:
    """The file without comments: ``#`` to end of line (outside quotes) and ``<# #>``.
    Inside the C# here-string the lines carry no ``#``, so they are kept whole."""
    text = path.read_text(encoding="utf-8-sig")
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    out = []
    for line in text.splitlines():
        in_single = in_double = False
        cut = len(line)
        for i, ch in enumerate(line):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                cut = i
                break
        out.append(line[:cut])
    return out


class TestStaticallyReadOnly:
    def test_the_helper_declares_only_the_six_read_entry_points(self):
        code = "\n".join(_code_lines(HELPER))
        declared = _EXTERN.findall(code)
        plcomm = {n for n in declared if n not in {"LoadLibrary", "SetDllDirectory"}}
        assert plcomm == READ_CALLS, sorted(plcomm ^ READ_CALLS)
        # the two kernel32 calls load the DLL; nothing else is declared
        assert sorted(set(declared) - READ_CALLS) == ["LoadLibrary", "SetDllDirectory"]
        assert code.count('DllImport("plcommpro.dll"') == len(READ_CALLS)

    def test_the_helper_calls_only_what_it_declares(self):
        code = "\n".join(_code_lines(HELPER))
        called = set(re.findall(r"\[MonClubPullRead\]::([A-Za-z_]+)\(", code))
        assert called <= READ_CALLS | {"LoadLibrary", "SetDllDirectory"}, sorted(called)

    @pytest.mark.parametrize("path", [SCRIPT, HELPER], ids=lambda p: p.name)
    def test_no_write_entry_point_is_named_outside_a_comment(self, path: Path):
        code = "\n".join(_code_lines(path))
        found = sorted(n for n in WRITE_OR_CONSUME if re.search(rf"\b{re.escape(n)}\b", code))
        assert not found, f"{path.name} names {found} in code"

    @pytest.mark.parametrize("path", [SCRIPT, HELPER], ids=lambda p: p.name)
    def test_no_dynamic_invocation(self, path: Path):
        code = "\n".join(_code_lines(path))
        for pattern in (r"\$sdk\.\$", r"InvokeMember", r"Invoke-Expression", r"\biex\b",
                        r"GetProcAddress", r"GetDelegateForFunctionPointer", r"\$sdk\.PSObject"):
            assert not re.search(pattern, code, re.I), f"dynamic access ({pattern}) in {path.name}"

    def test_every_call_on_the_sdk_object_is_a_read(self):
        calls = set(_SDK_CALL.findall("\n".join(_code_lines(SCRIPT))))
        assert calls, "no $sdk.<call>( found: the check is no longer looking at the right thing"
        assert calls <= READ_CALLS, sorted(calls - READ_CALLS)

    def test_the_sdk_object_is_only_created(self):
        bare = [line.strip() for line in _code_lines(SCRIPT) for _ in re.finditer(r"\$sdk\b(?!\.)", line)]
        assert bare == ["$sdk = New-PullSdk -DllPath $dll"], bare

    def test_the_export_script_never_touches_the_dll_directly(self):
        code = "\n".join(_code_lines(SCRIPT))
        assert "MonClubPullRead" not in code and "DllImport" not in code and "Add-Type" not in code

    def test_only_the_helper_is_dot_sourced(self):
        code = "\n".join(_code_lines(SCRIPT))
        sourced = re.findall(r"^\s*\.\s+['\"]?([^'\"\s]+)", code, re.M)
        assert sourced == ["$PSScriptRoot\\_pullsdk_read.ps1"], sourced
        assert not re.findall(r"^\s*\.\s+['\"]?([^'\"\s]+)", "\n".join(_code_lines(HELPER)), re.M)

    def test_the_connection_string_is_the_one_access_sends(self):
        """pullsdk.py::PullSDK.connect joins exactly these five keys (pullsdk_guide 4.1)."""
        code = "\n".join(_code_lines(SCRIPT))
        assert '"protocol=TCP,ipaddress=$DeviceIp,port=$Port,timeout=$TimeoutMs,passwd=$Password"' in code


pwsh = shutil.which("powershell") or shutil.which("pwsh")

# Replaces _pullsdk_read.ps1 in a COPY of the folder: the same helper functions, and a
# fake panel object with only the six read methods, each logging its name.
_FAKE_HELPER = r"""
$ErrorActionPreference = 'Stop'
function Write-Title { param([string]$t) Write-Host $t }
function Write-Ok   { param([string]$m) Write-Host "[OK] $m" }
function Write-Err  { param([string]$m) Write-Host "[FAIL] $m" }
function Write-Warn { param([string]$m) Write-Host "[!] $m" }
function Write-Info { param([string]$m) Write-Host "[i] $m" }
function Enter-32Bit { param([string]$ScriptPath, [object[]]$ScriptArgs) }
function Resolve-PlcommproDll { param([string]$Explicit, [string]$Here) 'fake-plcommpro.dll' }
function Get-Process { param($Name, $ErrorAction) __PROCS__ }
function New-PullSdk {
    param([string]$DllPath)
    $o = [pscustomobject]@{ log = '__LOG__'; connectOk = __CONNECT_OK__ }
    function Add-Fake($name, [scriptblock]$body) { $o | Add-Member -MemberType ScriptMethod -Name $name -Value $body }
    Add-Fake 'Connect' { param($s) Add-Content -LiteralPath $this.log "Connect:$s"; if ($this.connectOk) { [IntPtr]1 } else { [IntPtr]::Zero } }
    Add-Fake 'Disconnect' { param($h) Add-Content -LiteralPath $this.log 'Disconnect' }
    Add-Fake 'PullLastError' { Add-Content -LiteralPath $this.log 'PullLastError'; -2 }
    Add-Fake 'GetDeviceDataCount' { param($h, $t, $f, $o2) Add-Content -LiteralPath $this.log "GetDeviceDataCount:$t"
        $c = @{ user = 4; userauthorize = 3; transaction = 1200; templatev10 = 2; template = 0; timezone = 1; holiday = 0 }
        __COUNT_OVERRIDES__
        $c[$t] }
    Add-Fake 'GetDeviceParam' { param($h, $items) Add-Content -LiteralPath $this.log "GetDeviceParam:$($items.Split(',').Count)"
        if ($items -eq 'DateTime') {
            $n = Get-Date
            $v = ((($n.Year - 2000) * 12 * 31 + ($n.Month - 1) * 31 + ($n.Day - 1)) * 86400) + ($n.Hour * 3600 + $n.Minute * 60 + $n.Second)
            return [pscustomobject]@{ rc = 0; text = "DateTime=$v" } }
        [pscustomobject]@{ rc = 0; text = "~SerialNumber=SN58,FirmVer=AC Ver 4.3.4,LockCount=4" } }
    Add-Fake 'GetDeviceData' { param($h, $t, $fields, $f, $o2) Add-Content -LiteralPath $this.log "GetDeviceData:$t"
        switch ($t) {
            'user' { [pscustomobject]@{ rc = 4; text = "CardNo,Pin,Password,Group,StartTime,EndTime,Name`r`n12345,101,,0,0,0,Alpha`r`n0,2002,9999,0,0,0,Beta`r`n777,30003,,0,20260101,20261231,Gamma`r`n,44,,0,0,0,`r`n" } }
            'userauthorize' { [pscustomobject]@{ rc = 3; text = "Pin,AuthorizeTimezoneId,AuthorizeDoorId`r`n101,1,15`r`n2002,1,1`r`n999,1,15`r`n" } }
            'templatev10' {
                if ($fields -match 'Template') { throw 'the template column must never be read' }
                [pscustomobject]@{ rc = 2; text = "Pin,FingerID,Valid,Size`r`n101,0,1,512`r`n101,6,1,498`r`n" } }
            default { [pscustomobject]@{ rc = -100; text = '' } }
        } }
    return $o
}
"""


def _run(tmp_path: Path, *, connect_ok: bool = True, access_running: bool = False,
         counts: dict[str, int] | None = None) -> tuple[subprocess.CompletedProcess, dict | None, list[str]]:
    pack = tmp_path / "pack"
    pack.mkdir()
    shutil.copy2(SCRIPT, pack / SCRIPT.name)
    log = tmp_path / "calls.log"
    procs = "@([pscustomobject]@{ ProcessName = 'MonClubAccess' })" if access_running else "@()"
    overrides = "; ".join(f"$c['{t}'] = {n}" for t, n in (counts or {}).items())
    helper = (_FAKE_HELPER.replace("__LOG__", str(log)).replace("__CONNECT_OK__", "$true" if connect_ok else "$false")
              .replace("__PROCS__", procs).replace("__COUNT_OVERRIDES__", overrides))
    (pack / HELPER.name).write_text(helper, encoding="utf-8")
    proc = subprocess.run(
        [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(pack / SCRIPT.name),
         "-DeviceIp", "10.0.0.5", "-Label", "t", "-Auto"],
        capture_output=True, text=True, timeout=180, check=False,
    )
    files = sorted((pack / "exports").glob("panel_t_*.json")) if (pack / "exports").exists() else []
    doc = json.loads(files[-1].read_text(encoding="utf-8-sig")) if files else None
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return proc, doc, calls


@pytest.mark.skipif(pwsh is None, reason="PowerShell not available")
class TestAgainstAFakePanel:
    def test_a_full_export_makes_only_read_calls(self, tmp_path: Path):
        proc, doc, calls = _run(tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert doc is not None and doc["complete"] is True, proc.stdout + proc.stderr
        names = {c.split(":")[0] for c in calls}
        assert names <= READ_CALLS, sorted(names - READ_CALLS)
        assert calls[0] == "Connect:protocol=TCP,ipaddress=10.0.0.5,port=4370,timeout=5000,passwd="
        assert calls[-1] == "Disconnect"

    def test_the_file_carries_users_cards_door_rights_and_finger_ids(self, tmp_path: Path):
        proc, doc, _ = _run(tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert doc["schema"] == "monclub.pullsdk.panel_export/1"
        users = {u["pin"]: u for u in doc["users"]}
        assert set(users) == {"101", "2002", "30003", "44"}
        assert users["101"]["card"] == "12345" and users["101"]["doors"] == "15"
        assert users["101"]["fingerIds"] == ["0", "6"]
        assert users["2002"]["hasPassword"] is True
        assert "9999" not in json.dumps(doc), "the password value must never be exported"
        assert users["30003"]["other"]["EndTime"] == "20261231"
        assert users["44"]["doors"] is None
        assert doc["summary"]["withCard"] == 2          # '0' and '' are no card
        assert doc["summary"]["authorizeWithoutUser"] == 1
        assert doc["counts"]["transaction"] == 1200
        assert doc["params"]["~SerialNumber"] == "SN58"
        assert abs(doc["device"]["clockSkewSec"]) < 5

    def test_the_shape_is_what_the_comparison_reads(self, tmp_path: Path):
        """tools/gym45_cutover/compare_terminal_export.py loads this file."""
        import importlib.util
        import sys
        spec = importlib.util.spec_from_file_location(
            "compare_terminal_export_c3", REPO / "tools" / "gym45_cutover" / "compare_terminal_export.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod  # dataclasses resolve annotations through sys.modules
        spec.loader.exec_module(mod)
        proc, doc, _ = _run(tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        (path,) = (tmp_path / "pack" / "exports").glob("panel_t_*.json")
        ex = mod.load_export(str(path), 5)
        assert {u.key for u in ex.users} == {"101", "2002", "30003", "44"}
        assert ex.fingers_read is False and ex.complete is True

    def test_a_refused_connection_writes_nothing_and_exits_1(self, tmp_path: Path):
        """The firewall proof of the plan relies on this answer."""
        proc, doc, calls = _run(tmp_path, connect_ok=False)
        assert proc.returncode == 1
        assert doc is None
        assert "CONNECT FAILED" in proc.stdout
        assert [c.split(":")[0] for c in calls] == ["Connect", "PullLastError"]

    def test_a_sha256_sidecar_names_the_file(self, tmp_path: Path):
        _run(tmp_path)
        exports = tmp_path / "pack" / "exports"
        (sidecar,) = exports.glob("*.sha256")
        digest, name = sidecar.read_text(encoding="ascii").split()
        import hashlib
        assert hashlib.sha256((exports / name).read_bytes()).hexdigest() == digest


    def test_it_refuses_to_run_while_monclub_access_runs_on_this_pc(self, tmp_path: Path):
        """The guard runs before the DLL is looked for: no connection, no file."""
        proc, doc, calls = _run(tmp_path, access_running=True)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert doc is None
        assert not (tmp_path / "pack" / "exports").exists()
        assert calls == []
        assert "MonClub Access is running on this PC" in proc.stdout

    def test_a_failed_finger_count_is_an_error_not_a_count_and_the_export_is_partial(self, tmp_path: Path):
        proc, doc, calls = _run(tmp_path, counts={"templatev10": -100})
        assert proc.returncode == 2, proc.stdout + proc.stderr
        assert doc["complete"] is False
        assert doc["counts"]["templatev10"] is None
        assert "GetDeviceDataCount(templatev10) rc=-100" in doc["errors"]
        # unknown is not empty: the finger ids are still listed
        assert "GetDeviceData:templatev10" in calls
        assert {u["pin"]: u["fingerIds"] for u in doc["users"]}["101"] == ["0", "6"]
        assert "templatev10=FAILED" in proc.stdout

    def test_a_failed_user_count_makes_the_export_partial(self, tmp_path: Path):
        proc, doc, _ = _run(tmp_path, counts={"user": -2})
        assert proc.returncode == 2, proc.stdout + proc.stderr
        assert doc["complete"] is False and doc["counts"]["user"] is None
        assert "GetDeviceDataCount(user) rc=-2" in doc["errors"]
        assert doc["summary"]["users"] == 4          # the table itself was read

    def test_a_failed_count_of_another_table_is_recorded_but_not_partial(self, tmp_path: Path):
        """Whether a C3-400 answers every table name is not known: a table the runbook does not
        read as proof does not make the export partial, but it is in errors."""
        proc, doc, _ = _run(tmp_path, counts={"holiday": -100})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert doc["complete"] is True and doc["counts"]["holiday"] is None
        assert doc["errors"] == ["GetDeviceDataCount(holiday) rc=-100"]
        assert "error: GetDeviceDataCount(holiday) rc=-100" in proc.stdout

    def test_an_empty_finger_table_is_not_listed(self, tmp_path: Path):
        _, doc, calls = _run(tmp_path, counts={"templatev10": 0})
        assert doc["complete"] is True and doc["counts"]["templatev10"] == 0
        assert "GetDeviceData:templatev10" not in calls
