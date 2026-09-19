"""tools/mb2000_scripts/14_export_terminal_readonly.ps1 must never write to a terminal.

It is the tool the gym-45 cutover plan hands to the owner to read both MB2000s
before they are wiped, so "read-only" is the property that matters, and it is
checked two ways:

  * statically - every COM call in the script and in the ``_common.ps1`` it
    dot-sources is on a read allowlist, and no write method name appears in
    either file outside a comment;
  * by running the SHIPPED script against a fake COM object that has ONLY the
    read methods and logs every call it receives. A write call would throw
    "method not found" inside the script and the export would come back
    incomplete - and it would be in the call log.

The allowlist is the ZKTeco standalone SDK's documented reads plus the
connection itself. "Documented as a read" is what the static check can prove;
what the firmware does with a read is not something a test on a fake can
settle (guide_for_agents_and_dev.md section 7).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PACK = REPO / "tools" / "mb2000_scripts"
SCRIPT = PACK / "14_export_terminal_readonly.ps1"
COMMON = PACK / "_common.ps1"

READ_CALLS = {
    # the connection (_common.ps1) - SetCommPassword sets the PC side of the COMM key
    "SetCommPassword", "Connect_Net", "Disconnect",
    # identity and counters
    "GetFirmwareVersion", "GetSerialNumber", "GetDeviceMAC", "GetPlatform",
    "GetVendor", "GetDeviceIP", "GetDeviceTime", "GetDeviceStatus", "GetSysOption",
    # users and templates
    "ReadAllUserID", "SSR_GetAllUserInfo", "GetStrCardNumber", "SSR_GetUserTmpStr",
}

# Methods of the zkemkeeper COM object that change the terminal. None may appear in
# the export script or in _common.ps1 outside a comment.
WRITE_CALLS = {
    "SetStrCardNumber", "SSR_SetUserInfo", "SetUserInfo", "SetUserTmpExStr",
    "SetUserTmpStr", "SSR_SetUserTmpStr", "SetUserTmp", "SetUserTmpEx",
    "SSR_DelUserTmpExt", "SSR_DelUserTmp", "DelUserTmp", "SSR_DeleteEnrollData",
    "DeleteEnrollData", "SSR_DeleteEnrollDataExt", "ClearData", "ClearGLog",
    "ClearSLog", "ClearKeeperData", "ClearAdministrators", "EnableDevice",
    "EnableUser", "SSR_EnableUser", "RefreshData", "SetDeviceTime", "SetDeviceTime2",
    "SetSysOption", "SetDeviceInfo", "ACUnlock", "RestartDevice", "PowerOffDevice",
    "SetUserFace", "DelUserFace", "SetDeviceIP", "SetDeviceMAC", "SetDeviceCommPwd",
    "SetUserGroup", "SetUserTZStr", "SSR_SetUserSMS", "SetSMS", "ClearPhotoByTime",
    "DeleteAttlogBetweenTheDate", "DeleteAttlogByTime", "SetWiegandFmt", "UpdateFirmware",
    "WriteLCD", "PlayVoice", "PlayVoiceByIndex", "SetCustomizeAttState", "StartEnrollEx",
    "StartEnroll", "CancelOperation", "SetCardFun",
}

_ZK_CALL = re.compile(r"\$zk\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _code_lines(path: Path) -> list[str]:
    """The file without comments: ``#`` to end of line (outside quotes) and ``<# #>``."""
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
    @pytest.mark.parametrize("path", [SCRIPT, COMMON], ids=lambda p: p.name)
    def test_every_com_call_is_a_read(self, path: Path):
        calls = set(_ZK_CALL.findall("\n".join(_code_lines(path))))
        assert calls, f"no $zk.<call>( found in {path.name}: the check is no longer looking at the right thing"
        assert calls <= READ_CALLS, f"{path.name} calls {sorted(calls - READ_CALLS)}, which is not on the read allowlist"

    @pytest.mark.parametrize("path", [SCRIPT, COMMON], ids=lambda p: p.name)
    def test_no_write_method_name_outside_a_comment(self, path: Path):
        code = "\n".join(_code_lines(path))
        found = sorted(n for n in WRITE_CALLS if re.search(rf"\b{re.escape(n)}\b", code))
        assert not found, f"{path.name} names {found} in code"

    def test_no_dynamic_invocation_on_the_com_object(self):
        code = "\n".join(_code_lines(SCRIPT))
        for pattern in (r"\$zk\.\$", r"InvokeMember", r"Invoke-Expression", r"\biex\b",
                        r"\$zk\.PSObject", r"\$zk\.psbase"):
            assert not re.search(pattern, code, re.I), f"dynamic COM access ({pattern}) in the export script"

    def test_the_com_object_is_never_handed_anywhere_else(self):
        """Outside ``$zk.<Method>(`` the object may only be created by Connect-Zkem and
        closed by Disconnect-Zkem (both in _common.ps1, checked above). Anything else -
        an alias, a helper taking it as an argument - would put a call out of reach of
        the allowlist check."""
        bare = [line.strip() for line in _code_lines(SCRIPT)
                for _ in re.finditer(r"\$zk\b(?!\.)", line)]
        assert bare == ["$zk = Connect-Zkem $cfg", "Disconnect-Zkem $zk"], bare

    def test_only_common_is_dot_sourced(self):
        code = "\n".join(_code_lines(SCRIPT))
        sourced = re.findall(r"^\s*\.\s+['\"]?([^'\"\s]+)", code, re.M)
        assert sourced == ["$PSScriptRoot\\_common.ps1"], sourced


pwsh = shutil.which("powershell") or shutil.which("pwsh")

# Appended to a COPY of _common.ps1: shadows New-Zkem with a fake terminal holding three
# users, and Get-Process with an empty answer (the dev PC may run MonClub Access).
_FAKE = r"""
function Get-Process { param($Name, $ErrorAction) @() }
function New-Zkem {
    $o = [pscustomobject]@{
        users = @(
            @{ pin = '101'; name = 'Alpha'; card = '555'; pwd = ''; priv = 0; en = $true;  fp = @{ 0 = 'AAEC'; 3 = 'BAUG' } },
            @{ pin = '2002'; name = 'Beta';  card = '';    pwd = 'x'; priv = 3; en = $true;  fp = @{} },
            @{ pin = '30003'; name = 'Gamma'; card = '0';  pwd = ''; priv = 0; en = $false; fp = @{ 9 = 'not base64!' } }
        )
        i = 0
        log = '__LOG__'
    }
    function Add-Fake($name, [scriptblock]$body) { $o | Add-Member -MemberType ScriptMethod -Name $name -Value $body }
    Add-Fake 'SetCommPassword'   { param($k) Add-Content -LiteralPath $this.log 'SetCommPassword'; $true }
    Add-Fake 'Connect_Net'       { param($ip, $port) Add-Content -LiteralPath $this.log 'Connect_Net'; $true }
    Add-Fake 'Disconnect'        { Add-Content -LiteralPath $this.log 'Disconnect' }
    Add-Fake 'GetFirmwareVersion' { param($mn, [ref]$v) Add-Content -LiteralPath $this.log 'GetFirmwareVersion'; $v.Value = 'Ver 6.60'; $true }
    Add-Fake 'GetSerialNumber'   { param($mn, [ref]$v) Add-Content -LiteralPath $this.log 'GetSerialNumber'; $v.Value = 'SN123'; $true }
    Add-Fake 'GetDeviceMAC'      { param($mn, [ref]$v) Add-Content -LiteralPath $this.log 'GetDeviceMAC'; $v.Value = '00:17:61'; $true }
    Add-Fake 'GetPlatform'       { param($mn, [ref]$v) Add-Content -LiteralPath $this.log 'GetPlatform'; $v.Value = 'ZMM220'; $true }
    Add-Fake 'GetVendor'         { param([ref]$v) Add-Content -LiteralPath $this.log 'GetVendor'; $v.Value = 'ZKTeco'; $true }
    Add-Fake 'GetDeviceIP'       { param($mn, [ref]$v) Add-Content -LiteralPath $this.log 'GetDeviceIP'; $v.Value = '10.0.0.1'; $true }
    Add-Fake 'GetSysOption'      { param($mn, $opt, [ref]$v) Add-Content -LiteralPath $this.log "GetSysOption:$opt"; $v.Value = '10'; $true }
    Add-Fake 'GetDeviceTime'     { param($mn, [ref]$y, [ref]$mo, [ref]$d, [ref]$h, [ref]$mi, [ref]$s)
        Add-Content -LiteralPath $this.log 'GetDeviceTime'; $n = Get-Date
        $y.Value = $n.Year; $mo.Value = $n.Month; $d.Value = $n.Day; $h.Value = $n.Hour; $mi.Value = $n.Minute; $s.Value = $n.Second; $true }
    Add-Fake 'GetDeviceStatus'   { param($mn, $idx, [ref]$n) Add-Content -LiteralPath $this.log 'GetDeviceStatus'
        $map = @{ 1 = 1; 2 = 3; 3 = 3; 7 = 3000; 8 = 3000; 10 = 2997; 11 = 2997; 21 = 0 }
        if ($map.ContainsKey([int]$idx)) { $n.Value = $map[[int]$idx]; return $true }; return $false }
    Add-Fake 'ReadAllUserID'     { param($mn) Add-Content -LiteralPath $this.log 'ReadAllUserID'; $this.i = 0; $true }
    Add-Fake 'SSR_GetAllUserInfo' { param($mn, [ref]$pin, [ref]$name, [ref]$pwd, [ref]$priv, [ref]$en)
        Add-Content -LiteralPath $this.log 'SSR_GetAllUserInfo'
        if ($this.i -ge $this.users.Count) { return $false }
        $u = $this.users[$this.i]; $this.i++
        $pin.Value = $u.pin; $name.Value = $u.name; $pwd.Value = $u.pwd; $priv.Value = $u.priv; $en.Value = $u.en; $true }
    Add-Fake 'GetStrCardNumber'  { param([ref]$card) Add-Content -LiteralPath $this.log 'GetStrCardNumber'; $card.Value = $this.users[$this.i - 1].card; $true }
    Add-Fake 'SSR_GetUserTmpStr' { param($mn, $pin, $fid, [ref]$tmp, [ref]$len)
        Add-Content -LiteralPath $this.log 'SSR_GetUserTmpStr'
        $u = $this.users | Where-Object { $_.pin -eq "$pin" }
        if ($u -and $u.fp.ContainsKey([int]$fid)) { $tmp.Value = $u.fp[[int]$fid]; $len.Value = $u.fp[[int]$fid].Length; return $true }
        return $false }
    return $o
}
"""


def _run_export(tmp_path: Path, *extra: str) -> tuple[subprocess.CompletedProcess, dict | None, list[str]]:
    pack = tmp_path / "pack"
    pack.mkdir()
    shutil.copy2(SCRIPT, pack / SCRIPT.name)
    log = tmp_path / "calls.log"
    common = COMMON.read_text(encoding="utf-8-sig") + _FAKE.replace("__LOG__", str(log))
    (pack / "_common.ps1").write_text(common, encoding="utf-8")
    proc = subprocess.run(
        [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(pack / SCRIPT.name),
         "-DeviceIp", "10.0.0.1", "-Label", "t", "-Auto", *extra],
        capture_output=True, text=True, timeout=180, check=False,
    )
    files = sorted((pack / "exports").glob("terminal_t_*.json")) if (pack / "exports").exists() else []
    doc = json.loads(files[-1].read_text(encoding="utf-8-sig")) if files else None
    calls = log.read_text(encoding="utf-8").split() if log.exists() else []
    return proc, doc, calls


@pytest.mark.skipif(pwsh is None, reason="PowerShell not available")
class TestAgainstAFakeTerminal:
    def test_a_full_export_makes_only_read_calls(self, tmp_path: Path):
        proc, doc, calls = _run_export(tmp_path, "-IncludeTemplates")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert doc is not None and doc["complete"] is True, proc.stdout + proc.stderr
        names = {c.split(":")[0] for c in calls}
        assert names <= READ_CALLS, sorted(names - READ_CALLS)
        assert "GetSysOption:~ZKFPVersion" in calls

    def test_the_file_carries_users_slots_and_counters(self, tmp_path: Path):
        proc, doc, _ = _run_export(tmp_path, "-Fingers")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert doc["schema"] == "monclub.mb2000.terminal_export/1"
        assert doc["device"]["fpVersion"] == "10"
        assert doc["counters"]["2"]["value"] == 3 and doc["counters"]["11"]["value"] == 2997
        users = {u["pin"]: u for u in doc["users"]}
        assert set(users) == {"101", "2002", "30003"}
        assert users["2002"]["privilege"] == 3 and users["2002"]["hasPassword"] is True
        assert "x" not in json.dumps(users["2002"]), "the password value must never be exported"
        assert users["30003"]["enabled"] is False
        assert [s["fingerId"] for s in users["101"]["slots"]] == [0, 3]
        assert users["101"]["slots"][0]["hashedAs"] == "base64"
        assert users["101"]["slots"][0]["decodedBytes"] == 3
        assert users["30003"]["slots"][0]["hashedAs"] == "text"
        assert doc["summary"] == {
            "users": 3, "privileged": 1, "disabled": 1, "withCard": 1, "withPassword": 1,
            "withFingers": 2, "fingerSlots": 3,
        }

    def test_without_templates_there_is_no_restorable_fingers_list(self, tmp_path: Path):
        """10_backup_restore_device.ps1's Restore clears every slot named in ``fingers``
        before writing its template; a ``fingers`` list without templates must not exist."""
        proc, doc, _ = _run_export(tmp_path, "-Fingers")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert all("fingers" not in u for u in doc["users"])
        assert "AAEC" not in json.dumps(doc), "no template string without -IncludeTemplates"

    def test_with_templates_the_file_is_in_the_restore_shape(self, tmp_path: Path):
        proc, doc, _ = _run_export(tmp_path, "-IncludeTemplates")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        alpha = next(u for u in doc["users"] if u["pin"] == "101")
        assert alpha["fingers"] == [
            {"fingerId": 0, "template": "AAEC", "size": 4},
            {"fingerId": 3, "template": "BAUG", "size": 4},
        ]

    def test_users_only_reads_no_template(self, tmp_path: Path):
        proc, doc, calls = _run_export(tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "SSR_GetUserTmpStr" not in calls
        assert all("slots" not in u for u in doc["users"])

    def test_a_sample_run_is_marked_partial(self, tmp_path: Path):
        proc, doc, _ = _run_export(tmp_path, "-MaxUsers", "2")
        assert proc.returncode == 2
        assert doc["complete"] is False and "MaxUsers" in doc["stopReason"]
        assert len(doc["users"]) == 2

    def test_a_sha256_sidecar_names_the_file(self, tmp_path: Path):
        _run_export(tmp_path)
        exports = tmp_path / "pack" / "exports"
        (sidecar,) = exports.glob("*.sha256")
        digest, name = sidecar.read_text(encoding="ascii").split()
        import hashlib
        assert hashlib.sha256((exports / name).read_bytes()).hexdigest() == digest
