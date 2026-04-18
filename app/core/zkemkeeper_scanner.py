from __future__ import annotations
"""
SCR100 card reader via zkemkeeper COM — subprocess-based implementation.

Rationale:
  The PS1 script (read-card-from-scr100-zkem.ps1) works reliably on this machine.
  Our direct pywin32 Dispatch path was returning stale "0" from the idle buffer
  and never the real card UID, almost certainly because of a cross-bitness COM
  marshaling quirk between 64-bit Python and the 32-bit zkemkeeper.dll surrogate.

  Instead of fighting that, we launch PowerShell as a subprocess and run the
  same polling logic as the PS1 script.  This guarantees the COM interaction
  happens in the exact environment the user confirmed works.
"""

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class ZkemkeeperError(RuntimeError):
    pass


def initialize_com_apartment():
    """No-op: COM is owned by the PowerShell subprocess, not this thread."""
    return lambda: None


def create_zkemkeeper_com_object() -> tuple[object, str]:
    """Kept for backwards compatibility; not used by the subprocess path."""
    return None, "powershell"


_PS_SCRIPT_TEMPLATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
try {
    $zk = New-Object -ComObject "zkemkeeper.CZKEM"
} catch {
    Write-Output ("ERROR:COM_CREATE:{0}" -f $_.Exception.Message)
    exit 1
}
if (-not $zk.Connect_Net("__IP__", __PORT__)) {
    Write-Output "ERROR:CONNECT_FAIL"
    exit 2
}
try { [void]$zk.RegEvent(1, 0xFFFFFFFF) } catch {}
try { [void]$zk.GetRTLog(1) } catch {}

$deadline = (Get-Date).AddSeconds(__TIMEOUT__)
$lastCard = $null
$seenEmpty = $true

while ((Get-Date) -lt $deadline) {
    try {
        $card = ""
        $ok = $zk.GetHIDEventCardNumAsStr([ref]$card)
        if (-not $ok -or [string]::IsNullOrWhiteSpace($card)) {
            $ok = $zk.GetStrCardNumber([ref]$card)
        }
        if ($ok -and $card) {
            $card = $card.Trim()
            if ($card -and $card.TrimStart("0")) {
                if ($card -ne $lastCard -or $seenEmpty) {
                    Write-Output ("CARD:{0}" -f $card)
                    try { $zk.Disconnect() | Out-Null } catch {}
                    exit 0
                }
                $seenEmpty = $false
            } else {
                $seenEmpty = $true
            }
        } else {
            $seenEmpty = $true
        }
    } catch {}
    Start-Sleep -Milliseconds 60
}

try { $zk.Disconnect() | Out-Null } catch {}
Write-Output "TIMEOUT"
exit 3
"""


def _find_powershell() -> str:
    """Prefer 32-bit PowerShell (SysWOW64) because zkemkeeper.dll is x86."""
    candidates = [
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",          # 32-bit
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",          # 64-bit fallback
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return "powershell.exe"


@dataclass
class ZkemkeeperScanner:
    _ip: str = ""
    _port: int = 4370
    _backend: str = field(default="powershell", repr=False)

    def connect(self, *, ip: str, port: int, timeout_ms: int) -> None:
        if not ip:
            raise ZkemkeeperError("SCR100 IP address is required")
        self._ip = ip
        self._port = int(port)
        logger.info(
            "[zkemkeeper] configured for %s:%d (via PowerShell subprocess)",
            self._ip, self._port,
        )
        _ = timeout_ms

    def disconnect(self) -> None:
        # Each read is a self-contained subprocess; nothing to close here.
        pass

    def read_card_once(self, *, poll_sec: float = 20.0) -> str:
        if not self._ip:
            raise ZkemkeeperError("Not connected")

        ps_exe = _find_powershell()
        script = (
            _PS_SCRIPT_TEMPLATE
            .replace("__IP__", self._ip)
            .replace("__PORT__", str(self._port))
            .replace("__TIMEOUT__", str(max(1, int(poll_sec))))
        )

        logger.info(
            "[zkemkeeper] %s polling %s:%d for up to %.0fs",
            os.path.basename(ps_exe), self._ip, self._port, poll_sec,
        )

        creationflags = 0
        if os.name == "nt":
            creationflags = 0x08000000  # CREATE_NO_WINDOW

        try:
            proc = subprocess.run(
                [
                    ps_exe,
                    "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", script,
                ],
                capture_output=True, text=True,
                timeout=poll_sec + 15,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired:
            raise ZkemkeeperError("PowerShell subprocess timed out (hung)")
        except FileNotFoundError:
            raise ZkemkeeperError(f"PowerShell not found at {ps_exe}")

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        logger.info(
            "[zkemkeeper] PS exit=%d stdout=%r stderr=%r",
            proc.returncode, stdout[:300], stderr[:200],
        )

        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("CARD:"):
                card = line[len("CARD:"):].strip()
                logger.info("[zkemkeeper] CARD DETECTED: %r", card)
                return card
            if line.startswith("ERROR:"):
                raise ZkemkeeperError(line[len("ERROR:"):].strip() or "PowerShell error")

        if "TIMEOUT" in stdout:
            raise ZkemkeeperError("No card detected before timeout")

        raise ZkemkeeperError(
            f"PowerShell returned no CARD line (exit={proc.returncode}, stdout={stdout[:200]!r})"
        )
