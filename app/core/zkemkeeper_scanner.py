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
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

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
    [Console]::Out.WriteLine(("ERROR:COM_CREATE:{0}" -f $_.Exception.Message))
    [Console]::Out.Flush()
    exit 1
}
if (-not $zk.Connect_Net("__IP__", __PORT__)) {
    [Console]::Out.WriteLine("ERROR:CONNECT_FAIL")
    [Console]::Out.Flush()
    exit 2
}
try { [void]$zk.RegEvent(1, 0xFFFFFFFF) } catch {}
try { [void]$zk.GetRTLog(1) } catch {}
[Console]::Out.WriteLine("READY")
[Console]::Out.Flush()

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
                    [Console]::Out.WriteLine(("CARD:{0}" -f $card))
                    [Console]::Out.Flush()
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
[Console]::Out.WriteLine("TIMEOUT")
[Console]::Out.Flush()
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

    def _terminate_process(self, proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except Exception:
            return
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                return
            try:
                proc.wait(timeout=2)
            except Exception:
                pass

    def read_card_once(
        self,
        *,
        poll_sec: float = 20.0,
        on_ready: Callable[[], None] | None = None,
        stop_event: threading.Event | None = None,
    ) -> str:
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
            proc = subprocess.Popen(
                [
                    ps_exe,
                    "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", script,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                creationflags=creationflags,
            )
        except FileNotFoundError:
            raise ZkemkeeperError(f"PowerShell not found at {ps_exe}")

        if proc.stdout is None or proc.stderr is None:
            self._terminate_process(proc)
            raise ZkemkeeperError("PowerShell output pipe was not available")

        line_queue: "queue.Queue[tuple[str, str | None]]" = queue.Queue()
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        def _pump_stream(stream_name: str, stream) -> None:
            try:
                while True:
                    raw_line = stream.readline()
                    if raw_line == "":
                        break
                    line = raw_line.strip()
                    if stream_name == "stdout":
                        stdout_lines.append(line)
                    else:
                        stderr_lines.append(line)
                    line_queue.put((stream_name, line))
            finally:
                try:
                    stream.close()
                except Exception:
                    pass
                line_queue.put((stream_name, None))

        threading.Thread(
            target=_pump_stream,
            args=("stdout", proc.stdout),
            daemon=True,
            name="zkemkeeper-stdout",
        ).start()
        threading.Thread(
            target=_pump_stream,
            args=("stderr", proc.stderr),
            daemon=True,
            name="zkemkeeper-stderr",
        ).start()

        ready_sent = False
        streams_closed = {"stdout": False, "stderr": False}
        external_deadline = time.monotonic() + max(1.0, float(poll_sec)) + 15.0

        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    self._terminate_process(proc)
                    return ""

                if proc.poll() is not None and all(streams_closed.values()) and line_queue.empty():
                    break

                remaining = external_deadline - time.monotonic()
                if remaining <= 0:
                    self._terminate_process(proc)
                    raise ZkemkeeperError("PowerShell subprocess timed out (hung)")

                try:
                    stream_name, line = line_queue.get(timeout=min(0.1, remaining))
                except queue.Empty:
                    continue

                if line is None:
                    streams_closed[stream_name] = True
                    continue

                if stream_name == "stderr":
                    continue

                if line == "READY":
                    if on_ready is not None and not ready_sent:
                        on_ready()
                    ready_sent = True
                    continue

                if line.startswith("CARD:"):
                    card = line[len("CARD:"):].strip()
                    logger.info("[zkemkeeper] CARD DETECTED: %r", card)
                    return card

                if line.startswith("ERROR:COM_CREATE:"):
                    detail = line.split(":", 2)[2].strip() or "COM creation failed"
                    raise ZkemkeeperError(f"Cannot create zkemkeeper COM object: {detail}")

                if line.startswith("ERROR:CONNECT_FAIL"):
                    raise ZkemkeeperError(
                        f"Cannot connect to SCR100 at {self._ip}:{self._port}"
                    )

                if line.startswith("ERROR:"):
                    raise ZkemkeeperError(line[len("ERROR:"):].strip() or "PowerShell error")

                if line == "TIMEOUT":
                    raise ZkemkeeperError("No card detected before timeout")
        finally:
            if proc.poll() is None:
                self._terminate_process(proc)

        stdout = "\n".join(stdout_lines).strip()
        stderr = "\n".join(stderr_lines).strip()
        logger.info(
            "[zkemkeeper] PS exit=%s stdout=%r stderr=%r",
            proc.returncode, stdout[:300], stderr[:200],
        )

        if "TIMEOUT" in stdout:
            raise ZkemkeeperError("No card detected before timeout")

        raise ZkemkeeperError(
            "PowerShell returned no CARD line "
            f"(exit={proc.returncode}, stdout={stdout[:200]!r}, stderr={stderr[:200]!r})"
        )
