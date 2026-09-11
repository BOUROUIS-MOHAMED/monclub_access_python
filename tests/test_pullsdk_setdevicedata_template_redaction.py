"""A fingerprint template must never reach `app.log` -- the log leaves the building.

WHY THIS FILE EXISTS
--------------------
`PullSDK.set_device_data` logged its whole payload at INFO::

    self.logger.info(f"SetDeviceData(table={table}) data={data}")

For `table="template"` / `"templatev10"` that payload carries
`Template=<full base64 fingerprint template>`. A 512-byte template rendered a
771-character log line containing the complete biometric. `[CODE]`

That line is not local. Three sinks consume it:

  * the rotated `app.log` on the gym PC's disk,
  * `log_uploader.py`, which ships finalized log files OFF-SITE to Cloudinary
    (POST_MULTIPART) or R2 -- no redaction exists anywhere in `logger.py`,
    `log_uploader.py` or `log_buffer.py`, and the default level is DEBUG,
  * `log_buffer.py`'s in-memory ring, which the dashboard's live-log view reads.

So every full roster sync exported one member's biometric per finger to a
third-party CDN. `[CODE]`

The codebase already knew this was wrong. The enrol path deliberately logs only
`templateChars` and `sha1[:8]` -- its comment says the digest exists "without any
part of the biometric ever being written to disk" (`app/ui/app.py`,
`ENROLL_BACKEND_REQ`). The push path simply never got the same treatment, so the
fix here mirrors that existing pattern rather than inventing a new one.

There are TWO sinks in this file, not one. `set_device_data_batch`'s row-by-row
fallback logged `row[:80]`. `Template=` begins at roughly offset 33 of a typical
row, so slicing to 80 characters published ~31 characters of the template. Slicing
BEFORE redacting is precisely how that second leak survived review; these tests pin
both.

WHAT IS DELIBERATELY *NOT* REDACTED
-----------------------------------
Only the `Template=` value is masked. `Pin`, `FingerID`, `Valid`, `Size`, the table
name and the rc code all pass through byte-for-byte, because structural-error
diagnosis (rc=-100/-101/-102/-103) depends on seeing exactly what was sent. A
handler-level logging filter was rejected for the same reason -- it would have had
to re-enumerate all three sinks; fixing the two emit sites closes all three at once.

The wire is untouched: `encode_ansi(data)` still hands the REAL template to
`plcommpro.dll`. A test that only checked the log could pass while silently
breaking every door in the fleet, so `test_..._but_real_on_the_wire` asserts the
unredacted bytes still reach the DLL.
"""

from __future__ import annotations

import base64
import hashlib
import threading

import pytest

from app.sdk.pullsdk import PullSDK, PullSDKError, _redact_template_field


# A realistic 512-byte ZK template, base64 -> 684 chars.
TEMPLATE_B64 = base64.b64encode(bytes(range(256)) * 2).decode("ascii")


class _RecordingLogger:
    """Captures rendered lines so we can compare them to the real bytes."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def _record(self, msg, *args):
        try:
            self.lines.append(str(msg) % args if args else str(msg))
        except Exception:  # pragma: no cover - a format mismatch is its own failure
            self.lines.append(f"{msg!r} % {args!r}")

    info = _record
    debug = _record
    warning = _record
    error = _record

    def exception(self, msg, *args, **kw):  # pragma: no cover
        self._record(msg, *args)

    @property
    def blob(self) -> str:
        return "\n".join(self.lines)


class _RecordingDLL:
    """Fake plcommpro.dll that records the exact bytes handed to SetDeviceData."""

    def __init__(self, fail_marker: bytes | None = None) -> None:
        self.calls: list[bytes] = []
        self._fail_marker = fail_marker

    def SetDeviceData(self, handle, table, data, options):
        self.calls.append(data)
        if self._fail_marker is not None and self._fail_marker in data:
            return -101  # structural error
        return 0

    def PullLastError(self):  # pragma: no cover - only reached on the failure path
        return -101

    @property
    def wire(self) -> bytes:
        return b"".join(self.calls)


def _sdk(dll: _RecordingDLL) -> PullSDK:
    sdk = PullSDK.__new__(PullSDK)
    sdk.logger = _RecordingLogger()
    sdk._dll = dll
    sdk._require_handle = lambda: 1
    # set_device_data is @_holds_handle-decorated (commit c3ea99e), so the
    # fixture needs the handle-lease bookkeeping the decorator touches.
    sdk._h_lock = threading.Lock()
    sdk._inflight = 0
    sdk._pending_free = None
    return sdk


def _row(pin: str, template: str) -> str:
    return f"Pin={pin}\tFingerID=1\tValid=1\tSize=512\tTemplate={template}"


class TestSetDeviceDataTemplateRedaction:
    def test_template_is_masked_in_the_log_but_real_on_the_wire(self):
        dll = _RecordingDLL()
        sdk = _sdk(dll)

        sdk.set_device_data(table="templatev10", data=_row("1234", TEMPLATE_B64) + "\r\n")

        log = sdk.logger.blob

        # (1) THE WIRE IS UNTOUCHED. Without this, a "passing" redaction could mean
        #     we stopped sending real templates to the door.
        assert TEMPLATE_B64.encode("mbcs") in dll.wire

        # (2) the biometric never reaches the log
        assert TEMPLATE_B64 not in log

        # (3) something visibly stands in for it
        assert "Template=<redacted" in log

        # (4) every non-biometric field survives verbatim, for rc=-101 diagnosis
        for field in ("Pin=1234", "FingerID=1", "Valid=1", "Size=512", "templatev10"):
            assert field in log, f"{field!r} must stay greppable in the log"

        # (5) the digest is the SAME shape the enrol path already emits, so one
        #     template can be correlated across enrol and push log lines
        digest = hashlib.sha1(TEMPLATE_B64.encode("utf-8")).hexdigest()[:8]
        assert f"sha1={digest}" in log
        assert f"len={len(TEMPLATE_B64)}" in log

    def test_batch_row_by_row_fallback_does_not_leak_a_template_fragment(self):
        # Row 2 is poisoned, so the combined chunk fails, the row-by-row fallback
        # runs, and row 2 fails again -- landing on the `row=%s` warning.
        dll = _RecordingDLL(fail_marker=b"FAIL_ME")
        sdk = _sdk(dll)

        rows = [_row("1", TEMPLATE_B64), _row("2", "FAIL_ME" + TEMPLATE_B64)]
        ok, failed = sdk.set_device_data_batch(table="templatev10", rows=rows, chunk_size=50)

        log = sdk.logger.blob

        # the slice-before-redact bug published ~31 chars of the template here
        assert TEMPLATE_B64[:20] not in log
        assert TEMPLATE_B64 not in log

        # and the fallback still did its job
        assert ok == 1
        assert failed == [rows[1]]

    def test_non_template_tables_are_logged_byte_for_byte(self):
        """Redaction must not blind the diagnostics operators actually grep."""
        dll = _RecordingDLL()
        sdk = _sdk(dll)

        payload = "Pin=1234\tName=Jane Doe\tCardNo=0009876543\tPri=0"
        sdk.set_device_data(table="user", data=payload + "\r\n")

        assert payload in sdk.logger.blob
        assert "redacted" not in sdk.logger.blob


class TestRedactHelper:
    def test_passthrough_when_no_template_field(self):
        s = "Pin=1\tName=x"
        assert _redact_template_field(s) is s or _redact_template_field(s) == s

    def test_redacts_every_row_of_a_multi_row_payload(self):
        a, b = "AAAA1111", "BBBB2222"
        data = "\r\n".join([_row("1", a), _row("2", b)])
        out = _redact_template_field(data)

        assert a not in out and b not in out
        # both rows are masked independently, with their own digests
        assert out.count("Template=<redacted") == 2
        assert hashlib.sha1(a.encode()).hexdigest()[:8] in out
        assert hashlib.sha1(b.encode()).hexdigest()[:8] in out
        # row structure preserved
        assert out.count("\r\n") == 1
        assert "Pin=1" in out and "Pin=2" in out

    def test_an_empty_template_value_is_still_masked(self):
        out = _redact_template_field("Pin=1\tTemplate=")
        assert "Template=<redacted:len=0:" in out
