from __future__ import annotations

import ctypes
import logging
import math
import os
import threading
import time
from ctypes import c_void_p, c_char_p, c_int
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.utils import encode_ansi, parse_device_text


class PullSDKError(RuntimeError):
    pass


def _decode_sdk_bytes(data: bytes) -> str:
    """
    Decode bytes from PullSDK buffer.
    ZKTeco PullSDK uses ANSI (system code page) encoding.
    Falls back through utf-8 and latin-1 to ensure no data is lost.
    """
    if not data:
        return ""
    # Try system ANSI code page first (mbcs — correct for ZKTeco SDK)
    try:
        return data.decode("mbcs", errors="strict")
    except (UnicodeDecodeError, LookupError):
        pass
    # Try UTF-8 (some newer firmware may use UTF-8)
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    # Latin-1 never raises — safe last resort
    return data.decode("latin-1", errors="replace")


_GLOBAL_SDK_LOCK = threading.Lock()  # serialize DLL load + connect across all devices


class PullSDK:
    """
    ctypes wrapper for plcommpro.dll (Pull SDK).
    """
    _load_lock = threading.Lock()  # class-level: serialize DLL loading across instances
    # Class-level DLL cache: dll_path → ctypes.WinDLL (with all prototypes registered).
    # After the first load (~200ms), every subsequent PullSDK instance that uses the same
    # DLL path skips WinDLL() + all argtypes/restype registration and completes in ~1µs.
    # This makes _GLOBAL_SDK_LOCK hold-time near-zero on retries.
    _dll_cache: Dict[str, Any] = {}

    def __init__(self, dll_path: str, logger):
        self.dll_path = str(Path(dll_path))
        self.logger = logger
        self._dll = None
        self._h: Optional[int] = None

    def load(self) -> None:
        if self._dll is not None:
            return
        # Fast path: return cached DLL without acquiring any lock (~1µs).
        # The dict assignment below is GIL-protected, so no lock needed for reads.
        cached = PullSDK._dll_cache.get(self.dll_path)
        if cached is not None:
            self._dll = cached
            return
        with PullSDK._load_lock:
            if self._dll is not None:
                return  # another thread loaded while we waited for lock
            # Re-check cache inside lock (double-checked locking).
            cached = PullSDK._dll_cache.get(self.dll_path)
            if cached is not None:
                self._dll = cached
                return
            try:
                self.logger.info(f"Loading PullSDK DLL: {self.dll_path}")
                self._dll = ctypes.WinDLL(self.dll_path)  # stdcall

                # prototypes
                self._dll.Connect.argtypes = [c_char_p]
                self._dll.Connect.restype = c_void_p

                self._dll.Disconnect.argtypes = [c_void_p]
                self._dll.Disconnect.restype = c_int

                # int GetDeviceData(HANDLE h, char* buffer, int buffersize, char* table, char* fields, char* filter, char* options);
                self._dll.GetDeviceData.argtypes = [c_void_p, c_void_p, c_int, c_char_p, c_char_p, c_char_p, c_char_p]
                self._dll.GetDeviceData.restype = c_int

                # int SetDeviceData(HANDLE h, char* table, char* data, char* options);
                self._dll.SetDeviceData.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
                self._dll.SetDeviceData.restype = c_int

                # int DeleteDeviceData(HANDLE h, char* table, char* data, char* options);
                if hasattr(self._dll, "DeleteDeviceData"):
                    self._dll.DeleteDeviceData.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
                    self._dll.DeleteDeviceData.restype = c_int

                # int ControlDevice(HANDLE h, int operationId, int param1, int param2, int param3, int param4, char* options);
                if hasattr(self._dll, "ControlDevice"):
                    self._dll.ControlDevice.argtypes = [c_void_p, c_int, c_int, c_int, c_int, c_int, c_char_p]
                    self._dll.ControlDevice.restype = c_int

                # int GetRTLog(void *handle,char *Buffer, int BufferSize)
                if hasattr(self._dll, "GetRTLog"):
                    self._dll.GetRTLog.argtypes = [c_void_p, c_void_p, c_int]
                    self._dll.GetRTLog.restype = c_int

                # int GetRTLogExt(void *handle,char *Buffer, int BufferSize)
                if hasattr(self._dll, "GetRTLogExt"):
                    self._dll.GetRTLogExt.argtypes = [c_void_p, c_void_p, c_int]
                    self._dll.GetRTLogExt.restype = c_int

                self._dll.PullLastError.argtypes = []
                self._dll.PullLastError.restype = c_int

                # int GetDeviceDataCount(HANDLE h, char* table, char* filter, char* options);
                if hasattr(self._dll, "GetDeviceDataCount"):
                    self._dll.GetDeviceDataCount.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
                    self._dll.GetDeviceDataCount.restype = c_int

                # int GetDeviceParam(HANDLE h, char* buffer, int buffersize, char* itemname);
                if hasattr(self._dll, "GetDeviceParam"):
                    self._dll.GetDeviceParam.argtypes = [c_void_p, c_void_p, c_int, c_char_p]
                    self._dll.GetDeviceParam.restype = c_int

                # int SetDeviceParam(HANDLE h, char* item);
                if hasattr(self._dll, "SetDeviceParam"):
                    self._dll.SetDeviceParam.argtypes = [c_void_p, c_char_p]
                    self._dll.SetDeviceParam.restype = c_int

                self.logger.info("PullSDK loaded OK.")
                # Cache the fully-initialised DLL object for all future instances.
                # GIL makes this dict write atomic — no extra lock needed.
                PullSDK._dll_cache[self.dll_path] = self._dll
            except OSError as e:
                self._dll = None
                raise PullSDKError(f"Failed to load plcommpro.dll: {e}")

    def connect(self, *, ip: str, port: int, timeout_ms: int, password: str, platform: str | None = None) -> None:
        self.load()
        if self._dll is None:
            raise PullSDKError("PullSDK not loaded")

        parts = [
            "protocol=TCP",
            f"ipaddress={ip}",
            f"port={port}",
            f"timeout={timeout_ms}",
            f"passwd={password}",
        ]

        conn_str = ",".join(parts)

        self.logger.info(
            "PullSDK Connect: protocol=TCP,ipaddress=%s,port=%s,timeout=%s,passwd=%s%s",
            ip,
            port,
            timeout_ms,
            ("*" * min(8, len(password)) if password else ""),
            (f",platform={platform}" if platform else ""),
        )

        h = self._dll.Connect(encode_ansi(conn_str))
        if not h:
            err = self.pull_last_error()
            raise PullSDKError(f"Connection FAILED ({ip}:{port}) PullLastError={err}")
        self._h = int(h)
        self.logger.info(f"Connected OK. Handle={self._h}")

    def disconnect(self) -> None:
        if self._dll is None or not self._h:
            return
        try:
            self.logger.info("PullSDK Disconnect...")
            self._dll.Disconnect(c_void_p(self._h))
        finally:
            self._h = None
            self.logger.info("Disconnected.")

    def pull_last_error(self) -> int:
        """
        NOTE: PullLastError() reads from a global (non-thread-local) DLL variable.
        Under concurrent multi-device scenarios, the returned value may reflect
        a different thread's last error. Use only for supplementary diagnostics.
        All correctness decisions must be based on the return code (rc) of each SDK call.
        """
        if self._dll is None:
            return -9999
        return int(self._dll.PullLastError())

    def _require_handle(self) -> int:
        if not self._h:
            raise PullSDKError("Not connected to device.")
        return self._h

    @staticmethod
    def _normalize_fields(fields: str) -> str:
        # PullSDK v2.2+ expects FieldNames separated by '\t' when not '*'
        f = (fields or "").strip()
        if not f:
            return "*"
        if f == "*":
            return "*"
        tmp = f.replace(";", "\t").replace(",", "\t").replace("  ", " ").strip()
        parts = [p.strip() for p in tmp.split("\t") if p.strip()]
        return "\t".join(parts) if parts else "*"

    @staticmethod
    def _normalize_filter(filter_expr: str) -> str:
        # v2.2: multiple conditions separated by '\t'
        s = (filter_expr or "").strip()
        if not s:
            return ""
        s = s.replace(" = ", "=").replace("= ", "=").replace(" =", "=")
        s = s.replace(", ", ",")
        # allow user to pass either comma-separated or tab-separated conditions
        s = s.replace(",", "\t")
        while "\t\t" in s:
            s = s.replace("\t\t", "\t")
        return s

    # -------------------- low-level buffer helpers --------------------

    def _call_with_growing_buffer(
            self,
            *,
            fn_name: str,
            call: Any,
            sizes: List[int],
            debug_label: str,
    ) -> Tuple[int, str]:
        """
        Execute a PullSDK function that writes into a buffer.
        Returns (rc, text).
        """
        last_rc: Optional[int] = None
        last_err: Optional[int] = None

        for attempt, sz in enumerate(sizes, start=1):
            buf = ctypes.create_string_buffer(sz)
            rc = int(call(buf, sz))

            if rc >= 0:
                text = _decode_sdk_bytes(buf.value)
                self.logger.debug(f"{fn_name} OK rc={rc} size={sz} attempt={attempt} {debug_label}")
                return rc, text

            # PullLastError is often 0 here; rc itself is what matters.
            err = self.pull_last_error()
            last_rc, last_err = rc, err
            self.logger.warning(f"{fn_name} rc={rc} err={err} size={sz} attempt={attempt} {debug_label}")

            # Buffer-related (documented): -3 buffer insufficient, -112 recv buffer insufficient.
            # Some firmwares return other negative codes for "need more buffer"; include -114/-115 (observed in the wild).
            if rc in (-3, -112, -114, -115):
                continue

            raise PullSDKError(f"{fn_name} FAILED rc={rc} PullLastError={err} {debug_label}")

        raise PullSDKError(f"{fn_name} FAILED after max size last_rc={last_rc} PullLastError={last_err} {debug_label}")

    # -------------------- GetRTLog / GetRTLogExt --------------------

    def supports_get_rtlog(self) -> bool:
        self.load()
        return self._dll is not None and hasattr(self._dll, "GetRTLog")

    def supports_get_rtlog_ext(self) -> bool:
        self.load()
        return self._dll is not None and hasattr(self._dll, "GetRTLogExt")

    def get_rtlog_text(self, *, initial_size: int | None = None) -> Tuple[int, str]:
        h = self._require_handle()
        self.load()
        if self._dll is None or not hasattr(self._dll, "GetRTLog"):
            raise PullSDKError("GetRTLog not available in this plcommpro.dll build.")

        sizes = [64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024]
        if initial_size and initial_size > 0:
            sizes = [initial_size] + [s for s in sizes if s > initial_size]

        def _do(buf: Any, sz: int) -> int:
            return int(self._dll.GetRTLog(c_void_p(h), ctypes.cast(buf, c_void_p), c_int(sz)))

        return self._call_with_growing_buffer(
            fn_name="GetRTLog",
            call=_do,
            sizes=sizes,
            debug_label="",
        )

    def get_rtlog_ext_text(self, *, initial_size: int | None = None) -> Tuple[int, str]:
        h = self._require_handle()
        self.load()
        if self._dll is None or not hasattr(self._dll, "GetRTLogExt"):
            raise PullSDKError("GetRTLogExt not available in this plcommpro.dll build.")

        sizes = [64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024]
        if initial_size and initial_size > 0:
            sizes = [initial_size] + [s for s in sizes if s > initial_size]

        def _do(buf: Any, sz: int) -> int:
            return int(self._dll.GetRTLogExt(c_void_p(h), ctypes.cast(buf, c_void_p), c_int(sz)))

        return self._call_with_growing_buffer(
            fn_name="GetRTLogExt",
            call=_do,
            sizes=sizes,
            debug_label="",
        )

    @staticmethod
    def _parse_rtlogext(text: str) -> List[Dict[str, str]]:
        """
        Parse PUSH-format lines:
          type=rtlog\ttime=...\tpin=...\tcardno=...\teventaddr=...\tevent=...\tinoutstatus=...\tverifytype=...
          type=rtstate\t...
        """
        out: List[Dict[str, str]] = []
        if not text:
            return out

        # records separated by CRLF
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        for ln in lines:
            parts = [p for p in ln.split("\t") if p]
            d: Dict[str, str] = {}
            for p in parts:
                if "=" in p:
                    k, v = p.split("=", 1)
                    d[k.strip()] = v.strip()
                else:
                    # tolerate weird tokens
                    d[p.strip()] = ""
            if d:
                out.append(d)
        return out

    def get_rtlogext_records(self) -> List[Dict[str, str]]:
        """
        Returns parsed records from GetRTLogExt. May contain:
          - type=rtlog (event)
          - type=rtstate (door/alarm state)
        """
        rc, text = self.get_rtlog_ext_text()
        if rc <= 0 or not text.strip():
            return []
        return self._parse_rtlogext(text)

    # -------------------- GetDeviceData --------------------

    def get_device_data_text(
            self,
            *,
            table: str,
            fields: str = "*",
            filter_expr: str = "",
            options: str = "",
            initial_size: int | None = None,
    ) -> Tuple[int, str]:
        h = self._require_handle()
        if self._dll is None:
            raise PullSDKError("PullSDK not loaded")

        fields_n = self._normalize_fields(fields)
        filter_n = self._normalize_filter(filter_expr)

        self.logger.debug(f"GetDeviceData(table={table}, fields={fields_n}, filter={filter_n}, options={options})")

        sizes = [1_048_576, 2_097_152, 4_194_304, 8_388_608]
        if initial_size and initial_size > 0:
            sizes = [initial_size] + [s for s in sizes if s > initial_size]

        last_rc: Optional[int] = None
        last_err: Optional[int] = None

        for attempt, sz in enumerate(sizes, start=1):
            buf = ctypes.create_string_buffer(sz)
            rc = int(
                self._dll.GetDeviceData(
                    c_void_p(h),
                    ctypes.cast(buf, c_void_p),
                    c_int(sz),
                    encode_ansi(table),
                    encode_ansi(fields_n),
                    encode_ansi(filter_n),
                    encode_ansi(options),
                )
            )

            if rc >= 0:
                text = _decode_sdk_bytes(buf.value)
                self.logger.debug(f"GetDeviceData OK rc={rc} size={sz} attempt={attempt}")
                return rc, text

            err = self.pull_last_error()
            last_rc, last_err = rc, err
            self.logger.warning(f"GetDeviceData rc={rc} err={err} size={sz} attempt={attempt}")

            # buffer-related / controller-quirk codes
            if rc in (-3, -112, -114, -115):
                continue

            raise PullSDKError(f"GetDeviceData FAILED table={table} rc={rc} PullLastError={err}")

        raise PullSDKError(
            f"GetDeviceData FAILED after max size. table={table} last_rc={last_rc} PullLastError={last_err}")

    def get_device_data_rows(
            self,
            *,
            table: str,
            fields: str = "*",
            filter_expr: str = "",
            options: str = "",
            initial_size: int | None = None,
    ) -> List[Dict[str, str]]:
        import time as _ptime
        _t0 = _ptime.monotonic()
        rc, text = self.get_device_data_text(
            table=table,
            fields=fields,
            filter_expr=filter_expr,
            options=options,
            initial_size=initial_size,
        )
        if rc == 0 or not text.strip():
            _el = (_ptime.monotonic() - _t0) * 1000
            self.logger.debug(f"get_device_data_rows: table={table} rc={rc} rows=0 {_el:.0f}ms")
            return []
        rows = parse_device_text(text)
        _el = (_ptime.monotonic() - _t0) * 1000
        self.logger.debug(f"get_device_data_rows: table={table} rc={rc} rows={len(rows)} {_el:.0f}ms")
        return rows

    def get_device_data_count(self, *, table: str, filter_expr: str = "", options: str = "") -> int:
        h = self._require_handle()
        if self._dll is None or not hasattr(self._dll, "GetDeviceDataCount"):
            return -1

        filter_n = self._normalize_filter(filter_expr)
        rc = int(
            self._dll.GetDeviceDataCount(c_void_p(h), encode_ansi(table), encode_ansi(filter_n), encode_ansi(options)))
        self.logger.debug(f"GetDeviceDataCount(table={table}, filter={filter_n}) => {rc}")
        return rc

    def set_device_data(self, *, table: str, data: str, options: str = "") -> int:
        h = self._require_handle()
        if self._dll is None:
            raise PullSDKError("PullSDK not loaded")

        self.logger.info(f"SetDeviceData(table={table}) data={data}")
        rc = int(self._dll.SetDeviceData(c_void_p(h), encode_ansi(table), encode_ansi(data), encode_ansi(options)))
        if rc < 0:
            err = self.pull_last_error()
            raise PullSDKError(f"SetDeviceData FAILED table={table} rc={rc} PullLastError={err}")
        return rc

    def set_device_data_batch(
        self,
        *,
        table: str,
        rows: list,
        chunk_size: int = 50,
        progress_cb=None,
    ) -> tuple:
        """
        Send multiple rows to the device in batched SetDeviceData calls.

        Each row is a tab-separated key=value string (without trailing \\r\\n).
        Rows are grouped into chunks of ``chunk_size`` and each chunk is sent as
        a single SetDeviceData call with rows separated by \\r\\n.

        Returns ``(ok_count, failed_rows)`` where *failed_rows* is a list of row
        strings that could not be written (empty on full success).

        On chunk failure the method falls back to row-by-row for that chunk so
        a single bad record does not block the rest.

        **Fast-path short-circuit:** if the row-by-row fallback returns a
        STRUCTURAL error code (rc=-101 field missing, rc=-100 table missing,
        rc=-102/-103 field layout mismatch) on the very first row, every
        subsequent row in this AND all remaining chunks will fail the same way
        — the row payload format itself is wrong for this firmware. We bail out
        immediately and mark the rest as failed so the caller's domain-level
        retry (e.g. drop-Name-and-retry) can fire without burning N×50 SDK
        round-trips on a foregone conclusion.
        """
        if not rows:
            return (0, [])

        # Structural errors — the payload shape is wrong; row-by-row won't help.
        _FATAL_CODES = ("rc=-100", "rc=-101", "rc=-102", "rc=-103")

        ok = 0
        failed: list = []
        structural_bailout = False

        for i in range(0, len(rows), chunk_size):
            if structural_bailout:
                failed.extend(rows[i:])
                break

            chunk = rows[i:i + chunk_size]
            data = "\r\n".join(chunk) + "\r\n"
            try:
                self.set_device_data(table=table, data=data, options="")
                ok += len(chunk)
            except PullSDKError:
                # Chunk failed — fall back to row-by-row for this chunk
                self.logger.warning(
                    "set_device_data_batch chunk failed (table=%s, rows=%d), falling back to row-by-row",
                    table, len(chunk),
                )
                for j, row in enumerate(chunk):
                    try:
                        self.set_device_data(table=table, data=row + "\r\n", options="")
                        ok += 1
                    except PullSDKError as ex:
                        self.logger.warning("set_device_data_batch row-by-row failed: %s | row=%s", ex, row[:80])
                        failed.append(row)
                        # Short-circuit on the FIRST row if it's a structural error:
                        # subsequent rows in the same and later chunks will all fail
                        # the same way. Let the caller's outer retry take over.
                        if j == 0 and any(code in str(ex) for code in _FATAL_CODES):
                            remaining_in_chunk = chunk[j + 1:]
                            if remaining_in_chunk:
                                self.logger.warning(
                                    "set_device_data_batch: structural error on first row "
                                    "(%s), short-circuiting remaining %d row(s) in chunk and "
                                    "%d later chunks",
                                    str(ex).split(" PullLastError")[0],
                                    len(remaining_in_chunk),
                                    max(0, (len(rows) - (i + chunk_size))),
                                )
                            failed.extend(remaining_in_chunk)
                            structural_bailout = True
                            break
            # Progress tick after every chunk (successful OR fallback) so the
            # dashboard sees movement during the multi-minute batch phase.
            if progress_cb is not None:
                try:
                    progress_cb(ok, len(rows))
                except Exception:
                    pass
        return (ok, failed)

    def clear_device_table(self, *, table: str) -> int:
        """
        Delete ALL records from a device table by passing an empty filter.

        Equivalent to ``DeleteDeviceData(handle, table, "", "")``.
        Used by nuke-and-repave when more users need deleting than keeping.
        """
        h = self._require_handle()
        self.load()
        if self._dll is None or not hasattr(self._dll, "DeleteDeviceData"):
            raise PullSDKError("DeleteDeviceData not available in this plcommpro.dll build.")

        self.logger.info(f"ClearDeviceTable(table={table}) — deleting ALL rows")
        rc = int(self._dll.DeleteDeviceData(c_void_p(h), encode_ansi(table), encode_ansi(""), encode_ansi("")))
        if rc < 0:
            err = self.pull_last_error()
            raise PullSDKError(f"ClearDeviceTable FAILED table={table} rc={rc} PullLastError={err}")
        return rc

    def supports_delete_device_data(self) -> bool:
        self.load()
        return self._dll is not None and hasattr(self._dll, "DeleteDeviceData")

    def delete_device_data(self, *, table: str, data: str, options: str = "") -> int:
        h = self._require_handle()
        self.load()
        if self._dll is None or not hasattr(self._dll, "DeleteDeviceData"):
            raise PullSDKError("DeleteDeviceData not available in this plcommpro.dll build.")

        self.logger.info(f"DeleteDeviceData(table={table}) data={data}")
        rc = int(self._dll.DeleteDeviceData(c_void_p(h), encode_ansi(table), encode_ansi(data), encode_ansi(options)))
        if rc < 0:
            err = self.pull_last_error()
            raise PullSDKError(f"DeleteDeviceData FAILED table={table} rc={rc} PullLastError={err}")
        return rc

    def delete_device_data_batch(
        self,
        *,
        table: str,
        pins: list,
        chunk_size: int = 100,
        condition_field: str = "Pin",
    ) -> tuple:
        """
        Delete multiple rows from a device table in one DeleteDeviceData call.

        Each pin becomes a record ``{condition_field}={pin}`` joined by \\r\\n,
        and the batch is split into chunks of ``chunk_size``. On chunk failure
        the method falls back to per-pin deletes so a bad record cannot block
        the rest of the chunk.

        Returns ``(ok_count, failed_pins)`` — failed_pins is the list of pins
        that could not be deleted (empty on full success).

        Validated against ZKTeco PullSDK User Guide V2.0: ``Data`` is a record
        payload, not a SQL filter; multi-row deletes are the documented bulk
        pattern on C2/C3/InBio firmware.
        """
        if not pins:
            return (0, [])

        self.load()
        if self._dll is None or not hasattr(self._dll, "DeleteDeviceData"):
            raise PullSDKError("DeleteDeviceData not available in this plcommpro.dll build.")

        ok = 0
        failed: list = []
        pins_list = [str(p) for p in pins]
        for i in range(0, len(pins_list), chunk_size):
            chunk = pins_list[i:i + chunk_size]
            data = "\r\n".join(f"{condition_field}={p}" for p in chunk) + "\r\n"
            try:
                self.delete_device_data(table=table, data=data, options="")
                ok += len(chunk)
            except PullSDKError as ex:
                self.logger.warning(
                    "delete_device_data_batch chunk failed (table=%s, rows=%d): %s — falling back to per-pin",
                    table, len(chunk), ex,
                )
                for pin in chunk:
                    try:
                        self.delete_device_data(
                            table=table,
                            data=f"{condition_field}={pin}",
                            options="",
                        )
                        ok += 1
                    except PullSDKError as ex2:
                        self.logger.warning(
                            "delete_device_data_batch per-pin fallback failed table=%s %s=%s: %s",
                            table, condition_field, pin, ex2,
                        )
                        failed.append(pin)
        return (ok, failed)

    # -------------------- ControlDevice (Door control) --------------------

    def supports_control_device(self) -> bool:
        self.load()
        return self._dll is not None and hasattr(self._dll, "ControlDevice")

    def control_device(
            self,
            *,
            operation_id: int,
            param1: int,
            param2: int,
            param3: int,
            param4: int,
            options: str = "",
    ) -> int:
        h = self._require_handle()
        self.load()
        if self._dll is None or not hasattr(self._dll, "ControlDevice"):
            raise PullSDKError("ControlDevice not available in this plcommpro.dll build.")

        self.logger.info(
            f"ControlDevice(op={operation_id}, p1={param1}, p2={param2}, p3={param3}, p4={param4}, options={options!r})"
        )
        rc = int(
            self._dll.ControlDevice(
                c_void_p(h),
                c_int(int(operation_id)),
                c_int(int(param1)),
                c_int(int(param2)),
                c_int(int(param3)),
                c_int(int(param4)),
                encode_ansi(options or ""),
            )
        )
        if rc < 0:
            err = self.pull_last_error()
            raise PullSDKError(f"ControlDevice FAILED rc={rc} PullLastError={err}")
        return rc

    def door_pulse_open(self, *, door: int, seconds: int = 3) -> int:
        if seconds < 1:
            seconds = 1
        if seconds > 60:
            seconds = 60
        return self.control_device(operation_id=1, param1=int(door), param2=1, param3=int(seconds), param4=0,
                                   options="")

    def set_door_normal_open(self, *, door: int, enabled: bool) -> int:
        return self.control_device(
            operation_id=4,
            param1=int(door),
            param2=(1 if enabled else 0),
            param3=0,
            param4=0,
            options="",
        )

    def cancel_alarm(self) -> int:
        return self.control_device(operation_id=2, param1=0, param2=0, param3=0, param4=0, options="")

    # -------------------- GetDeviceParam --------------------

    def supports_get_device_param(self) -> bool:
        self.load()
        return self._dll is not None and hasattr(self._dll, "GetDeviceParam")

    def get_device_param(self, *, items: str, initial_size: int | None = None) -> str:
        h = self._require_handle()
        self.load()
        if self._dll is None or not hasattr(self._dll, "GetDeviceParam"):
            raise PullSDKError("GetDeviceParam not available in this plcommpro.dll build.")

        it = (items or "").strip()
        if not it:
            raise PullSDKError("items is empty for GetDeviceParam")

        sizes = [64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024]
        if initial_size and initial_size > 0:
            sizes = [initial_size] + [s for s in sizes if s > initial_size]

        last_err = None
        last_rc = None

        for attempt, sz in enumerate(sizes, start=1):
            buf = ctypes.create_string_buffer(sz)
            rc = int(
                self._dll.GetDeviceParam(
                    c_void_p(h),
                    ctypes.cast(buf, c_void_p),
                    c_int(sz),
                    encode_ansi(it),
                )
            )

            if rc >= 0:
                text = _decode_sdk_bytes(buf.value)
                self.logger.debug(f"GetDeviceParam OK rc={rc} size={sz} attempt={attempt}")
                return text

            err = self.pull_last_error()
            last_err = err
            last_rc = rc
            self.logger.warning(f"GetDeviceParam rc={rc} err={err} size={sz} attempt={attempt}")

            if rc in (-3, -112, -114, -115):
                continue

            raise PullSDKError(f"GetDeviceParam FAILED rc={rc} PullLastError={err}")

        raise PullSDKError(f"GetDeviceParam FAILED after max size. last_rc={last_rc} PullLastError={last_err}")

    def supports_set_device_param(self) -> bool:
        self.load()
        return self._dll is not None and hasattr(self._dll, "SetDeviceParam")

    def set_device_param(self, *, items: str) -> int:
        h = self._require_handle()
        self.load()
        if self._dll is None or not hasattr(self._dll, "SetDeviceParam"):
            raise PullSDKError("SetDeviceParam not available in this plcommpro.dll build.")
        it = (items or "").strip()
        if not it:
            raise PullSDKError("items is empty for SetDeviceParam")
        self.logger.debug(f"SetDeviceParam({it!r})")
        rc = int(self._dll.SetDeviceParam(c_void_p(h), encode_ansi(it)))
        if rc < 0:
            err = self.pull_last_error()
            raise PullSDKError(f"SetDeviceParam FAILED rc={rc} PullLastError={err} items={it!r}")
        return rc


class PullSDKDevice:
    """
    High-level per-device wrapper used by realtime_agent.py.

    Exposes ONLY device-oriented operations:
      - ensure_connected / disconnect
      - poll_rtlog_once (normalized event rows)
      - open_door
    """

    def __init__(self, device_payload: Dict[str, Any], logger=None):
        self.payload = device_payload or {}
        self.logger = logger or logging.getLogger("PullSDKDevice")

        self.device_id = self._safe_int(self.payload.get("id"), 0)
        self.name = self._safe_str(self.payload.get("name"), f"device-{self.device_id}")

        self.ip = self._pick_str(["ip", "ipAddress", "ipaddress", "ip_address", "host", "address"], default="")
        self.port = self._pick_int(["port", "portNumber", "port_number", "devicePort"], default=4370)
        self.password = self._pick_str(["password", "passwd", "pass", "devicePassword"], default="")
        self.platform = self._pick_str(["platform", "devicePlatform"], default="")

        self.timeout_ms = self._pick_int(["timeoutMs", "timeout", "connectTimeoutMs"], default=3000)
        self.dll_path = self._resolve_dll_path(self._pick_str(["dllPath", "dll_path", "pullsdkDllPath"], default=""))

        self._sdk: Optional[PullSDK] = None
        self._connected = False
        self._event_seq: int = 0
        self._sdk_lock = threading.Lock()  # F-007: serialize concurrent SDK calls

    @property
    def is_connected(self) -> bool:
        return bool(self._connected and self._sdk is not None)

    def ensure_connected(self) -> bool:
        if self.is_connected:
            return True
        return self.connect()

    def connect(self) -> bool:
        self.logger.info(
            "[PullSDKDevice][%s] connect attempt: name=%r ip=%s port=%s timeout_ms=%s",
            self.device_id, self.name, self.ip, self.port, self.timeout_ms,
        )
        # Declared before try so it's always accessible in the except block,
        # even if an early-path exception (e.g. invalid params) fires before
        # the SDK object is created.
        _pending_sdk: Optional["PullSDK"] = None
        try:
            self.disconnect()

            if not self.ip or int(self.port) <= 0:
                raise PullSDKError(f"invalid device connection params ip={self.ip!r} port={self.port!r}")

            # Serialize DLL load + prototype registration only (~100ms).
            # PullSDK._load_lock (class-level) already handles this, but
            # _GLOBAL_SDK_LOCK adds a belt-and-suspenders guarantee across
            # all PullSDK instances.  The TCP connect (timeout_ms, up to 5s)
            # runs OUTSIDE the lock so that multiple devices can connect in
            # parallel instead of serializing the full timeout per device.
            _pending_sdk = PullSDK(self.dll_path, self.logger)
            with _GLOBAL_SDK_LOCK:
                _pending_sdk.load()  # WinDLL + ctypes prototype registration only
            _pending_sdk.connect(
                ip=str(self.ip),
                port=int(self.port),
                timeout_ms=int(self.timeout_ms),
                password=str(self.password or ""),
                platform=str(self.platform or "") if (self.platform or "").strip() else None,
            )
            self._sdk = _pending_sdk
            self._connected = True
            self.logger.info(
                "[PullSDKDevice][%s] connected OK: name=%r ip=%s port=%s",
                self.device_id, self.name, self.ip, self.port,
            )
            return True
        except Exception as e:
            self._connected = False
            self._sdk = None
            # Clean up the pending SDK instance in case the TCP connect
            # succeeded but something raised afterward (prevents DLL handle
            # leak).  PullSDK.disconnect() is a no-op when _h is None, so
            # this is always safe.
            if _pending_sdk is not None:
                try:
                    _pending_sdk.disconnect()
                except Exception:
                    pass
            try:
                self.logger.warning(
                    "[PullSDKDevice][%s] connect FAILED: name=%r ip=%s port=%s error=%s",
                    self.device_id, self.name, self.ip, self.port, e,
                )
            except Exception:
                pass
            return False

    def disconnect(self) -> None:
        if self._connected or self._sdk:
            self.logger.debug(
                "[PullSDKDevice][%s] disconnect: name=%r was_connected=%s",
                self.device_id, self.name, self._connected,
            )
        try:
            if self._sdk:
                self._sdk.disconnect()
        except Exception:
            pass
        self._sdk = None
        self._connected = False

    def open_door(self, *, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> bool:
        # F-007: serialize concurrent SDK calls with per-device lock
        with self._sdk_lock:
            _ = timeout_ms  # Pull SDK door pulse is synchronous; kept for API symmetry
            self.logger.info(
                "[PullSDKDevice][%s] open_door: name=%r door_id=%s pulse_ms=%s",
                self.device_id, self.name, door_id, pulse_time_ms,
            )
            if not self.ensure_connected():
                self.logger.warning(
                    "[PullSDKDevice][%s] open_door FAILED: not connected (name=%r door_id=%s)",
                    self.device_id, self.name, door_id,
                )
                return False
            try:
                assert self._sdk is not None
                seconds = int(max(1, min(60, math.ceil(int(pulse_time_ms) / 1000.0))))

                # Many C3-200 firmware versions ignore ControlDevice param3 and use the
                # device's stored DoorNDriveTime instead. Set it explicitly before firing
                # the relay so the configured pulse time is always respected.
                if self._sdk.supports_set_device_param():
                    try:
                        self._sdk.set_device_param(items=f"Door{door_id}Drivertime={seconds}")
                    except Exception as _sp_err:
                        self.logger.debug(
                            "[PullSDKDevice][%s] SetDeviceParam Door%sDriveTime=%s ignored: %s",
                            self.device_id, door_id, seconds, _sp_err,
                        )

                self._sdk.door_pulse_open(door=int(door_id), seconds=int(seconds))
                self.logger.info(
                    "[PullSDKDevice][%s] open_door OK: name=%r door_id=%s seconds=%s",
                    self.device_id, self.name, door_id, seconds,
                )
                return True
            except Exception as e:
                try:
                    self.logger.warning(
                        "[PullSDKDevice][%s] open_door FAILED: name=%r door_id=%s error=%s",
                        self.device_id, self.name, door_id, e,
                    )
                except Exception:
                    pass
                return False

    def get_table_count(self, *, table: str, filter_expr: str = "", options: str = "") -> int:
        with self._sdk_lock:
            if not self.ensure_connected():
                return -1
            try:
                assert self._sdk is not None
                return int(self._sdk.get_device_data_count(table=table, filter_expr=filter_expr, options=options))
            except Exception as e:
                try:
                    self.logger.debug(f"[PullSDKDevice][{self.device_id}] get_table_count failed table={table}: {e}")
                except Exception:
                    pass
                return -1

    def read_table_rows(
        self,
        *,
        table: str,
        fields: str = "*",
        filter_expr: str = "",
        options: str = "",
        initial_size: int | None = None,
    ) -> List[Dict[str, str]]:
        with self._sdk_lock:
            if not self.ensure_connected():
                return []
            try:
                assert self._sdk is not None
                return self._sdk.get_device_data_rows(
                    table=table,
                    fields=fields,
                    filter_expr=filter_expr,
                    options=options,
                    initial_size=initial_size,
                )
            except Exception as e:
                try:
                    self.logger.debug(f"[PullSDKDevice][{self.device_id}] read_table_rows failed table={table}: {e}")
                except Exception:
                    pass
                return []

    def delete_table_rows(self, *, table: str, data: str = "", options: str = "") -> int:
        with self._sdk_lock:
            if not self.ensure_connected():
                return -1
            try:
                assert self._sdk is not None
                return int(self._sdk.delete_device_data(table=table, data=data, options=options))
            except Exception as e:
                try:
                    self.logger.debug(f"[PullSDKDevice][{self.device_id}] delete_table_rows failed table={table}: {e}")
                except Exception:
                    pass
                return -1

    def read_transaction_rows(self, *, options: str = "new record", initial_size: int | None = None) -> List[Dict[str, str]]:
        return self.read_table_rows(
            table="transaction",
            fields="*",
            filter_expr="",
            options=options,
            initial_size=initial_size,
        )

    def delete_all_transaction_rows(self) -> int:
        return self.delete_table_rows(table="transaction", data="", options="")

    def poll_rtlog_once(self) -> List[Dict[str, Any]]:
        """
        Preferred: GetRTLogExt (PUSH format, easy parsing).
        Fallback: GetDeviceData(transaction, Options="new record").

        Returns normalized dicts:
          eventId, doorId, eventType, cardNo, eventTime, table, rawRow
        """
        # F-007: serialize concurrent SDK calls with per-device lock
        with self._sdk_lock:
            return self._poll_rtlog_once_locked()

    def _poll_rtlog_once_locked(self) -> List[Dict[str, Any]]:
        """Internal: called under _sdk_lock."""
        import time as _ptime
        _t0 = _ptime.monotonic()
        if not self.ensure_connected():
            self.logger.debug(f"[PullSDKDevice][{self.device_id}] poll_rtlog: not connected")
            return []

        assert self._sdk is not None

        self._event_seq += 1
        seq = self._event_seq

        # 1) Preferred: RTLogExt
        try:
            if self._sdk.supports_get_rtlog_ext():
                recs = self._sdk.get_rtlogext_records()
                if not recs:
                    return []

                out: List[Dict[str, Any]] = []
                for idx, r in enumerate(recs, 1):
                    rtype = (r.get("type") or "").strip().lower()
                    if rtype != "rtlog":
                        # rtstate (door/alarm state) or unknown => ignore for access events
                        continue

                    event_time = (r.get("time") or "").strip()
                    card_no = (r.get("cardno") or "").strip()
                    event_code = (r.get("event") or "").strip()
                    event_addr = (r.get("eventaddr") or "").strip()  # door number / point number
                    inout = (r.get("inoutstatus") or "").strip()
                    verify = (r.get("verifytype") or "").strip()
                    pin = (r.get("pin") or "").strip()

                    # Create a stable synthetic eventId (device does not provide an id in rtlogext).
                    # Include idx (position within this poll batch) to disambiguate same-second events.
                    event_id = f"{event_time}|{card_no}|{event_code}|{event_addr}|{pin}|{inout}|{verify}|{seq}:{idx}"

                    out.append(
                        {
                            "eventId": event_id,
                            "doorId": event_addr or None,
                            "eventType": event_code or "RTLOG",
                            # F-004: use pin as fallback identifier when cardno is empty (PIN-only/fingerprint events)
                            "cardNo": card_no or pin,
                            "eventTime": event_time,
                            "table": "rtlogext",
                            "rawRow": r,
                        }
                    )

                _el = (_ptime.monotonic() - _t0) * 1000
                if out:
                    self.logger.debug(
                        f"[PullSDKDevice][{self.device_id}] poll_rtlog: {len(out)} event(s) via rtlogext {_el:.0f}ms"
                    )
                return out
        except Exception as e:
            # Don't disconnect here; just fall back
            try:
                self.logger.debug(f"[PullSDKDevice][{self.device_id}] GetRTLogExt failed, fallback to transaction: {e}")
            except Exception:
                pass

        # 2) Fallback: transaction "new record"
        try:
            rows = self._sdk.get_device_data_rows(
                table="transaction",
                fields="*",
                filter_expr="",
                options="new record",
            )
            if not rows:
                return []

            out: List[Dict[str, Any]] = []
            for idx, r in enumerate(rows, 1):
                # common keys
                event_time = self._safe_str(self._get_any(r, ["time", "Time"]), "")
                card_no = self._safe_str(self._get_any(r, ["cardno", "CardNo"]), "")
                door_id = self._safe_str(self._get_any(r, ["doorid", "DoorID", "eventaddr", "EventAddr"]), "")
                event_type = self._safe_str(self._get_any(r, ["eventtype", "EventType", "event", "Event"]), "TX")

                # F-010: Skip non-access event types in transaction table.
                # Event code 0 = normal punch (access). Larger codes are alarms, sensor events, etc.
                # Only process events that look like access events (empty type or code 0 or non-numeric).
                try:
                    et_int = int(event_type)
                    if et_int not in (0,) and et_int > 0:
                        continue  # skip alarm/sensor events
                except (ValueError, TypeError):
                    pass  # non-numeric type — keep it (may be "TX" etc.)

                # Include idx (position within this poll batch) to disambiguate same-second events.
                event_id = f"{event_time}|{card_no}|{event_type}|{door_id}|{seq}:{idx}"

                out.append(
                    {
                        "eventId": event_id,
                        "doorId": door_id or None,
                        "eventType": event_type,
                        "cardNo": card_no,
                        "eventTime": event_time,
                        "table": "transaction",
                        "rawRow": r,
                    }
                )
            return out
        except Exception as e:
            # At this point, something is genuinely wrong; let upper layers decide reconnect policy
            raise e

    # -------------------- helpers --------------------

    @staticmethod
    def _safe_int(v: Any, default: int = 0) -> int:
        try:
            if v is None:
                return default
            if isinstance(v, bool):
                return int(v)
            return int(float(str(v).strip()))
        except Exception:
            return default

    @staticmethod
    def _safe_str(v: Any, default: str = "") -> str:
        if v is None:
            return default
        try:
            return str(v)
        except Exception:
            return default

    def _pick_str(self, keys: List[str], default: str = "") -> str:
        for k in keys:
            v = self.payload.get(k)
            s = self._safe_str(v, "").strip()
            if s:
                return s
        lm = {str(k).lower(): k for k in (self.payload or {}).keys()}
        for k in keys:
            kk = lm.get(str(k).lower())
            if kk is None:
                continue
            s = self._safe_str(self.payload.get(kk), "").strip()
            if s:
                return s
        return default

    def _pick_int(self, keys: List[str], default: int = 0) -> int:
        s = self._pick_str(keys, default="")
        if not s:
            return int(default)
        return self._safe_int(s, int(default))

    def _get_any(self, row: Dict[str, Any], keys: List[str]) -> Any:
        for k in keys:
            if k in row:
                v = row.get(k)
                if v not in (None, ""):
                    return v
        lm = {str(k).lower(): k for k in row.keys()}
        for k in keys:
            kk = lm.get(str(k).lower())
            if kk is None:
                continue
            v = row.get(kk)
            if v not in (None, ""):
                return v
        return None

    def _resolve_dll_path(self, dll_path: str) -> str:
        env = os.getenv("MC_PULLSDK_DLL", "").strip()
        if env:
            return env

        p = (dll_path or "").strip()
        if p:
            return p

        here = Path(__file__).resolve().parent
        candidates = [
            here / "plcommpro.dll",
            here / "dll" / "plcommpro.dll",
            Path.cwd() / "plcommpro.dll",
            Path.cwd() / "dll" / "plcommpro.dll",
        ]
        for c in candidates:
            try:
                if c.exists() and c.is_file():
                    return str(c)
            except Exception:
                continue

        return "plcommpro.dll"
