from __future__ import annotations

import ctypes
import logging
import math
import os
import time
from ctypes import c_void_p, c_char_p, c_int
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.utils import encode_ansi, parse_device_text


class PullSDKError(RuntimeError):
    pass


class PullSDK:
    """
    ctypes wrapper for plcommpro.dll (Pull SDK).
    """

    def __init__(self, dll_path: str, logger):
        self.dll_path = str(Path(dll_path))
        self.logger = logger
        self._dll = None
        self._h: Optional[int] = None

    def load(self) -> None:
        if self._dll is not None:
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

            self.logger.info("PullSDK loaded OK.")
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
            f"passwd={''}",
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
                text = buf.value.decode("mbcs", errors="replace")
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
                text = buf.value.decode("mbcs", errors="replace")
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
        rc, text = self.get_device_data_text(
            table=table,
            fields=fields,
            filter_expr=filter_expr,
            options=options,
            initial_size=initial_size,
        )
        if rc == 0 or not text.strip():
            return []
        return parse_device_text(text)

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
                text = buf.value.decode("mbcs", errors="replace")
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

        self.ip = self._pick_str(["ip", "ipAddress", "ipaddress", "host", "address"], default="")
        self.port = self._pick_int(["port", "devicePort"], default=4370)
        self.password = self._pick_str(["password", "passwd", "pass", "devicePassword"], default="")
        self.platform = self._pick_str(["platform", "devicePlatform"], default="")

        self.timeout_ms = self._pick_int(["timeoutMs", "timeout", "connectTimeoutMs"], default=3000)
        self.dll_path = self._resolve_dll_path(self._pick_str(["dllPath", "dll_path", "pullsdkDllPath"], default=""))

        self._sdk: Optional[PullSDK] = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return bool(self._connected and self._sdk is not None)

    def ensure_connected(self) -> bool:
        if self.is_connected:
            return True
        return self.connect()

    def connect(self) -> bool:
        try:
            self.disconnect()

            if not self.ip or int(self.port) <= 0:
                raise PullSDKError(f"invalid device connection params ip={self.ip!r} port={self.port!r}")

            self._sdk = PullSDK(self.dll_path, self.logger)
            self._sdk.connect(
                ip=str(self.ip),
                port=int(self.port),
                timeout_ms=int(self.timeout_ms),
                password=str(self.password or ""),
                platform=str(self.platform or "") if (self.platform or "").strip() else None,
            )
            self._connected = True
            return True
        except Exception as e:
            self._connected = False
            self._sdk = None
            try:
                self.logger.debug(f"[PullSDKDevice][{self.device_id}] connect failed: {e}")
            except Exception:
                pass
            return False

    def disconnect(self) -> None:
        try:
            if self._sdk:
                self._sdk.disconnect()
        except Exception:
            pass
        self._sdk = None
        self._connected = False

    def open_door(self, *, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> bool:
        _ = timeout_ms  # Pull SDK door pulse is synchronous; kept for API symmetry
        if not self.ensure_connected():
            return False
        try:
            assert self._sdk is not None
            seconds = int(max(1, min(60, math.ceil(int(pulse_time_ms) / 1000.0))))
            self._sdk.door_pulse_open(door=int(door_id), seconds=int(seconds))
            return True
        except Exception as e:
            try:
                self.logger.debug(f"[PullSDKDevice][{self.device_id}] open_door failed: {e}")
            except Exception:
                pass
            return False

    def poll_rtlog_once(self) -> List[Dict[str, Any]]:
        """
        Preferred: GetRTLogExt (PUSH format, easy parsing).
        Fallback: GetDeviceData(transaction, Options="new record").

        Returns normalized dicts:
          eventId, doorId, eventType, cardNo, eventTime, table, rawRow
        """
        if not self.ensure_connected():
            return []

        assert self._sdk is not None

        # 1) Preferred: RTLogExt
        try:
            if self._sdk.supports_get_rtlog_ext():
                recs = self._sdk.get_rtlogext_records()
                if not recs:
                    return []

                out: List[Dict[str, Any]] = []
                for r in recs:
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

                    # Create a stable synthetic eventId (device does not provide an id in rtlogext)
                    event_id = f"{event_time}|{card_no}|{event_code}|{event_addr}|{pin}|{inout}|{verify}"

                    out.append(
                        {
                            "eventId": event_id,
                            "doorId": event_addr or None,
                            "eventType": event_code or "RTLOG",
                            "cardNo": card_no,
                            "eventTime": event_time,
                            "table": "rtlogext",
                            "rawRow": r,
                        }
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
            for r in rows:
                # common keys
                event_time = self._safe_str(self._get_any(r, ["time", "Time"]), "")
                card_no = self._safe_str(self._get_any(r, ["cardno", "CardNo"]), "")
                door_id = self._safe_str(self._get_any(r, ["doorid", "DoorID", "eventaddr", "EventAddr"]), "")
                event_type = self._safe_str(self._get_any(r, ["eventtype", "EventType", "event", "Event"]), "TX")

                event_id = f"{event_time}|{card_no}|{event_type}|{door_id}"

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
