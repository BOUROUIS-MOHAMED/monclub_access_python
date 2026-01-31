# monclub_access_python/app/sdk/pullsdk.py
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
            f"passwd={password}",
        ]
        if platform and str(platform).strip():
            parts.append(f"platform={str(platform).strip()}")

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
        f = (fields or "").strip()
        if not f:
            return "*"
        if f == "*":
            return "*"

        tmp = f.replace(";", ",").replace("\t", ",")
        parts = [p.strip() for p in tmp.split(",") if p.strip()]
        return "\t".join(parts) if parts else "*"

    @staticmethod
    def _normalize_filter(filter_expr: str) -> str:
        s = (filter_expr or "").strip()
        if not s:
            return ""

        s = s.replace(" = ", "=").replace("= ", "=").replace(" =", "=")
        s = s.replace(", ", ",")
        s = s.replace(",", "\t")
        while "\t\t" in s:
            s = s.replace("\t\t", "\t")
        return s

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

        sizes = [1_048_576, 2_097_152, 4_194_304, 8_388_608, 16_777_216, 33_554_432, 50_331_648]
        if initial_size and initial_size > 0:
            sizes = [initial_size] + [s for s in sizes if s > initial_size]

        last_err = None
        last_rc = None

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
            last_err = err
            last_rc = rc
            self.logger.warning(f"GetDeviceData rc={rc} err={err} size={sz} attempt={attempt}")

            if rc in (-102, -114):
                continue

            raise PullSDKError(f"GetDeviceData FAILED table={table} rc={rc} PullLastError={err}")

        raise PullSDKError(
            f"GetDeviceData FAILED after max size. table={table} last_rc={last_rc} PullLastError={last_err}"
        )

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
        rc = int(self._dll.GetDeviceDataCount(c_void_p(h), encode_ansi(table), encode_ansi(filter_n), encode_ansi(options)))
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
        return self.control_device(operation_id=1, param1=int(door), param2=1, param3=int(seconds), param4=0, options="")

    def set_door_normal_open(self, *, door: int, enabled: bool) -> int:
        return self.control_device(operation_id=4, param1=int(door), param2=(1 if enabled else 0), param3=0, param4=0, options="")

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

            if rc in (-102, -114):
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

    This fixes: `from app.sdk.pullsdk import PullSDKDevice`
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

        # in-memory cursor (keeps reads incremental inside one process)
        self._last_id = 0

        # rtlog read strategy (fallbacks)
        self._rtlog_candidates = [
            # common in controllers
            ("rtlog", "id,time,cardno,eventtype,doorid", "id", "time", "cardno", "doorid", "eventtype"),
            ("rtlog", "id,Time,CardNo,EventType,DoorID", "id", "Time", "CardNo", "DoorID", "EventType"),
            # common in attendance devices / some firmwares
            ("transaction", "id,time,cardno,eventtype,doorid", "id", "time", "cardno", "doorid", "eventtype"),
            ("transaction", "id,Time,CardNo,EventType,DoorID", "id", "Time", "CardNo", "DoorID", "EventType"),
        ]

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
                password=str(self.password),
                platform=str(self.platform).strip() or None,
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
        Reads new RTLog rows and returns normalized dicts containing:
          eventId, doorId, eventType, cardNo, eventTime
        """
        if not self.ensure_connected():
            return []

        assert self._sdk is not None

        last_err: Optional[Exception] = None
        for table, fields, id_k, time_k, card_k, door_k, type_k in self._rtlog_candidates:
            try:
                filter_expr = f"{id_k}>{int(self._last_id)}" if int(self._last_id) > 0 else ""
                rows = self._sdk.get_device_data_rows(table=table, fields=fields, filter_expr=filter_expr, options="")
                if not rows:
                    return []

                out: List[Dict[str, Any]] = []
                max_id = int(self._last_id)

                for r in rows:
                    if not isinstance(r, dict):
                        continue

                    rid_raw = self._get_any(r, [id_k, "id", "ID", "LogID", "logid", "recordid"])
                    rid_int = self._safe_int(rid_raw, 0)

                    if rid_int > 0 and rid_int <= int(self._last_id):
                        continue

                    card_no = self._safe_str(self._get_any(r, [card_k, "cardno", "CardNo", "CARDNO", "Card", "card"]), "")
                    event_time = self._safe_str(self._get_any(r, [time_k, "time", "Time", "EventTime", "eventtime"]), "")
                    door_id = self._get_any(r, [door_k, "doorid", "DoorID", "Door", "door"])
                    event_type = self._safe_str(self._get_any(r, [type_k, "eventtype", "EventType", "Type", "type"]), "RTLOG")

                    norm = {
                        "eventId": str(rid_int) if rid_int > 0 else "",
                        "doorId": str(self._safe_int(door_id, 0)) if door_id is not None else None,
                        "eventType": str(event_type),
                        "cardNo": str(card_no),
                        "eventTime": str(event_time),
                        "table": table,
                        "rawRow": r,
                    }
                    out.append(norm)

                    if rid_int > max_id:
                        max_id = rid_int

                if max_id > int(self._last_id):
                    self._last_id = max_id

                return out
            except Exception as e:
                last_err = e
                continue

        if last_err:
            raise last_err
        return []

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
        # case-insensitive
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
