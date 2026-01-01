from __future__ import annotations

import ctypes
from ctypes import c_void_p, c_char_p, c_int
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.core.utils import encode_ansi, parse_device_text


class PullSDKError(RuntimeError):
    pass


class PullSDK:
    """
    ctypes wrapper for plcommpro.dll (Pull SDK).

    Key notes:
    - PullSDK GetDeviceData 'FieldNames' must be separated by SEMICOLONS ';' (not commas).
    - Filter must be like: Pin=123 (no spaces around '=') and multiple conditions separated by commas.
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
            # NOTE: buffersize is int (value), not int* in some PullSDK guides.
            self._dll.GetDeviceData.argtypes = [c_void_p, c_void_p, c_int, c_char_p, c_char_p, c_char_p, c_char_p]
            self._dll.GetDeviceData.restype = c_int

            # int SetDeviceData(HANDLE h, char* table, char* data, char* options);
            self._dll.SetDeviceData.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
            self._dll.SetDeviceData.restype = c_int

            self._dll.PullLastError.argtypes = []
            self._dll.PullLastError.restype = c_int

            # int GetDeviceDataCount(HANDLE h, char* table, char* filter, char* options);
            if hasattr(self._dll, "GetDeviceDataCount"):
                self._dll.GetDeviceDataCount.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
                self._dll.GetDeviceDataCount.restype = c_int

            # int GetDeviceParam(HANDLE h, char* buffer, int buffersize, char* itemname);
            # This is commonly present in plcommpro.dll builds.
            if hasattr(self._dll, "GetDeviceParam"):
                self._dll.GetDeviceParam.argtypes = [c_void_p, c_void_p, c_int, c_char_p]
                self._dll.GetDeviceParam.restype = c_int

            self.logger.info("PullSDK loaded OK.")
        except OSError as e:
            self._dll = None
            raise PullSDKError(f"Failed to load plcommpro.dll: {e}")

    def connect(self, *, ip: str, port: int, timeout_ms: int, password: str) -> None:
        self.load()
        if self._dll is None:
            raise PullSDKError("PullSDK not loaded")

        conn_str = f"protocol=TCP,ipaddress={ip},port={port},timeout={timeout_ms},passwd={password}"
        self.logger.info(
            f"PullSDK Connect: protocol=TCP,ipaddress={ip},port={port},timeout={timeout_ms},passwd={'*' * min(8, len(password)) if password else ''}"
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
        """
        PullSDK expects semicolon-separated fields: Pin;CardNo;Password
        We'll accept commas from UI and convert to semicolons.
        """
        f = (fields or "").strip()
        if not f:
            return "*"
        if f == "*":
            return "*"

        # accept user typing commas or semicolons
        tmp = f.replace(";", ",")
        parts = [p.strip() for p in tmp.split(",") if p.strip()]
        return ";".join(parts) if parts else "*"

    @staticmethod
    def _normalize_filter(filter_expr: str) -> str:
        """
        PullSDK filter example: Pin=123 (no spaces around '=')
        We'll remove common accidental spaces around '=' and after commas.
        """
        s = (filter_expr or "").strip()
        if not s:
            return ""
        s = s.replace(" = ", "=").replace("= ", "=").replace(" =", "=")
        s = s.replace(", ", ",")
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
        """
        Robust auto-resize GetDeviceData.
        Returns (rc, text).
        """
        h = self._require_handle()
        if self._dll is None:
            raise PullSDKError("PullSDK not loaded")

        fields_n = self._normalize_fields(fields)
        filter_n = self._normalize_filter(filter_expr)

        self.logger.debug(f"GetDeviceData(table={table}, fields={fields_n}, filter={filter_n}, options={options})")

        # Start larger for template tables (they can be heavy)
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

            # Typical "buffer too small" codes
            if rc in (-102, -114):
                continue

            raise PullSDKError(f"GetDeviceData FAILED table={table} rc={rc} PullLastError={err}")

        raise PullSDKError(f"GetDeviceData FAILED after max size. table={table} last_rc={last_rc} PullLastError={last_err}")

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

    # -------------------- GetDeviceParam (NEW) --------------------

    def supports_get_device_param(self) -> bool:
        self.load()
        return self._dll is not None and hasattr(self._dll, "GetDeviceParam")

    def get_device_param(self, *, items: str, initial_size: int | None = None) -> str:
        """
        Calls plcommpro.dll GetDeviceParam.

        items: comma-separated names, ex:
          "SerialNumber,DeviceName,FirmwareVersion"
        Returns raw string, often:
          "SerialNumber=...,DeviceName=...,FirmwareVersion=..."
        """
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
