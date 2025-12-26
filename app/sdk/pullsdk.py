from __future__ import annotations

import ctypes
from ctypes import c_void_p, c_char_p, c_int, POINTER
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.core.utils import encode_ansi, parse_device_text


class PullSDKError(RuntimeError):
    pass


class PullSDK:
    """
    ctypes wrapper for plcommpro.dll (Pull SDK).
    Matches your PowerShell P/Invoke calls:
    - Connect
    - Disconnect
    - GetDeviceData
    - SetDeviceData
    - PullLastError
    - GetDeviceDataCount
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

            # int GetDeviceData(HANDLE h, char* buffer, int* buffersize, char* table, char* fields, char* filter, char* options);
            self._dll.GetDeviceData.argtypes = [c_void_p, c_void_p, POINTER(c_int), c_char_p, c_char_p, c_char_p, c_char_p]
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

            self.logger.info("PullSDK loaded OK.")
        except OSError as e:
            self._dll = None
            raise PullSDKError(f"Failed to load plcommpro.dll: {e}")

    def connect(self, *, ip: str, port: int, timeout_ms: int, password: str) -> None:
        self.load()
        if self._dll is None:
            raise PullSDKError("PullSDK not loaded")

        conn_str = f"protocol=TCP,ipaddress={ip},port={port},timeout={timeout_ms},passwd={password}"
        self.logger.info(f"PullSDK Connect: protocol=TCP,ipaddress={ip},port={port},timeout={timeout_ms},passwd={'*' * min(8,len(password)) if password else ''}")
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

    def get_device_data_text(self, *, table: str, fields: str = "*", filter_expr: str = "", options: str = "") -> Tuple[int, str]:
        """
        Robust auto-resize GetDeviceData, similar to your PowerShell helper.
        Returns (rc, text).
        """
        h = self._require_handle()
        self.logger.debug(f"GetDeviceData(table={table}, fields={fields}, filter={filter_expr}, options={options})")
        sizes = [1_048_576, 2_097_152, 4_194_304, 8_388_608, 12_582_912, 16_777_216]  # 1MB..16MB

        for sz in sizes:
            buf = ctypes.create_string_buffer(sz)
            blen = c_int(sz)
            rc = int(
                self._dll.GetDeviceData(
                    c_void_p(h),
                    ctypes.cast(buf, c_void_p),
                    ctypes.byref(blen),
                    encode_ansi(table),
                    encode_ansi(fields),
                    encode_ansi(filter_expr),
                    encode_ansi(options),
                )
            )
            if rc >= 0:
                text = buf.value.decode("mbcs", errors="replace")
                self.logger.debug(f"GetDeviceData OK rc={rc} buffer_used={blen.value}")
                return rc, text

            err = self.pull_last_error()
            self.logger.warning(f"GetDeviceData rc={rc} err={err} sz={sz}")
            if rc == -102:
                continue
            raise PullSDKError(f"GetDeviceData FAILED table={table} rc={rc} PullLastError={err}")

        raise PullSDKError("GetDeviceData FAILED: buffer too small after max size.")

    def get_device_data_rows(self, *, table: str, fields: str = "*", filter_expr: str = "", options: str = "") -> List[Dict[str, str]]:
        rc, text = self.get_device_data_text(table=table, fields=fields, filter_expr=filter_expr, options=options)
        if rc == 0 or not text.strip():
            return []
        return parse_device_text(text)

    def get_device_data_count(self, *, table: str, filter_expr: str = "", options: str = "") -> int:
        h = self._require_handle()
        if self._dll is None or not hasattr(self._dll, "GetDeviceDataCount"):
            return -1
        rc = int(self._dll.GetDeviceDataCount(c_void_p(h), encode_ansi(table), encode_ansi(filter_expr), encode_ansi(options)))
        self.logger.debug(f"GetDeviceDataCount(table={table}, filter={filter_expr}) => {rc}")
        return rc

    def set_device_data(self, *, table: str, data: str, options: str = "") -> int:
        h = self._require_handle()
        self.logger.info(f"SetDeviceData(table={table}) data={data}")
        rc = int(self._dll.SetDeviceData(c_void_p(h), encode_ansi(table), encode_ansi(data), encode_ansi(options)))
        if rc < 0:
            err = self.pull_last_error()
            raise PullSDKError(f"SetDeviceData FAILED table={table} rc={rc} PullLastError={err}")
        return rc
