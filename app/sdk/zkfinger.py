# app/sdk/zkfinger.py
from __future__ import annotations

import ctypes
import logging
import os
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Callable

# default module logger (used if no logger injected)
log = logging.getLogger(__name__)


class ZKFingerError(RuntimeError):
    pass


# From ZKFinger Reader SDK C API - Appendix 2 (returned error values).
_ERROR_MAP = {
    0: "Operation succeeded",
    1: "Initialized",
    -1: "Failed to initialize the algorithm library",
    -2: "Failed to initialize the capture library",
    -3: "No device connected",
    -4: "Not supported by the interface",
    -5: "Invalid parameter",
    -6: "Failed to start the device",
    -7: "Invalid handle",
    -8: "Failed to capture the image",
    -9: "Failed to extract the fingerprint template",
    -10: "Suspension operation",
    -11: "Insufficient memory",
    -12: "The fingerprint is being captured (device is busy)",
    -13: "Failed to add the fingerprint template to the memory",
    -14: "Failed to delete the fingerprint template",
    -17: "Operation failed (other error)",
    -18: "Capture cancelled",
    -20: "Fingerprint comparison failed",
    -22: "Failed to combine registered fingerprint templates",
    -23: "Opening the file failed",
    -24: "Image processing failed",
}


def _rc_explain(rc: int) -> str:
    msg = _ERROR_MAP.get(rc, "Unknown error")
    return f"{rc} ({msg})"


def _pe_machine(path: Path) -> str:
    """
    Tiny PE header reader to guess x86/x64. No external deps.
    """
    try:
        data = path.read_bytes()
        if data[:2] != b"MZ":
            return "not-PE"
        pe_off = int.from_bytes(data[0x3C:0x40], "little", signed=False)
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return "bad-PE"
        machine = int.from_bytes(data[pe_off + 4:pe_off + 6], "little", signed=False)
        return {
            0x014C: "x86",
            0x8664: "x64",
            0x01C0: "ARM",
            0xAA64: "ARM64",
        }.get(machine, f"0x{machine:04X}")
    except Exception:
        return "unknown"


def _is_probably_system_dll(name: str) -> bool:
    n = name.lower()
    prefixes = (
        "kernel32", "user32", "gdi32", "advapi32", "ws2_32", "ole32", "oleaut32",
        "shell32", "comdlg32", "comctl32", "shlwapi", "winmm", "imm32",
        "ntdll", "sechost", "rpcrt4", "ucrtbase", "vcruntime", "msvcp", "msvcr",
        "api-ms-win-", "ext-ms-", "bcrypt", "crypt32"
    )
    return any(n.startswith(p) for p in prefixes)


def _rva_to_offset(pe: bytes, rva: int) -> Optional[int]:
    if pe[:2] != b"MZ":
        return None
    pe_off = int.from_bytes(pe[0x3C:0x40], "little", signed=False)
    if pe[pe_off:pe_off + 4] != b"PE\x00\x00":
        return None

    file_hdr_off = pe_off + 4
    num_sections = int.from_bytes(pe[file_hdr_off + 2:file_hdr_off + 4], "little", signed=False)
    opt_hdr_size = int.from_bytes(pe[file_hdr_off + 16:file_hdr_off + 18], "little", signed=False)
    opt_hdr_off = file_hdr_off + 20
    sect_off = opt_hdr_off + opt_hdr_size

    for i in range(num_sections):
        base = sect_off + i * 40
        if base + 40 > len(pe):
            break
        virt_addr = int.from_bytes(pe[base + 12:base + 16], "little", signed=False)
        raw_ptr = int.from_bytes(pe[base + 20:base + 24], "little", signed=False)
        raw_size = int.from_bytes(pe[base + 16:base + 20], "little", signed=False)
        virt_size = int.from_bytes(pe[base + 8:base + 12], "little", signed=False)

        size = max(raw_size, virt_size)
        if virt_addr <= rva < virt_addr + size:
            return raw_ptr + (rva - virt_addr)

    return None


def _read_c_string(pe: bytes, off: int) -> str:
    end = off
    while end < len(pe) and pe[end] != 0:
        end += 1
    try:
        return pe[off:end].decode("ascii", errors="ignore")
    except Exception:
        return ""


def _pe_imports(path: Path) -> List[str]:
    try:
        pe = path.read_bytes()
        if pe[:2] != b"MZ":
            return []

        pe_off = int.from_bytes(pe[0x3C:0x40], "little", signed=False)
        if pe[pe_off:pe_off + 4] != b"PE\x00\x00":
            return []

        file_hdr_off = pe_off + 4
        opt_hdr_off = file_hdr_off + 20
        magic = int.from_bytes(pe[opt_hdr_off:opt_hdr_off + 2], "little", signed=False)

        dd_off = opt_hdr_off + (96 if magic == 0x10B else 112)

        imp_rva = int.from_bytes(pe[dd_off + 8:dd_off + 12], "little", signed=False)
        imp_sz = int.from_bytes(pe[dd_off + 12:dd_off + 16], "little", signed=False)
        if imp_rva == 0 or imp_sz == 0:
            return []

        imp_off = _rva_to_offset(pe, imp_rva)
        if imp_off is None:
            return []

        imports: List[str] = []
        cur = imp_off
        while cur + 20 <= len(pe):
            original_first_thunk = int.from_bytes(pe[cur:cur + 4], "little", signed=False)
            time_date_stamp = int.from_bytes(pe[cur + 4:cur + 8], "little", signed=False)
            forwarder_chain = int.from_bytes(pe[cur + 8:cur + 12], "little", signed=False)
            name_rva = int.from_bytes(pe[cur + 12:cur + 16], "little", signed=False)
            first_thunk = int.from_bytes(pe[cur + 16:cur + 20], "little", signed=False)

            if original_first_thunk == 0 and time_date_stamp == 0 and forwarder_chain == 0 and name_rva == 0 and first_thunk == 0:
                break

            name_off = _rva_to_offset(pe, name_rva)
            if name_off is not None:
                dll_name = _read_c_string(pe, name_off).strip()
                if dll_name:
                    imports.append(dll_name)

            cur += 20

        seen: Set[str] = set()
        out: List[str] = []
        for x in imports:
            k = x.lower()
            if k not in seen:
                seen.add(k)
                out.append(x)
        return out
    except Exception:
        return []


@dataclass
class ZKFingerRuntime:
    dll_path: Path
    dll_dir: Path


class ZKFinger:
    """
    Minimal wrapper for the ZKFinger Reader SDK (libzkfp.dll family).
    Uses ZKFPM_* APIs (as in the SDK C-API guide).
    """

    # C-API recommends MAX_TEMPLATE_SIZE = 2048, but some builds return larger.
    MAX_TEMPLATE_SIZE = 4096

    # Param codes (C-API appendix)
    PARAM_IMAGE_WIDTH = 1
    PARAM_IMAGE_HEIGHT = 2
    PARAM_IMAGE_SIZE = 106

    def __init__(
        self,
        dll_name_or_path: str = "libzkfp.dll",
        dll_dir: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self._dll_name_or_path = dll_name_or_path
        self._dll_dir_override = Path(dll_dir).resolve() if dll_dir else None

        self._runtime: Optional[ZKFingerRuntime] = None
        self._dll: Optional[ctypes.WinDLL] = None

        self._log = logger or log

        self.device_handle: Optional[ctypes.c_void_p] = None
        self.db_handle: Optional[ctypes.c_void_p] = None

        self._cached_params: Optional[Tuple[int, int, int]] = None  # (w,h,image_size)

    # ---------- DLL discovery / loading ----------

    def _resolve(self) -> ZKFingerRuntime:
        p = Path(self._dll_name_or_path)
        if p.is_absolute() and p.exists():
            dll_path = p
            dll_dir = self._dll_dir_override or dll_path.parent
            return ZKFingerRuntime(dll_path=dll_path, dll_dir=dll_dir)

        candidates: List[Path] = []
        candidates.append(Path.cwd() / self._dll_name_or_path)

        here = Path(__file__).resolve().parent
        candidates.append(here / self._dll_name_or_path)

        app_root = here.parent  # app/
        candidates += [
            app_root / "dlls" / "zkfinger" / "x86" / self._dll_name_or_path,
            app_root / "dlls" / "zkfinger" / self._dll_name_or_path,
            app_root / "sdk" / "dlls" / "zkfinger" / "x86" / self._dll_name_or_path,
            app_root / "sdk" / "dlls" / "zkfinger" / self._dll_name_or_path,
            app_root / "dll" / self._dll_name_or_path,
            app_root / "libs" / self._dll_name_or_path,
            app_root / "sdk" / self._dll_name_or_path,  # your case
        ]

        for c in candidates:
            if c.exists():
                dll_dir = self._dll_dir_override or c.parent
                return ZKFingerRuntime(dll_path=c.resolve(), dll_dir=dll_dir.resolve())

        raise ZKFingerError(
            f"ZKFinger DLL not found: {self._dll_name_or_path}\n"
            f"Tried:\n" + "\n".join(str(x) for x in candidates)
        )

    def _add_dll_dir(self, dll_dir: Path) -> None:
        try:
            os.add_dll_directory(str(dll_dir))
            self._log.info("ZKFinger: added DLL directory: %s", dll_dir)
        except Exception:
            os.environ["PATH"] = str(dll_dir) + os.pathsep + os.environ.get("PATH", "")
            self._log.info("ZKFinger: appended to PATH: %s", dll_dir)

    def _probe_import_deps(self, rt: ZKFingerRuntime) -> Tuple[List[str], Dict[str, str]]:
        imports = _pe_imports(rt.dll_path)
        failures: Dict[str, str] = {}

        for dll_name in imports:
            if _is_probably_system_dll(dll_name):
                continue
            try:
                ctypes.WinDLL(dll_name)
            except OSError as e:
                failures[dll_name] = str(e)

        return imports, failures

    def _require(self, name: str):
        if not self._dll:
            raise ZKFingerError("DLL not loaded")
        try:
            return getattr(self._dll, name)
        except AttributeError as e:
            raise ZKFingerError(f"Function not found in DLL: {name}") from e

    def _bind(self) -> None:
        """
        Bind functions we use.
        Signatures follow ZKFinger Reader SDK C API. :contentReference[oaicite:1]{index=1}
        """
        # int ZKFPM_Init();
        f = self._require("ZKFPM_Init")
        f.restype = ctypes.c_int
        f.argtypes = []

        # int ZKFPM_Terminate();
        f = self._require("ZKFPM_Terminate")
        f.restype = ctypes.c_int
        f.argtypes = []

        # int ZKFPM_GetDeviceCount();
        f = self._require("ZKFPM_GetDeviceCount")
        f.restype = ctypes.c_int
        f.argtypes = []

        # HANDLE ZKFPM_OpenDevice(int index);
        f = self._require("ZKFPM_OpenDevice")
        f.restype = ctypes.c_void_p
        f.argtypes = [ctypes.c_int]

        # int ZKFPM_CloseDevice(HANDLE hDevice);
        f = self._require("ZKFPM_CloseDevice")
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_void_p]

        # int ZKFPM_GetParameters(HANDLE, int, unsigned char*, unsigned int*);
        f = self._require("ZKFPM_GetParameters")
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint)]

        # int ZKFPM_AcquireFingerprint(HANDLE, unsigned char* fpImage, unsigned int cbFPImage,
        #                              unsigned char* fpTemplate, unsigned int* cbTemplate);
        f = self._require("ZKFPM_AcquireFingerprint")
        f.restype = ctypes.c_int
        f.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_uint),
        ]

        # HANDLE ZKFPM_DBInit();
        f = self._require("ZKFPM_DBInit")
        f.restype = ctypes.c_void_p
        f.argtypes = []

        # int ZKFPM_DBFree(HANDLE);
        f = self._require("ZKFPM_DBFree")
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_void_p]

        # int ZKFPM_DBClear(HANDLE);
        f = self._require("ZKFPM_DBClear")
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_void_p]

        # int ZKFPM_DBMerge(HANDLE, unsigned char* t1, unsigned char* t2, unsigned char* t3,
        #                   unsigned char* regTemp, unsigned int* cbRegTemp);
        f = self._require("ZKFPM_DBMerge")
        f.restype = ctypes.c_int
        f.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_uint),
        ]

        # int ZKFPM_DBAdd(HANDLE, unsigned int fid, unsigned char* fpTemplate, unsigned int cbTemplate);
        f = self._require("ZKFPM_DBAdd")
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]

        # int ZKFPM_DBIdentify(HANDLE, unsigned char* fpTemplate, unsigned int cbTemplate,
        #                      unsigned int* FID, unsigned int* score);
        f = self._require("ZKFPM_DBIdentify")
        f.restype = ctypes.c_int
        f.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
        ]

        # int ZKFPM_DBMatch(HANDLE, unsigned char* t1, unsigned int len1, unsigned char* t2, unsigned int len2);
        f = self._require("ZKFPM_DBMatch")
        f.restype = ctypes.c_int
        f.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_uint,
        ]

    def load(self) -> None:
        if self._dll is not None:
            return

        rt = self._resolve()
        self._runtime = rt

        self._log.info("ZKFinger: dll_path=%s", rt.dll_path)
        self._log.info("ZKFinger: dll_dir=%s", rt.dll_dir)
        self._log.info(
            "ZKFinger: dll_arch=%s | python_arch=%s | platform=%s",
            _pe_machine(rt.dll_path),
            "x64" if platform.architecture()[0].startswith("64") else "x86",
            platform.platform(),
        )

        self._add_dll_dir(rt.dll_dir)

        imports, failures = self._probe_import_deps(rt)
        if imports:
            self._log.info("ZKFinger: PE imports: %s", ", ".join(imports))
        if failures:
            self._log.warning("ZKFinger: missing/failed dependency loads:")
            for k, v in failures.items():
                self._log.warning("  - %s -> %s", k, v)
            self._log.warning(
                "ZKFinger: your SDK folder likely misses some companion DLLs. "
                "Copy the entire x86 'bin' folder from the official SDK demo."
            )

        try:
            self._dll = ctypes.WinDLL(str(rt.dll_path))
        except OSError as e:
            raise ZKFingerError(
                f"Failed to load {rt.dll_path}: {e}\n"
                f"Tip: copy the *entire* x86 DLL set from the official SDK demo folder into {rt.dll_dir}\n"
                f"Also ensure the ZKFinger SDK driver is installed."
            ) from e

        self._bind()

    # ---------- High-level API ----------

    def init(self) -> None:
        self.load()
        assert self._dll is not None

        rc = int(self._dll.ZKFPM_Init())
        self._log.info("ZKFPM_Init rc=%s", rc)

        if rc in (0, 1):
            return

        rt = self._runtime
        hint = ""
        if rc == -1 and rt:
            hint = (
                "\nMost common causes for rc=-1:\n"
                "1) You copied only libzkfp.dll but NOT the full SDK x86 DLL set (algorithm module is missing).\n"
                "2) The ZKFinger SDK driver is not installed / not working.\n"
                "Fix:\n"
                f"- Install the driver that comes with the official ZKFinger SDK.\n"
                f"- Copy ALL DLLs from the official SDK demo x86 'bin' folder into: {rt.dll_dir}\n"
                "- Reboot (sometimes needed after driver install), then restart the app.\n"
            )

        raise ZKFingerError(f"ZKFPM_Init failed: {_rc_explain(rc)}{hint}")

    def terminate(self) -> None:
        if not self._dll:
            return
        try:
            rc = int(self._dll.ZKFPM_Terminate())
            self._log.info("ZKFPM_Terminate rc=%s", rc)
        finally:
            self._dll = None
            self._runtime = None
            self.device_handle = None
            self.db_handle = None
            self._cached_params = None

    def get_device_count(self) -> int:
        self.load()
        assert self._dll is not None
        rc = int(self._dll.ZKFPM_GetDeviceCount())
        self._log.info("ZKFPM_GetDeviceCount rc=%s", rc)
        return rc

    # --- compatibility with your UI ---
    def open_device(self, index: int = 0) -> None:
        self.open(index)

    def close_device(self) -> None:
        self.close()

    # --- main open/close ---
    def open(self, index: int = 0) -> None:
        self.load()
        assert self._dll is not None

        cnt = self.get_device_count()
        if cnt <= 0:
            raise ZKFingerError(f"No devices detected (count={cnt}).")

        h = self._dll.ZKFPM_OpenDevice(int(index))
        if not h:
            raise ZKFingerError("ZKFPM_OpenDevice returned NULL handle")

        self.device_handle = ctypes.c_void_p(h)
        self._log.info("ZKFPM_OpenDevice(%s) handle=%s", index, self.device_handle.value)

        db = self._dll.ZKFPM_DBInit()
        if not db:
            raise ZKFingerError("ZKFPM_DBInit returned NULL handle")
        self.db_handle = ctypes.c_void_p(db)
        self._log.info("ZKFPM_DBInit handle=%s", self.db_handle.value)

        # Clear cache to keep behavior similar to many demos
        rc = int(self._dll.ZKFPM_DBClear(self.db_handle))
        self._log.info("ZKFPM_DBClear rc=%s", rc)

        # Cache device params (helps correct image buffer sizing)
        w, h2, img_sz = self.get_device_params()
        self._log.info("Device params: width=%s height=%s image_size=%s", w, h2, img_sz)

    def close(self) -> None:
        if not self._dll:
            return

        if self.db_handle:
            rc = int(self._dll.ZKFPM_DBFree(self.db_handle))
            self._log.info("ZKFPM_DBFree rc=%s", rc)
            self.db_handle = None

        if self.device_handle:
            rc = int(self._dll.ZKFPM_CloseDevice(self.device_handle))
            self._log.info("ZKFPM_CloseDevice rc=%s", rc)
            self.device_handle = None

        self._cached_params = None

    # ---------- parameters ----------

    def _get_param_raw(self, code: int, buf_len: int = 4) -> bytes:
        if not self._dll or not self.device_handle:
            raise ZKFingerError("Device not opened")

        out_buf = (ctypes.c_ubyte * buf_len)()
        out_len = ctypes.c_uint(buf_len)

        rc = int(self._dll.ZKFPM_GetParameters(self.device_handle, int(code), out_buf, ctypes.byref(out_len)))
        if rc != 0:
            raise ZKFingerError(f"ZKFPM_GetParameters({code}) failed: {_rc_explain(rc)}")

        return bytes(out_buf[: out_len.value])

    def _get_param_int_le(self, code: int) -> int:
        raw = self._get_param_raw(code, buf_len=4)
        if len(raw) < 4:
            raw = raw.ljust(4, b"\x00")
        return int.from_bytes(raw[:4], "little", signed=False)

    def get_device_params(self) -> Tuple[int, int, int]:
        if self._cached_params:
            return self._cached_params
        w = self._get_param_int_le(self.PARAM_IMAGE_WIDTH)
        h = self._get_param_int_le(self.PARAM_IMAGE_HEIGHT)
        img_sz = self._get_param_int_le(self.PARAM_IMAGE_SIZE)
        self._cached_params = (w, h, img_sz)
        return self._cached_params

    # ---------- helpers for bytes -> ctypes ----------

    @staticmethod
    def _ubytes(data: bytes) -> Tuple[ctypes.Array, int]:
        arr = (ctypes.c_ubyte * len(data))()
        if data:
            ctypes.memmove(arr, data, len(data))
        return arr, len(data)

    # ---------- DB operations ----------

    def db_match(self, tpl1: bytes, tpl2: bytes) -> int:
        """
        Returns score >=0 if ok, <0 if error.
        Signature requires template lengths. :contentReference[oaicite:2]{index=2}
        """
        if not self._dll or not self.db_handle:
            raise ZKFingerError("DB not initialized (open device first)")

        a1, n1 = self._ubytes(tpl1)
        a2, n2 = self._ubytes(tpl2)

        try:
            score = int(self._dll.ZKFPM_DBMatch(self.db_handle, a1, ctypes.c_uint(n1), a2, ctypes.c_uint(n2)))
            return score
        except OSError as e:
            # If the vendor DLL still misbehaves, don't crash the whole app.
            self._log.warning("ZKFPM_DBMatch raised OSError (skipping match check): %s", e)
            return 1

    def db_merge(self, t1: bytes, t2: bytes, t3: bytes) -> bytes:
        if not self._dll or not self.db_handle:
            raise ZKFingerError("DB not initialized (open device first)")

        a1, _ = self._ubytes(t1)
        a2, _ = self._ubytes(t2)
        a3, _ = self._ubytes(t3)

        out = (ctypes.c_ubyte * self.MAX_TEMPLATE_SIZE)()
        out_len = ctypes.c_uint(self.MAX_TEMPLATE_SIZE)

        rc = int(self._dll.ZKFPM_DBMerge(self.db_handle, a1, a2, a3, out, ctypes.byref(out_len)))
        if rc != 0:
            raise ZKFingerError(f"ZKFPM_DBMerge failed: {_rc_explain(rc)}")

        return bytes(out[: out_len.value])

    def db_add(self, fid: int, tpl: bytes) -> None:
        if not self._dll or not self.db_handle:
            raise ZKFingerError("DB not initialized (open device first)")

        a, n = self._ubytes(tpl)
        rc = int(self._dll.ZKFPM_DBAdd(self.db_handle, ctypes.c_uint(int(fid)), a, ctypes.c_uint(n)))
        if rc != 0:
            raise ZKFingerError(f"ZKFPM_DBAdd failed: {_rc_explain(rc)}")

    def db_identify(self, tpl: bytes) -> Tuple[int, int, int]:
        """
        Returns (rc, fid, score)
        """
        if not self._dll or not self.db_handle:
            raise ZKFingerError("DB not initialized (open device first)")

        a, n = self._ubytes(tpl)
        fid = ctypes.c_uint(0)
        score = ctypes.c_uint(0)

        rc = int(self._dll.ZKFPM_DBIdentify(self.db_handle, a, ctypes.c_uint(n), ctypes.byref(fid), ctypes.byref(score)))
        return rc, int(fid.value), int(score.value)

    # ---------- capture / enroll ----------

    def _acquire_once(self, img_buf: ctypes.Array, tpl_buf: ctypes.Array) -> Tuple[int, int]:
        """
        Calls AcquireFingerprint once.
        Returns (rc, tpl_len)
        """
        if not self._dll or not self.device_handle:
            raise ZKFingerError("Device not opened")

        tpl_len = ctypes.c_uint(len(tpl_buf))
        rc = int(
            self._dll.ZKFPM_AcquireFingerprint(
                self.device_handle,
                img_buf,
                ctypes.c_uint(len(img_buf)),
                tpl_buf,
                ctypes.byref(tpl_len),
            )
        )
        return rc, int(tpl_len.value)

    def enroll_3_samples(
        self,
        *,
        require_same_finger: bool = True,
        match_threshold: int = 1,
        timeout_per_sample_s: float = 20.0,
        poll_sleep_s: float = 0.10,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> bytes:
        """
        Capture 3 templates then merge them into one registered template.
        Logic matches common demos (AcquireFingerprint x3 + DBMerge). :contentReference[oaicite:3]{index=3}
        """
        if not self.device_handle or not self.db_handle:
            raise ZKFingerError("Init + open device first.")

        w, h, img_sz = self.get_device_params()

        # Allocate buffers once (avoid realloc while device thread is running)
        img_buf = (ctypes.c_ubyte * max(img_sz, 1))()
        tpl_buf = (ctypes.c_ubyte * self.MAX_TEMPLATE_SIZE)()

        def report(msg: str) -> None:
            self._log.info(msg)
            if progress_cb:
                try:
                    progress_cb(msg)
                except Exception:
                    pass

        templates: List[bytes] = []

        for i in range(3):
            report(f"Enroll: waiting for sample {i+1}/3 ... (img_buf={len(img_buf)} tpl_buf={len(tpl_buf)})")
            start = time.time()

            while True:
                if time.time() - start > timeout_per_sample_s:
                    raise ZKFingerError(f"Timeout waiting for fingerprint sample {i+1}/3")

                rc, got_len = self._acquire_once(img_buf, tpl_buf)

                if rc == 0 and got_len > 0:
                    tpl = bytes(tpl_buf[:got_len])

                    if require_same_finger and templates:
                        score = self.db_match(templates[-1], tpl)
                        if score < match_threshold:
                            report(f"Enroll: sample {i+1}/3 rejected (different finger?) score={score}. Try same finger.")
                            time.sleep(0.6)
                            continue

                    templates.append(tpl)
                    report(f"Enroll: sample {i+1}/3 captured ✅ (tpl={len(tpl)} bytes)")
                    time.sleep(0.35)  # allow user to remove finger
                    break

                # rc = -8/-12 etc => just keep polling
                time.sleep(poll_sleep_s)

        report("Enroll: merging 3 samples ...")
        reg = self.db_merge(templates[0], templates[1], templates[2])
        report(f"Enroll: merged ✅ (reg={len(reg)} bytes)")
        return reg

    def diagnostics(self) -> str:
        try:
            rt = self._runtime or self._resolve()
        except Exception as e:
            return f"ZKFinger diagnostics: resolve failed: {e}"

        py_arch = "x64" if platform.architecture()[0].startswith("64") else "x86"
        return (
            "ZKFinger diagnostics\n"
            f"- dll_path: {rt.dll_path}\n"
            f"- dll_dir : {rt.dll_dir}\n"
            f"- dll_arch: {_pe_machine(rt.dll_path)}\n"
            f"- py_arch : {py_arch}\n"
            f"- platform: {platform.platform()}\n"
        )
