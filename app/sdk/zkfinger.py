# app/sdk/zkfinger.py
from __future__ import annotations

import ctypes
import logging
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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
    # common Windows/system runtime dlls
    prefixes = (
        "kernel32", "user32", "gdi32", "advapi32", "ws2_32", "ole32", "oleaut32",
        "shell32", "comdlg32", "comctl32", "shlwapi", "winmm", "imm32",
        "ntdll", "sechost", "rpcrt4", "ucrtbase", "vcruntime", "msvcp", "msvcr",
        "api-ms-win-", "ext-ms-", "bcrypt", "crypt32"
    )
    return any(n.startswith(p) for p in prefixes)


def _rva_to_offset(pe: bytes, rva: int) -> Optional[int]:
    """
    Map an RVA to a file offset using section headers.
    Minimal PE parsing (no external libs).
    """
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

    # Iterate sections
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
    """
    List imported DLL names from PE import directory.
    This helps detect which extra DLLs must be present.
    """
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

        # DataDirectory begins at:
        # PE32  (0x10B): opt_hdr_off + 96
        # PE32+ (0x20B): opt_hdr_off + 112
        dd_off = opt_hdr_off + (96 if magic == 0x10B else 112)

        # Import directory is DataDirectory[1]
        imp_rva = int.from_bytes(pe[dd_off + 8:dd_off + 12], "little", signed=False)
        imp_sz = int.from_bytes(pe[dd_off + 12:dd_off + 16], "little", signed=False)
        if imp_rva == 0 or imp_sz == 0:
            return []

        imp_off = _rva_to_offset(pe, imp_rva)
        if imp_off is None:
            return []

        imports: List[str] = []
        # IMAGE_IMPORT_DESCRIPTOR = 20 bytes
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

        # unique, keep order
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

    def __init__(
        self,
        dll_name_or_path: str = "libzkfp.dll",
        dll_dir: Optional[str] = None,
        logger: Optional[logging.Logger] = None,  # <-- compatibility with your UI call
    ):
        self._dll_name_or_path = dll_name_or_path
        self._dll_dir_override = Path(dll_dir).resolve() if dll_dir else None

        self._runtime: Optional[ZKFingerRuntime] = None
        self._dll: Optional[ctypes.WinDLL] = None

        self._log = logger or log

        # Common handles (optional use)
        self.device_handle: Optional[int] = None
        self.db_handle: Optional[int] = None

    # ---------- DLL discovery / loading ----------

    def _resolve(self) -> ZKFingerRuntime:
        # If user provided an absolute path, trust it.
        p = Path(self._dll_name_or_path)
        if p.is_absolute() and p.exists():
            dll_path = p
            dll_dir = self._dll_dir_override or dll_path.parent
            return ZKFingerRuntime(dll_path=dll_path, dll_dir=dll_dir)

        # Otherwise search typical project locations
        candidates: List[Path] = []

        # current working directory
        candidates.append(Path.cwd() / self._dll_name_or_path)

        # alongside this file
        here = Path(__file__).resolve().parent
        candidates.append(here / self._dll_name_or_path)

        # common project folders
        app_root = here.parent  # app/
        candidates += [
            app_root / "dlls" / "zkfinger" / "x86" / self._dll_name_or_path,
            app_root / "dlls" / "zkfinger" / self._dll_name_or_path,
            app_root / "sdk" / "dlls" / "zkfinger" / "x86" / self._dll_name_or_path,
            app_root / "sdk" / "dlls" / "zkfinger" / self._dll_name_or_path,
            app_root / "dll" / self._dll_name_or_path,
            app_root / "libs" / self._dll_name_or_path,
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
        # Python 3.8+ supports add_dll_directory on Windows.
        try:
            os.add_dll_directory(str(dll_dir))
            self._log.info("ZKFinger: added DLL directory: %s", dll_dir)
        except Exception:
            # fallback: PATH (less reliable but better than nothing)
            os.environ["PATH"] = str(dll_dir) + os.pathsep + os.environ.get("PATH", "")
            self._log.info("ZKFinger: appended to PATH: %s", dll_dir)

    def _probe_import_deps(self, rt: ZKFingerRuntime) -> Tuple[List[str], Dict[str, str]]:
        """
        Reads the import table of libzkfp.dll, then tries to load non-system imports.
        Returns (imports, failures{dll_name: error}).
        """
        imports = _pe_imports(rt.dll_path)
        failures: Dict[str, str] = {}

        for dll_name in imports:
            if _is_probably_system_dll(dll_name):
                continue
            # Try load by name; add_dll_directory/ PATH should point to rt.dll_dir
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
        Bind only the functions we need now.
        Extend this later for enroll/capture flow.
        """
        # int APICALL ZKFPM_Init();
        f = self._require("ZKFPM_Init")
        f.restype = ctypes.c_int
        f.argtypes = []

        # int APICALL ZKFPM_Terminate();
        f = self._require("ZKFPM_Terminate")
        f.restype = ctypes.c_int
        f.argtypes = []

        # int APICALL ZKFPM_GetDeviceCount();
        f = self._require("ZKFPM_GetDeviceCount")
        f.restype = ctypes.c_int
        f.argtypes = []

        # HANDLE APICALL ZKFPM_OpenDevice(int index);
        f = self._require("ZKFPM_OpenDevice")
        f.restype = ctypes.c_void_p
        f.argtypes = [ctypes.c_int]

        # int APICALL ZKFPM_CloseDevice(HANDLE hDevice);
        f = self._require("ZKFPM_CloseDevice")
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_void_p]

        # HANDLE APICALL ZKFPM_DBInit();
        f = self._require("ZKFPM_DBInit")
        f.restype = ctypes.c_void_p
        f.argtypes = []

        # int APICALL ZKFPM_DBFree(HANDLE hDBCache);
        f = self._require("ZKFPM_DBFree")
        f.restype = ctypes.c_int
        f.argtypes = [ctypes.c_void_p]

    def load(self) -> None:
        if self._dll is not None:
            return

        rt = self._resolve()
        self._runtime = rt

        # Log diagnostics
        self._log.info("ZKFinger: dll_path=%s", rt.dll_path)
        self._log.info("ZKFinger: dll_dir=%s", rt.dll_dir)
        self._log.info(
            "ZKFinger: dll_arch=%s | python_arch=%s | platform=%s",
            _pe_machine(rt.dll_path),
            "x64" if platform.architecture()[0].startswith("64") else "x86",
            platform.platform(),
        )

        # IMPORTANT: add the directory containing *all* SDK DLLs
        self._add_dll_dir(rt.dll_dir)

        # Probe imports to help detect missing companion DLLs
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

        # Load using full path to avoid CWD confusion
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
        """
        Initialize SDK resources.
        rc=0 success, rc=1 already initialized (treat as OK).
        """
        self.load()
        assert self._dll is not None

        rc = self._dll.ZKFPM_Init()
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
        rc = self._dll.ZKFPM_Terminate()
        self._log.info("ZKFPM_Terminate rc=%s", rc)
        self._dll = None
        self._runtime = None

    def get_device_count(self) -> int:
        self.load()
        assert self._dll is not None
        rc = self._dll.ZKFPM_GetDeviceCount()
        self._log.info("ZKFPM_GetDeviceCount rc=%s", rc)
        return int(rc)

    def open_first_device(self) -> None:
        self.load()
        assert self._dll is not None

        cnt = self.get_device_count()
        if cnt <= 0:
            raise ZKFingerError(f"No devices detected (count={cnt}).")

        h = self._dll.ZKFPM_OpenDevice(0)
        if not h:
            raise ZKFingerError("ZKFPM_OpenDevice returned NULL handle")
        self.device_handle = int(ctypes.cast(h, ctypes.c_void_p).value)
        self._log.info("ZKFPM_OpenDevice handle=%s", self.device_handle)

        db = self._dll.ZKFPM_DBInit()
        if not db:
            raise ZKFingerError("ZKFPM_DBInit returned NULL handle")
        self.db_handle = int(ctypes.cast(db, ctypes.c_void_p).value)
        self._log.info("ZKFPM_DBInit handle=%s", self.db_handle)

    def close(self) -> None:
        if not self._dll:
            return

        if self.db_handle:
            rc = self._dll.ZKFPM_DBFree(ctypes.c_void_p(self.db_handle))
            self._log.info("ZKFPM_DBFree rc=%s", rc)
            self.db_handle = None

        if self.device_handle:
            rc = self._dll.ZKFPM_CloseDevice(ctypes.c_void_p(self.device_handle))
            self._log.info("ZKFPM_CloseDevice rc=%s", rc)
            self.device_handle = None

    def diagnostics(self) -> str:
        """
        Returns a human-readable diagnostic block to paste into logs/issues.
        """
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
