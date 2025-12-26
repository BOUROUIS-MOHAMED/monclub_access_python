import platform
import struct


def is_64bit_python() -> bool:
    return struct.calcsize("P") * 8 == 64


def platform_summary() -> str:
    return f"{platform.system()} {platform.release()} | Python {platform.python_version()} ({'64' if is_64bit_python() else '32'}-bit)"


def require_32bit_python_for_32bit_dll(dll_path: str) -> None:
    """
    We cannot reliably detect DLL bitness without external tools.
    So we enforce: if user config says PullSDK DLL is 32-bit, they must run 32-bit Python.
    In this project we assume plcommpro.dll is 32-bit (as user said).
    """
    if is_64bit_python():
        raise RuntimeError(
            "You are running 64-bit Python, but plcommpro.dll is 32-bit. "
            "Install/run 32-bit Python (Win32), or build a separate 32-bit bridge process."
        )
