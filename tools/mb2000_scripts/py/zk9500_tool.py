#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
zk9500_tool.py - ZK9500 desk-reader DIAGNOSE + ENROLL, in Python.

Why Python (and not only the .ps1 pack): this mirrors MonClub Access's own
fingerprint code path (app/sdk/zkfinger.py - same ctypes signatures), so whatever
we prove here ports 1:1 into the product. It is self-contained: it loads the x86
ZKFinger runtime bundled in the pack's ..\sdk\ folder, so it does NOT depend on
whatever ZKFinger SDK may or may not be installed on the PC.

It is deliberately step-by-step: every call prints its result and the SDK's own
meaning, so a failure on the gym PC tells us EXACTLY which step fails (load /
algorithm-init / capture-init / no-device / open) instead of a bare "-1".

USAGE (run under 32-bit Python 3 - the DLLs are x86):
    python zk9500_tool.py                      # diagnose (no finger needed)
    python zk9500_tool.py --enroll --pin 117 --name Bob --card 8192567 --finger 6
    python zk9500_tool.py --dll-dir "C:\\Windows\\SysWOW64"   # test another runtime

SDK return codes (from the ZKFinger Reader SDK C API, see app/sdk/zkfinger.py):
    0/1 = OK   -1 = algorithm library init failed   -2 = capture library init failed
    -3 = no device connected   -4 = not supported   -5 = bad param   -6 = start failed
"""
import argparse
import base64
import ctypes
import datetime
import json
import os
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK_ROOT = os.path.dirname(HERE)                     # tools\mb2000_scripts
DEFAULT_SDK = os.path.join(PACK_ROOT, "sdk")          # bundled matched runtime
STORE_DIR = os.path.join(PACK_ROOT, "templates")

RC_MEANING = {
    0: "OK", 1: "OK (already initialized)",
    -1: "algorithm library init failed",
    -2: "capture library init failed",
    -3: "no device connected",
    -4: "not supported by the interface",
    -5: "invalid parameter",
    -6: "failed to start the device",
}
# The runtime chain, in load order. Companions must be pinned BEFORE libzkfp so the
# bundled copies win by base-name over any system-installed copy (no version mixing).
CHAIN = ["ZKFPCap.dll", "fpslib.dll", "zkfpslibLow.dll", "fppswsk12.dll", "libzkfp.dll"]

# ZKFPM_GetParameters codes (image geometry) - from app/sdk/zkfinger.py
PARAM_IMAGE_WIDTH, PARAM_IMAGE_HEIGHT, PARAM_IMAGE_SIZE = 1, 2, 106


def c(txt, color):
    codes = {"g": 32, "r": 31, "y": 33, "c": 36, "d": 90}
    return "\033[%dm%s\033[0m" % (codes.get(color, 0), txt)


def ok(m):    print(c("[OK]   ", "g") + m)
def err(m):   print(c("[FAIL] ", "r") + m)
def warn(m):  print(c("[!]    ", "y") + m)
def info(m):  print(c("[i]    ", "d") + m)
def title(m):
    print()
    print(c("=" * 68, "c"))
    print(c("  " + m, "c"))
    print(c("=" * 68, "c"))


def module_path(name):
    """Full path a currently-loaded DLL was resolved from (proves which copy won)."""
    k = ctypes.windll.kernel32
    h = k.GetModuleHandleW(name)
    if not h:
        return None
    buf = ctypes.create_unicode_buffer(1024)
    k.GetModuleFileNameW(ctypes.c_void_p(h), buf, 1024)
    return buf.value or None


def enumerate_zk_readers():
    """Best-effort: does Windows see a ZK/biometric fingerprint reader on THIS PC?"""
    ps = (
        "Get-PnpDevice -PresentOnly | "
        "Where-Object { $_.Class -eq 'Biometric' -or $_.FriendlyName -match 'finger|ZK|SLK' } | "
        "ForEach-Object { $_.Status + '  ' + $_.FriendlyName }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=25,
        ).stdout.strip()
        return [ln.strip() for ln in out.splitlines() if ln.strip()]
    except Exception as e:
        return ["(device enumeration failed: %s)" % e]


class Zk9500:
    def __init__(self, dll_dir):
        self.dll_dir = os.path.abspath(dll_dir)
        self.dll = None

    def load(self):
        if not os.path.isdir(self.dll_dir):
            raise RuntimeError("sdk dir not found: %s" % self.dll_dir)
        # pin the search dir + preload the whole chain by FULL PATH from here
        try:
            os.add_dll_directory(self.dll_dir)   # py3.8+
        except Exception:
            pass
        os.environ["PATH"] = self.dll_dir + os.pathsep + os.environ.get("PATH", "")
        ctypes.windll.kernel32.SetDllDirectoryW(self.dll_dir)
        # ZKFPCap loads its sensor plugins from a ZKFPSensors\ folder relative to cwd
        try:
            os.chdir(self.dll_dir)
        except Exception:
            pass
        for name in CHAIN[:-1]:
            p = os.path.join(self.dll_dir, name)
            if os.path.exists(p):
                h = ctypes.windll.kernel32.LoadLibraryW(p)
                if not h:
                    warn("preload %s failed (Win32 err %d)"
                         % (name, ctypes.windll.kernel32.GetLastError()))
                else:
                    info("pinned %s" % name)
            else:
                warn("%s not in sdk dir (a dynamic dep may resolve elsewhere)" % name)
        self.dll = ctypes.CDLL(os.path.join(self.dll_dir, "libzkfp.dll"))
        self._bind()

    def _bind(self):
        d = self.dll
        d.ZKFPM_Init.restype = ctypes.c_int
        d.ZKFPM_Terminate.restype = ctypes.c_int
        d.ZKFPM_GetDeviceCount.restype = ctypes.c_int
        d.ZKFPM_OpenDevice.restype = ctypes.c_void_p
        d.ZKFPM_OpenDevice.argtypes = [ctypes.c_int]
        d.ZKFPM_CloseDevice.restype = ctypes.c_int
        d.ZKFPM_CloseDevice.argtypes = [ctypes.c_void_p]
        d.ZKFPM_GetParameters.restype = ctypes.c_int
        d.ZKFPM_GetParameters.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                          ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint)]
        d.ZKFPM_AcquireFingerprint.restype = ctypes.c_int
        d.ZKFPM_AcquireFingerprint.argtypes = [ctypes.c_void_p,
                                               ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
                                               ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint)]
        d.ZKFPM_DBInit.restype = ctypes.c_void_p
        d.ZKFPM_DBFree.restype = ctypes.c_int
        d.ZKFPM_DBFree.argtypes = [ctypes.c_void_p]
        d.ZKFPM_DBMerge.restype = ctypes.c_int
        d.ZKFPM_DBMerge.argtypes = [ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte),
                                    ctypes.POINTER(ctypes.c_ubyte),
                                    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint)]

    def init(self):
        return int(self.dll.ZKFPM_Init())

    def device_count(self):
        return int(self.dll.ZKFPM_GetDeviceCount())

    def param_int(self, handle, code):
        buf = (ctypes.c_ubyte * 4)()
        ln = ctypes.c_uint(4)
        rc = int(self.dll.ZKFPM_GetParameters(handle, code, buf, ctypes.byref(ln)))
        if rc != 0:
            return None
        return int.from_bytes(bytes(buf[:4]), "little")


def report_runtime(dll_dir):
    """Show which chain DLLs are present in the chosen runtime + their sizes."""
    info("runtime dir: %s" % os.path.abspath(dll_dir))
    for name in CHAIN:
        p = os.path.join(dll_dir, name)
        if os.path.exists(p):
            ok("%-16s present (%d bytes)" % (name, os.path.getsize(p)))
        else:
            err("%-16s MISSING from this runtime dir" % name)
    sub = os.path.join(dll_dir, "ZKFPSensors")
    if os.path.isdir(sub):
        ok("ZKFPSensors/     present (%d capture plugins)" % len(os.listdir(sub)))
    else:
        warn("ZKFPSensors/     absent (capture may fail once a reader is attached)")


def diagnose(dll_dir):
    title("ZK9500 DIAGNOSE")
    bits = struct.calcsize("P") * 8
    (ok if bits == 32 else err)("Python is %d-bit  (the ZK9500 DLLs are 32-bit; MUST be 32-bit)" % bits)
    if bits != 32:
        err("Re-run with a 32-bit Python 3, or the DLLs will refuse to load.")
        return

    print()
    info("Step 1/5  -  which fingerprint runtime are we using?")
    report_runtime(dll_dir)

    print()
    info("Step 2/5  -  load libzkfp + pin the algorithm chain")
    dev = Zk9500(dll_dir)
    try:
        dev.load()
    except OSError as e:
        err("libzkfp.dll failed to LOAD: %s" % e)
        warn("A STATIC dependency is missing/blocked. That is a DLL problem.")
        return
    ok("libzkfp.dll loaded")
    for name in CHAIN:
        p = module_path(name)
        info("  loaded %-16s <- %s" % (name, p or "(not yet resolved / loaded on demand)"))

    print()
    info("Step 3/5  -  ZKFPM_Init()  (initializes the matching algorithm)")
    rc = dev.init()
    if rc in (0, 1):
        ok("ZKFPM_Init() = %d  (%s)" % (rc, RC_MEANING.get(rc)))
    else:
        err("ZKFPM_Init() = %d  (%s)" % (rc, RC_MEANING.get(rc, "unknown")))

    print()
    info("Step 4/5  -  does Windows see a fingerprint reader on THIS PC?")
    readers = enumerate_zk_readers()
    if readers:
        for r in readers:
            info("  %s" % r)
    else:
        warn("  no biometric/ZK reader enumerated by Windows on this PC")

    print()
    info("Step 5/5  -  device count via the SDK")
    if rc in (0, 1):
        cnt = dev.device_count()
        (ok if cnt > 0 else warn)("ZKFPM_GetDeviceCount() = %d" % cnt)
    else:
        warn("skipped (Init did not succeed)")

    # ---- verdict -----------------------------------------------------------
    print()
    title("VERDICT")
    if rc in (0, 1):
        ok("Algorithm library initializes on this PC. If device count is 0, just")
        ok("attach the ZK9500 and run  --enroll  to capture a template.")
    elif rc == -1:
        if not readers:
            warn("Init failed -1 AND no reader is attached to THIS PC.")
            warn("The complete matched runtime is present (Step 1), so this -1 is NOT a")
            warn("missing/mismatched DLL. The remaining unproven variable is the ABSENT")
            warn("reader. Re-run this on the gym PC WITH the ZK9500 plugged in - if Init")
            warn("then returns 0, the algorithm simply needs the device present.")
        else:
            err("Init failed -1 WITH a reader present and the complete matched runtime.")
            err("This is the real defect. Capture the output above (esp. Step 1 sizes +")
            err("Step 4 reader status) - it rules out DLLs, so the cause is the reader's")
            err("driver binding or the device itself. Next: try the ZKFinger SDK's own")
            err("Demo.exe on this same PC; if it ALSO fails, it is environment/driver.")
    else:
        err("Init failed %d (%s). See the meaning above." % (rc, RC_MEANING.get(rc, "?")))
    try:
        dev.dll.ZKFPM_Terminate()
    except Exception:
        pass


def enroll(dll_dir, pin, name, card, finger, samples=3, timeout_s=30):
    title("ZK9500 ENROLL -> local store")
    if not (pin.isdigit() and 1 <= len(pin) <= 9):
        err("PIN must be 1-9 digits"); return
    dev = Zk9500(dll_dir)
    try:
        dev.load()
    except OSError as e:
        err("load failed: %s" % e); return
    rc = dev.init()
    if rc not in (0, 1):
        err("ZKFPM_Init() = %d (%s) - run  --diagnose  first." % (rc, RC_MEANING.get(rc, "?")))
        return
    if dev.device_count() < 1:
        err("Init OK but no ZK9500 detected - plug it in / try another USB port.")
        dev.dll.ZKFPM_Terminate(); return

    h = dev.dll.ZKFPM_OpenDevice(0)
    if not h:
        err("ZKFPM_OpenDevice returned NULL"); dev.dll.ZKFPM_Terminate(); return
    h = ctypes.c_void_p(h)
    ok("reader open")

    w = dev.param_int(h, PARAM_IMAGE_WIDTH) or 300
    ht = dev.param_int(h, PARAM_IMAGE_HEIGHT) or 400
    img = (ctypes.c_ubyte * (w * ht))()
    db = ctypes.c_void_p(dev.dll.ZKFPM_DBInit())
    caps = []
    try:
        for i in range(1, samples + 1):
            print()
            print(c(">>> Sample %d/%d - PLACE the finger on the reader..." % (i, samples), "y"))
            deadline = time.time() + timeout_s
            got = None
            while time.time() < deadline:
                tmpl = (ctypes.c_ubyte * 2048)()
                size = ctypes.c_uint(2048)
                rc = int(dev.dll.ZKFPM_AcquireFingerprint(h, img, len(img), tmpl, ctypes.byref(size)))
                if rc == 0:
                    got = bytes(tmpl[:size.value])
                    ok("sample %d captured (%d bytes) - LIFT the finger" % (i, size.value))
                    time.sleep(0.9)
                    break
                time.sleep(0.12)
            if got is None:
                err("timeout waiting for finger (%ds)" % timeout_s); return
            caps.append(got)

        info("merging %d samples into one registered template..." % samples)
        a = (ctypes.c_ubyte * len(caps[0]))(*caps[0])
        b = (ctypes.c_ubyte * len(caps[1]))(*caps[1])
        cc = (ctypes.c_ubyte * len(caps[2]))(*caps[2])
        reg = (ctypes.c_ubyte * 2048)()
        rsize = ctypes.c_uint(2048)
        rc = int(dev.dll.ZKFPM_DBMerge(db, a, b, cc, reg, ctypes.byref(rsize)))
        if rc != 0:
            err("ZKFPM_DBMerge failed rc=%d (use the SAME finger 3 times)" % rc); return
        raw = bytes(reg[:rsize.value])
        b64 = base64.b64encode(raw).decode("ascii")
        ok("registered template: %d bytes" % rsize.value)

        # save to the SHARED store the .ps1 pack uses (templates\<pin>.json)
        os.makedirs(STORE_DIR, exist_ok=True)
        fpath = os.path.join(STORE_DIR, pin + ".json")
        member = {"pin": pin, "name": name, "card": card, "fingers": []}
        if os.path.exists(fpath):
            try:
                member = json.load(open(fpath, encoding="utf-8"))
            except Exception:
                pass
        member["name"] = name or member.get("name", "")
        member["card"] = card or member.get("card", "")
        member["fingers"] = [f for f in member.get("fingers", []) if f.get("fingerId") != finger] + [{
            "fingerId": finger, "template": b64, "size": rsize.value,
            "capturedAt": datetime.datetime.now().isoformat(timespec="seconds"),
            "source": "zk9500",
        }]
        json.dump(member, open(fpath, "w", encoding="utf-8"), indent=2)
        ok("saved %s  (member now has %d finger(s))" % (fpath, len(member["fingers"])))
        info("push it to a terminal with the .ps1 pack:  5_push_member_to_device.ps1")
    finally:
        try: dev.dll.ZKFPM_DBFree(db)
        except Exception: pass
        try: dev.dll.ZKFPM_CloseDevice(h)
        except Exception: pass
        try: dev.dll.ZKFPM_Terminate()
        except Exception: pass


def main():
    ap = argparse.ArgumentParser(description="ZK9500 diagnose + enroll (Python mirror of app/sdk/zkfinger.py)")
    ap.add_argument("--enroll", action="store_true", help="capture + save a template (default is diagnose)")
    ap.add_argument("--dll-dir", default=DEFAULT_SDK, help="runtime folder (default: the pack's bundled sdk\\)")
    ap.add_argument("--pin"); ap.add_argument("--name", default=""); ap.add_argument("--card", default="")
    ap.add_argument("--finger", type=int, default=6)
    a = ap.parse_args()
    if os.name != "nt":
        err("Windows only (ZKFinger is a Windows x86 SDK)."); sys.exit(1)
    if a.enroll:
        if not a.pin:
            err("--enroll needs --pin"); sys.exit(2)
        enroll(a.dll_dir, a.pin, a.name, a.card, a.finger)
    else:
        diagnose(a.dll_dir)


if __name__ == "__main__":
    main()
