from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Tuple

from app.sdk.pullsdk import PullSDK, PullSDKError


def _parse_params_text(raw: str) -> Dict[str, str]:
    """
    PullSDK GetDeviceParam often returns:
      "Key=Value,Key2=Value2"
    Sometimes with newlines. We'll support both.
    """
    out: Dict[str, str] = {}
    if not raw:
        return out

    s = raw.strip()
    if not s:
        return out

    # Normalize separators
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    parts: List[str] = []
    for line in s.split("\n"):
        line = line.strip()
        if not line:
            continue
        # sometimes a line contains comma-separated pairs
        parts.extend([p.strip() for p in line.split(",") if p.strip()])

    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                out[k] = v
        else:
            # fallback if no '='
            out[p] = ""

    return out


class DeviceInfoPage(ttk.Frame):
    """
    Shows device configuration/info using PullSDK GetDeviceParam + some counts.
    Does NOT reuse a global connection; it opens a temporary connection on each refresh.
    """

    DEFAULT_ITEMS = (
        # Common-ish fields across ZKTeco firmwares (some may return empty)
        "DeviceName,SerialNumber,ProductTime,FirmwareVersion,Platform,DeviceType,LockCount,ReaderCount,DoorCount,"
        "IPAddress,NetMask,Gateway,DHCP,MAC,CommPassword,TimeZone,ACFun,PhotoFunOn,FaceFunOn,FPFunOn,"
        "AlgVer,FPAlgVer,FaceAlgVer,~DeviceName,~SerialNumber,~FirmwareVersion,~Platform,~DeviceType"
    )

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # ---------- Top bar ----------
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        top.columnconfigure(1, weight=1)

        ttk.Button(top, text="Refresh device info", command=self.refresh).grid(row=0, column=0, sticky="w")

        self.lbl_status = ttk.Label(top, text="Status: ready")
        self.lbl_status.grid(row=0, column=1, sticky="w", padx=12)

        ttk.Button(top, text="Copy raw to clipboard", command=self.copy_raw).grid(row=0, column=2, sticky="e")

        # ---------- Items entry ----------
        items_row = ttk.Frame(self)
        items_row.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        items_row.columnconfigure(1, weight=1)

        ttk.Label(items_row, text="GetDeviceParam items (comma-separated):").grid(row=0, column=0, sticky="w")
        self.var_items = tk.StringVar(value=self.DEFAULT_ITEMS)
        ttk.Entry(items_row, textvariable=self.var_items).grid(row=0, column=1, sticky="ew", padx=10)

        # ---------- Paned view ----------
        pw = ttk.Panedwindow(self, orient="horizontal")
        pw.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Left: Key/Value tree
        left = ttk.Frame(pw)
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(left, columns=("key", "value"), show="headings", height=24)
        self.tree.heading("key", text="Key")
        self.tree.heading("value", text="Value")
        self.tree.column("key", width=260, anchor="w")
        self.tree.column("value", width=520, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")

        y = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        y.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=y.set)

        pw.add(left, weight=3)

        # Right: raw + counts
        right = ttk.Frame(pw)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        ttk.Label(right, text="Raw / extra info").grid(row=0, column=0, sticky="w", pady=(0, 6))

        self.txt = tk.Text(right, height=10)
        self.txt.grid(row=1, column=0, sticky="nsew")

        y2 = ttk.Scrollbar(right, orient="vertical", command=self.txt.yview)
        y2.grid(row=1, column=1, sticky="ns")
        self.txt.configure(yscrollcommand=y2.set)

        pw.add(right, weight=2)

        self._last_raw = ""
        self.refresh()

    def copy_raw(self):
        raw = self._last_raw or ""
        self.clipboard_clear()
        self.clipboard_append(raw)
        self.lbl_status.config(text="Status: raw copied ✅")

    def _tree_clear(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)

    def _tree_set(self, kv: Dict[str, str]):
        self._tree_clear()
        for k in sorted(kv.keys(), key=lambda x: x.lower()):
            self.tree.insert("", "end", values=(k, kv.get(k, "")))

    def refresh(self):
        items = (self.var_items.get() or "").strip()
        if not items:
            messagebox.showwarning("Device Info", "Please provide GetDeviceParam items.")
            return

        self.lbl_status.config(text="Status: loading...")
        self.txt.delete("1.0", "end")
        self.txt.insert("end", "Loading device info...\n")

        def work():
            sdk = None
            try:
                sdk = PullSDK(self.app.cfg.plcomm_dll_path, logger=self.app.logger)
                sdk.connect(
                    ip=self.app.cfg.ip,
                    port=self.app.cfg.port,
                    timeout_ms=self.app.cfg.timeout_ms,
                    password=self.app.cfg.password,
                )

                # 1) GetDeviceParam
                raw = ""
                params: Dict[str, str] = {}
                if sdk.supports_get_device_param():
                    raw = sdk.get_device_param(items=items, initial_size=65536)
                    params = _parse_params_text(raw)
                else:
                    raw = "(GetDeviceParam not available in this plcommpro.dll build)\n"
                    params = {}

                # 2) Some counts (best-effort; may return -1 if not supported)
                counts_lines: List[str] = []
                tables_to_count = [
                    "user",
                    "userauthorize",
                    "transaction",
                    "rtlog",
                    "timezone",
                    "holiday",
                    "templatev10",
                    "templatev9",
                ]
                for t in tables_to_count:
                    try:
                        c = sdk.get_device_data_count(table=t)
                        if c >= 0:
                            counts_lines.append(f"- {t}: {c}")
                    except Exception:
                        pass

                # 3) Render to UI
                def apply():
                    self._last_raw = raw

                    self._tree_set(params)

                    self.txt.delete("1.0", "end")
                    self.txt.insert("end", "=== Connection ===\n")
                    self.txt.insert("end", f"ip={self.app.cfg.ip} port={self.app.cfg.port} timeout={self.app.cfg.timeout_ms}\n\n")

                    self.txt.insert("end", "=== Counts (if supported) ===\n")
                    if counts_lines:
                        self.txt.insert("end", "\n".join(counts_lines) + "\n\n")
                    else:
                        self.txt.insert("end", "(counts not available)\n\n")

                    self.txt.insert("end", "=== Raw GetDeviceParam ===\n")
                    self.txt.insert("end", raw if raw else "(empty)\n")

                    self.lbl_status.config(text=f"Status: loaded ✅ | params={len(params)}")

                self.after(0, apply)

            except Exception as e:
                msg = str(e)

                def apply_err():
                    self.lbl_status.config(text="Status: failed ❌")
                    self.txt.delete("1.0", "end")
                    self.txt.insert("end", f"ERROR: {msg}\n")
                    messagebox.showerror("Device Info", msg)

                self.after(0, apply_err)
            finally:
                try:
                    if sdk:
                        sdk.disconnect()
                except Exception:
                    pass

        threading.Thread(target=work, daemon=True).start()
