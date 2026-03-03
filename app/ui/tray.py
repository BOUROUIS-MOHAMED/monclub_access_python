# monclub_access_python/app/ui/tray.py
from __future__ import annotations

import threading
from functools import partial
from typing import Any, Dict, List, Optional


class TrayController:
    """
    Windows tray integration using pystray + Pillow.

    NOTE:
      Your installed pystray backend is failing with nested submenus (Open -> Device -> Presets),
      so we implement a flattened menu:
         Open -> [Device] Preset items

    Clicking a preset:
      Connects to the device and sends door_pulse_open(door, seconds).
    """

    def __init__(self, *, app, logger):
        self.app = app
        self.logger = logger
        self._icon = None
        self._thread: Optional[threading.Thread] = None
        self.available = False

    # -------------------- public --------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        try:
            import pystray  # type: ignore
            from PIL import Image, ImageDraw  # type: ignore
        except Exception as e:
            self.available = False
            self.logger.warning(f"Tray disabled (missing pystray/Pillow): {e}")
            return

        self.available = True

        def make_icon_image():
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.rounded_rectangle((6, 6, 58, 58), radius=10, fill=(30, 144, 255, 255))
            d.rectangle((18, 20, 46, 26), fill=(255, 255, 255, 255))
            d.rectangle((18, 30, 46, 36), fill=(255, 255, 255, 255))
            d.rectangle((18, 40, 46, 46), fill=(255, 255, 255, 255))
            return img

        try:
            menu = self._build_menu(pystray)

            self._icon = pystray.Icon("monclub_access", make_icon_image(), "MonClub Access", menu)

            def run():
                try:
                    self._icon.run()
                except Exception as e:
                    self.logger.warning(f"Tray icon stopped: {e}")

            self._thread = threading.Thread(target=run, daemon=True)
            self._thread.start()
            self.logger.info("Tray icon started ✅")

        except Exception as e:
            self.available = False
            self.logger.warning(f"Tray init failed: {e}")

    def stop(self) -> None:
        try:
            if self._icon:
                self._icon.stop()
        except Exception:
            pass
        self._icon = None

    # -------------------- menu --------------------

    def _build_menu(self, pystray):
        return pystray.Menu(
            pystray.MenuItem("Show", self._on_show),
            pystray.MenuItem("Open", self._build_open_menu(pystray)),  # OLD-style submenu: action=Menu(...)
            pystray.MenuItem("Refresh tray menu", partial(self._on_refresh, pystray=pystray)),
            pystray.MenuItem("Sync now", self._on_sync),
            pystray.MenuItem("Quit", self._on_quit),
        )

    def _rebuild_menu(self, pystray) -> None:
        if not self._icon:
            return
        self._icon.menu = self._build_menu(pystray)
        if hasattr(self._icon, "update_menu"):
            try:
                self._icon.update_menu()
            except Exception:
                pass
        self.logger.info("Tray menu refreshed ✅")

    def _build_open_menu(self, pystray):
        """
        Flattened:
          Open -> [Device] Open preset ...
        """
        devices = self._list_devices_best_effort()
        items: List[Any] = []

        if not devices:
            # Avoid enabled=False (may not exist on very old pystray); use a no-op action.
            items.append(pystray.MenuItem("(No devices)", self._noop))
            return pystray.Menu(*items)

        # Build presets for each device
        for dev in devices:
            device_label = self._device_label(dev)
            did = dev.get("id")

            # If no id, skip presets lookup but still show something
            try:
                did_int = int(did) if did not in (None, "") else None
            except Exception:
                did_int = None

            presets = []
            if did_int is not None:
                try:
                    from app.core.db import list_device_door_presets

                    presets = list_device_door_presets(did_int) or []
                except Exception as e:
                    items.append(pystray.MenuItem(f"[{device_label}] (Failed loading presets: {e})", self._noop))
                    continue
            else:
                items.append(pystray.MenuItem(f"[{device_label}] (No device id — presets disabled)", self._noop))
                continue

            if not presets:
                # optional: show placeholder
                items.append(pystray.MenuItem(f"[{device_label}] (No presets)", self._noop))
                continue

            # Add each preset as a direct item under Open
            for p in presets[:10]:
                try:
                    door_name = str(getattr(p, "door_name", "") or "Door")
                    door_number = int(getattr(p, "door_number", 1) or 1)
                    pulse_seconds = int(getattr(p, "pulse_seconds", 3) or 3)
                except Exception:
                    continue

                title = f"[{device_label}] Open {door_name} (door {door_number}, {pulse_seconds}s)"
                action = partial(
                    self._on_open_preset,
                    device=dev,
                    door=door_number,
                    seconds=pulse_seconds,
                    preset_name=door_name,
                )
                items.append(pystray.MenuItem(title, action))

        return pystray.Menu(*items)

    # -------------------- tray handlers --------------------

    def _on_show(self, _icon, _item):
        self.app.after(0, self._show_window)

    def _on_sync(self, _icon, _item):
        try:
            self.app.after(0, self.app.request_sync_now)
        except Exception:
            pass

    def _on_quit(self, _icon, _item):
        self.app.after(0, self.app.quit_app)

    def _on_refresh(self, _icon, _item, *, pystray):
        try:
            self._rebuild_menu(pystray)
        except Exception as e:
            self.logger.warning(f"Tray refresh failed: {e}")

    def _noop(self, _icon=None, _item=None):
        return

    # -------------------- window --------------------

    def _show_window(self) -> None:
        try:
            self.app.deiconify()
            self.app.lift()
            try:
                self.app.focus_force()
            except Exception:
                pass
        except Exception:
            pass

    # -------------------- device discovery --------------------

    def _list_devices_best_effort(self) -> List[Dict[str, Any]]:
        src: List[Any] = []

        try:
            from app.core.db import list_sync_devices

            src = list_sync_devices() or []
        except Exception:
            src = []

        if not src:
            if hasattr(self.app, "devices") and isinstance(getattr(self.app, "devices"), list):
                src = getattr(self.app, "devices")

        devices: List[Dict[str, Any]] = []
        for item in (src or []):
            if isinstance(item, dict):
                devices.append(self._normalize_device(item))

        return devices

    def _normalize_device(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        def pick(*keys: str, default=None):
            for k in keys:
                if k in raw and raw.get(k) not in (None, ""):
                    return raw.get(k)
            return default

        did = pick("id", "device_id", "deviceId", default=None)
        name = str(pick("name", "device_name", "deviceName", default="") or "").strip() or "(unnamed)"
        model = str(pick("model", "platform", "device_model", "deviceModel", default="") or "").strip()
        ip = str(pick("ip", "ip_address", "ipAddress", "ipaddress", default="") or "").strip()
        port = pick("port", "port_number", "portNumber", default=4370)
        password = str(pick("password", "commPassword", "comm_password", "passwd", default="") or "")
        timeout_ms = pick("timeout_ms", "timeoutMs", "timeout", default=5000)

        try:
            port_i = int(str(port).strip())
        except Exception:
            port_i = 4370

        try:
            timeout_i = int(str(timeout_ms).strip())
        except Exception:
            timeout_i = 5000

        return {
            "id": did,
            "name": name,
            "model": model,
            "ip": ip,
            "port": port_i,
            "password": password,
            "timeout_ms": timeout_i,
        }

    def _device_label(self, d: Dict[str, Any]) -> str:
        did = d.get("id")
        name = (d.get("name") or "").strip() or "(unnamed)"
        ip = (d.get("ip") or "").strip()
        port = d.get("port")
        if did not in (None, ""):
            try:
                return f"{int(did)}:{name}@{ip}:{port}"
            except Exception:
                return f"{did}:{name}@{ip}:{port}"
        return f"{name}@{ip}:{port}"

    # -------------------- open preset action --------------------

    def _on_open_preset(self, icon, _item, *, device: Dict[str, Any], door: int, seconds: int, preset_name: str):
        self._tray_open_door_preset_async(
            icon=icon,
            device=device,
            door=door,
            seconds=seconds,
            preset_name=preset_name,
        )

    def _tray_open_door_preset_async(
        self,
        *,
        icon,
        device: Dict[str, Any],
        door: int,
        seconds: int,
        preset_name: str,
    ) -> None:
        def notify(msg: str) -> None:
            try:
                if hasattr(icon, "notify"):
                    icon.notify(msg, "MonClub Access")
            except Exception:
                pass

        def work():
            label = self._device_label(device)
            ip = (device.get("ip") or "").strip()
            port = int(device.get("port") or 4370)
            timeout_ms = int(device.get("timeout_ms") or 5000)
            password = str(device.get("password") or "")

            if not ip:
                msg = f"Open failed: device has no IP ({label})"
                self.logger.warning(msg)
                notify(msg)
                return

            try:
                from app.sdk.pullsdk import PullSDK

                cfg = getattr(self.app, "cfg", None)
                dll_path = None
                if cfg is not None:
                    dll_path = getattr(cfg, "pullsdk_dll_path", None) or getattr(cfg, "plcomm_dll_path", None)

                if not dll_path:
                    msg = "Open failed: PullSDK DLL path not configured (pullsdk_dll_path)."
                    self.logger.warning(msg)
                    notify(msg)
                    return

                sdk = PullSDK(dll_path, logger=self.logger)
                try:
                    sdk.connect(ip=ip, port=port, timeout_ms=timeout_ms, password=password)
                    rc = sdk.door_pulse_open(door=int(door), seconds=int(seconds))
                    msg = f"Door opened ✅ {preset_name} @ {label} (door={door}, {seconds}s, rc={rc})"
                    self.logger.info(msg)
                    notify(msg)
                finally:
                    try:
                        sdk.disconnect()
                    except Exception:
                        pass

            except Exception as e:
                msg = f"Open failed ❌ {preset_name} @ {label}: {e}"
                self.logger.exception(msg)
                notify(msg)

        threading.Thread(target=work, daemon=True).start()
