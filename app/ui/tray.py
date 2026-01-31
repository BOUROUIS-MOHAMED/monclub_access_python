# monclub_access_python/app/ui/tray.py
from __future__ import annotations

import threading
from typing import Optional


class TrayController:
    """
    Windows tray integration using pystray + Pillow.

    If dependencies are missing, this becomes a no-op and the app behaves normally.
    """

    def __init__(self, *, app, logger):
        self.app = app
        self.logger = logger
        self._icon = None
        self._thread: Optional[threading.Thread] = None
        self.available = False

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
            # simple generated icon
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.rounded_rectangle((6, 6, 58, 58), radius=10, fill=(30, 144, 255, 255))
            d.rectangle((18, 20, 46, 26), fill=(255, 255, 255, 255))
            d.rectangle((18, 30, 46, 36), fill=(255, 255, 255, 255))
            d.rectangle((18, 40, 46, 46), fill=(255, 255, 255, 255))
            return img

        def on_show(_icon, _item):
            self.app.after(0, self._show_window)

        def on_sync(_icon, _item):
            try:
                self.app.after(0, self.app.request_sync_now)
            except Exception:
                pass

        def on_quit(_icon, _item):
            self.app.after(0, self.app.quit_app)

        menu = pystray.Menu(
            pystray.MenuItem("Show", on_show),
            pystray.MenuItem("Sync now", on_sync),
            pystray.MenuItem("Quit", on_quit),
        )

        self._icon = pystray.Icon("monclub_access", make_icon_image(), "MonClub Access", menu)

        def run():
            try:
                self._icon.run()
            except Exception as e:
                self.logger.warning(f"Tray icon stopped: {e}")

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        self.logger.info("Tray icon started ✅")

    def stop(self) -> None:
        try:
            if self._icon:
                self._icon.stop()
        except Exception:
            pass
        self._icon = None

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
