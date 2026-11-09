import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { get } from "@/api/client";
import { deskActionPath, type DeskNotifyAction, type DeskNotifySettings } from "@/lib/deskNotify";

/** Main-window lifetime, independent of the active page or the staff login state. */
export function useDeskNotifyActions() {
  const navigate = useNavigate();
  useEffect(() => {
    let stopped = false;
    let unlisten: (() => void) | undefined;
    let timer: number | undefined;
    void listen<DeskNotifyAction>("desk-notify-action", (event) => {
      void invoke("show_main_for_desk_notify").then(() => {
        if (!stopped) navigate(deskActionPath(event.payload));
      }).catch(() => {});
    }).then((fn) => { if (stopped) fn(); else unlisten = fn; }).catch(() => {});
    const check = async () => {
      try {
        const settings = await get<DeskNotifySettings>("/desk-notify/settings");
        if (stopped) return;
        await invoke(settings.enabled ? "ensure_desk_notify_window" : "hide_desk_notify_window");
      } catch { /* Startup API readiness and browser preview. */ }
      if (!stopped) timer = window.setTimeout(check, 3000);
    };
    void check();
    return () => { stopped = true; unlisten?.(); window.clearTimeout(timer); };
  }, [navigate]);
}
