/**
 * Tauri tray integration — sets the API port, refreshes the tray menu
 * on sync/device changes, and listens for quit confirmation events.
 */
import { useEffect, useRef, useCallback, useState } from "react";

// Dynamically import Tauri API (only available when running inside Tauri)
let invoke: ((cmd: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null;
let listen: ((event: string, handler: (event: { payload: unknown }) => void) => Promise<() => void>) | null = null;

async function loadTauriApi() {
  try {
    const core = await import("@tauri-apps/api/core");
    invoke = core.invoke;
    const eventModule = await import("@tauri-apps/api/event");
    listen = eventModule.listen;
  } catch {
    // Not running inside Tauri (browser dev mode)
    invoke = null;
    listen = null;
  }
}

const tauriReady = loadTauriApi();

export function useTrayIntegration(apiPort: number = 8788): {
  refreshTray: () => Promise<void>;
  quitRequested: boolean;
  confirmQuit: () => Promise<void>;
  cancelQuit: () => void;
} {
  const unlisten = useRef<(() => void) | null>(null);
  const [quitRequested, setQuitRequested] = useState(false);

  // Set the API port and refresh menu
  const refreshTray = useCallback(async () => {
    await tauriReady;
    if (!invoke) return;
    try {
      await invoke("set_api_port", { port: apiPort });
      await invoke("refresh_tray_menu");
    } catch {
      // Ignore — tray might not be available
    }
  }, [apiPort]);

  const confirmQuit = useCallback(async () => {
    // Send quit to Python backend
    try {
      await fetch(`http://127.0.0.1:${apiPort}/api/v2/app/quit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
    } catch { /* ignore */ }
    // Close the Tauri window
    setTimeout(async () => {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        await getCurrentWindow().close();
      } catch {
        window.close();
      }
    }, 300);
  }, [apiPort]);

  const cancelQuit = useCallback(() => setQuitRequested(false), []);

  useEffect(() => {
    // Set port + initial menu refresh
    refreshTray();

    // Refresh tray menu periodically (every 30s) to pick up new devices/presets
    const interval = setInterval(refreshTray, 30_000);

    // Listen for tray-quit-request event from Rust
    (async () => {
      await tauriReady;
      if (!listen) return;
      try {
        const un = await listen("tray-quit-request", () => {
          setQuitRequested(true);
        });
        unlisten.current = un;
      } catch {
        // Ignore
      }
    })();

    return () => {
      clearInterval(interval);
      if (unlisten.current) {
        unlisten.current();
        unlisten.current = null;
      }
    };
  }, [apiPort, refreshTray]);

  return { refreshTray, quitRequested, confirmQuit, cancelQuit };
}

