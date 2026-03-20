import { useEffect, useRef } from "react";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { availableMonitors } from "@tauri-apps/api/window";

import {
  getTvHostBindings,
  refreshTvHostMonitors,
} from "@/tv/api";
import type { TvScreenBinding } from "@/tv/api/types";
import {
  closeTvPlayerWindow,
  ensureTvPlayerWindow,
  getTvPlayerWindowLabel,
} from "@/tv/runtime/playerWindows";

const SUPPORT_RESTART_REASONS = new Set([
  "SUPPORT_RESTART_BINDING",
  "SUPPORT_RESTART_PLAYER_WINDOW",
]);

export function TvOrchestrator() {
  const syncingRef = useRef(false);

  useEffect(() => {
    const discoverMonitors = async () => {
      try {
        const monitors = await availableMonitors();
        const payload = monitors.map((monitor, index) => ({
          monitor_id: monitor.name || `monitor_${index}`,
          monitor_label: monitor.name || `Monitor ${index + 1}`,
          monitor_index: index,
          is_connected: true,
          width: monitor.size.width,
          height: monitor.size.height,
          offset_x: monitor.position.x,
          offset_y: monitor.position.y,
          scale_factor: monitor.scaleFactor,
          is_primary: index === 0,
        }));
        await refreshTvHostMonitors(payload);
      } catch (error) {
        console.error("TvOrchestrator: monitor discovery failed", error);
      }
    };

    const superviseBindings = async () => {
      if (syncingRef.current) {
        return;
      }
      syncingRef.current = true;

      try {
        const [bindingsResponse, monitorList] = await Promise.all([
          getTvHostBindings(),
          availableMonitors(),
        ]);
        if (!bindingsResponse.ok) {
          throw new Error("Failed to fetch host bindings");
        }

        const bindings = bindingsResponse.rows;
        const bindingByLabel = new Map<string, TvScreenBinding>();
        for (const binding of bindings) {
          bindingByLabel.set(getTvPlayerWindowLabel(binding.id), binding);
        }

        const allWindows = await WebviewWindow.getAll();
        const tvWindows = allWindows.filter((win) => win.label.startsWith("tv-player-"));
        const windowMap = new Map(tvWindows.map((win) => [win.label, win]));

        for (const win of tvWindows) {
          const binding = bindingByLabel.get(win.label);
          if (!binding || binding.desired_state !== "RUNNING") {
            const bindingId = binding?.id ?? Number.parseInt(win.label.replace("tv-player-", ""), 10);
            if (Number.isFinite(bindingId) && bindingId > 0) {
              await closeTvPlayerWindow(bindingId, win.label, win, "DESIRED_STOPPED");
            } else {
              try {
                await win.close();
              } catch (error) {
                console.warn(`TvOrchestrator: close failed for ${win.label}`, error);
              }
            }
            windowMap.delete(win.label);
          }
        }

        for (const binding of bindings) {
          if (binding.desired_state !== "RUNNING") {
            continue;
          }

          const label = getTvPlayerWindowLabel(binding.id);
          const runtime = binding.runtime ?? null;
          const restartRequested =
            runtime !== null &&
            (runtime.runtime_state === "CRASHED" ||
              runtime.runtime_state === "ERROR" ||
              SUPPORT_RESTART_REASONS.has(runtime.last_exit_reason ?? ""));

          const existingWindow = windowMap.get(label);
          if (existingWindow && restartRequested) {
            await closeTvPlayerWindow(
              binding.id,
              label,
              existingWindow,
              runtime?.last_exit_reason || "SUPPORT_RESTART",
            );
            windowMap.delete(label);
          }

          if (windowMap.has(label)) {
            continue;
          }

          const ensuredWindow = await ensureTvPlayerWindow(binding, monitorList);
          if (ensuredWindow.ok) {
            windowMap.set(label, ensuredWindow.window);
          }
        }
      } catch (error) {
        console.error("TvOrchestrator: supervisor cycle failed", error);
      } finally {
        syncingRef.current = false;
      }
    };

    void discoverMonitors();
    void superviseBindings();

    const discoveryInterval = window.setInterval(() => {
      void discoverMonitors();
    }, 10000);
    const supervisorInterval = window.setInterval(() => {
      void superviseBindings();
    }, 5000);

    return () => {
      window.clearInterval(discoveryInterval);
      window.clearInterval(supervisorInterval);
    };
  }, []);

  return null;
}
