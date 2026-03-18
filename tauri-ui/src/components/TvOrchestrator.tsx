import { useEffect, useRef } from "react";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { availableMonitors } from "@tauri-apps/api/window";

import {
  getTvHostBindings,
  postTvBindingRuntimeEvent,
  refreshTvHostMonitors,
} from "../api/tv";
import type { TvScreenBinding } from "../api/types";

const SUPPORT_RESTART_REASONS = new Set([
  "SUPPORT_RESTART_BINDING",
  "SUPPORT_RESTART_PLAYER_WINDOW",
]);

function matchesAssignedMonitor(binding: TvScreenBinding, monitor: Awaited<ReturnType<typeof availableMonitors>>[number]) {
  if (!binding.monitor_id && !binding.monitor_label) {
    return true;
  }
  return monitor.name === binding.monitor_id || monitor.name === binding.monitor_label;
}

async function reportRuntimeEvent(
  bindingId: number,
  body: {
    eventType: string;
    windowId?: string;
    errorCode?: string;
    errorMessage?: string;
  },
) {
  try {
    await postTvBindingRuntimeEvent(bindingId, body);
  } catch (error) {
    console.error("TvOrchestrator: failed to report runtime event", bindingId, body, error);
  }
}

async function closeWindowSafely(
  bindingId: number,
  windowLabel: string,
  win: WebviewWindow,
  errorCode: string,
  errorMessage?: string,
) {
  try {
    await win.close();
  } catch (error) {
    console.warn(`TvOrchestrator: close failed for ${windowLabel}`, error);
  }
  await reportRuntimeEvent(bindingId, {
    eventType: "WINDOW_CLOSED",
    windowId: windowLabel,
    errorCode,
    errorMessage,
  });
}

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
          bindingByLabel.set(`tv-player-${binding.id}`, binding);
        }

        const allWindows = await WebviewWindow.getAll();
        const tvWindows = allWindows.filter((win) => win.label.startsWith("tv-player-"));
        const windowMap = new Map(tvWindows.map((win) => [win.label, win]));

        for (const win of tvWindows) {
          const binding = bindingByLabel.get(win.label);
          if (!binding || binding.desired_state !== "RUNNING") {
            const bindingId = binding?.id ?? Number.parseInt(win.label.replace("tv-player-", ""), 10);
            if (Number.isFinite(bindingId) && bindingId > 0) {
              await closeWindowSafely(bindingId, win.label, win, "DESIRED_STOPPED");
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

          const label = `tv-player-${binding.id}`;
          const runtime = binding.runtime ?? null;
          const restartRequested =
            runtime !== null &&
            (runtime.runtime_state === "CRASHED" ||
              runtime.runtime_state === "ERROR" ||
              SUPPORT_RESTART_REASONS.has(runtime.last_exit_reason ?? ""));

          const assignedMonitor = binding.monitor_id
            ? monitorList.find((monitor) => matchesAssignedMonitor(binding, monitor))
            : monitorList[0] ?? null;

          if (!assignedMonitor) {
            await reportRuntimeEvent(binding.id, {
              eventType: "WINDOW_ERROR",
              windowId: label,
              errorCode: "MONITOR_MISSING",
              errorMessage: "Assigned monitor is missing or disconnected.",
            });
            continue;
          }

          const existingWindow = windowMap.get(label);
          if (existingWindow && restartRequested) {
            await closeWindowSafely(
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

          await reportRuntimeEvent(binding.id, {
            eventType: "WINDOW_STARTING",
            windowId: label,
          });

          const win = new WebviewWindow(label, {
            url: `/tv-player?bindingId=${binding.id}&screenId=${binding.screen_id}`,
            title: binding.window_label || `MonClub TV - Screen ${binding.screen_id}`,
            x: assignedMonitor.position.x,
            y: assignedMonitor.position.y,
            fullscreen: binding.fullscreen,
            decorations: !binding.fullscreen,
          });

          win.once("tauri://created", () => {
            void reportRuntimeEvent(binding.id, {
              eventType: "WINDOW_OPENED",
              windowId: label,
            });
          });

          win.once("tauri://error", (error) => {
            console.error(`TvOrchestrator: window creation failed for ${label}`, error);
            void reportRuntimeEvent(binding.id, {
              eventType: "WINDOW_ERROR",
              windowId: label,
              errorCode: "WINDOW_CREATE_ERROR",
              errorMessage: typeof error === "string" ? error : JSON.stringify(error),
            });
          });

          windowMap.set(label, win);
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
