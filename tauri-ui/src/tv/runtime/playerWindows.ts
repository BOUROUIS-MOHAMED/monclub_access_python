import { availableMonitors } from "@tauri-apps/api/window";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";

import { postTvBindingRuntimeEvent } from "@/tv/api";
import type { TvScreenBinding } from "@/tv/api/types";

type DesktopMonitor = Awaited<ReturnType<typeof availableMonitors>>[number];

function buildPlayerWindowUrl(binding: TvScreenBinding) {
  const path = `/tv-player?bindingId=${binding.id}&screenId=${binding.screen_id}`;
  if (typeof window === "undefined" || !window.location?.origin) {
    return path;
  }
  return new URL(path, window.location.origin).toString();
}

export function getTvPlayerWindowLabel(bindingId: number) {
  return `tv-player-${bindingId}`;
}

export function matchesAssignedMonitor(binding: TvScreenBinding, monitor: DesktopMonitor) {
  if (!binding.monitor_id && !binding.monitor_label && !binding.target_display_id) {
    return true;
  }
  // Primary: target_display_id (set by the auto-attach resolution algorithm)
  if (binding.target_display_id && monitor.name === binding.target_display_id) {
    return true;
  }
  // Fallback: legacy monitor_id / monitor_label
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
    console.error("playerWindows: failed to report runtime event", bindingId, body, error);
  }
}

export async function closeTvPlayerWindow(
  bindingId: number,
  windowLabel: string,
  win: WebviewWindow,
  errorCode: string,
  errorMessage?: string,
) {
  try {
    await win.close();
  } catch (error) {
    console.warn(`playerWindows: close failed for ${windowLabel}`, error);
  }

  await reportRuntimeEvent(bindingId, {
    eventType: "WINDOW_CLOSED",
    windowId: windowLabel,
    errorCode,
    errorMessage,
  });
}

export async function ensureTvPlayerWindow(
  binding: TvScreenBinding,
  monitorList?: DesktopMonitor[],
) {
  const label = getTvPlayerWindowLabel(binding.id);
  const monitors = monitorList ?? await availableMonitors();
  const assignedMonitor =
    binding.monitor_id || binding.monitor_label
      ? monitors.find((monitor) => matchesAssignedMonitor(binding, monitor)) ?? null
      : monitors[0] ?? null;

  if (!assignedMonitor) {
    const errorMessage = "Assigned monitor is missing or disconnected.";
    await reportRuntimeEvent(binding.id, {
      eventType: "WINDOW_ERROR",
      windowId: label,
      errorCode: "MONITOR_MISSING",
      errorMessage,
    });
    return { ok: false as const, reason: errorMessage };
  }

  const existingWindow = (await WebviewWindow.getAll()).find((win) => win.label === label);
  if (existingWindow) {
    try {
      await existingWindow.show();
      await existingWindow.setFocus();
    } catch (error) {
      console.warn(`playerWindows: failed to focus existing ${label}`, error);
    }
    return { ok: true as const, created: false as const, window: existingWindow };
  }

  await reportRuntimeEvent(binding.id, {
    eventType: "WINDOW_STARTING",
    windowId: label,
  });

  const win = new WebviewWindow(label, {
    url: buildPlayerWindowUrl(binding),
    title: binding.window_label || `MonClub TV - Screen ${binding.screen_id}`,
    x: assignedMonitor.position.x,
    y: assignedMonitor.position.y,
    width: assignedMonitor.size.width,
    height: assignedMonitor.size.height,
    fullscreen: Boolean(binding.fullscreen),
    decorations: !binding.fullscreen,
    focus: true,
  });

  win.once("tauri://created", () => {
    void reportRuntimeEvent(binding.id, {
      eventType: "WINDOW_OPENED",
      windowId: label,
    });
    void win.setFocus().catch((error) => {
      console.warn(`playerWindows: failed to focus new ${label}`, error);
    });
  });

  win.once("tauri://error", (error) => {
    console.error(`playerWindows: window creation failed for ${label}`, error);
    void reportRuntimeEvent(binding.id, {
      eventType: "WINDOW_ERROR",
      windowId: label,
      errorCode: "WINDOW_CREATE_ERROR",
      errorMessage: typeof error === "string" ? error : JSON.stringify(error),
    });
  });

  return { ok: true as const, created: true as const, window: win };
}
