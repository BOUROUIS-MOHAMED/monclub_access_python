import type { TvHostBindingRow } from "@/api/types";

export interface TvDetectedMonitor {
  monitorId: string;
  monitorLabel: string;
  monitorIndex: number;
  x: number;
  y: number;
  width: number;
  height: number;
  scaleFactor: number;
  isPrimary: boolean;
}

function boolish(v: unknown): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    return s === "1" || s === "true" || s === "yes" || s === "on";
  }
  return false;
}

export function bindingWindowLabel(binding: TvHostBindingRow): string {
  const raw = String((binding as any)?.window_label || "").trim();
  if (raw) return raw;
  return `tv-player-binding-${binding.id}`;
}

function monitorIdFor(name: string, x: number, y: number, width: number, height: number): string {
  return `${name || "monitor"}:${x}:${y}:${width}x${height}`;
}

export async function detectHostMonitors(): Promise<TvDetectedMonitor[]> {
  try {
    const mod = await import("@tauri-apps/api/window");
    const monitors = await mod.availableMonitors();
    return (monitors || []).map((m: any, idx: number) => {
      const x = Number(m?.position?.x ?? 0);
      const y = Number(m?.position?.y ?? 0);
      const width = Number(m?.size?.width ?? 0);
      const height = Number(m?.size?.height ?? 0);
      const label = String(m?.name ?? `Monitor ${idx + 1}`);
      return {
        monitorId: monitorIdFor(label, x, y, width, height),
        monitorLabel: label,
        monitorIndex: idx,
        x,
        y,
        width,
        height,
        scaleFactor: Number(m?.scaleFactor ?? 1),
        isPrimary: idx === 0,
      } as TvDetectedMonitor;
    });
  } catch {
    return [];
  }
}

export async function getBindingWindow(bindingId: number): Promise<any | null> {
  try {
    const { WebviewWindow } = await import("@tauri-apps/api/webviewWindow");
    const label = `tv-player-binding-${bindingId}`;
    return await WebviewWindow.getByLabel(label);
  } catch {
    return null;
  }
}

export async function openBindingWindow(binding: TvHostBindingRow, monitor: TvDetectedMonitor | null): Promise<{ ok: boolean; windowId?: string; error?: string; alreadyRunning?: boolean }> {
  try {
    const { WebviewWindow } = await import("@tauri-apps/api/webviewWindow");
    const label = bindingWindowLabel(binding);
    const existing = await WebviewWindow.getByLabel(label);
    if (existing) {
      try {
        await existing.setFocus();
      } catch {
        // ignore focus failures
      }
      return { ok: true, windowId: label, alreadyRunning: true };
    }

    if (!monitor) {
      return { ok: false, error: "MONITOR_NOT_FOUND" };
    }

    const q = new URLSearchParams({
      bindingId: String(binding.id),
      screenId: String(binding.screen_id),
    });

    const win = new WebviewWindow(label, {
      url: `/tv/player?${q.toString()}`,
      title: `MonClub TV Player #${binding.screen_id}`,
      x: monitor.x,
      y: monitor.y,
      width: Math.max(640, monitor.width || 1280),
      height: Math.max(360, monitor.height || 720),
      decorations: false,
      resizable: false,
      focus: true,
      visible: true,
      fullscreen: boolish((binding as any)?.fullscreen),
    });

    return await new Promise((resolve) => {
      let done = false;
      const finish = (v: { ok: boolean; windowId?: string; error?: string; alreadyRunning?: boolean }) => {
        if (done) return;
        done = true;
        resolve(v);
      };
      win.once("tauri://created", () => finish({ ok: true, windowId: label, alreadyRunning: false }));
      win.once("tauri://error", (e: any) => finish({ ok: false, error: String(e?.payload ?? "WINDOW_LAUNCH_FAILED") }));
      setTimeout(() => finish({ ok: true, windowId: label, alreadyRunning: false }), 2000);
    });
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export async function closeBindingWindow(binding: TvHostBindingRow): Promise<{ ok: boolean; windowId?: string; error?: string }> {
  try {
    const { WebviewWindow } = await import("@tauri-apps/api/webviewWindow");
    const label = bindingWindowLabel(binding);
    const existing = await WebviewWindow.getByLabel(label);
    if (!existing) {
      return { ok: true, windowId: label };
    }
    await existing.close();
    return { ok: true, windowId: label };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
