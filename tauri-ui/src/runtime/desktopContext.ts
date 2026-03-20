import { invoke } from "@tauri-apps/api/core";
import { configureApiPort } from "@/api/client";

export type DesktopShellRole = "access" | "tv";

export interface DesktopRuntimeContext {
  role: DesktopShellRole;
  apiPort: number;
  productName: string;
  trayEnabled: boolean;
}

const DEFAULT_CONTEXT: DesktopRuntimeContext = {
  role: "access",
  apiPort: 8788,
  productName: "MonClub Access",
  trayEnabled: true,
};

let currentContext: DesktopRuntimeContext = DEFAULT_CONTEXT;

async function syncNativeWindowTitle(title: string) {
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow().setTitle(title);
  } catch {
    // Browser/dev mode or unsupported host.
  }
}

function normalizeContext(value: Partial<DesktopRuntimeContext> | null | undefined): DesktopRuntimeContext {
  const role = value?.role === "tv" ? "tv" : "access";
  const apiPort = Number.isFinite(value?.apiPort) && Number(value?.apiPort) > 0
    ? Number(value?.apiPort)
    : (role === "tv" ? 8789 : 8788);
  return {
    role,
    apiPort,
    productName: value?.productName?.trim() || (role === "tv" ? "MonClub TV" : "MonClub Access"),
    trayEnabled: value?.trayEnabled ?? (role === "access"),
  };
}

export async function loadDesktopRuntimeContext(): Promise<DesktopRuntimeContext> {
  try {
    const runtimeContext = await invoke<DesktopRuntimeContext>("get_desktop_runtime_context");
    currentContext = normalizeContext(runtimeContext);
  } catch {
    currentContext = DEFAULT_CONTEXT;
  }

  configureApiPort(currentContext.apiPort);

  if (typeof document !== "undefined") {
    document.title = currentContext.productName;
    document.documentElement.dataset.desktopRole = currentContext.role;
    if (document.body) {
      document.body.dataset.desktopRole = currentContext.role;
    }
  }
  void syncNativeWindowTitle(currentContext.productName);

  return currentContext;
}

export function getDesktopRuntimeContext(): DesktopRuntimeContext {
  return currentContext;
}
