import { useDeferredValue, useEffect, useState } from "react";

import { post } from "@/api/client";
import type { AgentDeviceSnap, DeviceDto, DoorPresetDto } from "@/api/types";
import { useAgentStatus, useDevices } from "@/api/hooks";
import StatusChip from "@/components/StatusChip2";
import { useApp } from "@/context/AppContext";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Activity,
  Bot,
  Cable,
  CircleAlert,
  DoorOpen,
  ExternalLink,
  LockOpen,
  RefreshCw,
  Router,
  Search,
  ShieldCheck,
  Wifi,
  WifiOff,
  X,
} from "lucide-react";

const statCardClassName = "rounded-[20px] border border-border bg-muted px-3 py-3";
const detailCardClassName = "rounded-[18px] border border-border bg-muted p-3";
const outlineBadgeClassName = "border-border bg-secondary text-secondary-foreground";
const infoBadgeClassName = `${outlineBadgeClassName} text-[10px] tracking-wide`;

type Notice = {
  variant: "success" | "destructive" | "info";
  title: string;
  message: string;
};

type AgentDeviceInfo = AgentDeviceSnap[string];

type PanelDevice = {
  id: number;
  name: string;
  description: string;
  accessDataMode: string;
  ipAddress: string;
  portNumber: string;
  platform: string;
  active: boolean;
  accessDevice: boolean;
  doorIds: number[];
  doorPresets: DoorPresetDto[];
  statusVariant: string;
  statusLabel: string;
  connected: boolean;
  lastError: string;
};

function toNumber(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toStringValue(value: unknown, fallback = ""): string {
  if (typeof value === "string") return value;
  if (value == null) return fallback;
  return String(value);
}

function toBoolean(value: unknown, fallback = false): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized)) return true;
    if (["0", "false", "no", "off"].includes(normalized)) return false;
  }
  return fallback;
}

function toNumberList(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => toNumber(item, Number.NaN))
    .filter((item) => Number.isFinite(item));
}

function normalizePreset(raw: unknown, deviceId: number): DoorPresetDto {
  const source = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
  return {
    id: toNumber(source.id, 0),
    deviceId: toNumber(source.deviceId ?? deviceId, deviceId),
    doorNumber: toNumber(source.doorNumber, 1),
    pulseSeconds: toNumber(source.pulseSeconds, 3),
    doorName: toStringValue(source.doorName, `Door ${toNumber(source.doorNumber, 1)}`),
  };
}

function normalizeDevice(raw: unknown): Omit<PanelDevice, "statusVariant" | "statusLabel" | "connected" | "lastError"> {
  const source = raw && typeof raw === "object" ? raw as Partial<DeviceDto> & Record<string, unknown> : {};
  const id = toNumber(source.id ?? source.deviceId, 0);
  const presetsRaw = Array.isArray(source.doorPresets)
    ? source.doorPresets
    : Array.isArray(source.door_presets)
      ? source.door_presets
      : [];

  return {
    id,
    name: toStringValue(source.name ?? source.deviceName, `Device #${id || "?"}`),
    description: toStringValue(source.description, ""),
    accessDataMode: toStringValue(source.accessDataMode ?? source.access_data_mode, "UNKNOWN").toUpperCase(),
    ipAddress: toStringValue(source.ipAddress ?? source.ip_address ?? source.ip, "-"),
    portNumber: toStringValue(source.portNumber ?? source.port_number ?? source.port, "4370"),
    platform: toStringValue(source.platform, ""),
    active: toBoolean(source.active, true),
    accessDevice: toBoolean(source.accessDevice ?? source.access_device, true),
    doorIds: toNumberList(source.doorIds ?? source.door_ids),
    doorPresets: presetsRaw.map((preset) => normalizePreset(preset, id)),
  };
}

function resolveDeviceStatus(
  device: ReturnType<typeof normalizeDevice>,
  agentDevice: AgentDeviceInfo | undefined,
  pullsdkConnected: boolean,
  pullsdkDeviceId: number | null | undefined,
  syncRunning: boolean,
): Pick<PanelDevice, "statusVariant" | "statusLabel" | "connected" | "lastError"> {
  const agentConnected = Boolean(agentDevice?.connected);
  const pullsdkLive = pullsdkConnected && pullsdkDeviceId === device.id;
  const lastError = toStringValue(agentDevice?.lastError, "");

  if (!device.active) {
    return { statusVariant: "offline", statusLabel: "Inactive", connected: false, lastError };
  }
  if (lastError) {
    return { statusVariant: "error", statusLabel: "Agent error", connected: false, lastError };
  }
  if (agentConnected || pullsdkLive) {
    return { statusVariant: "online", statusLabel: "Connected", connected: true, lastError: "" };
  }
  if (device.accessDataMode === "AGENT") {
    if (agentDevice?.enabled === false) {
      return { statusVariant: "offline", statusLabel: "Agent off", connected: false, lastError: "" };
    }
    return { statusVariant: "idle", statusLabel: "Agent standby", connected: false, lastError: "" };
  }
  if (syncRunning) {
    return { statusVariant: "syncing", statusLabel: "Syncing", connected: false, lastError: "" };
  }
  return { statusVariant: "idle", statusLabel: "Ready", connected: false, lastError: "" };
}

function formatClock(value: string | null | undefined): string {
  if (!value) return "No sync yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return toStringValue(value, "No sync yet");
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function PanelStat({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className={statCardClassName}>
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">{label}</span>
        <Icon className="h-4 w-4 text-primary" />
      </div>
      <div className="mt-2 text-xl font-semibold text-foreground">{value}</div>
      <div className="mt-1 text-xs text-muted-foreground">{hint}</div>
    </div>
  );
}

export default function TrayPanelPage() {
  const { status, loading, error, refreshStatus, syncNow } = useApp();
  const { data, loading: devicesLoading, error: devicesError, reload } = useDevices();
  const { devices: agentDevices } = useAgentStatus(3000);

  const [query, setQuery] = useState("");
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const deferredQuery = useDeferredValue(query.trim().toLowerCase());

  useEffect(() => {
    if (!notice) return undefined;
    const timer = window.setTimeout(() => setNotice(null), 3200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        void hideCurrentPanel();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const rawDevices = Array.isArray(data?.devices) ? data.devices : [];
  const devices = rawDevices.map((rawDevice) => {
    const normalized = normalizeDevice(rawDevice);
    const agentDevice = agentDevices[String(normalized.id)];
    return {
      ...normalized,
      ...resolveDeviceStatus(
        normalized,
        agentDevice,
        Boolean(status?.pullsdk?.connected),
        status?.pullsdk?.deviceId,
        Boolean(status?.sync?.running),
      ),
    };
  });

  const filteredDevices = devices.filter((device) => {
    if (!deferredQuery) return true;
    const searchable = [
      device.name,
      device.ipAddress,
      device.accessDataMode,
      device.platform,
      device.connected ? "connected" : "offline",
    ]
      .join(" ")
      .toLowerCase();
    return searchable.includes(deferredQuery);
  });

  const connectedCount = devices.filter((device) => device.connected).length;
  const agentCount = devices.filter((device) => device.accessDataMode === "AGENT").length;
  const deviceModeCount = devices.filter((device) => device.accessDataMode === "DEVICE").length;

  async function hideCurrentPanel() {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("destroy_access_panel_window");
    } catch {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        await getCurrentWindow().hide();
      } catch {
        window.close();
      }
    }
  }

  async function openMainApp() {
    try {
      const [{ WebviewWindow }, { getCurrentWindow }] = await Promise.all([
        import("@tauri-apps/api/webviewWindow"),
        import("@tauri-apps/api/window"),
      ]);
      const main = await WebviewWindow.getByLabel("main");
      if (main) {
        await main.show();
        await main.setFocus();
      }
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("destroy_access_panel_window");
      } catch {
        await getCurrentWindow().hide();
      }
    } catch {
      // Browser mode fallback: keep the panel open.
    }
  }

  async function handleSyncNow() {
    setBusyKey("sync");
    try {
      await syncNow();
      setNotice({
        variant: "info",
        title: "Sync started",
        message: "The local backend is refreshing device data.",
      });
      window.setTimeout(() => {
        void refreshStatus();
        void reload();
      }, 1800);
    } catch (syncError) {
      setNotice({
        variant: "destructive",
        title: "Sync failed",
        message: String(syncError),
      });
    } finally {
      setBusyKey(null);
    }
  }

  async function handleOpenPreset(device: PanelDevice, preset: DoorPresetDto) {
    const actionKey = `preset:${device.id}:${preset.doorNumber}:${preset.pulseSeconds}`;
    setBusyKey(actionKey);
    try {
      await post(`/devices/${device.id}/door/open`, {
        doorNumber: preset.doorNumber,
        pulseSeconds: preset.pulseSeconds,
      });
      setNotice({
        variant: "success",
        title: "Door command sent",
        message: `${device.name} - ${preset.doorName}`,
      });
    } catch (openError) {
      setNotice({
        variant: "destructive",
        title: "Door open failed",
        message: String(openError),
      });
    } finally {
      setBusyKey(null);
    }
  }

  const sessionEmail = status?.session?.email ?? "Local runtime";
  const panelBusy = (loading && !status) || (devicesLoading && rawDevices.length === 0);
  const showLoginState = !panelBusy && !(status?.session?.loggedIn ?? false);
  const showRestrictedState = !showLoginState && Boolean(status?.session?.restricted);

  return (
    <div className="h-screen w-screen overflow-hidden bg-transparent">
      <div
        className="h-full w-full origin-top-left text-foreground"
        style={{ transform: "scale(0.9)", width: "111.1112%", height: "111.1112%" }}
      >
        <div className="flex h-full flex-col overflow-hidden rounded-[24px] border border-border bg-background shadow-[0_18px_50px_rgba(0,0,0,0.16)] dark:shadow-[0_28px_70px_rgba(0,0,0,0.5)]">
        <div className="border-b border-border px-4 pb-4 pt-4">
          <div className="flex items-start justify-between gap-3">
            <div data-tauri-drag-region className="flex min-w-0 items-start gap-3">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-primary/25 bg-primary/10 text-primary">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="text-[11px] uppercase tracking-[0.22em] text-muted-foreground">Tray panel</div>
                <h1 className="mt-1 truncate text-lg font-semibold text-foreground">MonClub Access</h1>
                <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  <span className="truncate">{sessionEmail}</span>
                  <Badge variant="outline" className={outlineBadgeClassName}>
                    {status?.agent?.running ? "Agent on" : "Agent off"}
                  </Badge>
                  <Badge variant="outline" className={outlineBadgeClassName}>
                    Last sync {formatClock(status?.sync?.lastSyncAt)}
                  </Badge>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-9 rounded-xl"
                onClick={openMainApp}
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Open app
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 rounded-full text-muted-foreground hover:text-foreground"
                onClick={() => void hideCurrentPanel()}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="mt-4 grid grid-cols-3 gap-2">
            <PanelStat icon={Router} label="Devices" value={String(devices.length)} hint={`${deviceModeCount} device mode`} />
            <PanelStat icon={Wifi} label="Connected" value={String(connectedCount)} hint={`${agentCount} agent mode`} />
            <PanelStat
              icon={status?.sync?.running ? RefreshCw : Activity}
              label="Runtime"
              value={status?.sync?.running ? "Syncing" : "Ready"}
              hint={status?.pullsdk?.connected ? "PullSDK live link active" : "Waiting for command"}
            />
          </div>

          <div className="mt-4 flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search by name, IP, mode..."
                className="h-10 rounded-xl border-input bg-card pl-9 placeholder:text-muted-foreground"
              />
            </div>
            <Button
              variant="default"
              size="sm"
              className="h-10 rounded-xl px-3"
              onClick={() => void handleSyncNow()}
              disabled={busyKey === "sync"}
            >
              <RefreshCw className={`h-4 w-4 ${busyKey === "sync" ? "animate-spin" : ""}`} />
              Sync
            </Button>
          </div>
        </div>

        {notice && (
          <div className="px-4 pt-3">
            <Alert variant={notice.variant}>
              <CircleAlert className="h-4 w-4" />
              <AlertTitle>{notice.title}</AlertTitle>
              <AlertDescription>{notice.message}</AlertDescription>
            </Alert>
          </div>
        )}

          <ScrollArea className="flex-1 px-4 pb-4 pt-4">
          {panelBusy && (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, index) => (
                <div key={index} className="rounded-[20px] border border-border bg-muted p-4">
                  <div className="h-4 w-28 animate-pulse rounded-full bg-secondary" />
                  <div className="mt-3 h-10 animate-pulse rounded-xl bg-secondary" />
                  <div className="mt-2 h-10 animate-pulse rounded-xl bg-secondary" />
                </div>
              ))}
            </div>
          )}

          {showLoginState && (
            <Alert variant="warning" className="border border-border bg-card">
              <CircleAlert className="h-4 w-4" />
              <AlertTitle>Login required</AlertTitle>
              <AlertDescription>
                Open the main application, sign in, then reopen this panel from the tray.
              </AlertDescription>
            </Alert>
          )}

          {showRestrictedState && (
            <Alert variant="warning" className="border border-border bg-card">
              <CircleAlert className="h-4 w-4" />
              <AlertTitle>Access restricted</AlertTitle>
              <AlertDescription>
                {(status?.session?.reasons ?? []).join(" | ") || "The local runtime is currently restricted."}
              </AlertDescription>
            </Alert>
          )}

          {!panelBusy && !showLoginState && !showRestrictedState && (error || devicesError) && (
            <Alert variant="destructive">
              <CircleAlert className="h-4 w-4" />
              <AlertTitle>Panel data unavailable</AlertTitle>
              <AlertDescription>{devicesError || error || "Unknown error"}</AlertDescription>
            </Alert>
          )}

          {!panelBusy && !showLoginState && !showRestrictedState && !error && !devicesError && filteredDevices.length === 0 && (
            <div className="rounded-[22px] border border-dashed border-border bg-muted px-5 py-10 text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-border bg-card text-primary">
                <Router className="h-6 w-6" />
              </div>
              <div className="mt-4 text-sm font-medium text-foreground">No matching devices</div>
              <div className="mt-1 text-xs text-muted-foreground">
                Try another search term or run a sync to refresh the local cache.
              </div>
            </div>
          )}

          {!panelBusy && !showLoginState && !showRestrictedState && !error && !devicesError && filteredDevices.length > 0 && (
            <Accordion type="multiple" className="space-y-3">
              {filteredDevices.map((device) => (
                <AccordionItem
                  key={device.id}
                  value={`device-${device.id}`}
                  className="overflow-hidden rounded-[22px] border border-border bg-card px-0"
                >
                  <AccordionTrigger className="px-4 py-4 hover:no-underline">
                    <div className="flex min-w-0 flex-1 items-center gap-3 text-left">
                      <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-border bg-muted text-primary">
                        <Router className="h-5 w-5" />
                      </div>

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="truncate text-sm font-semibold text-foreground">{device.name}</span>
                          <Badge variant="outline" className="border-primary/25 bg-primary/10 text-[10px] tracking-wide text-primary">
                            {device.accessDataMode}
                          </Badge>
                          <Badge variant="outline" className={infoBadgeClassName}>
                            {device.accessDevice ? "ACCESS" : "GENERIC"}
                          </Badge>
                          {device.platform && (
                            <Badge variant="outline" className={infoBadgeClassName}>
                              {device.platform}
                            </Badge>
                          )}
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                          <span>{device.ipAddress}:{device.portNumber}</span>
                          <span className="text-border">/</span>
                          <span>{device.doorPresets.length} presets</span>
                        </div>
                      </div>

                      <div className="shrink-0">
                        <StatusChip variant={device.statusVariant} label={device.statusLabel} />
                      </div>
                    </div>
                  </AccordionTrigger>

                  <AccordionContent className="px-4 pb-4">
                    <div className="grid grid-cols-2 gap-2">
                      <div className={detailCardClassName}>
                        <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                          <Cable className="h-3.5 w-3.5" />
                          Status
                        </div>
                        <div className="mt-2 text-sm font-medium text-foreground">{device.statusLabel}</div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {device.connected ? "Live communication active" : "Using cached runtime info"}
                        </div>
                      </div>

                      <div className={detailCardClassName}>
                        <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                          <Bot className="h-3.5 w-3.5" />
                          Type
                        </div>
                        <div className="mt-2 text-sm font-medium text-foreground">{device.accessDataMode}</div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {device.accessDevice ? "Access controller enabled" : "Listed but not used for access"}
                        </div>
                      </div>

                      <div className={detailCardClassName}>
                        <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                          <DoorOpen className="h-3.5 w-3.5" />
                          Doors
                        </div>
                        <div className="mt-2 text-sm font-medium text-foreground">
                          {device.doorIds.length > 0 ? device.doorIds.join(", ") : "Default backend rule"}
                        </div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          Authorized doors configured for this controller
                        </div>
                      </div>

                      <div className={detailCardClassName}>
                        <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                          {device.connected ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
                          Endpoint
                        </div>
                        <div className="mt-2 text-sm font-medium text-foreground">{device.ipAddress}:{device.portNumber}</div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {device.platform || "Standard controller link"}
                        </div>
                      </div>
                    </div>

                    {device.lastError && (
                      <Alert variant="destructive" className="mt-3">
                        <CircleAlert className="h-4 w-4" />
                        <AlertTitle>Last device error</AlertTitle>
                        <AlertDescription>{device.lastError}</AlertDescription>
                      </Alert>
                    )}

                    <div className="mt-3 rounded-[20px] border border-border bg-muted p-3">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="text-sm font-medium text-foreground">Door presets</div>
                          <div className="text-xs text-muted-foreground">Quick actions synced from the dashboard</div>
                        </div>
                        <Badge variant="outline" className={outlineBadgeClassName}>
                          {device.doorPresets.length}
                        </Badge>
                      </div>

                      {device.doorPresets.length > 0 ? (
                        <div className="mt-3 space-y-2">
                          {device.doorPresets.map((preset) => {
                            const actionKey = `preset:${device.id}:${preset.doorNumber}:${preset.pulseSeconds}`;
                            const presetLabel = preset.doorName || `Door ${preset.doorNumber}`;
                            return (
                              <div
                                key={`${device.id}-${preset.id}-${preset.doorNumber}-${preset.pulseSeconds}`}
                                className="flex items-center justify-between rounded-[18px] border border-border bg-background px-3 py-2.5"
                              >
                                <div className="min-w-0">
                                  <div className="truncate text-sm font-medium text-foreground">{presetLabel}</div>
                                  <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                                    <span>Door #{preset.doorNumber}</span>
                                    <span className="text-border">/</span>
                                    <span>{preset.pulseSeconds}s pulse</span>
                                  </div>
                                </div>
                                <Button
                                  size="sm"
                                  className="rounded-xl"
                                  onClick={() => void handleOpenPreset(device, preset)}
                                  disabled={busyKey === actionKey}
                                >
                                  <LockOpen className={`h-4 w-4 ${busyKey === actionKey ? "animate-pulse" : ""}`} />
                                  Open
                                </Button>
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <div className="mt-3 rounded-[18px] border border-dashed border-border bg-background px-3 py-5 text-center text-xs text-muted-foreground">
                          No presets are available for this device yet.
                        </div>
                      )}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          )}
          </ScrollArea>
        </div>
      </div>
    </div>
  );
}
