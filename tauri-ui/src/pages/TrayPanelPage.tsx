import { useDeferredValue, useEffect, useState, type ReactNode } from "react";

import { post } from "@/api/client";
import type { AgentDeviceSnap, DeviceDto, DoorPresetDto } from "@/api/types";
import { useAgentStatus, useDevices } from "@/api/hooks";
import { useApp } from "@/context/AppContext";
import { hasAgentDevices } from "@/lib/agentMode";
import { cn } from "@/lib/utils";
import { ActionButton } from "@/components/ui/action-button";
import { Chip } from "@/components/ui/chip";
import { SOFT, type Tone } from "@/components/ui/tone";
import { doorRequestedMessage } from "@/api/realtime";
import {
  ChevronDown,
  CircleAlert,
  CircleCheck,
  CircleX,
  ExternalLink,
  Info,
  LockOpen,
  RadioTower,
  RefreshCw,
  Router,
  Search,
  Send,
  ShieldCheck,
  Star,
  Wifi,
  WifiOff,
  X,
  type LucideIcon,
} from "lucide-react";

// Access v5 tray panel (boards W01–W03): frameless always-on-top window, 428×608.

type Notice = {
  tone: Tone;
  icon: LucideIcon;
  title: string;
  message: string;
};

type AgentDeviceInfo = AgentDeviceSnap[string];

type PanelPreset = DoorPresetDto & { favorite: boolean };

type PanelDevice = {
  id: number;
  name: string;
  description: string;
  accessDataMode: string;
  ipAddress: string;
  portNumber: string;
  platform: string;
  model: string;
  protocol: DeviceProtocol;
  active: boolean;
  accessDevice: boolean;
  doorIds: number[];
  doorPresets: PanelPreset[];
  statusTone: Tone;
  statusLabel: string;
  connected: boolean;
  lastError: string;
};

// Protocol family, read like DevicesPage.protocolOf (mirrors
// app/sdk/device_driver.resolve_device_protocol): absent or unknown = PullSDK.
const STANDALONE_ALIASES = new Set([
  "ZK_STANDALONE", "STANDALONE", "ZKEMKEEPER", "ZKEM", "PUSH", "ADMS", "MB2000",
]);
type DeviceProtocol = "ZK_PULLSDK" | "ZK_STANDALONE";
const PROTOCOL_LABEL: Record<DeviceProtocol, string> = {
  ZK_PULLSDK: "PullSDK",
  ZK_STANDALONE: "ZKTeco autonome",
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

function normalizePreset(raw: unknown, deviceId: number): PanelPreset {
  const source = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
  return {
    id: toNumber(source.id, 0),
    deviceId: toNumber(source.deviceId ?? deviceId, deviceId),
    doorNumber: toNumber(source.doorNumber, 1),
    pulseSeconds: toNumber(source.pulseSeconds, 3),
    doorName: toStringValue(source.doorName, `Porte ${toNumber(source.doorNumber, 1)}`),
    // Star only when the synced preset really says so; absent = no star.
    favorite: source.favoriteEnabled === true,
  };
}

function normalizeDevice(raw: unknown): Omit<PanelDevice, "statusTone" | "statusLabel" | "connected" | "lastError"> {
  const source = raw && typeof raw === "object" ? raw as Partial<DeviceDto> & Record<string, unknown> : {};
  const id = toNumber(source.id ?? source.deviceId, 0);
  const presetsRaw = Array.isArray(source.doorPresets)
    ? source.doorPresets
    : Array.isArray(source.door_presets)
      ? source.door_presets
      : [];
  const protocolRaw = toStringValue(source.deviceProtocol ?? source.device_protocol, "").trim().toUpperCase();

  return {
    id,
    name: toStringValue(source.name ?? source.deviceName, `Appareil #${id || "?"}`),
    description: toStringValue(source.description, ""),
    accessDataMode: toStringValue(source.accessDataMode ?? source.access_data_mode, "UNKNOWN").toUpperCase(),
    // Empty string = no address (shown as « Adresse absente »), never a placeholder.
    ipAddress: toStringValue(source.ipAddress ?? source.ip_address ?? source.ip, "").trim(),
    portNumber: toStringValue(source.portNumber ?? source.port_number ?? source.port, "4370"),
    platform: toStringValue(source.platform, ""),
    model: toStringValue(source.model, ""),
    protocol: STANDALONE_ALIASES.has(protocolRaw) ? "ZK_STANDALONE" : "ZK_PULLSDK",
    active: toBoolean(source.active, true),
    accessDevice: toBoolean(source.accessDevice ?? source.access_device, true),
    doorIds: toNumberList(source.doorIds ?? source.door_ids),
    doorPresets: presetsRaw.map((preset) => normalizePreset(preset, id)),
  };
}

// Same four states as Appareils (DevicesPage.deviceStateOf) plus the AGENT-mode
// ones. « Non connecté » is red only where this PC runs a worker for the device:
// on a PC that drives nothing (a reader PC) every row would otherwise read as a fault.
function resolveDeviceStatus(
  device: ReturnType<typeof normalizeDevice>,
  agentDevice: AgentDeviceInfo | undefined,
  pullsdkConnected: boolean,
  pullsdkDeviceId: number | null | undefined,
  ultraWorker: { connected?: boolean } | undefined,
): Pick<PanelDevice, "statusTone" | "statusLabel" | "connected" | "lastError"> {
  const agentConnected = Boolean(agentDevice?.connected);
  const pullsdkLive = pullsdkConnected && pullsdkDeviceId === device.id;
  const lastError = toStringValue(agentDevice?.lastError, "");

  if (!device.active) {
    return { statusTone: "grey", statusLabel: "Inactif", connected: false, lastError };
  }
  if (!device.ipAddress) {
    return { statusTone: "warning", statusLabel: "Adresse absente", connected: false, lastError };
  }
  if (lastError) {
    return { statusTone: "error", statusLabel: "Erreur agent", connected: false, lastError };
  }
  // ULTRA workers own their own connection and never enter the manual PullSDK
  // session pool: this is the worker's real connected flag, not an assumption.
  if (agentConnected || pullsdkLive || Boolean(ultraWorker?.connected)) {
    return { statusTone: "success", statusLabel: "Connecté", connected: true, lastError: "" };
  }
  if (device.accessDataMode === "AGENT") {
    if (agentDevice?.enabled === false) {
      return { statusTone: "grey", statusLabel: "Agent arrêté", connected: false, lastError: "" };
    }
    return { statusTone: "grey", statusLabel: "Agent en attente", connected: false, lastError: "" };
  }
  return { statusTone: ultraWorker ? "error" : "grey", statusLabel: "Non connecté", connected: false, lastError: "" };
}

function formatClock(value: string | null | undefined): string {
  if (!value) return "Aucune sync";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return toStringValue(value, "Aucune sync");
  return `Dernière sync ${date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}`;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n > 1 ? "s" : ""}`;
}

function PanelStat({
  icon: Icon,
  label,
  value,
  hint,
  valueClassName,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  hint: string;
  valueClassName?: string;
}) {
  return (
    <div className="min-w-0 rounded-xl bg-muted px-2.5 py-[9px]">
      <div className="flex items-center gap-[5px] text-[11px] font-bold uppercase tracking-[0.04em] text-muted-foreground">
        <Icon className="h-[13px] w-[13px] shrink-0" />
        {label}
      </div>
      <div className={cn("font-num text-[21px] font-bold leading-[1.25] text-foreground", valueClassName)}>{value}</div>
      <div className="truncate text-[11.5px] text-muted-foreground">{hint}</div>
    </div>
  );
}

function NoticeBox({ notice, action }: { notice: Notice; action?: ReactNode }) {
  const Icon = notice.icon;
  return (
    <div role="status" className={cn("flex gap-[9px] rounded-[10px] px-3 py-2.5 text-[12.5px] leading-[1.45]", SOFT[notice.tone])}>
      <Icon className="mt-px h-[17px] w-[17px] shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="font-bold">{notice.title}</div>
        <div className="break-words">{notice.message}</div>
        {action}
      </div>
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
  const [openIds, setOpenIds] = useState<Set<number>>(() => new Set());
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

  const ultraDevices = status?.ultra?.devices ?? {};
  const rawDevices = Array.isArray(data?.devices) ? data.devices : [];
  const devices: (PanelDevice & { canOpenDoor: boolean })[] = rawDevices.map((rawDevice) => {
    const normalized = normalizeDevice(rawDevice);
    const agentDevice = agentDevices[String(normalized.id)];
    const ultraWorker = ultraDevices[String(normalized.id)];
    return {
      ...normalized,
      ...resolveDeviceStatus(
        normalized,
        agentDevice,
        Boolean(status?.pullsdk?.connected),
        status?.pullsdk?.deviceId,
        ultraWorker,
      ),
      // Door availability comes from the DRIVER, never the protocol: a standalone
      // terminal ships with the door command gated off but it can be enabled per
      // machine once the relay is verified. undefined = unknown -> keep it live.
      canOpenDoor: ultraWorker?.supports_open_door !== false,
    };
  });

  const filteredDevices = devices.filter((device) => {
    if (!deferredQuery) return true;
    const searchable = [
      device.name,
      device.ipAddress,
      device.accessDataMode,
      device.platform,
      device.model,
      PROTOCOL_LABEL[device.protocol],
      device.statusLabel,
    ]
      .join(" ")
      .toLowerCase();
    return searchable.includes(deferredQuery);
  });

  // ── Stats ──
  const modeCounts = devices.reduce<Record<string, number>>((acc, device) => {
    acc[device.accessDataMode] = (acc[device.accessDataMode] ?? 0) + 1;
    return acc;
  }, {});
  const modeEntries = Object.entries(modeCounts);
  const modeHint = devices.length === 0
    ? "aucun appareil"
    : modeEntries.length === 1
      ? `tous en mode ${modeEntries[0][0]}`
      : modeEntries.map(([mode, count]) => `${count} ${mode}`).join(" · ");

  const connectedCount = devices.filter((device) => device.connected).length;
  // « x / y » counts only the ULTRA workers this PC runs (same as the header pill of
  // the main window): a reader PC or a DEVICE-mode gym holds no permanent link, and
  // counting every roster row there would show a false « hors ligne ».
  const drivesTurnstiles = status?.ultra?.drivesTurnstiles;
  const ultraWorkers = Object.values(ultraDevices);
  const workerConnected = ultraWorkers.filter((worker) => worker?.connected).length;
  const showWorkerRatio = drivesTurnstiles !== false && ultraWorkers.length > 0;
  const allWorkersUp = workerConnected === ultraWorkers.length;

  // Role: `drivesTurnstiles` is false on a READER PC, but also on a PC of a gym with
  // no ULTRA device at all, so « Lecteur » needs ULTRA devices in the roster too.
  const ultraInRoster = (modeCounts.ULTRA ?? 0) > 0;
  const isReader = drivesTurnstiles === false && ultraInRoster;
  const isDriver = drivesTurnstiles === true && ultraInRoster;
  const showRole = isReader || isDriver;

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
        tone: "info",
        icon: RefreshCw,
        title: "Synchronisation lancée",
        message: "Le service local met à jour les appareils.",
      });
      window.setTimeout(() => {
        void refreshStatus();
        void reload();
      }, 1800);
    } catch (syncError) {
      setNotice({
        tone: "error",
        icon: CircleX,
        title: "Échec de la synchronisation",
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
      const res: any = await post(`/devices/${device.id}/door/open`, {
        doorNumber: preset.doorNumber,
        pulseSeconds: preset.pulseSeconds,
      });
      // P3b-2: another PC drives this turnstile -- filed for it, not opened here.
      // A filed request is information (its result is not visible here); one the
      // driver will never pick up is a warning. Neither is an error.
      setNotice(res?.requested
        ? {
            tone: res.targetConnected ? "info" : "warning",
            icon: res.targetConnected ? Send : CircleAlert,
            title: "Demande au PC pilote",
            message: `${device.name} · ${preset.doorName} : ${doorRequestedMessage(res)}`,
          }
        : {
            tone: "success",
            icon: CircleCheck,
            title: "Porte ouverte",
            message: `${device.name} · ${preset.doorName} (${preset.pulseSeconds} s)`,
          });
    } catch (openError) {
      setNotice({
        tone: "error",
        icon: CircleX,
        title: "Échec de l'ouverture",
        message: String(openError),
      });
    } finally {
      setBusyKey(null);
    }
  }

  function toggleDevice(id: number) {
    setOpenIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const panelBusy = (loading && !status) || (devicesLoading && rawDevices.length === 0);
  const showLoginState = !panelBusy && !(status?.session?.loggedIn ?? false);
  const showRestrictedState = !showLoginState && Boolean(status?.session?.restricted);
  const sessionEmail = showLoginState ? "Non connecté" : (status?.session?.email ?? "Service local");
  const dataError = devicesError || error;
  const showList = !panelBusy && !showLoginState && !showRestrictedState && !dataError;
  const syncSpinning = busyKey === "sync" || Boolean(status?.sync?.running);

  return (
    <div className="h-screen w-screen overflow-hidden bg-transparent">
      <div className="flex h-full w-full flex-col overflow-hidden rounded-[20px] border border-border bg-card text-foreground">
        {/* ── Header ── */}
        <div data-tauri-drag-region className="shrink-0 border-b border-dashed border-border px-3.5 pb-3 pt-3.5">
          <div data-tauri-drag-region className="flex items-start gap-2.5">
            <span className="grid h-[38px] w-[38px] shrink-0 place-items-center rounded-[11px] bg-primary text-primary-foreground">
              <ShieldCheck className="h-5 w-5" />
            </span>
            <div data-tauri-drag-region className="min-w-0 flex-1">
              <h1 className="m-0 text-[16px] font-bold leading-[1.2]">MonClub Access</h1>
              <div className="mt-[3px] flex min-w-0 items-center gap-1.5 text-[12px] text-muted-foreground">
                <span className="truncate">{sessionEmail}</span>
                {!showLoginState && (
                  <Chip size="sm" tone="grey" className="bg-muted text-foreground">
                    {formatClock(status?.sync?.lastSyncAt)}
                  </Chip>
                )}
                {!showLoginState && hasAgentDevices(status) && (
                  <Chip size="sm" tone={status?.agent?.running ? "success" : "grey"}>
                    {status?.agent?.running ? "Agent actif" : "Agent arrêté"}
                  </Chip>
                )}
              </div>
            </div>
            <ActionButton kind="outline" size="md" icon={ExternalLink} className="text-[12.5px]" onClick={() => void openMainApp()}>
              Ouvrir l’app
            </ActionButton>
            <button
              type="button"
              aria-label="Fermer le panneau (Échap)"
              title="Fermer (Échap)"
              onClick={() => void hideCurrentPanel()}
              className="grid h-8 w-8 shrink-0 place-items-center rounded-full text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {!showLoginState && (
            <>
              <div className={cn("mt-3 grid gap-2", showRole ? "grid-cols-3" : "grid-cols-2")}>
                <PanelStat icon={Router} label="Appareils" value={String(devices.length)} hint={modeHint} />
                {showWorkerRatio ? (
                  <PanelStat
                    icon={Wifi}
                    label="Connectés"
                    value={`${workerConnected} / ${ultraWorkers.length}`}
                    hint={allWorkersUp ? "tous les lecteurs" : `${ultraWorkers.length - workerConnected} hors ligne`}
                    valueClassName={allWorkersUp ? "text-success-ink" : "text-error-ink"}
                  />
                ) : (
                  <PanelStat
                    icon={Wifi}
                    label="Connectés"
                    value={String(connectedCount)}
                    hint={isReader ? "ce PC ne pilote aucun tourniquet" : `${connectedCount} liaison${connectedCount > 1 ? "s" : ""} active${connectedCount > 1 ? "s" : ""}`}
                  />
                )}
                {showRole && (
                  <PanelStat
                    icon={RadioTower}
                    label="Rôle"
                    value={isReader ? "Lecteur" : "Pilote"}
                    hint={isReader ? "demande au PC pilote" : "ouvre ses tourniquets"}
                  />
                )}
              </div>

              <div className="mt-2.5 flex gap-2">
                <div className="relative min-w-0 flex-1">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 h-[15px] w-[15px] -translate-y-1/2 text-muted-foreground" />
                  <input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Nom, adresse IP…"
                    aria-label="Rechercher un appareil"
                    className="h-9 w-full rounded-lg border border-grey/32 bg-card pl-[30px] pr-2.5 text-[13px] text-foreground outline-none placeholder:text-muted-foreground focus-visible:border-primary focus-visible:ring-2 focus-visible:ring-primary/20"
                  />
                </div>
                <ActionButton
                  kind="primary"
                  size="lg"
                  icon={RefreshCw}
                  spin={syncSpinning}
                  className="text-[13px]"
                  onClick={() => void handleSyncNow()}
                  disabled={busyKey === "sync"}
                >
                  Synchroniser
                </ActionButton>
              </div>
            </>
          )}
        </div>

        {/* ── Body ── */}
        <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto px-3 pb-3 pt-2.5">
          {notice && <NoticeBox notice={notice} />}

          {panelBusy && Array.from({ length: 3 }).map((_, index) => (
            <div key={index} className="flex items-center gap-2.5 rounded-[14px] border border-border px-3 py-2.5">
              <div className="h-[34px] w-[34px] animate-pulse rounded-[10px] bg-muted" />
              <div className="flex-1 space-y-1.5">
                <div className="h-3 w-32 animate-pulse rounded-full bg-muted" />
                <div className="h-2.5 w-44 animate-pulse rounded-full bg-muted" />
              </div>
            </div>
          ))}

          {showLoginState && (
            <NoticeBox
              notice={{
                tone: "warning",
                icon: CircleAlert,
                title: "Connexion requise",
                message: "Ouvrez l’application, connectez-vous, puis rouvrez ce panneau depuis la barre des tâches.",
              }}
              action={
                <ActionButton kind="dark" size="sm" className="mt-2" onClick={() => void openMainApp()}>
                  Ouvrir l’app
                </ActionButton>
              }
            />
          )}

          {showRestrictedState && (
            <NoticeBox
              notice={{
                tone: "warning",
                icon: CircleAlert,
                title: "Accès restreint",
                message: (status?.session?.reasons ?? []).join(" · ") || "Le service local est actuellement restreint.",
              }}
            />
          )}

          {!panelBusy && !showLoginState && !showRestrictedState && dataError && (
            <NoticeBox
              notice={{
                tone: "error",
                icon: CircleX,
                title: "Données du panneau indisponibles",
                message: String(dataError || "Erreur inconnue"),
              }}
            />
          )}

          {showList && filteredDevices.length === 0 && (
            <div className="rounded-[14px] border border-dashed border-grey/50 px-4 py-8 text-center text-[12.5px] leading-normal text-muted-foreground">
              <div className="font-bold text-foreground">
                {deferredQuery ? "Aucun appareil ne correspond" : "Aucun appareil synchronisé"}
              </div>
              {deferredQuery ? "Essayez une autre recherche." : "Lancez une synchronisation pour rafraîchir la liste."}
            </div>
          )}

          {showList && filteredDevices.map((device) => {
            const open = openIds.has(device.id);
            const ok = device.statusTone === "success";
            const faulty = device.statusTone === "error" || device.statusTone === "warning";
            const address = device.ipAddress ? `${device.ipAddress}:${device.portNumber}` : "";
            const hardware = [PROTOCOL_LABEL[device.protocol], device.model || device.platform].filter(Boolean).join(" · ");
            const readerNote = isReader && device.accessDataMode === "ULTRA";
            const note = !device.canOpenDoor
              ? "Commande d’ouverture non activée pour cet appareil (à activer dans Appareils › Contrôle une fois le relais vérifié)."
              : device.doorPresets.length === 0
                ? "Aucun preset de porte pour cet appareil."
                : readerNote
                  ? "Ce PC est lecteur : « Ouvrir » envoie une demande au PC pilote."
                  : "";
            return (
              <div
                key={device.id}
                className={cn(
                  "shrink-0 overflow-hidden rounded-[14px] border bg-card",
                  open ? "border-primary/40" : "border-border",
                )}
              >
                <button
                  type="button"
                  aria-expanded={open}
                  onClick={() => toggleDevice(device.id)}
                  className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left text-foreground"
                >
                  <span
                    className={cn(
                      "grid h-[34px] w-[34px] shrink-0 place-items-center rounded-[10px]",
                      ok ? "bg-primary/10 text-primary" : SOFT[device.statusTone],
                    )}
                  >
                    {faulty ? <WifiOff className="h-[17px] w-[17px]" /> : <Router className="h-[17px] w-[17px]" />}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13.5px] font-bold">{device.name}</span>
                    <span className="block truncate text-[11.5px] text-muted-foreground">
                      {[address || "adresse absente", PROTOCOL_LABEL[device.protocol], plural(device.doorPresets.length, "preset")].join(" · ")}
                    </span>
                  </span>
                  <Chip size="sm" tone={device.statusTone} className="h-[22px] px-[7px] text-[11.5px]">
                    {device.statusLabel}
                  </Chip>
                  <ChevronDown
                    className={cn("h-[15px] w-[15px] shrink-0 text-muted-foreground transition-transform", open && "rotate-180")}
                  />
                </button>

                {open && (
                  <div className="px-3 pb-3">
                    <div className="grid grid-cols-2 gap-1.5">
                      <Fact label="Adresse" value={address || "—"} mono />
                      <Fact label="Matériel" value={hardware || "—"} />
                      <Fact label="Mode" value={device.accessDataMode} />
                      <Fact
                        label="Portes autorisées"
                        value={device.doorIds.length > 0 ? device.doorIds.join(", ") : "Règle par défaut"}
                      />
                    </div>

                    {device.lastError && (
                      <div className="mt-2 rounded-[9px] bg-error/12 px-2.5 py-2 text-[12px] leading-[1.45] text-error-ink">
                        <strong>Dernière erreur :</strong> <span className="break-all font-mono">{device.lastError}</span>
                      </div>
                    )}

                    <div className="mt-2.5 text-[11px] font-bold uppercase tracking-[0.05em] text-muted-foreground">
                      Portes · presets du tableau de bord
                    </div>
                    {device.doorPresets.map((preset) => {
                      const actionKey = `preset:${device.id}:${preset.doorNumber}:${preset.pulseSeconds}`;
                      const presetLabel = preset.doorName || `Porte ${preset.doorNumber}`;
                      const busy = busyKey === actionKey;
                      return (
                        <div
                          key={`${device.id}-${preset.id}-${preset.doorNumber}-${preset.pulseSeconds}`}
                          className="mt-1.5 flex items-center gap-2 rounded-[10px] border border-border py-[7px] pl-2.5 pr-2"
                        >
                          <span className="min-w-0 flex-1">
                            <span className="flex items-center gap-1.5 text-[13px] font-semibold">
                              <span className="truncate">{presetLabel}</span>
                              {preset.favorite && (
                                <Star className="h-3 w-3 shrink-0 fill-current text-warning-ink" aria-label="Favori" role="img" />
                              )}
                            </span>
                            <span className="block text-[11.5px] text-muted-foreground">
                              Porte {preset.doorNumber} · impulsion {preset.pulseSeconds} s
                            </span>
                          </span>
                          <ActionButton
                            kind={device.canOpenDoor ? "primary" : "ghost"}
                            size="sm"
                            icon={LockOpen}
                            className={cn(!device.canOpenDoor && "bg-muted text-muted-foreground", busy && "[&_svg]:animate-pulse")}
                            onClick={() => void handleOpenPreset(device, preset)}
                            disabled={busy || !device.canOpenDoor}
                            title={!device.canOpenDoor
                              ? "Commande d’ouverture non activée pour cet appareil"
                              : readerNote ? "Envoie une demande au PC pilote" : "Ouvrir maintenant"}
                          >
                            Ouvrir
                          </ActionButton>
                        </div>
                      );
                    })}
                    {note && (
                      <div className="mt-2 flex items-start gap-1.5 text-[11.5px] leading-[1.45] text-muted-foreground">
                        <Info className="mt-px h-3.5 w-3.5 shrink-0" />
                        <span>{note}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0 rounded-[9px] bg-muted px-[9px] py-[7px]">
      <div className="text-[10.5px] font-bold uppercase tracking-[0.05em] text-muted-foreground">{label}</div>
      <div className={cn("truncate text-[12.5px] font-semibold", mono && "font-mono")} title={value}>{value}</div>
    </div>
  );
}
