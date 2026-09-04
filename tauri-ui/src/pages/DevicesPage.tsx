import { useState, useCallback, useMemo } from "react";
import { useDevices, usePullSdk, usePopupStream } from "@/api/hooks";
import { useApp } from "@/context/AppContext";
import { usePageChrome } from "@/context/PageChromeContext";
import { get, post } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import {
  RefreshCw, Router, Wifi, WifiOff, DoorOpen, Info, LockOpen, Loader2, AlertCircle,
  SlidersHorizontal, Clock, CheckCircle2, XCircle, Monitor, Bug, ListChecks,
} from "lucide-react";

interface DoorPreset { id: number; deviceId: number; doorNumber: number; pulseSeconds: number; doorName: string; }
interface DeviceContentState {
  tableName: string | null;
  rows: Record<string, unknown>[];
  count: number;
  loading: boolean;
  error: string | null;
}

interface VerifyState {
  status: "idle" | "saving" | "ok" | "err";
  rfid?: boolean;
  qr?: boolean;
  backendSaved?: boolean;
  driftSec?: number | null;
  error?: string;
}
interface ControlState {
  deviceId: number;
  deviceName: string;
  loading: boolean;
  loadError: string | null;
  mode: string;
  doors: { doorNumber: number; intertimeSec: number }[];
  driftSec: number | null;
  /** false when the device family exposes no Door{N}Intertime parameter
   *  (zkemkeeper standalone terminals). The value was NOT read, so it must not
   *  be rendered as a setting -- an unread value is not "off". */
  supportsDeviceParams: boolean;
  reentryEnabled: boolean;
  reentrySeconds: string;
  reentry: VerifyState;
  clock: VerifyState;
  // MIRROR pushing-policy review (only meaningful when policy === "MIRROR")
  policy: string;
  mirror: {
    armed: boolean;
    count: number | null;
    sample: string[];
    at: string | null;
    status: "idle" | "saving";
    error?: string;
  };
  errorPopup: { title: string; text: string } | null;
}

const CONTENT_TABLES = [
  { key: "user", label: "Utilisateurs" },
  { key: "userauthorize", label: "Autorisations" },
  { key: "templatev10", label: "Empreintes" },
  { key: "transaction", label: "Transactions" },
] as const;

// ── Row state ──────────────────────────────────────────────────────────────
// IMPORTANT: /sync/cache/devices returns the backend-declared device roster —
// configuration only. There is NO reachability/lastSeen field anywhere in
// _coerce_device_row_to_payload, so this page cannot say whether a device is
// "en ligne". The only liveness signal available is `isConnected()`, which is
// THIS app's own PullSDK session, not device health — hence "Connecté" /
// "Non connecté" rather than "En ligne" / "Hors ligne".
type DeviceState = "connected" | "idle" | "noaddress" | "inactive";

function deviceStateOf(d: any, connected: boolean): DeviceState {
  if (d.active === false) return "inactive";
  const ip = String(d.ip ?? d.ipAddress ?? "").trim();
  if (!ip) return "noaddress";
  return connected ? "connected" : "idle";
}

const STATE_LABEL: Record<DeviceState, string> = {
  connected: "Connecté",
  idle: "Non connecté",
  noaddress: "Adresse absente",
  inactive: "Inactif",
};

/** Design's `.ch` chip. */
function Chip({ tone, children }: { tone: "ok" | "no" | "wn" | "flat"; children: React.ReactNode }) {
  const tones = {
    ok: "bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400",
    no: "bg-primary/[0.09] text-primary",
    wn: "bg-amber-500/[0.14] text-amber-700 dark:text-amber-400",
    flat: "bg-muted text-muted-foreground",
  } as const;
  return (
    <span className={cn("inline-flex h-[22px] shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-2 text-[11px] font-bold", tones[tone])}>
      {children}
    </span>
  );
}

// Protocol family the device speaks. Mirrors app/sdk/device_driver.resolve_device_protocol:
// anything absent or unrecognised resolves to ZK_PULLSDK (the backend column defaults to
// it), so a missing field can never route a working PullSDK panel away from its path.
const STANDALONE_ALIASES = new Set([
  "ZK_STANDALONE", "STANDALONE", "ZKEMKEEPER", "ZKEM", "PUSH", "ADMS", "MB2000",
]);
type DeviceProtocol = "ZK_PULLSDK" | "ZK_STANDALONE";
function protocolOf(d: any): DeviceProtocol {
  const raw = String(d?.deviceProtocol ?? d?.device_protocol ?? "").trim().toUpperCase();
  return STANDALONE_ALIASES.has(raw) ? "ZK_STANDALONE" : "ZK_PULLSDK";
}
const PROTOCOL_LABEL: Record<DeviceProtocol, string> = {
  ZK_PULLSDK: "PullSDK",
  ZK_STANDALONE: "ZKTeco autonome",
};

const STATE_TONE: Record<DeviceState, "ok" | "no" | "wn" | "flat"> = {
  connected: "ok", idle: "flat", noaddress: "wn", inactive: "flat",
};

/** Design's mode badge — ULTRA is the violet one. */
function ModeBadge({ mode }: { mode: string }) {
  const m = (mode || "").toUpperCase();
  const style =
    m === "AGENT" ? "bg-primary text-primary-foreground"
    : m === "ULTRA" ? "bg-violet-700 text-white"
    : "bg-muted text-muted-foreground";
  return (
    <span className={cn("inline-flex h-[18px] items-center rounded-lg px-2 text-[9.5px] font-bold tracking-[0.04em]", style)}>
      {m || "—"}
    </span>
  );
}

const GRID = "grid grid-cols-[1.7fr_1.1fr_0.8fr_1.5fr] gap-3.5 items-center";

function Lb({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("text-[10px] font-bold uppercase tracking-[0.18em] text-muted-foreground", className)}>{children}</span>;
}

export default function DevicesPage() {
  const { data, loading, error, reload } = useDevices(false);
  const pullsdk = usePullSdk();
  const { status, syncNow } = useApp();
  const { openPopupWindow, sendTestNotification } = usePopupStream();

  const [connectedIds, setConnectedIds] = useState<Set<number>>(new Set());
  const [toast, setToast] = useState<string | null>(null);

  // Door open dialog (manual)
  const [doorDialog, setDoorDialog] = useState<{ deviceId: number; deviceName: string } | null>(null);
  const [doorNum, setDoorNum] = useState("1");
  const [pulseSec, setPulseSec] = useState("3");

  // Info dialog
  const [infoDialog, setInfoDialog] = useState<{
    deviceId: number; cached: Record<string, unknown>; live: any | null;
    liveError: string | null; liveLoading: boolean; presets: DoorPreset[]; presetsLoading: boolean;
    content: DeviceContentState;
  } | null>(null);

  // Control panel (re-entry block + clock). One scan-modify-apply object per device.
  const [control, setControl] = useState<ControlState | null>(null);

  const devices = data?.devices ?? [];

  const handleConnect = useCallback(async (deviceId: number) => {
    try { await pullsdk.connect(deviceId); setConnectedIds((p) => new Set(p).add(deviceId)); setToast(`Appareil ${deviceId} connecté`); }
    catch (e) { setToast(`Connexion échouée: ${e}`); }
  }, [pullsdk]);

  const handleDisconnect = useCallback(async (deviceId: number) => {
    try { await pullsdk.disconnect(deviceId); setConnectedIds((p) => { const s = new Set(p); s.delete(deviceId); return s; }); setToast(`Appareil ${deviceId} déconnecté`); }
    catch (e) { setToast(`Déconnexion échouée: ${e}`); }
  }, [pullsdk]);

  // ── Control panel: scan the device, then modify + apply (verified) ──
  const openControl = useCallback(async (deviceId: number, deviceName: string) => {
    setControl({
      deviceId, deviceName, loading: true, loadError: null, mode: "",
      doors: [], driftSec: null, supportsDeviceParams: true,
      reentryEnabled: false, reentrySeconds: "30",
      reentry: { status: "idle" }, clock: { status: "idle" },
      policy: "", mirror: { armed: false, count: null, sample: [], at: null, status: "idle" },
      errorPopup: null,
    });
    try {
      const s = await pullsdk.getSettings(deviceId);
      const doors = s.doors || [];
      const maxInt = doors.reduce((m: number, d: any) => Math.max(m, Number(d.intertimeSec) || 0), 0);
      setControl((p) => p && p.deviceId === deviceId ? {
        ...p, loading: false, mode: String(s.mode || ""),
        doors, driftSec: s.clock?.driftSec ?? null,
        supportsDeviceParams: (s as any).supportsDeviceParams !== false,
        reentryEnabled: maxInt > 0,
        reentrySeconds: maxInt > 0 ? String(maxInt) : "30",
      } : p);
      // MIRROR review (best-effort; standalone devices only, ignored elsewhere)
      try {
        const m = await pullsdk.getMirrorPlan(deviceId);
        setControl((p) => p && p.deviceId === deviceId ? {
          ...p, policy: String(m.policy || "PRESERVE"),
          mirror: { armed: !!m.armed, count: m.lastPlanCount ?? null,
            sample: m.lastPlanSample || [], at: m.lastPlanAt ?? null, status: "idle" },
        } : p);
      } catch { /* endpoint absent / non-standalone — leave policy blank */ }
    } catch (e) {
      setControl((p) => p && p.deviceId === deviceId ? { ...p, loading: false, loadError: String(e) } : p);
    }
  }, [pullsdk]);

  const applyReentry = useCallback(async () => {
    if (!control) return;
    const { deviceId, reentryEnabled, reentrySeconds } = control;
    const seconds = parseInt(reentrySeconds) || 0;
    setControl((p) => p ? { ...p, reentry: { status: "saving" } } : p);
    try {
      const res = await pullsdk.setReentry(deviceId, reentryEnabled, seconds);
      const ok = !!res.rfid && (res.mode !== "ultra" || !!res.qr);
      // Distinguish the failure halves so the message isn't misleading: the
      // device (RFID) write can succeed while the PC-side QR cooldown fails.
      const errMsg = !res.rfid
        ? "L'appareil n'a pas confirmé la valeur écrite."
        : (res.mode === "ultra" && !res.qr)
          ? "Appareil OK, mais le délai logiciel (QR) n'a pas pu être appliqué."
          : (res.backendError || "Échec partiel.");
      setControl((p) => p && p.deviceId === deviceId ? {
        ...p,
        doors: res.readBack?.doors || p.doors,
        // Reconcile the seconds field with the value actually written (server
        // clamps to 5-255), so the input matches the confirmed device value.
        reentrySeconds: (reentryEnabled && res.effectiveSec && res.effectiveSec > 0)
          ? String(res.effectiveSec) : p.reentrySeconds,
        reentry: {
          status: ok ? "ok" : "err",
          rfid: !!res.rfid, qr: !!res.qr, backendSaved: !!res.backendSaved,
          error: ok ? (res.backendSaved ? "" : (res.backendError || "Enregistrement backend échoué.")) : errMsg,
        },
      } : p);
    } catch (e) {
      setControl((p) => p && p.deviceId === deviceId ? { ...p, reentry: { status: "err", error: String(e) } } : p);
    }
  }, [control, pullsdk]);

  const syncClock = useCallback(async () => {
    if (!control) return;
    const { deviceId } = control;
    setControl((p) => p ? { ...p, clock: { status: "saving" } } : p);
    try {
      const res = await pullsdk.syncClock(deviceId);
      setControl((p) => p && p.deviceId === deviceId ? {
        ...p, driftSec: res.driftSec ?? p.driftSec,
        clock: { status: "ok", driftSec: res.driftSec ?? null },
      } : p);
    } catch (e) {
      setControl((p) => p && p.deviceId === deviceId ? { ...p, clock: { status: "err", error: String(e) } } : p);
    }
  }, [control, pullsdk]);

  // Arm / disarm the destructive MIRROR reconcile (after reviewing the dry-run plan).
  const setMirrorArmed = useCallback(async (arm: boolean) => {
    if (!control) return;
    const { deviceId } = control;
    setControl((p) => p ? { ...p, mirror: { ...p.mirror, status: "saving", error: undefined } } : p);
    try {
      const res = arm ? await pullsdk.armMirror(deviceId) : await pullsdk.disarmMirror(deviceId);
      setControl((p) => p && p.deviceId === deviceId ? {
        ...p, mirror: { armed: !!res.armed, count: res.lastPlanCount ?? p.mirror.count,
          sample: res.lastPlanSample || p.mirror.sample, at: res.lastPlanAt ?? p.mirror.at,
          status: "idle" },
      } : p);
      setToast(arm ? "MIRROR armé — les suppressions sont activées" : "MIRROR désarmé (mode simulation)");
    } catch (e) {
      setControl((p) => p && p.deviceId === deviceId ? { ...p, mirror: { ...p.mirror, status: "idle", error: String(e) } } : p);
    }
  }, [control, pullsdk]);

  const showControlError = useCallback((title: string, text: string) => {
    setControl((p) => p ? { ...p, errorPopup: { title, text } } : p);
  }, []);

  const handleDoorOpen = useCallback(async () => {
    if (!doorDialog) return;
    try { await pullsdk.doorOpen(doorDialog.deviceId, parseInt(doorNum) || 1, parseInt(pulseSec) || 3); setToast("Porte ouverte !"); setDoorDialog(null); }
    catch (e) { setToast(`Ouverture échouée: ${e}`); }
  }, [doorDialog, doorNum, pulseSec, pullsdk]);

  const handlePresetDoorOpen = useCallback(async (deviceId: number, doorNumber: number, pulseSeconds: number) => {
    try { await post(`/devices/${deviceId}/door/open`, { doorNumber, pulseSeconds }); setToast(`Porte ${doorNumber} ouverte (${pulseSeconds}s)`); }
    catch (e) { setToast(`Ouverture échouée: ${e}`); }
  }, []);

  const loadPresets = useCallback(async (deviceId: number) => {
    try { const res = await get<{ presets: DoorPreset[] }>(`/devices/${deviceId}/door-presets`); setInfoDialog((p) => p ? { ...p, presets: res.presets || [], presetsLoading: false } : p); }
    catch { setInfoDialog((p) => p ? { ...p, presets: [], presetsLoading: false } : p); }
  }, []);

  const handleInfo = useCallback((deviceId: number) => {
    const cachedDev = devices.find((d: any) => (d.id ?? d.deviceId) === deviceId) || {};
    setInfoDialog({
      deviceId,
      cached: cachedDev as Record<string, unknown>,
      live: null,
      liveError: null,
      liveLoading: false,
      presets: [],
      presetsLoading: true,
      content: {
        tableName: null,
        rows: [],
        count: 0,
        loading: false,
        error: null,
      },
    });
    loadPresets(deviceId);
  }, [devices, loadPresets]);

  const handleFetchLiveInfo = useCallback(async () => {
    if (!infoDialog) return;
    setInfoDialog((p) => p ? { ...p, liveLoading: true, liveError: null, live: null } : p);
    try { const info = await pullsdk.getInfo(infoDialog.deviceId); setInfoDialog((p) => p ? { ...p, live: info, liveLoading: false } : p); }
    catch (e) { setInfoDialog((p) => p ? { ...p, liveError: String(e), liveLoading: false } : p); }
  }, [infoDialog, pullsdk]);

  const handleFetchContent = useCallback(async (tableName: string) => {
    if (!infoDialog) return;
    setInfoDialog((p) => p ? {
      ...p,
      content: { ...p.content, tableName, loading: true, error: null, rows: [] },
    } : p);
    try {
      const res = await pullsdk.getTable(infoDialog.deviceId, tableName, { maxRows: "250" });
      setInfoDialog((p) => p ? {
        ...p,
        content: {
          tableName,
          rows: res.rows || [],
          count: res.count || 0,
          loading: false,
          error: null,
        },
      } : p);
    } catch (e) {
      setInfoDialog((p) => p ? {
        ...p,
        content: {
          ...p.content,
          tableName,
          rows: [],
          count: 0,
          loading: false,
          error: String(e),
        },
      } : p);
    }
  }, [infoDialog, pullsdk]);

  const isConnected = (d: any) => {
    const did = d.id ?? d.deviceId;
    if (did && connectedIds.has(did)) return true;
    if (status?.pullsdk?.connected && status.pullsdk.deviceId === did) return true;
    // A ZK_STANDALONE terminal never enters the manual PullSDK session pool -- its
    // driver owns the COM connection and the ULTRA worker holds it. Without this a
    // perfectly healthy MB2000 was listed as "Non connecté". This reads the worker's
    // real `connected` flag; it does not assume a device is up.
    if (did != null && status?.ultra?.devices?.[String(did)]?.connected) return true;
    return false;
  };

  const HIDE_KEYS = new Set(["payload_json", "raw_payload"]);
  const contentColumns = infoDialog?.content.rows[0]
    ? Object.keys(infoDialog.content.rows[0]).filter((key) => !HIDE_KEYS.has(key)).slice(0, 8)
    : [];

  // Fleet composition — counted from the roster itself rather than status.mode,
  // which is a separate aggregate and can disagree with the list on screen.
  const parc = useMemo(() => {
    const byMode: Record<string, number> = { DEVICE: 0, AGENT: 0, ULTRA: 0 };
    let needsAttention = 0;
    const problems: { d: any; did: number; name: string; state: DeviceState }[] = [];
    for (const d of devices as any[]) {
      const m = String(d.accessDataMode ?? d.access_data_mode ?? "").toUpperCase();
      if (m in byMode) byMode[m] += 1;
      const did = d.id ?? d.deviceId;
      const st = deviceStateOf(d, isConnected(d));
      if (st === "noaddress" || st === "inactive") {
        needsAttention += 1;
        problems.push({ d, did, name: d.name || d.deviceName || `Appareil #${did}`, state: st });
      }
    }
    return { byMode, needsAttention, problems };
  }, [devices, connectedIds, status?.pullsdk?.connected, status?.pullsdk?.deviceId, status?.ultra]);

  const firstProblem = parc.problems[0] ?? null;

  usePageChrome(() => ({
    fill: true,
    subtitle: `${devices.length} appareil${devices.length > 1 ? "s" : ""} déclaré${devices.length > 1 ? "s" : ""}`,
    actions: (
      <>
        <Button
          variant="outline"
          className="h-[30px] gap-1.5 rounded-[14px] px-[13px] text-[12px] font-semibold"
          onClick={reload}
          disabled={loading}
        >
          <RefreshCw className={cn("h-[15px] w-[15px]", loading && "animate-spin")} />
          Recharger
        </Button>
        <Button
          className="h-[34px] gap-[7px] rounded-full px-[18px] text-[12.5px] font-bold shadow-[0_8px_20px_rgba(226,32,63,0.22)]"
          onClick={() => { void syncNow(); }}
          disabled={status?.sync?.running}
        >
          <RefreshCw className={cn("h-4 w-4", status?.sync?.running && "animate-spin")} />
          {status?.sync?.running ? "En cours…" : "Synchroniser"}
        </Button>
      </>
    ),
  }), [devices.length, loading, reload, syncNow, status?.sync?.running]);

  return (
    <div className="flex h-full min-h-0 gap-4">
      {/* ── Le sujet : le parc, pleine hauteur ──────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col gap-[11px]">
        <div className="flex flex-none items-center gap-[9px]">
          <Router className="h-[17px] w-[17px] text-primary" />
          <span className="font-display text-[13px] font-extrabold tracking-[-0.01em] text-foreground">Le parc</span>
          <span className="ml-1 text-[12px] text-muted-foreground">
            {devices.length} appareil{devices.length > 1 ? "s" : ""} déclaré{devices.length > 1 ? "s" : ""}
          </span>
        </div>

        {error && (
          <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{error}</AlertDescription></Alert>
        )}

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-3xl bg-card shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className={cn(GRID, "flex-none border-b border-border px-6 py-[11px]")}>
            <Lb>Appareil</Lb><Lb>Adresse</Lb><Lb>État</Lb><Lb className="text-right">Actions</Lb>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto">
            {devices.length === 0 && !loading && (
              <div className="flex h-full min-h-[240px] flex-col items-center justify-center gap-2 text-center">
                <Router className="h-8 w-8 text-muted-foreground/40" />
                <p className="text-[13px] font-semibold text-foreground">Aucun appareil trouvé</p>
                <p className="max-w-[340px] text-[11.5px] text-muted-foreground">
                  Lancez une synchronisation pour charger les appareils déclarés côté serveur.
                </p>
              </div>
            )}
            {loading && devices.length === 0 && (
              <div className="flex h-full min-h-[240px] items-center justify-center">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
              </div>
            )}

            {(devices as any[]).map((d, i) => {
              const did = d.id ?? d.deviceId ?? i;
              const name = d.name || d.deviceName || `Appareil #${did}`;
              const ip = String(d.ip ?? d.ipAddress ?? "").trim();
              const mode = String(d.accessDataMode ?? d.access_data_mode ?? "").toUpperCase();
              const conn = isConnected(d);
              const protocol = protocolOf(d);
              // Door availability comes from the DRIVER, never from the protocol:
              // a standalone terminal ships with the door command gated off, but it
              // can be enabled per machine once the relay is verified. undefined =
              // unknown -> keep the control live.
              const canOpenDoor = status?.ultra?.devices?.[String(did)]?.supports_open_door !== false;
              const state = deviceStateOf(d, conn);
              const faulty = state === "noaddress" || state === "inactive";
              return (
                <div
                  key={did}
                  className={cn(
                    GRID,
                    "border-b border-border/60 px-6 py-3.5 last:border-b-0",
                    faulty && "bg-primary/[0.035]",
                  )}
                >
                  <div className="flex min-w-0 items-center gap-[11px]">
                    <span className={cn(
                      "flex h-9 w-9 shrink-0 items-center justify-center rounded-[18px]",
                      state === "connected" ? "bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400"
                        : faulty ? "bg-primary/[0.09] text-primary"
                        : "bg-muted text-muted-foreground",
                    )}>
                      {faulty ? <WifiOff className="h-[19px] w-[19px]" /> : <Router className="h-[19px] w-[19px]" />}
                    </span>
                    <div className="min-w-0">
                      <div className="truncate text-[14px] font-bold text-foreground">{name}</div>
                      <div className="mt-0.5 flex items-center gap-1.5">
                        <ModeBadge mode={mode} />
                        <span className="truncate text-[11px] text-muted-foreground">
                          {d.zone || d.model || (d.deviceProtocol ? String(d.deviceProtocol) : "—")}
                        </span>
                      </div>
                    </div>
                  </div>

                  <span className="truncate font-mono text-[12px] text-muted-foreground">
                    {ip ? `${ip}:${d.portNumber ?? d.port ?? 4370}` : "adresse absente"}
                  </span>

                  <span><Chip tone={STATE_TONE[state]}>{STATE_LABEL[state]}</Chip></span>

                  <div className="flex items-center justify-end gap-1.5">
                    {state === "noaddress" || state === "inactive" ? (
                      <Button
                        variant="outline"
                        className="h-7 gap-1.5 rounded-[14px] px-3 text-[11.5px] font-semibold"
                        onClick={() => handleInfo(did)}
                      >
                        <Info className="h-3.5 w-3.5" />Détails
                      </Button>
                    ) : (
                      <>
                        {canOpenDoor ? (
                          <Button
                            variant="outline"
                            className="h-7 gap-1.5 rounded-[14px] px-3 text-[11.5px] font-semibold"
                            onClick={() => setDoorDialog({ deviceId: did, deviceName: name })}
                          >
                            <DoorOpen className="h-3.5 w-3.5" />Porte
                          </Button>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span tabIndex={0}>
                                <Button
                                  variant="outline" disabled
                                  className="h-7 gap-1.5 rounded-[14px] px-3 text-[11.5px] font-semibold"
                                >
                                  <DoorOpen className="h-3.5 w-3.5" />Porte
                                </Button>
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Commande d'ouverture non activée pour ce modèle (à valider sur le matériel).
                            </TooltipContent>
                          </Tooltip>
                        )}
                        <Button
                          variant="outline"
                          className="h-7 gap-1.5 rounded-[14px] px-3 text-[11.5px] font-semibold"
                          onClick={() => openControl(did, name)}
                        >
                          <SlidersHorizontal className="h-3.5 w-3.5" />Contrôle
                        </Button>
                        {/* Manual connect exists only for PullSDK panels. A ZK_STANDALONE
                            terminal is driven by its own COM event sink, which the live
                            worker already owns -- offering "Connect" here would open a
                            second session and could only ever fail. Show the protocol
                            instead of a button that cannot work. */}
                        {protocol === "ZK_PULLSDK" ? (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="outline"
                                size="icon"
                                className="h-7 w-7 shrink-0 rounded-[14px]"
                                onClick={() => (conn ? handleDisconnect(did) : handleConnect(did))}
                              >
                                {conn ? <WifiOff className="h-3.5 w-3.5" /> : <Wifi className="h-3.5 w-3.5" />}
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                              {conn ? `Déconnecter (${PROTOCOL_LABEL[protocol]})` : `Connecter (${PROTOCOL_LABEL[protocol]})`}
                            </TooltipContent>
                          </Tooltip>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span><Chip tone="flat">{PROTOCOL_LABEL[protocol]}</Chip></span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Connexion gérée en continu par le service — pas de session manuelle.
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </>
                    )}
                    <Button
                      variant="outline"
                      size="icon"
                      className="h-7 w-7 shrink-0 rounded-[14px]"
                      onClick={() => handleInfo(did)}
                    >
                      <Info className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Le rail ─────────────────────────────────────────────────────── */}
      <div className="flex w-[330px] flex-none flex-col gap-[11px]">
        <div className="flex flex-none items-center gap-[9px]">
          <span className={cn(
            "inline-flex h-[22px] items-center gap-1.5 rounded-lg px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em]",
            firstProblem ? "bg-primary/[0.08] text-primary" : "bg-muted text-muted-foreground",
          )}>
            <ListChecks className="h-3 w-3" />À traiter
          </span>
        </div>

        {firstProblem ? (
          <div className="flex-none rounded-3xl border-[1.5px] border-primary/30 bg-card px-[22px] py-5 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
            <div className="mb-3.5 flex items-center gap-[13px]">
              <span className="flex h-[46px] w-[46px] shrink-0 items-center justify-center rounded-[18px] bg-primary/[0.09] text-primary">
                <WifiOff className="h-[23px] w-[23px]" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="truncate font-display text-[16px] font-extrabold leading-[1.2] tracking-[-0.02em] text-foreground">
                  {firstProblem.name}
                </div>
                <div className="mt-1 text-[11.5px] text-muted-foreground">
                  {firstProblem.state === "noaddress" ? "aucune adresse IP déclarée" : "désactivé côté serveur"}
                </div>
              </div>
            </div>
            <p className="mb-3.5 text-[12px] leading-[1.55] text-muted-foreground">
              {firstProblem.state === "noaddress"
                ? "Cet appareil est déclaré mais n'a pas d'adresse réseau, donc l'application ne peut pas le joindre. Renseignez son adresse IP côté serveur, puis synchronisez."
                : "Cet appareil est marqué inactif côté serveur : il est ignoré par la synchronisation et par le moteur d'accès. Réactivez-le côté serveur, puis synchronisez."}
            </p>
            <Button
              className="h-[34px] w-full justify-center gap-[7px] rounded-full text-[12.5px] font-bold shadow-[0_8px_20px_rgba(226,32,63,0.22)]"
              onClick={() => handleInfo(firstProblem.did)}
            >
              <Info className="h-4 w-4" />Voir la fiche
            </Button>
            {parc.needsAttention > 1 && (
              <p className="mt-2.5 text-center text-[11px] text-muted-foreground">
                +{parc.needsAttention - 1} autre{parc.needsAttention - 1 > 1 ? "s" : ""} appareil{parc.needsAttention - 1 > 1 ? "s" : ""} à vérifier
              </p>
            )}
          </div>
        ) : (
          <div className="flex-none rounded-3xl bg-card px-[22px] py-5 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
            <div className="flex items-center gap-[13px]">
              <span className="flex h-[46px] w-[46px] shrink-0 items-center justify-center rounded-[18px] bg-emerald-500/[0.055] text-emerald-700 dark:text-emerald-400">
                <CheckCircle2 className="h-[23px] w-[23px]" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="font-display text-[16px] font-extrabold leading-[1.2] tracking-[-0.02em] text-foreground">
                  Rien à traiter
                </div>
                <div className="mt-1 text-[11.5px] text-muted-foreground">
                  Tous les appareils déclarés ont une adresse et sont actifs.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Composition — every number below is counted from the roster on screen. */}
        <div className="mt-[3px] flex flex-none items-center gap-[9px]">
          <span className="inline-flex h-[22px] items-center gap-1.5 rounded-lg bg-muted px-[9px] text-[10.5px] font-bold uppercase tracking-[0.05em] text-muted-foreground">
            <Router className="h-3 w-3" />Composition
          </span>
        </div>
        <div className="flex min-h-0 flex-1 flex-col gap-[11px] rounded-[18px] bg-card px-5 py-4 shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="mb-0.5 flex items-baseline gap-2.5">
            <span className="num text-[30px] leading-none">{devices.length}</span>
            <span className="text-[13px] text-muted-foreground">
              appareil{devices.length > 1 ? "s" : ""} déclaré{devices.length > 1 ? "s" : ""}
            </span>
          </div>
          <div className="h-px bg-border" />
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Appareil direct (DEVICE)</span>
            <span className="text-[12.5px] font-bold text-foreground">{parc.byMode.DEVICE}</span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Agent</span>
            <span className="text-[12.5px] font-bold text-foreground">{parc.byMode.AGENT}</span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Ultra</span>
            <span className="text-[12.5px] font-bold text-foreground">{parc.byMode.ULTRA}</span>
          </div>
          <div className="h-px bg-border" />
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Lecteur PullSDK</span>
            <span className="font-mono text-[12px] text-foreground">
              {status?.pullsdk?.connected
                ? `#${status.pullsdk.deviceId ?? "—"}`
                : "non connecté"}
            </span>
          </div>
          <div className="flex items-center justify-between gap-2.5">
            <span className="text-[12px] text-muted-foreground">Session PullSDK ouverte</span>
            <span className="text-[12.5px] font-bold text-foreground">{connectedIds.size}</span>
          </div>
          {parc.needsAttention > 0 && (
            <div className="flex items-center justify-between gap-2.5">
              <span className="text-[12px] text-muted-foreground">À vérifier</span>
              <span className="text-[12.5px] font-bold text-primary">{parc.needsAttention}</span>
            </div>
          )}
          <p className="mt-auto pt-2 text-[10.5px] leading-[1.5] text-muted-foreground">
            L'état reflète la connexion réelle de cette application&nbsp;: session PullSDK pour les
            centrales, connexion du service temps réel pour les terminaux autonomes. Le serveur ne
            publie pas d'indicateur d'accessibilité par appareil.
          </p>
        </div>

        {/* Action tile — same tile as the dashboard's, real handlers. */}
        <div className="flex-none rounded-[18px] bg-card px-5 py-[15px] shadow-[0_8px_20px_rgba(0,0,0,0.08)]">
          <div className="mb-3 flex items-center gap-2.5">
            <Monitor className="h-[18px] w-[18px] shrink-0 text-primary" />
            <div className="min-w-0 flex-1">
              <div className="text-[12.5px] font-bold text-foreground">Écran d'entrée</div>
              <div className="truncate text-[10.5px] text-muted-foreground">Affiche les accès en temps réel</div>
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              className="h-8 flex-1 gap-1.5 rounded-[14px] text-[12px] font-semibold"
              onClick={openPopupWindow}
            >
              <Monitor className="h-[15px] w-[15px]" />Ouvrir
            </Button>
            <Button
              variant="outline"
              className="h-8 flex-1 gap-1.5 rounded-[14px] text-[12px] font-semibold"
              onClick={sendTestNotification}
            >
              <Bug className="h-[15px] w-[15px]" />Tester
            </Button>
          </div>
        </div>
      </div>

      {/* Manual Door Open Dialog */}
      <Dialog open={!!doorDialog} onOpenChange={(open: boolean) => { if (!open) setDoorDialog(null); }}>
        <DialogContent className="rounded-3xlmax-w-xs">
          <DialogHeader>
            <DialogTitle className="font-display text-[18px] font-extrabold tracking-[-0.02em]">Ouvrir la porte — {doorDialog?.deviceName}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label>Numéro de porte</Label>
              <Input type="number" value={doorNum} onChange={(e) => setDoorNum(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>Durée impulsion (sec)</Label>
              <Input type="number" value={pulseSec} onChange={(e) => setPulseSec(e.target.value)} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDoorDialog(null)}>Annuler</Button>
            <Button onClick={handleDoorOpen}>Ouvrir</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Info Dialog */}
      <Dialog open={!!infoDialog} onOpenChange={(open: boolean) => { if (!open) setInfoDialog(null); }}>
        <DialogContent className="rounded-3xlmax-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle className="font-display text-[18px] font-extrabold tracking-[-0.02em]">Info Appareil #{infoDialog?.deviceId}</DialogTitle>
          </DialogHeader>
          <Tabs defaultValue="cached" className="flex-1 overflow-hidden flex flex-col">
            <TabsList className="w-full justify-start">
              <TabsTrigger value="cached">Cache</TabsTrigger>
              <TabsTrigger value="presets">Presets portes</TabsTrigger>
              <TabsTrigger value="content">Contenu</TabsTrigger>
              <TabsTrigger value="live">Live (PullSDK)</TabsTrigger>
            </TabsList>
            <TabsContent value="cached" className="flex-1 overflow-auto">
              {infoDialog?.cached && Object.keys(infoDialog.cached).length > 0 ? (
                <Table>
                  <TableHeader><TableRow><TableHead>Clé</TableHead><TableHead>Valeur</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {Object.entries(infoDialog.cached).filter(([k]) => !HIDE_KEYS.has(k)).filter(([, v]) => v != null && v !== "").map(([k, v]) => (
                      <TableRow key={k}><TableCell className="font-mono text-xs">{k}</TableCell><TableCell className="text-xs max-w-[300px] truncate">{typeof v === "object" ? JSON.stringify(v) : String(v)}</TableCell></TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : <p className="text-sm text-muted-foreground py-4 text-center">Aucune donnée en cache.</p>}
            </TabsContent>
            <TabsContent value="presets" className="flex-1 overflow-auto">
              {infoDialog?.presetsLoading ? <Loader2 className="h-6 w-6 animate-spin mx-auto my-4" /> : (
                (infoDialog?.presets?.length ?? 0) > 0 ? (
                  <div className="space-y-2">
                    {infoDialog!.presets.map((p) => (
                      <div key={p.id} className="flex items-center justify-between p-3 rounded-md border">
                        <div className="flex items-center gap-2">
                          <DoorOpen className="h-4 w-4 text-primary" />
                          <span className="font-medium text-sm">{p.doorName || `Porte ${p.doorNumber}`}</span>
                          <Badge variant="outline" className="text-xs">#{p.doorNumber}</Badge>
                          <Badge variant="secondary" className="text-xs">{p.pulseSeconds}s</Badge>
                        </div>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button size="icon" variant="ghost" className="h-8 w-8 text-emerald-500" onClick={() => handlePresetDoorOpen(infoDialog!.deviceId, p.doorNumber, p.pulseSeconds)}>
                              <LockOpen className="h-4 w-4" />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Ouvrir porte {p.doorNumber} ({p.pulseSeconds}s)</TooltipContent>
                        </Tooltip>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Alert variant="info"><AlertDescription>Aucun preset de porte configuré pour cet appareil.</AlertDescription></Alert>
                )
              )}
            </TabsContent>
            <TabsContent value="content" className="flex-1 overflow-auto space-y-3">
              <Alert variant="info">
                <AlertDescription>
                  Lit directement les tables PullSDK de l&apos;appareil. Utilisez ce panneau pour inspecter les utilisateurs, autorisations, empreintes et transactions en live.
                </AlertDescription>
              </Alert>
              <div className="flex flex-wrap gap-2">
                {CONTENT_TABLES.map((table) => (
                  <Button
                    key={table.key}
                    size="sm"
                    variant={infoDialog?.content.tableName === table.key ? "default" : "outline"}
                    onClick={() => void handleFetchContent(table.key)}
                    disabled={!!infoDialog?.content.loading}
                  >
                    {table.label}
                  </Button>
                ))}
              </div>
              {infoDialog?.content.loading && (
                <div className="py-6 flex justify-center">
                  <Loader2 className="h-6 w-6 animate-spin text-primary" />
                </div>
              )}
              {infoDialog?.content.error && (
                <Alert variant="destructive">
                  <AlertDescription>{infoDialog.content.error}</AlertDescription>
                </Alert>
              )}
              {!infoDialog?.content.loading && !infoDialog?.content.error && !infoDialog?.content.tableName && (
                <p className="text-sm text-muted-foreground text-center py-8">
                  Choisissez une table pour lancer la lecture live.
                </p>
              )}
              {!!infoDialog?.content.tableName && !infoDialog?.content.loading && !infoDialog?.content.error && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {infoDialog.content.tableName}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {infoDialog.content.count} ligne(s) renvoyée(s)
                    </span>
                  </div>
                  <div className="rounded-md border overflow-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          {contentColumns.map((column) => (
                            <TableHead key={column} className="whitespace-nowrap">{column}</TableHead>
                          ))}
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {infoDialog.content.rows.length > 0 && contentColumns.length > 0 ? infoDialog.content.rows.map((row, index) => (
                          <TableRow key={`${infoDialog.content.tableName}-${index}`}>
                            {contentColumns.map((column) => (
                              <TableCell key={column} className="text-xs max-w-[240px] truncate">
                                {typeof row[column] === "object" ? JSON.stringify(row[column]) : String(row[column] ?? "")}
                              </TableCell>
                            ))}
                          </TableRow>
                        )) : (
                          <TableRow>
                            <TableCell colSpan={Math.max(contentColumns.length, 1)} className="text-center py-8 text-sm text-muted-foreground">
                              Aucune ligne disponible pour cette table.
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              )}
            </TabsContent>
            <TabsContent value="live" className="flex-1 overflow-auto space-y-3">
              <Alert variant="info"><AlertDescription>Récupère les informations en direct via PullSDK (connexion TCP). Peut échouer si l'appareil n'est pas joignable.</AlertDescription></Alert>
              <Button size="sm" onClick={handleFetchLiveInfo} disabled={!!infoDialog?.liveLoading}>
                {infoDialog?.liveLoading ? <><Loader2 className="h-4 w-4 animate-spin" /> Connexion…</> : <><Wifi className="h-4 w-4" /> Récupérer info live</>}
              </Button>
              {infoDialog?.liveError && (
                <Alert variant="destructive"><AlertDescription>{infoDialog.liveError}</AlertDescription></Alert>
              )}
              {infoDialog?.live && (
                <>
                  {infoDialog.live.params && Object.keys(infoDialog.live.params).length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold mb-2">Paramètres</h4>
                      <Table><TableHeader><TableRow><TableHead>Clé</TableHead><TableHead>Valeur</TableHead></TableRow></TableHeader>
                        <TableBody>{Object.entries(infoDialog.live.params).map(([k, v]) => (<TableRow key={k}><TableCell className="font-mono text-xs">{k}</TableCell><TableCell className="text-xs">{String(v)}</TableCell></TableRow>))}</TableBody>
                      </Table>
                    </div>
                  )}
                </>
              )}
            </TabsContent>
          </Tabs>
        </DialogContent>
      </Dialog>

      {/* Control panel: re-entry block + clock */}
      <Dialog open={!!control} onOpenChange={(open: boolean) => { if (!open) setControl(null); }}>
        <DialogContent className="rounded-3xlmax-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-display text-[18px] font-extrabold tracking-[-0.02em]"><SlidersHorizontal className="h-4 w-4" /> Contrôle — {control?.deviceName}</DialogTitle>
          </DialogHeader>
          {control?.loading ? (
            <div className="py-10 flex justify-center"><Loader2 className="h-6 w-6 animate-spin text-primary" /></div>
          ) : control?.loadError ? (
            <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{control.loadError}</AlertDescription></Alert>
          ) : control ? (
            <div className="space-y-5">
              {/* Re-entry block. On a family with no Door{N}Intertime parameter the
                  value was never read, so we say so rather than showing a switch
                  that would read as "re-entry is off on this terminal". */}
              <div className="space-y-2.5">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium">Blocage de ré-entrée</p>
                    <p className="text-xs text-muted-foreground">Même carte/QR refusée pendant le délai · RFID (appareil) + QR (logiciel)</p>
                  </div>
                  {control.supportsDeviceParams ? (
                    <div className="flex items-center gap-2 shrink-0">
                      <Switch checked={control.reentryEnabled} onCheckedChange={(v: boolean) => setControl((p) => p ? { ...p, reentryEnabled: v } : p)} />
                      <Input type="number" min={5} max={255} className="w-16" value={control.reentrySeconds} disabled={!control.reentryEnabled}
                        onChange={(e) => setControl((p) => p ? { ...p, reentrySeconds: e.target.value } : p)} />
                      <span className="text-xs text-muted-foreground">sec</span>
                    </div>
                  ) : null}
                </div>
                {!control.supportsDeviceParams ? (
                  <Alert><AlertCircle className="h-4 w-4" /><AlertDescription className="text-xs">
                    Ce modèle (terminal autonome) n'expose pas de paramètre de ré-entrée côté
                    appareil&nbsp;: la valeur n'a pas pu être lue et ne peut pas être modifiée ici.
                  </AlertDescription></Alert>
                ) : null}
                <div className={cn("flex items-center gap-2 flex-wrap", !control.supportsDeviceParams && "hidden")}>
                  <Button size="sm" onClick={applyReentry} disabled={control.reentry.status === "saving"}>
                    {control.reentry.status === "saving" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null} Appliquer
                  </Button>
                  {control.reentry.status === "ok" && (
                    <>
                      <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-600"><CheckCircle2 className="h-3.5 w-3.5" /> Appliqué</span>
                      <Badge variant="secondary" className="text-xs">RFID {control.reentry.rfid ? "✓" : "✗"}</Badge>
                      {control.mode === "ultra" && <Badge variant="secondary" className="text-xs">QR {control.reentry.qr ? "✓" : "✗"}</Badge>}
                      <button type="button"
                        onClick={() => { if (!control.reentry.backendSaved) showControlError("Enregistrement backend", control.reentry.error || "Échec de l'enregistrement sur le serveur."); }}
                        className={cn("text-xs px-2 py-0.5 rounded border", control.reentry.backendSaved ? "text-emerald-600 border-emerald-600/30" : "text-amber-600 border-amber-600/40 cursor-pointer")}>
                        backend {control.reentry.backendSaved ? "✓" : "⚠"}
                      </button>
                    </>
                  )}
                  {control.reentry.status === "err" && (
                    <>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="inline-flex items-center gap-1 text-xs font-medium text-destructive"><XCircle className="h-3.5 w-3.5" /> Échec</span>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-xs">{(control.reentry.error || "Erreur").slice(0, 160)}</TooltipContent>
                      </Tooltip>
                      {/* Show which half succeeded when the device responded (split failure). */}
                      {control.reentry.rfid !== undefined && <Badge variant="secondary" className="text-xs">RFID {control.reentry.rfid ? "✓" : "✗"}</Badge>}
                      {control.reentry.rfid !== undefined && control.mode === "ultra" && <Badge variant="secondary" className="text-xs">QR {control.reentry.qr ? "✓" : "✗"}</Badge>}
                      <Button size="sm" variant="ghost" className="h-6 text-xs" onClick={() => showControlError("Erreur — blocage de ré-entrée", control.reentry.error || "")}>Voir l'erreur complète</Button>
                    </>
                  )}
                </div>
                {control.doors.length > 0 && (
                  <p className="text-[11px] text-muted-foreground font-mono">
                    {control.doors.map((d) => `Door${d.doorNumber}Intertime=${d.intertimeSec}`).join("  ·  ")}
                  </p>
                )}
              </div>

              <div className="border-t" />

              {/* Clock */}
              <div className="space-y-2.5">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium">Horloge de l'appareil</p>
                    <p className={cn("text-xs", control.driftSec != null && Math.abs(control.driftSec) > 10 ? "text-destructive" : "text-muted-foreground")}>
                      {control.driftSec == null ? "Dérive inconnue"
                        : Math.abs(control.driftSec) < 1 ? "À l'heure (dérive < 1 s)"
                        : `Dérive : appareil ${control.driftSec > 0 ? "en retard" : "en avance"} de ${Math.abs(Math.round(control.driftSec))} s`}
                    </p>
                  </div>
                  <Button size="sm" variant="outline" className="shrink-0" onClick={syncClock} disabled={control.clock.status === "saving"}>
                    {control.clock.status === "saving" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Clock className="h-3.5 w-3.5" />} Synchroniser au PC
                  </Button>
                </div>
                <Alert variant="info"><AlertDescription className="text-xs">Vérifiez que l'horloge du PC est correcte (synchronisée NTP) avant de pousser — une heure PC fausse rejettera les QR valides.</AlertDescription></Alert>
                {control.clock.status === "ok" && (
                  <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-600"><CheckCircle2 className="h-3.5 w-3.5" /> Synchronisé{control.clock.driftSec != null ? ` (dérive ${Math.abs(Math.round(control.clock.driftSec))} s)` : ""}</span>
                )}
                {control.clock.status === "err" && (
                  <div className="flex items-center gap-2">
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-destructive"><XCircle className="h-3.5 w-3.5" /> Échec</span>
                    <Button size="sm" variant="ghost" className="h-6 text-xs" onClick={() => showControlError("Erreur — synchronisation horloge", control.clock.error || "")}>Voir l'erreur</Button>
                  </div>
                )}
              </div>

              {/* MIRROR pushing-policy review (standalone devices set to MIRROR) */}
              {control.policy === "MIRROR" && (
                <>
                  <div className="border-t" />
                  <div className="space-y-2.5">
                    <div>
                      <p className="text-sm font-medium flex items-center gap-2">
                        Synchronisation miroir (MIRROR)
                        {control.mirror.armed
                          ? <Badge variant="destructive" className="text-xs">Suppressions activées</Badge>
                          : <Badge variant="secondary" className="text-xs">Simulation (dry-run)</Badge>}
                      </p>
                      <p className="text-xs text-muted-foreground">À chaque synchro complète, supprime de l'appareil les utilisateurs absents du fichier de l'app.</p>
                    </div>

                    {control.mirror.count != null ? (
                      <Alert variant={control.mirror.count > 0 ? "destructive" : "info"}>
                        <AlertDescription className="text-xs">
                          {control.mirror.count > 0 ? (
                            <>
                              Dernière simulation : <strong>{control.mirror.count}</strong> utilisateur(s) seraient supprimés
                              {control.mirror.sample.length > 0 && (
                                <span className="font-mono"> — PIN {control.mirror.sample.slice(0, 12).join(", ")}{control.mirror.count > control.mirror.sample.length ? "…" : ""}</span>
                              )}
                              {control.mirror.at && <span className="text-muted-foreground"> ({control.mirror.at})</span>}
                            </>
                          ) : (
                            <>Dernière simulation : aucun utilisateur à supprimer.</>
                          )}
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <p className="text-xs text-muted-foreground">Aucune simulation encore enregistrée — elle apparaîtra après la prochaine synchro complète.</p>
                    )}

                    <div className="flex items-center gap-2 flex-wrap">
                      {control.mirror.armed ? (
                        <Button size="sm" variant="outline" onClick={() => setMirrorArmed(false)} disabled={control.mirror.status === "saving"}>
                          {control.mirror.status === "saving" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null} Repasser en simulation
                        </Button>
                      ) : (
                        <Button size="sm" variant="destructive" onClick={() => setMirrorArmed(true)} disabled={control.mirror.status === "saving" || control.mirror.count == null || control.mirror.count === 0}>
                          {control.mirror.status === "saving" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null} Activer les suppressions
                        </Button>
                      )}
                      {control.mirror.error && (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-destructive"><XCircle className="h-3.5 w-3.5" /> {control.mirror.error.slice(0, 80)}</span>
                      )}
                    </div>

                    {!control.mirror.armed && (
                      <Alert variant="info"><AlertDescription className="text-xs">Tant que non activé, MIRROR ne supprime rien : il journalise seulement ce qu'il supprimerait. Vérifiez la liste ci-dessus avant d'activer.</AlertDescription></Alert>
                    )}
                  </div>
                </>
              )}

              <p className="text-[11px] text-muted-foreground flex items-center gap-1.5"><Router className="h-3 w-3" /> Écritures via la connexion du worker · valeur relue pour confirmer{control.mode ? ` · mode ${control.mode}` : ""}</p>
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setControl(null)}>Fermer</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Control error popup (full SDK log) */}
      <Dialog open={!!control?.errorPopup} onOpenChange={(open: boolean) => { if (!open) setControl((p) => p ? { ...p, errorPopup: null } : p); }}>
        <DialogContent className="rounded-3xlmax-w-lg">
          <DialogHeader><DialogTitle className="flex items-center gap-2"><AlertCircle className="h-4 w-4 text-destructive" /> {control?.errorPopup?.title || "Erreur"}</DialogTitle></DialogHeader>
          <pre className="text-xs font-mono whitespace-pre-wrap text-destructive max-h-[50vh] overflow-auto bg-muted rounded-md p-3">{control?.errorPopup?.text || "(aucun détail)"}</pre>
          <DialogFooter><Button variant="outline" onClick={() => setControl((p) => p ? { ...p, errorPopup: null } : p)}>Fermer</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-4 right-4 z-50 bg-card border rounded-lg shadow-lg px-4 py-3 text-sm animate-in slide-in-from-bottom-2 fade-in" onClick={() => setToast(null)}>
          {toast}
        </div>
      )}
    </div>
  );
}

