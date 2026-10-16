import { useState, useCallback, useMemo, useEffect } from "react";
import { useDevices, usePullSdk, usePopupStream } from "@/api/hooks";
import { useApp } from "@/context/AppContext";
import { usePageChrome } from "@/context/PageChromeContext";
import { get, post } from "@/api/client";
import { doorRequestedMessage, isNotDriverError, requestDoorViaDriver } from "@/api/realtime";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Switch } from "@/components/ui/switch";
import { ActionButton } from "@/components/ui/action-button";
import { Chip, ToneIcon } from "@/components/ui/chip";
import { DialogFrame, DialogRow, DialogSection } from "@/components/ui/dialog-frame";
import { CellText, FlexCell, FlexRow, FlexTable } from "@/components/ui/flex-table";
import { LineTabs } from "@/components/ui/line-tabs";
import { ListRow, Note, PageGrid, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import type { Tone } from "@/components/ui/tone";
import { cn } from "@/lib/utils";
import EraseWizardDialog from "@/components/EraseWizardDialog";
import { ERASE_TEXT, loadLang } from "@/lib/eraseWizardText";
import { liveEraseApi } from "@/api/erase";
import {
  RefreshCw, Router, Wifi, WifiOff, DoorOpen, Info, Loader2, AlertCircle, Cable, Server, Plug,
  SlidersHorizontal, Clock, CheckCircle2, XCircle, Monitor, Bug, Eraser, PauseCircle, TriangleAlert, CircleCheck,
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
  /** Standalone-family door switch (may the driver issue ACUnlock?). supported=false
   *  on the PullSDK family (the endpoint answers 409) -> the block is not rendered. */
  openDoor: {
    supported: boolean;
    enabled: boolean;        // effective value
    source: string;          // env | local | default
    local: boolean | null;   // persisted per-device switch, null = not set
    envOverride: boolean | null;
    live: boolean | null;
    pending: boolean;        // the position the operator chose, before « Appliquer »
    status: VerifyState;
  };
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

// v5 state chip tones (design S04): Connecté green, Non connecté red, Adresse absente amber,
// Inactif grey. « Non connecté » is red only where this PC runs a worker for the device (see
// rowTone below): on a PC that drives nothing, every row would otherwise read as a fault.
const STATE_TONE: Record<DeviceState, Tone> = {
  connected: "success", idle: "error", noaddress: "warning", inactive: "grey",
};

// The live-content tables, labelled as the erase wizard names them.
const CONTENT_LABEL: Record<string, string> = {
  user: "Utilisateurs et cartes",
  userauthorize: "Droits d'accès aux portes",
  templatev10: "Empreintes v10",
  transaction: "Journal des passages",
};

type InfoTab = "cached" | "presets" | "content" | "live";
const INFO_TABS: { value: InfoTab; label: string }[] = [
  { value: "cached", label: "Cache" },
  { value: "presets", label: "Presets portes" },
  { value: "content", label: "Contenu" },
  { value: "live", label: "Live (PullSDK)" },
];

function valueText(v: unknown): string {
  return typeof v === "object" ? JSON.stringify(v) : String(v);
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

  // Erase-content wizard (lane 1, 2026-09-27) and the turnstiles an erase left on hold.
  const [eraseDialog, setEraseDialog] = useState<{ deviceId: number; deviceName: string; mode: "erase" | "refill" } | null>(null);
  const [heldIds, setHeldIds] = useState<Set<number>>(new Set());
  // The holds where NOTHING was erased (lane 1e): kept because the scheme moved, or could not be read, before any delete --
  // "erase-scheme-moved", or a leftover "erase-prep" row whose recorded scheme is not the one now.
  const [nothingErasedIds, setNothingErasedIds] = useState<Set<number>>(new Set());
  // The start-up read of the holds failed: Access then holds EVERY turnstile until it reads.
  const [holdsUnknown, setHoldsUnknown] = useState(false);
  const reloadHolds = useCallback(async () => {
    try {
      const res = await liveEraseApi.holds();
      const held = (res.holds ?? []).filter((h) => Number.isFinite(Number(h.deviceId)));
      setHeldIds(new Set(held.map((h) => Number(h.deviceId))));
      setNothingErasedIds(new Set(held.filter((h) => h.reason === "erase-scheme-moved"
        || (h.reason === "erase-prep" && h.terminalScheme != null && h.terminalScheme !== h.pinScheme))
        .map((h) => Number(h.deviceId))));
      setHoldsUnknown(!!res.loadFailed);
    } catch { /* an older Access API without the wizard: no hold is shown */ }
  }, []);
  useEffect(() => { void reloadHolds(); }, [reloadHolds, data]);

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
      openDoor: { supported: false, enabled: true, source: "", local: null, envOverride: null,
        live: null, pending: true, status: { status: "idle" } },
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
      // Door switch (standalone family only; 409 elsewhere -> block stays hidden)
      try {
        const sw = await pullsdk.getOpenDoorSwitch(deviceId);
        setControl((p) => p && p.deviceId === deviceId ? {
          ...p, openDoor: { ...p.openDoor, supported: true, enabled: !!sw.enabled,
            source: String(sw.source || ""), local: sw.local ?? null,
            envOverride: sw.envOverride ?? null, live: sw.live ?? null,
            pending: !!sw.enabled, status: { status: "idle" } },
        } : p);
      } catch { /* PullSDK family: no switch, the door always opens */ }
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

  // Standalone door switch: persist + apply to the running driver (no reconnect).
  // null = clear the per-device value and fall back to the family default.
  const applyOpenDoorSwitch = useCallback(async (value: boolean | null) => {
    if (!control) return;
    const { deviceId } = control;
    setControl((p) => p ? { ...p, openDoor: { ...p.openDoor, status: { status: "saving" } } } : p);
    try {
      const res = await pullsdk.setOpenDoorSwitch(deviceId, value);
      setControl((p) => p && p.deviceId === deviceId ? {
        ...p, openDoor: { ...p.openDoor, enabled: !!res.enabled, source: String(res.source || ""),
          local: res.local ?? null, envOverride: res.envOverride ?? null, live: res.live ?? null,
          pending: !!res.enabled, status: { status: "ok" } },
      } : p);
      setToast(res.enabled ? "Commande d'ouverture activée (ACUnlock sera émis)" : "Commande d'ouverture désactivée");
    } catch (e) {
      setControl((p) => p && p.deviceId === deviceId ? { ...p, openDoor: { ...p.openDoor, status: { status: "err", error: String(e) } } } : p);
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
    try {
      const res: any = await pullsdk.doorOpen(doorDialog.deviceId, parseInt(doorNum) || 1, parseInt(pulseSec) || 3);
      setToast(res?.requested ? doorRequestedMessage(res) : "Porte ouverte !"); setDoorDialog(null);
    }
    catch (e) {
      // P3b-2: another PC drives this turnstile -- ask it through the server instead.
      if (isNotDriverError(e)) {
        try { setToast(await requestDoorViaDriver(doorDialog.deviceId, parseInt(doorNum) || 1)); setDoorDialog(null); }
        catch (e2) { setToast(`Demande au PC pilote échouée: ${e2}`); }
        return;
      }
      setToast(`Ouverture échouée: ${e}`);
    }
  }, [doorDialog, doorNum, pulseSec, pullsdk]);

  const handlePresetDoorOpen = useCallback(async (deviceId: number, doorNumber: number, pulseSeconds: number) => {
    try {
      const res: any = await post(`/devices/${deviceId}/door/open`, { doorNumber, pulseSeconds });
      setToast(res?.requested ? doorRequestedMessage(res) : `Porte ${doorNumber} ouverte (${pulseSeconds}s)`);
    }
    catch (e) {
      if (isNotDriverError(e)) {
        try { setToast(await requestDoorViaDriver(deviceId, doorNumber)); }
        catch (e2) { setToast(`Demande au PC pilote échouée: ${e2}`); }
        return;
      }
      setToast(`Ouverture échouée: ${e}`);
    }
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

  // Infos appareil tabs: controlled, so opening the dialog goes back to « Cache ».
  const [infoTab, setInfoTab] = useState<InfoTab>("cached");
  const openInfo = (deviceId: number) => { setInfoTab("cached"); handleInfo(deviceId); };

  // Composition by protocol (what really differs between devices) and the access-mode check,
  // counted from the roster on screen -- never assumed.
  const fleet = useMemo(() => {
    let pullsdkCount = 0, standaloneCount = 0, ultraCount = 0, reachable = 0, connectedCount = 0;
    const offMode: Record<string, number> = {};
    for (const d of devices as any[]) {
      if (protocolOf(d) === "ZK_STANDALONE") standaloneCount += 1; else pullsdkCount += 1;
      const m = String(d.accessDataMode ?? d.access_data_mode ?? "").toUpperCase();
      if (m === "ULTRA") ultraCount += 1;
      else offMode[m || "?"] = (offMode[m || "?"] ?? 0) + 1;
      const st = deviceStateOf(d, isConnected(d));
      if (st === "connected" || st === "idle") reachable += 1;
      if (st === "connected") connectedCount += 1;
    }
    return { pullsdkCount, standaloneCount, ultraCount, offMode, reachable, connectedCount };
  }, [devices, connectedIds, status?.pullsdk?.connected, status?.pullsdk?.deviceId, status?.ultra]);

  const heldDevices = (devices as any[]).filter((d) => heldIds.has(Number(d.id ?? d.deviceId)));
  const deviceOf = (id: number | undefined): any =>
    id == null ? null : (devices as any[]).find((d) => (d.id ?? d.deviceId) === id) ?? null;

  const plural = devices.length > 1 ? "s" : "";
  const modeLine = devices.length === 0 ? ""
    : fleet.ultraCount === devices.length ? " · tous en mode ULTRA"
    : ` · ${fleet.ultraCount} / ${devices.length} en mode ULTRA`;

  usePageChrome(() => ({
    subtitle: `${devices.length} appareil${plural} déclaré${plural}${modeLine}`,
    actions: (
      <>
        <ActionButton kind="outline" icon={RefreshCw} spin={loading} onClick={reload} disabled={loading}>
          Recharger
        </ActionButton>
        <ActionButton kind="primary" icon={RefreshCw} spin={!!status?.sync?.running}
          onClick={() => { void syncNow(); }} disabled={status?.sync?.running}>
          {status?.sync?.running ? "En cours…" : "Synchroniser"}
        </ActionButton>
      </>
    ),
  }), [devices.length, plural, modeLine, loading, reload, syncNow, status?.sync?.running]);

  // Dialog subtitles: protocol · model · address, from the roster row.
  const infoDev: any = infoDialog?.cached ?? null;
  const infoName = infoDev?.name || infoDev?.deviceName || `Appareil #${infoDialog?.deviceId ?? ""}`;
  const infoProtocol = protocolOf(infoDev);
  const ctlDev = deviceOf(control?.deviceId);
  const ctlIp = ctlDev ? String(ctlDev.ip ?? ctlDev.ipAddress ?? "").trim() : "";
  const ctlSub = ctlDev
    ? [PROTOCOL_LABEL[protocolOf(ctlDev)], ctlDev.model, ctlIp ? `${ctlIp}:${ctlDev.portNumber ?? ctlDev.port ?? 4370}` : ""]
      .filter(Boolean).join(" · ")
    : undefined;
  const standaloneNote = "Cette lecture n'est pas disponible sur un terminal autonome (ZKTeco) : seulement sur les contrôleurs PullSDK.";

  return (
    <div className="flex flex-col gap-[18px]">
      {error && (
        <Note tone="error" className="flex items-start gap-2"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{error}</Note>
      )}
      {holdsUnknown && (
        <Note tone="error" className="flex items-start gap-2">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Access n'a pas pu relire les mises en attente après un effacement : aucun membre n'est écrit sur
            aucun appareil jusqu'à la prochaine lecture réussie (réessayée à chaque synchronisation).
          </span>
        </Note>
      )}

      <PageGrid>
        {/* ── Le parc ─────────────────────────────────────────────────────── */}
        <Panel className="col-span-8">
          <PanelHeader title="Le parc" sub="Déclaré dans le tableau de bord MonClub, synchronisé sur ce poste" />
          <FlexTable
            label="Le parc"
            columns={[
              { label: "Appareil", flex: 2.1 },
              { label: "Adresse", flex: 1.25 },
              { label: "État", flex: 1 },
              { label: "Actions", flex: 2.6, align: "right" },
            ]}
            empty={loading ? (
              <Loader2 className="mx-auto h-6 w-6 animate-spin text-primary" />
            ) : (
              <div className="flex flex-col items-center gap-1.5">
                <Router className="h-8 w-8 text-muted-foreground/40" />
                <span className="font-semibold text-foreground">Aucun appareil trouvé</span>
                <span className="max-w-[340px] text-[12.5px]">
                  Lancez une synchronisation pour charger les appareils déclarés côté serveur.
                </span>
              </div>
            )}
          >
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
              // « Non connecté » is a fault only where this PC runs a worker for the device.
              const hasWorker = status?.ultra?.devices?.[String(did)] != null;
              const tone: Tone = state === "idle" && !hasWorker ? "grey" : STATE_TONE[state];
              const sub = [PROTOCOL_LABEL[protocol], d.model, d.zone].filter(Boolean).join(" · ");
              return (
                <FlexRow key={did} minHeight={60}>
                  <FlexCell
                    flex={2.1}
                    title={protocol === "ZK_STANDALONE" ? "Connexion gérée en continu par le service — pas de session manuelle." : undefined}
                  >
                    <ToneIcon icon={faulty ? WifiOff : Router} tone={state === "connected" ? "primary" : tone} size={34} />
                    <CellText
                      title={name}
                      strong
                      sub={sub || "—"}
                      flags={mode !== "ULTRA" ? [{ label: mode || "mode ?", tone: "warning" }] : undefined}
                    />
                  </FlexCell>
                  <FlexCell flex={1.25}>
                    <span className={cn("truncate text-[12.5px]", ip ? "font-mono text-foreground" : "text-muted-foreground")}>
                      {ip ? `${ip}:${d.portNumber ?? d.port ?? 4370}` : "adresse absente"}
                    </span>
                  </FlexCell>
                  <FlexCell flex={1}>
                    <Chip tone={tone}>{STATE_LABEL[state]}</Chip>
                  </FlexCell>
                  <FlexCell flex={2.6} align="right" className="flex-wrap gap-1.5">
                    {faulty ? (
                      <ActionButton size="xs" icon={Info} onClick={() => openInfo(did)}>Détails</ActionButton>
                    ) : (
                      <>
                        {canOpenDoor ? (
                          <ActionButton size="xs" icon={DoorOpen} onClick={() => setDoorDialog({ deviceId: did, deviceName: name })}>
                            Porte
                          </ActionButton>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span tabIndex={0}>
                                <ActionButton size="xs" icon={DoorOpen} disabled>Porte</ActionButton>
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Commande d'ouverture non activée pour ce modèle (à valider sur le matériel).
                            </TooltipContent>
                          </Tooltip>
                        )}
                        <ActionButton size="xs" icon={SlidersHorizontal} onClick={() => openControl(did, name)}>
                          Contrôle
                        </ActionButton>
                        {heldIds.has(Number(did)) && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <ActionButton
                                size="xs" kind="warn" icon={PauseCircle}
                                onClick={() => setEraseDialog({ deviceId: did, deviceName: name, mode: "refill" })}
                              >
                                Remplir
                              </ActionButton>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-xs">
                              {nothingErasedIds.has(Number(did))
                                ? ERASE_TEXT[loadLang()].rowHoldNothingErased
                                : ERASE_TEXT[loadLang()].rowHoldBanner}
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </>
                    )}
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <ActionButton size="xs" iconOnly icon={Info} onClick={() => openInfo(did)}>Infos appareil</ActionButton>
                      </TooltipTrigger>
                      <TooltipContent>Infos appareil</TooltipContent>
                    </Tooltip>
                    {/* Manual connect exists only for PullSDK panels. A ZK_STANDALONE
                        terminal is driven by its own COM event sink, which the live
                        worker already owns -- offering "Connect" here would open a
                        second session and could only ever fail. */}
                    {!faulty && protocol === "ZK_PULLSDK" && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <ActionButton
                            size="xs" iconOnly icon={conn ? WifiOff : Wifi}
                            onClick={() => (conn ? handleDisconnect(did) : handleConnect(did))}
                          >
                            {conn ? `Déconnecter (${PROTOCOL_LABEL[protocol]})` : `Connecter (${PROTOCOL_LABEL[protocol]})`}
                          </ActionButton>
                        </TooltipTrigger>
                        <TooltipContent>
                          {conn ? `Déconnecter (${PROTOCOL_LABEL[protocol]})` : `Connecter (${PROTOCOL_LABEL[protocol]})`}
                        </TooltipContent>
                      </Tooltip>
                    )}
                    {!faulty && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <ActionButton
                            size="xs" kind="danger" iconOnly icon={Eraser}
                            onClick={() => setEraseDialog({ deviceId: did, deviceName: name, mode: "erase" })}
                          >
                            Effacer le contenu (administrateur)
                          </ActionButton>
                        </TooltipTrigger>
                        <TooltipContent>Effacer le contenu (administrateur)</TooltipContent>
                      </Tooltip>
                    )}
                  </FlexCell>
                </FlexRow>
              );
            })}
          </FlexTable>
        </Panel>

        {/* ── Le rail ─────────────────────────────────────────────────────── */}
        <div className="col-span-4 flex min-w-0 flex-col gap-[18px]">
          <Panel>
            <PanelHeader title="À traiter" />
            <PanelList>
              {parc.problems.map((p) => (
                <ListRow
                  key={`p${p.did}`}
                  icon={TriangleAlert}
                  tone={p.state === "noaddress" ? "warning" : "grey"}
                  title={p.name}
                  wrap
                  sub={p.state === "noaddress"
                    ? "Aucune adresse IP déclarée : l'application ne peut pas le joindre. Ajoutez-la dans le tableau de bord MonClub, puis synchronisez."
                    : "Marqué inactif côté serveur : ignoré par la synchronisation et par le moteur d'accès. Réactivez-le dans le tableau de bord MonClub, puis synchronisez."}
                  actions={<ActionButton size="sm" icon={Info} onClick={() => openInfo(p.did)}>Voir la fiche</ActionButton>}
                />
              ))}
              {heldDevices.map((d) => {
                const did = d.id ?? d.deviceId;
                return (
                  <ListRow
                    key={`h${did}`}
                    icon={PauseCircle}
                    tone="warning"
                    title={`${d.name || d.deviceName || `Appareil #${did}`} en attente`}
                    wrap
                    sub={nothingErasedIds.has(Number(did))
                      ? ERASE_TEXT[loadLang()].rowHoldNothingErased
                      : ERASE_TEXT[loadLang()].rowHoldBanner}
                  />
                );
              })}
              {parc.problems.length === 0 && heldDevices.length === 0 && (
                <ListRow
                  icon={CircleCheck}
                  tone="success"
                  title="Rien à traiter"
                  wrap
                  sub="Tous les appareils déclarés ont une adresse et sont actifs."
                />
              )}
            </PanelList>
          </Panel>

          {/* Composition — every number below is counted from the roster on screen. */}
          <Panel>
            <PanelHeader title="Composition" />
            <PanelList>
              <ListRow icon={Router} title="Appareils déclarés" value={devices.length} />
              <ListRow icon={Wifi} tone="success" title="Connectés" value={`${fleet.connectedCount} / ${fleet.reachable}`} />
              <ListRow icon={Cable} title="PullSDK" sub="centrales d'accès" value={fleet.pullsdkCount} />
              <ListRow icon={Server} title="ZKTeco autonome" sub="connexion gérée par le service" value={fleet.standaloneCount} />
              <ListRow
                icon={CheckCircle2}
                tone={fleet.ultraCount === devices.length ? "success" : "warning"}
                title="Mode ULTRA"
                sub={Object.entries(fleet.offMode).map(([m, n]) => `${m} : ${n}`).join(" · ") || undefined}
                subTone={fleet.ultraCount === devices.length ? undefined : "warning"}
                value={`${fleet.ultraCount} / ${devices.length}`}
              />
              <ListRow
                icon={Plug}
                tone={status?.pullsdk?.connected ? "primary" : "grey"}
                title="Lecteur PullSDK"
                value={status?.pullsdk?.connected ? `#${status.pullsdk.deviceId ?? "—"}` : "non connecté"}
                valueMono={!!status?.pullsdk?.connected}
              />
              <ListRow icon={Cable} title="Session PullSDK ouverte" value={connectedIds.size} />
              {parc.needsAttention > 0 && (
                <ListRow icon={TriangleAlert} tone="warning" title="À vérifier" value={parc.needsAttention} valueTone="warning" />
              )}
              <p className="mt-1.5 text-[12px] leading-[1.5] text-muted-foreground">
                L'état reflète la connexion réelle de cette application&nbsp;: session PullSDK pour les
                centrales, connexion du service temps réel pour les terminaux autonomes. Le serveur ne
                publie pas d'indicateur d'accessibilité par appareil.
              </p>
            </PanelList>
          </Panel>

          {/* Action tile — same tile as the dashboard's, real handlers. */}
          <Panel>
            <PanelList>
              <ListRow
                icon={Monitor}
                tone="primary"
                title="Écran d'entrée"
                sub="Affiche les accès en temps réel"
                actions={
                  <>
                    <ActionButton size="sm" icon={Monitor} onClick={openPopupWindow}>Ouvrir</ActionButton>
                    <ActionButton size="sm" icon={Bug} onClick={sendTestNotification}>Tester</ActionButton>
                  </>
                }
              />
            </PanelList>
          </Panel>
        </div>
      </PageGrid>

      {/* Manual Door Open Dialog */}
      <DialogFrame
        open={!!doorDialog}
        onOpenChange={(open: boolean) => { if (!open) setDoorDialog(null); }}
        width={440}
        title={`Ouvrir la porte — ${doorDialog?.deviceName ?? ""}`}
        sub="Commande envoyée par ce PC (ou demandée au PC pilote)"
        footer={
          <>
            <ActionButton onClick={() => setDoorDialog(null)}>Annuler</ActionButton>
            <ActionButton kind="primary" icon={DoorOpen} onClick={handleDoorOpen}>Ouvrir</ActionButton>
          </>
        }
      >
        <div className="grid grid-cols-2 gap-3 pb-1">
          <div className="space-y-1.5">
            <Label htmlFor="door-num">Numéro de porte</Label>
            <Input id="door-num" type="number" value={doorNum} onChange={(e) => setDoorNum(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="door-pulse">Durée impulsion (sec)</Label>
            <Input id="door-pulse" type="number" value={pulseSec} onChange={(e) => setPulseSec(e.target.value)} />
          </div>
        </div>
      </DialogFrame>

      {/* Infos appareil */}
      <DialogFrame
        open={!!infoDialog}
        onOpenChange={(open: boolean) => { if (!open) setInfoDialog(null); }}
        width={680}
        title={`Infos appareil — ${infoName}`}
        sub={`Appareil #${infoDialog?.deviceId ?? ""} · ${PROTOCOL_LABEL[infoProtocol]}`}
        tabs={<LineTabs size="dialog" items={INFO_TABS} value={infoTab} onChange={setInfoTab} />}
        footer={<ActionButton kind="dark" onClick={() => setInfoDialog(null)}>Fermer</ActionButton>}
        bodyClassName="min-h-[240px]"
      >
        {infoTab === "cached" && (
          infoDialog?.cached && Object.keys(infoDialog.cached).length > 0 ? (
            <div>
              {Object.entries(infoDialog.cached).filter(([k]) => !HIDE_KEYS.has(k)).filter(([, v]) => v != null && v !== "").map(([k, v]) => (
                <div key={k} className="flex items-start gap-3 border-b border-dashed border-grey/20 py-2 font-mono text-[12.5px]">
                  <span className="w-[210px] shrink-0 truncate text-muted-foreground">{k}</span>
                  {/* The device password is masked here (UI only). */}
                  <span className="min-w-0 flex-1 break-all text-foreground">
                    {k === "password" ? "•••••• (masqué)" : valueText(v)}
                  </span>
                </div>
              ))}
            </div>
          ) : <p className="py-6 text-center text-[13.5px] text-muted-foreground">Aucune donnée en cache.</p>
        )}

        {infoTab === "presets" && (
          infoDialog?.presetsLoading ? <Loader2 className="mx-auto my-6 h-6 w-6 animate-spin text-primary" /> : (
            (infoDialog?.presets?.length ?? 0) > 0 ? (
              <div className="pb-2">
                {infoDialog!.presets.map((p) => (
                  <DialogRow key={p.id} label={p.doorName || `Porte ${p.doorNumber}`} hint={`Porte ${p.doorNumber} · impulsion ${p.pulseSeconds} s`}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <ActionButton size="sm" icon={DoorOpen} onClick={() => handlePresetDoorOpen(infoDialog!.deviceId, p.doorNumber, p.pulseSeconds)}>
                          Ouvrir
                        </ActionButton>
                      </TooltipTrigger>
                      <TooltipContent>Ouvrir porte {p.doorNumber} ({p.pulseSeconds}s)</TooltipContent>
                    </Tooltip>
                  </DialogRow>
                ))}
                <Note className="mt-3">Les favoris parmi ces presets apparaissent dans le dock flottant.</Note>
              </div>
            ) : (
              <Note className="my-2">Aucun preset de porte configuré pour cet appareil.</Note>
            )
          )
        )}

        {infoTab === "content" && (
          <div className="flex flex-col gap-3 pb-2">
            {infoProtocol === "ZK_STANDALONE" && <Note>{standaloneNote}</Note>}
            <div>
              {CONTENT_TABLES.map((table) => (
                <DialogRow key={table.key} label={CONTENT_LABEL[table.key] ?? table.label} hint={<span className="font-mono">table {table.key}</span>}>
                  <ActionButton
                    size="sm"
                    kind={infoDialog?.content.tableName === table.key ? "dark" : "outline"}
                    onClick={() => void handleFetchContent(table.key)}
                    disabled={!!infoDialog?.content.loading}
                  >
                    Lire
                  </ActionButton>
                </DialogRow>
              ))}
            </div>
            <Note>Lit directement les tables du contrôleur (250 lignes max). Pour effacer, utilisez « Effacer le contenu ».</Note>
            {infoDialog?.content.loading && (
              <div className="flex justify-center py-6">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
              </div>
            )}
            {infoDialog?.content.error && <Note tone="error">{infoDialog.content.error}</Note>}
            {!infoDialog?.content.loading && !infoDialog?.content.error && !infoDialog?.content.tableName && (
              <p className="py-4 text-center text-[13px] text-muted-foreground">
                Choisissez une table pour lancer la lecture live.
              </p>
            )}
            {!!infoDialog?.content.tableName && !infoDialog?.content.loading && !infoDialog?.content.error && (
              <div className="flex flex-col gap-2.5">
                <div className="flex items-center gap-2">
                  <Chip tone="grey" className="font-mono">{infoDialog.content.tableName}</Chip>
                  <span className="text-[12.5px] text-muted-foreground">
                    {infoDialog.content.count} ligne(s) renvoyée(s)
                  </span>
                </div>
                <div className="max-h-[300px] overflow-auto rounded-xl border border-grey/20">
                  <table className="w-full text-[12px]">
                    <thead className="sticky top-0 bg-muted text-left text-muted-foreground">
                      <tr>
                        {contentColumns.map((column) => (
                          <th key={column} className="whitespace-nowrap px-3 py-2 font-semibold">{column}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {infoDialog.content.rows.length > 0 && contentColumns.length > 0 ? infoDialog.content.rows.map((row, index) => (
                        <tr key={`${infoDialog.content.tableName}-${index}`} className="border-b border-dashed border-grey/20 last:border-0">
                          {contentColumns.map((column) => (
                            <td key={column} className="max-w-[240px] truncate px-3 py-1.5 font-mono">
                              {typeof row[column] === "object" ? JSON.stringify(row[column]) : String(row[column] ?? "")}
                            </td>
                          ))}
                        </tr>
                      )) : (
                        <tr>
                          <td colSpan={Math.max(contentColumns.length, 1)} className="py-8 text-center text-[13px] text-muted-foreground">
                            Aucune ligne disponible pour cette table.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {infoTab === "live" && (
          <div className="flex flex-col gap-3 pb-2">
            {infoProtocol === "ZK_STANDALONE" && <Note>{standaloneNote}</Note>}
            <DialogRow label="Récupérer les infos en direct" hint="Connexion TCP via PullSDK : peut échouer si l'appareil n'est pas joignable.">
              <ActionButton
                size="sm" kind="dark" icon={infoDialog?.liveLoading ? Loader2 : RefreshCw} spin={!!infoDialog?.liveLoading}
                onClick={handleFetchLiveInfo} disabled={!!infoDialog?.liveLoading}
              >
                {infoDialog?.liveLoading ? "Connexion…" : "Récupérer"}
              </ActionButton>
            </DialogRow>
            {infoDialog?.liveError && <Note tone="error">{infoDialog.liveError}</Note>}
            {infoDialog?.live?.params && Object.keys(infoDialog.live.params).length > 0 && (
              <div>
                <DialogSection>Paramètres</DialogSection>
                {Object.entries(infoDialog.live.params).map(([k, v]) => (
                  <div key={k} className="flex items-start gap-3 border-b border-dashed border-grey/20 py-2 font-mono text-[12.5px]">
                    <span className="w-[210px] shrink-0 truncate text-muted-foreground">{k}</span>
                    <span className="min-w-0 flex-1 break-all text-foreground">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </DialogFrame>

      {/* Contrôle: re-entry block, door switch, clock, MIRROR */}
      <DialogFrame
        open={!!control}
        onOpenChange={(open: boolean) => { if (!open) setControl(null); }}
        width={620}
        title={`Contrôle — ${control?.deviceName ?? ""}`}
        sub={ctlSub}
        footer={<ActionButton kind="dark" onClick={() => setControl(null)}>Fermer</ActionButton>}
      >
        {control?.loading ? (
          <div className="flex justify-center py-10"><Loader2 className="h-6 w-6 animate-spin text-primary" /></div>
        ) : control?.loadError ? (
          <Note tone="error" className="flex items-start gap-2"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{control.loadError}</Note>
        ) : control ? (
          <div className="pb-1">
            {/* Re-entry block. On a family with no Door{N}Intertime parameter the
                value was never read, so we say so rather than showing a switch
                that would read as "re-entry is off on this terminal". */}
            <DialogSection>Blocage de ré-entrée</DialogSection>
            {control.supportsDeviceParams ? (
              <>
                <DialogRow label="Même carte ou QR refusé pendant le délai" hint="RFID par l'appareil + QR par le logiciel">
                  <Switch
                    aria-label="Blocage de ré-entrée"
                    checked={control.reentryEnabled}
                    onCheckedChange={(v: boolean) => setControl((p) => p ? { ...p, reentryEnabled: v } : p)}
                  />
                </DialogRow>
                <DialogRow label="Délai" hint="5 à 255 secondes">
                  <Input
                    type="number" min={5} max={255} className="h-8 w-[72px]" value={control.reentrySeconds}
                    disabled={!control.reentryEnabled} aria-label="Délai en secondes"
                    onChange={(e) => setControl((p) => p ? { ...p, reentrySeconds: e.target.value } : p)}
                  />
                  <span className="text-[12.5px] text-muted-foreground">sec</span>
                  <ActionButton
                    size="sm" kind="dark" icon={control.reentry.status === "saving" ? Loader2 : undefined} spin
                    onClick={applyReentry} disabled={control.reentry.status === "saving"}
                  >
                    Appliquer
                  </ActionButton>
                </DialogRow>
                {control.reentry.status === "ok" && (
                  <DialogRow label="Résultat">
                    <Chip tone="success" icon={CheckCircle2}>Appliqué</Chip>
                    <Chip tone={control.reentry.rfid ? "success" : "error"}>RFID {control.reentry.rfid ? "✓" : "✗"}</Chip>
                    {control.mode === "ultra" && (
                      <Chip tone={control.reentry.qr ? "success" : "error"}>QR {control.reentry.qr ? "✓" : "✗"}</Chip>
                    )}
                    <button
                      type="button"
                      onClick={() => { if (!control.reentry.backendSaved) showControlError("Enregistrement serveur", control.reentry.error || "Échec de l'enregistrement sur le serveur."); }}
                      className={cn("rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50", !control.reentry.backendSaved && "cursor-pointer")}
                      title={control.reentry.backendSaved ? "Enregistré sur le serveur MonClub" : "Voir l'erreur d'enregistrement"}
                    >
                      <Chip tone={control.reentry.backendSaved ? "success" : "warning"}>serveur {control.reentry.backendSaved ? "✓" : "⚠"}</Chip>
                    </button>
                  </DialogRow>
                )}
                {control.reentry.status === "err" && (
                  <DialogRow label="Résultat">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span><Chip tone="error" icon={XCircle}>Échec</Chip></span>
                      </TooltipTrigger>
                      <TooltipContent className="max-w-xs">{(control.reentry.error || "Erreur").slice(0, 160)}</TooltipContent>
                    </Tooltip>
                    {/* Show which half succeeded when the device responded (split failure). */}
                    {control.reentry.rfid !== undefined && (
                      <Chip tone={control.reentry.rfid ? "success" : "error"}>RFID {control.reentry.rfid ? "✓" : "✗"}</Chip>
                    )}
                    {control.reentry.rfid !== undefined && control.mode === "ultra" && (
                      <Chip tone={control.reentry.qr ? "success" : "error"}>QR {control.reentry.qr ? "✓" : "✗"}</Chip>
                    )}
                    <ActionButton size="xs" kind="ghost" onClick={() => showControlError("Erreur — blocage de ré-entrée", control.reentry.error || "")}>
                      Voir l'erreur complète
                    </ActionButton>
                  </DialogRow>
                )}
              </>
            ) : (
              <Note className="my-1.5">
                Ce modèle (terminal autonome) n'expose pas de paramètre de ré-entrée côté
                appareil&nbsp;: la valeur n'a pas pu être lue et ne peut pas être modifiée ici.
              </Note>
            )}
            {control.doors.length > 0 && (
              <p className="py-2 font-mono text-[12px] text-muted-foreground">
                Relu sur l'appareil : {control.doors.map((d) => `Door${d.doorNumber}Intertime=${d.intertimeSec}`).join("  ·  ")}
              </p>
            )}

            {control.openDoor.supported ? (
              <>
                {/* Standalone-family door switch. ON by default since 2026-09-04
                    (operator decision); the relay is still unverified on this
                    hardware, so the block says so rather than implying the door
                    will open. Hidden on the PullSDK family (no switch). */}
                <DialogSection>Commande d'ouverture (ACUnlock)</DialogSection>
                <DialogRow
                  label="Autoriser le bouton « Ouvrir » sur ce terminal"
                  hint="Aussi pour les secours QR et accueil : la commande est émise sur ce terminal"
                >
                  <Switch
                    aria-label="Commande d'ouverture"
                    checked={control.openDoor.pending} disabled={control.openDoor.envOverride !== null}
                    onCheckedChange={(v: boolean) => setControl((p) => p ? { ...p, openDoor: { ...p.openDoor, pending: v } } : p)}
                  />
                </DialogRow>
                {control.openDoor.envOverride !== null ? (
                  <Note tone="warning" className="my-1.5">
                    Forcé {control.openDoor.envOverride ? "ACTIVÉ" : "DÉSACTIVÉ"} par la variable d'environnement
                    MONCLUB_ZK_STANDALONE_OPEN_DOOR sur ce PC&nbsp;: l'interrupteur est ignoré tant qu'elle est définie.
                  </Note>
                ) : null}
                <DialogRow
                  label={control.openDoor.enabled ? "Activée" : "Désactivée"}
                  labelTone={control.openDoor.enabled ? "success" : undefined}
                  hint={`source : ${control.openDoor.source || "?"}`}
                >
                  {control.openDoor.status.status === "ok" && <Chip tone="success" icon={CheckCircle2}>Appliqué</Chip>}
                  {control.openDoor.status.status === "err" && (
                    <ActionButton
                      size="xs" kind="ghost" icon={XCircle} className="text-error-ink"
                      onClick={() => showControlError("Erreur — commande d'ouverture", control.openDoor.status.error || "")}
                    >
                      Échec — voir
                    </ActionButton>
                  )}
                  <ActionButton
                    size="sm" kind="dark" icon={control.openDoor.status.status === "saving" ? Loader2 : undefined} spin
                    onClick={() => applyOpenDoorSwitch(control.openDoor.pending)}
                    disabled={control.openDoor.status.status === "saving" || control.openDoor.envOverride !== null}
                  >
                    Appliquer
                  </ActionButton>
                  <ActionButton
                    size="sm" kind="ghost" onClick={() => applyOpenDoorSwitch(null)}
                    disabled={control.openDoor.local === null || control.openDoor.status.status === "saving"}
                  >
                    Valeur par défaut
                  </ActionButton>
                </DialogRow>
                <p className="py-2 text-[12px] text-muted-foreground">
                  Relais non validé sur ce matériel tant que le script 12/9 n'a pas réussi sur site&nbsp;:
                  un retour TRUE sans ouverture physique = câblage, pas SDK.
                </p>
              </>
            ) : null}

            {/* Clock */}
            <DialogSection>Horloge de l'appareil</DialogSection>
            <DialogRow
              label={control.driftSec == null ? "Dérive inconnue"
                : Math.abs(control.driftSec) < 1 ? "À l'heure (dérive < 1 s)"
                : `Dérive : appareil ${control.driftSec > 0 ? "en retard" : "en avance"} de ${Math.abs(Math.round(control.driftSec))} s`}
              labelTone={control.driftSec == null ? undefined
                : Math.abs(control.driftSec) > 10 ? "error"
                : Math.abs(control.driftSec) < 1 ? "success" : undefined}
            >
              {control.clock.status === "ok" && (
                <Chip tone="success" icon={CheckCircle2}>
                  Synchronisé{control.clock.driftSec != null ? ` (dérive ${Math.abs(Math.round(control.clock.driftSec))} s)` : ""}
                </Chip>
              )}
              {control.clock.status === "err" && (
                <>
                  <Chip tone="error" icon={XCircle}>Échec</Chip>
                  <ActionButton size="xs" kind="ghost" onClick={() => showControlError("Erreur — synchronisation horloge", control.clock.error || "")}>
                    Voir l'erreur
                  </ActionButton>
                </>
              )}
              <ActionButton
                size="sm" icon={control.clock.status === "saving" ? Loader2 : Clock} spin={control.clock.status === "saving"}
                onClick={syncClock} disabled={control.clock.status === "saving"}
              >
                Synchroniser au PC
              </ActionButton>
            </DialogRow>
            <Note className="my-2">
              Vérifiez d'abord que l'heure de ce PC est juste (synchronisée par Internet)&nbsp;: une heure PC
              fausse fait refuser des QR valides.
            </Note>

            {/* MIRROR pushing-policy review (standalone devices set to MIRROR) */}
            {control.policy === "MIRROR" && (
              <>
                <DialogSection>Synchronisation miroir (MIRROR)</DialogSection>
                <DialogRow
                  label={control.mirror.armed ? "Suppressions activées" : "Simulation (dry-run)"}
                  labelTone={control.mirror.armed ? "error" : undefined}
                  hint="À chaque synchro complète, supprime de l'appareil les utilisateurs absents du fichier de l'app."
                >
                  {control.mirror.error && (
                    <Chip tone="error" icon={XCircle} title={control.mirror.error}>{control.mirror.error.slice(0, 80)}</Chip>
                  )}
                  {control.mirror.armed ? (
                    <ActionButton
                      size="sm" icon={control.mirror.status === "saving" ? Loader2 : undefined} spin
                      onClick={() => setMirrorArmed(false)} disabled={control.mirror.status === "saving"}
                    >
                      Repasser en simulation
                    </ActionButton>
                  ) : (
                    <ActionButton
                      size="sm" kind="danger" icon={control.mirror.status === "saving" ? Loader2 : undefined} spin
                      onClick={() => setMirrorArmed(true)}
                      disabled={control.mirror.status === "saving" || control.mirror.count == null || control.mirror.count === 0}
                    >
                      Activer les suppressions
                    </ActionButton>
                  )}
                </DialogRow>
                {control.mirror.count != null ? (
                  <Note tone={control.mirror.count > 0 ? "error" : "info"} className="my-2">
                    {control.mirror.count > 0 ? (
                      <>
                        Dernière simulation : <strong>{control.mirror.count}</strong> utilisateur(s) seraient supprimés
                        {control.mirror.sample.length > 0 && (
                          <span className="font-mono"> — PIN {control.mirror.sample.slice(0, 12).join(", ")}{control.mirror.count > control.mirror.sample.length ? "…" : ""}</span>
                        )}
                        {control.mirror.at && <span className="opacity-80"> ({control.mirror.at})</span>}
                      </>
                    ) : (
                      <>Dernière simulation : aucun utilisateur à supprimer.</>
                    )}
                  </Note>
                ) : (
                  <p className="py-2 text-[12.5px] text-muted-foreground">Aucune simulation encore enregistrée — elle apparaîtra après la prochaine synchro complète.</p>
                )}
                {!control.mirror.armed && (
                  <Note className="my-2">Tant que non activé, MIRROR ne supprime rien : il journalise seulement ce qu'il supprimerait. Vérifiez la liste ci-dessus avant d'activer.</Note>
                )}
              </>
            )}

            <p className="flex items-center gap-1.5 pt-2 text-[12px] text-muted-foreground">
              <Router className="h-3.5 w-3.5" /> Écritures via la connexion du worker · valeur relue pour confirmer{control.mode ? ` · mode ${control.mode}` : ""}
            </p>
          </div>
        ) : null}
      </DialogFrame>

      {/* Control error popup (full SDK log) */}
      <DialogFrame
        open={!!control?.errorPopup}
        onOpenChange={(open: boolean) => { if (!open) setControl((p) => p ? { ...p, errorPopup: null } : p); }}
        width={560}
        title={control?.errorPopup?.title || "Erreur"}
        footer={<ActionButton kind="dark" onClick={() => setControl((p) => p ? { ...p, errorPopup: null } : p)}>Fermer</ActionButton>}
      >
        <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-lg bg-muted p-3 font-mono text-[12px] text-error-ink">
          {control?.errorPopup?.text || "(aucun détail)"}
        </pre>
      </DialogFrame>

      {eraseDialog && (
        <EraseWizardDialog
          open
          deviceId={eraseDialog.deviceId}
          deviceName={eraseDialog.deviceName}
          mode={eraseDialog.mode}
          onClose={() => setEraseDialog(null)}
          onChanged={() => { void reloadHolds(); }}
        />
      )}

      {/* Toast */}
      {toast && (
        <div
          className="fixed bottom-4 right-4 z-50 max-w-[420px] cursor-pointer rounded-xl bg-card px-4 py-3 text-[13.5px] text-foreground shadow-[var(--shadow-dialog)] animate-in slide-in-from-bottom-2 fade-in"
          onClick={() => setToast(null)}
        >
          {toast}
        </div>
      )}
    </div>
  );
}
