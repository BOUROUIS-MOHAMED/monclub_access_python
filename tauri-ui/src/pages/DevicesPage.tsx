import { useState, useCallback } from "react";
import { useDevices, usePullSdk } from "@/api/hooks";
import { useApp } from "@/context/AppContext";
import { get, post } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import StatusChip from "@/components/StatusChip2";
import { cn } from "@/lib/utils";
import {
  RefreshCw, Router, Wifi, WifiOff, DoorOpen, Info, LockOpen, Loader2, AlertCircle,
  SlidersHorizontal, Clock, CheckCircle2, XCircle,
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
  reentryEnabled: boolean;
  reentrySeconds: string;
  reentry: VerifyState;
  clock: VerifyState;
  errorPopup: { title: string; text: string } | null;
}

const CONTENT_TABLES = [
  { key: "user", label: "Utilisateurs" },
  { key: "userauthorize", label: "Autorisations" },
  { key: "templatev10", label: "Empreintes" },
  { key: "transaction", label: "Transactions" },
] as const;

export default function DevicesPage() {
  const { data, loading, error, reload } = useDevices(false);
  const pullsdk = usePullSdk();
  const { status } = useApp();

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
      doors: [], driftSec: null, reentryEnabled: false, reentrySeconds: "30",
      reentry: { status: "idle" }, clock: { status: "idle" }, errorPopup: null,
    });
    try {
      const s = await pullsdk.getSettings(deviceId);
      const doors = s.doors || [];
      const maxInt = doors.reduce((m: number, d: any) => Math.max(m, Number(d.intertimeSec) || 0), 0);
      setControl((p) => p && p.deviceId === deviceId ? {
        ...p, loading: false, mode: String(s.mode || ""),
        doors, driftSec: s.clock?.driftSec ?? null,
        reentryEnabled: maxInt > 0,
        reentrySeconds: maxInt > 0 ? String(maxInt) : "30",
      } : p);
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
    return false;
  };

  const HIDE_KEYS = new Set(["payload_json", "raw_payload"]);
  const contentColumns = infoDialog?.content.rows[0]
    ? Object.keys(infoDialog.content.rows[0]).filter((key) => !HIDE_KEYS.has(key)).slice(0, 8)
    : [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Router className="h-5 w-5 text-primary" />
          <h1 className="text-lg font-semibold">Appareils</h1>
          <Badge variant="secondary" className="text-xs">{devices.length}</Badge>
        </div>
        <Button size="sm" variant="outline" onClick={reload} disabled={loading}>
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} /> Recharger
        </Button>
      </div>

      {error && <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{error}</AlertDescription></Alert>}

      {devices.length === 0 && !loading ? (
        <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
          <Router className="h-12 w-12 opacity-30" />
          <p className="font-medium">Aucun appareil trouvé</p>
          <p className="text-sm">Lancez une synchronisation pour charger les appareils.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {devices.map((d: any, i: number) => {
            const did = d.id ?? d.deviceId ?? i;
            const name = d.name || d.deviceName || `Appareil #${did}`;
            const ip = d.ip || d.ipAddress || "—";
            const mode = (d.accessDataMode || d.access_data_mode || "—").toUpperCase();
            const conn = isConnected(d);
            return (
              <Card key={did} className="py-4">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm">{name}</CardTitle>
                    <Badge variant={mode === "ULTRA" ? "default" : mode === "AGENT" ? "default" : mode === "DEVICE" ? "secondary" : "outline"} className={cn("text-[10px]", mode === "ULTRA" && "bg-violet-500 hover:bg-violet-600")}>{mode}</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground font-mono">{ip}:{d.port || 4370}</p>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-2">
                    <StatusChip variant={conn ? "online" : "offline"} label={conn ? "Connecté" : "Déconnecté"} />
                  </div>
                  <div className="flex gap-1.5 flex-wrap">
                    {conn ? (
                      <Button size="sm" variant="outline" onClick={() => handleDisconnect(did)}><WifiOff className="h-3.5 w-3.5" /> Déconnecter</Button>
                    ) : (
                      <Button size="sm" variant="outline" onClick={() => handleConnect(did)}><Wifi className="h-3.5 w-3.5" /> Connecter</Button>
                    )}
                    <Button size="sm" variant="outline" onClick={() => setDoorDialog({ deviceId: did, deviceName: name })}><DoorOpen className="h-3.5 w-3.5" /> Porte</Button>
                    <Button size="sm" variant="outline" onClick={() => openControl(did, name)}><SlidersHorizontal className="h-3.5 w-3.5" /> Contrôle</Button>
                    <Button size="sm" variant="ghost" onClick={() => handleInfo(did)}><Info className="h-3.5 w-3.5" /></Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Manual Door Open Dialog */}
      <Dialog open={!!doorDialog} onOpenChange={(open: boolean) => { if (!open) setDoorDialog(null); }}>
        <DialogContent className="max-w-xs">
          <DialogHeader>
            <DialogTitle>Ouvrir la porte — {doorDialog?.deviceName}</DialogTitle>
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
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle>Info Appareil #{infoDialog?.deviceId}</DialogTitle>
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
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><SlidersHorizontal className="h-4 w-4" /> Contrôle — {control?.deviceName}</DialogTitle>
          </DialogHeader>
          {control?.loading ? (
            <div className="py-10 flex justify-center"><Loader2 className="h-6 w-6 animate-spin text-primary" /></div>
          ) : control?.loadError ? (
            <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{control.loadError}</AlertDescription></Alert>
          ) : control ? (
            <div className="space-y-5">
              {/* Re-entry block */}
              <div className="space-y-2.5">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium">Blocage de ré-entrée</p>
                    <p className="text-xs text-muted-foreground">Même carte/QR refusée pendant le délai · RFID (appareil) + QR (logiciel)</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Switch checked={control.reentryEnabled} onCheckedChange={(v: boolean) => setControl((p) => p ? { ...p, reentryEnabled: v } : p)} />
                    <Input type="number" min={5} max={255} className="w-16" value={control.reentrySeconds} disabled={!control.reentryEnabled}
                      onChange={(e) => setControl((p) => p ? { ...p, reentrySeconds: e.target.value } : p)} />
                    <span className="text-xs text-muted-foreground">sec</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
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
        <DialogContent className="max-w-lg">
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

