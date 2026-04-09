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
import StatusChip from "@/components/StatusChip2";
import { cn } from "@/lib/utils";
import {
  RefreshCw, Router, Wifi, WifiOff, DoorOpen, Info, LockOpen, Loader2, AlertCircle,
} from "lucide-react";

interface DoorPreset { id: number; deviceId: number; doorNumber: number; pulseSeconds: number; doorName: string; }

export default function DevicesPage() {
  const { data, loading, error, reload } = useDevices();
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
  } | null>(null);

  const devices = data?.devices ?? [];

  const handleConnect = useCallback(async (deviceId: number) => {
    try { await pullsdk.connect(deviceId); setConnectedIds((p) => new Set(p).add(deviceId)); setToast(`Appareil ${deviceId} connecté`); }
    catch (e) { setToast(`Connexion échouée: ${e}`); }
  }, [pullsdk]);

  const handleDisconnect = useCallback(async (deviceId: number) => {
    try { await pullsdk.disconnect(deviceId); setConnectedIds((p) => { const s = new Set(p); s.delete(deviceId); return s; }); setToast(`Appareil ${deviceId} déconnecté`); }
    catch (e) { setToast(`Déconnexion échouée: ${e}`); }
  }, [pullsdk]);

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
    setInfoDialog({ deviceId, cached: cachedDev as Record<string, unknown>, live: null, liveError: null, liveLoading: false, presets: [], presetsLoading: true });
    loadPresets(deviceId);
  }, [devices, loadPresets]);

  const handleFetchLiveInfo = useCallback(async () => {
    if (!infoDialog) return;
    setInfoDialog((p) => p ? { ...p, liveLoading: true, liveError: null, live: null } : p);
    try { const info = await pullsdk.getInfo(infoDialog.deviceId); setInfoDialog((p) => p ? { ...p, live: info, liveLoading: false } : p); }
    catch (e) { setInfoDialog((p) => p ? { ...p, liveError: String(e), liveLoading: false } : p); }
  }, [infoDialog, pullsdk]);

  const isConnected = (d: any) => {
    const did = d.id ?? d.deviceId;
    if (did && connectedIds.has(did)) return true;
    if (status?.pullsdk?.connected && status.pullsdk.deviceId === did) return true;
    return false;
  };

  const HIDE_KEYS = new Set(["payload_json", "raw_payload"]);

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

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-4 right-4 z-50 bg-card border rounded-lg shadow-lg px-4 py-3 text-sm animate-in slide-in-from-bottom-2 fade-in" onClick={() => setToast(null)}>
          {toast}
        </div>
      )}
    </div>
  );
}

