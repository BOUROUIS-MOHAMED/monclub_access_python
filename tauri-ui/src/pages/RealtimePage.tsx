// P3b-2: this PC's role (pilote / lecteur), its turnstiles, the notice socket, and — for a
// reader — the door history of the drivers it reads, from the server (a reader never
// connects to a turnstile).
import { useCallback, useEffect, useState } from "react";
import { Loader2, RefreshCw, Radio } from "lucide-react";

import { realtime, ROLE_LABEL_FR, type ReaderDoorEvent, type RealtimeStatus } from "@/api/realtime";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const AVAILABILITY_FR: Record<string, string> = {
  ON: "Serveur v2 actif",
  OFF: "Serveur sans v2 (fonctionnement habituel)",
  UNKNOWN: "Serveur injoignable pour l'instant (rôles du cache local)",
  NOT_STARTED: "Pas encore démarré",
};

function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? value : dt.toLocaleString("fr-FR");
}

export default function RealtimePage() {
  const [status, setStatus] = useState<RealtimeStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ReaderDoorEvent[]>([]);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const load = useCallback(async () => {
    try { setStatus(await realtime.status()); setError(null); }
    catch (e) { setError(String(e)); }
  }, []);

  const loadHistory = useCallback(async (before?: number | null) => {
    setLoadingHistory(true);
    try {
      const page = await realtime.readerHistory(before ?? null, 50);
      setHistory((h) => (before ? [...h, ...page.items] : page.items));
      setNextBefore(page.nextBeforeId);
    } catch (e) { setError(String(e)); }
    finally { setLoadingHistory(false); }
  }, []);

  useEffect(() => { load(); const id = setInterval(load, 10_000); return () => clearInterval(id); }, [load]);
  const isReader = status?.role === "READER";
  useEffect(() => { if (isReader || (status?.readerOf?.length ?? 0) > 0) loadHistory(null); }, [isReader, status?.readerOf?.length, loadHistory]);

  if (!status) {
    return error
      ? <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
      : <div className="flex items-center gap-2 p-6 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Chargement…</div>;
  }

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-center justify-end">
        <Button variant="outline" size="sm" onClick={load}><RefreshCw className="mr-1 h-4 w-4" />Actualiser</Button>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <Card><CardHeader className="pb-1"><CardTitle className="text-sm text-muted-foreground">Rôle de ce PC</CardTitle></CardHeader>
          <CardContent className="text-base font-semibold">{ROLE_LABEL_FR[status.role] ?? status.role}
            <div className="text-xs font-normal text-muted-foreground">{AVAILABILITY_FR[status.availability] ?? status.availability}</div>
          </CardContent></Card>
        <Card><CardHeader className="pb-1"><CardTitle className="text-sm text-muted-foreground">Connexion temps réel</CardTitle></CardHeader>
          <CardContent className="flex items-center gap-2 text-sm">
            <Radio className={status.socket?.connected ? "h-4 w-4 text-green-600" : "h-4 w-4 text-muted-foreground"} />
            {status.socket?.connected ? "Connecté" : `Non connecté — vérification toutes les ${status.socket?.pollIntervalSec ?? 120} s`}
          </CardContent></Card>
        <Card><CardHeader className="pb-1"><CardTitle className="text-sm text-muted-foreground">Horloge (écart avec le serveur)</CardTitle></CardHeader>
          <CardContent className="text-sm">{status.clock ? `${status.clock.offsetSec >= 0 ? "+" : ""}${status.clock.offsetSec.toFixed(1)} s` : "pas encore mesuré"}</CardContent></Card>
      </div>

      {status.mode === "LEASED" && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">Tourniquets pilotés par ce PC</CardTitle></CardHeader>
          <CardContent>
            {status.drive.length === 0 && status.release.length === 0
              ? <div className="text-sm text-muted-foreground">Aucun : ce PC ne se connecte à aucun tourniquet.</div>
              : (
                <Table>
                  <TableHeader><TableRow><TableHead>Tourniquet</TableHead><TableHead>État</TableHead><TableHead>Retraits</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {status.drive.map((d) => (
                      <TableRow key={d.gymDeviceId}>
                        <TableCell>{d.name || d.gymDeviceId}</TableCell>
                        <TableCell>{d.state === "DRIVE" ? <Badge variant="success">Piloté</Badge> : <Badge variant="outline">En attente de la passation</Badge>}</TableCell>
                        <TableCell>{d.addOnly ? <Badge variant="warning">Ajouts seulement (relecture en attente)</Badge> : "Normaux"}</TableCell>
                      </TableRow>
                    ))}
                    {status.release.map((r) => (
                      <TableRow key={`r${r.gymDeviceId}`}>
                        <TableCell>{r.name || r.gymDeviceId}</TableCell>
                        <TableCell><Badge variant="warning">Passation en cours</Badge></TableCell>
                        <TableCell>Aucune écriture jusqu'à la fin de la passation</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            {status.readerOf.length > 0 && (
              <div className="mt-2 text-xs text-muted-foreground">Lit l'historique de : {status.readerOf.map((r) => r.name).join(", ")}</div>
            )}
          </CardContent>
        </Card>
      )}

      {(isReader || status.readerOf.length > 0) && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">Historique des portes (depuis le serveur)</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader><TableRow><TableHead>Date</TableHead><TableHead>Tourniquet</TableHead><TableHead>Membre</TableHead><TableHead>Type</TableHead><TableHead>Résultat</TableHead></TableRow></TableHeader>
              <TableBody>
                {history.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell>{formatDate(e.date)}</TableCell>
                    <TableCell>{e.deviceName}</TableCell>
                    <TableCell>{e.userName || "—"}</TableCell>
                    <TableCell>{e.type}</TableCell>
                    <TableCell>{e.allowed ? <Badge variant="success">Autorisé</Badge> : <Badge variant="destructive">{e.reason || "Refusé"}</Badge>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {nextBefore && (
              <Button className="mt-2" variant="outline" size="sm" disabled={loadingHistory} onClick={() => loadHistory(nextBefore)}>
                {loadingHistory ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : null}Plus
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {(status.lastError || error) && (
        <Alert variant="warning"><AlertDescription>{status.lastError || error}</AlertDescription></Alert>
      )}
    </div>
  );
}
