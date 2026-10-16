// P3b-2: this PC's role (pilote / lecteur), its turnstiles, the notice socket, and — for a
// reader — the door history of the drivers it reads, from the server (a reader never
// connects to a turnstile).
import { useCallback, useEffect, useState } from "react";
import { Activity, Clock, Loader2, RadioTower, RefreshCw, Router } from "lucide-react";

import { realtime, ROLE_LABEL_FR, type ReaderDoorEvent, type RealtimeStatus } from "@/api/realtime";
import { usePageChrome } from "@/context/PageChromeContext";
import { ActionButton } from "@/components/ui/action-button";
import { Chip } from "@/components/ui/chip";
import { CellText, FlexCell, FlexRow, FlexTable, IconCell } from "@/components/ui/flex-table";
import { KpiCard, KpiRow } from "@/components/ui/kpi-card";
import { Note, Panel, PanelHeader } from "@/components/ui/panel";
import { aDenyCopy } from "@/pages/PopupWindow";

const AVAILABILITY_FR: Record<string, string> = {
  ON: "Serveur v2 actif",
  OFF: "Serveur sans v2 (fonctionnement habituel)",
  UNKNOWN: "Serveur injoignable pour l'instant (rôles du cache local)",
  NOT_STARTED: "Pas encore démarré",
};

// Server door-history credential types; anything else is shown as sent.
const TYPE_FR: Record<string, string> = {
  CARD: "Carte",
  FINGER_PRINT: "Empreinte",
  FACE_ID: "Visage",
  QR_CODE: "QR Code",
};

function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? value : dt.toLocaleString("fr-FR");
}

export default function RealtimePage() {
  const [status, setStatus] = useState<RealtimeStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Own error for the door history: the 10 s status poll clears `error` on success, which used to
  // wipe a failed history load before anyone could read it.
  const [historyError, setHistoryError] = useState<string | null>(null);
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
      setHistoryError(null);
    } catch (e) { setHistoryError(String(e)); }
    finally { setLoadingHistory(false); }
  }, []);

  useEffect(() => { load(); const id = setInterval(load, 10_000); return () => clearInterval(id); }, [load]);
  const isReader = status?.role === "READER";
  useEffect(() => { if (isReader || (status?.readerOf?.length ?? 0) > 0) loadHistory(null); }, [isReader, status?.readerOf?.length, loadHistory]);

  usePageChrome(() => ({
    subtitle: isReader ? "Ce PC lit l'historique, il n'écrit dans aucun tourniquet" : "Qui écrit dans quel tourniquet",
    actions: <ActionButton kind="outline" icon={RefreshCw} onClick={load}>Actualiser</ActionButton>,
  }), [isReader, load]);

  if (!status) {
    return error
      ? <Note tone="error">{error}</Note>
      : <div className="flex items-center gap-2 p-6 text-[13.5px] text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Chargement…</div>;
  }

  const connected = !!status.socket?.connected;
  const roleLabel = ROLE_LABEL_FR[status.role] ?? status.role;

  return (
    <div className="flex flex-col gap-[18px]">
      <KpiRow cols={3}>
        <KpiCard
          label="Rôle de ce PC"
          value={<span title={roleLabel}>{roleLabel}</span>}
          sub={AVAILABILITY_FR[status.availability] ?? status.availability}
          icon={RadioTower}
          tone="primary"
        />
        <KpiCard
          label="Connexion temps réel"
          value={connected ? "Connecté" : "Non connecté"}
          sub={connected ? undefined : `Vérification toutes les ${status.socket?.pollIntervalSec ?? 120} s`}
          subTone={connected ? undefined : "warning"}
          icon={Activity}
          tone={connected ? "success" : "grey"}
        />
        <KpiCard
          label="Horloge (écart avec le serveur)"
          value={status.clock ? `${status.clock.offsetSec >= 0 ? "+" : ""}${status.clock.offsetSec.toFixed(1).replace(".", ",")} s` : "pas encore mesuré"}
          icon={Clock}
          tone="info"
        />
      </KpiRow>

      {status.mode === "LEASED" && (
        <Panel>
          <PanelHeader title="Tourniquets pilotés par ce PC" sub="Un seul PC écrit dans chaque tourniquet" />
          <FlexTable
            label="Tourniquets pilotés par ce PC"
            columns={[
              { label: "Tourniquet", flex: 1.6 },
              { label: "État", flex: 1.2 },
              { label: "Retraits", flex: 2 },
            ]}
            empty="Aucun : ce PC ne se connecte à aucun tourniquet."
            footer={status.readerOf.length > 0
              ? <span>Lit l'historique de : {status.readerOf.map((r) => r.name).join(", ")}</span>
              : undefined}
          >
            {status.drive.map((d) => (
              <FlexRow key={d.gymDeviceId}>
                <FlexCell flex={1.6}><IconCell icon={Router} tone="primary" title={d.name || d.gymDeviceId} /></FlexCell>
                <FlexCell flex={1.2}>
                  {d.state === "DRIVE"
                    ? <Chip tone="success">Piloté</Chip>
                    : <Chip tone="warning">En attente de la passation</Chip>}
                </FlexCell>
                <FlexCell flex={2}>
                  {d.addOnly
                    ? <Chip tone="warning">Ajouts seulement (relecture en attente)</Chip>
                    : <Chip tone="grey">Normaux</Chip>}
                </FlexCell>
              </FlexRow>
            ))}
            {status.release.map((r) => (
              <FlexRow key={`r${r.gymDeviceId}`}>
                <FlexCell flex={1.6}><IconCell icon={Router} tone="primary" title={r.name || r.gymDeviceId} /></FlexCell>
                <FlexCell flex={1.2}><Chip tone="info">Passation en cours</Chip></FlexCell>
                <FlexCell flex={2}><Chip tone="grey">Aucune écriture jusqu'à la fin de la passation</Chip></FlexCell>
              </FlexRow>
            ))}
          </FlexTable>
        </Panel>
      )}

      {(isReader || status.readerOf.length > 0) && (
        <Panel>
          <PanelHeader title="Historique des portes" sub="Depuis le serveur · tourniquets des PC pilotes suivis" />
          {historyError && <Note tone="error" className="mx-[18px] mt-3">Historique non chargé : {historyError}</Note>}
          <FlexTable
            label="Historique des portes"
            columns={[
              { label: "Date", flex: 1.1 },
              { label: "Tourniquet", flex: 1.4 },
              { label: "Membre", flex: 1.6 },
              { label: "Type", flex: 0.9 },
              { label: "Résultat", flex: 1.1, align: "right" },
            ]}
            empty={loadingHistory
              ? <Loader2 className="mx-auto h-5 w-5 animate-spin text-primary" />
              : "Aucun passage à afficher."}
            footer={
              <>
                {nextBefore && (
                  <ActionButton size="sm" icon={loadingHistory ? Loader2 : undefined} spin disabled={loadingHistory} onClick={() => loadHistory(nextBefore)}>
                    Plus
                  </ActionButton>
                )}
                <span>50 par page</span>
              </>
            }
          >
            {history.map((e) => {
              // Refusals in the entry screen's French short copy; the raw code stays in the tooltip.
              const deny = e.allowed ? null : aDenyCopy(e.reason || "");
              return (
                <FlexRow key={e.id} minHeight={50}>
                  <FlexCell flex={1.1}><span className="truncate font-mono text-[12.5px] text-muted-foreground">{formatDate(e.date)}</span></FlexCell>
                  <FlexCell flex={1.4}><CellText title={e.deviceName} /></FlexCell>
                  <FlexCell flex={1.6}><CellText title={e.userName || "—"} strong /></FlexCell>
                  <FlexCell flex={0.9}><CellText title={TYPE_FR[e.type] ?? e.type} /></FlexCell>
                  <FlexCell flex={1.1} align="right">
                    {deny
                      ? <Chip tone="error" title={e.reason || undefined}>{deny.short}</Chip>
                      : <Chip tone="success">Autorisé</Chip>}
                  </FlexCell>
                </FlexRow>
              );
            })}
          </FlexTable>
        </Panel>
      )}

      {status.lastError && <Note tone="warning">{status.lastError}</Note>}
      {error && <Note tone="warning">Statut non actualisé : {error}</Note>}
    </div>
  );
}
