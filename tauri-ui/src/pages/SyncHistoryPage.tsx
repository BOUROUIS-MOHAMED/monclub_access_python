import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity, CircleCheck, CircleX, Eye, ListChecks, Loader2, Play, RefreshCw, Router, ScrollText, TriangleAlert, Users,
} from "lucide-react";

import { get } from "@/api/client";
import type { SyncRunHistoryResponse, SyncRunHistoryRow } from "@/api/types";
import { usePageChrome } from "@/context/PageChromeContext";
import { ActionButton } from "@/components/ui/action-button";
import { Chip } from "@/components/ui/chip";
import { DialogFrame, DialogSection } from "@/components/ui/dialog-frame";
import { FilterSelect } from "@/components/ui/filter-select";
import { CellText, FlexCell, FlexRow, FlexTable } from "@/components/ui/flex-table";
import { KpiCard, KpiRow } from "@/components/ui/kpi-card";
import { ListRow, Note, PageGrid, Panel, PanelHeader, PanelList } from "@/components/ui/panel";
import {
  RUN_TYPE, STATUS_FILTER_OPTIONS, TRIGGER_SOURCE, formatDate, formatDuration, runStatus,
} from "@/lib/historyCopy";

function parseJsonBlock(value: string | null | undefined): string {
  if (!value) return "—";
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function clockOf(value: string | null | undefined): string {
  if (!value) return "—";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? value : dt.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

const sourceLabel = (s: string) => TRIGGER_SOURCE[s] ?? s ?? "—";
const typeLabel = (t: string) => RUN_TYPE[t] ?? t ?? "—";

const RUN_TYPE_OPTIONS = [
  { value: "__all", label: "tous" },
  { value: "PERIODIC", label: "Périodique" },
  { value: "TRIGGERED", label: "Déclenché" },
  { value: "HARD_RESET", label: "Réinitialisation" },
];

export default function SyncHistoryPage() {
  const navigate = useNavigate();
  const [rows, setRows] = useState<SyncRunHistoryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("__all");
  const [runTypeFilter, setRunTypeFilter] = useState("__all");
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedRun, setSelectedRun] = useState<SyncRunHistoryRow | null>(null);
  const [rawOpen, setRawOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = { page: "0", size: "100" };
      if (statusFilter !== "__all") params.status = statusFilter;
      if (runTypeFilter !== "__all") params.runType = runTypeFilter;
      const res = await get<SyncRunHistoryResponse>("/sync-history", params);
      setRows(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [runTypeFilter, statusFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const stats = useMemo(() => {
    return rows.reduce(
      (acc, row) => {
        const status = String(row.status || "").toUpperCase();
        if (status === "SUCCESS") acc.success += 1;
        else if (status === "PARTIAL") acc.partial += 1;
        else if (status === "FAILED") acc.failed += 1;
        return acc;
      },
      { success: 0, partial: 0, failed: 0 },
    );
  }, [rows]);

  // Newest first (the API order): the first SUCCESS / FAILED among the loaded runs.
  const lastOk = useMemo(() => rows.find((r) => String(r.status || "").toUpperCase() === "SUCCESS") ?? null, [rows]);
  const lastFailed = useMemo(() => rows.find((r) => String(r.status || "").toUpperCase() === "FAILED") ?? null, [rows]);

  const openDetail = useCallback(async (id: number) => {
    setDetailLoading(true);
    try {
      const res = await get<{ ok: boolean; item: SyncRunHistoryRow }>(`/sync-history/${id}`);
      setSelectedRun(res.item);
    } catch (err) {
      setError(String(err));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  usePageChrome(() => ({
    subtitle: `Serveur → ce poste · ${total} run${total > 1 ? "s" : ""} conservé${total > 1 ? "s" : ""} (30 jours)`,
    actions: (
      <>
        <FilterSelect label="Statut" value={statusFilter} options={STATUS_FILTER_OPTIONS} onChange={setStatusFilter} />
        <FilterSelect label="Type" value={runTypeFilter} options={RUN_TYPE_OPTIONS} onChange={setRunTypeFilter} />
        <ActionButton kind="outline" icon={RefreshCw} spin={loading} onClick={() => void load()} disabled={loading}>
          Recharger
        </ActionButton>
      </>
    ),
  }), [total, statusFilter, runTypeFilter, loading, load]);

  const sel = selectedRun;
  const selStatus = sel ? runStatus(sel.status) : null;

  return (
    <div className="flex flex-col gap-[18px]">
      {error && <Note tone="error">{error}</Note>}

      <KpiRow cols={4}>
        <KpiCard
          label="Dernière réussie"
          value={lastOk ? clockOf(lastOk.created_at) : "—"}
          sub={lastOk ? `${formatDate(lastOk.created_at).slice(0, 10)} · ${formatDuration(lastOk.duration_ms)}` : "aucune dans les runs chargés"}
          icon={CircleCheck}
          tone="success"
        />
        <KpiCard label="Runs chargés" value={rows.length} sub={`les plus récents · ${stats.success} réussi${stats.success > 1 ? "s" : ""}`} icon={Activity} tone="primary" />
        <KpiCard label="Partiels" value={stats.partial} sub="sur les runs chargés" icon={TriangleAlert} tone="warning" subTone={stats.partial > 0 ? "warning" : undefined} />
        <KpiCard
          label="Échecs"
          value={stats.failed}
          sub={lastFailed ? `dernier à ${clockOf(lastFailed.created_at)}` : "sur les runs chargés"}
          icon={CircleX}
          tone="error"
          subTone={stats.failed > 0 ? "error" : undefined}
        />
      </KpiRow>

      <PageGrid>
        <Panel className="col-span-8">
          <PanelHeader title="Synchronisations" sub="Les 100 plus récentes pour les filtres choisis" />
          <FlexTable
            label="Synchronisations"
            columns={[
              { label: "Déclenché le", flex: 1.4 },
              { label: "Source", flex: 1.5 },
              { label: "Statut", flex: 0.75 },
              { label: "Membres", flex: 0.85, align: "right" },
              { label: "Durée", flex: 0.6, align: "right" },
              { label: "", flex: 0.4, align: "right" },
            ]}
            empty={loading
              ? <Loader2 className="mx-auto h-6 w-6 animate-spin text-primary" />
              : "Aucun run trouvé pour les filtres actuels."}
          >
            {loading ? null : rows.map((row) => {
              const st = runStatus(row.status);
              return (
                <FlexRow key={row.id} selected={sel?.id === row.id}>
                  <FlexCell flex={1.4}><CellText title={formatDate(row.created_at)} mono titleClassName="text-[12.5px] text-muted-foreground" /></FlexCell>
                  <FlexCell flex={1.5}>
                    <CellText title={sourceLabel(row.trigger_source)} sub={`${typeLabel(row.run_type)} · ${row.trigger_source}`} strong />
                  </FlexCell>
                  <FlexCell flex={0.75}><Chip tone={st.tone}>{st.l}</Chip></FlexCell>
                  <FlexCell flex={0.85} align="right">
                    <CellText title={`${row.members_changed} / ${row.members_total}`} sub="changés / total" titleClassName="font-bold" />
                  </FlexCell>
                  <FlexCell flex={0.6} align="right"><CellText title={formatDuration(row.duration_ms)} mono titleClassName="text-[12.5px] text-muted-foreground" /></FlexCell>
                  <FlexCell flex={0.4} align="right">
                    <ActionButton kind="outline" size="xs" iconOnly icon={Eye} title="Voir le détail" onClick={() => void openDetail(row.id)}>Voir le détail</ActionButton>
                  </FlexCell>
                </FlexRow>
              );
            })}
          </FlexTable>
        </Panel>

        <Panel className="col-span-4">
          {detailLoading && !sel ? (
            <div className="flex justify-center py-10"><Loader2 className="h-6 w-6 animate-spin text-primary" /></div>
          ) : sel && selStatus ? (
            <>
              <PanelHeader
                title={`Run du ${formatDate(sel.created_at)}`}
                sub={`${typeLabel(sel.run_type)} · ${selStatus.l} · ${formatDuration(sel.duration_ms)}`}
              />
              <PanelList>
                <ListRow icon={Play} tone="primary" wrap title="Déclenchement" sub={`${sourceLabel(sel.trigger_source)} (${sel.trigger_source})`} />
                <ListRow
                  icon={ListChecks}
                  tone={selStatus.tone}
                  wrap
                  title="Résultat"
                  sub={sel.error_message ? `Erreur : ${sel.error_message}` : "Aucune erreur enregistrée"}
                  trailing={<Chip tone={selStatus.tone}>{selStatus.l}</Chip>}
                />
                <ListRow icon={Users} tone="grey" wrap title="Membres" sub={`${sel.members_changed} changés sur ${sel.members_total}`} />
                <ListRow
                  icon={Router}
                  tone="grey"
                  wrap
                  title="Appareils lancés"
                  sub={`${sel.devices_synced} envoi${sel.devices_synced > 1 ? "s" : ""} démarré${sel.devices_synced > 1 ? "s" : ""} (lancés, pas confirmés) · le résultat de chaque appareil est dans Historique push`}
                  actions={<ActionButton kind="outline" size="sm" onClick={() => navigate("/push-history")}>Historique push</ActionButton>}
                />
                <ListRow
                  icon={ScrollText}
                  tone="grey"
                  wrap
                  title="Trigger hint et résumé brut"
                  sub="JSON enregistré avec le run"
                  actions={<ActionButton kind="outline" size="sm" onClick={() => setRawOpen(true)}>Voir le JSON</ActionButton>}
                />
              </PanelList>
            </>
          ) : (
            <>
              <PanelHeader title="Détail du run" />
              <div className="px-[18px] pb-5 pt-2 text-[13.5px] text-muted-foreground">
                Choisissez un run (<Eye className="inline h-3.5 w-3.5 align-[-2px]" />) pour voir son déclenchement, son résultat et le JSON enregistré.
              </div>
            </>
          )}
        </Panel>
      </PageGrid>

      <DialogFrame
        open={rawOpen && !!sel}
        onOpenChange={setRawOpen}
        width={600}
        title="Run de synchronisation"
        sub="JSON enregistré avec le run"
        footer={<ActionButton kind="dark" className="px-4" onClick={() => setRawOpen(false)}>Fermer</ActionButton>}
      >
        <DialogSection>Trigger hint</DialogSection>
        <pre className="whitespace-pre-wrap break-all rounded-lg bg-muted p-3 font-mono text-[12px]">{parseJsonBlock(sel?.trigger_hint)}</pre>
        <DialogSection>Résumé brut</DialogSection>
        <pre className="whitespace-pre-wrap break-all rounded-lg bg-muted p-3 font-mono text-[12px]">{parseJsonBlock(sel?.raw_response)}</pre>
      </DialogFrame>
    </div>
  );
}
