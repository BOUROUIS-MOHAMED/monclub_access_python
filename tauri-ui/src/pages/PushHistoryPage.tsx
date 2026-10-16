import { useCallback, useEffect, useMemo, useState } from "react";
import { CircleCheck, CircleX, Eye, Hash, Loader2, RefreshCw, Send, TriangleAlert } from "lucide-react";

import { get } from "@/api/client";
import type {
  PushBatchHistoryResponse,
  PushBatchHistoryRow,
  PushBatchPinsResponse,
  PushPinHistoryRow,
} from "@/api/types";
import { usePageChrome } from "@/context/PageChromeContext";
import { ActionButton } from "@/components/ui/action-button";
import { Chip } from "@/components/ui/chip";
import { FilterSelect } from "@/components/ui/filter-select";
import { CellText, FlexCell, FlexRow, FlexTable } from "@/components/ui/flex-table";
import { KpiCard, KpiRow } from "@/components/ui/kpi-card";
import { Note, PageGrid, Panel, PanelHeader } from "@/components/ui/panel";
import { INK } from "@/components/ui/tone";
import {
  PIN_OPERATION, PUSH_POLICY, STATUS_FILTER_OPTIONS, formatDate, formatDuration, runStatus,
} from "@/lib/historyCopy";

const policyLabel = (p: string) => PUSH_POLICY[p] ?? p ?? "—";

export default function PushHistoryPage() {
  const [rows, setRows] = useState<PushBatchHistoryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("__all");
  const [deviceIdFilter, setDeviceIdFilter] = useState("");
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedBatch, setSelectedBatch] = useState<PushBatchHistoryRow | null>(null);
  const [selectedPins, setSelectedPins] = useState<PushPinHistoryRow[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = { page: "0", size: "100" };
      if (statusFilter !== "__all") params.status = statusFilter;
      if (deviceIdFilter.trim()) params.deviceId = deviceIdFilter.trim();
      const res = await get<PushBatchHistoryResponse>("/push-history", params);
      setRows(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [deviceIdFilter, statusFilter]);

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
      { success: 0, partial: 0, failed: 0, pinsFailed: 0 },
    );
  }, [rows]);

  const pinsFailed = useMemo(
    () => rows.reduce((sum, row) => sum + Number(row.pins_failed || 0), 0),
    [rows],
  );

  const openDetail = useCallback(async (batchId: number) => {
    setDetailLoading(true);
    try {
      const res = await get<PushBatchPinsResponse>(`/push-history/${batchId}/pins`);
      setSelectedBatch(res.batch);
      setSelectedPins(res.pins || []);
    } catch (err) {
      setError(String(err));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  usePageChrome(() => ({
    subtitle: `Ce poste → appareils · ${total} envoi${total > 1 ? "s" : ""} conservé${total > 1 ? "s" : ""} (30 jours)`,
    actions: (
      <>
        <div className="flex h-9 items-center gap-[7px] rounded-lg border border-grey/32 bg-card px-3 focus-within:border-primary">
          <Hash className="h-[17px] w-[17px] shrink-0 text-muted-foreground" aria-hidden="true" />
          <input
            value={deviceIdFilter}
            onChange={(event) => setDeviceIdFilter(event.target.value)}
            placeholder="N° d'appareil"
            aria-label="Filtrer par numéro d'appareil"
            className="w-[110px] bg-transparent text-[14px] font-bold text-foreground outline-none placeholder:font-semibold placeholder:text-muted-foreground"
          />
        </div>
        <FilterSelect label="Statut" value={statusFilter} options={STATUS_FILTER_OPTIONS} onChange={setStatusFilter} />
        <ActionButton kind="outline" icon={RefreshCw} spin={loading} onClick={() => void load()} disabled={loading}>
          Recharger
        </ActionButton>
      </>
    ),
  }), [total, deviceIdFilter, statusFilter, loading, load]);

  const filtered = statusFilter !== "__all" || !!deviceIdFilter.trim();
  const sel = selectedBatch;
  const selStatus = sel ? runStatus(sel.status) : null;

  return (
    <div className="flex flex-col gap-[18px]">
      {error && <Note tone="error">{error}</Note>}

      <KpiRow cols={4}>
        <KpiCard label="Envois chargés" value={rows.length} sub="les plus récents" icon={Send} tone="primary" />
        <KpiCard label="Réussis" value={stats.success} sub="sur les envois chargés" icon={CircleCheck} tone="success" />
        <KpiCard label="Partiels" value={stats.partial} sub="au moins un PIN en échec" icon={TriangleAlert} tone="warning" subTone={stats.partial > 0 ? "warning" : undefined} />
        <KpiCard label="PIN en échec" value={pinsFailed} sub="sur les envois chargés" icon={CircleX} tone="error" subTone={pinsFailed > 0 ? "error" : undefined} />
      </KpiRow>

      <PageGrid>
        <Panel className="col-span-7">
          <PanelHeader title="Envois récents vers les appareils" sub="Les 100 plus récents pour les filtres choisis" />
          <FlexTable
            label="Envois récents vers les appareils"
            columns={[
              { label: "Date", flex: 1.35 },
              { label: "Appareil", flex: 1.3 },
              { label: "Politique", flex: 1.1 },
              { label: "Statut", flex: 0.75 },
              { label: "PIN", flex: 0.75, align: "right" },
              { label: "", flex: 0.4, align: "right" },
            ]}
            empty={loading ? (
              <Loader2 className="mx-auto h-6 w-6 animate-spin text-primary" />
            ) : filtered ? (
              // Do not blame filters that are not set.
              "Aucun envoi trouvé pour les filtres actuels."
            ) : (
              <span className="block space-y-1">
                <span className="block">Aucun envoi enregistré.</span>
                <span className="block text-[12px]">
                  Les envois de ce poste vers les appareils apparaissent ici au fil des synchronisations.
                </span>
              </span>
            )}
          >
            {loading ? null : rows.map((row) => {
              const st = runStatus(row.status);
              return (
                <FlexRow key={row.id} selected={sel?.id === row.id}>
                  <FlexCell flex={1.35}>
                    <CellText title={formatDate(row.created_at)} sub={formatDuration(row.duration_ms)} mono subMono titleClassName="text-[12.5px] text-muted-foreground" />
                  </FlexCell>
                  <FlexCell flex={1.3}><CellText title={row.device_name || "—"} sub={`appareil #${row.device_id}`} strong /></FlexCell>
                  <FlexCell flex={1.1}><CellText title={policyLabel(row.policy)} sub={row.policy} subMono /></FlexCell>
                  <FlexCell flex={0.75}><Chip tone={st.tone}>{st.l}</Chip></FlexCell>
                  <FlexCell flex={0.75} align="right">
                    <CellText
                      title={`${row.pins_success} / ${row.pins_attempted}`}
                      sub={row.pins_failed > 0 ? `${row.pins_failed} KO` : ""}
                      titleClassName="font-bold"
                      subClassName={INK.error}
                    />
                  </FlexCell>
                  <FlexCell flex={0.4} align="right">
                    <ActionButton kind="outline" size="xs" iconOnly icon={Eye} title="Voir le détail" onClick={() => void openDetail(row.id)}>Voir le détail</ActionButton>
                  </FlexCell>
                </FlexRow>
              );
            })}
          </FlexTable>
        </Panel>

        <Panel className="col-span-5">
          {detailLoading && !sel ? (
            <div className="flex justify-center py-10"><Loader2 className="h-6 w-6 animate-spin text-primary" /></div>
          ) : sel && selStatus ? (
            <>
              <PanelHeader
                title={`${sel.device_name || `Appareil #${sel.device_id}`} · ${selStatus.l}`}
                sub={[
                  formatDate(sel.created_at),
                  formatDuration(sel.duration_ms),
                  policyLabel(sel.policy),
                  sel.sync_run_id != null ? `run #${sel.sync_run_id}` : "",
                ].filter(Boolean).join(" · ")}
              />
              <div className="flex flex-wrap gap-1.5 px-[18px] pt-3">
                <Chip tone="grey">{sel.pins_attempted} tentés</Chip>
                <Chip tone="success">{sel.pins_success} OK</Chip>
                <Chip tone={sel.pins_failed > 0 ? "error" : "grey"}>{sel.pins_failed} KO</Chip>
              </div>
              {sel.error_message && <Note tone="warning" className="mx-[18px] mt-3">{sel.error_message}</Note>}
              <FlexTable
                label="Détail par PIN"
                columns={[
                  { label: "PIN", flex: 0.6 },
                  { label: "Membre", flex: 1.6 },
                  { label: "Statut", flex: 0.8, align: "right" },
                ]}
                empty="Aucun détail par PIN pour cet envoi. Les terminaux autonomes n'enregistrent que le total."
              >
                {selectedPins.map((pin) => {
                  const ps = runStatus(pin.status);
                  const op = PIN_OPERATION[pin.operation] ?? pin.operation;
                  return (
                    <FlexRow key={pin.id} minHeight={52}>
                      <FlexCell flex={0.6}><CellText title={pin.pin} mono /></FlexCell>
                      <FlexCell flex={1.6} title={pin.error_message || ""}>
                        <CellText
                          title={pin.full_name || "—"}
                          sub={pin.error_message || `${op} · ${formatDuration(pin.duration_ms)}`}
                          strong
                          subClassName={pin.error_message ? INK.error : undefined}
                        />
                      </FlexCell>
                      <FlexCell flex={0.8} align="right"><Chip tone={ps.tone}>{ps.l}</Chip></FlexCell>
                    </FlexRow>
                  );
                })}
              </FlexTable>
            </>
          ) : (
            <>
              <PanelHeader title="Détail par PIN" />
              <div className="px-[18px] pb-5 pt-2 text-[13.5px] text-muted-foreground">
                Choisissez un envoi (<Eye className="inline h-3.5 w-3.5 align-[-2px]" />) pour voir chaque PIN écrit sur l'appareil.
              </div>
            </>
          )}
        </Panel>
      </PageGrid>
    </div>
  );
}
