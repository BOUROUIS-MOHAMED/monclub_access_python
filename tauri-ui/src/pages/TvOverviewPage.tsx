import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Monitor, Play, RefreshCw, RotateCcw, Square, Trash2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  createTvHostBinding,
  deleteTvHostBinding,
  getTvHostBindings,
  getTvHostMonitors,
  postTvHostBindingRuntimeEvent,
  refreshTvHostMonitors,
  restartTvHostBinding,
  startTvHostBinding,
  stopTvHostBinding,
  updateTvHostBinding,
  getTvHostBindingSupportSummary,
  getTvObservabilityOverview,
  runTvHostBindingSupportAction,
  getTvHostBindingSupportActionHistory,
  getTvHardeningPreflight,
  getTvHardeningStartupLatest,
  runTvHardeningStartupReconciliation,
  getTvHardeningQueryChecks,
} from "@/api/tv";
import type { TvHostBindingRow, TvHostMonitorRow, TvBindingSupportSummaryResponse, TvSupportActionType, TvObservabilityOverviewResponse } from "@/api/types";
import { closeBindingWindow, detectHostMonitors, openBindingWindow, type TvDetectedMonitor } from "@/lib/tv-host-orchestrator";

function boolish(v: unknown): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    return s === "1" || s === "true" || s === "yes" || s === "on";
  }
  return false;
}

function runtimeBadge(state: string): "success" | "warning" | "destructive" | "secondary" {
  const s = String(state || "").toUpperCase();
  if (s === "RUNNING") return "success";
  if (s === "STARTING" || s === "STOPPING") return "warning";
  if (s === "STOPPED" || s === "OFFLINE" || s === "UNKNOWN") return "secondary";
  return "destructive";
}


function healthBadge(state: string): "success" | "warning" | "destructive" | "secondary" {
  const s = String(state || "").toUpperCase();
  if (s === "HEALTHY") return "success";
  if (s === "WARNING" || s === "DEGRADED") return "warning";
  if (s === "STOPPED" || s === "OFFLINE" || s === "UNKNOWN") return "secondary";
  return "destructive";
}

function shortValue(v: unknown, max = 12): string {
  const s = String(v || "");
  if (s.length <= max) return s;
  return `${s.slice(0, max)}...`;
}

export default function TvOverviewPage() {
  const [bindings, setBindings] = useState<TvHostBindingRow[]>([]);
  const [monitors, setMonitors] = useState<TvHostMonitorRow[]>([]);
  const [detected, setDetected] = useState<TvDetectedMonitor[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [supportByBinding, setSupportByBinding] = useState<Record<number, TvBindingSupportSummaryResponse>>({});
  const [selectedSupportBindingId, setSelectedSupportBindingId] = useState<number | null>(null);
  const [supportHistory, setSupportHistory] = useState<Array<Record<string, any>>>([]);
  const [supportHistoryTotal, setSupportHistoryTotal] = useState(0);
  const [supportBusy, setSupportBusy] = useState(false);
  const [observability, setObservability] = useState<TvObservabilityOverviewResponse | null>(null);
  const [startupLatest, setStartupLatest] = useState<Record<string, any> | null>(null);
  const [preflight, setPreflight] = useState<Record<string, any> | null>(null);
  const [queryChecks, setQueryChecks] = useState<Record<string, any> | null>(null);
  const [hardeningBusy, setHardeningBusy] = useState(false);

  const [newScreenId, setNewScreenId] = useState("");
  const [newScreenName, setNewScreenName] = useState("");
  const [newMonitorId, setNewMonitorId] = useState("");
  const [newAutostart, setNewAutostart] = useState(true);
  const [newEnabled, setNewEnabled] = useState(true);
  const [newFullscreen, setNewFullscreen] = useState(true);

  const loadSupportSummary = useCallback(async (bindingId: number) => {
    if (!(bindingId > 0)) return;
    try {
      const summary = await getTvHostBindingSupportSummary(bindingId);
      setSupportByBinding((prev) => ({ ...prev, [bindingId]: summary }));
    } catch {
      // keep support summary best-effort
    }
  }, []);

  const refreshSupportHistory = useCallback(async (bindingId: number) => {
    if (!(bindingId > 0)) {
      setSupportHistory([]);
      setSupportHistoryTotal(0);
      return;
    }
    try {
      const history = await getTvHostBindingSupportActionHistory(bindingId, { limit: 30, offset: 0 });
      setSupportHistory(history.rows || []);
      setSupportHistoryTotal(Number(history.total || 0));
    } catch {
      setSupportHistory([]);
      setSupportHistoryTotal(0);
    }
  }, []);

  const refreshSupportMapForBindings = useCallback(async (rows: TvHostBindingRow[]) => {
    if (!rows.length) {
      setSupportByBinding({});
      return;
    }
    const entries = await Promise.all(
      rows.map(async (b) => {
        try {
          const summary = await getTvHostBindingSupportSummary(b.id);
          return [b.id, summary] as const;
        } catch {
          return [b.id, { ok: false } as TvBindingSupportSummaryResponse] as const;
        }
      })
    );
    const map: Record<number, TvBindingSupportSummaryResponse> = {};
    for (const [id, summary] of entries) map[id] = summary;
    setSupportByBinding(map);
  }, []);
  const monitorMap = useMemo(() => {
    const m = new Map<string, TvDetectedMonitor>();
    for (const row of detected) m.set(row.monitorId, row);
    return m;
  }, [detected]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [apiMonitors, apiBindings, localMonitors, obs, preflightRes, startup, checks] = await Promise.all([
        getTvHostMonitors(),
        getTvHostBindings(),
        detectHostMonitors(),
        getTvObservabilityOverview(),
        getTvHardeningPreflight(),
        getTvHardeningStartupLatest(),
        getTvHardeningQueryChecks({ limit: 200 }),
      ]);
      setMonitors((apiMonitors.rows || []) as TvHostMonitorRow[]);
      const bindingRows = (apiBindings.rows || []) as TvHostBindingRow[];
      setBindings(bindingRows);
      await refreshSupportMapForBindings(bindingRows);
      setObservability(obs);
      setPreflight((preflightRes && (preflightRes as any).status) ? (preflightRes as Record<string, any>) : null);
      setStartupLatest((startup && (startup as any).ok) ? (startup as Record<string, any>) : null);
      setQueryChecks((checks && (checks as any).ok) ? (checks as Record<string, any>) : null);
      setDetected(localMonitors || []);
      if (!newMonitorId && localMonitors.length > 0) {
        setNewMonitorId(localMonitors[0].monitorId);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [newMonitorId, refreshSupportMapForBindings]);

  const refreshMonitors = useCallback(async () => {
    const local = await detectHostMonitors();
    setDetected(local || []);
    const refreshed = await refreshTvHostMonitors(local || []);
    setMonitors((refreshed.rows || []) as TvHostMonitorRow[]);
    if (!newMonitorId && local.length > 0) {
      setNewMonitorId(local[0].monitorId);
    }
  }, [newMonitorId, refreshSupportMapForBindings]);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      await refreshMonitors();
      const [apiBindings, obs, preflightRes, startup, checks] = await Promise.all([
        getTvHostBindings(),
        getTvObservabilityOverview(),
        getTvHardeningPreflight(),
        getTvHardeningStartupLatest(),
        getTvHardeningQueryChecks({ limit: 200 }),
      ]);
      const bindingRows = (apiBindings.rows || []) as TvHostBindingRow[];
      setBindings(bindingRows);
      await refreshSupportMapForBindings(bindingRows);
      setObservability(obs);
      setPreflight((preflightRes && (preflightRes as any).status) ? (preflightRes as Record<string, any>) : null);
      setStartupLatest((startup && (startup as any).ok) ? (startup as Record<string, any>) : null);
      setQueryChecks((checks && (checks as any).ok) ? (checks as Record<string, any>) : null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [refreshMonitors, refreshSupportMapForBindings]);

  const onRunStartupReconciliation = useCallback(async () => {
    setHardeningBusy(true);
    setError(null);
    setInfo(null);
    try {
      const res = await runTvHardeningStartupReconciliation({ triggerSource: "UI_OPERATOR" });
      if (!res.ok) {
        throw new Error(res.error || "Startup reconciliation failed");
      }
      setStartupLatest(res as unknown as Record<string, any>);
      const checks = await getTvHardeningQueryChecks({ limit: 200 });
      const pf = await getTvHardeningPreflight();
      setPreflight((pf && (pf as any).status) ? (pf as unknown as Record<string, any>) : null);
      setQueryChecks((checks as unknown as Record<string, any>) || null);
      setInfo(`Startup reconciliation ${String((res as any).status || "completed")}.`);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setHardeningBusy(false);
    }
  }, [loadAll]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);
  useEffect(() => {
    if (selectedSupportBindingId && selectedSupportBindingId > 0) {
      void refreshSupportHistory(selectedSupportBindingId);
      void loadSupportSummary(selectedSupportBindingId);
    } else {
      setSupportHistory([]);
      setSupportHistoryTotal(0);
    }
  }, [selectedSupportBindingId, refreshSupportHistory, loadSupportSummary]);

  const emitRuntimeEvent = useCallback(async (bindingId: number, eventType: string, payload?: { windowId?: string; errorCode?: string; errorMessage?: string }) => {
    try {
      await postTvHostBindingRuntimeEvent(bindingId, { eventType, ...(payload || {}) });
    } catch {
      // runtime event best-effort
    }
  }, []);

  const startWindow = useCallback(async (binding: TvHostBindingRow) => {
    const monitor = monitorMap.get(String(binding.monitor_id || "")) || null;
    const opened = await openBindingWindow(binding, monitor);
    if (opened.ok) {
      await emitRuntimeEvent(binding.id, "WINDOW_LAUNCHED", { windowId: opened.windowId });
      return;
    }
    const code = opened.error === "MONITOR_NOT_FOUND" ? "MONITOR_NOT_FOUND" : "WINDOW_LAUNCH_FAILED";
    await emitRuntimeEvent(binding.id, "WINDOW_LAUNCH_FAILED", { errorCode: code, errorMessage: opened.error || code });
  }, [emitRuntimeEvent, monitorMap]);

  const stopWindow = useCallback(async (binding: TvHostBindingRow) => {
    const closed = await closeBindingWindow(binding);
    if (closed.ok) {
      await emitRuntimeEvent(binding.id, "WINDOW_CLOSED", { windowId: closed.windowId });
    }
  }, [emitRuntimeEvent]);

  const onCreateBinding = useCallback(async () => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      const sid = Number(newScreenId);
      if (!Number.isFinite(sid) || sid <= 0) {
        throw new Error("Screen ID must be a positive number.");
      }
      const mon = detected.find((m) => m.monitorId === newMonitorId) || null;
      const res = await createTvHostBinding({
        screenId: sid,
        screenName: newScreenName.trim() || undefined,
        monitorId: mon?.monitorId,
        monitorLabel: mon?.monitorLabel,
        monitorIndex: mon?.monitorIndex,
        enabled: newEnabled,
        autostart: newAutostart,
        fullscreen: newFullscreen,
      });
      setInfo(`Binding #${res.binding.id} created.`);
      setNewScreenId("");
      setNewScreenName("");
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [newScreenId, newScreenName, newMonitorId, newEnabled, newAutostart, newFullscreen, detected, loadAll]);

  const onStart = useCallback(async (binding: TvHostBindingRow) => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      await startTvHostBinding(binding.id);
      await startWindow(binding);
      setInfo(`Binding #${binding.id} start requested.`);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [loadAll, startWindow]);

  const onStop = useCallback(async (binding: TvHostBindingRow) => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      await stopWindow(binding);
      await stopTvHostBinding(binding.id);
      setInfo(`Binding #${binding.id} stopped.`);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [loadAll, stopWindow]);

  const onRestart = useCallback(async (binding: TvHostBindingRow) => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      await stopWindow(binding);
      await restartTvHostBinding(binding.id);
      await startWindow(binding);
      setInfo(`Binding #${binding.id} restarted.`);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [loadAll, startWindow, stopWindow]);

  const onDelete = useCallback(async (binding: TvHostBindingRow) => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      await stopWindow(binding);
      await deleteTvHostBinding(binding.id);
      setInfo(`Binding #${binding.id} removed.`);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [loadAll, stopWindow]);

  const onToggle = useCallback(async (binding: TvHostBindingRow, field: "enabled" | "autostart", value: boolean) => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      await updateTvHostBinding(binding.id, { [field]: value } as any);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [loadAll]);

  const onRebind = useCallback(async (binding: TvHostBindingRow, targetMonitorId: string) => {
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      if (!targetMonitorId || targetMonitorId === String(binding.monitor_id || "")) {
        return;
      }
      const wasRunning = String(binding.desired_state || "").toUpperCase() === "RUNNING" || boolish(binding.window_exists);
      const mon = detected.find((m) => m.monitorId === targetMonitorId) || null;
      if (!mon) throw new Error("Target monitor not found locally.");

      if (wasRunning) {
        await stopWindow(binding);
        await stopTvHostBinding(binding.id);
      }

      await updateTvHostBinding(binding.id, {
        monitorId: mon.monitorId,
        monitorLabel: mon.monitorLabel,
        monitorIndex: mon.monitorIndex,
      });

      if (wasRunning) {
        await startTvHostBinding(binding.id);
        const latest = (await getTvHostBindings()).rows.find((x) => x.id === binding.id) as TvHostBindingRow | undefined;
        if (latest) {
          await startWindow(latest);
        }
      }

      setInfo(`Binding #${binding.id} monitor reassigned.`);
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [detected, loadAll, startWindow, stopWindow]);


  const runSupportAction = useCallback(async (
    binding: TvHostBindingRow,
    actionType: TvSupportActionType,
    options?: Record<string, any>,
    requireConfirm = false
  ) => {
    if (requireConfirm) {
      const ok = window.confirm(`Confirm action ${actionType} for binding #${binding.id}?`);
      if (!ok) return;
    }
    setSupportBusy(true);
    setError(null);
    setInfo(null);
    try {
      const res = await runTvHostBindingSupportAction(binding.id, {
        actionType,
        options: options || {},
        confirm: requireConfirm,
        triggeredBy: "LOCAL_OPERATOR",
      });
      const msg = String(res.message || `${actionType}: ${res.result}`);
      if (String(res.result || "").toUpperCase() === "FAILED") {
        setError(msg);
      } else {
        setInfo(msg);
      }
      if (res.summary) {
        setSupportByBinding((prev) => ({ ...prev, [binding.id]: res.summary as TvBindingSupportSummaryResponse }));
      } else {
        await loadSupportSummary(binding.id);
      }
      if (selectedSupportBindingId === binding.id) {
        await refreshSupportHistory(binding.id);
      }
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSupportBusy(false);
    }
  }, [loadAll, loadSupportSummary, refreshSupportHistory, selectedSupportBindingId]);

  const onRestartPlayerWindowSupport = useCallback(async (binding: TvHostBindingRow) => {
    const ok = window.confirm(`Confirm RESTART_PLAYER_WINDOW for binding #${binding.id}?`);
    if (!ok) return;

    setSupportBusy(true);
    setError(null);
    setInfo(null);
    const correlationId = `tvsup_ui_${binding.id}_${Date.now()}`;
    try {
      await stopWindow(binding);
      await postTvHostBindingRuntimeEvent(binding.id, {
        eventType: "WINDOW_CLOSED",
        windowId: `tv-player-binding-${binding.id}`,
        correlationId,
      });

      await restartTvHostBinding(binding.id);
      const latest = (await getTvHostBindings()).rows.find((x) => x.id === binding.id) as TvHostBindingRow | undefined;
      if (!latest) throw new Error("Binding row missing after restart request.");

      await startWindow(latest);
      await postTvHostBindingRuntimeEvent(binding.id, {
        eventType: "WINDOW_LAUNCHED",
        windowId: `tv-player-binding-${binding.id}`,
        correlationId,
      });

      await runTvHostBindingSupportAction(binding.id, {
        actionType: "RESTART_PLAYER_WINDOW",
        options: { clientExecuted: true, correlationId },
        confirm: true,
        triggeredBy: "LOCAL_OPERATOR",
      });

      setInfo(`Player window restarted for binding #${binding.id}.`);
      await loadSupportSummary(binding.id);
      if (selectedSupportBindingId === binding.id) {
        await refreshSupportHistory(binding.id);
      }
      await loadAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSupportBusy(false);
    }
  }, [loadAll, loadSupportSummary, refreshSupportHistory, selectedSupportBindingId, startWindow, stopWindow]);

  const onAutostartReconcile = useCallback(async () => {
    try {
      const localMon = await detectHostMonitors();
      setDetected(localMon);
      await refreshTvHostMonitors(localMon);
      const rows = (await getTvHostBindings()).rows || [];
      for (const row of rows) {
        const desired = String(row.desired_state || "").toUpperCase();
        const enabled = boolish(row.enabled);
        const autostart = boolish(row.autostart);
        const runtime = String(row.runtime_state || "").toUpperCase();

        if (enabled && autostart && desired === "RUNNING" && runtime !== "RUNNING") {
          await startWindow(row);
        }
        if ((desired === "STOPPED" || !enabled) && boolish(row.window_exists)) {
          await stopWindow(row);
        }
      }
      await load();
    } catch {
      // keep silent in background reconcile
    }
  }, [load, startWindow, stopWindow]);

  useEffect(() => {
    void onAutostartReconcile();
    const id = window.setInterval(() => {
      void onAutostartReconcile();
    }, 15000);
    return () => window.clearInterval(id);
  }, [onAutostartReconcile]);
                return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">TV Host Overview</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void loadAll()} disabled={loading || busy}>
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Refresh
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Host Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {info && (
        <Alert>
          <AlertTitle>Info</AlertTitle>
          <AlertDescription>{info}</AlertDescription>
        </Alert>
      )}
      <Card>
        <CardHeader><CardTitle className="text-sm">TV Operational Snapshot</CardTitle></CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <div className="border rounded p-2">
            <div className="text-muted-foreground">Total Screens</div>
            <div className="text-2xl font-semibold">{observability?.totalScreens ?? 0}</div>
          </div>
          <div className="border rounded p-2">
            <div className="text-muted-foreground">Online Screens</div>
            <div className="text-2xl font-semibold">{observability?.onlineScreens ?? 0}</div>
          </div>
          <div className="border rounded p-2">
            <div className="text-muted-foreground">Health Buckets</div>
            <div className="flex flex-wrap gap-1 mt-1">
              {Object.entries(observability?.healthCounts || {}).map(([k, v]) => (
                <Badge key={k} variant={healthBadge(String(k))}>{k}:{String(v)}</Badge>
              ))}
              {Object.keys(observability?.healthCounts || {}).length === 0 && <span className="text-muted-foreground">No data</span>}
            </div>
          </div>
          <div className="border rounded p-2 flex flex-col gap-1">
            <Link to="/tv/fleet-health" className="text-primary underline">Open Fleet Health</Link>
            <Link to="/tv/runtime" className="text-primary underline">Open Runtime Diagnostics</Link>
            <Link to="/tv/proof" className="text-primary underline">Open Proof / Stats</Link>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm">Deployment Preflight / Startup Hardening</CardTitle>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void onRunStartupReconciliation()}
            disabled={hardeningBusy || loading}
          >
            <RefreshCw className={`h-4 w-4 ${hardeningBusy ? "animate-spin" : ""}`} />
            Run Reconciliation
          </Button>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <div className="border rounded p-2">
            <div className="text-muted-foreground">Deployment Preflight</div>
            <div className="mt-1">Status: {String((preflight as any)?.status || "-")}</div>
            <div>Blockers: {String(((preflight as any)?.blockers || []).length)}</div>
            <div>Warnings: {String(((preflight as any)?.warnings || []).length)}</div>
            <div className="text-muted-foreground mt-1 max-w-[260px] truncate" title={String((((preflight as any)?.blockers || [])[0] || {}).message || "")}>Top blocker: {String((((preflight as any)?.blockers || [])[0] || {}).code || "-")}</div>
          </div>
          <div className="border rounded p-2">
            <div className="text-muted-foreground">Latest Startup Run</div>
            <div className="mt-1">Status: {String((startupLatest as any)?.status || "-")}</div>
            <div>Failed Phases: {String((startupLatest as any)?.failedPhaseCount ?? "-")}</div>
            <div className="text-muted-foreground mt-1">
              Corr: {shortValue((startupLatest as any)?.correlationId || "-", 18)}
            </div>
          </div>
          <div className="border rounded p-2">
            <div className="text-muted-foreground">Startup Phases</div>
            <div className="flex flex-wrap gap-1 mt-1">
              {(((startupLatest as any)?.phases as any[]) || []).map((p, idx) => (
                <Badge key={`${String((p as any)?.phase || "phase")}-${idx}`} variant={String((p as any)?.status || "").toUpperCase() === "SUCCEEDED" ? "success" : "destructive"}>
                  {String((p as any)?.phase || "phase")}:{String((p as any)?.status || "-")}
                </Badge>
              ))}
              {(!((startupLatest as any)?.phases) || ((startupLatest as any)?.phases as any[]).length === 0) && (
                <span className="text-muted-foreground">No startup run yet.</span>
              )}
            </div>
          </div>
          <div className="border rounded p-2">
            <div className="text-muted-foreground">Query Responsiveness</div>
            {queryChecks && (queryChecks as any).checksMs ? (
              <div className="space-y-1 mt-1">
                {Object.entries((queryChecks as any).checksMs || {}).map(([k, v]) => (
                  <div key={k}>
                    {k}: {String(v)} ms
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-1 text-muted-foreground">No query check data.</div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Create Binding</CardTitle></CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-7 gap-3 items-end">
          <div>
            <p className="text-xs text-muted-foreground mb-1">Screen ID</p>
            <Input value={newScreenId} onChange={(e) => setNewScreenId(e.target.value)} placeholder="e.g. 101" />
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Screen Name</p>
            <Input value={newScreenName} onChange={(e) => setNewScreenName(e.target.value)} placeholder="Front Desk TV" />
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Monitor</p>
            <Select value={newMonitorId} onValueChange={setNewMonitorId}>
              <SelectTrigger><SelectValue placeholder="Select monitor" /></SelectTrigger>
              <SelectContent>
                {detected.map((m) => (
                  <SelectItem key={m.monitorId} value={m.monitorId}>{m.monitorLabel} ({m.width}x{m.height})</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={newEnabled} onCheckedChange={setNewEnabled} />
            <span className="text-sm">Enabled</span>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={newAutostart} onCheckedChange={setNewAutostart} />
            <span className="text-sm">Autostart</span>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={newFullscreen} onCheckedChange={setNewFullscreen} />
            <span className="text-sm">Fullscreen</span>
          </div>
          <div>
            <Button className="w-full" onClick={() => void onCreateBinding()} disabled={busy}>Create</Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Bindings ({bindings.length})</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Binding</TableHead>
                <TableHead>Screen</TableHead>
                <TableHead>Monitor</TableHead>
                <TableHead>Desired</TableHead>
                <TableHead>Runtime</TableHead>
                <TableHead>Snapshots / Player</TableHead>
                <TableHead>Health</TableHead>
                <TableHead>Toggles</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {bindings.map((b) => {
                const desired = String(b.desired_state || "-");
                const runtime = String(b.runtime_state || "-");
                const monId = String(b.monitor_id || "");
                const monLabel = String(b.monitor_label || monId || "-");
                const canRun = boolish(b.enabled) && !!monId;
                const supportSummary = supportByBinding[b.id];
                const health = String(supportSummary?.health || "-");
                return (
                  <TableRow key={b.id}>
                    <TableCell className="font-mono text-xs">#{b.id}</TableCell>
                    <TableCell>
                      <div className="text-sm">{b.screen_id}</div>
                      <div className="text-xs text-muted-foreground max-w-[180px] truncate" title={String(b.screen_name || "")}>{String(b.screen_name || "-")}</div>
                      <Link className="text-[11px] text-primary underline" to={`/tv/screens/${encodeURIComponent(String(b.screen_id))}/diagnostics`}>Diagnostics</Link>
                    </TableCell>
                    <TableCell>
                      <div className="text-xs max-w-[220px] truncate" title={monLabel}>{monLabel}</div>
                      <div className="mt-1">
                        <Select value={monId || "none"} onValueChange={(v) => void onRebind(b, v)}>
                          <SelectTrigger className="h-8"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="none" disabled>Rebind...</SelectItem>
                            {detected.map((m) => (
                              <SelectItem key={`${b.id}-${m.monitorId}`} value={m.monitorId}>{m.monitorLabel}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    </TableCell>
                    <TableCell><Badge variant="outline">{desired}</Badge></TableCell>
                    <TableCell>
                      <Badge variant={runtimeBadge(runtime)}>{runtime}</Badge>
                      <div className="text-[11px] text-muted-foreground mt-1 max-w-[180px] truncate" title={String(b.blocked_reason || b.launch_error_code || "")}>{String(b.blocked_reason || b.launch_error_code || "-")}</div>
                    </TableCell>
                    <TableCell className="text-xs">
                      L: {b.latest_snapshot_version ?? "-"}<br />
                      LR: {b.latest_ready_snapshot_version ?? "-"}<br />
                      A: {b.active_snapshot_version ?? "-"}<br />
                      P: {String(b.player_state || "-")}<br />
                      M: {String(b.player_render_mode || "-")}<br />
                      F: {String(b.player_fallback_reason || "-")}<br />
                      AD: {Boolean((b as any).player_ad_override_active) ? "ON" : "OFF"}<br />
                      AT: {String((b as any).player_current_ad_task_id || "-")}<br />
                      AL: {String((b as any).player_ad_layout || "-")}<br />
                      GYM-AD: {String((b as any).gym_ad_coordination_state || "-")}<br />
                      I: V:{shortValue(b.player_visual_item_id || "-")} / A:{shortValue(b.player_audio_item_id || "-")}
                    </TableCell>
                    <TableCell>
                      <Badge variant={healthBadge(health)}>{health}</Badge>
                      <div className="text-[11px] text-muted-foreground mt-1 max-w-[180px] truncate" title={String((supportSummary?.healthReasons || []).join("; "))}>{String((supportSummary?.healthReasons || ["-"])[0] || "-")}</div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1 text-xs">
                        <label className="flex items-center gap-2"><Switch checked={boolish(b.enabled)} onCheckedChange={(v) => void onToggle(b, "enabled", v)} /><span>Enabled</span></label>
                        <label className="flex items-center gap-2"><Switch checked={boolish(b.autostart)} onCheckedChange={(v) => void onToggle(b, "autostart", v)} /><span>Autostart</span></label>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        <Button size="sm" variant="outline" disabled={busy || !canRun} onClick={() => void onStart(b)}><Play className="h-3.5 w-3.5" /> Open</Button>
                        <Button size="sm" variant="outline" disabled={busy || !canRun} onClick={() => void onRestart(b)}><RotateCcw className="h-3.5 w-3.5" /> Restart</Button>
                        <Button size="sm" variant="outline" disabled={busy} onClick={() => void onStop(b)}><Square className="h-3.5 w-3.5" /> Stop</Button>
                        <Button size="sm" variant="destructive" disabled={busy} onClick={() => void onDelete(b)}><Trash2 className="h-3.5 w-3.5" /></Button>
                      </div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        <Button size="sm" variant="secondary" disabled={supportBusy} onClick={() => setSelectedSupportBindingId(b.id)}>Support</Button>
                        <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => void runSupportAction(b, "RUN_SYNC")}>Sync</Button>
                        <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => void runSupportAction(b, "RETRY_FAILED_DOWNLOADS")}>Retry DL</Button>
                        <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => void runSupportAction(b, "REEVALUATE_ACTIVATION")}>Eval Act</Button>
                        <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => void runSupportAction(b, "ACTIVATE_LATEST_READY")}>Activate</Button>
                        <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => void runSupportAction(b, "RELOAD_PLAYER")}>Reload Player</Button>
                        <Button size="sm" variant="outline" disabled={supportBusy || !canRun} onClick={() => void onRestartPlayerWindowSupport(b)}>Restart Window</Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
              {bindings.length === 0 && (
                <TableRow>
                  <TableCell colSpan={9} className="text-center text-sm text-muted-foreground">No bindings yet.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {selectedSupportBindingId && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Binding Support #{selectedSupportBindingId}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
              <div className="border rounded p-2">
                <div>Health: <Badge variant={healthBadge(String(selectedSupportSummary?.health || "-"))}>{String(selectedSupportSummary?.health || "-")}</Badge></div>
                <div className="mt-1">Runtime: {String((selectedSupportSummary?.binding as any)?.runtime_state || "-")}</div>
                <div>Monitor Available: {boolish((selectedSupportSummary?.binding as any)?.monitor_available) ? "YES" : "NO"}</div>
                <div>Failed Downloads: {String(selectedSupportSummary?.failedDownloadCount ?? "-")}</div>
              </div>
              <div className="border rounded p-2">
                <div>Latest: {String((selectedSupportSummary?.latestSnapshot as any)?.snapshot_version || "-")}</div>
                <div>Latest Ready: {String((selectedSupportSummary?.latestReadySnapshot as any)?.snapshot_version || "-")}</div>
                <div>Active: {String((selectedSupportSummary?.activation as any)?.state?.active_snapshot_version || "-")}</div>
                <div>Readiness: {String((selectedSupportSummary?.readiness as any)?.readiness_state || "-")}</div>
              </div>
              <div className="border rounded p-2">
                <div>Player State: {String((selectedSupportSummary?.playerState as any)?.player_state || "-")}</div>
                <div>Render Mode: {String((selectedSupportSummary?.playerState as any)?.render_mode || "-")}</div>
                <div>Fallback: {String((selectedSupportSummary?.playerState as any)?.fallback_reason || "-")}</div>
                <div className="text-muted-foreground mt-1">History rows: {supportHistoryTotal}</div>
              </div>
            </div>

            <div className="flex flex-wrap gap-1">
              <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "RUN_SYNC");
              }}>Run Sync</Button>
              <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "RECOMPUTE_READINESS");
              }}>Recompute Readiness</Button>
              <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "RETRY_FAILED_DOWNLOADS");
              }}>Retry Failed DL</Button>
              <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "REEVALUATE_ACTIVATION");
              }}>Eval Activation</Button>
              <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "ACTIVATE_LATEST_READY");
              }}>Activate Latest Ready</Button>
              <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "RELOAD_PLAYER");
              }}>Reload Player</Button>
              <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "REEVALUATE_PLAYER_CONTEXT");
              }}>Re-eval Player</Button>
              <Button size="sm" variant="outline" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void onRestartPlayerWindowSupport(b);
              }}>Restart Window</Button>
              <Button size="sm" variant="destructive" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "STOP_BINDING", {}, true);
              }}>Stop Binding</Button>
              <Button size="sm" variant="destructive" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "RESTART_BINDING", {}, true);
              }}>Restart Binding</Button>
              <Button size="sm" variant="destructive" disabled={supportBusy} onClick={() => {
                const b = bindings.find((x) => x.id === selectedSupportBindingId);
                if (b) void runSupportAction(b, "RESET_TRANSIENT_PLAYER_STATE", {}, true);
              }}>Reset Transient Player</Button>
            </div>

            <div className="border rounded p-2 max-h-56 overflow-auto">
              <div className="text-xs font-medium mb-2">Support Action History</div>
              {(supportHistory || []).length === 0 ? (
                <div className="text-xs text-muted-foreground">No support actions yet.</div>
              ) : (
                <div className="space-y-1">
                  {supportHistory.map((row) => (
                    <div key={String(row.id)} className="text-xs border-b pb-1">
                      <div className="font-mono">#{String(row.id)} {String(row.action_type || "-")} [{String(row.result || "-")}]</div>
                      <div className="text-muted-foreground">{String(row.message || "-")}</div>
                      <div className="text-muted-foreground">corr={String(row.correlation_id || "-")} at {String(row.finished_at || row.created_at || "-")}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader><CardTitle className="text-sm">Local Monitors ({monitors.length})</CardTitle></CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm">
            {(monitors || []).map((m) => (
              <div key={m.monitor_id} className="border rounded p-2">
                <div className="flex items-center gap-2"><Monitor className="h-4 w-4" /> {m.monitor_label || m.monitor_id}</div>
                <div className="text-xs text-muted-foreground mt-1">{m.width}x{m.height} @ ({m.x},{m.y})</div>
              </div>
            ))}
            {monitors.length === 0 && <div className="text-sm text-muted-foreground">No monitors detected.</div>}
          </div>
        </CardContent>
      </Card>

      <Alert>
        <AlertTitle>Host Orchestration Rules</AlertTitle>
        <AlertDescription>
          Runtime is binding-scoped by <strong>bindingId + screenId</strong>. Duplicate active monitor assignment is blocked.
          Rebinding monitor requires stop, update, then restart. Missing startup monitor keeps the binding visible with warning/error.
        </AlertDescription>
      </Alert>
    </div>
  );
}















































