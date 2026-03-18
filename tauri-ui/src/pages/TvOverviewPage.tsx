import { useCallback, useEffect, useMemo, useState } from "react";
import { availableMonitors } from "@tauri-apps/api/window";
import {
  Activity,
  AlertCircle,
  Database,
  HeartPulse,
  Loader2,
  Monitor,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  Square,
  Trash2,
  Wrench,
} from "lucide-react";

import {
  createTvHostBinding,
  deleteTvHostBinding,
  getTvBindingSupportHistory,
  getTvBindingSupportSummary,
  getTvHostBindings,
  getTvHostMonitors,
  getTvObservabilityBinding,
  getTvObservabilityOverview,
  getTvObservabilityRetention,
  getTvStartupLatest,
  getTvStartupPreflight,
  getTvStartupRuns,
  restartTvHostBinding,
  runTvBindingSupportAction,
  runTvObservabilityRetention,
  runTvStartupReconciliation,
  startTvHostBinding,
  stopTvHostBinding,
} from "../api/tv";
import type {
  TvBindingHealthSummary,
  TvObservabilityBindingDetail,
  TvObservabilityOverviewResponse,
  TvObservabilityRetentionResponse,
  TvBindingSupportActionType,
  TvBindingSupportSummaryResponse,
  TvHostMonitor,
  TvScreenBinding,
  TvStartupLatestResponse,
  TvStartupPreflightResponse,
  TvStartupReconciliationRun,
  TvSupportActionLogRow,
} from "../api/types";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

const SAFE_ACTIONS: TvBindingSupportActionType[] = [
  "RUN_SYNC",
  "RECOMPUTE_READINESS",
  "RETRY_FAILED_DOWNLOADS",
  "REEVALUATE_ACTIVATION",
  "ACTIVATE_LATEST_READY",
  "REEVALUATE_PLAYER_CONTEXT",
  "RELOAD_PLAYER",
];

const CONTROL_ACTIONS: TvBindingSupportActionType[] = [
  "START_BINDING",
  "STOP_BINDING",
  "RESTART_BINDING",
  "RESTART_PLAYER_WINDOW",
  "RESET_TRANSIENT_PLAYER_STATE",
];

const ACTION_LABELS: Record<TvBindingSupportActionType, string> = {
  RUN_SYNC: "Run Sync",
  RECOMPUTE_READINESS: "Recompute Readiness",
  RETRY_FAILED_DOWNLOADS: "Retry Failed Downloads",
  RETRY_ONE_DOWNLOAD: "Retry One Download",
  REEVALUATE_ACTIVATION: "Reevaluate Activation",
  ACTIVATE_LATEST_READY: "Activate Latest Ready",
  REEVALUATE_PLAYER_CONTEXT: "Reevaluate Player Context",
  RELOAD_PLAYER: "Reload Player",
  START_BINDING: "Start Binding",
  STOP_BINDING: "Stop Binding",
  RESTART_BINDING: "Restart Binding",
  RESTART_PLAYER_WINDOW: "Restart Player Window",
  RESET_TRANSIENT_PLAYER_STATE: "Reset Transient Player State",
};

const ACTION_DESCRIPTIONS: Partial<Record<TvBindingSupportActionType, string>> = {
  STOP_BINDING: "Stop this binding and close its player window.",
  RESTART_BINDING: "Stop then restart the binding using the host supervisor.",
  RESTART_PLAYER_WINDOW: "Recycle the player window for this binding only.",
  RESET_TRANSIENT_PLAYER_STATE: "Clear local transient player/runtime rows without touching snapshots, assets, proofs, or history.",
};

function healthBadgeClass(health: TvBindingHealthSummary | undefined) {
  switch (health) {
    case "HEALTHY":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "WARNING":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "DEGRADED":
      return "border-orange-200 bg-orange-50 text-orange-700";
    case "ERROR":
      return "border-red-200 bg-red-50 text-red-700";
    case "STOPPED":
      return "border-slate-200 bg-slate-50 text-slate-700";
    default:
      return "border-slate-200 bg-slate-50 text-slate-700";
  }
}

function startupBadgeClass(status: string | null | undefined) {
  switch (status) {
    case "SUCCESS":
    case "PASSED":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "SUCCESS_WITH_WARNINGS":
    case "WARNING":
    case "REPAIRED":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "BLOCKER":
    case "FAILED":
    case "ERROR":
      return "border-red-200 bg-red-50 text-red-700";
    case "INFO":
      return "border-sky-200 bg-sky-50 text-sky-700";
    case "SKIPPED":
    case "BLOCKED":
      return "border-slate-200 bg-slate-50 text-slate-700";
    default:
      return "border-slate-200 bg-slate-50 text-slate-700";
  }
}

function formatTimestamp(value: string | null | undefined) {
  if (!value) {
    return "n/a";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function stringValue(value: unknown) {
  if (value == null) {
    return "";
  }
  return String(value);
}

export default function TvOverviewPage() {
  const [monitors, setMonitors] = useState<TvHostMonitor[]>([]);
  const [bindings, setBindings] = useState<TvScreenBinding[]>([]);
  const [supportByBinding, setSupportByBinding] = useState<Record<number, TvBindingSupportSummaryResponse>>({});
  const [overview, setOverview] = useState<TvObservabilityOverviewResponse | null>(null);
  const [retention, setRetention] = useState<TvObservabilityRetentionResponse | null>(null);
  const [startupLatest, setStartupLatest] = useState<TvStartupLatestResponse | null>(null);
  const [startupPreflight, setStartupPreflight] = useState<TvStartupPreflightResponse | null>(null);
  const [startupRuns, setStartupRuns] = useState<TvStartupReconciliationRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedBindingId, setSelectedBindingId] = useState<number | null>(null);
  const [selectedSummary, setSelectedSummary] = useState<TvBindingSupportSummaryResponse | null>(null);
  const [selectedHistory, setSelectedHistory] = useState<TvSupportActionLogRow[]>([]);
  const [selectedDiagnostics, setSelectedDiagnostics] = useState<TvObservabilityBindingDetail | null>(null);
  const [panelLoading, setPanelLoading] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [retentionFeedback, setRetentionFeedback] = useState<string | null>(null);
  const [startupBusy, setStartupBusy] = useState(false);
  const [startupFeedback, setStartupFeedback] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<{
    bindingId: number;
    actionType: TvBindingSupportActionType;
  } | null>(null);

  const selectedBinding = useMemo(
    () => bindings.find((binding) => binding.id === selectedBindingId) ?? null,
    [bindings, selectedBindingId],
  );

  const startupSignalItems = useMemo(() => {
    if (!startupPreflight) {
      return [];
    }
    return [
      ...(startupPreflight.blockers ?? []),
      ...(startupPreflight.warnings ?? []),
      ...((startupPreflight.infos ?? []).slice(0, 2)),
    ];
  }, [startupPreflight]);

  const refreshPanel = useCallback(
    async (bindingId: number) => {
      setPanelLoading(true);
      try {
        const [summary, history, diagnostics] = await Promise.all([
          getTvBindingSupportSummary(bindingId),
          getTvBindingSupportHistory(bindingId, 100, 0),
          getTvObservabilityBinding(bindingId, { eventLimit: 50, historyLimit: 20 }),
        ]);
        setSupportByBinding((current) => ({ ...current, [bindingId]: summary }));
        setSelectedSummary(summary);
        setSelectedHistory(history.rows ?? []);
        setSelectedDiagnostics(diagnostics);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load support details.");
      } finally {
        setPanelLoading(false);
      }
    },
    [],
  );

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [monitorResponse, bindingResponse, overviewResponse, retentionResponse, startupLatestResponse, startupPreflightResponse, startupRunsResponse] = await Promise.all([
        getTvHostMonitors(),
        getTvHostBindings(),
        getTvObservabilityOverview(),
        getTvObservabilityRetention(),
        getTvStartupLatest(),
        getTvStartupPreflight(),
        getTvStartupRuns(8, 0),
      ]);
      if (monitorResponse.ok) {
        setMonitors(monitorResponse.rows ?? []);
      }
      if (bindingResponse.ok) {
        const rows = bindingResponse.rows ?? [];
        setBindings(rows);
        const summaryPairs = await Promise.all(
          rows.map(async (binding) => {
            try {
              return [binding.id, await getTvBindingSupportSummary(binding.id)] as const;
            } catch {
              return [binding.id, null] as const;
            }
          }),
        );
        const next: Record<number, TvBindingSupportSummaryResponse> = {};
        for (const [bindingId, summary] of summaryPairs) {
          if (summary) {
            next[bindingId] = summary;
          }
        }
        setSupportByBinding(next);
        if (selectedBindingId && next[selectedBindingId]) {
          setSelectedSummary(next[selectedBindingId]);
        }
      }
      if (overviewResponse.ok) {
        setOverview(overviewResponse);
      }
      if (retentionResponse.ok) {
        setRetention(retentionResponse);
      }
      setStartupLatest(startupLatestResponse);
      setStartupPreflight(startupPreflightResponse);
      if (startupRunsResponse.ok) {
        setStartupRuns(startupRunsResponse.rows ?? []);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load TV host state.");
    } finally {
      setLoading(false);
    }
  }, [selectedBindingId]);

  useEffect(() => {
    void fetchData();
    const interval = window.setInterval(() => {
      void fetchData();
    }, 5000);
    return () => window.clearInterval(interval);
  }, [fetchData]);

  const openSupportPanel = useCallback(
    async (bindingId: number) => {
      setSelectedBindingId(bindingId);
      setActionFeedback(null);
      await refreshPanel(bindingId);
    },
    [refreshPanel],
  );

  const closeSupportPanel = useCallback(() => {
    setSelectedBindingId(null);
    setSelectedSummary(null);
    setSelectedHistory([]);
    setSelectedDiagnostics(null);
    setActionFeedback(null);
  }, []);

  const runAction = useCallback(
    async (
      bindingId: number,
      actionType: TvBindingSupportActionType,
      options?: Record<string, unknown>,
      confirm = false,
    ) => {
      setActionBusy(true);
      setActionFeedback(null);
      try {
        const result = await runTvBindingSupportAction(bindingId, {
          actionType,
          options,
          confirm,
          triggeredBy: "TV_OVERVIEW",
        });
        const status = result.result ?? "FAILED";
        const message = result.message || `${ACTION_LABELS[actionType]} finished with ${status}.`;
        setActionFeedback(`${ACTION_LABELS[actionType]}: ${status} - ${message}`);
        await fetchData();
        if (selectedBindingId === bindingId) {
          await refreshPanel(bindingId);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : `Failed to run ${ACTION_LABELS[actionType]}.`);
      } finally {
        setActionBusy(false);
      }
    },
    [fetchData, refreshPanel, selectedBindingId],
  );

  const handleStart = useCallback(async (bindingId: number) => {
    try {
      await startTvHostBinding(bindingId);
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start binding.");
    }
  }, [fetchData]);

  const handleStop = useCallback(async (bindingId: number) => {
    try {
      await stopTvHostBinding(bindingId);
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stop binding.");
    }
  }, [fetchData]);

  const handleRestart = useCallback(async (bindingId: number) => {
    try {
      await restartTvHostBinding(bindingId);
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to restart binding.");
    }
  }, [fetchData]);

  const handleDelete = useCallback(async (bindingId: number) => {
    if (!window.confirm("Delete this binding?")) {
      return;
    }
    try {
      await deleteTvHostBinding(bindingId);
      await fetchData();
      if (selectedBindingId === bindingId) {
        closeSupportPanel();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete binding.");
    }
  }, [closeSupportPanel, fetchData, selectedBindingId]);

  const handleCreateNew = useCallback(async () => {
    try {
      const maxScreenId = bindings.reduce((acc, binding) => Math.max(acc, binding.screen_id), 0);
      await createTvHostBinding({
        screen_id: maxScreenId + 1,
        screen_label: `Screen ${maxScreenId + 1}`,
        enabled: true,
      });
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create binding.");
    }
  }, [bindings, fetchData]);

  const handleRunRetention = useCallback(async () => {
    if (!window.confirm("Run TV retention cleanup now? This removes only old operational history.")) {
      return;
    }
    setRetentionBusy(true);
    setRetentionFeedback(null);
    try {
      const result = await runTvObservabilityRetention({
        dryRun: false,
        includeQueryChecks: false,
      });
      setRetention(result.summaryAfter);
      setRetentionFeedback(`Retention cleanup removed ${result.deletedRows} row(s).`);
      await fetchData();
      if (selectedBindingId) {
        await refreshPanel(selectedBindingId);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run retention cleanup.");
    } finally {
      setRetentionBusy(false);
    }
  }, [fetchData, refreshPanel, selectedBindingId]);

  const handleRunStartupCheck = useCallback(async () => {
    setStartupBusy(true);
    setStartupFeedback(null);
    try {
      const monitors = await availableMonitors();
      const monitorPayload = monitors.map((monitor, index) => ({
        monitor_id: monitor.name || `monitor_${index}`,
        monitor_label: monitor.name || `Monitor ${index + 1}`,
        monitor_index: index,
        is_connected: true,
        width: monitor.size.width,
        height: monitor.size.height,
        offset_x: monitor.position.x,
        offset_y: monitor.position.y,
        scale_factor: monitor.scaleFactor,
        is_primary: index === 0,
      }));
      const result = await runTvStartupReconciliation({
        triggerSource: "TV_OVERVIEW",
        includeQueryChecks: false,
        monitors: monitorPayload,
      });
      const status = result.status || result.overallResult || (result.ok ? "SUCCESS" : "FAILED");
      setStartupFeedback(result.message || `Startup reconciliation finished with ${status}.`);
      await fetchData();
      if (selectedBindingId) {
        await refreshPanel(selectedBindingId);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run startup reconciliation.");
    } finally {
      setStartupBusy(false);
    }
  }, [fetchData, refreshPanel, selectedBindingId]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Monitor className="h-5 w-5 text-primary" />
          <div>
            <h1 className="text-lg font-semibold">TV Host Overview</h1>
            <p className="text-sm text-muted-foreground">Bindings, runtime state, and support / recovery tools for MonClub TV.</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => void fetchData()} disabled={loading}>
            <RefreshCw className={cn("mr-2 h-3.5 w-3.5", loading && "animate-spin")} />
            Refresh
          </Button>
          <Button size="sm" onClick={() => void handleCreateNew()}>
            Create Binding
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {overview && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <HeartPulse className="h-4 w-4" />
              Host Observability
            </CardTitle>
            <CardDescription>Derived host-level health, proof backlog, and stale/problem signals from factual Access state.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Bindings</div>
                <div className="mt-2 text-2xl font-semibold">{overview.totals.totalBindings}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Healthy {overview.totals.healthyBindings} · Warning {overview.totals.warningBindings} · Degraded {overview.totals.degradedBindings} · Error {overview.totals.errorBindings} · Stopped {overview.totals.stoppedBindings}
                </div>
              </div>
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Runtime</div>
                <div className="mt-2 text-2xl font-semibold">{overview.totals.activePlayerWindows}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Player windows · {overview.totals.activeMonitors} active monitor(s)
                </div>
              </div>
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Ad / Proof</div>
                <div className="mt-2 text-2xl font-semibold">{overview.totals.queuedOrRetryableProofCount}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Queued or retryable proofs · {overview.totals.activeGymAdRuntimes} active gym ad runtime(s)
                </div>
              </div>
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Recovery Load</div>
                <div className="mt-2 text-2xl font-semibold">{overview.totals.recentFailedDownloadsCount}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Failed asset(s) · {overview.totals.recentSupportActionsCount} support action(s) in the last {overview.recentSupportWindowHours}h
                </div>
              </div>
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Problem Bindings</div>
                <div className="mt-2 text-2xl font-semibold">{overview.totals.staleProblemBindingsCount}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Bindings with stale or unhealthy runtime signals
                </div>
              </div>
            </div>
            {overview.problemBindings.length > 0 && (
              <div className="space-y-2">
                <div className="text-sm font-medium">Bindings needing attention</div>
                <div className="grid gap-2 md:grid-cols-2">
                  {overview.problemBindings.slice(0, 4).map((row) => (
                    <div key={row.bindingId} className="rounded-lg border px-3 py-2 text-sm">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{row.screenLabel}</span>
                        <Badge className={cn("border", healthBadgeClass(row.health))}>{row.health}</Badge>
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {row.reasons[0] || (row.stale ? "Runtime is stale." : "Needs operator attention.")}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {(startupPreflight || startupLatest || startupRuns.length > 0) && (
        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" />
                Startup Diagnostics
              </CardTitle>
              <CardDescription>Deterministic preflight and reconciliation history for startup safety, crash recovery, and operator reruns.</CardDescription>
            </div>
            <Button size="sm" variant="outline" onClick={() => void handleRunStartupCheck()} disabled={startupBusy}>
              <RefreshCw className={cn("mr-2 h-3.5 w-3.5", startupBusy && "animate-spin")} />
              Run Startup Check
            </Button>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Latest Run</div>
                <div className="mt-2 flex items-center gap-2">
                  <Badge className={cn("border", startupBadgeClass(startupLatest?.status))}>
                    {startupLatest?.status || "NO_RUN"}
                  </Badge>
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  {startupLatest?.finishedAt ? `Finished ${formatTimestamp(startupLatest.finishedAt)}` : "No recorded startup reconciliation yet."}
                </div>
              </div>
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Preflight Blockers</div>
                <div className="mt-2 text-2xl font-semibold">{startupPreflight?.counts.blockerCount ?? 0}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Warning {startupPreflight?.counts.warningCount ?? 0} · Info {startupPreflight?.counts.infoCount ?? 0}
                </div>
              </div>
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Startup Correlation</div>
                <div className="mt-2 text-sm font-medium">{startupLatest?.correlationId || "n/a"}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Trigger {startupLatest?.triggerSource || "unknown"}
                </div>
              </div>
              <div className="rounded-lg border bg-card p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Phase Health</div>
                <div className="mt-2 text-2xl font-semibold">{startupLatest?.phases?.length ?? 0}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Failed {startupLatest?.phases?.filter((phase) => phase.result === "FAILED").length ?? 0} · Repaired {startupLatest?.phases?.filter((phase) => phase.result === "REPAIRED").length ?? 0}
                </div>
              </div>
            </div>

            {startupFeedback && (
              <Alert>
                <AlertDescription>{startupFeedback}</AlertDescription>
              </Alert>
            )}

            <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
              <div className="space-y-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Current Preflight Signals</CardTitle>
                    <CardDescription>
                      {startupPreflight?.message || "No current preflight summary loaded."}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {startupSignalItems.length === 0 ? (
                      <div className="text-sm text-muted-foreground">No current blocker or warning signals.</div>
                    ) : (
                      startupSignalItems.map((item) => (
                        <div key={`${item.severity}-${item.code}`} className="rounded-lg border p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge variant="outline">{item.code}</Badge>
                            <Badge className={cn("border", startupBadgeClass(item.status))}>{item.status}</Badge>
                            <Badge className={cn("border", startupBadgeClass(item.severity))}>{item.severity}</Badge>
                          </div>
                          <div className="mt-2 text-sm">{item.message || "No message"}</div>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>

                {startupPreflight && (
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base">Preflight Facts</CardTitle>
                      <CardDescription>Current factual snapshot before any repair phases run.</CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-3 text-sm md:grid-cols-2">
                      <div className="rounded-md border bg-muted/30 px-3 py-2">
                        <div className="text-xs uppercase tracking-wide text-muted-foreground">Status</div>
                        <div className="mt-1 font-medium">{startupPreflight.status}</div>
                        <div className="text-xs text-muted-foreground">Generated {formatTimestamp(startupPreflight.generatedAt)}</div>
                      </div>
                      <div className="rounded-md border bg-muted/30 px-3 py-2">
                        <div className="text-xs uppercase tracking-wide text-muted-foreground">Runtime Target</div>
                        <div className="mt-1 font-medium">{String(startupPreflight.metadata.runtimeTarget ?? false)}</div>
                        <div className="text-xs text-muted-foreground">{stringValue(startupPreflight.metadata.dataRoot) || "n/a"}</div>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>

              <div className="space-y-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Latest Phase Timeline</CardTitle>
                    <CardDescription>Ordered startup reconciliation phases for the latest run.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {!startupLatest?.phases?.length ? (
                      <div className="text-sm text-muted-foreground">No startup phase history recorded yet.</div>
                    ) : (
                      startupLatest.phases.map((phase) => (
                        <div key={`${phase.id}-${phase.phaseName}`} className="rounded-lg border p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge variant="outline">{phase.phaseName}</Badge>
                            <Badge className={cn("border", startupBadgeClass(phase.result))}>{phase.result || "PENDING"}</Badge>
                          </div>
                          <div className="mt-2 text-sm">{phase.message || "No message"}</div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {formatTimestamp(phase.startedAt)} · {formatTimestamp(phase.finishedAt)}
                          </div>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Recent Startup Runs</CardTitle>
                    <CardDescription>Latest persisted reconciliation history for this Access host.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {startupRuns.length === 0 ? (
                      <div className="text-sm text-muted-foreground">No startup runs recorded yet.</div>
                    ) : (
                      startupRuns.map((run) => (
                        <div key={run.id} className="rounded-lg border p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge variant="outline">Run #{run.id}</Badge>
                            <Badge className={cn("border", startupBadgeClass(run.status))}>{run.status || "UNKNOWN"}</Badge>
                          </div>
                          <div className="mt-2 text-xs text-muted-foreground">
                            {formatTimestamp(run.startedAt)} · blocker {run.blockerCount} · warning {run.warningCount}
                          </div>
                          <div className="mt-1 text-sm">{run.message || "No message"}</div>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {retention && (
        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-4 w-4" />
                Retention Summary
              </CardTitle>
              <CardDescription>Preview of safe cleanup candidates across operational history tables. Active truth is preserved.</CardDescription>
            </div>
            <Button size="sm" variant="outline" onClick={() => void handleRunRetention()} disabled={retentionBusy}>
              <RefreshCw className={cn("mr-2 h-3.5 w-3.5", retentionBusy && "animate-spin")} />
              Run Cleanup
            </Button>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
              <span>{retention.eligibleDeleteCount} eligible row(s)</span>
              <span>Support logs {retention.policy.supportLogDays}d</span>
              <span>Proof terminal rows {retention.policy.proofTerminalDays}d</span>
              <span>Disconnected monitors {retention.policy.disconnectedMonitorDays}d</span>
            </div>
            {retentionFeedback && (
              <Alert>
                <AlertDescription>{retentionFeedback}</AlertDescription>
              </Alert>
            )}
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              {retention.tables.map((row) => (
                <div key={row.table} className="rounded-lg border bg-card p-3">
                  <div className="font-mono text-xs">{row.table}</div>
                  <div className="mt-2 text-lg font-semibold">{row.eligibleRows}</div>
                  <div className="text-xs text-muted-foreground">
                    eligible of {row.totalRows} total
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground">{row.rule}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Detected Monitors</CardTitle>
          <CardDescription>Physical monitors reported by the Access host.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            {monitors.map((monitor) => (
              <div key={monitor.id} className="rounded-lg border bg-card p-4 shadow-sm">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium">{monitor.monitor_label}</div>
                    <div className="text-xs text-muted-foreground">{monitor.monitor_id}</div>
                  </div>
                  <Badge className={cn("border", monitor.is_connected ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-slate-200 bg-slate-50 text-slate-700")}>
                    {monitor.is_connected ? "Connected" : "Disconnected"}
                  </Badge>
                </div>
                <div className="mt-3 text-xs text-muted-foreground">
                  {monitor.width}x{monitor.height} @ [{monitor.offset_x}, {monitor.offset_y}]
                </div>
              </div>
            ))}
            {monitors.length === 0 && (
              <div className="rounded-lg border border-dashed p-6 text-sm text-muted-foreground">
                No monitors detected yet.
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Bindings</CardTitle>
          <CardDescription>Each binding maps one logical screen to one host runtime.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {bindings.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-sm text-muted-foreground">
              No bindings configured.
            </div>
          ) : (
            bindings.map((binding) => {
              const summary = supportByBinding[binding.id];
              const runtime = binding.runtime?.runtime_state || "UNKNOWN";
              return (
                <div key={binding.id} className="rounded-xl border bg-background p-4 shadow-sm">
                  <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div className="space-y-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-base font-semibold">{binding.screen_label}</span>
                        <Badge variant="outline">Binding #{binding.id}</Badge>
                        <Badge className={cn("border", healthBadgeClass(summary?.health))}>
                          {summary?.health ?? "UNKNOWN"}
                        </Badge>
                        <Badge variant="outline">Desired {binding.desired_state}</Badge>
                        <Badge variant="outline">Runtime {runtime}</Badge>
                      </div>
                      <div className="grid gap-1 text-sm text-muted-foreground">
                        <span>Monitor: {binding.monitor_label || binding.monitor_id || "Unassigned"}</span>
                        <span>Last support correlation: {summary?.lastCorrelationId || "n/a"}</span>
                        {summary?.reasons?.[0] && <span>Health detail: {summary.reasons[0]}</span>}
                      </div>
                      {summary && (
                        <div className="flex flex-wrap gap-2">
                          <Badge variant="outline">Failed assets {summary.facts.downloadFailures.count}</Badge>
                          <Badge variant="outline">Proof retryable {summary.facts.proofFailures.retryableCount}</Badge>
                          <Badge variant="outline">Proof terminal {summary.facts.proofFailures.terminalCount}</Badge>
                          <Badge variant="outline">
                            Support {summary.activeAction?.actionType ? "active" : "idle"}
                          </Badge>
                        </div>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      {binding.desired_state !== "RUNNING" ? (
                        <Button size="sm" onClick={() => void handleStart(binding.id)}>
                          <Play className="mr-2 h-3.5 w-3.5 fill-current" />
                          Start
                        </Button>
                      ) : (
                        <>
                          <Button size="sm" variant="secondary" onClick={() => void handleRestart(binding.id)}>
                            <RotateCcw className="mr-2 h-3.5 w-3.5" />
                            Restart
                          </Button>
                          <Button size="sm" variant="destructive" onClick={() => void handleStop(binding.id)}>
                            <Square className="mr-2 h-3.5 w-3.5 fill-current" />
                            Stop
                          </Button>
                        </>
                      )}
                      <Button size="sm" variant="outline" onClick={() => void openSupportPanel(binding.id)}>
                        <Wrench className="mr-2 h-3.5 w-3.5" />
                        Support
                      </Button>
                      <Button size="sm" variant="ghost" className="text-destructive" onClick={() => void handleDelete(binding.id)}>
                        <Trash2 className="mr-2 h-3.5 w-3.5" />
                        Delete
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </CardContent>
      </Card>

      <Dialog open={selectedBindingId !== null} onOpenChange={(open) => { if (!open) closeSupportPanel(); }}>
        <DialogContent className="max-h-[85vh] max-w-6xl overflow-hidden">
          <DialogHeader>
            <DialogTitle>Binding Diagnostics / Support</DialogTitle>
            <DialogDescription>
              {selectedBinding ? `${selectedBinding.screen_label} (binding #${selectedBinding.id})` : "Support details"}
            </DialogDescription>
          </DialogHeader>

          {panelLoading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading support details...
            </div>
          )}

          {!panelLoading && selectedSummary && (
            <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
              <ScrollArea className="max-h-[68vh] pr-4">
                <div className="space-y-4">
                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="flex items-center gap-2 text-base">
                        <ShieldAlert className="h-4 w-4" />
                        Health Summary
                      </CardTitle>
                      <CardDescription>Derived from runtime facts only.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={cn("border", healthBadgeClass(selectedSummary.health))}>
                          {selectedSummary.health}
                        </Badge>
                        <Badge variant="outline">
                          Runtime {selectedSummary.facts.runtime?.runtime_state || "UNKNOWN"}
                        </Badge>
                        <Badge variant="outline">
                          Desired {selectedSummary.facts.binding.desired_state}
                        </Badge>
                        {selectedDiagnostics?.stale && <Badge variant="outline">Stale runtime</Badge>}
                      </div>
                      <div className="space-y-2 text-sm">
                        {selectedSummary.reasons.map((reason) => (
                          <div key={reason} className="rounded-md border bg-muted/40 px-3 py-2">
                            {reason}
                          </div>
                        ))}
                      </div>
                      <div className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                        <span>Latest support correlation: {selectedSummary.lastCorrelationId || "n/a"}</span>
                        <span>Failed downloads: {selectedSummary.facts.downloadFailures.count}</span>
                        <span>Proof retryable: {selectedSummary.facts.proofFailures.retryableCount}</span>
                        <span>Proof terminal: {selectedSummary.facts.proofFailures.terminalCount}</span>
                      </div>
                    </CardContent>
                  </Card>

                  {selectedDiagnostics && (
                    <Card>
                      <CardHeader className="pb-3">
                        <CardTitle className="flex items-center gap-2 text-base">
                          <Activity className="h-4 w-4" />
                          Diagnostics Snapshot
                        </CardTitle>
                        <CardDescription>Joined runtime, readiness, activation, player, ad, and proof state for this binding.</CardDescription>
                      </CardHeader>
                      <CardContent className="grid gap-3 text-sm md:grid-cols-2">
                        <div className="rounded-md border bg-muted/30 px-3 py-2">
                          <div className="text-xs uppercase tracking-wide text-muted-foreground">Readiness</div>
                          <div className="mt-1 font-medium">{stringValue(selectedDiagnostics.readiness?.readiness_state) || "n/a"}</div>
                          <div className="text-xs text-muted-foreground">
                            Latest snapshot {stringValue(selectedDiagnostics.readiness?.snapshot_id) || "n/a"}
                          </div>
                        </div>
                        <div className="rounded-md border bg-muted/30 px-3 py-2">
                          <div className="text-xs uppercase tracking-wide text-muted-foreground">Activation</div>
                          <div className="mt-1 font-medium">{stringValue(selectedDiagnostics.activation?.activation_state) || "n/a"}</div>
                          <div className="text-xs text-muted-foreground">
                            Active snapshot {stringValue(selectedDiagnostics.activation?.active_snapshot_id) || "n/a"}
                          </div>
                        </div>
                        <div className="rounded-md border bg-muted/30 px-3 py-2">
                          <div className="text-xs uppercase tracking-wide text-muted-foreground">Player</div>
                          <div className="mt-1 font-medium">{selectedDiagnostics.playerStateRow?.player_state || "n/a"}</div>
                          <div className="text-xs text-muted-foreground">
                            Last tick {formatTimestamp(selectedDiagnostics.playerStateRow?.last_tick_at)}
                          </div>
                        </div>
                        <div className="rounded-md border bg-muted/30 px-3 py-2">
                          <div className="text-xs uppercase tracking-wide text-muted-foreground">Monitor</div>
                          <div className="mt-1 font-medium">{selectedDiagnostics.monitor.available ? "Available" : "Missing / disconnected"}</div>
                          <div className="text-xs text-muted-foreground">
                            {selectedDiagnostics.bindingConfig.monitor_label || selectedDiagnostics.bindingConfig.monitor_id || "Unassigned"}
                          </div>
                        </div>
                        <div className="rounded-md border bg-muted/30 px-3 py-2">
                          <div className="text-xs uppercase tracking-wide text-muted-foreground">Ad Runtime</div>
                          <div className="mt-1 font-medium">{selectedDiagnostics.gymDiagnostics?.coordinationState || "IDLE"}</div>
                          <div className="text-xs text-muted-foreground">
                            Gym {selectedDiagnostics.gymId || "n/a"} · audio override {selectedDiagnostics.gymDiagnostics?.audioOverrideActive ? "on" : "off"}
                          </div>
                        </div>
                        <div className="rounded-md border bg-muted/30 px-3 py-2">
                          <div className="text-xs uppercase tracking-wide text-muted-foreground">Proof Backlog</div>
                          <div className="mt-1 font-medium">
                            {selectedDiagnostics.proofBacklog.retryableCount} retryable · {selectedDiagnostics.proofBacklog.terminalCount} terminal
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {selectedDiagnostics.proofBacklog.queuedCount} queued · {selectedDiagnostics.proofBacklog.sentCount} sent
                          </div>
                        </div>
                        <div className="rounded-md border bg-muted/30 px-3 py-2">
                          <div className="text-xs uppercase tracking-wide text-muted-foreground">Failed Assets</div>
                          <div className="mt-1 font-medium">{selectedDiagnostics.failedAssets.count}</div>
                          <div className="text-xs text-muted-foreground">
                            Latest support action {selectedDiagnostics.lastSupportAction?.action_type || "n/a"}
                          </div>
                        </div>
                        <div className="rounded-md border bg-muted/30 px-3 py-2">
                          <div className="text-xs uppercase tracking-wide text-muted-foreground">Recent Pipelines</div>
                          <div className="mt-1 font-medium">
                            Sync runs {selectedDiagnostics.syncRuns.rows.length} · Activation attempts {selectedDiagnostics.activationAttempts.rows.length}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            Active support action {selectedSummary.activeAction?.actionType || "none"}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  )}

                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base">Safe Actions</CardTitle>
                      <CardDescription>Non-destructive operational wrappers over A2-A9.</CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-2 md:grid-cols-2">
                      {SAFE_ACTIONS.map((actionType) => {
                        const availability = selectedSummary.actionAvailability[actionType];
                        return (
                          <Button
                            key={actionType}
                            variant="outline"
                            className="justify-start"
                            disabled={actionBusy || !availability?.allowed}
                            onClick={() => void runAction(selectedSummary.bindingId, actionType)}
                            title={availability?.blockedReason || ACTION_LABELS[actionType]}
                          >
                            {ACTION_LABELS[actionType]}
                          </Button>
                        );
                      })}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base">Control Actions</CardTitle>
                      <CardDescription>Confirmation is enforced for destructive actions.</CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-2 md:grid-cols-2">
                      {CONTROL_ACTIONS.map((actionType) => {
                        const availability = selectedSummary.actionAvailability[actionType];
                        const destructive = availability?.requiresConfirmation;
                        return (
                          <Button
                            key={actionType}
                            variant={destructive ? "destructive" : "outline"}
                            className="justify-start"
                            disabled={actionBusy || !availability?.allowed}
                            onClick={() => {
                              if (destructive) {
                                setConfirmAction({ bindingId: selectedSummary.bindingId, actionType });
                                return;
                              }
                              void runAction(selectedSummary.bindingId, actionType);
                            }}
                            title={availability?.blockedReason || ACTION_LABELS[actionType]}
                          >
                            {ACTION_LABELS[actionType]}
                          </Button>
                        );
                      })}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base">Targeted Download Retries</CardTitle>
                      <CardDescription>Retry one asset at a time for the selected binding.</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      {selectedSummary.facts.downloadFailures.rows.length === 0 ? (
                        <div className="text-sm text-muted-foreground">No failed downloads for this binding.</div>
                      ) : (
                        selectedSummary.facts.downloadFailures.rows.slice(0, 8).map((row) => {
                          const mediaAssetId = stringValue(row.media_asset_id);
                          const assetState = stringValue(row.asset_state) || "UNKNOWN";
                          const stateReason = stringValue(row.state_reason);
                          return (
                            <div key={mediaAssetId} className="flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-center sm:justify-between">
                              <div className="min-w-0">
                                <div className="font-mono text-xs">{mediaAssetId}</div>
                                <div className="text-xs text-muted-foreground">
                                  {assetState}
                                  {stateReason ? ` - ${stateReason}` : ""}
                                </div>
                              </div>
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={actionBusy}
                                onClick={() =>
                                  void runAction(selectedSummary.bindingId, "RETRY_ONE_DOWNLOAD", {
                                    mediaAssetId,
                                  })
                                }
                              >
                                Retry Asset
                              </Button>
                            </div>
                          );
                        })
                      )}
                    </CardContent>
                  </Card>

                  {actionFeedback && (
                    <Alert>
                      <AlertDescription>{actionFeedback}</AlertDescription>
                    </Alert>
                  )}
                </div>
              </ScrollArea>

              <div className="flex min-h-0 flex-col gap-4">
                <Card className="min-h-0 flex-1">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Support History</CardTitle>
                    <CardDescription>Durable action log with correlation IDs.</CardDescription>
                  </CardHeader>
                  <CardContent className="min-h-0">
                    <ScrollArea className="h-[52vh] pr-4">
                      <div className="space-y-3">
                        {selectedHistory.length === 0 ? (
                          <div className="text-sm text-muted-foreground">No support actions recorded yet.</div>
                        ) : (
                          selectedHistory.map((row) => (
                            <div key={row.id} className="rounded-lg border p-3">
                              <div className="flex flex-wrap items-center gap-2">
                                <Badge variant="outline">{row.action_type}</Badge>
                                <Badge className={cn("border", healthBadgeClass(
                                  row.result === "FAILED"
                                    ? "ERROR"
                                    : row.result === "BLOCKED"
                                      ? "WARNING"
                                      : row.result === "SKIPPED"
                                        ? "STOPPED"
                                        : "HEALTHY",
                                ))}>
                                  {row.result}
                                </Badge>
                              </div>
                              <div className="mt-2 text-xs text-muted-foreground">
                                Correlation: {row.correlation_id}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Started: {formatTimestamp(row.started_at)}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Finished: {formatTimestamp(row.finished_at)}
                              </div>
                              {(row.message || row.error_message) && (
                                <div className="mt-2 text-sm">
                                  {row.message || row.error_message}
                                </div>
                              )}
                              {row.error_code && (
                                <div className="mt-1 font-mono text-xs text-muted-foreground">
                                  {row.error_code}
                                </div>
                              )}
                            </div>
                          ))
                        )}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Recent Events</CardTitle>
                    <CardDescription>Unified binding, player, and support events for troubleshooting.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {!selectedDiagnostics || selectedDiagnostics.recentEvents.rows.length === 0 ? (
                      <div className="text-sm text-muted-foreground">No recent binding/player/support events yet.</div>
                    ) : (
                      selectedDiagnostics.recentEvents.rows.slice(0, 8).map((row) => (
                        <div key={`${row.source}-${row.id}-${row.createdAt}`} className="rounded-lg border p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge variant="outline">{row.source}</Badge>
                            {row.eventType && <Badge variant="outline">{row.eventType}</Badge>}
                            {row.severity && (
                              <Badge className={cn("border", healthBadgeClass(
                                row.severity === "ERROR"
                                  ? "ERROR"
                                  : row.severity === "WARN"
                                    ? "WARNING"
                                    : "HEALTHY",
                              ))}>
                                {row.severity}
                              </Badge>
                            )}
                          </div>
                          <div className="mt-2 text-sm">{row.message || "No message"}</div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {formatTimestamp(row.createdAt)}{row.correlationId ? ` · ${row.correlationId}` : ""}
                          </div>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog open={confirmAction !== null} onOpenChange={(open) => { if (!open) setConfirmAction(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{confirmAction ? ACTION_LABELS[confirmAction.actionType] : "Confirm action"}</AlertDialogTitle>
            <AlertDialogDescription>
              {confirmAction
                ? ACTION_DESCRIPTIONS[confirmAction.actionType] || "This action requires confirmation before it runs."
                : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!confirmAction) {
                  return;
                }
                void runAction(confirmAction.bindingId, confirmAction.actionType, undefined, true);
                setConfirmAction(null);
              }}
            >
              Confirm
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
