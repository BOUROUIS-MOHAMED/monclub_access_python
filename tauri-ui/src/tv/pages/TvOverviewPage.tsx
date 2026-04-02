import { useCallback, useEffect, useMemo, useState } from "react";
import { availableMonitors } from "@tauri-apps/api/window";
import {
  Activity,
  AlertCircle,
  Database,
  Download,
  Eye,
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
  checkTvUpdate,
  createTvHostBinding,
  deleteTvHostBinding,
  downloadTvUpdate,
  getTvBindingSupportHistory,
  getTvBindingSupportSummary,
  getTvDashboardScreens,
  getTvHostBindings,
  getTvHostMonitors,
  getTvObservabilityBinding,
  getTvObservabilityOverview,
  getTvObservabilityRetention,
  refreshTvHostMonitors,
  getTvStartupLatest,
  getTvStartupPreflight,
  getTvStartupRuns,
  getTvUpdateStatus,
  installTvUpdate,
  restartTvHostBinding,
  runTvBindingSupportAction,
  runTvObservabilityRetention,
  runTvStartupReconciliation,
  runTvSnapshotSync,
  startTvHostBinding,
  stopTvHostBinding,
} from "@/tv/api";
import type {
  UpdateStatusResponse,
  TvBindingHealthSummary,
  TvObservabilityBindingDetail,
  TvObservabilityOverviewResponse,
  TvObservabilityRetentionResponse,
  TvBindingSupportActionType,
  TvBindingSupportSummaryResponse,
  TvDashboardScreen,
  TvHostMonitor,
  TvScreenBinding,
  TvStartupLatestResponse,
  TvStartupPreflightResponse,
  TvStartupReconciliationRun,
  TvSupportActionLogRow,
} from "@/tv/api/types";
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import type { TvOverviewSectionId } from "@/tv/navigation";
import { ensureTvPlayerWindow } from "@/tv/runtime/playerWindows";

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

const CREATE_SCREEN_EMPTY_VALUE = "__none__";

function healthBadgeClass(health: TvBindingHealthSummary | undefined) {
  switch (health) {
    case "HEALTHY":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
    case "WARNING":
      return "border-amber-500/30 bg-amber-500/10 text-amber-400";
    case "DEGRADED":
      return "border-orange-500/30 bg-orange-500/10 text-orange-400";
    case "ERROR":
      return "border-red-500/30 bg-red-500/10 text-red-400";
    case "STOPPED":
      return "border-border bg-muted text-muted-foreground";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

function startupBadgeClass(status: string | null | undefined) {
  switch (status) {
    case "SUCCESS":
    case "PASSED":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
    case "SUCCESS_WITH_WARNINGS":
    case "WARNING":
    case "REPAIRED":
      return "border-amber-500/30 bg-amber-500/10 text-amber-400";
    case "BLOCKER":
    case "FAILED":
    case "ERROR":
      return "border-red-500/30 bg-red-500/10 text-red-400";
    case "INFO":
      return "border-sky-500/30 bg-sky-500/10 text-sky-400";
    case "SKIPPED":
    case "BLOCKED":
      return "border-border bg-muted text-muted-foreground";
    default:
      return "border-border bg-muted text-muted-foreground";
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

function formatEpochSeconds(value: number | null | undefined) {
  if (!value) {
    return "n/a";
  }
  const parsed = new Date(value * 1000);
  if (Number.isNaN(parsed.getTime())) {
    return "n/a";
  }
  return parsed.toLocaleString();
}

function stringValue(value: unknown) {
  if (value == null) {
    return "";
  }
  return String(value);
}

function matchesBindingMonitor(binding: TvScreenBinding, monitor: TvHostMonitor) {
  const candidates = [binding.monitor_id, binding.monitor_label].filter(Boolean);
  return candidates.includes(monitor.monitor_id) || candidates.includes(monitor.monitor_label);
}

const TV_SECTION_ELEMENT_IDS: Record<TvOverviewSectionId, string> = {
  overview: "tv-section-overview",
  updates: "tv-section-updates",
  startup: "tv-section-startup",
  operations: "tv-section-operations",
  bindings: "tv-section-bindings",
};

function sectionShellClass(sectionId: TvOverviewSectionId, focusSection: TvOverviewSectionId) {
  return cn(
    "scroll-mt-6 rounded-xl transition-all duration-200",
    focusSection === sectionId && "ring-1 ring-primary/30 ring-offset-2 ring-offset-background",
  );
}

interface TvOverviewPageProps {
  focusSection?: TvOverviewSectionId;
}

export default function TvOverviewPage({ focusSection = "overview" }: TvOverviewPageProps) {
  const [monitors, setMonitors] = useState<TvHostMonitor[]>([]);
  const [bindings, setBindings] = useState<TvScreenBinding[]>([]);
  const [supportByBinding, setSupportByBinding] = useState<Record<number, TvBindingSupportSummaryResponse>>({});
  const [overview, setOverview] = useState<TvObservabilityOverviewResponse | null>(null);
  const [retention, setRetention] = useState<TvObservabilityRetentionResponse | null>(null);
  const [startupLatest, setStartupLatest] = useState<TvStartupLatestResponse | null>(null);
  const [startupPreflight, setStartupPreflight] = useState<TvStartupPreflightResponse | null>(null);
  const [startupRuns, setStartupRuns] = useState<TvStartupReconciliationRun[]>([]);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedBindingId, setSelectedBindingId] = useState<number | null>(null);
  const [previewBindingId, setPreviewBindingId] = useState<number | null>(null);
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
  const [updateBusyAction, setUpdateBusyAction] = useState<"check" | "download" | "install" | null>(null);
  const [updateFeedback, setUpdateFeedback] = useState<string | null>(null);
  const [tvSyncing, setTvSyncing] = useState(false);
  const [confirmAction, setConfirmAction] = useState<{
    bindingId: number;
    actionType: TvBindingSupportActionType;
  } | null>(null);

  // Create binding dialog
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [dashboardScreens, setDashboardScreens] = useState<TvDashboardScreen[]>([]);
  const [dashboardScreensLoading, setDashboardScreensLoading] = useState(false);
  const [dashboardScreensError, setDashboardScreensError] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState({
    screen_id: "",
    screen_label: "",
    monitor_id: "",
    enabled: true,
    autostart: false,
    fullscreen: true,
  });

  const selectedBinding = useMemo(
    () => bindings.find((binding) => binding.id === selectedBindingId) ?? null,
    [bindings, selectedBindingId],
  );

  const previewBinding = useMemo(
    () => bindings.find((binding) => binding.id === previewBindingId) ?? null,
    [bindings, previewBindingId],
  );

  const previewMonitor = useMemo(() => {
    if (!previewBinding) {
      return null;
    }
    return monitors.find((monitor) => matchesBindingMonitor(previewBinding, monitor)) ?? null;
  }, [monitors, previewBinding]);

  const dashboardScreenById = useMemo(() => {
    const next = new Map<number, TvDashboardScreen>();
    for (const screen of dashboardScreens) {
      next.set(screen.id, screen);
    }
    return next;
  }, [dashboardScreens]);

  const boundScreenIds = useMemo(
    () => new Set(bindings.map((binding) => binding.screen_id)),
    [bindings],
  );

  const selectedCreateScreen = useMemo(() => {
    const sid = parseInt(createForm.screen_id, 10);
    if (!sid || sid <= 0) {
      return null;
    }
    return dashboardScreenById.get(sid) ?? null;
  }, [createForm.screen_id, dashboardScreenById]);

  const createScreenAlreadyBound = useMemo(() => {
    const sid = parseInt(createForm.screen_id, 10);
    return Boolean(sid && boundScreenIds.has(sid));
  }, [boundScreenIds, createForm.screen_id]);

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

  const syncHostMonitors = useCallback(async () => {
    const monitorList = await availableMonitors();
    const monitorPayload = monitorList.map((monitor, index) => ({
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
    try {
      await refreshTvHostMonitors(monitorPayload);
    } catch (error) {
      console.warn("Failed to refresh TV host monitors before player action.", error);
    }
    return monitorList;
  }, []);

  const loadDashboardScreens = useCallback(async () => {
    setDashboardScreensLoading(true);
    setDashboardScreensError(null);
    try {
      const response = await getTvDashboardScreens({
        includeArchived: false,
        page: 0,
        size: 100,
        sortBy: "name",
        sortDir: "asc",
      });
      setDashboardScreens(response.items ?? []);
    } catch (err) {
      setDashboardScreens([]);
      setDashboardScreensError(err instanceof Error ? err.message : "Failed to load dashboard screens.");
    } finally {
      setDashboardScreensLoading(false);
    }
  }, []);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [monitorResponse, bindingResponse, overviewResponse, retentionResponse, startupLatestResponse, startupPreflightResponse, startupRunsResponse, updateStatusResponse] = await Promise.all([
        getTvHostMonitors(),
        getTvHostBindings(),
        getTvObservabilityOverview(),
        getTvObservabilityRetention(),
        getTvStartupLatest(),
        getTvStartupPreflight(),
        getTvStartupRuns(8, 0),
        getTvUpdateStatus().catch(() => null),
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
      setUpdateStatus(updateStatusResponse);
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

  useEffect(() => {
    void loadDashboardScreens();
  }, [loadDashboardScreens]);

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
      const monitorList = await syncHostMonitors();
      const response = await startTvHostBinding(bindingId);
      const binding = response.binding ?? bindings.find((item) => item.id === bindingId) ?? null;
      if (binding) {
        const result = await ensureTvPlayerWindow(binding, monitorList);
        if (!result.ok) {
          setError(result.reason);
        }
      }
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start binding.");
    }
  }, [bindings, fetchData, syncHostMonitors]);

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
      const monitorList = await syncHostMonitors();
      const response = await restartTvHostBinding(bindingId);
      const binding = response.binding ?? bindings.find((item) => item.id === bindingId) ?? null;
      if (binding) {
        await ensureTvPlayerWindow(binding, monitorList);
      }
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to restart binding.");
    }
  }, [bindings, fetchData, syncHostMonitors]);

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

  const openCreateDialog = useCallback(() => {
    const preferredScreen = dashboardScreens.find((screen) => !boundScreenIds.has(screen.id))
      ?? null;
    setCreateForm({
      screen_id: preferredScreen ? String(preferredScreen.id) : "",
      screen_label: preferredScreen?.name ?? "",
      monitor_id: monitors[0]?.monitor_id ?? "",
      enabled: true,
      autostart: false,
      fullscreen: true,
    });
    setCreateDialogOpen(true);
  }, [boundScreenIds, dashboardScreens, monitors]);

  const handleCreateSubmit = useCallback(async () => {
    const sid = parseInt(createForm.screen_id, 10);
    if (!sid || sid <= 0) {
      setError("Please select a dashboard screen.");
      return;
    }
    if (createScreenAlreadyBound) {
      setError("This dashboard screen is already bound on this host.");
      return;
    }
    setCreateBusy(true);
    setError(null);
    try {
      await syncHostMonitors();
      const selectedMonitor = monitors.find((m) => m.monitor_id === createForm.monitor_id);
      await createTvHostBinding({
        screen_id: sid,
        screen_name: selectedCreateScreen?.name || createForm.screen_label.trim() || undefined,
        monitor_id: createForm.monitor_id || undefined,
        monitor_label: selectedMonitor?.monitor_label || undefined,
        monitor_index: selectedMonitor?.monitor_index ?? undefined,
        enabled: createForm.enabled,
        autostart: createForm.autostart,
        fullscreen: createForm.fullscreen,
        target_display_id: createForm.monitor_id || undefined,
        last_known_friendly_name: selectedMonitor?.monitor_label || undefined,
        last_known_bounds_x: selectedMonitor?.offset_x ?? undefined,
        last_known_bounds_y: selectedMonitor?.offset_y ?? undefined,
        last_known_width: selectedMonitor?.width ?? undefined,
        last_known_height: selectedMonitor?.height ?? undefined,
        last_known_display_order_index: selectedMonitor?.monitor_index ?? undefined,
      });
      setCreateDialogOpen(false);
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create binding.");
    } finally {
      setCreateBusy(false);
    }
  }, [createForm, createScreenAlreadyBound, selectedCreateScreen, monitors, fetchData, syncHostMonitors]);

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
      const monitors = await syncHostMonitors();
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
  }, [fetchData, refreshPanel, selectedBindingId, syncHostMonitors]);

  const handleTvSyncNow = useCallback(async () => {
    setTvSyncing(true);
    try {
      await runTvSnapshotSync();
      setTimeout(() => {
        void fetchData();
      }, 2000);
    } catch (err) {
      console.error("[TV Sync]", err);
    } finally {
      setTvSyncing(false);
    }
  }, [fetchData]);

  const handleUpdateAction = useCallback(async (action: "check" | "download" | "install") => {
    setUpdateBusyAction(action);
    setUpdateFeedback(null);
    try {
      if (action === "check") {
        await checkTvUpdate();
        setUpdateFeedback("TV update check requested.");
      } else if (action === "download") {
        await downloadTvUpdate();
        setUpdateFeedback("TV update download requested.");
      } else {
        await installTvUpdate();
        setUpdateFeedback("TV updater launch requested.");
      }
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${action} TV update.`);
    } finally {
      setUpdateBusyAction(null);
    }
  }, [fetchData]);

  const connectedMonitorCount = useMemo(
    () => monitors.filter((monitor) => monitor.is_connected).length,
    [monitors],
  );

  const attentionBindingCount = useMemo(() => {
    if (overview) {
      return overview.totals.staleProblemBindingsCount;
    }
    return Object.values(supportByBinding).filter((summary) => summary.health && summary.health !== "HEALTHY").length;
  }, [overview, supportByBinding]);

  const showOverviewPage = focusSection === "overview";
  const showUpdatesPage = focusSection === "updates";
  const showStartupPage = focusSection === "startup";
  const showOperationsPage = focusSection === "operations";
  const showBindingsPage = focusSection === "bindings";

  return (
    <div className="space-y-6 text-foreground">
      <div className="rounded-xl border border-border bg-card p-5 md:p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2">
              <div className="inline-flex items-center gap-1.5 rounded-md border border-primary/25 bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary uppercase tracking-wide">
                <Monitor className="h-3 w-3" />
                Host Console
              </div>
            </div>
            <h2 className="text-xl font-semibold tracking-tight text-foreground">
              TV Command Center
            </h2>
            <p className="text-[13px] leading-5 text-muted-foreground max-w-2xl">
              Global health, binding pressure, and quick operator actions for the signage runtime.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Button
              size="sm"
              variant="outline"
              onClick={() => void fetchData()}
              disabled={loading}
            >
              <RefreshCw className={cn("mr-1.5 h-3.5 w-3.5", loading && "animate-spin")} />
              Refresh
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => void handleTvSyncNow()}
              disabled={tvSyncing}
            >
              <RefreshCw className={cn("mr-1.5 h-3.5 w-3.5", tvSyncing && "animate-spin")} />
              {tvSyncing ? "Syncing…" : "Sync Now"}
            </Button>
            <Button
              size="sm"
              onClick={openCreateDialog}
            >
              Create Binding
            </Button>
          </div>
        </div>

        <div className="mt-5 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-lg border border-border bg-muted/40 px-4 py-3">
            <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Bindings</div>
            <div className="mt-2 text-2xl font-semibold text-foreground">{overview?.totals.totalBindings ?? bindings.length}</div>
            <div className="mt-1 text-[12px] text-muted-foreground">
              {overview?.totals.healthyBindings ?? 0} healthy · {attentionBindingCount} need attention
            </div>
          </div>
          <div className="rounded-lg border border-border bg-muted/40 px-4 py-3">
            <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Displays</div>
            <div className="mt-2 text-2xl font-semibold text-foreground">{connectedMonitorCount}</div>
            <div className="mt-1 text-[12px] text-muted-foreground">{monitors.length} monitor(s) detected on this host</div>
          </div>
          <div className="rounded-lg border border-border bg-muted/40 px-4 py-3">
            <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Startup Safety</div>
            <div className="mt-2 text-2xl font-semibold text-foreground">{startupPreflight?.counts.blockerCount ?? 0}</div>
            <div className="mt-1 text-[12px] text-muted-foreground">
              Blocker(s) · latest {startupLatest?.status ?? "NO_RUN"}
            </div>
          </div>
          <div className="rounded-lg border border-border bg-muted/40 px-4 py-3">
            <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Updater</div>
            <div className="mt-2 text-2xl font-semibold text-foreground">{updateStatus?.updateAvailable ? "Ready" : "Current"}</div>
            <div className="mt-1 text-[12px] text-muted-foreground">
              {updateStatus?.componentDisplayName || "MonClub TV"} · {updateStatus?.channel || "stable"}
            </div>
          </div>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {showOverviewPage && (
      <section id={TV_SECTION_ELEMENT_IDS.overview} className={sectionShellClass("overview", focusSection)}>
        {overview && (
        <Card className="border-border bg-card shadow-none">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-[15px]">
              <HeartPulse className="h-4 w-4 text-primary" />
              Host Observability
            </CardTitle>
            <CardDescription className="text-[13px]">
              Derived host-level health, proof backlog, and stale/problem signals from factual TV runtime state.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
              <div className="rounded-lg border border-border bg-muted/40 px-3 py-3">
                <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Bindings</div>
                <div className="mt-2 text-xl font-semibold text-foreground">{overview.totals.totalBindings}</div>
                <div className="mt-1 text-[11px] text-muted-foreground leading-4">
                  {overview.totals.healthyBindings} healthy · {overview.totals.warningBindings} warn · {overview.totals.errorBindings} error
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 px-3 py-3">
                <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Runtime</div>
                <div className="mt-2 text-xl font-semibold text-foreground">{overview.totals.activePlayerWindows}</div>
                <div className="mt-1 text-[11px] text-muted-foreground leading-4">
                  Player windows · {overview.totals.activeMonitors} active monitor(s)
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 px-3 py-3">
                <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Ad / Proof</div>
                <div className="mt-2 text-xl font-semibold text-foreground">{overview.totals.queuedOrRetryableProofCount}</div>
                <div className="mt-1 text-[11px] text-muted-foreground leading-4">
                  Queued · {overview.totals.activeGymAdRuntimes} gym ad runtime(s)
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 px-3 py-3">
                <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Recovery</div>
                <div className="mt-2 text-xl font-semibold text-foreground">{overview.totals.recentFailedDownloadsCount}</div>
                <div className="mt-1 text-[11px] text-muted-foreground leading-4">
                  Failed asset(s) · {overview.totals.recentSupportActionsCount} actions in {overview.recentSupportWindowHours}h
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 px-3 py-3">
                <div className="text-[11px] uppercase tracking-widest text-muted-foreground font-medium">Problems</div>
                <div className="mt-2 text-xl font-semibold text-foreground">{overview.totals.staleProblemBindingsCount}</div>
                <div className="mt-1 text-[11px] text-muted-foreground leading-4">
                  Stale or unhealthy bindings
                </div>
              </div>
            </div>
            {overview.problemBindings.length > 0 && (
              <div className="space-y-2">
                <div className="text-[13px] font-medium text-foreground">Bindings needing attention</div>
                <div className="grid gap-2 md:grid-cols-2">
                  {overview.problemBindings.slice(0, 4).map((row) => (
                    <div key={row.bindingId} className="rounded-lg border border-border bg-muted/30 px-3 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[13px] font-medium text-foreground">{row.screenLabel}</span>
                        <Badge className={cn("border text-[11px]", healthBadgeClass(row.health))}>{row.health}</Badge>
                      </div>
                      <div className="mt-1 text-[11px] text-muted-foreground">
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
      </section>
      )}

      {showUpdatesPage && (
      <section id={TV_SECTION_ELEMENT_IDS.updates} className={sectionShellClass("updates", focusSection)}>
        {updateStatus ? (
        <Card className="border-border bg-card shadow-none">
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between pb-3">
            <div>
              <CardTitle className="flex items-center gap-2 text-[15px]">
                <Download className="h-4 w-4 text-primary" />
                TV Updates
              </CardTitle>
              <CardDescription className="text-[13px]">
                TV-owned update runtime state for the standalone signage component.
              </CardDescription>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => void handleUpdateAction("check")}
                disabled={updateBusyAction !== null}
              >
                <RefreshCw className={cn("mr-2 h-3.5 w-3.5", updateBusyAction === "check" && "animate-spin")} />
                Check
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => void handleUpdateAction("download")}
                disabled={updateBusyAction !== null || !updateStatus.updateAvailable}
              >
                <Download className={cn("mr-2 h-3.5 w-3.5", updateBusyAction === "download" && "animate-pulse")} />
                Download
              </Button>
              <Button
                size="sm"
                onClick={() => void handleUpdateAction("install")}
                disabled={updateBusyAction !== null || !updateStatus.downloaded}
              >
                <Play className="mr-2 h-3.5 w-3.5" />
                Install
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-lg border border-border bg-muted/40 p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Component</div>
                <div className="mt-2 text-base font-semibold">{updateStatus.componentDisplayName || "MonClub TV"}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  {updateStatus.mainExecutable || "MonClubTV.exe"} · {updateStatus.channel || "stable"}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Current Version</div>
                <div className="mt-2 text-base font-semibold">
                  {updateStatus.currentVersion && updateStatus.currentVersion !== "0.0.0"
                    ? updateStatus.currentVersion
                    : (updateStatus.currentReleaseId || "dev")}
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Last check {formatEpochSeconds(updateStatus.lastCheckAt)}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Availability</div>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <Badge variant={updateStatus.updateAvailable ? "warning" : "outline"}>
                    {updateStatus.updateAvailable ? "Update Available" : "Up To Date"}
                  </Badge>
                  {updateStatus.downloaded && <Badge variant="outline">Downloaded</Badge>}
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  {updateStatus.latestVersion ? `Version ${updateStatus.latestVersion}` : (updateStatus.latestRelease?.releaseId || "No newer TV release detected.")}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Installer Package</div>
                <div className="mt-2 text-base font-semibold">
                  {updateStatus.downloaded ? "Downloaded EXE Ready" : "Downloaded EXE Required"}
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  {updateStatus.latestVersion ? `monclub_tv_${updateStatus.latestVersion}.exe` : "monclub_tv_<version>.exe"}
                </div>
              </div>
            </div>
            {updateFeedback && (
              <Alert>
                <AlertDescription>{updateFeedback}</AlertDescription>
              </Alert>
            )}
            {updateStatus.lastError && (
              <Alert variant="destructive">
                <AlertDescription>{updateStatus.lastError}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
        ) : (
          <Card className="border-border bg-card shadow-none">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Download className="h-4 w-4" />
                TV Updates
              </CardTitle>
              <CardDescription>The standalone TV updater has not reported status yet. Use Refresh Host or reopen the window if this stays empty.</CardDescription>
            </CardHeader>
          </Card>
        )}
      </section>
      )}

      {showStartupPage && (
      <section id={TV_SECTION_ELEMENT_IDS.startup} className={sectionShellClass("startup", focusSection)}>
        {(startupPreflight || startupLatest || startupRuns.length > 0) ? (
        <Card className="border-border bg-card shadow-none">
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
              <div className="rounded-lg border border-border bg-muted/40 p-4">
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
              <div className="rounded-lg border border-border bg-muted/40 p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Preflight Blockers</div>
                <div className="mt-2 text-2xl font-semibold">{startupPreflight?.counts.blockerCount ?? 0}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Warning {startupPreflight?.counts.warningCount ?? 0} · Info {startupPreflight?.counts.infoCount ?? 0}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 p-4">
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Startup Correlation</div>
                <div className="mt-2 text-sm font-medium">{startupLatest?.correlationId || "n/a"}</div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Trigger {startupLatest?.triggerSource || "unknown"}
                </div>
              </div>
              <div className="rounded-lg border border-border bg-muted/40 p-4">
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
                        <div key={`${item.severity}-${item.code}`} className="rounded-lg border border-border p-3">
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
                        <div key={`${phase.id}-${phase.phaseName}`} className="rounded-lg border border-border p-3">
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
                        <div key={run.id} className="rounded-lg border border-border p-3">
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
        ) : (
          <Card className="border-border bg-card shadow-none">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" />
                Startup Diagnostics
              </CardTitle>
              <CardDescription>No startup reconciliation history is available yet for this TV host.</CardDescription>
            </CardHeader>
          </Card>
        )}
      </section>
      )}

      {showOperationsPage && (
      <section id={TV_SECTION_ELEMENT_IDS.operations} className={sectionShellClass("operations", focusSection)}>
        {retention && (
        <Card className="border-border bg-card shadow-none">
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
                <div key={row.table} className="rounded-lg border border-border bg-muted/40 p-3">
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

      <Card className="border-border bg-card shadow-none">
        <CardHeader>
          <CardTitle>Detected Monitors</CardTitle>
          <CardDescription>Physical monitors reported by the TV host runtime.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            {monitors.map((monitor) => (
              <div key={monitor.id} className="rounded-lg border border-border bg-muted/40 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium">{monitor.monitor_label}</div>
                    <div className="text-xs text-muted-foreground">{monitor.monitor_id}</div>
                  </div>
                  <Badge className={cn("border", monitor.is_connected ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400" : "border-border bg-muted text-muted-foreground")}>
                    {monitor.is_connected ? "Connected" : "Disconnected"}
                  </Badge>
                </div>
                <div className="mt-3 text-xs text-muted-foreground">
                  {monitor.width}x{monitor.height} @ [{monitor.offset_x}, {monitor.offset_y}]
                </div>
              </div>
            ))}
            {monitors.length === 0 && (
              <div className="rounded-2xl border border-dashed p-6 text-sm text-muted-foreground">
                No monitors detected yet.
              </div>
            )}
          </div>
        </CardContent>
      </Card>
      </section>
      )}

      {showBindingsPage && (
      <section id={TV_SECTION_ELEMENT_IDS.bindings} className={sectionShellClass("bindings", focusSection)}>
      <Card className="border-border bg-card shadow-none">
        <CardHeader>
          <CardTitle>Bindings</CardTitle>
          <CardDescription>Each binding maps one logical screen to one host runtime.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {bindings.length === 0 ? (
            <div className="rounded-2xl border border-dashed p-6 text-sm text-muted-foreground">
              No bindings configured.
            </div>
          ) : (
            bindings.map((binding) => {
              const summary = supportByBinding[binding.id];
              const runtime = binding.runtime?.runtime_state || "UNKNOWN";
              return (
                <div key={binding.id} className="rounded-lg border border-border bg-muted/30 p-4">
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
                        {binding.autostart && (
                          <Badge variant="outline" className="border-sky-500/40 bg-sky-500/10 text-sky-400">
                            Auto-start
                          </Badge>
                        )}
                        {!binding.enabled && (
                          <Badge variant="outline" className="border-border bg-muted text-muted-foreground">
                            Disabled
                          </Badge>
                        )}
                      </div>
                      <div className="grid gap-1 text-sm text-muted-foreground">
                        <span>Monitor: {binding.monitor_label || binding.monitor_id || "Unassigned"}</span>
                        {binding.display_attach_confidence && (
                          <span>Display attach: {binding.display_attach_confidence}</span>
                        )}
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
                          Launch Player
                        </Button>
                      ) : (
                        <>
                          <Button size="sm" variant="secondary" onClick={() => void handleRestart(binding.id)}>
                            <RotateCcw className="mr-2 h-3.5 w-3.5" />
                            Restart Player
                          </Button>
                          <Button size="sm" variant="destructive" onClick={() => void handleStop(binding.id)}>
                            <Square className="mr-2 h-3.5 w-3.5 fill-current" />
                            Stop Player
                          </Button>
                        </>
                      )}
                      <Button size="sm" variant="outline" onClick={() => setPreviewBindingId(binding.id)}>
                        <Eye className="mr-2 h-3.5 w-3.5" />
                        Preview Layout
                      </Button>
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
      </section>
      )}

      <Dialog open={previewBindingId !== null} onOpenChange={(open) => { if (!open) setPreviewBindingId(null); }}>
        <DialogContent className="max-w-4xl border-border bg-card text-foreground">
          <DialogHeader>
            <DialogTitle>Screen Preview</DialogTitle>
            <DialogDescription>
              {previewBinding
                ? `${previewBinding.screen_label} (binding #${previewBinding.id})`
                : "TV screen preview"}
            </DialogDescription>
          </DialogHeader>

          {previewBinding && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                <Badge className="border-primary/25 bg-primary/10 text-primary">Preview only</Badge>
                <Badge variant="outline">Screen #{previewBinding.screen_id}</Badge>
                <Badge variant="outline">{previewBinding.monitor_label || previewBinding.monitor_id || "Unassigned monitor"}</Badge>
                <Badge variant="outline">{previewBinding.fullscreen ? "Fullscreen" : "Windowed"}</Badge>
                {previewMonitor && (
                  <Badge variant="outline">{previewMonitor.width}x{previewMonitor.height}</Badge>
                )}
              </div>

              <div className="overflow-hidden rounded-lg border border-border bg-background p-3">
                <div
                  className="relative mx-auto flex max-w-4xl items-center justify-center overflow-hidden rounded-md border border-border bg-muted/30"
                  style={{
                    aspectRatio: previewMonitor && previewMonitor.width > 0 && previewMonitor.height > 0
                      ? `${previewMonitor.width} / ${previewMonitor.height}`
                      : "16 / 9",
                  }}
                >
                  <div className="relative flex h-full w-full flex-col gap-3 p-4">
                    <div className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2">
                      <div>
                        <div className="text-[10px] uppercase tracking-widest text-muted-foreground">MonClub TV Preview</div>
                        <div className="mt-0.5 text-sm font-semibold text-foreground">{previewBinding.screen_label}</div>
                      </div>
                      <div className="text-right text-[11px] text-muted-foreground">
                        <div>{previewBinding.window_label || `Screen ${previewBinding.screen_id}`}</div>
                        <div>{previewMonitor ? `${previewMonitor.width}x${previewMonitor.height}` : "16:9"}</div>
                      </div>
                    </div>

                    <div className={cn(
                      "grid min-h-0 flex-1 gap-3",
                      previewMonitor && previewMonitor.height > previewMonitor.width
                        ? "grid-rows-[1.1fr_0.9fr]"
                        : "lg:grid-cols-[1.3fr_0.7fr]",
                    )}>
                      <div className="relative flex items-center justify-center overflow-hidden rounded-md border border-dashed border-border bg-muted/20 px-6 text-center">
                        <div>
                          <div className="text-2xl font-semibold tracking-tight text-foreground">{previewBinding.screen_label}</div>
                          <div className="mt-2 text-[12px] text-muted-foreground">
                            Non-live preview. Layout and framing reference only.
                          </div>
                          <div className="mt-1 text-[11px] text-muted-foreground">{previewBinding.fullscreen ? "Fullscreen" : "Windowed"}</div>
                        </div>
                      </div>

                      <div className="grid gap-2">
                        <div className="rounded-md border border-border bg-card px-3 py-2">
                          <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Binding</div>
                          <div className="mt-1 text-sm font-semibold text-foreground">#{previewBinding.id}</div>
                          <div className="text-[11px] text-muted-foreground">Desired {previewBinding.desired_state}</div>
                        </div>
                        <div className="rounded-md border border-border bg-card px-3 py-2">
                          <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Player State</div>
                          <div className="mt-1 text-sm font-semibold text-foreground">{previewBinding.runtime?.runtime_state || "UNKNOWN"}</div>
                          <div className="text-[11px] text-muted-foreground">{previewBinding.monitor_label || previewBinding.monitor_id || "No monitor"}</div>
                        </div>
                        <div className="rounded-md border border-border bg-card px-3 py-2">
                          <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Canvas</div>
                          <div className="mt-1 text-sm font-semibold text-foreground">
                            {previewMonitor ? `${previewMonitor.width}:${previewMonitor.height}` : "16:9"}
                          </div>
                          <div className="text-[11px] text-muted-foreground">
                            {previewMonitor && previewMonitor.height > previewMonitor.width ? "Portrait" : "Landscape"}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center justify-between rounded-md border border-border bg-muted/30 px-3 py-2 text-[11px] text-muted-foreground">
                      <span>Preview canvas only</span>
                      <span>Runtime state unchanged</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

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

              <ScrollArea className="max-h-[68vh] pr-4">
              <div className="flex flex-col gap-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base">Support History</CardTitle>
                    <CardDescription>Durable action log with correlation IDs.</CardDescription>
                  </CardHeader>
                  <CardContent>
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
              </ScrollArea>
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

      {/* Create binding dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create binding</DialogTitle>
            <DialogDescription>
              Link a MonClub screen to a physical display on this host.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="cb-screen-select">Screen</Label>
              <Select
                value={createForm.screen_id || CREATE_SCREEN_EMPTY_VALUE}
                onValueChange={(value) => {
                  if (value === CREATE_SCREEN_EMPTY_VALUE) {
                    setCreateForm((form) => ({ ...form, screen_id: "", screen_label: "" }));
                    return;
                  }
                  const nextScreen = dashboardScreens.find((screen) => screen.id === Number(value)) ?? null;
                  setCreateForm((form) => ({
                    ...form,
                    screen_id: value,
                    screen_label: nextScreen?.name ?? "",
                  }));
                }}
              >
                <SelectTrigger id="cb-screen-select">
                  <SelectValue placeholder="Select a dashboard screen" />
                </SelectTrigger>
                <SelectContent>
                  {dashboardScreens.map((screen) => {
                    const isBound = boundScreenIds.has(screen.id);
                    const label = `${screen.name} (#${screen.id})${isBound ? " - already bound" : ""}`;
                    return (
                      <SelectItem key={screen.id} value={String(screen.id)} disabled={isBound}>
                        {label}
                      </SelectItem>
                    );
                  })}
                  {dashboardScreens.length === 0 && (
                    <SelectItem value={CREATE_SCREEN_EMPTY_VALUE} disabled>
                      {dashboardScreensLoading ? "Loading dashboard screens..." : "No dashboard screens available"}
                    </SelectItem>
                  )}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Choose a real dashboard screen and MonClub TV will store its screen id automatically.
              </p>
            </div>
            {dashboardScreensError && (
              <Alert variant="destructive">
                <AlertDescription>{dashboardScreensError}</AlertDescription>
              </Alert>
            )}
            {createScreenAlreadyBound && (
              <Alert>
                <AlertDescription>
                  This dashboard screen is already bound on this host. Select a different screen to continue.
                </AlertDescription>
              </Alert>
            )}
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Selected screen id</Label>
                <div className="rounded-md border border-border bg-muted/30 px-3 py-2 text-sm text-foreground">
                  {createForm.screen_id || "No screen selected"}
                </div>
              </div>
              <div className="space-y-1.5">
                <Label>Screen label</Label>
                <div className="rounded-md border border-border bg-muted/30 px-3 py-2 text-sm text-foreground">
                  {selectedCreateScreen?.name || createForm.screen_label || "No screen selected"}
                </div>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cb-monitor">Monitor</Label>
              <Select
                value={createForm.monitor_id}
                onValueChange={(v) => setCreateForm((f) => ({ ...f, monitor_id: v }))}
              >
                <SelectTrigger id="cb-monitor">
                  <SelectValue placeholder="Select a monitor" />
                </SelectTrigger>
                <SelectContent>
                  {monitors.map((m) => (
                    <SelectItem key={m.monitor_id} value={m.monitor_id}>
                      {m.monitor_label || m.monitor_id} ({m.width}×{m.height})
                    </SelectItem>
                  ))}
                  {monitors.length === 0 && (
                    <SelectItem value="" disabled>No monitors detected</SelectItem>
                  )}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="cb-enabled" className="text-sm font-medium">Enabled</Label>
                <p className="text-xs text-muted-foreground">Binding will accept player sessions</p>
              </div>
              <Switch
                id="cb-enabled"
                checked={createForm.enabled}
                onCheckedChange={(v) => setCreateForm((f) => ({ ...f, enabled: v }))}
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="cb-autostart" className="text-sm font-medium">Auto-start</Label>
                <p className="text-xs text-muted-foreground">Launch player automatically on TV startup (requires master switch in Settings)</p>
              </div>
              <Switch
                id="cb-autostart"
                checked={createForm.autostart}
                onCheckedChange={(v) => setCreateForm((f) => ({ ...f, autostart: v }))}
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="cb-fullscreen" className="text-sm font-medium">Fullscreen</Label>
                <p className="text-xs text-muted-foreground">Open player window in fullscreen mode</p>
              </div>
              <Switch
                id="cb-fullscreen"
                checked={createForm.fullscreen}
                onCheckedChange={(v) => setCreateForm((f) => ({ ...f, fullscreen: v }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)} disabled={createBusy}>
              Cancel
            </Button>
            <Button
              onClick={() => void handleCreateSubmit()}
              disabled={createBusy || !createForm.screen_id || createScreenAlreadyBound}
            >
              {createBusy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
