import { startTransition, useCallback, useDeferredValue, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  Download,
  Loader2,
  RefreshCw,
  Sparkles,
  Wrench,
} from "lucide-react";

import {
  downloadTvAssets,
  getTvAssets,
  getTvLatestSnapshots,
  getTvObservabilityBinding,
  getTvObservabilityBindings,
  getTvPlayerRenderContext,
  getTvReadiness,
  getTvSnapshotAssets,
  runTvBindingSupportAction,
} from "@/tv/api";
import type {
  TvBindingHealthSummary,
  TvBindingSupportActionType,
  TvLocalAssetStateRow,
  TvObservabilityBindingDetail,
  TvObservabilityBindingSummary,
  TvPlayerRenderContext,
  TvSnapshotCacheRow,
  TvSnapshotReadinessRow,
  TvSnapshotRequiredAssetRow,
  TvSupportActionLogRow,
  TvTimelineItemPresented,
} from "@/tv/api/types";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

type DownloadsTab = "library" | "screens" | "history";
type LibraryScope = "selected" | "all";
type LibraryStateFilter = "ALL" | "READY" | "ATTENTION" | "ORPHAN";

interface TvLibraryOwner {
  bindingId: number;
  screenId: number;
  screenLabel: string;
  snapshotId: string;
  snapshotVersion: number;
  health: TvBindingHealthSummary;
}

interface TvDownloadLibraryItem {
  mediaAssetId: string;
  title: string | null;
  mediaType: string | null;
  mimeType: string | null;
  sizeBytes: number | null;
  durationSeconds: number | null;
  downloadLink: string | null;
  checksumSha256: string | null;
  timelineLabels: string[];
  sourcePresetItemIds: string[];
  localState: TvLocalAssetStateRow | null;
  requiredBy: TvLibraryOwner[];
  status: string;
  statusReason: string | null;
  orphan: boolean;
}

interface StatCardProps {
  icon: typeof Database;
  label: string;
  value: string;
  note: string;
  accentClassName: string;
}

const READY_ASSET_STATES = new Set(["VALID", "PRESENT_UNCHECKED"]);
const CONTENT_ACTIONS: TvBindingSupportActionType[] = [
  "RUN_SYNC",
  "RECOMPUTE_READINESS",
  "RETRY_FAILED_DOWNLOADS",
  "RETRY_ONE_DOWNLOAD",
  "REEVALUATE_ACTIVATION",
  "ACTIVATE_LATEST_READY",
];

function isAssetReady(state: string | null | undefined) {
  return READY_ASSET_STATES.has(String(state || "").toUpperCase());
}

function isLibraryItemAttention(item: TvDownloadLibraryItem) {
  return !item.orphan && !isAssetReady(item.status);
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

function formatBytes(value: number | null | undefined) {
  if (value == null || Number.isNaN(value)) {
    return "n/a";
  }
  if (value === 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let current = value;
  let unitIndex = 0;
  while (current >= 1024 && unitIndex < units.length - 1) {
    current /= 1024;
    unitIndex += 1;
  }
  const digits = current >= 100 || unitIndex === 0 ? 0 : current >= 10 ? 1 : 2;
  return `${current.toFixed(digits)} ${units[unitIndex]}`;
}

function formatDurationSeconds(value: number | null | undefined) {
  if (value == null || Number.isNaN(value)) {
    return "n/a";
  }
  const totalSeconds = Math.max(0, Math.round(value));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes <= 0) {
    return `${seconds}s`;
  }
  return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
}

function formatMinuteOfDay(value: number | null | undefined) {
  if (value == null || Number.isNaN(value)) {
    return "n/a";
  }
  const minute = Math.max(0, Math.floor(value));
  const hours = Math.floor(minute / 60) % 24;
  const mins = minute % 60;
  return `${String(hours).padStart(2, "0")}:${String(mins).padStart(2, "0")}`;
}

function safeString(value: unknown) {
  if (value == null) {
    return "";
  }
  return String(value);
}

function safeNumber(value: unknown) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

function extractPathName(path: string | null | undefined) {
  if (!path) {
    return "n/a";
  }
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

function describeTimelineRequirement(entry: unknown) {
  if (typeof entry === "string" || typeof entry === "number") {
    return String(entry);
  }
  if (!entry || typeof entry !== "object") {
    return "";
  }
  const row = entry as Record<string, unknown>;
  const timelineType = safeString(row.timelineType ?? row.timeline_type);
  const dayOfWeek = safeString(row.dayOfWeek ?? row.day_of_week);
  const startMinute = safeNumber(row.startMinuteOfDay ?? row.start_minute_of_day);
  const endMinute = safeNumber(row.endMinuteOfDay ?? row.end_minute_of_day);
  const windowLabel = startMinute != null && endMinute != null
    ? `${formatMinuteOfDay(startMinute)}-${formatMinuteOfDay(endMinute)}`
    : "";
  return [timelineType, dayOfWeek, windowLabel].filter(Boolean).join(" ");
}

function parseJsonStringArray(value: string | null | undefined, formatter?: (entry: unknown) => string) {
  if (!value) {
    return [];
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) {
      return [];
    }
    return uniqueStrings(
      parsed
        .map((entry) => formatter ? formatter(entry) : safeString(entry))
        .filter(Boolean),
    );
  } catch {
    return [];
  }
}

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

function readinessBadgeClass(state: string | null | undefined) {
  switch (String(state || "").toUpperCase()) {
    case "READY":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
    case "PARTIALLY_READY":
      return "border-amber-500/30 bg-amber-500/10 text-amber-400";
    case "NOT_READY":
    case "ERROR":
      return "border-red-500/30 bg-red-500/10 text-red-400";
    case "EMPTY":
      return "border-sky-500/30 bg-sky-500/10 text-sky-400";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

function assetStateBadgeClass(state: string | null | undefined, orphan = false) {
  if (orphan) {
    return "border-slate-500/30 bg-slate-500/10 text-slate-300";
  }
  switch (String(state || "").toUpperCase()) {
    case "VALID":
    case "PRESENT_UNCHECKED":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
    case "NOT_PRESENT":
    case "MISSING":
      return "border-red-500/30 bg-red-500/10 text-red-400";
    case "STALE":
      return "border-amber-500/30 bg-amber-500/10 text-amber-400";
    case "INVALID_CHECKSUM":
    case "INVALID_SIZE":
    case "ERROR":
    case "CORRUPTED":
      return "border-orange-500/30 bg-orange-500/10 text-orange-400";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

function actionResultBadgeClass(result: string | null | undefined) {
  switch (String(result || "").toUpperCase()) {
    case "SUCCEEDED":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
    case "STARTED":
      return "border-sky-500/30 bg-sky-500/10 text-sky-400";
    case "BLOCKED":
    case "SKIPPED":
      return "border-amber-500/30 bg-amber-500/10 text-amber-400";
    case "FAILED":
      return "border-red-500/30 bg-red-500/10 text-red-400";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

function readHistoryString(row: Record<string, unknown>, key: string) {
  return safeString(row[key]) || null;
}

function selectLatestReadinessRows(rows: TvSnapshotReadinessRow[]) {
  const byScreen = new Map<number, TvSnapshotReadinessRow>();
  for (const row of rows) {
    const existing = byScreen.get(row.screen_id);
    if (!existing || row.is_latest === 1 || row.id > existing.id) {
      byScreen.set(row.screen_id, row);
    }
  }
  return Array.from(byScreen.values());
}

function dedupeLatestSnapshots(rows: TvSnapshotCacheRow[]) {
  const byScreen = new Map<number, TvSnapshotCacheRow>();
  for (const row of rows) {
    const existing = byScreen.get(row.screen_id);
    if (!existing || row.is_latest === 1 || row.id > existing.id) {
      byScreen.set(row.screen_id, row);
    }
  }
  return Array.from(byScreen.values());
}

function buildLibraryRows(params: {
  bindings: TvObservabilityBindingSummary[];
  latestSnapshots: TvSnapshotCacheRow[];
  latestReadinessRows: TvSnapshotReadinessRow[];
  snapshotAssets: Record<string, TvSnapshotRequiredAssetRow[]>;
  localAssets: TvLocalAssetStateRow[];
}) {
  const { bindings, latestSnapshots, latestReadinessRows, snapshotAssets, localAssets } = params;
  const bindingByScreen = new Map<number, TvObservabilityBindingSummary>();
  for (const binding of bindings) {
    if (binding.screenId != null) {
      bindingByScreen.set(binding.screenId, binding);
    }
  }

  const readinessByScreen = new Map<number, TvSnapshotReadinessRow>();
  for (const readiness of latestReadinessRows) {
    readinessByScreen.set(readiness.screen_id, readiness);
  }

  const localByAsset = new Map<string, TvLocalAssetStateRow>();
  for (const localAsset of localAssets) {
    localByAsset.set(localAsset.media_asset_id, localAsset);
  }

  const library = new Map<string, TvDownloadLibraryItem>();

  for (const snapshot of latestSnapshots) {
    const assetRows = snapshotAssets[snapshot.snapshot_id] ?? [];
    const binding = bindingByScreen.get(snapshot.screen_id);
    const readiness = readinessByScreen.get(snapshot.screen_id);
    const owner: TvLibraryOwner = {
      bindingId: binding?.bindingId ?? 0,
      screenId: snapshot.screen_id,
      screenLabel: binding?.screenLabel ?? `Screen ${snapshot.screen_id}`,
      snapshotId: snapshot.snapshot_id,
      snapshotVersion: snapshot.snapshot_version,
      health: binding?.health ?? (readiness?.is_fully_ready === 1 ? "HEALTHY" : "STOPPED"),
    };

    for (const asset of assetRows) {
      const localState = localByAsset.get(asset.media_asset_id) ?? null;
      const current = library.get(asset.media_asset_id);
      const next: TvDownloadLibraryItem = current ?? {
        mediaAssetId: asset.media_asset_id,
        title: asset.title ?? null,
        mediaType: asset.media_type ?? null,
        mimeType: asset.mime_type ?? null,
        sizeBytes: asset.size_bytes ?? null,
        durationSeconds: asset.duration_in_seconds ?? null,
        downloadLink: asset.download_link ?? null,
        checksumSha256: asset.checksum_sha256 ?? null,
        timelineLabels: [],
        sourcePresetItemIds: [],
        localState,
        requiredBy: [],
        status: localState?.asset_state ?? "NOT_PRESENT",
        statusReason: localState?.state_reason ?? null,
        orphan: false,
      };

      if (!next.title && asset.title) {
        next.title = asset.title;
      }
      if (!next.mediaType && asset.media_type) {
        next.mediaType = asset.media_type;
      }
      if (!next.mimeType && asset.mime_type) {
        next.mimeType = asset.mime_type;
      }
      if (next.sizeBytes == null && asset.size_bytes != null) {
        next.sizeBytes = asset.size_bytes;
      }
      if (next.durationSeconds == null && asset.duration_in_seconds != null) {
        next.durationSeconds = asset.duration_in_seconds;
      }
      if (!next.downloadLink && asset.download_link) {
        next.downloadLink = asset.download_link;
      }
      if (!next.checksumSha256 && asset.checksum_sha256) {
        next.checksumSha256 = asset.checksum_sha256;
      }

      next.localState = next.localState ?? localState;
      next.status = next.localState?.asset_state ?? next.status;
      next.statusReason = next.localState?.state_reason ?? next.statusReason;
      next.orphan = false;

      if (!next.requiredBy.some((row) => row.screenId === owner.screenId && row.snapshotId === owner.snapshotId)) {
        next.requiredBy.push(owner);
      }
      next.timelineLabels = uniqueStrings([
        ...next.timelineLabels,
        ...parseJsonStringArray(asset.required_in_timelines_json, describeTimelineRequirement),
      ]);
      next.sourcePresetItemIds = uniqueStrings([
        ...next.sourcePresetItemIds,
        ...parseJsonStringArray(asset.source_preset_item_ids_json),
      ]);

      library.set(asset.media_asset_id, next);
    }
  }

  for (const localAsset of localAssets) {
    if (library.has(localAsset.media_asset_id)) {
      continue;
    }
    library.set(localAsset.media_asset_id, {
      mediaAssetId: localAsset.media_asset_id,
      title: null,
      mediaType: null,
      mimeType: null,
      sizeBytes: localAsset.local_size_bytes ?? null,
      durationSeconds: null,
      downloadLink: null,
      checksumSha256: localAsset.local_checksum_sha256 ?? null,
      timelineLabels: [],
      sourcePresetItemIds: [],
      localState: localAsset,
      requiredBy: [],
      status: localAsset.asset_state,
      statusReason: localAsset.state_reason ?? null,
      orphan: true,
    });
  }

  return Array.from(library.values()).sort((left, right) => {
    const leftAttention = isLibraryItemAttention(left) ? 1 : 0;
    const rightAttention = isLibraryItemAttention(right) ? 1 : 0;
    if (leftAttention !== rightAttention) {
      return rightAttention - leftAttention;
    }
    if (left.orphan !== right.orphan) {
      return Number(left.orphan) - Number(right.orphan);
    }
    const leftLabel = (left.title || left.mediaAssetId).toLowerCase();
    const rightLabel = (right.title || right.mediaAssetId).toLowerCase();
    return leftLabel.localeCompare(rightLabel);
  });
}

function StatCard({ icon: Icon, label, value, note, accentClassName }: StatCardProps) {
  return (
    <Card className="gap-4 py-5">
      <CardContent className="flex items-start justify-between px-5">
        <div className="space-y-1">
          <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
            {label}
          </div>
          <div className="text-2xl font-semibold tracking-tight">{value}</div>
          <div className="text-sm text-muted-foreground">{note}</div>
        </div>
        <div className={cn("rounded-xl border p-2.5", accentClassName)}>
          <Icon className="h-4 w-4" />
        </div>
      </CardContent>
    </Card>
  );
}

function ScheduleLaneTable({
  title,
  items,
  currentItemId,
}: {
  title: string;
  items: TvTimelineItemPresented[];
  currentItemId: string | null | undefined;
}) {
  return (
    <Card className="gap-4 py-5">
      <CardHeader className="px-5 pb-0">
        <CardTitle className="text-base">{title}</CardTitle>
        <CardDescription>
          Current schedule window, renderability, and backing local asset state.
        </CardDescription>
      </CardHeader>
      <CardContent className="px-5">
        {items.length === 0 ? (
          <div className="rounded-lg border border-dashed px-4 py-6 text-sm text-muted-foreground">
            No scheduled {title.toLowerCase()} items are cached for the active snapshot.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Window</TableHead>
                <TableHead>Asset</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Local file</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item) => (
                <TableRow
                  key={`${title}-${item.itemId}`}
                  className={cn(item.itemId === currentItemId && "bg-primary/5")}
                >
                  <TableCell className="whitespace-nowrap font-mono text-xs">
                    {formatMinuteOfDay(item.startMinuteOfDay)}-{formatMinuteOfDay(item.endMinuteOfDay)}
                  </TableCell>
                  <TableCell>
                    <div className="font-medium">{item.title || item.mediaAssetId}</div>
                    <div className="text-xs text-muted-foreground">
                      {item.mediaType} / {item.mediaAssetId}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-2">
                      <Badge className={cn("border", assetStateBadgeClass(item.assetState))}>
                        {item.assetState || "UNKNOWN"}
                      </Badge>
                      <Badge className={cn(
                        "border",
                        item.assetRenderable
                          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                          : "border-red-500/30 bg-red-500/10 text-red-400",
                      )}>
                        {item.assetRenderable ? "Renderable" : "Blocked"}
                      </Badge>
                    </div>
                    {item.stateReason && (
                      <div className="mt-1 text-xs text-muted-foreground">{item.stateReason}</div>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {extractPathName(item.assetPath)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

export default function TvDownloadsPage() {
  const [tab, setTab] = useState<DownloadsTab>("screens");
  const [bindings, setBindings] = useState<TvObservabilityBindingSummary[]>([]);
  const [latestSnapshots, setLatestSnapshots] = useState<TvSnapshotCacheRow[]>([]);
  const [latestReadinessRows, setLatestReadinessRows] = useState<TvSnapshotReadinessRow[]>([]);
  const [localAssets, setLocalAssets] = useState<TvLocalAssetStateRow[]>([]);
  const [libraryRows, setLibraryRows] = useState<TvDownloadLibraryItem[]>([]);
  const [selectedBindingId, setSelectedBindingId] = useState<number | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<TvObservabilityBindingDetail | null>(null);
  const [selectedRenderContext, setSelectedRenderContext] = useState<TvPlayerRenderContext | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [scope, setScope] = useState<LibraryScope>("selected");
  const [stateFilter, setStateFilter] = useState<LibraryStateFilter>("ALL");
  const deferredSearch = useDeferredValue(search);

  const fetchAllLocalAssets = useCallback(async () => {
    const limit = 500;
    let offset = 0;
    let total = Number.POSITIVE_INFINITY;
    const rows: TvLocalAssetStateRow[] = [];

    while (offset < total) {
      const response = await getTvAssets({ limit, offset });
      rows.push(...(response.rows ?? []));
      total = response.total ?? rows.length;
      if ((response.rows ?? []).length < limit) {
        break;
      }
      offset += limit;
    }

    return rows;
  }, []);

  const loadSummaryData = useCallback(async () => {
    setSummaryLoading(true);
    try {
      const [bindingsResponse, latestSnapshotsResponse, readinessResponse, localAssetRows] = await Promise.all([
        getTvObservabilityBindings({ limit: 500, offset: 0 }),
        getTvLatestSnapshots(),
        getTvReadiness({ limit: 500, offset: 0 }),
        fetchAllLocalAssets(),
      ]);

      const bindingRows = bindingsResponse.rows ?? [];
      const latestSnapshotRows = dedupeLatestSnapshots(latestSnapshotsResponse.snapshots ?? []);
      const readinessRows = selectLatestReadinessRows(readinessResponse.rows ?? []);

      const snapshotAssetsEntries = await Promise.all(
        latestSnapshotRows.map(async (snapshot) => {
          try {
            const response = await getTvSnapshotAssets(snapshot.snapshot_id);
            return [snapshot.snapshot_id, response.assets ?? []] as const;
          } catch {
            return [snapshot.snapshot_id, []] as const;
          }
        }),
      );

      const snapshotAssets = Object.fromEntries(snapshotAssetsEntries);
      const nextLibraryRows = buildLibraryRows({
        bindings: bindingRows,
        latestSnapshots: latestSnapshotRows,
        latestReadinessRows: readinessRows,
        snapshotAssets,
        localAssets: localAssetRows,
      });

      startTransition(() => {
        setBindings(bindingRows);
        setLatestSnapshots(latestSnapshotRows);
        setLatestReadinessRows(readinessRows);
        setLocalAssets(localAssetRows);
        setLibraryRows(nextLibraryRows);
        setSelectedBindingId((current) => {
          if (current != null && bindingRows.some((binding) => binding.bindingId === current)) {
            return current;
          }
          return bindingRows[0]?.bindingId ?? null;
        });
      });
      setError(null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to load TV downloads state.");
    } finally {
      setSummaryLoading(false);
    }
  }, [fetchAllLocalAssets]);

  const loadSelectedDetail = useCallback(async (bindingId: number) => {
    setDetailLoading(true);
    try {
      const [detail, renderContext] = await Promise.all([
        getTvObservabilityBinding(bindingId, { eventLimit: 50, historyLimit: 40 }),
        getTvPlayerRenderContext(bindingId).catch(() => null),
      ]);
      setSelectedDetail(detail.ok ? detail : null);
      setSelectedRenderContext(renderContext);
      setError(null);
    } catch (detailError) {
      setError(detailError instanceof Error ? detailError.message : "Failed to load selected screen details.");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    setBusyAction("refresh");
    await loadSummaryData();
    if (selectedBindingId != null) {
      await loadSelectedDetail(selectedBindingId);
    }
    setBusyAction(null);
  }, [loadSelectedDetail, loadSummaryData, selectedBindingId]);

  const scheduleFollowUpRefresh = useCallback((bindingId: number | null) => {
    window.setTimeout(() => {
      void loadSummaryData();
      if (bindingId != null) {
        void loadSelectedDetail(bindingId);
      }
    }, 1500);
  }, [loadSelectedDetail, loadSummaryData]);

  const runSupportAction = useCallback(async (
    actionType: TvBindingSupportActionType,
    options?: Record<string, unknown>,
    actionKey?: string,
  ) => {
    if (selectedBindingId == null) {
      return;
    }

    setBusyAction(actionKey ?? actionType);
    setFeedback(null);
    try {
      const response = await runTvBindingSupportAction(selectedBindingId, {
        actionType,
        options,
        triggeredBy: "TV_DOWNLOADS_PAGE",
      });
      const result = response.result ?? "FAILED";
      const message = response.message || `${actionType} finished with ${result}.`;
      setFeedback(`${actionType}: ${result} - ${message}`);
      setError(null);
      await loadSelectedDetail(selectedBindingId);
      await loadSummaryData();
      scheduleFollowUpRefresh(selectedBindingId);
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : `Failed to run ${actionType}.`);
    } finally {
      setBusyAction(null);
    }
  }, [loadSelectedDetail, loadSummaryData, scheduleFollowUpRefresh, selectedBindingId]);

  const handleBatchDownload = useCallback(async () => {
    const selectedBinding = bindings.find((binding) => binding.bindingId === selectedBindingId) ?? null;
    if (!selectedBinding?.screenId) {
      return;
    }

    setBusyAction("batch-download");
    setFeedback(null);
    try {
      const response = await downloadTvAssets({ screenId: selectedBinding.screenId });
      setFeedback(response.message || `Download started for ${selectedBinding.screenLabel}.`);
      setError(null);
      scheduleFollowUpRefresh(selectedBinding.bindingId);
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : "Failed to start asset download.");
    } finally {
      setBusyAction(null);
    }
  }, [bindings, scheduleFollowUpRefresh, selectedBindingId]);

  useEffect(() => {
    void loadSummaryData();
    const interval = window.setInterval(() => {
      void loadSummaryData();
    }, 15000);
    return () => window.clearInterval(interval);
  }, [loadSummaryData]);

  useEffect(() => {
    if (selectedBindingId == null) {
      setSelectedDetail(null);
      setSelectedRenderContext(null);
      return;
    }
    void loadSelectedDetail(selectedBindingId);
    const interval = window.setInterval(() => {
      void loadSelectedDetail(selectedBindingId);
    }, 15000);
    return () => window.clearInterval(interval);
  }, [loadSelectedDetail, selectedBindingId]);

  const selectedBinding = useMemo(
    () => bindings.find((binding) => binding.bindingId === selectedBindingId) ?? null,
    [bindings, selectedBindingId],
  );

  const readinessByScreen = useMemo(() => {
    const next = new Map<number, TvSnapshotReadinessRow>();
    for (const row of latestReadinessRows) {
      next.set(row.screen_id, row);
    }
    return next;
  }, [latestReadinessRows]);

  const snapshotByScreen = useMemo(() => {
    const next = new Map<number, TvSnapshotCacheRow>();
    for (const row of latestSnapshots) {
      next.set(row.screen_id, row);
    }
    return next;
  }, [latestSnapshots]);

  const selectedReadiness = useMemo(() => {
    if (!selectedBinding?.screenId) {
      return null;
    }
    return readinessByScreen.get(selectedBinding.screenId) ?? null;
  }, [readinessByScreen, selectedBinding?.screenId]);

  const selectedSnapshot = useMemo(() => {
    if (!selectedBinding?.screenId) {
      return null;
    }
    return snapshotByScreen.get(selectedBinding.screenId) ?? null;
  }, [selectedBinding?.screenId, snapshotByScreen]);

  const selectedScreenLibraryRows = useMemo(() => {
    if (!selectedBinding?.screenId) {
      return [];
    }
    return libraryRows.filter((item) => item.requiredBy.some((owner) => owner.screenId === selectedBinding.screenId));
  }, [libraryRows, selectedBinding?.screenId]);

  const readyScreenCount = useMemo(
    () => bindings.filter((binding) => {
      if (!binding.screenId) {
        return false;
      }
      return readinessByScreen.get(binding.screenId)?.is_fully_ready === 1;
    }).length,
    [bindings, readinessByScreen],
  );

  const attentionScreenCount = useMemo(
    () => bindings.filter((binding) => {
      const readiness = binding.screenId ? readinessByScreen.get(binding.screenId) : null;
      return Boolean(binding.problem || binding.failedAssetCount > 0 || readiness?.is_fully_ready !== 1);
    }).length,
    [bindings, readinessByScreen],
  );

  const validLocalAssetCount = useMemo(
    () => localAssets.filter((asset) => isAssetReady(asset.asset_state)).length,
    [localAssets],
  );

  const selectedScreenReadyCount = useMemo(
    () => selectedScreenLibraryRows.filter((item) => isAssetReady(item.status)).length,
    [selectedScreenLibraryRows],
  );

  const selectedScreenAttentionRows = useMemo(
    () => selectedScreenLibraryRows.filter((item) => isLibraryItemAttention(item)),
    [selectedScreenLibraryRows],
  );

  const selectedScreenDownloadedRows = useMemo(
    () => selectedScreenLibraryRows.filter((item) => isAssetReady(item.status)),
    [selectedScreenLibraryRows],
  );

  const selectedReadinessSummary = useMemo(() => {
    if (!selectedBinding) {
      return {
        title: "No screen selected",
        toneClassName: "border-border bg-muted/30 text-foreground",
        note: "Choose a screen to inspect its downloads and schedule.",
      };
    }
    if (!selectedReadiness) {
      return {
        title: "Readiness not computed yet",
        toneClassName: "border-sky-500/30 bg-sky-500/10 text-foreground",
        note: "Run a sync or readiness computation to know if this screen can play offline.",
      };
    }
    if (selectedReadiness.is_fully_ready === 1) {
      return {
        title: "Ready to play",
        toneClassName: "border-emerald-500/30 bg-emerald-500/10 text-foreground",
        note: `${selectedReadiness.ready_asset_count} media already available locally for this screen.`,
      };
    }

    const missingCount = (selectedReadiness.missing_asset_count ?? 0)
      + (selectedReadiness.invalid_asset_count ?? 0)
      + (selectedReadiness.stale_asset_count ?? 0);

    return {
      title: "Needs downloads before it is safe",
      toneClassName: "border-amber-500/30 bg-amber-500/10 text-foreground",
      note: `${missingCount} media item(s) still need to be downloaded or repaired.`,
    };
  }, [selectedBinding, selectedReadiness]);

  const filteredLibraryRows = useMemo(() => {
    const query = deferredSearch.trim().toLowerCase();
    return libraryRows.filter((item) => {
      if (scope === "selected" && selectedBinding?.screenId) {
        const belongsToSelectedScreen = item.requiredBy.some((owner) => owner.screenId === selectedBinding.screenId);
        if (!belongsToSelectedScreen) {
          return false;
        }
      }

      if (stateFilter === "READY" && !isAssetReady(item.status)) {
        return false;
      }
      if (stateFilter === "ATTENTION" && !isLibraryItemAttention(item)) {
        return false;
      }
      if (stateFilter === "ORPHAN" && !item.orphan) {
        return false;
      }

      if (!query) {
        return true;
      }

      const searchHaystack = [
        item.mediaAssetId,
        item.title || "",
        item.mediaType || "",
        item.status || "",
        item.localState?.local_file_path || "",
        item.requiredBy.map((owner) => owner.screenLabel).join(" "),
      ].join(" ").toLowerCase();

      return searchHaystack.includes(query);
    });
  }, [deferredSearch, libraryRows, scope, selectedBinding?.screenId, stateFilter]);

  const selectedSupportHistory = useMemo(
    () => (selectedDetail?.supportHistory.rows ?? []).filter((row) => CONTENT_ACTIONS.includes(row.action_type)),
    [selectedDetail?.supportHistory.rows],
  );

  const selectedSyncRuns = useMemo(
    () => (selectedDetail?.syncRuns.rows ?? []) as Record<string, unknown>[],
    [selectedDetail?.syncRuns.rows],
  );

  return (
    <div className="flex flex-col gap-6">
      <Card className="gap-5 py-5">
        <CardContent className="flex flex-col gap-4 px-5 xl:flex-row xl:items-end xl:justify-between">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className="border border-sky-500/30 bg-sky-500/10 text-sky-400">
                Download management
              </Badge>
              {selectedBinding && (
                <Badge className={cn("border", healthBadgeClass(selectedBinding.health))}>
                  {selectedBinding.health}
                </Badge>
              )}
              {selectedReadiness && (
                <Badge className={cn("border", readinessBadgeClass(selectedReadiness.readiness_state))}>
                  {selectedReadiness.readiness_state}
                </Badge>
              )}
            </div>
            <div>
              <div className="text-xl font-semibold tracking-tight">
                {selectedBinding?.screenLabel || "No screen binding selected"}
              </div>
              <div className="mt-1 text-sm text-muted-foreground">
                Track local TV media, latest snapshot readiness, per-screen schedules, and repair history from one place.
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:justify-end">
            <div className="min-w-[240px]">
              <Select
                value={selectedBindingId != null ? String(selectedBindingId) : undefined}
                onValueChange={(value) => setSelectedBindingId(Number(value))}
                disabled={bindings.length === 0}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Choose a screen" />
                </SelectTrigger>
                <SelectContent>
                  {bindings.map((binding) => (
                    <SelectItem key={binding.bindingId} value={String(binding.bindingId)}>
                      {binding.screenLabel} - {binding.health}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Button
              variant="outline"
              onClick={() => void refreshAll()}
              disabled={summaryLoading || detailLoading || busyAction === "refresh"}
            >
              {busyAction === "refresh" ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
              Refresh
            </Button>

            <Button
              variant="outline"
              onClick={() => void runSupportAction("RUN_SYNC")}
              disabled={!selectedBinding || busyAction != null}
            >
              {busyAction === "RUN_SYNC" ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Sparkles className="h-4 w-4" />
              )}
              Run Sync
            </Button>

            <Button
              variant="outline"
              onClick={() => void handleBatchDownload()}
              disabled={!selectedBinding?.screenId || busyAction != null}
            >
              {busyAction === "batch-download" ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              Download Latest
            </Button>

            <Button
              onClick={() => void runSupportAction("RETRY_FAILED_DOWNLOADS")}
              disabled={!selectedBinding || busyAction != null}
            >
              {busyAction === "RETRY_FAILED_DOWNLOADS" ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Wrench className="h-4 w-4" />
              )}
              Repair Issues
            </Button>
          </div>
        </CardContent>
      </Card>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {feedback && (
        <Alert variant="success">
          <CheckCircle2 className="h-4 w-4" />
          <AlertDescription>{feedback}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Database}
          label="Library Assets"
          value={libraryRows.length.toLocaleString()}
          note="Latest-screen asset library plus orphaned local files."
          accentClassName="border-sky-500/30 bg-sky-500/10 text-sky-400"
        />
        <StatCard
          icon={CheckCircle2}
          label="Valid Local Files"
          value={validLocalAssetCount.toLocaleString()}
          note={`${localAssets.length.toLocaleString()} rows in local asset cache.`}
          accentClassName="border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
        />
        <StatCard
          icon={Sparkles}
          label="Ready Screens"
          value={readyScreenCount.toLocaleString()}
          note={`${bindings.length.toLocaleString()} total TV bindings tracked.`}
          accentClassName="border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
        />
        <StatCard
          icon={AlertTriangle}
          label="Needs Attention"
          value={attentionScreenCount.toLocaleString()}
          note="Bindings with missing assets, readiness gaps, or active problems."
          accentClassName="border-amber-500/30 bg-amber-500/10 text-amber-400"
        />
      </div>

      <Tabs value={tab} onValueChange={(value) => setTab(value as DownloadsTab)}>
        <TabsList className="grid w-full grid-cols-3 md:w-auto">
          <TabsTrigger value="screens">Screens</TabsTrigger>
          <TabsTrigger value="library">Storage</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="library" className="space-y-4">
          <Card className="gap-4 py-5">
            <CardHeader className="px-5 pb-0">
              <CardTitle className="text-base">Stored Media</CardTitle>
              <CardDescription>
                Browse everything cached locally for the latest screen snapshots and trigger targeted repairs directly from the list.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 px-5">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                  <Input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search asset, screen, status, or local file..."
                    className="min-w-[260px]"
                  />

                  <Select value={scope} onValueChange={(value) => setScope(value as LibraryScope)}>
                    <SelectTrigger className="w-[190px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="selected">Selected screen only</SelectItem>
                      <SelectItem value="all">All screens</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={stateFilter} onValueChange={(value) => setStateFilter(value as LibraryStateFilter)}>
                    <SelectTrigger className="w-[180px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ALL">All states</SelectItem>
                      <SelectItem value="READY">Ready locally</SelectItem>
                      <SelectItem value="ATTENTION">Needs attention</SelectItem>
                      <SelectItem value="ORPHAN">Orphaned local</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="text-sm text-muted-foreground">
                  Showing {filteredLibraryRows.length.toLocaleString()} of {libraryRows.length.toLocaleString()} assets
                </div>
              </div>

              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Used By</TableHead>
                    <TableHead>Local Status</TableHead>
                    <TableHead>File</TableHead>
                    <TableHead>Last Checked</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredLibraryRows.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                        {summaryLoading ? "Loading local media library..." : "No assets match the current filters."}
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredLibraryRows.map((item) => {
                      const belongsToSelectedScreen = selectedBinding?.screenId != null
                        && item.requiredBy.some((owner) => owner.screenId === selectedBinding.screenId);
                      const canRepair = Boolean(belongsToSelectedScreen && !isAssetReady(item.status));
                      const actionKey = `asset:${item.mediaAssetId}`;
                      const localPath = item.localState?.local_file_path || item.localState?.expected_local_path || null;
                      return (
                        <TableRow key={item.mediaAssetId}>
                          <TableCell className="min-w-[250px]">
                            <div className="font-medium">{item.title || item.mediaAssetId}</div>
                            <div className="text-xs text-muted-foreground">
                              {item.mediaType || "unknown"} / {item.mediaAssetId}
                            </div>
                            <div className="mt-1 text-xs text-muted-foreground">
                              {formatBytes(item.sizeBytes)} / {formatDurationSeconds(item.durationSeconds)}
                            </div>
                            {item.timelineLabels.length > 0 && (
                              <div className="mt-1 text-xs text-muted-foreground">
                                {item.timelineLabels.slice(0, 2).join(" | ")}
                                {item.timelineLabels.length > 2 ? ` +${item.timelineLabels.length - 2} more` : ""}
                              </div>
                            )}
                          </TableCell>
                          <TableCell className="min-w-[220px]">
                            {item.requiredBy.length === 0 ? (
                              <div className="text-sm text-muted-foreground">Not required by latest snapshots</div>
                            ) : (
                              <div className="flex flex-wrap gap-2">
                                {item.requiredBy.map((owner) => (
                                  <Badge
                                    key={`${item.mediaAssetId}-${owner.screenId}-${owner.snapshotId}`}
                                    className={cn("border", healthBadgeClass(owner.health))}
                                  >
                                    {owner.screenLabel} v{owner.snapshotVersion}
                                  </Badge>
                                ))}
                              </div>
                            )}
                          </TableCell>
                          <TableCell className="min-w-[200px]">
                            <div className="flex flex-wrap gap-2">
                              <Badge className={cn("border", assetStateBadgeClass(item.status, item.orphan))}>
                                {item.orphan ? "ORPHAN" : item.status}
                              </Badge>
                              {item.orphan && <Badge variant="outline">Local only</Badge>}
                            </div>
                            {item.statusReason && (
                              <div className="mt-1 text-xs text-muted-foreground">{item.statusReason}</div>
                            )}
                          </TableCell>
                          <TableCell className="min-w-[160px] text-xs text-muted-foreground">
                            <div>{extractPathName(localPath)}</div>
                            {localPath && <div className="mt-1 truncate">{localPath}</div>}
                          </TableCell>
                          <TableCell className="whitespace-nowrap text-sm text-muted-foreground">
                            {formatTimestamp(item.localState?.last_checked_at)}
                          </TableCell>
                          <TableCell className="text-right">
                            {canRepair ? (
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={busyAction != null}
                                onClick={() => void runSupportAction(
                                  "RETRY_ONE_DOWNLOAD",
                                  { mediaAssetId: item.mediaAssetId },
                                  actionKey,
                                )}
                              >
                                {busyAction === actionKey ? (
                                  <Loader2 className="h-4 w-4 animate-spin" />
                                ) : (
                                  <Wrench className="h-4 w-4" />
                                )}
                                Repair
                              </Button>
                            ) : (
                              <span className="text-xs text-muted-foreground">
                                {item.orphan ? "No latest snapshot owner" : isAssetReady(item.status) ? "Ready" : "Select owning screen"}
                              </span>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="screens" className="space-y-4">
          <div className="grid gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
            <Card className="gap-4 py-5">
              <CardHeader className="px-5 pb-0">
                <CardTitle className="text-base">Screen Readiness</CardTitle>
                <CardDescription>
                  Every screen binding with its latest snapshot, readiness state, and problem signal.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 px-5">
                {bindings.length === 0 ? (
                  <div className="rounded-lg border border-dashed px-4 py-6 text-sm text-muted-foreground">
                    No TV bindings are configured yet.
                  </div>
                ) : (
                  bindings.map((binding) => {
                    const readiness = binding.screenId ? readinessByScreen.get(binding.screenId) ?? null : null;
                    const snapshot = binding.screenId ? snapshotByScreen.get(binding.screenId) ?? null : null;
                    const selected = binding.bindingId === selectedBindingId;
                    return (
                      <button
                        key={binding.bindingId}
                        type="button"
                        onClick={() => setSelectedBindingId(binding.bindingId)}
                        className={cn(
                          "w-full rounded-xl border px-4 py-4 text-left transition-colors hover:bg-muted/40",
                          selected && "border-primary/40 bg-primary/5",
                        )}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="font-medium">{binding.screenLabel}</div>
                            <div className="text-xs text-muted-foreground">
                              Binding #{binding.bindingId}
                              {binding.gymId ? ` / gym ${binding.gymId}` : ""}
                            </div>
                          </div>
                          <Badge className={cn("border", healthBadgeClass(binding.health))}>
                            {binding.health}
                          </Badge>
                        </div>

                        <div className="mt-3 flex flex-wrap gap-2">
                          <Badge className={cn("border", readinessBadgeClass(readiness?.readiness_state))}>
                            {readiness?.readiness_state || "UNKNOWN"}
                          </Badge>
                          <Badge variant="outline">{binding.runtimeState || "n/a"}</Badge>
                          <Badge variant="outline">{binding.playerState || "n/a"}</Badge>
                        </div>

                        <div className="mt-3 grid gap-2 text-sm text-muted-foreground sm:grid-cols-2">
                          <div>
                            Snapshot {snapshot ? `v${snapshot.snapshot_version}` : "n/a"}
                          </div>
                          <div>
                            Ready {readiness?.ready_asset_count ?? 0}/{readiness?.total_required_assets ?? 0}
                          </div>
                          <div>
                            Missing {readiness?.missing_asset_count ?? 0} / invalid {readiness?.invalid_asset_count ?? 0}
                          </div>
                          <div>
                            Failed assets {binding.failedAssetCount}
                          </div>
                        </div>

                        {binding.reasons.length > 0 && (
                          <div className="mt-3 text-xs text-muted-foreground">
                            {binding.reasons.slice(0, 2).join(" ")}
                          </div>
                        )}
                      </button>
                    );
                  })
                )}
              </CardContent>
            </Card>

            <div className="space-y-4">
              {detailLoading && !selectedDetail ? (
                <Card className="gap-4 py-5">
                  <CardContent className="px-5 py-12 text-sm text-muted-foreground">
                    Loading selected screen details...
                  </CardContent>
                </Card>
              ) : !selectedBinding ? (
                <Card className="gap-4 py-5">
                  <CardContent className="px-5 py-12 text-sm text-muted-foreground">
                    Select a screen on the left to manage its downloads.
                  </CardContent>
                </Card>
              ) : (
                <>
                  <Card className="gap-4 py-5">
                    <CardContent className="space-y-5 px-5">
                      <div className={cn("rounded-2xl border p-5", selectedReadinessSummary.toneClassName)}>
                        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                          <div className="space-y-2">
                            <div className="text-xs font-medium uppercase tracking-[0.16em] opacity-80">
                              {selectedBinding.screenLabel}
                            </div>
                            <div className="text-2xl font-semibold tracking-tight">
                              {selectedReadinessSummary.title}
                            </div>
                            <div className="max-w-2xl text-sm opacity-85">
                              {selectedReadinessSummary.note}
                            </div>
                          </div>

                          <div className="grid gap-3 sm:grid-cols-3">
                            <div className="rounded-xl border border-white/10 bg-background/40 p-3">
                              <div className="text-xs uppercase tracking-[0.12em] text-muted-foreground">Snapshot</div>
                              <div className="mt-1 text-lg font-semibold">
                                {selectedSnapshot ? `v${selectedSnapshot.snapshot_version}` : "n/a"}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {formatTimestamp(selectedSnapshot?.fetched_at)}
                              </div>
                            </div>
                            <div className="rounded-xl border border-white/10 bg-background/40 p-3">
                              <div className="text-xs uppercase tracking-[0.12em] text-muted-foreground">Downloaded</div>
                              <div className="mt-1 text-lg font-semibold">
                                {selectedScreenDownloadedRows.length}/{selectedScreenLibraryRows.length}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Ready locally
                              </div>
                            </div>
                            <div className="rounded-xl border border-white/10 bg-background/40 p-3">
                              <div className="text-xs uppercase tracking-[0.12em] text-muted-foreground">Missing</div>
                              <div className="mt-1 text-lg font-semibold">
                                {selectedScreenAttentionRows.length}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Need download or repair
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                        <div className="rounded-xl border p-4">
                          <div className="text-xs uppercase tracking-[0.12em] text-muted-foreground">Current visual</div>
                          <div className="mt-2 font-medium">
                            {selectedRenderContext?.currentVisual?.title || "Nothing active"}
                          </div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {selectedRenderContext?.currentVisual?.mediaAssetId || "No visual media right now"}
                          </div>
                        </div>

                        <div className="rounded-xl border p-4">
                          <div className="text-xs uppercase tracking-[0.12em] text-muted-foreground">Current audio</div>
                          <div className="mt-2 font-medium">
                            {selectedRenderContext?.currentAudio?.title || "Nothing active"}
                          </div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {selectedRenderContext?.currentAudio?.mediaAssetId || "No audio media right now"}
                          </div>
                        </div>

                        <div className="rounded-xl border p-4">
                          <div className="text-xs uppercase tracking-[0.12em] text-muted-foreground">Player</div>
                          <div className="mt-2 flex flex-wrap gap-2">
                            <Badge className={cn("border", healthBadgeClass(selectedBinding.health))}>
                              {selectedBinding.health}
                            </Badge>
                            <Badge variant="outline">
                              {selectedRenderContext?.playerState || selectedBinding.playerState || "n/a"}
                            </Badge>
                          </div>
                          <div className="mt-2 text-xs text-muted-foreground">
                            {selectedRenderContext?.renderMode || "No render mode reported"}
                          </div>
                        </div>

                        <div className="rounded-xl border p-4">
                          <div className="text-xs uppercase tracking-[0.12em] text-muted-foreground">Monitor</div>
                          <div className="mt-2 font-medium">
                            {selectedDetail?.monitor.available ? "Connected" : "Missing or disconnected"}
                          </div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            Last checked {formatTimestamp(selectedRenderContext?.evaluatedAt)}
                          </div>
                          {selectedRenderContext?.fallbackReason && (
                            <div className="mt-1 text-xs text-muted-foreground">
                              Fallback: {selectedRenderContext.fallbackReason}
                            </div>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <div className="grid gap-4 xl:grid-cols-2">
                    <ScheduleLaneTable
                      title="Visual Schedule"
                      items={selectedRenderContext?.visualItems ?? []}
                      currentItemId={selectedRenderContext?.currentVisual?.itemId}
                    />
                    <ScheduleLaneTable
                      title="Audio Schedule"
                      items={selectedRenderContext?.audioItems ?? []}
                      currentItemId={selectedRenderContext?.currentAudio?.itemId}
                    />
                  </div>

                  <div className="grid gap-4 xl:grid-cols-2">
                    <Card className="gap-4 py-5">
                      <CardHeader className="px-5 pb-0">
                        <CardTitle className="text-base">Already Downloaded</CardTitle>
                        <CardDescription>
                          Media that is already on this PC and ready for this screen.
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-3 px-5">
                        {selectedScreenDownloadedRows.length === 0 ? (
                          <div className="rounded-lg border border-dashed px-4 py-6 text-sm text-muted-foreground">
                            Nothing from the current screen schedule is ready locally yet.
                          </div>
                        ) : (
                          selectedScreenDownloadedRows.map((item) => {
                            const localPath = item.localState?.local_file_path || item.localState?.expected_local_path || null;
                            return (
                              <div key={`ready-${item.mediaAssetId}`} className="rounded-xl border p-4">
                                <div className="flex items-start justify-between gap-3">
                                  <div className="min-w-0">
                                    <div className="font-medium">{item.title || item.mediaAssetId}</div>
                                    <div className="mt-1 text-xs text-muted-foreground">
                                      {item.mediaType || "unknown"} / {formatBytes(item.sizeBytes)}
                                    </div>
                                  </div>
                                  <Badge className="border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
                                    Ready
                                  </Badge>
                                </div>
                                <div className="mt-3 text-xs text-muted-foreground">
                                  {localPath || "Local file path unavailable"}
                                </div>
                              </div>
                            );
                          })
                        )}
                      </CardContent>
                    </Card>

                    <Card className="gap-4 py-5">
                      <CardHeader className="px-5 pb-0">
                        <CardTitle className="text-base">Missing Or Broken Media</CardTitle>
                        <CardDescription>
                          These items still need to be downloaded or repaired before the screen is fully safe offline.
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-3 px-5">
                        {selectedScreenAttentionRows.length === 0 ? (
                          <div className="rounded-lg border border-dashed px-4 py-6 text-sm text-muted-foreground">
                            Everything required by the latest snapshot is already ready.
                          </div>
                        ) : (
                          selectedScreenAttentionRows.map((item) => {
                            const actionKey = `screen-asset:${item.mediaAssetId}`;
                            return (
                              <div key={`missing-${item.mediaAssetId}`} className="rounded-xl border p-4">
                                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                                  <div className="min-w-0">
                                    <div className="font-medium">{item.title || item.mediaAssetId}</div>
                                    <div className="mt-1 text-xs text-muted-foreground">
                                      {item.mediaType || "unknown"} / {item.mediaAssetId}
                                    </div>
                                    <div className="mt-2 flex flex-wrap gap-2">
                                      <Badge className={cn("border", assetStateBadgeClass(item.status))}>
                                        {item.status}
                                      </Badge>
                                      {item.statusReason && (
                                        <Badge variant="outline">{item.statusReason}</Badge>
                                      )}
                                    </div>
                                  </div>

                                  <Button
                                    size="sm"
                                    variant="outline"
                                    disabled={busyAction != null}
                                    onClick={() => void runSupportAction(
                                      "RETRY_ONE_DOWNLOAD",
                                      { mediaAssetId: item.mediaAssetId },
                                      actionKey,
                                    )}
                                  >
                                    {busyAction === actionKey ? (
                                      <Loader2 className="h-4 w-4 animate-spin" />
                                    ) : (
                                      <Wrench className="h-4 w-4" />
                                    )}
                                    Download / Repair
                                  </Button>
                                </div>
                              </div>
                            );
                          })
                        )}
                      </CardContent>
                    </Card>
                  </div>
                </>
              )}
            </div>
          </div>
        </TabsContent>
        <TabsContent value="history" className="space-y-4">
          <Alert variant="info">
            <Clock3 className="h-4 w-4" />
            <AlertDescription>
              History combines screen sync runs and support action logs. Background batch downloads started outside support actions are not persisted yet, so this is the best currently available operator view.
            </AlertDescription>
          </Alert>

          <div className="grid gap-4 xl:grid-cols-2">
            <Card className="gap-4 py-5">
              <CardHeader className="px-5 pb-0">
                <CardTitle className="text-base">Download And Repair Actions</CardTitle>
                <CardDescription>
                  Logged support actions for the selected binding, including sync, readiness recompute, and asset repair runs.
                </CardDescription>
              </CardHeader>
              <CardContent className="px-5">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Action</TableHead>
                      <TableHead>Result</TableHead>
                      <TableHead>When</TableHead>
                      <TableHead>Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selectedSupportHistory.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="py-8 text-center text-sm text-muted-foreground">
                          {selectedBinding ? "No content-related support actions logged yet." : "Select a binding to inspect its history."}
                        </TableCell>
                      </TableRow>
                    ) : (
                      selectedSupportHistory.map((row: TvSupportActionLogRow) => (
                        <TableRow key={row.id}>
                          <TableCell>
                            <div className="font-medium">{row.action_type}</div>
                            <div className="text-xs text-muted-foreground">
                              {row.correlation_id}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge className={cn("border", actionResultBadgeClass(row.result))}>
                              {row.result}
                            </Badge>
                          </TableCell>
                          <TableCell className="whitespace-nowrap text-sm text-muted-foreground">
                            <div>{formatTimestamp(row.started_at || row.created_at)}</div>
                            <div className="text-xs text-muted-foreground">
                              Finished {formatTimestamp(row.finished_at)}
                            </div>
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {row.message || row.error_message || "No message"}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card className="gap-4 py-5">
              <CardHeader className="px-5 pb-0">
                <CardTitle className="text-base">Snapshot Sync History</CardTitle>
                <CardDescription>
                  Recent sync runs for the selected screen, including snapshot version and final result.
                </CardDescription>
              </CardHeader>
              <CardContent className="px-5">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Snapshot</TableHead>
                      <TableHead>Result</TableHead>
                      <TableHead>Started</TableHead>
                      <TableHead>Notes</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selectedSyncRuns.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="py-8 text-center text-sm text-muted-foreground">
                          {selectedBinding ? "No sync runs recorded yet for this screen." : "Select a binding to inspect sync history."}
                        </TableCell>
                      </TableRow>
                    ) : (
                      selectedSyncRuns.map((row) => {
                        const result = readHistoryString(row, "result") || "UNKNOWN";
                        const targetSnapshotVersion = readHistoryString(row, "target_snapshot_version") || "n/a";
                        const warningCount = readHistoryString(row, "warning_count");
                        const errorMessage = readHistoryString(row, "error_message");
                        return (
                          <TableRow key={`${targetSnapshotVersion}-${readHistoryString(row, "started_at")}-${readHistoryString(row, "id")}`}>
                            <TableCell>
                              <div className="font-medium">v{targetSnapshotVersion}</div>
                              <div className="text-xs text-muted-foreground">
                                {readHistoryString(row, "correlation_id") || "No correlation id"}
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge className={cn("border", actionResultBadgeClass(result === "SUCCESS" ? "SUCCEEDED" : result))}>
                                {result}
                              </Badge>
                            </TableCell>
                            <TableCell className="whitespace-nowrap text-sm text-muted-foreground">
                              {formatTimestamp(readHistoryString(row, "started_at"))}
                            </TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {errorMessage || (warningCount ? `${warningCount} warning(s)` : "No warnings")}
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
