// TV Player API — A6: binding-scoped player runtime
import { ApiError, get, openSSE, patch, post } from "../../api/client";
import type {
  DbTableQueryResponse,
  DbTablesResponse,
  LogLine,
  TvPlayerRenderContext,
  TvPlayerStatusResponse,
  TvPlayerEventsResponse,
} from "./types";

// GET /api/v2/tv/player/{bindingId}/status
export function getTvPlayerStatus(bindingId: number): Promise<TvPlayerStatusResponse> {
  return get<TvPlayerStatusResponse>(`/tv/player/${bindingId}/status`);
}

// GET /api/v2/tv/player/{bindingId}/render-context
export function getTvPlayerRenderContext(
  bindingId: number,
  persist = false,
): Promise<TvPlayerRenderContext> {
  return get<TvPlayerRenderContext>(`/tv/player/${bindingId}/render-context`, {
    persist: persist ? "1" : "0",
  });
}

// POST /api/v2/tv/player/{bindingId}/reevaluate
export function reevaluateTvPlayer(
  bindingId: number,
  persist = true,
): Promise<{ ok: boolean; context: TvPlayerRenderContext }> {
  return post(`/tv/player/${bindingId}/reevaluate`, { persist });
}

// POST /api/v2/tv/player/{bindingId}/reload
export function reloadTvPlayer(
  bindingId: number,
  persist = true,
): Promise<{ ok: boolean; context: TvPlayerRenderContext }> {
  return post(`/tv/player/${bindingId}/reload`, { persist });
}

// POST /api/v2/tv/player/{bindingId}/state
export function reportTvPlayerState(
  bindingId: number,
  state: Record<string, unknown>,
  options?: { eventType?: string; force?: boolean; freshnessSeconds?: number },
): Promise<{ ok: boolean; updated: boolean; changed: boolean }> {
  return post(`/tv/player/${bindingId}/state`, {
    state,
    eventType: options?.eventType ?? "PLAYER_STATE_CHANGED",
    force: options?.force ?? false,
    freshnessSeconds: options?.freshnessSeconds ?? 20,
  });
}

// GET /api/v2/tv/player/{bindingId}/events
export function getTvPlayerEvents(
  bindingId: number,
  limit = 100,
  offset = 0,
): Promise<TvPlayerEventsResponse> {
  return get<TvPlayerEventsResponse>(`/tv/player/${bindingId}/events`, {
    limit: String(limit),
    offset: String(offset),
  });
}

// ─── Screen Messages ─────────────────────────────────────────────────────────

// GET /api/v2/tv/screen-messages
export function getTvScreenMessages(
  bindingId: number,
  limit = 5,
): Promise<import("./types").TvScreenMessagesResponse> {
  return get(`/tv/screen-messages`, {
    bindingId: String(bindingId),
    limit: String(limit),
  });
}

// ─── Ad Runtime (A7) ─────────────────────────────────────────────────────────

// GET /api/v2/tv/ad-runtime/tasks
export function getTvAdTasks(params?: {
  gymId?: number;
  limit?: number;
  offset?: number;
}): Promise<{ ok: boolean; rows: import("./types").TvAdTaskCache[]; total: number }> {
  const q: Record<string, string> = {};
  if (params?.gymId) q.gymId = String(params.gymId);
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get(`/tv/ad-runtime/tasks`, q);
}

// GET /api/v2/tv/ad-runtime/tasks/{taskId}
export function getTvAdTaskRuntime(
  taskId: string,
): Promise<{ ok: boolean; runtime: import("./types").TvAdTaskRuntime | null }> {
  return get(`/tv/ad-runtime/tasks/${taskId}`);
}

// GET /api/v2/tv/ad-runtime/gyms/{gymId}
export function getTvGymAdRuntime(
  gymId: number,
): Promise<{ ok: boolean; runtime: import("./types").TvGymAdRuntime | null }> {
  return get(`/tv/ad-runtime/gyms/${gymId}`);
}

// POST /api/v2/tv/ad-runtime/evaluate
export function evaluateTvAdRuntime(): Promise<import("./types").TvAdEvaluateResponse> {
  return post(`/tv/ad-runtime/evaluate`, {});
}

// POST /api/v2/tv/ad-runtime/tasks/{taskId}/inject-now
export function injectTvAdNow(
  taskId: string,
  support = true,
): Promise<{ ok: boolean; error?: string }> {
  return post(`/tv/ad-runtime/tasks/${taskId}/inject-now`, { support, confirm: true });
}

// POST /api/v2/tv/ad-runtime/tasks/{taskId}/abort
export function abortTvAd(
  taskId: string,
  reason = "MANUAL_ABORT",
  support = true,
): Promise<{ ok: boolean; error?: string }> {
  return post(`/tv/ad-runtime/tasks/${taskId}/abort`, { support, confirm: true, reason });
}

// ─── Host Orchestration (A9) ──────────────────────────────────────────────────

export function getTvHostMonitors(): Promise<{ ok: boolean; rows: import("./types").TvHostMonitor[] }> {
  return get(`/tv/host/monitors`);
}

export function refreshTvHostMonitors(
  monitors: import("./types").TvHostMonitorsRefreshRequest["monitors"]
): Promise<{ ok: boolean; replaced: number }> {
  return post(`/tv/host/monitors/refresh`, { monitors });
}

export function getTvHostBindings(): Promise<{ ok: boolean; rows: import("./types").TvScreenBinding[] }> {
  return get(`/tv/host/bindings`);
}

export function createTvHostBinding(
  body: Partial<import("./types").TvScreenBinding> & { screen_name?: string; screenName?: string }
): Promise<{ ok: boolean; binding: import("./types").TvScreenBinding }> {
  return post(`/tv/host/bindings`, body);
}

export function updateTvHostBinding(
  bindingId: number,
  body: Partial<import("./types").TvScreenBinding>
): Promise<{ ok: boolean; binding: import("./types").TvScreenBinding }> {
  return import("../../api/client").then((c) => c.patch(`/tv/host/bindings/${bindingId}`, body));
}

export function deleteTvHostBinding(bindingId: number): Promise<{ ok: boolean }> {
  return import("../../api/client").then((c) => c.del(`/tv/host/bindings/${bindingId}`));
}

export function startTvHostBinding(bindingId: number): Promise<{ ok: boolean; binding: import("./types").TvScreenBinding }> {
  return post(`/tv/host/bindings/${bindingId}/start`);
}

export function stopTvHostBinding(bindingId: number): Promise<{ ok: boolean; binding: import("./types").TvScreenBinding }> {
  return post(`/tv/host/bindings/${bindingId}/stop`);
}

export function restartTvHostBinding(bindingId: number): Promise<{ ok: boolean; binding: import("./types").TvScreenBinding }> {
  return post(`/tv/host/bindings/${bindingId}/restart`);
}

export function getTvBindingStatus(bindingId: number): Promise<{ ok: boolean; binding: import("./types").TvScreenBinding }> {
  return get(`/tv/host/bindings/${bindingId}/status`);
}

export function getTvBindingEvents(
  bindingId: number,
  limit = 100,
  offset = 0
): Promise<{ ok: boolean; rows: import("./types").TvPlayerEvent[]; total: number }> {
  return get(`/tv/host/bindings/${bindingId}/events`, {
    limit: String(limit),
    offset: String(offset),
  });
}

export function getTvBindingSupportSummary(
  bindingId: number,
): Promise<import("./types").TvBindingSupportSummaryResponse> {
  return get(`/tv/host/bindings/${bindingId}/support-summary`);
}

export function runTvBindingSupportAction(
  bindingId: number,
  body: {
    actionType: import("./types").TvBindingSupportActionType;
    options?: Record<string, unknown>;
    confirm?: boolean;
    triggeredBy?: string;
  },
): Promise<{
  ok: boolean;
  correlationId: string;
  result: import("./types").TvBindingSupportActionResult;
  message?: string;
  errorCode?: string | null;
  metadata?: Record<string, unknown>;
}> {
  return post(`/tv/host/bindings/${bindingId}/support-actions/run`, body);
}

export function getTvBindingSupportHistory(
  bindingId: number,
  limit = 100,
  offset = 0,
): Promise<{ ok: boolean; rows: import("./types").TvSupportActionLogRow[]; total: number }> {
  return get(`/tv/host/bindings/${bindingId}/support-actions/history`, {
    limit: String(limit),
    offset: String(offset),
  });
}

export function postTvBindingRuntimeEvent(
  bindingId: number,
  body: {
    eventType: string;
    windowId?: string;
    errorCode?: string;
    errorMessage?: string;
    correlationId?: string;
  },
): Promise<{ ok: boolean; binding: import("./types").TvScreenBinding }> {
  return post(`/tv/host/bindings/${bindingId}/runtime-event`, body);
}

export function getTvObservabilityOverview(
  gymId?: number,
): Promise<import("./types").TvObservabilityOverviewResponse> {
  return get(`/tv/observability/overview`, gymId ? { gymId: String(gymId) } : undefined);
}

export function getTvObservabilityBindings(params?: {
  gymId?: number;
  health?: string;
  runtimeState?: string;
  q?: string;
  problemOnly?: boolean;
  limit?: number;
  offset?: number;
}): Promise<{ ok: boolean; rows: import("./types").TvObservabilityBindingSummary[]; total: number; limit: number; offset: number }> {
  const query: Record<string, string> = {};
  if (params?.gymId) query.gymId = String(params.gymId);
  if (params?.health) query.health = params.health;
  if (params?.runtimeState) query.runtimeState = params.runtimeState;
  if (params?.q) query.q = params.q;
  if (params?.problemOnly != null) query.problemOnly = params.problemOnly ? "1" : "0";
  if (params?.limit != null) query.limit = String(params.limit);
  if (params?.offset != null) query.offset = String(params.offset);
  return get(`/tv/observability/bindings`, query);
}

export function getTvObservabilityBinding(
  bindingId: number,
  params?: { eventLimit?: number; historyLimit?: number },
): Promise<import("./types").TvObservabilityBindingDetail> {
  const query: Record<string, string> = {};
  if (params?.eventLimit != null) query.eventLimit = String(params.eventLimit);
  if (params?.historyLimit != null) query.historyLimit = String(params.historyLimit);
  return get(`/tv/observability/bindings/${bindingId}`, query);
}

export function getTvObservabilityGyms(
  params?: { limit?: number; offset?: number },
): Promise<{ ok: boolean; rows: import("./types").TvObservabilityGymDetail[]; total: number; limit: number; offset: number }> {
  const query: Record<string, string> = {};
  if (params?.limit != null) query.limit = String(params.limit);
  if (params?.offset != null) query.offset = String(params.offset);
  return get(`/tv/observability/gyms`, query);
}

export function getTvObservabilityGym(
  gymId: number,
): Promise<import("./types").TvObservabilityGymDetail> {
  return get(`/tv/observability/gyms/${gymId}`);
}

export function getTvObservabilityProofs(params?: {
  gymId?: number;
  bindingId?: number;
  outboxStates?: string[];
  resultStatus?: string;
  countable?: boolean;
  limit?: number;
  offset?: number;
}): Promise<import("./types").TvObservabilityProofsResponse> {
  const query: Record<string, string> = {};
  if (params?.gymId) query.gymId = String(params.gymId);
  if (params?.bindingId) query.bindingId = String(params.bindingId);
  if (params?.outboxStates?.length) query.outboxStates = params.outboxStates.join(",");
  if (params?.resultStatus) query.resultStatus = params.resultStatus;
  if (params?.countable != null) query.countable = params.countable ? "1" : "0";
  if (params?.limit != null) query.limit = String(params.limit);
  if (params?.offset != null) query.offset = String(params.offset);
  return get(`/tv/observability/proofs`, query);
}

export function getTvObservabilityRetention(): Promise<import("./types").TvObservabilityRetentionResponse> {
  return get(`/tv/observability/retention`);
}

export function runTvObservabilityRetention(body?: {
  dryRun?: boolean;
  includeQueryChecks?: boolean;
}): Promise<import("./types").TvObservabilityRetentionRunResponse> {
  return post(`/tv/observability/retention/run`, body ?? {});
}

export function getTvObservabilityEvents(params?: {
  bindingId?: number;
  gymId?: number;
  sources?: string[];
  limit?: number;
  offset?: number;
}): Promise<{ ok: boolean; rows: import("./types").TvObservabilityEventRow[]; total: number; limit: number; offset: number }> {
  const query: Record<string, string> = {};
  if (params?.bindingId) query.bindingId = String(params.bindingId);
  if (params?.gymId) query.gymId = String(params.gymId);
  if (params?.sources?.length) query.sources = params.sources.join(",");
  if (params?.limit != null) query.limit = String(params.limit);
  if (params?.offset != null) query.offset = String(params.offset);
  return get(`/tv/observability/events`, query);
}

export function getTvSnapshotCache(params?: {
  screenId?: number;
  limit?: number;
  offset?: number;
}): Promise<import("./types").TvSnapshotCacheResponse> {
  const query: Record<string, string> = {};
  if (params?.screenId) query.screenId = String(params.screenId);
  if (params?.limit != null) query.limit = String(params.limit);
  if (params?.offset != null) query.offset = String(params.offset);
  return get(`/tv/snapshots`, query);
}

export function getTvLatestSnapshots(
  screenId?: number,
): Promise<import("./types").TvLatestSnapshotsResponse> {
  return get(`/tv/snapshots/latest`, screenId ? { screenId: String(screenId) } : undefined);
}

export function getTvSnapshotAssets(
  snapshotId: string,
): Promise<import("./types").TvSnapshotAssetsResponse> {
  return get(`/tv/snapshots/${encodeURIComponent(snapshotId)}/assets`);
}

export function getTvDashboardScreens(params?: {
  q?: string;
  gymId?: number;
  enabled?: boolean;
  orientation?: string;
  hasLayout?: boolean;
  includeArchived?: boolean;
  page?: number;
  size?: number;
  sortBy?: string;
  sortDir?: string;
}): Promise<import("./types").TvDashboardScreenPageResponse> {
  const query: Record<string, string> = {};
  if (params?.q) query.q = params.q;
  if (params?.gymId) query.gymId = String(params.gymId);
  if (params?.enabled != null) query.enabled = params.enabled ? "true" : "false";
  if (params?.orientation) query.orientation = params.orientation;
  if (params?.hasLayout != null) query.hasLayout = params.hasLayout ? "true" : "false";
  if (params?.includeArchived != null) query.includeArchived = params.includeArchived ? "true" : "false";
  if (params?.page != null) query.page = String(params.page);
  if (params?.size != null) query.size = String(params.size);
  if (params?.sortBy) query.sortBy = params.sortBy;
  if (params?.sortDir) query.sortDir = params.sortDir;
  return get(`/tv/dashboard/screens`, query);
}

export function getTvDashboardScreen(
  screenId: number,
): Promise<import("./types").TvDashboardScreenResponse> {
  return get(`/tv/dashboard/screens/${screenId}`);
}

export function getTvDashboardScreenContentPlan(
  screenId: number,
): Promise<import("./types").TvDashboardScreenContentPlan> {
  return get(`/tv/dashboard/screens/${screenId}/content-plan`);
}

export function getTvDashboardScreenSnapshots(
  screenId: number,
  params?: {
    page?: number;
    size?: number;
    sortBy?: string;
    sortDir?: string;
  },
): Promise<import("./types").TvDashboardSnapshotPageResponse> {
  const query: Record<string, string> = {};
  if (params?.page != null) query.page = String(params.page);
  if (params?.size != null) query.size = String(params.size);
  if (params?.sortBy) query.sortBy = params.sortBy;
  if (params?.sortDir) query.sortDir = params.sortDir;
  return get(`/tv/dashboard/screens/${screenId}/snapshots`, query);
}

export function getTvDashboardScreenLatestSnapshot(
  screenId: number,
  resolveAt?: string,
): Promise<import("./types").TvDashboardResolvedSnapshotResponse> {
  return get(
    `/tv/dashboard/screens/${screenId}/snapshots/latest`,
    resolveAt ? { resolveAt } : undefined,
  );
}

export function getTvDashboardSnapshot(
  snapshotId: number | string,
): Promise<import("./types").TvDashboardResolvedSnapshotResponse> {
  return get(`/tv/dashboard/snapshots/${encodeURIComponent(String(snapshotId))}`);
}

export function getTvDashboardSnapshotManifest(
  snapshotId: number | string,
): Promise<import("./types").TvDashboardSnapshotAssetManifestResponse> {
  return get(`/tv/dashboard/snapshots/${encodeURIComponent(String(snapshotId))}/asset-manifest`);
}

export function getTvAssets(params?: {
  screenId?: number;
  snapshotId?: string;
  state?: string;
  mediaAssetId?: string;
  limit?: number;
  offset?: number;
}): Promise<import("./types").TvLocalAssetsResponse> {
  const query: Record<string, string> = {};
  if (params?.screenId) query.screenId = String(params.screenId);
  if (params?.snapshotId) query.snapshotId = params.snapshotId;
  if (params?.state) query.state = params.state;
  if (params?.mediaAssetId) query.mediaAssetId = params.mediaAssetId;
  if (params?.limit != null) query.limit = String(params.limit);
  if (params?.offset != null) query.offset = String(params.offset);
  return get(`/tv/assets`, query);
}

export function downloadTvAssets(body?: {
  screenId?: number;
  snapshotId?: string;
}): Promise<{ ok: boolean; message?: string }> {
  return post(`/tv/assets/download`, body ?? {});
}

export function getTvReadiness(params?: {
  screenId?: number;
  limit?: number;
  offset?: number;
}): Promise<import("./types").TvSnapshotReadinessResponse> {
  const query: Record<string, string> = {};
  if (params?.screenId) query.screenId = String(params.screenId);
  if (params?.limit != null) query.limit = String(params.limit);
  if (params?.offset != null) query.offset = String(params.offset);
  return get(`/tv/readiness`, query);
}

export function getTvLatestReadiness(
  screenId: number,
): Promise<import("./types").TvLatestReadinessResponse> {
  return get(`/tv/readiness/latest`, { screenId: String(screenId) });
}

export function getTvDbTables(): Promise<DbTablesResponse> {
  return get(`/tv/db/tables`);
}

export function getTvDbTable(
  tableName: string,
  limit = 500,
  offset = 0,
): Promise<DbTableQueryResponse> {
  return get(`/tv/db/table/${encodeURIComponent(tableName)}`, {
    limit: String(limit),
    offset: String(offset),
  });
}

export function getTvUpdateStatus(): Promise<import("../../api/types").UpdateStatusResponse> {
  return get(`/tv/update/status`);
}

export function checkTvUpdate(): Promise<{ ok: boolean }> {
  return post(`/tv/update/check`, {});
}

export function downloadTvUpdate(): Promise<{ ok: boolean }> {
  return post(`/tv/update/download`, {});
}

export function installTvUpdate(): Promise<{ ok: boolean; message?: string }> {
  return post(`/tv/update/install`, {});
}

export function cancelTvUpdate(): Promise<{ ok: boolean }> {
  return post(`/tv/update/cancel`, {});
}

export function getTvVersionInfo(): Promise<import("../../api/types").UpdateVersionInfoResponse> {
  return get(`/tv/update/version`);
}

export function getTvConfig(): Promise<import("./types").AppConfig> {
  return get(`/tv/config`);
}

export function patchTvConfig(
  body: Partial<import("./types").AppConfig>,
): Promise<{ ok: boolean; changed: Record<string, unknown>; config: import("./types").AppConfig }> {
  return patch(`/tv/config`, body);
}

export function getTvRecentLogs(
  params?: { level?: string; limit?: number },
): Promise<{ ok: boolean; lines: LogLine[]; total: number }> {
  const query: Record<string, string> = {};
  if (params?.level) query.level = params.level;
  if (params?.limit != null) query.limit = String(params.limit);
  return get(`/tv/logs/recent`, query);
}

export function openTvLogsStream(
  onEvent: (type: string, data: unknown) => void,
  options?: {
    level?: string;
    onError?: (event: Event) => void;
  },
): EventSource {
  const level = String(options?.level || "ALL").trim().toUpperCase();
  const path = level && level !== "ALL"
    ? `/tv/logs/stream?level=${encodeURIComponent(level)}`
    : `/tv/logs/stream`;
  return openSSE(path, onEvent, options?.onError);
}

export async function getTvStartupLatest(): Promise<import("./types").TvStartupLatestResponse | null> {
  try {
    return await get(`/tv/startup/latest`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null;
    }
    throw error;
  }
}

export function getTvStartupRuns(
  limit = 20,
  offset = 0,
): Promise<import("./types").TvStartupRunsResponse> {
  return get(`/tv/startup/runs`, {
    limit: String(limit),
    offset: String(offset),
  });
}

export function runTvStartupReconciliation(body?: {
  triggerSource?: string;
  correlationId?: string;
  includeQueryChecks?: boolean;
  monitors?: import("./types").TvHostMonitorsRefreshRequest["monitors"];
}): Promise<import("./types").TvStartupRunResponse> {
  return post(`/tv/startup/run`, body ?? {});
}

export function getTvStartupPreflight(
  includeQueryChecks = false,
): Promise<import("./types").TvStartupPreflightResponse> {
  return get(`/tv/startup/preflight`, {
    includeQueryChecks: includeQueryChecks ? "1" : "0",
  });
}

// POST /api/v2/tv/snapshots/sync
export function runTvSnapshotSync(): Promise<{ ok: boolean; message: string }> {
  return post<{ ok: boolean; message: string }>(`/tv/snapshots/sync`, {});
}
