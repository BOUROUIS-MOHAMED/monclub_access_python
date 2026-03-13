import { del, get, patch, post } from "@/api/client";
import type {
  TvActivationAttemptRow,
  TvActivationStatusPayload,
  TvCacheAssetsResponse,
  TvDownloadBatchSummary,
  TvDownloadJobRow,
  TvAdTaskListResponse,
  TvReadinessRow,
  TvScreenBinding,
  TvSnapshotCacheRow,
  TvSyncStatusResponse,
  TvHostBindingEventsResponse,
  TvHostBindingResponse,
  TvHostBindingsResponse,
  TvHostMonitorsResponse,
  TvPlayerActionResponse,
  TvPlayerEventsResponse,
  TvPlayerRenderContextResponse,
  TvPlayerStateReportResponse,
  TvPlayerStatusResponse,
  TvBindingSupportSummaryResponse,
  TvSupportActionRunResponse,
  TvSupportActionHistoryResponse,
  TvObservabilityOverviewResponse,
  TvObservabilityFleetHealthResponse,
  TvObservabilityScreenDetailsResponse,
  TvObservabilityTimelineResponse,
  TvObservabilityHeartbeatsResponse,
  TvObservabilityRuntimeEventsResponse,
  TvObservabilityProofEventsResponse,
  TvObservabilityProofStatsResponse,
  TvObservabilityRuntimeStatsResponse,
  TvHardeningStartupLatestResponse,
  TvHardeningStartupRunsResponse,
  TvHardeningQueryChecksResponse,
  TvHardeningRetentionPolicyResponse,
  TvHardeningRetentionRunResponse,
  TvHardeningCorrelationAuditResponse,
  TvHardeningPreflightResponse,
  TvAdTaskInjectNowResponse,
  TvGymAdRuntimeResponse,
  TvAdTaskRuntimeOneResponse,
  TvAdTaskRuntimeListResponse,
} from "@/api/types";

export interface TvBindingResponse {
  ok: boolean;
  binding: TvScreenBinding;
}

export interface TvSyncRunResponse {
  ok: boolean;
  screenId: number;
  syncStatus: string;
  snapshotId?: string;
  snapshotVersion?: number;
  warnings?: string[];
  error?: string;
  readiness?: Record<string, any>;
  latestSnapshot?: TvSnapshotCacheRow | null;
  previousReadySnapshot?: TvSnapshotCacheRow | null;
  activation?: TvActivationStatusPayload | null;
}

export interface TvSnapshotLatestResponse {
  ok: boolean;
  screenId: number;
  latest: TvSnapshotCacheRow | null;
  latestReady?: TvSnapshotCacheRow | null;
  previousReady: TvSnapshotCacheRow | null;
}

export interface TvSnapshotByIdResponse {
  ok: boolean;
  snapshot: TvSnapshotCacheRow;
}

export interface TvSnapshotManifestResponse {
  ok: boolean;
  snapshotId: string;
  manifest: Record<string, any>;
}

export interface TvLatestReadinessResponse {
  ok: boolean;
  screenId: number;
  readiness: TvReadinessRow | null;
  latestSnapshot?: TvSnapshotCacheRow | null;
  previousReadySnapshot?: TvSnapshotCacheRow | null;
}

export interface TvDownloadRunResponse {
  ok: boolean;
  error?: string;
  batchId?: string;
  screenId?: number;
  snapshotId?: string;
  snapshotVersion?: number;
  counts?: Record<string, number>;
  totalJobs?: number;
  queued?: number;
  skipped?: number;
  concurrency?: number;
  background?: boolean;
  status?: string;
  latestReadiness?: TvReadinessRow | null;
  latestSnapshot?: TvSnapshotCacheRow | null;
  previousReadySnapshot?: TvSnapshotCacheRow | null;
  activation?: TvActivationStatusPayload | null;
}

export interface TvLatestDownloadBatchResponse {
  ok: boolean;
  screenId: number | null;
  batch: TvDownloadBatchSummary | null;
}

export interface TvDownloadJobsResponse {
  ok: boolean;
  screenId: number;
  rows: TvDownloadJobRow[];
  total: number;
  latestBatch?: TvDownloadBatchSummary | null;
  latestReadiness?: TvReadinessRow | null;
}

export interface TvActivationStatusResponse {
  ok: boolean;
  screenId: number;
  activation: TvActivationStatusPayload;
}

export interface TvActivationRunResponse {
  ok: boolean;
  screenId: number;
  result: string;
  failureReason?: string;
  failureMessage?: string;
  error?: string;
  activation?: TvActivationStatusPayload;
}

export interface TvActivationHistoryResponse {
  ok: boolean;
  screenId: number;
  rows: TvActivationAttemptRow[];
  total: number;
}

export function getTvBinding() {
  return get<TvBindingResponse>("/tv/binding");
}

export function patchTvBinding(payload: { screenId: number; screenName?: string }) {
  return patch<TvBindingResponse>("/tv/binding", payload);
}

export function runTvSync(payload?: { screenId?: number; resolveAt?: string }) {
  return post<TvSyncRunResponse>("/tv/sync/run", payload || {});
}

export function getTvSyncStatus(screenId?: number) {
  return get<TvSyncStatusResponse>("/tv/sync/status", screenId ? { screenId: String(screenId) } : undefined);
}

export function getTvLatestSnapshot(screenId?: number) {
  return get<TvSnapshotLatestResponse>("/tv/snapshots/latest", screenId ? { screenId: String(screenId) } : undefined);
}

export function getTvSnapshotById(snapshotId: string) {
  return get<TvSnapshotByIdResponse>(`/tv/snapshots/${encodeURIComponent(snapshotId)}`);
}

export function getTvSnapshotManifest(snapshotId: string) {
  return get<TvSnapshotManifestResponse>(`/tv/snapshots/${encodeURIComponent(snapshotId)}/manifest`);
}

export function getTvLatestReadiness(screenId?: number) {
  return get<TvLatestReadinessResponse>("/tv/readiness/latest", screenId ? { screenId: String(screenId) } : undefined);
}

export function getTvCacheAssets(params?: {
  screenId?: number;
  snapshotVersion?: number;
  states?: string;
  limit?: number;
  offset?: number;
}) {
  const q: Record<string, string> = {};
  if (params?.screenId != null) q.screenId = String(params.screenId);
  if (params?.snapshotVersion != null) q.snapshotVersion = String(params.snapshotVersion);
  if (params?.states) q.states = params.states;
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvCacheAssetsResponse>("/tv/cache/assets", q);
}

export function runTvDownloads(payload?: {
  screenId?: number;
  snapshotVersion?: number;
  runInBackground?: boolean;
  retryFailedOnly?: boolean;
  force?: boolean;
  mediaAssetId?: string;
  maxAttempts?: number;
  maxConcurrency?: number;
}) {
  return post<TvDownloadRunResponse>("/tv/downloads/run", payload || {});
}

export function getTvLatestDownloadBatch(screenId?: number) {
  return get<TvLatestDownloadBatchResponse>(
    "/tv/downloads/batches/latest",
    screenId ? { screenId: String(screenId) } : undefined
  );
}

export function getTvDownloadJobs(params?: {
  screenId?: number;
  snapshotVersion?: number;
  batchId?: string;
  states?: string;
  limit?: number;
  offset?: number;
}) {
  const q: Record<string, string> = {};
  if (params?.screenId != null) q.screenId = String(params.screenId);
  if (params?.snapshotVersion != null) q.snapshotVersion = String(params.snapshotVersion);
  if (params?.batchId) q.batchId = params.batchId;
  if (params?.states) q.states = params.states;
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvDownloadJobsResponse>("/tv/downloads/jobs", q);
}

export function retryTvDownloadJob(jobId: number, payload?: { runInBackground?: boolean }) {
  return post<TvDownloadRunResponse>(`/tv/downloads/jobs/${encodeURIComponent(String(jobId))}/retry`, payload || {});
}
export interface TvAdTaskFetchResponse {
  ok: boolean;
  fetched?: number;
  rows?: Array<Record<string, any>>;
  gymIds?: number[];
  updatedAfter?: string | null;
  serverTimeUtc?: string;
  stats?: Record<string, number>;
  error?: string;
}

export interface TvAdTaskPrepareResponse {
  ok: boolean;
  prepare?: Record<string, any>;
  confirm?: Record<string, any>;
  error?: string;
}

export interface TvAdTaskCycleResponse {
  ok: boolean;
  fetch?: Record<string, any>;
  prepare?: Record<string, any>;
  confirm?: Record<string, any>;
  error?: string;
}

export function getTvAdTasks(params?: {
  gymId?: number;
  remoteStatuses?: string;
  localStates?: string;
  q?: string;
  limit?: number;
  offset?: number;
}) {
  const q: Record<string, string> = {};
  if (params?.gymId != null) q.gymId = String(params.gymId);
  if (params?.remoteStatuses) q.remoteStatuses = params.remoteStatuses;
  if (params?.localStates) q.localStates = params.localStates;
  if (params?.q) q.q = params.q;
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvAdTaskListResponse>("/tv/ad-tasks", q);
}

export function fetchTvAdTasks(payload?: { force?: boolean; limit?: number; correlationId?: string }) {
  return post<TvAdTaskFetchResponse>("/tv/ad-tasks/fetch", payload || {});
}

export function prepareTvAdTasks(payload?: {
  campaignTaskId?: number;
  force?: boolean;
  limit?: number;
  processConfirm?: boolean;
  correlationId?: string;
}) {
  return post<TvAdTaskPrepareResponse>("/tv/ad-tasks/prepare", payload || {});
}

export function runTvAdTasksCycle(payload?: {
  forceFetch?: boolean;
  forcePrepare?: boolean;
  forceConfirm?: boolean;
  correlationId?: string;
}) {
  return post<TvAdTaskCycleResponse>("/tv/ad-tasks/cycle", payload || {});
}

export function retryTvAdTaskPrepare(taskId: number, payload?: { correlationId?: string }) {
  return post<TvAdTaskPrepareResponse>(`/tv/ad-tasks/${encodeURIComponent(String(taskId))}/retry-prepare`, payload || {});
}

export function retryTvAdTaskConfirm(taskId: number, payload?: { correlationId?: string }) {
  return post<TvAdTaskPrepareResponse>(`/tv/ad-tasks/${encodeURIComponent(String(taskId))}/retry-confirm`, payload || {});
}


export function getTvAdTaskRuntime(params?: { gymId?: number; campaignTaskId?: number; limit?: number; offset?: number }) {
  const q: Record<string, string> = {};
  if (params?.gymId != null) q.gymId = String(params.gymId);
  if (params?.campaignTaskId != null) q.campaignTaskId = String(params.campaignTaskId);
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvAdTaskRuntimeListResponse>("/tv/ad-tasks/runtime", q);
}

export function getTvAdTaskRuntimeById(taskId: number) {
  return get<TvAdTaskRuntimeOneResponse>(`/tv/ad-tasks/${encodeURIComponent(String(taskId))}/runtime`);
}

export function getTvGymAdRuntime(gymId: number) {
  return get<TvGymAdRuntimeResponse>(`/tv/gym-ad-runtime/${encodeURIComponent(String(gymId))}`);
}

export function injectTvAdTaskNow(taskId: number, payload?: { support?: boolean; confirm?: boolean; correlationId?: string }) {
  return post<TvAdTaskInjectNowResponse>(`/tv/ad-tasks/${encodeURIComponent(String(taskId))}/inject-now`, payload || {});
}

export function getTvActivationStatus(screenId?: number) {
  return get<TvActivationStatusResponse>("/tv/activation/status", screenId ? { screenId: String(screenId) } : undefined);
}

export function evaluateTvActivation(payload?: { screenId?: number; autoActivate?: boolean; recheckReadiness?: boolean }) {
  return post<TvActivationRunResponse>("/tv/activation/evaluate", payload || {});
}

export function activateTvLatestReady(payload?: { screenId?: number }) {
  return post<TvActivationRunResponse>("/tv/activation/activate-latest-ready", payload || {});
}

export function getTvActivationHistory(params?: { screenId?: number; limit?: number; offset?: number }) {
  const q: Record<string, string> = {};
  if (params?.screenId != null) q.screenId = String(params.screenId);
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvActivationHistoryResponse>("/tv/activation/history", q);
}


export function getTvHostMonitors() {
  return get<TvHostMonitorsResponse>("/tv/host/monitors");
}

export function refreshTvHostMonitors(monitors: Array<Record<string, any>>) {
  return post<TvHostMonitorsResponse>("/tv/host/monitors/refresh", { monitors });
}

export function getTvHostBindings() {
  return get<TvHostBindingsResponse>("/tv/host/bindings");
}

export function createTvHostBinding(payload: {
  screenId: number;
  screenName?: string;
  monitorId?: string;
  monitorLabel?: string;
  monitorIndex?: number;
  enabled?: boolean;
  autostart?: boolean;
  fullscreen?: boolean;
}) {
  return post<TvHostBindingResponse>("/tv/host/bindings", payload);
}

export function updateTvHostBinding(bindingId: number, payload: {
  screenName?: string;
  monitorId?: string;
  monitorLabel?: string;
  monitorIndex?: number;
  enabled?: boolean;
  autostart?: boolean;
  fullscreen?: boolean;
}) {
  return patch<TvHostBindingResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}`, payload);
}

export function deleteTvHostBinding(bindingId: number) {
  return del<{ ok: boolean }>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}`);
}

export function getTvHostBindingStatus(bindingId: number) {
  return get<TvHostBindingResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/status`);
}

export function getTvHostBindingEvents(bindingId: number, params?: { limit?: number; offset?: number }) {
  const q: Record<string, string> = {};
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvHostBindingEventsResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/events`, q);
}

export function postTvHostBindingRuntimeEvent(bindingId: number, payload: {
  eventType: string;
  windowId?: string;
  errorCode?: string;
  errorMessage?: string;
  correlationId?: string;
}) {
  return post<TvHostBindingResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/runtime-event`, payload);
}

export function getTvHostBindingSupportSummary(bindingId: number) {
  return get<TvBindingSupportSummaryResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/support-summary`);
}

export function runTvHostBindingSupportAction(bindingId: number, payload: {
  actionType: string;
  options?: Record<string, any>;
  confirm?: boolean;
  triggeredBy?: string;
}) {
  return post<TvSupportActionRunResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/support-actions/run`, payload);
}

export function getTvHostBindingSupportActionHistory(bindingId: number, params?: { limit?: number; offset?: number }) {
  const q: Record<string, string> = {};
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvSupportActionHistoryResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/support-actions/history`, q);
}

export function startTvHostBinding(bindingId: number) {
  return post<TvHostBindingResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/start`, {});
}

export function stopTvHostBinding(bindingId: number) {
  return post<TvHostBindingResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/stop`, {});
}

export function restartTvHostBinding(bindingId: number) {
  return post<TvHostBindingResponse>(`/tv/host/bindings/${encodeURIComponent(String(bindingId))}/restart`, {});
}


export function getTvPlayerStatus(bindingId: number) {
  return get<TvPlayerStatusResponse>(`/tv/player/${encodeURIComponent(String(bindingId))}/status`);
}

export function getTvPlayerRenderContext(bindingId: number, params?: { persist?: boolean }) {
  const q: Record<string, string> = {};
  if (params?.persist != null) q.persist = params.persist ? "1" : "0";
  return get<TvPlayerRenderContextResponse>(`/tv/player/${encodeURIComponent(String(bindingId))}/render-context`, q);
}

export function reevaluateTvPlayer(bindingId: number, payload?: { persist?: boolean }) {
  return post<TvPlayerActionResponse>(`/tv/player/${encodeURIComponent(String(bindingId))}/reevaluate`, payload || {});
}

export function reloadTvPlayer(bindingId: number, payload?: { persist?: boolean }) {
  return post<TvPlayerActionResponse>(`/tv/player/${encodeURIComponent(String(bindingId))}/reload`, payload || {});
}

export function reportTvPlayerState(bindingId: number, payload: {
  state?: Record<string, any>;
  eventType?: string;
  force?: boolean;
  freshnessSeconds?: number;
}) {
  return post<TvPlayerStateReportResponse>(`/tv/player/${encodeURIComponent(String(bindingId))}/state`, payload);
}

export function getTvPlayerEvents(bindingId: number, params?: { limit?: number; offset?: number }) {
  const q: Record<string, string> = {};
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvPlayerEventsResponse>(`/tv/player/${encodeURIComponent(String(bindingId))}/events`, q);
}



export function getTvObservabilityOverview(params?: { gymId?: number }) {
  const q: Record<string, string> = {};
  if (params?.gymId != null) q.gymId = String(params.gymId);
  return get<TvObservabilityOverviewResponse>("/tv/observability/overview", q);
}

export function getTvObservabilityFleetHealth(params?: {
  gymId?: number;
  health?: string;
  runtimeState?: string;
  q?: string;
  limit?: number;
  offset?: number;
}) {
  const qv: Record<string, string> = {};
  if (params?.gymId != null) qv.gymId = String(params.gymId);
  if (params?.health) qv.health = params.health;
  if (params?.runtimeState) qv.runtimeState = params.runtimeState;
  if (params?.q) qv.q = params.q;
  if (params?.limit != null) qv.limit = String(params.limit);
  if (params?.offset != null) qv.offset = String(params.offset);
  return get<TvObservabilityFleetHealthResponse>("/tv/observability/fleet-health", qv);
}

export function getTvObservabilityScreenDetails(screenId: number) {
  return get<TvObservabilityScreenDetailsResponse>(`/tv/observability/screens/${encodeURIComponent(String(screenId))}`);
}

export function getTvObservabilityScreenTimeline(screenId: number, params?: { limit?: number; offset?: number }) {
  const q: Record<string, string> = {};
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvObservabilityTimelineResponse>(`/tv/observability/screens/${encodeURIComponent(String(screenId))}/timeline`, q);
}

export function getTvObservabilityHeartbeats(params?: {
  gymId?: number;
  screenId?: number;
  bindingId?: number;
  fromUtc?: string;
  toUtc?: string;
  limit?: number;
  offset?: number;
}) {
  const q: Record<string, string> = {};
  if (params?.gymId != null) q.gymId = String(params.gymId);
  if (params?.screenId != null) q.screenId = String(params.screenId);
  if (params?.bindingId != null) q.bindingId = String(params.bindingId);
  if (params?.fromUtc) q.fromUtc = params.fromUtc;
  if (params?.toUtc) q.toUtc = params.toUtc;
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvObservabilityHeartbeatsResponse>("/tv/observability/heartbeats", q);
}

export function getTvObservabilityRuntimeEvents(params?: {
  gymId?: number;
  screenId?: number;
  bindingId?: number;
  severities?: string;
  eventTypes?: string;
  fromUtc?: string;
  toUtc?: string;
  limit?: number;
  offset?: number;
}) {
  const q: Record<string, string> = {};
  if (params?.gymId != null) q.gymId = String(params.gymId);
  if (params?.screenId != null) q.screenId = String(params.screenId);
  if (params?.bindingId != null) q.bindingId = String(params.bindingId);
  if (params?.severities) q.severities = params.severities;
  if (params?.eventTypes) q.eventTypes = params.eventTypes;
  if (params?.fromUtc) q.fromUtc = params.fromUtc;
  if (params?.toUtc) q.toUtc = params.toUtc;
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvObservabilityRuntimeEventsResponse>("/tv/observability/runtime-events", q);
}

export function getTvObservabilityProofEvents(params?: {
  gymId?: number;
  screenId?: number;
  bindingId?: number;
  snapshotVersion?: number;
  timelineTypes?: string;
  statuses?: string;
  fromUtc?: string;
  toUtc?: string;
  limit?: number;
  offset?: number;
}) {
  const q: Record<string, string> = {};
  if (params?.gymId != null) q.gymId = String(params.gymId);
  if (params?.screenId != null) q.screenId = String(params.screenId);
  if (params?.bindingId != null) q.bindingId = String(params.bindingId);
  if (params?.snapshotVersion != null) q.snapshotVersion = String(params.snapshotVersion);
  if (params?.timelineTypes) q.timelineTypes = params.timelineTypes;
  if (params?.statuses) q.statuses = params.statuses;
  if (params?.fromUtc) q.fromUtc = params.fromUtc;
  if (params?.toUtc) q.toUtc = params.toUtc;
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvObservabilityProofEventsResponse>("/tv/observability/proof-events", q);
}

export function getTvObservabilityProofStats(params?: {
  gymId?: number;
  screenId?: number;
  fromUtc?: string;
  toUtc?: string;
  bucket?: "HOUR" | "DAY";
}) {
  const q: Record<string, string> = {};
  if (params?.gymId != null) q.gymId = String(params.gymId);
  if (params?.screenId != null) q.screenId = String(params.screenId);
  if (params?.fromUtc) q.fromUtc = params.fromUtc;
  if (params?.toUtc) q.toUtc = params.toUtc;
  if (params?.bucket) q.bucket = params.bucket;
  return get<TvObservabilityProofStatsResponse>("/tv/observability/stats/proof", q);
}

export function getTvObservabilityRuntimeStats(params?: {
  gymId?: number;
  screenId?: number;
  fromUtc?: string;
  toUtc?: string;
}) {
  const q: Record<string, string> = {};
  if (params?.gymId != null) q.gymId = String(params.gymId);
  if (params?.screenId != null) q.screenId = String(params.screenId);
  if (params?.fromUtc) q.fromUtc = params.fromUtc;
  if (params?.toUtc) q.toUtc = params.toUtc;
  return get<TvObservabilityRuntimeStatsResponse>("/tv/observability/stats/runtime", q);
}

export function getTvHardeningPreflight(params?: { includeQueryChecks?: boolean }) {
  const q: Record<string, string> = {};
  if (params?.includeQueryChecks) q.includeQueryChecks = "1";
  return get<TvHardeningPreflightResponse>("/tv/hardening/preflight", q);
}
export function getTvHardeningStartupLatest() {
  return get<TvHardeningStartupLatestResponse>("/tv/hardening/startup/latest");
}

export function getTvHardeningStartupRuns(params?: { limit?: number; offset?: number }) {
  const q: Record<string, string> = {};
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.offset != null) q.offset = String(params.offset);
  return get<TvHardeningStartupRunsResponse>("/tv/hardening/startup/runs", q);
}

export function runTvHardeningStartupReconciliation(payload?: {
  triggerSource?: string;
  correlationId?: string;
  monitors?: Array<Record<string, any>>;
}) {
  return post<TvHardeningStartupLatestResponse>("/tv/hardening/startup/run", payload || {});
}

export function getTvHardeningRetentionPolicy() {
  return get<TvHardeningRetentionPolicyResponse>("/tv/hardening/retention-policy");
}

export function runTvHardeningRetention(payload?: { dryRun?: boolean; includeQueryChecks?: boolean }) {
  return post<TvHardeningRetentionRunResponse>("/tv/hardening/retention/run", payload || {});
}

export function getTvHardeningQueryChecks(params?: { limit?: number }) {
  const q: Record<string, string> = {};
  if (params?.limit != null) q.limit = String(params.limit);
  return get<TvHardeningQueryChecksResponse>("/tv/hardening/query-checks", q);
}

export function getTvHardeningCorrelationAudit(correlationId: string) {
  return get<TvHardeningCorrelationAuditResponse>("/tv/hardening/correlation-audit", { correlationId });
}






