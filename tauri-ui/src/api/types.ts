// TypeScript types aligned with real /api/v2/ responses from local_access_api_v2.py

// ─── Common ───
export interface ApiOk { ok: true }

// ─── A) Unified Status (GET /api/v2/status) ───
export interface SessionBlock {
  loggedIn: boolean;
  restricted: boolean;
  reasons: string[];
  email: string | null;
  lastLoginAt: string | null;
  contractStatus: boolean;
  contractEndDate: string | null;
  /** Days remaining before login session expires (null = unknown) */
  loginDaysRemaining: number | null;
  /** True if login expires within 7 days */
  loginWarning: boolean;
  /** Days remaining before contract expires (null = unknown) */
  contractDaysRemaining: number | null;
  /** True if contract expires within 10 days */
  contractWarning: boolean;
}

export interface ModeBlock {
  globalMode: "DEVICE_ONLY" | "AGENT_ONLY" | "MIXED";
  summary: { DEVICE: number; AGENT: number; UNKNOWN: number };
}

export interface SyncBlock {
  running: boolean;
  lastSyncAt: string | null;
  lastOk: boolean;
  lastError: string | null;
}

export interface PullSdkBlock {
  connected: boolean;
  deviceId: number | null;
  ip: string | null;
  since: string | null;
  lastError: string | null;
}

export interface AgentBlock {
  running: boolean;
  eventQueueDepth: number;
  avgDecisionMs: number;
}

export interface UpdatesBlock {
  updateAvailable: boolean;
  downloaded: boolean;
  downloading: boolean;
  progress: number | null;
  currentReleaseId: string | null;
  lastCheckAt: number | null;
  lastError: string | null;
}

export interface StatusResponse extends ApiOk {
  session: SessionBlock;
  mode: ModeBlock;
  sync: SyncBlock;
  deviceSync: { lastRunAt: string | null; lastOk: boolean; lastError: string | null };
  pullsdk: PullSdkBlock;
  agent: AgentBlock;
  updates: UpdatesBlock;
}

// ─── B) Auth ───
export interface LoginRequest { email: string; password: string }
export interface LoginResponse extends ApiOk { token: string }

// ─── C) Config (GET /api/v2/config) ───
export interface AppConfig {
  selected_device_id: number | null;
  data_mode: string;
  device_timeout_ms: number;
  local_api_enabled: boolean;
  local_api_host: string;
  local_api_port: number;
  sync_interval_sec: number;
  max_login_age_minutes: number;
  device_sync_enabled: boolean;
  agent_realtime_enabled: boolean;
  template_version: number;
  template_encoding: string;
  plcomm_dll_path: string;
  zkfp_dll_path: string;
  log_level: string;
  api_login_url: string;
  api_sync_url: string;
  api_create_user_fingerprint_url: string;
  api_latest_release_url: string;
  api_tv_snapshot_latest_url: string;
  api_tv_snapshot_manifest_url: string;
  update_enabled: boolean;
  update_check_interval_sec: number;
  update_auto_download_zip: boolean;
  tray_enabled: boolean;
  minimize_to_tray_on_close: boolean;
  start_minimized_to_tray: boolean;
  login_email: string;
  [key: string]: unknown;
}

// ─── D) Sync cache DTOs ───
export interface DoorPresetDto {
  id: number;
  deviceId: number;
  doorNumber: number;
  pulseSeconds: number;
  doorName: string;
}

export interface DeviceDto {
  id: number;
  name: string;
  description: string;
  accessDataMode: string;
  ipAddress: string;
  portNumber: string;
  password: string;
  platform: string;
  active: boolean;
  accessDevice: boolean;
  doorIds: number[];
  doorPresets: DoorPresetDto[];
  timeoutMs: number;
  totpEnabled: boolean;
  rfidEnabled: boolean;
  showNotifications: boolean;
  [key: string]: unknown;
}

export interface FingerprintDto {
  fingerId: number;
  templateVersion: number;
  templateEncoding: string;
  templateData: string;
  templateSize: number;
  enabled: boolean;
  label: string;
}

export interface UserDto {
  userId: number;
  activeMembershipId: number | null;
  membershipId: number | null;
  fullName: string;
  phone: string;
  email: string;
  validFrom: string;
  validTo: string;
  firstCardId: string | null;
  secondCardId: string | null;
  image: string | null;
  fingerprints: FingerprintDto[];
  accountUsernameId?: string | null;
  offlinePending?: boolean;
  offlinePendingLocalId?: string;
  offlinePendingState?: string;
  offlinePendingKind?: string;
  offlineModeNote?: string;
}

export type OfflineCreationKind = "membership_only" | "account_plus_membership";
export type OfflineFailureType = "network" | "server" | "auth" | "validation" | "conflict" | "unknown";
export type OfflineCreationState =
  | "pending"
  | "processing"
  | "failed_retryable"
  | "blocked_auth"
  | "succeeded"
  | "reconciled"
  | "cancelled"
  | "failed_terminal"
  | "archived";

export interface OfflineCreationRow {
  local_id: string;
  client_request_id: string;
  creation_kind: OfflineCreationKind;
  payload: Record<string, any>;
  payload_hash?: string | null;
  state: OfflineCreationState;
  created: boolean;
  try_to_create: boolean;
  attempt_count: number;
  failure_count: number;
  failure_type?: OfflineFailureType | null;
  failure_code?: string | null;
  last_http_status?: number | null;
  last_error_message?: string | null;
  failed_reason?: string | null;
  last_attempt_at?: string | null;
  next_retry_at?: string | null;
  processing_started_at?: string | null;
  processing_lock_token?: string | null;
  processing_lock_expires_at?: string | null;
  succeeded_at?: string | null;
  reconciled_at?: string | null;
  cancelled_at?: string | null;
  archived_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface OfflineAttemptResponse {
  ok: boolean;
  creationKind?: OfflineCreationKind;
  clientRequestId?: string;
  created?: boolean;
  alreadyExists?: boolean;
  state?: OfflineCreationState;
  result?: Record<string, any>;
  failureType?: OfflineFailureType;
  failureCode?: string;
  lastHttpStatus?: number | null;
  error?: string;
  recommendation?: "modify" | "save_later";
  countable?: boolean;
}

export interface OfflineQueueListResponse {
  ok: boolean;
  rows: OfflineCreationRow[];
  total: number;
  states: OfflineCreationState[];
}

// ─── E) Local fingerprints (GET /api/v2/fingerprints) ───
export interface LocalFingerprintDto {
  id: number;
  createdAt: string;
  label: string;
  pin: string;
  cardNo: string;
  fingerId: number;
  templateVersion: number;
  templateEncoding: string;
  templateSize: number;
}

// ─── F) Agent (GET /api/v2/agent/status, /agent/devices) ───
export interface AgentStatusResponse {
  running: boolean;
  eventQueueDepth: number;
  avgDecisionMs: number;
  notificationServiceAlive?: boolean;
  historyServiceAlive?: boolean;
  decisionWorkersActive?: number;
  decisionWorkersTotal?: number;
}

export interface AgentDeviceSnap {
  [deviceId: string]: {
    name?: string;
    enabled?: boolean;
    connected?: boolean;
    polls?: number;
    events?: number;
    lastError?: string;
  };
}

// ─── G) Updates (GET /api/v2/update/status) ───
export interface UpdateStatusResponse {
  updateAvailable: boolean;
  downloaded: boolean;
  downloading: boolean;
  progressPercent: number | null;
  currentReleaseId: string | null;
  lastCheckAt: number | null;
  lastError: string | null;
  latestRelease?: {
    releaseId?: string;
    publishDate?: string;
    channel?: string;
    platform?: string;
    version?: string;
    notes?: string;
  } | null;
}

// ─── H) Logs ───
export interface LogLine { level: string; text: string }

// ─── I) Enroll ───
export interface EnrollStatusResponse {
  running: boolean;
  step: string;
  logs: string[];
  result: string | null;
}

// ─── J) DB ───
export interface DbTableInfo { name: string; rowCount: number }
export interface AccessHistoryRecord {
  eventId: string;
  deviceId: number | null;
  doorId: number | null;
  cardNo: string;
  eventTime: string;
  eventType: string;
  allowed: number;
  reason: string;
  createdAt: string;
}

// ─── K) Popup / Notification events (SSE) ───
export interface PopupEvent {
  eventId: string;
  title: string;
  message: string;
  imagePath: string;
  popupShowImage: boolean;
  userFullName: string;
  userImage: string;
  userValidFrom: string;
  userValidTo: string;
  userMembershipId: number | null;
  userPhone: string;
  deviceId: number;
  deviceName: string;
  allowed: boolean;
  reason: string;
  scanMode: string;
  popupDurationSec: number;
  popupEnabled?: boolean;
  winNotifyEnabled?: boolean;
  /** Timestamp when the event was received client-side */
  receivedAt?: number;
}


// --- L) TV local sync/cache/readiness ---
export type TvAssetState =
  | "NOT_PRESENT"
  | "PRESENT_UNCHECKED"
  | "VALID"
  | "INVALID_SIZE"
  | "INVALID_CHECKSUM"
  | "INVALID_UNREADABLE"
  | "STALE"
  | "ERROR";

export type TvReadinessState = "READY" | "PARTIALLY_READY" | "NOT_READY" | "EMPTY" | "ERROR";
export type TvValidationMode = "STRONG" | "WEAK";
export type TvDownloadJobState =
  | "QUEUED"
  | "DOWNLOADING"
  | "VALIDATING"
  | "SUCCEEDED"
  | "FAILED"
  | "CANCELLED"
  | "SKIPPED_ALREADY_VALID"
  | "RETRY_WAIT";
export type TvDownloadFailureReason =
  | "MISSING_DOWNLOAD_LINK"
  | "INVALID_URL"
  | "HTTP_ERROR"
  | "TIMEOUT"
  | "NETWORK_ERROR"
  | "WRITE_ERROR"
  | "TEMPFILE_ERROR"
  | "ATOMIC_RENAME_FAILED"
  | "SIZE_MISMATCH"
  | "CHECKSUM_MISMATCH"
  | "UNREADABLE_FILE"
  | "UNKNOWN_ERROR";

export interface TvScreenBinding {
  screenId: number | null;
  screenName: string | null;
  updatedAt: string;
}

export type TvHostBindingDesiredState = "RUNNING" | "STOPPED";
export type TvHostBindingRuntimeState = "STOPPED" | "STARTING" | "RUNNING" | "STOPPING" | "CRASHED" | "ERROR";

export type TvPlayerState =
  | "IDLE"
  | "LOADING_BINDING"
  | "LOADING_ACTIVE_SNAPSHOT"
  | "RENDERING"
  | "FALLBACK_RENDERING"
  | "BLOCKED_NO_BINDING"
  | "BLOCKED_BINDING_DISABLED"
  | "BLOCKED_NO_ACTIVE_SNAPSHOT"
  | "BLOCKED_NO_RENDERABLE_ITEM"
  | "ERROR";

export type TvPlayerRenderMode =
  | "VISUAL_ONLY"
  | "AUDIO_ONLY"
  | "VISUAL_AND_AUDIO"
  | "IDLE_FALLBACK"
  | "ERROR_FALLBACK";

export type TvPlayerFallbackReason =
  | "NO_ACTIVE_SNAPSHOT"
  | "NO_CURRENT_ITEM"
  | "VISUAL_ASSET_INVALID"
  | "AUDIO_ASSET_INVALID"
  | "BOTH_ASSETS_INVALID"
  | "SNAPSHOT_INVALID"
  | "BINDING_DISABLED"
  | "BINDING_NOT_FOUND"
  | "INTERNAL_ERROR";

export interface TvHostMonitorRow {
  monitor_id: string;
  monitor_label?: string | null;
  monitor_index?: number | null;
  x?: number | null;
  y?: number | null;
  width?: number | null;
  height?: number | null;
  scale_factor?: number | null;
  is_primary?: number | boolean | null;
  available?: number | boolean | null;
  updated_at?: string | null;
}

export interface TvHostBindingRow {
  id: number;
  screen_id: number;
  screen_name?: string | null;
  monitor_id?: string | null;
  monitor_label?: string | null;
  monitor_index?: number | null;
  enabled: number | boolean;
  autostart: number | boolean;
  desired_state: TvHostBindingDesiredState | string;
  fullscreen: number | boolean;
  window_label?: string | null;
  window_id?: string | null;
  window_exists?: number | boolean;
  runtime_state?: TvHostBindingRuntimeState | string;
  blocked_reason?: string | null;
  launch_outcome?: string | null;
  launch_error_code?: string | null;
  launch_error_message?: string | null;
  last_started_at?: string | null;
  last_closed_at?: string | null;
  last_crashed_at?: string | null;
  latest_snapshot_version?: number | null;
  latest_ready_snapshot_version?: number | null;
  active_snapshot_version?: number | null;
  latest_readiness_state?: TvReadinessState | string | null;
  monitor_available?: number | boolean;
  player_state?: TvPlayerState | string | null;
  player_render_mode?: TvPlayerRenderMode | string | null;
  player_fallback_reason?: TvPlayerFallbackReason | string | null;
  player_visual_item_id?: string | null;
  player_audio_item_id?: string | null;
  player_last_error_code?: string | null;
  player_last_error_message?: string | null;
  player_updated_at?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface TvHostMonitorsResponse {
  ok: boolean;
  rows: TvHostMonitorRow[];
  total: number;
}

export interface TvHostBindingsResponse {
  ok: boolean;
  rows: TvHostBindingRow[];
  total: number;
}

export interface TvHostBindingResponse {
  ok: boolean;
  binding: TvHostBindingRow;
}

export interface TvHostBindingEventsResponse {
  ok: boolean;
  rows: Array<Record<string, any>>;
  total: number;
}

export interface TvPlayerTimelineItem {
  itemId?: string | null;
  timelineType?: "VISUAL" | "AUDIO" | string;
  mediaAssetId?: string | null;
  mediaType?: string | null;
  title?: string | null;
  startMinuteOfDay?: number | null;
  endMinuteOfDay?: number | null;
  videoAudioEnabled?: boolean;
  assetPath?: string | null;
  assetState?: string | null;
  assetRenderable?: boolean;
  stateReason?: string | null;
}

export interface TvPlayerRenderContext {
  ok: boolean;
  bindingId: number;
  screenId: number | null;
  bindingEnabled?: boolean;
  activeSnapshotId?: string | null;
  activeSnapshotVersion?: number | null;
  timezone?: string | null;
  currentDayOfWeek?: string | null;
  currentMinuteOfDay?: number | null;
  visualItems?: TvPlayerTimelineItem[];
  audioItems?: TvPlayerTimelineItem[];
  currentVisual?: TvPlayerTimelineItem | null;
  currentAudio?: TvPlayerTimelineItem | null;
  playerState?: TvPlayerState | string | null;
  renderMode?: TvPlayerRenderMode | string | null;
  fallbackReason?: TvPlayerFallbackReason | string | null;
  lastRenderErrorCode?: string | null;
  lastRenderErrorMessage?: string | null;
  videoMutedByAudio?: boolean;
  evaluatedAt?: string | null;
  adOverrideActive?: boolean;
  adAudioOverrideActive?: boolean;
  currentAdTaskId?: number | null;
  currentAdMediaId?: string | null;
  adLayout?: string | null;
  adAssetPath?: string | null;
  adDisplayState?: string | null;
  adDisplayStartedAt?: string | null;
  adExpectedFinishAt?: string | null;
  adValidationStrength?: TvValidationMode | string | null;
  adParticipatingBindingIds?: number[];
  adFailedBindingIds?: number[];
  adFallbackReason?: string | null;
  gymAdRuntime?: Record<string, any> | null;
  error?: string;
}

export interface TvPlayerStatusResponse {
  ok: boolean;
  error?: string;
  binding?: TvHostBindingRow | null;
  playerState?: Record<string, any> | null;
}

export interface TvPlayerRenderContextResponse extends TvPlayerRenderContext {}

export interface TvPlayerActionResponse {
  ok: boolean;
  context?: TvPlayerRenderContext;
  error?: string;
}

export interface TvPlayerStateReportResponse {
  ok: boolean;
  updated?: boolean;
  changed?: boolean;
  row?: Record<string, any>;
  error?: string;
}

export interface TvPlayerEventsResponse {
  ok: boolean;
  rows: Array<Record<string, any>>;
  total: number;
}


export type TvBindingHealthSummary = "HEALTHY" | "WARNING" | "DEGRADED" | "ERROR" | "STOPPED";

export type TvSupportActionType =
  | "RUN_SYNC"
  | "RECOMPUTE_READINESS"
  | "RETRY_FAILED_DOWNLOADS"
  | "RETRY_ONE_DOWNLOAD"
  | "REEVALUATE_ACTIVATION"
  | "ACTIVATE_LATEST_READY"
  | "REEVALUATE_PLAYER_CONTEXT"
  | "RELOAD_PLAYER"
  | "START_BINDING"
  | "STOP_BINDING"
  | "RESTART_BINDING"
  | "RESTART_PLAYER_WINDOW"
  | "RESET_TRANSIENT_PLAYER_STATE";

export type TvSupportActionResult = "STARTED" | "SUCCEEDED" | "FAILED" | "SKIPPED" | "BLOCKED";

export interface TvBindingSupportSummaryResponse {
  ok: boolean;
  error?: string;
  binding?: TvHostBindingRow;
  screenId?: number;
  latestSnapshot?: TvSnapshotCacheRow | null;
  latestReadySnapshot?: TvSnapshotCacheRow | null;
  activation?: TvActivationStatusPayload | null;
  readiness?: TvReadinessRow | null;
  playerState?: Record<string, any> | null;
  failedDownloadCount?: number;
  latestDownloadBatch?: TvDownloadBatchSummary | null;
  health?: TvBindingHealthSummary | string;
  healthReasons?: string[];
  healthIndicators?: Record<string, any>;
  supportActions?: {
    rows: Array<Record<string, any>>;
    total: number;
  };
}

export interface TvSupportActionRunResponse {
  ok: boolean;
  bindingId: number;
  screenId?: number;
  actionType: TvSupportActionType | string;
  correlationId: string;
  logId?: number;
  result: TvSupportActionResult | string;
  errorCode?: string | null;
  message?: string | null;
  data?: Record<string, any>;
  summary?: TvBindingSupportSummaryResponse;
}

export interface TvSupportActionHistoryResponse {
  ok: boolean;
  rows: Array<Record<string, any>>;
  total: number;
}
export interface TvReadinessRow {
  id?: number;
  screen_id?: number;
  screenId?: number;
  snapshot_id?: string;
  snapshotId?: string;
  snapshot_version?: number;
  snapshotVersion?: number;
  readiness_state?: TvReadinessState;
  readinessState?: TvReadinessState;
  is_fully_ready?: number | boolean;
  isFullyReady?: number | boolean;
  total_required_assets?: number;
  totalRequiredAssets?: number;
  ready_asset_count?: number;
  readyAssetCount?: number;
  missing_asset_count?: number;
  missingAssetCount?: number;
  invalid_asset_count?: number;
  invalidAssetCount?: number;
  stale_asset_count?: number;
  staleAssetCount?: number;
  computed_at?: string;
  computedAt?: string;
  warning_count?: number;
  warningCount?: number;
}

export interface TvSnapshotCacheRow {
  id?: number;
  screen_id?: number;
  screenId?: number;
  snapshot_id?: string;
  snapshotId?: string;
  snapshot_version?: number;
  snapshotVersion?: number;
  generated_at?: string;
  generatedAt?: string;
  fetched_at?: string;
  fetchedAt?: string;
  resolved_day_of_week?: string;
  resolvedDayOfWeek?: string;
  resolved_preset_id?: string;
  resolvedPresetId?: string;
  resolved_layout_preset_id?: string;
  resolvedLayoutPresetId?: string;
  resolved_policy_id?: string;
  resolvedPolicyId?: string;
  manifest_status?: string;
  manifestStatus?: string;
  sync_status?: string;
  syncStatus?: string;
  warning_count?: number;
  warningCount?: number;
  error_message?: string;
  errorMessage?: string;
  is_latest?: boolean;
  is_previous_ready?: boolean;
  is_fully_ready?: boolean;
  readiness_state?: TvReadinessState;
  total_required_assets?: number;
  ready_asset_count?: number;
  missing_asset_count?: number;
  invalid_asset_count?: number;
  stale_asset_count?: number;
  payload?: Record<string, any>;
  manifest?: Record<string, any>;
}

export interface TvSyncStatusResponse {
  ok: boolean;
  screenId: number | null;
  binding?: TvScreenBinding;
  lastRun?: Record<string, any> | null;
  latestSnapshot?: TvSnapshotCacheRow | null;
  latestReadySnapshot?: TvSnapshotCacheRow | null;
  previousReadySnapshot?: TvSnapshotCacheRow | null;
  latestReadiness?: TvReadinessRow | null;
  latestDownloadBatch?: TvDownloadBatchSummary | null;
  activation?: TvActivationStatusPayload | null;
}

export interface TvCacheAssetRow {
  media_asset_id: string;
  expected_local_path: string;
  local_file_path?: string;
  file_exists: number;
  local_size_bytes?: number;
  local_checksum_sha256?: string;
  asset_state: TvAssetState;
  state_reason?: string;
  last_checked_at: string;
  media_type?: string;
  title?: string;
  download_link?: string;
  snapshot_version?: number;
  validation_mode?: TvValidationMode | string | null;
  download_state?: TvDownloadJobState | string | null;
  download_attempt_count?: number;
  last_download_attempt_at?: string | null;
  last_download_success_at?: string | null;
  last_download_error_reason?: TvDownloadFailureReason | string | null;
  last_download_error_message?: string | null;
  last_download_http_status?: number | null;
  download_bytes_downloaded?: number | null;
  download_bytes_total?: number | null;
  download_updated_at?: string | null;
  last_download_batch_id?: string | null;
}

export interface TvCacheAssetsResponse {
  ok: boolean;
  screenId: number;
  snapshotVersion: number | null;
  rows: TvCacheAssetRow[];
  total: number;
  latestReadiness?: TvReadinessRow | null;
  latestSnapshot?: TvSnapshotCacheRow | null;
}


export interface TvDownloadBatchSummary {
  batchId: string;
  screenId: number;
  snapshotId?: string;
  snapshotVersion?: number;
  counts: Record<string, number>;
  totalJobs: number;
  latestReadiness?: TvReadinessRow | null;
  latestSnapshot?: TvSnapshotCacheRow | null;
  previousReadySnapshot?: TvSnapshotCacheRow | null;
  queued?: number;
  skipped?: number;
  concurrency?: number;
  background?: boolean;
  status?: string;
}

export interface TvDownloadJobRow {
  id: number;
  batch_id: string;
  screen_id: number;
  snapshot_id: string;
  snapshot_version: number;
  media_asset_id: string;
  expected_local_path: string;
  download_link?: string | null;
  state: TvDownloadJobState | string;
  failure_reason?: TvDownloadFailureReason | string | null;
  failure_message?: string | null;
  retriable?: number | boolean;
  http_status?: number | null;
  attempt_no?: number;
  max_attempts?: number;
  bytes_downloaded?: number | null;
  bytes_total?: number | null;
  trigger_source?: string;
  queued_at?: string;
  started_at?: string | null;
  finished_at?: string | null;
  next_retry_at?: string | null;
  updated_at?: string;
}
export type TvAdTaskRemoteStatus =
  | "PREPARATION_PHASE"
  | "READY_TO_DISPLAY"
  | "DISPLAYING"
  | "DONE"
  | "FAILED"
  | "CANCELLED"
  | "EXPIRED";

export type TvAdTaskLocalPreparationState =
  | "DISCOVERED"
  | "DOWNLOADING"
  | "READY_LOCAL"
  | "READY_CONFIRM_PENDING"
  | "READY_CONFIRMED"
  | "FAILED"
  | "CANCELLED"
  | "EXPIRED";

export type TvAdTaskDisplayState =
  | "READY_TO_DISPLAY_LOCAL"
  | "DISPLAYING"
  | "DISPLAY_COMPLETED_LOCAL"
  | "DISPLAY_ABORTED_LOCAL"
  | "SKIPPED_WINDOW_MISSED"
  | "CANCELLED_REMOTE"
  | "EXPIRED_REMOTE";

export type TvAdTaskOutboxState =
  | "NOT_QUEUED"
  | "QUEUED"
  | "SENDING"
  | "SENT"
  | "FAILED_RETRYABLE"
  | "FAILED_TERMINAL";

export interface TvAdTaskOutboxRow {
  state?: TvAdTaskOutboxState | string;
  attempt_count?: number;
  last_http_status?: number | null;
  last_error_code?: string | null;
  last_error_message?: string | null;
  next_attempt_at?: string | null;
  sent_at?: string | null;
  updated_at?: string | null;
}

export interface TvAdTaskRow {
  id?: number;
  campaign_task_id: number;
  campaign_id: number;
  gym_id: number;
  ad_media_id: string;
  ad_download_link_snapshot?: string | null;
  ad_checksum_sha256?: string | null;
  ad_size_bytes?: number | null;
  ad_mime_type?: string | null;
  scheduled_at: string;
  layout?: string | null;
  display_duration_sec?: number | null;
  remote_status: TvAdTaskRemoteStatus | string;
  remote_updated_at?: string | null;
  expected_local_path?: string | null;
  local_asset_state?: TvAssetState | string | null;
  validation_strength?: TvValidationMode | string | null;
  local_preparation_state?: TvAdTaskLocalPreparationState | string | null;
  ready_confirm_outbox_state?: TvAdTaskOutboxState | string | null;
  ready_confirmed_at?: string | null;
  last_fetched_at?: string;
  last_prepare_attempt_at?: string | null;
  last_prepare_success_at?: string | null;
  last_error_code?: string | null;
  last_error_message?: string | null;
  last_ready_confirm_attempt_at?: string | null;
  correlation_id?: string | null;
  generation_batch_no?: number | null;
  created_at?: string;
  updated_at?: string;
  outbox?: TvAdTaskOutboxRow | null;
  local_display_state?: TvAdTaskDisplayState | string | null;
  display_started_at?: string | null;
  display_finished_at?: string | null;
  display_aborted_at?: string | null;
  display_abort_reason?: string | null;
  currently_injected?: boolean | number;
  participating_binding_ids?: number[];
  failed_binding_ids?: number[];
  gym_coordination_state?: string | null;
  gym_current_task_id?: number | null;
}

export interface TvAdTaskListResponse {
  ok: boolean;
  rows: TvAdTaskRow[];
  total: number;
  limit: number;
  offset: number;
}



export interface TvAdTaskRuntimeListResponse {
  ok: boolean;
  rows: Array<Record<string, any>>;
  total: number;
  limit: number;
  offset: number;
}

export interface TvAdTaskRuntimeOneResponse {
  ok: boolean;
  runtime?: Record<string, any>;
  error?: string;
}

export interface TvGymAdRuntimeResponse {
  ok: boolean;
  runtime?: Record<string, any>;
  error?: string;
}

export interface TvAdTaskInjectNowResponse {
  ok: boolean;
  result?: string;
  campaignTaskId?: number;
  gymId?: number;
  runtime?: Record<string, any>;
  gymRuntime?: Record<string, any>;
  error?: string;
  reason?: string;
}

export type TvActivationState =
  | "NO_ACTIVE_SNAPSHOT"
  | "ACTIVE_CURRENT"
  | "ACTIVE_OLDER_THAN_LATEST"
  | "BLOCKED_WAITING_FOR_READY"
  | "BLOCKED_PREREQUISITE"
  | "ERROR";

export type TvActivationResult =
  | "ACTIVATED"
  | "SKIPPED_ALREADY_ACTIVE"
  | "SKIPPED_NO_SNAPSHOT"
  | "SKIPPED_NOT_READY"
  | "SKIPPED_LATEST_NOT_NEWER"
  | "SKIPPED_SINGLE_FLIGHT_BUSY"
  | "FAILED";

export interface TvActivationStateRow {
  screen_id?: number;
  latest_snapshot_id?: string | null;
  latest_snapshot_version?: number | null;
  latest_ready_snapshot_id?: string | null;
  latest_ready_snapshot_version?: number | null;
  active_snapshot_id?: string | null;
  active_snapshot_version?: number | null;
  previous_active_snapshot_id?: string | null;
  previous_active_snapshot_version?: number | null;
  blocked_reason?: string | null;
  activation_state?: TvActivationState | string;
  last_decision_at?: string | null;
  last_activation_at?: string | null;
  last_attempt_id?: number | null;
  updated_at?: string | null;
}

export interface TvActivationStatusPayload {
  screenId: number;
  state: TvActivationStateRow;
  latestSnapshot?: TvSnapshotCacheRow | null;
  latestReadySnapshot?: TvSnapshotCacheRow | null;
  activeSnapshot?: TvSnapshotCacheRow | null;
  previousActiveSnapshot?: TvSnapshotCacheRow | null;
}

export interface TvActivationAttemptRow {
  id: number;
  screen_id: number;
  trigger_source: string;
  target_snapshot_id?: string | null;
  target_snapshot_version?: number | null;
  result: TvActivationResult | string;
  failure_reason?: string | null;
  failure_message?: string | null;
  precheck_readiness_state?: string | null;
  precheck_manifest_status?: string | null;
  active_snapshot_id_before?: string | null;
  active_snapshot_version_before?: number | null;
  started_at: string;
  finished_at: string;
}


// --- M) TV Observability ---
export type TvObservabilityHealth =
  | "UNKNOWN"
  | "OFFLINE"
  | "ERROR"
  | "DEGRADED"
  | "WARNING"
  | "HEALTHY";

export interface TvObservabilityFleetRow {
  screenId: number;
  bindingId?: number;
  screenName?: string | null;
  monitorId?: string | null;
  monitorLabel?: string | null;
  enabled?: boolean;
  desiredState?: string | null;
  runtimeState?: string | null;
  playerState?: string | null;
  playerRenderMode?: string | null;
  playerFallbackReason?: string | null;
  readinessState?: TvReadinessState | string | null;
  activationState?: TvActivationState | string | null;
  latestSnapshotVersion?: number | null;
  latestReadySnapshotVersion?: number | null;
  activeSnapshotVersion?: number | null;
  latestHeartbeatAtUtc?: string | null;
  heartbeatAgeSec?: number | null;
  latestProofAtUtc?: string | null;
  proofAgeSec?: number | null;
  proofExpected?: boolean;
  runtimeErrors15m?: number;
  runtimeWarnings15m?: number;
  failedDownloadCount?: number;
  health: TvObservabilityHealth | string;
  healthReasons: string[];
  monitorAvailable?: boolean;
  lastUpdatedAt?: string | null;
}

export interface TvObservabilityPaged<T> {
  rows: T[];
  total: number;
}

export interface TvObservabilityOverviewResponse {
  ok: boolean;
  totalScreens: number;
  onlineScreens: number;
  healthCounts: Record<string, number>;
  fleet: TvObservabilityPaged<TvObservabilityFleetRow>;
  recentRuntimeIncidents: TvObservabilityPaged<Record<string, any>>;
  recentProofEvents: TvObservabilityPaged<Record<string, any>>;
  recentSupportActions: TvObservabilityPaged<Record<string, any>>;
}

export interface TvObservabilityFleetHealthResponse {
  ok: boolean;
  rows: TvObservabilityFleetRow[];
  total: number;
}

export interface TvObservabilityScreenDetailsResponse {
  ok: boolean;
  error?: string;
  screen?: TvObservabilityFleetRow;
  heartbeats?: TvObservabilityPaged<Record<string, any>>;
  runtimeEvents?: TvObservabilityPaged<Record<string, any>>;
  proofEvents?: TvObservabilityPaged<Record<string, any>>;
  supportActions?: TvObservabilityPaged<Record<string, any>>;
  activationAttempts?: TvObservabilityPaged<TvActivationAttemptRow>;
}

export interface TvObservabilityTimelineItem {
  source: "HEARTBEAT" | "RUNTIME_EVENT" | "PROOF_EVENT" | "SUPPORT_ACTION" | "ACTIVATION_ATTEMPT" | string;
  timestampUtc?: string | null;
  severity?: string | null;
  title?: string | null;
  message?: string | null;
  correlationId?: string | null;
  row?: Record<string, any>;
}

export interface TvObservabilityTimelineResponse {
  ok: boolean;
  rows: TvObservabilityTimelineItem[];
  total: number;
}

export interface TvObservabilityHeartbeatsResponse {
  ok: boolean;
  rows: Record<string, any>[];
  total: number;
}

export interface TvObservabilityRuntimeEventsResponse {
  ok: boolean;
  rows: Record<string, any>[];
  total: number;
}

export interface TvObservabilityProofEventsResponse {
  ok: boolean;
  rows: Record<string, any>[];
  total: number;
}

export interface TvObservabilityProofStatsResponse {
  ok: boolean;
  totalProofEvents: number;
  statusCounts: Record<string, number>;
  timelineCounts: Record<string, number>;
  series: Array<{ bucket: string; count: number }>;
  topScreens: Array<{ screenId: number; count: number }>;
  topAssets: Array<{ mediaAssetId: string; count: number }>;
}

export interface TvObservabilityRuntimeStatsResponse {
  ok: boolean;
  totalRuntimeEvents: number;
  severityCounts: Record<string, number>;
  eventTypeCounts: Record<string, number>;
  errorCodeCounts: Record<string, number>;
}

// --- N) TV Hardening ---
export interface TvStartupReconciliationRunRow {
  id: number;
  correlation_id?: string | null;
  trigger_source?: string | null;
  status?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  summary?: Record<string, any>;
}

export interface TvStartupReconciliationPhaseRow {
  id: number;
  run_id: number;
  phase_name: string;
  status?: string | null;
  message?: string | null;
  metadata?: Record<string, any>;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface TvHardeningStartupLatestResponse {
  ok: boolean;
  error?: string;
  run?: TvStartupReconciliationRunRow;
  phases?: TvStartupReconciliationPhaseRow[];
}

export interface TvHardeningStartupRunsResponse {
  ok: boolean;
  rows: TvStartupReconciliationRunRow[];
  total: number;
}

export interface TvHardeningQueryChecksResponse {
  ok: boolean;
  limit: number;
  checksMs: Record<string, number>;
}

export interface TvHardeningRetentionPolicyResponse {
  ok: boolean;
  retentionDays: Record<string, number>;
}

export interface TvHardeningRetentionRunResponse {
  ok: boolean;
  dryRun: boolean;
  retentionDays: Record<string, number>;
  scannedRows: Record<string, number>;
  deletedRows: Record<string, number>;
  ranAt: string;
  queryChecks?: {
    limit: number;
    checksMs: Record<string, number>;
  };
}

export interface TvHardeningCorrelationAuditResponse {
  ok: boolean;
  error?: string;
  correlationId?: string;
  counts?: Record<string, number>;
  present?: string[];
  missing?: string[];
  isCompleteCorePath?: boolean;
}

export interface TvHardeningPreflightIssue {
  code: string;
  severity: string;
  message: string;
  details?: Record<string, any>;
}

export interface TvHardeningPreflightResponse {
  ok: boolean;
  status: "PASS" | "WARN" | "FAIL" | string;
  generatedAt: string;
  blockers: TvHardeningPreflightIssue[];
  warnings: TvHardeningPreflightIssue[];
  infos: TvHardeningPreflightIssue[];
  checks: Record<string, any>;
}


