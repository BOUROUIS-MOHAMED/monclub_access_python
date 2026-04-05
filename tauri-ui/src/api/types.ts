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
  DEVICE: number;
  AGENT: number;
  UNKNOWN: number;
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
  progressPercent?: number | null;
  currentVersion?: string | null;
  currentCodename?: string | null;
  currentReleaseId: string | null;
  latestVersion?: string | null;
  latestCodename?: string | null;
  releaseDate?: string | null;
  availableUntil?: string | null;
  sizeBytes?: number | null;
  releaseNotes?: string | null;
  lastCheckAt: number | null;
  lastError: string | null;
  componentId?: string | null;
  componentDisplayName?: string | null;
  artifactName?: string | null;
  mainExecutable?: string | null;
  updaterExecutable?: string | null;
  updaterInstalled?: boolean;
  installRoot?: string | null;
  updateEnabled?: boolean;
  channel?: string | null;
  platform?: string | null;
}

export interface StatusResponse extends ApiOk {
  session: SessionBlock;
  mode: ModeBlock;
  sync: SyncBlock;
  deviceSync: {
    lastRunAt: string | null;
    lastOk: boolean;
    lastError: string | null;
    progress: {
      running: boolean;
      deviceName: string;
      deviceId: number | null;
      current: number;
      total: number;
    } | null;
  };
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
  update_enabled: boolean;
  update_check_interval_sec: number;
  update_auto_download_zip: boolean;
  tray_enabled: boolean;
  minimize_to_tray_on_close: boolean;
  start_minimized_to_tray: boolean;
  start_on_system_startup: boolean;
  login_email: string;
  autostart_bindings_enabled?: boolean;
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

  // Current version info (new semver system)
  currentVersion: string | null;       // "1.0.0"
  currentCodename: string | null;      // "Panda"
  currentReleaseId: string | null;     // legacy "20260321-020139Z"

  // Latest available version info
  latestVersion: string | null;        // "1.2.0"
  latestCodename: string | null;       // "KitKat"
  releaseDate: string | null;          // ISO date string
  availableUntil: string | null;       // ISO date string
  sizeBytes: number | null;
  releaseNotes: string | null;         // HTML string
  downloadUrl: string | null;
  minCompatibleVersion: string | null;

  lastCheckAt: number | null;
  lastError: string | null;
  componentId?: string | null;
  componentDisplayName?: string | null;
  artifactName?: string | null;
  mainExecutable?: string | null;
  updaterExecutable?: string | null;
  updaterInstalled?: boolean;
  installRoot?: string | null;
  updateEnabled?: boolean;
  channel?: string | null;
  platform?: string | null;

  // Legacy block (backward compat)
  latestRelease?: {
    releaseId?: string;
    publishDate?: string;
    channel?: string;
    platform?: string;
    version?: string;
    codename?: string;
    notes?: string;
    availableUntil?: string;
    minCompatibleVersion?: string;
  } | null;
}

export interface UpdateVersionInfoResponse {
  ok: boolean;
  currentVersion: string;
  currentCodename: string;
  currentReleaseId: string;
  componentId?: string | null;
  componentDisplayName?: string | null;
}

// ─── H) Logs ───
export interface LogLine {
  level: string;
  text: string;
  id?: string | number | null;
  revision?: number | null;
  rawText?: string | null;
  repeatCount?: number | null;
  collapsed?: boolean;
  ts?: string | null;
  firstSeenAt?: string | null;
  lastSeenAt?: string | null;
  tokens?: Record<string, string> | null;
}

// ─── I) Enroll ───
export interface EnrollStatusResponse {
  running: boolean;
  step: string;
  logs: string[];
  result: string | null;
}

// ─── J) DB ───
export interface DbTableInfo {
  name: string;
  rowCount: number;
  owned?: boolean;
}

export interface DbTablesResponse {
  ok: boolean;
  dbPath?: string;
  dbSizeBytes?: number;
  tables: DbTableInfo[];
}

export interface DbTableQueryResponse {
  ok: boolean;
  tableName?: string;
  columns: string[];
  rows: Record<string, unknown>[];
  total: number;
  limit?: number;
  offset?: number;
}

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

export interface TvSnapshotCacheRow {
  id: number;
  screen_id: number;
  snapshot_id: string;
  snapshot_version: number;
  activation_state: string | null;
  resolved_at: string | null;
  resolved_day_of_week: string | null;
  resolved_preset_id: number | null;
  resolved_layout_preset_id: number | null;
  resolved_policy_id: number | null;
  playback_policy_version: number | null;
  playback_policy_hash: string | null;
  generated_at: string | null;
  fetched_at: string | null;
  payload_json: string | null;
  manifest_json: string | null;
  asset_count: number;
  warning_count: number;
  manifest_status: string | null;
  sync_status: string | null;
  last_error: string | null;
  is_latest: number;
  is_previous_ready: number;
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
}

export interface TvSnapshotCacheResponse {
  ok: boolean;
  rows: TvSnapshotCacheRow[];
  total: number;
}

export interface TvLatestSnapshotsResponse {
  ok: boolean;
  snapshot?: TvSnapshotCacheRow | null;
  snapshots?: TvSnapshotCacheRow[];
}

export interface TvSnapshotRequiredAssetRow {
  id: number;
  snapshot_id: string;
  media_asset_id: string;
  title: string | null;
  media_type: string | null;
  download_link: string | null;
  checksum_sha256: string | null;
  size_bytes: number | null;
  mime_type: string | null;
  duration_in_seconds: number | null;
  required_in_timelines_json: string | null;
  source_preset_item_ids_json: string | null;
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
}

export interface TvSnapshotAssetsResponse {
  ok: boolean;
  assets: TvSnapshotRequiredAssetRow[];
  total: number;
}

// ─── J2) Dashboard TV read-only proxy ───

export type TvDashboardScreenOrientation = "LANDSCAPE" | "PORTRAIT";

export type TvDashboardDayOfWeek =
  | "MONDAY"
  | "TUESDAY"
  | "WEDNESDAY"
  | "THURSDAY"
  | "FRIDAY"
  | "SATURDAY"
  | "SUNDAY";

export interface TvDashboardScreen {
  id: number;
  gymId: number;
  name: string;
  description?: string | null;
  orientation: TvDashboardScreenOrientation;
  resolutionWidth: number;
  resolutionHeight: number;
  layoutPresetId?: number | null;
  playbackPolicyId?: number | null;
  enabled: boolean;
  timezone: string;
  lastHeartbeatAt?: string | null;
  lastSyncAt?: string | null;
  activeSnapshotVersion?: string | null;
  archivedAt?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  readyForProgramming: boolean;
  readinessNote: string;
  usesDefaultPolicy: boolean;
  policyNote: string;
  supportOverride: boolean;
}

export interface TvDashboardScreenPageResponse extends ApiOk {
  items: TvDashboardScreen[];
  page: number;
  size: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
}

export interface TvDashboardScreenResponse extends ApiOk, TvDashboardScreen {}

export type TvDashboardScreenContentPlanDayAssignments = Record<TvDashboardDayOfWeek, number | null>;

export interface TvDashboardScreenContentPlan extends ApiOk {
  id?: number | null;
  screenId: number;
  gymId: number;
  defaultPresetId?: number | null;
  enabled: boolean;
  dayAssignments: TvDashboardScreenContentPlanDayAssignments;
  createdAt?: string | null;
  updatedAt?: string | null;
  supportOverride: boolean;
}

export interface TvDashboardMediaAsset {
  id: number;
  title: string;
  mediaType?: string | null;
  durationInSeconds?: number | null;
  hasSound?: boolean | null;
  mimeType?: string | null;
  sizeBytes?: number | null;
  checksumSha256?: string | null;
}

export interface TvDashboardTimelineItem {
  presetItemId?: number | null;
  timelineType: "VISUAL" | "AUDIO" | string;
  startMinuteOfDay: number;
  endMinuteOfDay: number;
  startTime?: string | null;
  endTime?: string | null;
  mediaAsset?: TvDashboardMediaAsset | null;
  videoAudioEnabled?: boolean | null;
  audioOverriddenByTimeline?: boolean | null;
  [key: string]: unknown;
}

export interface TvDashboardSnapshotPayload {
  timelines?: Partial<Record<"VISUAL" | "AUDIO", TvDashboardTimelineItem[]>>;
  [key: string]: unknown;
}

export interface TvDashboardSnapshotManifestItem {
  mediaAssetId: number;
  title: string;
  mediaType: "VIDEO" | "AUDIO" | "IMAGE";
  downloadLink?: string | null;
  checksumSha256?: string | null;
  sizeBytes?: number | null;
  mimeType?: string | null;
  durationInSeconds?: number | null;
  requiredInTimelines: Array<"VISUAL" | "AUDIO">;
  sourcePresetItemIds: number[];
}

export interface TvDashboardSnapshotAssetManifest {
  snapshotId: number;
  screenId: number;
  snapshotVersion: number;
  generatedAt: string;
  assetCount: number;
  items: TvDashboardSnapshotManifestItem[];
}

export interface TvDashboardResolvedSnapshot {
  id: number;
  screenId: number;
  version: number;
  activationState: "GENERATED" | "ACTIVE" | "SUPERSEDED" | string;
  resolvedAt: string;
  resolvedDayOfWeek: TvDashboardDayOfWeek | string;
  resolvedPresetId?: number | null;
  resolvedLayoutPresetId: number;
  resolvedPolicyId: number;
  playbackPolicyVersion: number;
  playbackPolicyHash: string;
  assetCount: number;
  warningCount: number;
  generatedAt: string;
  createdAt?: string | null;
  updatedAt?: string | null;
  payload?: TvDashboardSnapshotPayload | null;
  assetManifest?: TvDashboardSnapshotAssetManifest | null;
}

export interface TvDashboardResolvedSnapshotResponse extends ApiOk, TvDashboardResolvedSnapshot {}

export interface TvDashboardSnapshotPageResponse extends ApiOk {
  items: TvDashboardResolvedSnapshot[];
  page: number;
  size: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
}

export interface TvDashboardSnapshotAssetManifestResponse
  extends ApiOk,
    TvDashboardSnapshotAssetManifest {}

export interface TvLocalAssetStateRow {
  id: number;
  media_asset_id: string;
  expected_local_path: string | null;
  local_file_path: string | null;
  file_exists: number;
  local_size_bytes: number | null;
  local_checksum_sha256: string | null;
  asset_state: string;
  state_reason: string | null;
  validation_mode: string | null;
  last_checked_at: string | null;
  last_seen_in_snapshot_version: number | null;
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
}

export interface TvLocalAssetsResponse {
  ok: boolean;
  rows: TvLocalAssetStateRow[];
  total: number;
  limit: number;
  offset: number;
}

export interface TvSnapshotReadinessRow {
  id: number;
  screen_id: number;
  snapshot_id: string;
  snapshot_version: number;
  readiness_state: string;
  total_required_assets: number;
  ready_asset_count: number;
  missing_asset_count: number;
  invalid_asset_count: number;
  stale_asset_count: number;
  computed_at: string | null;
  is_fully_ready: number;
  is_latest: number;
  is_previous_ready: number;
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
}

export interface TvSnapshotReadinessResponse {
  ok: boolean;
  rows: TvSnapshotReadinessRow[];
  total: number;
}

export interface TvLatestReadinessResponse {
  ok: boolean;
  readiness: TvSnapshotReadinessRow;
}

// ─── L) TV Player (A6) ───

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

export type TvRenderMode =
  | "VISUAL_ONLY"
  | "AUDIO_ONLY"
  | "VISUAL_AND_AUDIO"
  | "IDLE_FALLBACK"
  | "ERROR_FALLBACK";

export type TvFallbackReason =
  | "NO_ACTIVE_SNAPSHOT"
  | "NO_CURRENT_ITEM"
  | "VISUAL_ASSET_INVALID"
  | "AUDIO_ASSET_INVALID"
  | "BOTH_ASSETS_INVALID"
  | "SNAPSHOT_INVALID"
  | "BINDING_DISABLED"
  | "BINDING_NOT_FOUND"
  | "INTERNAL_ERROR"
  | null;

export interface TvTimelineItemPresented {
  itemId: string;
  timelineType: "VISUAL" | "AUDIO";
  mediaAssetId: string;
  mediaType: string;
  title: string;
  startMinuteOfDay: number;
  endMinuteOfDay: number;
  videoAudioEnabled: boolean;
  assetPath: string | null;
  assetState: string | null;
  assetRenderable: boolean;
  stateReason: string | null;
}

export interface TvPlayerRenderContext {
  ok: boolean;
  bindingId: number;
  screenId: number | null;
  layoutPresetId?: number;
  bindingEnabled: boolean;
  activeSnapshotId: string | null;
  activeSnapshotVersion: number | null;
  timezone: string;
  currentDayOfWeek: string | null;
  currentMinuteOfDay: number | null;
  visualItems: TvTimelineItemPresented[];
  audioItems: TvTimelineItemPresented[];
  currentVisual: TvTimelineItemPresented | null;
  currentAudio: TvTimelineItemPresented | null;
  playerState: TvPlayerState;
  renderMode: TvRenderMode;
  fallbackReason: TvFallbackReason;
  lastRenderErrorCode: string | null;
  lastRenderErrorMessage: string | null;
  videoMutedByAudio: boolean;
  evaluatedAt: string;
  // A7 ad overlay fields
  adOverrideActive?: boolean;
  currentAdTaskId?: string | null;
  currentAdMediaId?: string | null;
  currentAdLayout?: string | null;
  adAssetPath?: string | null;
  adMimeType?: string | null;
  adAudioOverrideActive?: boolean;
  adDisplayDurationSec?: number | null;
  error?: string;
}

export interface TvScreenMessage {
  id: number;
  bindingId: number;
  title: string;
  description: string | null;
  hasImage: boolean;
  displayDurationSec: number;
  createdAt: string;
}

export interface TvScreenMessagesResponse {
  ok: boolean;
  rows: TvScreenMessage[];
  total: number;
}

export interface TvPlayerStateRow {
  binding_id: number;
  screen_id: number | null;
  active_snapshot_id: string | null;
  active_snapshot_version: number | null;
  current_minute_of_day: number | null;
  current_day_of_week: string | null;
  current_visual_item_id: string | null;
  current_audio_item_id: string | null;
  current_visual_asset_id: string | null;
  current_audio_asset_id: string | null;
  current_visual_asset_path: string | null;
  current_audio_asset_path: string | null;
  player_state: TvPlayerState;
  render_mode: TvRenderMode | null;
  fallback_reason: TvFallbackReason;
  video_muted_by_audio: number;
  last_render_error_code: string | null;
  last_render_error_message: string | null;
  last_tick_at: string | null;
  last_snapshot_check_at: string | null;
  last_state_change_at: string | null;
  updated_at: string;
}

export interface TvPlayerStatusResponse {
  ok: boolean;
  binding: Record<string, unknown> | null;
  playerState: TvPlayerStateRow | null;
  error?: string;
}

export interface TvPlayerEvent {
  id: number;
  binding_id: number;
  event_type: string;
  severity: string;
  message: string | null;
  metadata_json: string | null;
  created_at: string;
}

export interface TvPlayerEventsResponse {
  ok: boolean;
  rows: TvPlayerEvent[];
  total: number;
}

// ─── M) Ad Runtime (A7) ───

export interface TvAdTaskCache {
  campaign_task_id: string;
  campaign_id: string | null;
  gym_id: number;
  ad_media_id: string | null;
  ad_download_link: string | null;
  ad_checksum_sha256: string | null;
  ad_size_bytes: number | null;
  ad_mime_type: string | null;
  scheduled_at: string | null;
  layout: string;
  display_duration_sec: number;
  remote_status: string | null;
  generation_batch_no: number | null;
  remote_updated_at: string | null;
  local_file_path: string | null;
  local_file_state: string;
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
}

export interface TvAdTaskRuntime {
  campaign_task_id: string;
  gym_id: number;
  binding_scope_count: number;
  local_display_state: string;
  due_at: string | null;
  display_started_at: string | null;
  display_finished_at: string | null;
  display_aborted_at: string | null;
  display_abort_reason: string | null;
  display_abort_message: string | null;
  injected_layout: string | null;
  active_binding_ids_json: string | null;
  failed_binding_ids_json: string | null;
  correlation_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface TvGymAdRuntime {
  gym_id: number;
  coordination_state: string;
  current_campaign_task_id: string | null;
  started_at: string | null;
  expected_finish_at: string | null;
  active_binding_count: number;
  failed_binding_count: number;
  audio_override_active: number;
  last_error_code: string | null;
  last_error_message: string | null;
  updated_at: string;
}

export interface TvAdEvaluateResponse {
  ok: boolean;
  reconciled: number;
  injected: number;
  completed: number;
  skipped: number;
  errors: number;
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
  /** ISO date string (YYYY-MM-DD) of the member's birthday, if available */
  userBirthday?: string;
  /** "PROFILE_BORROWED" | "GYM_UPLOAD" | "GYM_CAPTURE" | "GYM_GALLERY" | undefined */
  imageSource?: string;
  /** "REQUIRED_CHANGE" | "OK" | undefined */
  userImageStatus?: string;
}

// ─── N) Host Monitor & Binding (A9) ───

export interface TvHostMonitor {
  id: number;
  monitor_id: string;
  monitor_label: string;
  monitor_index: number;
  is_connected: boolean;
  width: number;
  height: number;
  offset_x: number;
  offset_y: number;
  scale_factor: number;
  is_primary: boolean;
  last_seen_at: string;
}

export interface TvScreenBinding {
  id: number;
  screen_id: number;
  screen_label: string;
  gym_id: number | null;
  gym_label: string | null;
  monitor_id: string | null;
  monitor_label: string | null;
  monitor_index: number | null;
  enabled: boolean;
  autostart: boolean;
  desired_state: string;
  fullscreen: boolean;
  window_label: string | null;
  last_error_code: string | null;
  last_error_message: string | null;
  created_at: string;
  updated_at: string;
  // Display-target fields (A9 auto-attach)
  target_display_id: string | null;
  target_display_path: string | null;
  last_known_friendly_name: string | null;
  last_known_bounds_x: number | null;
  last_known_bounds_y: number | null;
  last_known_width: number | null;
  last_known_height: number | null;
  last_known_display_order_index: number | null;
  display_attach_confidence: string | null;
  runtime?: TvScreenBindingRuntime | null;
}

export interface TvScreenBindingRuntime {
  binding_id: number;
  runtime_state: string;
  window_id: string | null;
  tauri_window_label?: string | null;
  last_started_at: string | null;
  last_stopped_at: string | null;
  crash_count: number;
  last_crashed_at?: string | null;
  last_crash_at?: string | null;
  last_exit_reason?: string | null;
  last_error_code: string | null;
  last_error_message: string | null;
  updated_at: string;
}

export interface TvHostMonitorsRefreshRequest {
  monitors: Omit<TvHostMonitor, "id" | "last_seen_at">[];
}

export type TvBindingSupportActionType =
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

export type TvBindingSupportActionResult =
  | "STARTED"
  | "SUCCEEDED"
  | "FAILED"
  | "SKIPPED"
  | "BLOCKED";

export type TvBindingHealthSummary =
  | "HEALTHY"
  | "WARNING"
  | "DEGRADED"
  | "ERROR"
  | "STOPPED";

export interface TvSupportActionLogRow {
  id: number;
  binding_id: number | null;
  gym_id: number | null;
  correlation_id: string;
  action_type: TvBindingSupportActionType;
  result: TvBindingSupportActionResult;
  message: string | null;
  error_code: string | null;
  error_message: string | null;
  metadata_json?: string | null;
  metadata?: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TvSupportActionAvailability {
  actionType: TvBindingSupportActionType;
  allowed: boolean;
  blockedCode: string | null;
  blockedReason: string | null;
  requiresConfirmation: boolean;
  destructive: boolean;
  requiredOptions?: string[];
}

export interface TvBindingSupportFacts {
  binding: TvScreenBinding;
  runtime: TvScreenBindingRuntime | null;
  monitor: {
    row: TvHostMonitor | null;
    available: boolean;
  };
  playerState: TvPlayerStateRow | null;
  latestSnapshot: Record<string, unknown> | null;
  latestReadiness: Record<string, unknown> | null;
  activation: Record<string, unknown> | null;
  latestReadySnapshot: Record<string, unknown> | null;
  previousReadySnapshot: Record<string, unknown> | null;
  adRuntime: Record<string, unknown> | null;
  downloadFailures: {
    count: number;
    rows: Array<Record<string, unknown>>;
  };
  proofFailures: {
    retryableCount: number;
    terminalCount: number;
    rows: Array<Record<string, unknown>>;
  };
  latestSupportAction: TvSupportActionLogRow | null;
  activeSupportAction: {
    bindingId: number;
    actionType: TvBindingSupportActionType;
    correlationId: string;
    startedAt: string;
  } | null;
}

export interface TvBindingSupportSummaryResponse {
  ok: boolean;
  bindingId: number;
  screenId: number | null;
  gymId: number | null;
  health: TvBindingHealthSummary;
  reasons: string[];
  facts: TvBindingSupportFacts;
  actionAvailability: Record<TvBindingSupportActionType, TvSupportActionAvailability>;
  lastCorrelationId: string | null;
  latestSupportAction: TvSupportActionLogRow | null;
  activeAction: {
    bindingId: number;
    actionType: TvBindingSupportActionType;
    correlationId: string;
    startedAt: string;
  } | null;
}

export interface TvAdProofOutboxRow {
  local_proof_id: number;
  campaign_task_id: string;
  campaign_id: string | null;
  gym_id: number;
  ad_media_id: string | null;
  idempotency_key: string;
  started_at: string | null;
  finished_at: string | null;
  displayed_duration_sec: number | null;
  expected_duration_sec: number | null;
  completed_fully: number;
  countable: number;
  result_status: string;
  reason_if_not_countable: string | null;
  correlation_id: string | null;
  participating_binding_count: number;
  failed_binding_count: number;
  outbox_state: string;
  attempt_count: number;
  next_attempt_at: string | null;
  last_error: string | null;
  backend_proof_id: string | null;
  backend_task_status: string | null;
  created_at: string;
  updated_at: string;
}

export interface TvObservabilityBindingSummary {
  bindingId: number;
  screenId: number | null;
  gymId: number | null;
  screenLabel: string;
  binding: TvScreenBinding;
  runtime: TvScreenBindingRuntime | null;
  health: TvBindingHealthSummary;
  reasons: string[];
  desiredState: string;
  runtimeState: string;
  monitorAvailable: boolean;
  failedAssetCount: number;
  proofRetryableCount: number;
  proofTerminalCount: number;
  playerState: string | null;
  readinessState: string | null;
  activationState: string | null;
  lastSupportAction: TvSupportActionLogRow | null;
  activeSupportAction: {
    bindingId: number;
    actionType: TvBindingSupportActionType;
    correlationId: string;
    startedAt: string;
  } | null;
  stale: boolean;
  problem: boolean;
}

export interface TvObservabilityEventRow {
  id: number | null;
  source: "BINDING_EVENT" | "PLAYER_EVENT" | "SUPPORT_ACTION";
  bindingId: number | null;
  gymId: number | null;
  createdAt: string | null;
  eventType: string | null;
  severity: string | null;
  message: string | null;
  correlationId: string | null;
  metadata: Record<string, unknown> | null;
  result?: string | null;
}

export interface TvObservabilityOverviewResponse {
  ok: boolean;
  generatedAt: string;
  totals: {
    totalBindings: number;
    healthyBindings: number;
    warningBindings: number;
    degradedBindings: number;
    errorBindings: number;
    stoppedBindings: number;
    activeMonitors: number;
    activePlayerWindows: number;
    activeGymAdRuntimes: number;
    queuedOrRetryableProofCount: number;
    recentFailedDownloadsCount: number;
    recentSupportActionsCount: number;
    staleProblemBindingsCount: number;
  };
  problemBindings: Array<{
    bindingId: number;
    screenLabel: string;
    health: TvBindingHealthSummary;
    reasons: string[];
    stale: boolean;
  }>;
  recentSupportWindowHours: number;
}

export interface TvObservabilityBindingDetail extends TvObservabilityBindingSummary {
  ok: boolean;
  bindingConfig: TvScreenBinding;
  monitor: {
    row: TvHostMonitor | null;
    available: boolean;
  };
  readiness: Record<string, unknown> | null;
  activation: Record<string, unknown> | null;
  playerStateRow: TvPlayerStateRow | null;
  adRuntime: TvGymAdRuntime | null;
  failedAssets: {
    count: number;
    rows: Array<Record<string, unknown>>;
  };
  proofBacklog: {
    queuedCount: number;
    sendingCount: number;
    retryableCount: number;
    terminalCount: number;
    sentCount: number;
    rows: TvAdProofOutboxRow[];
    total: number;
  };
  lastSupportAction: TvSupportActionLogRow | null;
  supportSummary: TvBindingSupportSummaryResponse;
  supportHistory: {
    rows: TvSupportActionLogRow[];
    total: number;
    limit: number;
    offset: number;
  };
  bindingEvents: {
    rows: Array<Record<string, unknown>>;
    total: number;
  };
  playerEvents: {
    rows: TvPlayerEvent[];
    total: number;
  };
  syncRuns: {
    rows: Array<Record<string, unknown>>;
    total: number;
  };
  activationAttempts: {
    rows: Array<Record<string, unknown>>;
    total: number;
  };
  recentEvents: {
    rows: TvObservabilityEventRow[];
    total: number;
    limit: number;
    offset: number;
  };
  gymDiagnostics: TvObservabilityGymDetail | null;
}

export interface TvObservabilityGymDetail {
  ok: boolean;
  gymId: number;
  runtime: TvGymAdRuntime | null;
  currentTaskId: string | null;
  currentTask: TvAdTaskCache | null;
  coordinationState: string;
  activeBindingCount: number;
  failedBindingCount: number;
  audioOverrideActive: boolean;
  lastErrorCode: string | null;
  lastErrorMessage: string | null;
  bindingHealthCounts: Record<TvBindingHealthSummary, number>;
  proofBacklog: {
    queuedCount: number;
    sendingCount: number;
    retryableCount: number;
    terminalCount: number;
    sentCount: number;
    rows: TvAdProofOutboxRow[];
    total: number;
  };
  recentTaskRuntime: {
    rows: TvAdTaskRuntime[];
    total: number;
    limit: number;
    offset: number;
  };
  bindings: TvObservabilityBindingSummary[];
  updatedAt: string | null;
}

export interface TvObservabilityProofsResponse {
  ok: boolean;
  rows: TvAdProofOutboxRow[];
  total: number;
  limit: number;
  offset: number;
  bindingId: number | null;
  gymId: number | null;
  summary: {
    queuedCount: number;
    sendingCount: number;
    retryableCount: number;
    terminalCount: number;
    sentCount: number;
  };
}

export interface TvObservabilityRetentionResponse {
  ok: boolean;
  generatedAt: string;
  policy: {
    bindingEventDays: number;
    playerEventDays: number;
    syncRunDays: number;
    activationAttemptDays: number;
    supportLogDays: number;
    adTaskRuntimeDays: number;
    proofTerminalDays: number;
    disconnectedMonitorDays: number;
  };
  tables: Array<{
    table: string;
    totalRows: number;
    eligibleRows: number;
    rule: string;
    cutoffAt: string | null;
  }>;
  eligibleDeleteCount: number;
}

export interface TvObservabilityRetentionRunResponse {
  ok: boolean;
  dryRun: boolean;
  includeQueryChecks: boolean;
  policy: TvObservabilityRetentionResponse["policy"];
  deletedRows: number;
  tables: Array<{
    table: string;
    deletedRows: number;
    eligibleRows?: number;
  }>;
  summaryAfter: TvObservabilityRetentionResponse;
}

export type TvStartupCheckSeverity = "BLOCKER" | "WARNING" | "INFO";
export type TvStartupCheckResult = "PASSED" | "FAILED" | "SKIPPED" | "REPAIRED";
export type TvStartupOverallResult = "SUCCESS" | "SUCCESS_WITH_WARNINGS" | "FAILED";

export interface TvStartupCheckItem {
  code: string;
  severity: TvStartupCheckSeverity;
  status: TvStartupCheckResult;
  message: string | null;
  metadata: Record<string, unknown>;
}

export interface TvStartupReconciliationPhase {
  id: number;
  runId: number;
  phaseName: string | null;
  result: TvStartupCheckResult | null;
  message: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  metadata: Record<string, unknown>;
  createdAt: string | null;
}

export interface TvStartupReconciliationRun {
  id: number;
  startedAt: string | null;
  finishedAt: string | null;
  overallResult: TvStartupOverallResult | null;
  status: TvStartupOverallResult | string | null;
  blockerCount: number;
  warningCount: number;
  infoCount: number;
  message: string | null;
  metadata: Record<string, unknown>;
  triggerSource: string | null;
  correlationId: string | null;
  checks: TvStartupCheckItem[];
  blockers: TvStartupCheckItem[];
  warnings: TvStartupCheckItem[];
  infos: TvStartupCheckItem[];
  createdAt: string | null;
  updatedAt: string | null;
  phases: TvStartupReconciliationPhase[];
}

export interface TvStartupLatestResponse extends Partial<TvStartupReconciliationRun> {
  ok: boolean;
  error?: string;
}

export interface TvStartupRunsResponse {
  ok: boolean;
  rows: TvStartupReconciliationRun[];
  total: number;
  limit: number;
  offset: number;
}

export interface TvStartupPreflightResponse {
  ok: boolean;
  status: TvStartupOverallResult;
  overallResult: TvStartupOverallResult;
  generatedAt: string;
  message: string;
  checks: TvStartupCheckItem[];
  blockers: TvStartupCheckItem[];
  warnings: TvStartupCheckItem[];
  infos: TvStartupCheckItem[];
  counts: {
    blockerCount: number;
    warningCount: number;
    infoCount: number;
  };
  metadata: Record<string, unknown>;
}

export interface TvStartupRunResponse {
  ok: boolean;
  result?: "BLOCKED";
  status: TvStartupOverallResult | "BLOCKED";
  overallResult?: TvStartupOverallResult;
  error?: string;
  message?: string;
  runId?: number;
  failedPhaseCount?: number;
  warningCount?: number;
  blockerCount?: number;
  infoCount?: number;
  latest?: TvStartupLatestResponse;
  activeRun?: {
    runId?: number;
    triggerSource?: string;
    correlationId?: string;
    startedAt?: string;
  } | null;
}
