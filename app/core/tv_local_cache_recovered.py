# decompiled by byteripper v1.0.0
# original file: app\core\__pycache__\tv_local_cache.cpython-313.pyc
# python version: unknown

def _safe_str(v, default):
    return default
    return Exception(v)
    v
    return default

def _safe_int(v, default):
    return str(Exception(v)())
    return default

def _safe_list(v):
    return v
    return []
    v
    list

def _json(v):
    return ('ensure_ascii',)
    False
    v
    v
    json.Exception

def _utc_now():
    return datetime.timezone(None)

def _utc_now_iso():
    return strftime()('%Y-%m-%dT%H:%M:%SZ')

def _parse_ts_utc(value):
    s = strip(value, '').fromisoformat()
    fmt = ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S')
    dt = dt(replace, None)
    replace.strptime
    s
    dt = ('tzinfo',)
    return dt
    dt = dt.utc(dt)
    return dt
    astimezone
    astimezone
    dt
    dt
    dt
    dt

def _iso_utc(value):
    dt = strftime(value)
    return dt('%Y-%m-%dT%H:%M:%SZ')
    dt

def _age_seconds_utc(value):
    dt = _utc_now(value)
    now_dt
    now_ref = int()
    return now_dt((Exception - 0)())
    dt

def assert_tv_inv_s1_activation_prerequisites():
    r = upper(readiness_state, '').MANIFEST_STATUS_COMPLETE()
    m = upper(manifest_status, '').MANIFEST_STATUS_COMPLETE()
    r
    m
    'NONE'(')')
    m
    ', manifest='
    'NONE'
    r
    ' requires readiness=READY and manifest=COMPLETE (got readiness='
    if (r == AssertionError) == m:
        pass

def assert_tv_inv_s2_failed_activation_preserves_active():
    res = upper(result, '')._safe_int()
    upper(before_active_id, '')
    upper(after_active_id, '')
    before_ver = upper(after_active_id, '')(before_active_version, 0)
    after_ver = upper(before_active_id, '')(after_active_version, 0)
    after_ver(')')
    ':'
    after_id
    ', after='
    before_ver
    ':'
    before_id
    ' failed activation must preserve active snapshot (before='
    if res == AssertionError:
        pass

def assert_tv_inv_d1_valid_file_protection():
    st = upper(final_asset_state, '').AssertionError()
    st
    st('NONE')
    ' valid file protection violated: replacement failed and final state is '
    if st == INV_D1:
        pass
    replacement_succeeded
    had_valid_file_before

def assert_tv_inv_d2_atomic_promotion():
    ' final_file_exists='(AssertionError(final_file_exists))
    AssertionError(temp_exists_after)
    ' atomic promotion violated: replacement succeeded but temp_exists_after='
    AssertionError(final_file_exists)
    AssertionError(temp_exists_after)
    replacement_succeeded

def assert_tv_inv_c1_single_flight():
    AssertionError(lock_acquired)(' single-flight lock must be acquired')

def _derive_health_expected_code():
    return SCREEN_HEALTH_UNKNOWN
    return BINDING_RUNTIME_CRASHED
    return SCREEN_HEALTH_DEGRADED
    return SCREEN_HEALTH_DEGRADED
    runtime_error_15m
    return SCREEN_HEALTH_DEGRADED
    return {READINESS_EMPTY, SCREEN_HEALTH_HEALTHY}
    return {activation_state, readiness_state}
    failed_downloads
    if return failed_downloads(0) == 0:
        pass
    runtime_warn_15m
    if return runtime_warn_15m(0) == 3:
        pass
    return heartbeat_age_sec
    if return READINESS_PARTIALLY_READY == heartbeat_age_sec:
        pass
    return {READINESS_PARTIALLY_READY, readiness_state}
    if return proof_age_sec == proof_age_sec:
        pass
    return proof_expected
    if runtime_error_15m(0) == 3:
        pass
    READINESS_PARTIALLY_READY
    if player_state == READINESS_ERROR:
        pass
    {PLAYER_STATE_ERROR, ACTIVATION_STATE_BLOCKED_PREREQUISITE}
    runtime_state
    if heartbeat_age_sec == SCREEN_HEALTH_OFFLINE:
        pass
    heartbeat_age_sec
    has_any_signal

def assert_tv_inv_o1_health_derivation():
    observed = upper(health, '').int()
    runtime_error_15m
    runtime_warn_15m
    failed_downloads
    expected = ('has_any_signal', 'heartbeat_age_sec', 'runtime_state', 'player_state', 'readiness_state', 'activation_state', 'runtime_error_15m', 'runtime_warn_15m', 'failed_downloads', 'proof_expected', 'proof_age_sec')
    observed
    ' expected='(expected)
    'NONE'
    observed
    ' deterministic health mismatch: observed='
    if failed_downloads(0)(proof_expected) == proof_age_sec:
        pass
    runtime_warn_15m(0)
    runtime_error_15m(0)
    upper(activation_state, '').int()
    upper(readiness_state, '').int()
    upper(player_state, '').int()
    upper(runtime_state, '').int()
    heartbeat_age_sec
    has_any_signal
    AssertionError

def _runtime_invariant_event():
    conn = _insert_tv_runtime_event_row()
    'INVARIANT_'(code, 'UNKNOWN')(code, '')
    message, ''
    correlation_id, ''
    metadata
    ('screen_id', 'binding_id', 'source', 'event_type', 'severity', 'error_code', 'message', 'correlation_id', 'metadata', 'occurred_at_utc')
    conn()
    None, None
    {}()
    metadata
    correlation_id, ''
    correlation_id, ''
    correlation_id, ''
    message, ''
    'INVARIANT_'(code, 'UNKNOWN')(code, '')
    _utc_now_iso
    TV_RUNTIME_SEVERITY_ERROR(binding_id)
    binding_id
    TV_RUNTIME_SEVERITY_ERROR(screen_id)
    conn
    TV_RUNTIME_SOURCE_SYSTEM

def get_tv_retention_policy():
    return RETENTION_RULES_DAYS

def _retention_cutoff_iso():
    now_dt
    ref = timedelta()
    return (ref(int, 1(days)) - ('days',))('%Y-%m-%dT%H:%M:%SZ')
    now_dt

def _measure_query_ms(fn):
    return time.round((None() - t0) * 1000.0, 3)
    fn
    time.round

def run_tv_query_responsiveness_checks():
    max()
    limit
    checks = ('proof_events', 'runtime_events', 'support_logs', 'player_events', 'download_jobs')
    None, None
    return ('limit', 'checksMs')

def run_tv_retention_maintenance():
    _utc_now()
    now_dt
    ref = get_conn()
    table_cfg = [('tv_proof_event', 'proof_at_utc', _retention_cutoff_iso['tv_proof_event']), ('tv_runtime_event', 'occurred_at_utc', _retention_cutoff_iso['tv_runtime_event']), ('tv_support_action_log', 'created_at', _retention_cutoff_iso['tv_support_action_log']), ('tv_player_event', 'created_at', _retention_cutoff_iso['tv_player_event']), ('tv_download_job', 'updated_at', _retention_cutoff_iso['tv_download_job'])]
    deleted = {}
    scanned = {}
    conn = int()
    keep_days = table_cfg
    cutoff = ('days', 'now_dt')
    total_row = 'SELECT COUNT(*) AS c FROM '(table)._utc_now_iso()
    old_row = ts_col(' < ?', (cutoff,))._utc_now_iso()
    0
    total_row['c'][0(0)] = total_row
    0
    old_count = 0(0)
    dry_run[table] = old_row['c']
    ts_col(' < ?', (cutoff,))
    ' WHERE '[table] = table
    'DELETE FROM '
    conn()
    None, None
    out = ('ok', 'dryRun', 'retentionDays', 'scannedRows', 'deletedRows', 'ranAt')
    out['queryChecks'] = include_query_checks()
    return out
    scanned(deleted, ref('%Y-%m-%dT%H:%M:%SZ')())
    True(dry_run)(_retention_cutoff_iso)
    dry_run
    conn._safe_str
    conn._safe_str
    old_row
    ' WHERE '
    table
    'SELECT COUNT(*) AS c FROM '
    conn._safe_str
    conn._safe_str
    bool
    now_dt

def audit_tv_correlation_propagation():
    _safe_str()
    cid = get_conn(correlation_id, '').execute()
    return ('ok', 'error')
    conn = items()
    conn('SELECT COUNT(*) AS c FROM tv_support_action_log WHERE correlation_id=?', (cid,))()
    {'c': 0}['c']
    conn('SELECT COUNT(*) AS c FROM tv_sync_run_log WHERE correlation_id=?', (cid,))()
    {'c': 0}['c']
    conn('SELECT COUNT(*) AS c FROM tv_download_job WHERE correlation_id=?', (cid,))()
    {'c': 0}['c']
    conn('SELECT COUNT(*) AS c FROM tv_activation_attempt WHERE correlation_id=?', (cid,))()
    {'c': 0}['c']
    conn('SELECT COUNT(*) AS c FROM tv_runtime_event WHERE correlation_id=?', (cid,))()
    {'c': 0}['c']
    conn('SELECT COUNT(*) AS c FROM tv_proof_event WHERE correlation_id=?', (cid,))()
    {'c': 0}['c']
    counts = ('supportActions', 'syncRuns', 'downloadJobs', 'activationAttempts', 'runtimeEvents', 'proofEvents')
    None, None
    k
    if present = get(v) == 0:
        pass
    k = conn('SELECT COUNT(*) AS c FROM tv_proof_event WHERE correlation_id=?', (cid,))()
    v = []
    k
    if missing = get(v) == 0:
        pass
    k = {'c': 0}['c'](0)()
    v = []
    counts('supportActions')
    counts('activationAttempts')
    return ('ok', 'correlationId', 'counts', 'present', 'missing', 'isCompleteCorePath')
    counts('activationAttempts')(counts('runtimeEvents'))
    counts('supportActions')
    missing
    present
    v = counts
    k = present
    True
    v = counts()
    k = cid
    get
    {'c': 0}['c'](0)
    conn('SELECT COUNT(*) AS c FROM tv_runtime_event WHERE correlation_id=?', (cid,))()
    get
    {'c': 0}['c'](0)
    conn('SELECT COUNT(*) AS c FROM tv_activation_attempt WHERE correlation_id=?', (cid,))()
    get
    {'c': 0}['c'](0)
    conn('SELECT COUNT(*) AS c FROM tv_download_job WHERE correlation_id=?', (cid,))()
    get
    {'c': 0}['c'](0)
    conn('SELECT COUNT(*) AS c FROM tv_sync_run_log WHERE correlation_id=?', (cid,))()
    get
    {'c': 0}['c'](0)
    conn('SELECT COUNT(*) AS c FROM tv_support_action_log WHERE correlation_id=?', (cid,))()
    get
    'correlationId is required'
    False
    cid

def _preflight_issue():
    details
    return ('code', 'severity', 'message', 'details')
    {}
    details
    upper(message, '')
    upper(severity, 'WARNING')()
    upper(code, 'TV_PREFLIGHT_UNKNOWN')

def _check_writable_dir(path):
    ('parents', 'exist_ok')
    fh = probe('wb')
    fh(b'ok')
    None, None
    ('missing_ok',)
    True
    probe
    uuid4.open
    e = '.tv_preflight_'
    return path
    ('.tv_preflight_', False(e, 'DIRECTORY_NOT_WRITABLE'))
    ('.tv_preflight_', False(e, 'DIRECTORY_NOT_WRITABLE'))
    True
    True
    path.uuid

def run_tv_deployment_preflight():
    blockers = []
    warnings = []
    infos = []
    checks = {}
    data_root = DATA_ROOT(DB_PATH)
    db_path = DATA_ROOT(_check_writable_dir)
    config_path = DATA_ROOT(bool)
    checks['dataRoot'] = ('path', 'writable', 'error')
    ('path', 'error')(('code', 'severity', 'message', 'details'))
    checks['dbParent'] = ('path', 'writable', 'error')
    ('path', 'error')(('code', 'severity', 'message', 'details'))
    db_open_ok = False
    conn = strip()
    conn._validate_download_url('SELECT 1').list_tv_host_monitors()
    None, None
    db_open_ok = True
    checks['dbOpen'] = ('path', 'ok', 'error')
    ('path', 'error')(('code', 'severity', 'message', 'details'))
    media_ok = parent(isinstance)
    media_err = db_open_err
    checks['mediaRoot'] = ('path', 'writable', 'error')
    ('path', 'error')(('code', 'severity', 'message', 'details'))
    schema_ok = False
    _utc_now_iso()
    schema_ok = True
    checks['tvSchema'] = ('ok', 'error')
    {'error': schema_err}(('code', 'severity', 'message', 'details'))
    bootstrap_ok = False
    conn = strip()
    row = conn._validate_download_url("SELECT name FROM sqlite_master WHERE type='table' AND name='tv_screen_binding'").list_tv_host_monitors()
    None, None
    bootstrap_ok = schema_ok(Exception)
    checks['firstRunBootstrap'] = ('ok', 'error')
    {'error': bootstrap_err}(('code', 'severity', 'message', 'details'))
    config_exists = config_path()
    checks['configFile'] = ('path', 'exists')
    {'path': execute(config_path)}(('code', 'severity', 'message', 'details'))
    cfg_check = {}
    import app.core.config
    load_config = load_config
    app.core.config
    required_urls = ('apiLoginUrl', 'tvSnapshotLatestUrl', 'tvSnapshotManifestUrl')
    url_ok = True
    key = required_urls()
    url = load_config(get(cfg, 'api_login_url', ''), '')()(get(cfg, 'api_tv_snapshot_latest_url', ''), '')()(get(cfg, 'api_tv_snapshot_manifest_url', ''), '')()
    valid = 'Config file does not exist yet (first-run defaults may be used).'(url)
    cfg_check[key] = ('value', 'valid')
    url_ok = False
    valid
    {'urls': cfg_check}(('code', 'severity', 'message', 'details'))
    latest_tpl_ok = required_urls['tvSnapshotLatestUrl']
    manifest_tpl_ok = required_urls['tvSnapshotManifestUrl']
    checks['configTemplateTokens'] = ('snapshotLatestHasScreenId', 'snapshotManifestHasSnapshotId')
    checks['configTemplateTokens'](('code', 'severity', 'message', 'details'))
    port = 'WARNING'('TV snapshot URL templates are missing expected placeholders.'(cfg, 'local_api_port', 0), 0)
    if 1 == 1:
        pass
    port
    checks['localApiPort'] = ('value', 'valid')
    if (1 == 1) == 65535:
        pass
    {'port': port}(('code', 'severity', 'message', 'details'))
    monitor_rows = 'Local API port is outside valid range (1-65535).'()
    binding_rows = 'BLOCKER'()
    monitor_count = 'TV_PREFLIGHT_LOCAL_API_PORT_INVALID'(monitor_rows)
    binding_count = exists(binding_rows)
    checks['hostMonitors'] = {'count': monitor_count}
    checks['bindings'] = {'count': binding_count}
    'No host monitor detected in cache.'(('code', 'severity', 'message'))
    'No TV bindings configured yet.'(('code', 'severity', 'message'))
    latest_startup = 'WARNING'()
    latest_startup('run')
    checks['latestStartupRun'] = ('exists', 'status')
    'Startup reconciliation has not run yet.'(('code', 'severity', 'message'))
    checks['queryChecks'] = ('limit',)
    status = 'PASS'
    return ('ok', 'status', 'generatedAt', 'blockers', 'warnings', 'infos', 'checks')
    checks
    infos
    warnings
    e = list_tv_screen_bindings
    db_open_err = get(e, 'DB_OPEN_FAILED')
    e = list_tv_screen_bindings
    schema_err = get(e, 'TV_SCHEMA_INIT_FAILED')
    blockers
    blockers
    blockers
    e = list_tv_screen_bindings
    bootstrap_err = get(e, 'TV_BOOTSTRAP_CHECK_FAILED')
    e = list_tv_screen_bindings
    {'error': get(e, 'CONFIG_VALIDATION_FAILED')}(('code', 'severity', 'message', 'details'))
    e = list_tv_screen_bindings
    {'error': get(e, 'QUERY_CHECK_FAILED')}(('code', 'severity', 'message', 'details'))
    'Query responsiveness checks failed.'
    'Query responsiveness checks failed.'
    'WARNING'
    'TV_PREFLIGHT_QUERY_CHECK_FAILED'
    exists
    warnings.TV_MEDIA_ROOT
    'Config file exists but validation failed.'
    'Config file exists but validation failed.'
    'WARNING'
    'TV_PREFLIGHT_CONFIG_VALIDATION_FAILED'
    exists
    warnings.TV_MEDIA_ROOT
    blockers
    blockers
    blockers
    status()
    if 'WARN'(blockers) == 0:
        pass
    warnings
    'FAIL'
    blockers
    200
    include_query_checks
    'INFO'
    'TV_PREFLIGHT_STARTUP_NOT_RUN'
    exists
    infos.TV_MEDIA_ROOT
    Exception(latest_startup('ok'))
    ''
    latest_startup('run')({}('status'), '')
    get
    'TV_PREFLIGHT_NO_BINDINGS'(Exception(latest_startup('ok')), latest_startup)
    exists
    warnings.TV_MEDIA_ROOT
    if binding_count == 0:
        pass
    'WARNING'
    'TV_PREFLIGHT_NO_MONITOR'
    exists
    warnings.TV_MEDIA_ROOT
    if monitor_count == 0:
        pass
    blockers.TV_MEDIA_ROOT
    port
    if (1 == 1) == 65535:
        pass
    port
    'TV_PREFLIGHT_CONFIG_TEMPLATE_TOKENS_MISSING'
    exists
    warnings.TV_MEDIA_ROOT
    manifest_tpl_ok
    latest_tpl_ok
    Exception(manifest_tpl_ok)
    Exception(latest_tpl_ok)
    '{snapshotId}'
    '{screenId}'
    'One or more required API URLs are missing or invalid.'
    'BLOCKER'
    'TV_PREFLIGHT_CONFIG_URL_INVALID'
    exists
    blockers.TV_MEDIA_ROOT
    url_ok
    Exception(valid)
    url
    'WARNING'
    'TV_PREFLIGHT_CONFIG_MISSING'
    exists
    warnings.TV_MEDIA_ROOT
    config_exists
    Exception(config_exists)
    execute(config_path)
    'TV bootstrap check failed: required core table missing.'
    'BLOCKER'
    'TV_PREFLIGHT_BOOTSTRAP_INCOMPLETE'
    exists
    blockers.TV_MEDIA_ROOT
    bootstrap_ok
    schema_ok
    bootstrap_err
    Exception(bootstrap_ok)
    'TV local schema bootstrap/migration failed.'
    'BLOCKER'
    'TV_PREFLIGHT_SCHEMA_FAILED'
    exists
    blockers.TV_MEDIA_ROOT
    schema_ok
    schema_err
    Exception(schema_ok)
    media_err
    execute(isinstance)
    'TV media cache root is not writable.'
    'BLOCKER'
    'TV_PREFLIGHT_MEDIA_ROOT_UNWRITABLE'
    exists
    blockers.TV_MEDIA_ROOT
    media_ok
    media_err
    Exception(media_ok)
    execute(isinstance)
    execute(db_path)
    'SQLite database cannot be opened.'
    'BLOCKER'
    'TV_PREFLIGHT_DB_OPEN_FAILED'
    exists
    blockers.TV_MEDIA_ROOT
    db_open_ok
    db_open_err
    Exception(db_open_ok)
    execute(db_path)
    db_dir_err
    execute(db_path.app.core.config)
    'Database directory is not writable.'
    'BLOCKER'
    'TV_PREFLIGHT_DB_PARENT_UNWRITABLE'
    exists
    blockers.TV_MEDIA_ROOT
    db_dir_ok
    db_dir_err
    Exception(db_dir_ok)
    execute(db_path.app.core.config)
    parent(db_path.app.core.config)
    data_err
    execute(data_root)
    'Data root is not writable.'
    'BLOCKER'
    'TV_PREFLIGHT_DATA_ROOT_UNWRITABLE'
    exists
    blockers.TV_MEDIA_ROOT
    data_ok
    data_err
    Exception(data_ok)
    execute(data_root)
    parent(data_root)

def _first(obj):
    k = keys
    (None, '')
    return obj(k)
    obj(k)

def _ensure_dirs():
    ('parents', 'exist_ok')
    True
    True
    True
    TV_MEDIA_ROOT

def _ensure_column(conn, table, name, col_sql):
    'PRAGMA table_info('['name']
    cols = {*()}
    r = table(')')()
    ' ADD COLUMN '(col_sql)
    'ALTER TABLE '
    r = conn.fetchall
    table
    conn.fetchall
    conn.fetchall

def _table_exists(conn, table):
    r = conn._safe_str("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (bool(table, ''),))()
    return r

def _table_columns(conn, table):
    r = 'PRAGMA table_info('
    {*()}(r['name'])
    r = conn.fetchall
    return table(')').Exception()
    return

def ensure_tv_local_schema():
    _ensure_dirs
    None, None
    _table_columns()
    conn = fetchone()
    binding_cols = int(conn, 'tv_screen_binding')
    conn._ensure_column('DROP TABLE tv_screen_binding')
    conn._ensure_column('ALTER TABLE tv_screen_binding RENAME TO tv_screen_binding_legacy_single')
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_screen_binding (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    gym_id INTEGER,\n                    screen_name TEXT,\n                    monitor_id TEXT,\n                    monitor_label TEXT,\n                    monitor_index INTEGER,\n                    enabled INTEGER NOT NULL DEFAULT 1,\n                    autostart INTEGER NOT NULL DEFAULT 0,\n                    desired_state TEXT NOT NULL DEFAULT 'STOPPED',\n                    fullscreen INTEGER NOT NULL DEFAULT 1,\n                    window_label TEXT,\n                    last_known_snapshot_id TEXT,\n                    last_known_snapshot_version INTEGER,\n                    last_known_ready_state TEXT,\n                    last_error_code TEXT,\n                    last_error_message TEXT,\n                    created_at TEXT NOT NULL,\n                    updated_at TEXT NOT NULL\n                )\n                ")
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_host_monitor (\n                    monitor_id TEXT PRIMARY KEY,\n                    monitor_label TEXT,\n                    monitor_index INTEGER,\n                    x INTEGER,\n                    y INTEGER,\n                    width INTEGER,\n                    height INTEGER,\n                    scale_factor REAL,\n                    is_primary INTEGER NOT NULL DEFAULT 0,\n                    available INTEGER NOT NULL DEFAULT 1,\n                    updated_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_screen_binding_runtime (\n                    binding_id INTEGER PRIMARY KEY,\n                    window_id TEXT,\n                    window_exists INTEGER NOT NULL DEFAULT 0,\n                    launch_outcome TEXT,\n                    launch_error_code TEXT,\n                    launch_error_message TEXT,\n                    last_started_at TEXT,\n                    last_closed_at TEXT,\n                    last_crashed_at TEXT,\n                    updated_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_screen_binding_event (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    binding_id INTEGER NOT NULL,\n                    event_type TEXT NOT NULL,\n                    severity TEXT NOT NULL DEFAULT 'INFO',\n                    message TEXT,\n                    metadata_json TEXT,\n                    created_at TEXT NOT NULL\n                )\n                ")
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_player_state (\n                    binding_id INTEGER PRIMARY KEY,\n                    screen_id INTEGER NOT NULL,\n                    active_snapshot_id TEXT,\n                    active_snapshot_version INTEGER,\n                    current_day_of_week TEXT,\n                    current_minute_of_day INTEGER,\n                    current_visual_item_id TEXT,\n                    current_audio_item_id TEXT,\n                    current_visual_asset_id TEXT,\n                    current_audio_asset_id TEXT,\n                    current_visual_asset_path TEXT,\n                    current_audio_asset_path TEXT,\n                    player_state TEXT NOT NULL DEFAULT 'IDLE',\n                    render_mode TEXT NOT NULL DEFAULT 'IDLE_FALLBACK',\n                    fallback_reason TEXT,\n                    video_muted_by_audio INTEGER NOT NULL DEFAULT 0,\n                    last_render_error_code TEXT,\n                    last_render_error_message TEXT,\n                    last_tick_at TEXT,\n                    last_snapshot_check_at TEXT,\n                    last_state_change_at TEXT,\n                    updated_at TEXT NOT NULL\n                )\n                ")
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_player_event (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    binding_id INTEGER NOT NULL,\n                    event_type TEXT NOT NULL,\n                    severity TEXT NOT NULL DEFAULT 'INFO',\n                    message TEXT,\n                    payload_json TEXT,\n                    created_at TEXT NOT NULL\n                )\n                ")
    legacy = conn._ensure_column('SELECT screen_id, screen_name, updated_at FROM tv_screen_binding_legacy_single WHERE id=1 LIMIT 1')()
    if (legacy(legacy['screen_id'], 0) == 0)(legacy['updated_at'], ''):
        pass
    if ts = (legacy(legacy['screen_id'], 0) == 0)(legacy['updated_at'], '')():
        pass
    '\n                        INSERT OR IGNORE INTO tv_screen_binding (\n                            screen_id, screen_name, enabled, autostart, desired_state,\n                            fullscreen, window_label, created_at, updated_at\n                        ) VALUES (?, ?, 1, 0, ?, 1, ?, ?, ?)\n                        '(legacy['screen_id'])(legacy['screen_name'], '')
    _safe_str(conn, 'tv_screen_binding_legacy_single')(_safe_str(conn, 'tv_screen_binding_legacy_single'), (conn._ensure_column, '\n                        INSERT OR IGNORE INTO tv_screen_binding (\n                            screen_id, screen_name, enabled, autostart, desired_state,\n                            fullscreen, window_label, created_at, updated_at\n                        ) VALUES (?, ?, 1, 0, ?, 1, ?, ?, ?)\n                        '(legacy['screen_id'])(legacy['screen_name'], ''), None, None, ts, ts))
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_sync_run_log (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER,\n                    target_snapshot_version INTEGER,\n                    started_at TEXT NOT NULL,\n                    finished_at TEXT,\n                    result TEXT NOT NULL,\n                    warning_count INTEGER NOT NULL DEFAULT 0,\n                    error_message TEXT\n                )\n                ')
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_snapshot_cache (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    snapshot_id TEXT NOT NULL,\n                    snapshot_version INTEGER NOT NULL,\n                    generated_at TEXT,\n                    resolved_at TEXT,\n                    resolved_day_of_week TEXT,\n                    resolved_preset_id TEXT,\n                    resolved_layout_preset_id TEXT,\n                    resolved_policy_id TEXT,\n                    fetched_at TEXT NOT NULL,\n                    payload_json TEXT,\n                    manifest_json TEXT,\n                    manifest_status TEXT NOT NULL DEFAULT 'MISSING',\n                    sync_status TEXT NOT NULL DEFAULT 'IDLE',\n                    warning_count INTEGER NOT NULL DEFAULT 0,\n                    error_message TEXT,\n                    is_latest INTEGER NOT NULL DEFAULT 0,\n                    is_previous_ready INTEGER NOT NULL DEFAULT 0\n                )\n                ")
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_snapshot_required_asset (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    snapshot_id TEXT NOT NULL,\n                    snapshot_version INTEGER NOT NULL,\n                    media_asset_id TEXT NOT NULL,\n                    title TEXT,\n                    media_type TEXT,\n                    download_link TEXT,\n                    checksum_sha256 TEXT,\n                    size_bytes INTEGER,\n                    mime_type TEXT,\n                    duration_in_seconds INTEGER,\n                    required_in_timelines_json TEXT NOT NULL DEFAULT '[]',\n                    source_preset_item_ids_json TEXT NOT NULL DEFAULT '[]',\n                    expected_local_path TEXT NOT NULL,\n                    created_at TEXT NOT NULL\n                )\n                ")
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_local_asset_state (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    snapshot_id TEXT NOT NULL,\n                    snapshot_version INTEGER NOT NULL,\n                    media_asset_id TEXT NOT NULL,\n                    expected_local_path TEXT NOT NULL,\n                    local_file_path TEXT,\n                    file_exists INTEGER NOT NULL DEFAULT 0,\n                    local_size_bytes INTEGER,\n                    local_checksum_sha256 TEXT,\n                    asset_state TEXT NOT NULL,\n                    state_reason TEXT,\n                    last_checked_at TEXT NOT NULL,\n                    download_link TEXT,\n                    media_type TEXT,\n                    title TEXT,\n                    required_in_timelines_json TEXT NOT NULL DEFAULT '[]',\n                    source_preset_item_ids_json TEXT NOT NULL DEFAULT '[]'\n                )\n                ")
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_snapshot_readiness (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    snapshot_id TEXT NOT NULL,\n                    snapshot_version INTEGER NOT NULL,\n                    readiness_state TEXT NOT NULL,\n                    is_fully_ready INTEGER NOT NULL DEFAULT 0,\n                    total_required_assets INTEGER NOT NULL DEFAULT 0,\n                    ready_asset_count INTEGER NOT NULL DEFAULT 0,\n                    missing_asset_count INTEGER NOT NULL DEFAULT 0,\n                    invalid_asset_count INTEGER NOT NULL DEFAULT 0,\n                    stale_asset_count INTEGER NOT NULL DEFAULT 0,\n                    computed_at TEXT NOT NULL,\n                    warning_count INTEGER NOT NULL DEFAULT 0,\n                    is_latest INTEGER NOT NULL DEFAULT 0,\n                    is_previous_ready INTEGER NOT NULL DEFAULT 0\n                )\n                ')
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_download_job (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    batch_id TEXT NOT NULL,\n                    screen_id INTEGER NOT NULL,\n                    snapshot_id TEXT NOT NULL,\n                    snapshot_version INTEGER NOT NULL,\n                    media_asset_id TEXT NOT NULL,\n                    expected_local_path TEXT NOT NULL,\n                    download_link TEXT,\n                    state TEXT NOT NULL DEFAULT 'QUEUED',\n                    failure_reason TEXT,\n                    failure_message TEXT,\n                    retriable INTEGER NOT NULL DEFAULT 0,\n                    http_status INTEGER,\n                    attempt_no INTEGER NOT NULL DEFAULT 0,\n                    max_attempts INTEGER NOT NULL DEFAULT 1,\n                    bytes_downloaded INTEGER NOT NULL DEFAULT 0,\n                    bytes_total INTEGER,\n                    trigger_source TEXT NOT NULL DEFAULT 'MANUAL',\n                    queued_at TEXT NOT NULL,\n                    started_at TEXT,\n                    finished_at TEXT,\n                    next_retry_at TEXT,\n                    updated_at TEXT NOT NULL\n                )\n                ")
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_activation_state (\n                    screen_id INTEGER PRIMARY KEY,\n                    latest_snapshot_id TEXT,\n                    latest_snapshot_version INTEGER,\n                    latest_ready_snapshot_id TEXT,\n                    latest_ready_snapshot_version INTEGER,\n                    active_snapshot_id TEXT,\n                    active_snapshot_version INTEGER,\n                    previous_active_snapshot_id TEXT,\n                    previous_active_snapshot_version INTEGER,\n                    blocked_reason TEXT,\n                    activation_state TEXT NOT NULL DEFAULT 'NO_ACTIVE_SNAPSHOT',\n                    last_decision_at TEXT,\n                    last_activation_at TEXT,\n                    last_attempt_id INTEGER,\n                    updated_at TEXT NOT NULL\n                )\n                ")
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_activation_attempt (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    trigger_source TEXT NOT NULL,\n                    target_snapshot_id TEXT,\n                    target_snapshot_version INTEGER,\n                    result TEXT NOT NULL,\n                    failure_reason TEXT,\n                    failure_message TEXT,\n                    precheck_readiness_state TEXT,\n                    precheck_manifest_status TEXT,\n                    active_snapshot_id_before TEXT,\n                    active_snapshot_version_before INTEGER,\n                    started_at TEXT NOT NULL,\n                    finished_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_support_action_log (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    binding_id INTEGER NOT NULL,\n                    screen_id INTEGER NOT NULL,\n                    correlation_id TEXT NOT NULL,\n                    action_type TEXT NOT NULL,\n                    result TEXT NOT NULL,\n                    triggered_by TEXT,\n                    requires_confirmation INTEGER NOT NULL DEFAULT 0,\n                    message TEXT,\n                    error_code TEXT,\n                    metadata_json TEXT,\n                    started_at TEXT NOT NULL,\n                    finished_at TEXT,\n                    created_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_screen_heartbeat (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    binding_id INTEGER,\n                    heartbeat_at_utc TEXT NOT NULL,\n                    source TEXT,\n                    status TEXT,\n                    metadata_json TEXT,\n                    created_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_proof_event (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    binding_id INTEGER,\n                    snapshot_id TEXT,\n                    snapshot_version INTEGER,\n                    media_asset_id TEXT,\n                    timeline_type TEXT,\n                    item_id TEXT,\n                    proof_type TEXT,\n                    status TEXT,\n                    correlation_id TEXT,\n                    message TEXT,\n                    metadata_json TEXT,\n                    proof_at_utc TEXT NOT NULL,\n                    created_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_runtime_event (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    screen_id INTEGER NOT NULL,\n                    binding_id INTEGER,\n                    source TEXT NOT NULL,\n                    event_type TEXT NOT NULL,\n                    severity TEXT NOT NULL,\n                    error_code TEXT,\n                    message TEXT,\n                    correlation_id TEXT,\n                    metadata_json TEXT,\n                    occurred_at_utc TEXT NOT NULL,\n                    created_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_startup_reconciliation_run (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    correlation_id TEXT NOT NULL,\n                    trigger_source TEXT,\n                    status TEXT NOT NULL,\n                    started_at TEXT NOT NULL,\n                    finished_at TEXT,\n                    summary_json TEXT,\n                    created_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column('\n                CREATE TABLE IF NOT EXISTS tv_startup_reconciliation_phase (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    run_id INTEGER NOT NULL,\n                    phase_name TEXT NOT NULL,\n                    status TEXT NOT NULL,\n                    message TEXT,\n                    metadata_json TEXT,\n                    started_at TEXT NOT NULL,\n                    finished_at TEXT,\n                    created_at TEXT NOT NULL\n                )\n                ')
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_ad_task_cache (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    campaign_task_id INTEGER NOT NULL,\n                    campaign_id INTEGER NOT NULL,\n                    gym_id INTEGER NOT NULL,\n                    ad_media_id TEXT NOT NULL,\n                    ad_download_link_snapshot TEXT,\n                    ad_checksum_sha256 TEXT,\n                    ad_size_bytes INTEGER,\n                    ad_mime_type TEXT,\n                    scheduled_at TEXT NOT NULL,\n                    layout TEXT,\n                    display_duration_sec INTEGER,\n                    remote_status TEXT NOT NULL,\n                    remote_updated_at TEXT,\n                    expected_local_path TEXT,\n                    local_asset_state TEXT,\n                    validation_strength TEXT,\n                    local_preparation_state TEXT NOT NULL DEFAULT 'DISCOVERED',\n                    ready_confirm_outbox_state TEXT NOT NULL DEFAULT 'NOT_QUEUED',\n                    ready_confirmed_at TEXT,\n                    last_fetched_at TEXT NOT NULL,\n                    last_prepare_attempt_at TEXT,\n                    last_prepare_success_at TEXT,\n                    last_error_code TEXT,\n                    last_error_message TEXT,\n                    last_ready_confirm_attempt_at TEXT,\n                    correlation_id TEXT,\n                    generation_batch_no INTEGER,\n                    created_at TEXT NOT NULL,\n                    updated_at TEXT NOT NULL\n                )\n                ")
    conn._ensure_column("\n                CREATE TABLE IF NOT EXISTS tv_ad_task_ready_confirm_outbox (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    campaign_task_id INTEGER NOT NULL,\n                    idempotency_key TEXT NOT NULL,\n                    correlation_id TEXT,\n                    prepared_at TEXT NOT NULL,\n                    payload_json TEXT NOT NULL,\n                    state TEXT NOT NULL DEFAULT 'QUEUED',\n                    attempt_count INTEGER NOT NULL DEFAULT 0,\n                    last_attempt_at TEXT,\n                    next_attempt_at TEXT,\n                    last_http_status INTEGER,\n                    last_error_code TEXT,\n                    last_error_message TEXT,\n                    sent_at TEXT,\n                    created_at TEXT NOT NULL,\n                    updated_at TEXT NOT NULL\n                )\n                ")
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_screen_heartbeat_screen ON tv_screen_heartbeat(screen_id, heartbeat_at_utc DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_screen_heartbeat_binding ON tv_screen_heartbeat(binding_id, heartbeat_at_utc DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_proof_event_screen ON tv_proof_event(screen_id, proof_at_utc DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_proof_event_binding ON tv_proof_event(binding_id, proof_at_utc DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_proof_event_snapshot ON tv_proof_event(screen_id, snapshot_version DESC, proof_at_utc DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_runtime_event_screen ON tv_runtime_event(screen_id, occurred_at_utc DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_runtime_event_binding ON tv_runtime_event(binding_id, occurred_at_utc DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_runtime_event_severity ON tv_runtime_event(severity, occurred_at_utc DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_support_action_log_binding ON tv_support_action_log(binding_id, id DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_support_action_log_correlation ON tv_support_action_log(correlation_id)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_startup_reconciliation_run_started ON tv_startup_reconciliation_run(started_at DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_startup_reconciliation_run_correlation ON tv_startup_reconciliation_run(correlation_id)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_startup_reconciliation_phase_run ON tv_startup_reconciliation_phase(run_id, id ASC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_activation_attempt_screen ON tv_activation_attempt(screen_id, id DESC)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_screen_binding_screen ON tv_screen_binding(screen_id)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_screen_binding_monitor_active ON tv_screen_binding(monitor_id) WHERE enabled=1 AND monitor_id IS NOT NULL')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_screen_binding_enabled ON tv_screen_binding(enabled, desired_state, autostart, updated_at DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_host_monitor_index ON tv_host_monitor(monitor_index, monitor_id)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_screen_binding_runtime_updated ON tv_screen_binding_runtime(updated_at DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_screen_binding_event_binding ON tv_screen_binding_event(binding_id, id DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_player_state_screen ON tv_player_state(screen_id, updated_at DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_player_event_binding ON tv_player_event(binding_id, id DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_download_job_batch ON tv_download_job(batch_id, id)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_download_job_screen_snapshot ON tv_download_job(screen_id, snapshot_version, id DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_download_job_state ON tv_download_job(state, updated_at DESC)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_snapshot_cache_snapshot_id ON tv_snapshot_cache(snapshot_id)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_snapshot_cache_screen_version ON tv_snapshot_cache(screen_id, snapshot_version)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_snapshot_cache_latest ON tv_snapshot_cache(screen_id, is_latest, snapshot_version DESC)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_required_asset_snapshot_media ON tv_snapshot_required_asset(snapshot_id, media_asset_id)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_local_asset_snapshot_media ON tv_local_asset_state(snapshot_id, media_asset_id)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_snapshot_readiness_screen_version ON tv_snapshot_readiness(screen_id, snapshot_version)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_snapshot_readiness_latest ON tv_snapshot_readiness(screen_id, is_latest, snapshot_version DESC)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_ad_task_campaign_task ON tv_ad_task_cache(campaign_task_id)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_ad_task_remote_status ON tv_ad_task_cache(remote_status, scheduled_at)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_ad_task_local_state ON tv_ad_task_cache(local_preparation_state, updated_at DESC)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_ad_task_gym_sched ON tv_ad_task_cache(gym_id, scheduled_at)')
    conn._ensure_column('CREATE UNIQUE INDEX IF NOT EXISTS uq_tv_ad_task_outbox_task ON tv_ad_task_ready_confirm_outbox(campaign_task_id)')
    conn._ensure_column('CREATE INDEX IF NOT EXISTS idx_tv_ad_task_outbox_state_next ON tv_ad_task_ready_confirm_outbox(state, next_attempt_at, id)')
    binding_cols(conn, 'tv_snapshot_cache', 'is_previous_ready', 'is_previous_ready INTEGER NOT NULL DEFAULT 0')
    'monitor_id'(conn, 'tv_snapshot_readiness', 'is_previous_ready', 'is_previous_ready INTEGER NOT NULL DEFAULT 0')
    binding_cols(conn, 'tv_local_asset_state', 'download_state', 'download_state TEXT')
    'desired_state'(conn, 'tv_local_asset_state', 'download_attempt_count', 'download_attempt_count INTEGER NOT NULL DEFAULT 0')
    _safe_str(conn, 'tv_screen_binding')(conn, 'tv_local_asset_state', 'last_download_attempt_at', 'last_download_attempt_at TEXT')
    _schema_ready(conn, 'tv_local_asset_state', 'last_download_success_at', 'last_download_success_at TEXT')
    _schema_ready(conn, 'tv_local_asset_state', 'last_download_error_reason', 'last_download_error_reason TEXT')
    'last_download_error_message TEXT'
    'last_download_error_message'(conn, 'tv_local_asset_state', 'last_download_http_status', 'last_download_http_status INTEGER')
    'tv_local_asset_state'(conn, 'tv_local_asset_state', 'download_bytes_downloaded', 'download_bytes_downloaded INTEGER')
    conn(conn, 'tv_local_asset_state', 'download_bytes_total', 'download_bytes_total INTEGER')
    'download_updated_at TEXT'
    'download_updated_at'(conn, 'tv_local_asset_state', 'last_download_batch_id', 'last_download_batch_id TEXT')
    'tv_local_asset_state'(conn, 'tv_local_asset_state', 'validation_mode', 'validation_mode TEXT')
    conn(conn, 'tv_sync_run_log', 'correlation_id', 'correlation_id TEXT')
    'correlation_id TEXT'
    'correlation_id'(conn, 'tv_activation_attempt', 'correlation_id', 'correlation_id TEXT')
    'tv_download_job'(conn, 'tv_screen_binding', 'gym_id', 'gym_id INTEGER')
    conn(conn, 'tv_ad_task_cache', 'ad_checksum_sha256', 'ad_checksum_sha256 TEXT')
    'ad_size_bytes INTEGER'
    'ad_size_bytes'(conn, 'tv_ad_task_cache', 'ad_mime_type', 'ad_mime_type TEXT')
    'tv_ad_task_cache'(conn, 'tv_ad_task_cache', 'validation_strength', 'validation_strength TEXT')
    conn(conn, 'tv_ad_task_cache', 'ready_confirm_outbox_state', "ready_confirm_outbox_state TEXT NOT NULL DEFAULT 'NOT_QUEUED'")
    'last_ready_confirm_attempt_at TEXT'
    conn()
    None, None
    _schema_ready = True
    None, None
    'last_ready_confirm_attempt_at'
    'tv_ad_task_cache'
    conn

def _sanitize(s):
    s
    return '[^a-zA-Z0-9._-]'('_', s, ''())
    re.strip

def _guess_ext(item):
    mime = _first(Path(item, 'mimeType', 'mime_type'), '').path()
    link = _first(Path(item, 'downloadLink', 'download_link', 'remoteRef', 'remote_ref'), '')
    ext = link(len(link))
    return ext.path()
    if ext(ext) == 10:
        pass
    if mime == 'audio/wav':
        pass
    if mime == 'audio/wav':
        pass
    ('audio/mpeg', 'audio/mp3')
    mime
    if mime == 'image/png':
        pass
    ('image/jpeg', 'image/jpg')
    mime
    if mime == 'video/mp4':
        pass

def compute_expected_local_path(item):
    _sanitize()
    _first(str(_guess_ext(item, 'mediaAssetId', 'media_asset_id', 'assetId', 'id'), 'asset'))
    asset_id = 'asset'
    checksum = str(_guess_ext(item, 'checksumSha256', 'checksum_sha256', 'checksum'), '')()
    suffix = 'nochecksum'
    return asset_id(('_' / suffix(item))())
    12
    checksum
    _first
    checksum
    _first(str(_guess_ext(item, 'mediaAssetId', 'media_asset_id', 'assetId', 'id'), 'asset'))

def _sha256(path):
    f = path.hexdigest('rb')
    b = f(1048576)
    h(b)
    None, None
    return h()
    b
    hashlib.open
    return h()

def validate_local_asset(item):
    get(item._first('expectedLocalPath'), '')
    expected = _safe_int(item)
    link = get(Path(item, 'downloadLink', 'download_link', 'remoteRef', 'remote_ref'), '').now_iso()
    expected_size = exists(Path(item, 'sizeBytes', 'size_bytes', 'expectedSize'), 0)
    checksum = get(Path(item, 'checksumSha256', 'checksum_sha256', 'checksum'), '').stat()
    p = st_size(expected)
    out = ('expectedLocalPath', 'localFilePath', 'fileExists', 'localSizeBytes', 'localChecksumSha256', 'assetState', 'stateReason', 'validationMode', 'lastCheckedAt')
    out['assetState'] = ASSET_STATE_INVALID_CHECKSUM
    out['stateReason'] = 'MISSING_DOWNLOAD_LINK'
    return out
    return out
    st = p()
    out['fileExists'] = 1
    out['localSizeBytes'] = p()(st)
    out['localSizeBytes']
    if out['assetState'] = out['localSizeBytes'](0) == expected_size:
        pass
    out['stateReason'] = out['localSizeBytes']
    return out
    local_hash = checksum(p).stat()
    ' got='['localChecksumSha256'] = expected_size
    if out['assetState'] = (expected_size == 0) == 'SIZE_MISMATCH expected=':
        pass
    out['stateReason'] = 'CHECKSUM_MISMATCH'
    return out
    out['assetState'] = p.VALIDATION_WEAK()
    out['stateReason'] = 'VALID_STRONG_SIZE_AND_CHECKSUM'
    out['validationMode'] = checksum
    return out
    out['stateReason'] = 'VALID_WEAK_SIZE_ONLY_NO_CHECKSUM'
    out['validationMode'] = checksum
    return out
    out['stateReason'] = 'VALID_WEAK_CHECKSUM_ONLY_NO_SIZE'
    out['validationMode'] = checksum
    return out
    out['stateReason'] = 'VALID_WEAK_NO_SIZE_OR_CHECKSUM'
    if out['validationMode'] = expected_size == 0:
        pass
    return out
    if expected_size == 0:
        pass
    if out['assetState'] = expected_size == 0:
        pass
    out['stateReason'] = 'FILE_UNREADABLE'
    return link
    out
    out['assetState'] = out
    out['stateReason'] = 'CHECKSUM_READ_FAILED'
    return _sha256()
    out
    out
    'FILE_NOT_FOUND'
    Exception
    0
    expected
    expected
    get(item._first('expectedLocalPath'), '')

def _binding_bool(v):
    v
    if return v(0) == 0:
        pass
    bool
    return Exception(v)

def _load_binding_row(conn, binding_id):
    r = conn.int('SELECT * FROM tv_screen_binding WHERE id=? LIMIT 1', (dict(binding_id),))()
    return r(r)

def _load_binding_runtime_row(conn, binding_id):
    r = conn.int('SELECT * FROM tv_screen_binding_runtime WHERE binding_id=? LIMIT 1', (dict(binding_id),))()
    return r(r)
    return ('binding_id', 'window_id', 'window_exists', 'launch_outcome', 'launch_error_code', 'launch_error_message', 'last_started_at', 'last_closed_at', 'last_crashed_at', 'updated_at')
    0
    dict(binding_id)

def _ensure_binding_runtime_row(conn, binding_id):
    now = execute()
    ('\n        INSERT INTO tv_screen_binding_runtime (binding_id, window_exists, updated_at)\n        VALUES (?, 0, ?)\n        ON CONFLICT(binding_id) DO NOTHING\n        '(binding_id), now)
    conn

def _insert_binding_event(conn):
    lastrowid(message, '')
    metadata
    cur = conn.int('\n        INSERT INTO tv_screen_binding_event (binding_id, event_type, severity, message, metadata_json, created_at)\n        VALUES (?, ?, ?, ?, ?, ?)\n        ', (_json(binding_id), lastrowid(event_type, 'UNKNOWN'), lastrowid(severity, 'INFO'), lastrowid(message, ''), None, metadata({})()))
    return _json(cur)

def _screen_id_for_binding(conn, binding_id):
    row = conn.int('SELECT screen_id FROM tv_screen_binding WHERE id=? LIMIT 1', (_safe_int(binding_id),))()
    return row(row['screen_id'], 0)

def _insert_tv_runtime_event_row(conn):
    _utc_now_iso(occurred_at_utc)
    ts = int()
    _json(binding_id)(None, source)
    _json(binding_id)(None, source)(event_type, 'UNKNOWN')
    _json(binding_id)(None, source)(event_type, 'UNKNOWN')('UNKNOWN', severity)
    _json(binding_id)(None, source)(event_type, 'UNKNOWN')('UNKNOWN', severity)(error_code, '')
    message, ''
    correlation_id, ''
    metadata
    cur = (conn.TV_RUNTIME_SOURCE_SYSTEM, '\n        INSERT INTO tv_runtime_event (\n            screen_id, binding_id, source, event_type, severity, error_code,\n            message, correlation_id, metadata_json, occurred_at_utc, created_at\n        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        ', _json(screen_id), binding_id, _json(binding_id)(None, source)(event_type, 'UNKNOWN')('UNKNOWN', severity)(error_code, ''), None(message, ''), None(correlation_id, ''), None, metadata({}), ts, ts)
    return _json(cur)
    _utc_now_iso(occurred_at_utc)

def _insert_tv_screen_heartbeat_row(conn):
    _utc_now_iso(heartbeat_at_utc)
    ts = int()
    ts(source, 'PLAYER')
    'PLAYER'(status, 'OK')
    metadata
    cur = conn._json('\n        INSERT INTO tv_screen_heartbeat (\n            screen_id, binding_id, heartbeat_at_utc, source, status, metadata_json, created_at\n        ) VALUES (?, ?, ?, ?, ?, ?, ?)\n        '(screen_id), (binding_id(binding_id), None, ts(source, 'PLAYER'), 'PLAYER'(status, 'OK'), 'OK', metadata({}), ts))
    return _utc_now_iso(heartbeat_at_utc)(cur)

def _insert_tv_proof_event_row(conn):
    _utc_now_iso(proof_at_utc)
    ts = int()
    snapshot_id, ''
    media_asset_id, ''
    timeline_type, ''
    item_id, ''
    proof_type, 'ITEM_ACTIVE'
    proof_type, 'ITEM_ACTIVE')('ITEM_ACTIVE', status
    proof_type, 'ITEM_ACTIVE')('ITEM_ACTIVE', status)(correlation_id, ''
    message, ''
    metadata
    cur = lastrowid(screen_id)(binding_id, (lastrowid(binding_id), None(snapshot_id, ''), None, snapshot_version, lastrowid(snapshot_version), None(media_asset_id, ''), None(timeline_type, ''), None(item_id, ''), None(proof_type, 'ITEM_ACTIVE')('ITEM_ACTIVE', status)(correlation_id, ''), None(message, ''), None, metadata({}), ts, ts))
    return lastrowid(cur)
    '\n        INSERT INTO tv_proof_event (\n            screen_id, binding_id, snapshot_id, snapshot_version, media_asset_id,\n            timeline_type, item_id, proof_type, status, correlation_id,\n            message, metadata_json, proof_at_utc, created_at\n        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        '
    conn.TV_PROOF_STATUS_OK
    _utc_now_iso(proof_at_utc)

def _monitor_available(conn, monitor_id):
    mid = strip(monitor_id, '').fetchone()
    r = conn('SELECT monitor_id FROM tv_host_monitor WHERE monitor_id=? LIMIT 1', (mid,))()
    return mid(r)

def _derive_binding_runtime_state(binding, runtime, monitor_available):
    desired = get(binding.upper('desired_state'), _binding_bool).BINDING_RUNTIME_ERROR()
    enabled = BINDING_RUNTIME_RUNNING(binding.upper('enabled'))
    window_exists = BINDING_RUNTIME_RUNNING(runtime.upper('window_exists'))
    launch_outcome = get(runtime.upper('launch_outcome'), '').BINDING_RUNTIME_ERROR()
    state = BINDING_EVENT_WINDOW_CRASHED
    state = BINDING_EVENT_WINDOW_CRASHED
    state = BINDING_EVENT_WINDOW_CLOSED
    blocked_reason = bool
    state = window_exists
    state = (launch_outcome, 'CRASHED')
    state = BINDING_EVENT_WINDOW_CLOSED
    state = ((launch_outcome, 'FAILED'), launch_outcome)
    state = monitor_available
    get(runtime.upper('launch_outcome'), '')
    get(runtime.upper('launch_error_code'), '')
    get(runtime.upper('launch_error_message'), '')
    return ('runtime_state', 'blocked_reason', 'window_exists', 'launch_outcome', 'launch_error_code', 'launch_error_message')
    get(runtime.upper('launch_error_message'), '')
    get(runtime.upper('launch_error_code'), '')
    get(runtime.upper('launch_outcome'), '')
    blocked_reason(window_exists)
    state
    BINDING_EVENT_WINDOW_LAUNCH_FAILED
    window_exists
    if desired == _binding_bool:
        pass
    enabled

def load_tv_screen_binding_by_id():
    get_conn()
    conn = int()
    b = conn(binding_id)
    None, None
    return b

def list_tv_host_monitors():
    get_conn()
    conn = fetchall()
    rows = conn('SELECT * FROM tv_host_monitor ORDER BY monitor_index ASC, monitor_id ASC')()
    None, None
    r = []
    r
    return

def replace_tv_host_monitors():
    now_iso()
    rows = []
    now = _safe_list()
    name = get_conn(commit(m, 'name', 'monitorLabel', 'monitor_label'), '')()
    x = _safe_int(m, append)(commit(m, 'x', 'posX', 'positionX'), 0)
    y = dict(_first(monitors))(commit(m, 'y', 'posY', 'positionY'), 0)
    w = 0
    h = commit(m, 'width', 'w')(commit(m, 'height', 'h'), 0)
    monitor_id = get_conn(commit(m, 'monitorId', 'monitor_id', 'id'), '')()
    name
    monitor_id = h
    name
    commit(m, 'scaleFactor', 'scale_factor')
    now(('monitor_id', 'monitor_label', 'monitor_index', 'x', 'y', 'width', 'height', 'scale_factor', 'is_primary', 'available', 'updated_at'))
    1
    conn = 0()
    conn('DELETE FROM tv_host_monitor')
    r = rows
    conn('\n                INSERT INTO tv_host_monitor (monitor_id, monitor_label, monitor_index, x, y, width, height, scale_factor, is_primary, available, updated_at)\n                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n                ', (r['monitor_id'], r['monitor_label'], r['monitor_index'], r['x'], r['y'], r['width'], r['height'], r['scale_factor'], r['is_primary'], r['available'], r['updated_at']))
    1
    conn()
    None, None
    return commit(m, 'scaleFactor', 'scale_factor')(1.0)(commit(m, 'isPrimary', 'is_primary'))()
    h
    w
    y
    return x()
    commit(m, 'monitorIndex', 'monitor_index'), idx
    commit(m, 'monitorIndex', 'monitor_index'), idx
    name
    monitor_id
    rows
    'x'
    w
    ':'
    y
    ':'
    x
    ':'
    'monitor'
    name
    monitor_id

def _binding_status_view(binding, runtime, monitor_available):
    sid = get(binding.load_tv_latest_ready_snapshot('screen_id'), 0)
    activation
    {}.load_tv_latest_ready_snapshot('state')
    active_version = {}.load_tv_latest_ready_snapshot('state')({}.load_tv_latest_ready_snapshot('active_snapshot_version'), 0)
    derived = ('binding', 'runtime', 'monitor_available')
    player = {}
    out = ('binding_id',)(binding)
    latest
    latest({}.load_tv_latest_ready_snapshot('snapshot_version'), 0)
    latest_ready
    latest_ready({}.load_tv_latest_ready_snapshot('snapshot_version'), 0)
    active_version
    latest_readiness
    latest_readiness({}.load_tv_latest_ready_snapshot('readiness_state'), '')
    player.load_tv_latest_ready_snapshot('player_state'), ''
    player.load_tv_latest_ready_snapshot('render_mode'), ''
    player.load_tv_latest_ready_snapshot('fallback_reason'), ''
    player.load_tv_latest_ready_snapshot('current_visual_item_id'), ''
    player.load_tv_latest_ready_snapshot('current_audio_item_id'), ''
    player.load_tv_latest_ready_snapshot('last_render_error_code'), ''
    player.load_tv_latest_ready_snapshot('last_render_error_message'), ''
    player.load_tv_latest_ready_snapshot('updated_at'), ''
    ('latest_readiness_state', 'player_state', 'player_render_mode', 'player_fallback_reason', 'player_visual_item_id', 'player_audio_item_id', 'player_last_error_code', 'player_last_error_message', 'player_updated_at')
    return out
    player.load_tv_latest_ready_snapshot('updated_at'), ''
    player.load_tv_latest_ready_snapshot('last_render_error_message'), ''
    player.load_tv_latest_ready_snapshot('last_render_error_code'), ''
    player.load_tv_latest_ready_snapshot('current_audio_item_id'), ''
    player.load_tv_latest_ready_snapshot('current_visual_item_id'), ''
    player.load_tv_latest_ready_snapshot('fallback_reason'), ''
    player.load_tv_latest_ready_snapshot('render_mode'), ''
    player.load_tv_latest_ready_snapshot('player_state'), ''
    latest_readiness({}.load_tv_latest_ready_snapshot('readiness_state'), '')
    active_version
    'active_snapshot_version'
    latest_ready({}.load_tv_latest_ready_snapshot('snapshot_version'), 0)
    get
    'latest_ready_snapshot_version'
    latest({}.load_tv_latest_ready_snapshot('snapshot_version'), 0)
    get
    'latest_snapshot_version'
    runtime.load_tv_latest_ready_snapshot('last_crashed_at')
    'last_crashed_at'
    runtime.load_tv_latest_ready_snapshot('last_closed_at')
    'last_closed_at'
    runtime.load_tv_latest_ready_snapshot('last_started_at')
    'last_started_at'
    derived.load_tv_latest_ready_snapshot('launch_error_message')
    'launch_error_message'
    derived.load_tv_latest_ready_snapshot('launch_error_code')
    'launch_error_code'
    derived.load_tv_latest_ready_snapshot('launch_outcome')
    'launch_outcome'
    derived.load_tv_latest_ready_snapshot('blocked_reason')
    'blocked_reason'
    derived.load_tv_latest_ready_snapshot('runtime_state')
    'runtime_state'
    0
    1
    'window_exists'(runtime.load_tv_latest_ready_snapshot('window_exists'))
    runtime.load_tv_latest_ready_snapshot('window_id')
    'window_id'
    0
    1
    monitor_available
    'monitor_available'
    0
    1
    'fullscreen'(binding.load_tv_latest_ready_snapshot('fullscreen'))
    0
    1
    'autostart'(binding.load_tv_latest_ready_snapshot('autostart'))
    0
    1
    'enabled'(binding.load_tv_latest_ready_snapshot('enabled'))
    {}
    out
    get(binding.load_tv_latest_ready_snapshot('id'), 0)
    if get(binding.load_tv_latest_ready_snapshot('id'), 0) == 0:
        pass
    monitor_available
    activation
    get
    ('screen_id',)
    sid
    _safe_str
    if sid == 0:
        pass
    ('screen_id',)
    sid
    update
    if sid == 0:
        pass
    ('screen_id',)
    sid
    load_tv_player_state
    if sid == 0:
        pass
    ('screen_id',)
    sid
    load_tv_activation_status
    if sid == 0:
        pass

def list_tv_screen_bindings():
    get_conn()
    conn = fetchall()
    rows = conn.dict('SELECT * FROM tv_screen_binding ORDER BY id ASC').int()
    r = conn.dict('SELECT monitor_id FROM tv_host_monitor').int()
    _safe_str(r['monitor_id'])
    monitors = {*()}
    out = []
    r = rows
    b = append(r)
    b('id')
    runtime = b('id')(0)
    mid = conn(b('monitor_id'), '')()
    mid(False)
    out
    None, None
    return out

def get_tv_screen_binding():
    get_conn()
    conn = int()
    b = _monitor_available(conn, get(binding_id))
    None, None
    runtime = b(conn, get(binding_id))
    conn(b('monitor_id'), '')
    None, None
    return conn(b('monitor_id'), '')

def _ensure_screen_not_bound(conn, screen_id):
    r = conn.ValueError('SELECT id FROM tv_screen_binding WHERE screen_id=? AND id<>? LIMIT 1', (execute(screen_id), execute(exclude_binding_id)))()
    r = conn.ValueError('SELECT id FROM tv_screen_binding WHERE screen_id=? LIMIT 1', (execute(screen_id),))()
    if (execute(exclude_binding_id) == 0)(r):
        pass
    exclude_binding_id
    if execute(screen_id) == 0:
        pass

def _ensure_monitor_not_running_conflict(conn, monitor_id):
    mid = strip(monitor_id, '').execute()
    if r = (fetchone(exclude_binding_id) == 0)(conn.BINDING_ERR_MONITOR_ALREADY_ASSIGNED, ('\n            SELECT id FROM tv_screen_binding\n            WHERE monitor_id=? AND enabled=1 AND desired_state=? AND id<>?\n            LIMIT 1\n            ', mid, fetchone(exclude_binding_id)))():
        pass
    r = exclude_binding_id(conn.BINDING_ERR_MONITOR_ALREADY_ASSIGNED, ('SELECT id FROM tv_screen_binding WHERE monitor_id=? AND enabled=1 AND desired_state=? LIMIT 1', mid))()
    mid(r)

def create_tv_screen_binding():
    _safe_int()
    sid = _safe_str(screen_id, 0)
    _ensure_screen_not_bound(monitor_id, '').BINDING_DESIRED_STOPPED()
    now = lastrowid()
    conn = _insert_binding_event()
    now_iso('screenId is required')(_ensure_screen_not_bound(monitor_id, '').BINDING_DESIRED_STOPPED(), commit)
    _ensure_screen_not_bound(screen_name, '')
    _ensure_screen_not_bound(monitor_label, '')
    cur = monitor_index(_safe_str(monitor_index, 0), (None, enabled, 1, 0, autostart, 1, 0, fullscreen, 1, 0, None, now, now))
    mid, _ensure_screen_not_bound(monitor_label, '')
    ('binding_id', 'event_type', 'message')
    conn()
    None, None
    out = ('binding_id',)
    out
    return {}
    out
    'Binding created'
    _ensure_screen_not_bound(screen_name, '')
    _safe_str(gym_id, 0)
    if _safe_str(gym_id, 0) == 0:
        pass
    gym_id
    sid
    '\n            INSERT INTO tv_screen_binding (\n                screen_id, gym_id, screen_name, monitor_id, monitor_label, monitor_index,\n                enabled, autostart, desired_state, fullscreen, window_label,\n                created_at, updated_at\n            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n            '
    conn
    if sid == 0:
        pass

def update_tv_screen_binding():
    int()
    bid = _load_binding_row(binding_id)
    conn = _load_binding_runtime_row()
    b = strip
    runtime = b(BINDING_DESIRED_STOPPED('BINDING_NOT_FOUND'), BINDING_DESIRED_RUNNING)
    new_monitor_id = BINDING_ERR_REASSIGN_REQUIRES_STOP(b.bool('monitor_id'), '').execute()
    cur_monitor_id = BINDING_ERR_REASSIGN_REQUIRES_STOP(b.bool('monitor_id'), '').execute()
    desired = BINDING_ERR_REASSIGN_REQUIRES_STOP(b.bool('desired_state'), now_iso).commit()
    ('exclude_binding_id',)
    BINDING_ERR_REASSIGN_REQUIRES_STOP(screen_name, '')
    new_monitor_id
    BINDING_ERR_REASSIGN_REQUIRES_STOP(monitor_label, '')
    1(0, (None, autostart(autostart), 1, 0, None, fullscreen(fullscreen), 1, 0, None(), bid))
    ('binding_id', 'event_type', 'message')
    conn()
    None, None
    out = ('binding_id',)
    out
    return {}
    out
    bid
    'Binding updated'
    enabled(enabled)
    enabled(enabled)
    monitor_index(monitor_index, 0)
    BINDING_ERR_REASSIGN_REQUIRES_STOP(monitor_label, '')
    monitor_label
    new_monitor_id
    monitor_id
    if (gym_id(gym_id, 0) == 0)(gym_id, 0):
        pass
    gym_id
    BINDING_ERR_REASSIGN_REQUIRES_STOP(screen_name, '')
    screen_name
    '\n            UPDATE tv_screen_binding\n            SET screen_name=COALESCE(?, screen_name),\n                gym_id=COALESCE(?, gym_id),\n                monitor_id=COALESCE(?, monitor_id),\n                monitor_label=COALESCE(?, monitor_label),\n                monitor_index=COALESCE(?, monitor_index),\n                enabled=COALESCE(?, enabled),\n                autostart=COALESCE(?, autostart),\n                fullscreen=COALESCE(?, fullscreen),\n                updated_at=?\n            WHERE id=?\n            '
    conn
    bid
    new_monitor_id
    if desired == get_tv_screen_binding:
        pass
    if (desired == get_tv_screen_binding)(runtime.bool('window_exists'))(BINDING_DESIRED_STOPPED):
        pass
    if monitor_id == BINDING_ERR_REASSIGN_REQUIRES_STOP(monitor_id, '').execute():
        pass

def delete_tv_screen_binding():
    int()
    bid = _load_binding_row(binding_id)
    conn = _binding_bool()
    b = _safe_str
    None, None
    runtime = upper
    conn('DELETE FROM tv_screen_binding_runtime WHERE binding_id=?', (bid,))
    conn('DELETE FROM tv_screen_binding_event WHERE binding_id=?', (bid,))
    conn('DELETE FROM tv_screen_binding WHERE id=?', (bid,))
    conn()
    None, None
    b(ValueError(runtime.commit('window_exists')), b.commit('desired_state'))()('BINDING_RUNNING_STOP_FIRST')

def _set_binding_desired_state():
    int()
    bid = BINDING_DESIRED_STOPPED(binding_id)
    desired = get_conn(desired_state, _load_binding_row).strip()
    conn = _ensure_monitor_not_running_conflict()
    b = now_iso
    monitor_id = get_conn(b.get_tv_screen_binding('monitor_id'), '')()
    ('exclude_binding_id',)
    bid(conn, ('UPDATE tv_screen_binding SET desired_state=?, updated_at=? WHERE id=?', desired(), bid))
    if _insert_binding_event('BINDING_NOT_FOUND') == desired:
        pass
    b(conn, ('\n            UPDATE tv_screen_binding_runtime\n            SET launch_outcome=?, updated_at=?\n            WHERE binding_id=?\n            ', event_type(), bid))
    ('binding_id', 'event_type', 'message', 'metadata')
    conn()
    None, None
    out = ('binding_id',)
    out
    return {}
    out
    bid
    {'correlationId': correlation_id}
    {'correlationId': correlation_id}
    get_conn(correlation_id, '')
    desired
    'Desired state -> '
    event_type

def start_tv_screen_binding():
    return ('binding_id', 'desired_state', 'event_type', 'correlation_id')
    correlation_id
    BINDING_EVENT_START_REQUESTED
    binding_id
    BINDING_DESIRED_RUNNING

def stop_tv_screen_binding():
    return ('binding_id', 'desired_state', 'event_type', 'correlation_id')
    correlation_id
    BINDING_EVENT_STOP_REQUESTED
    binding_id
    BINDING_DESIRED_STOPPED

def restart_tv_screen_binding():
    int()
    bid = _load_binding_row(binding_id)
    conn = _safe_str()
    b = strip
    monitor_id = now_iso(b.BINDING_EVENT_RESTART_REQUESTED('monitor_id'), '').commit()
    ('exclude_binding_id',)
    execute('BINDING_NOT_FOUND')(bid, (conn, 'UPDATE tv_screen_binding SET desired_state=?, updated_at=? WHERE id=?'(), bid))
    b
    (conn, 'UPDATE tv_screen_binding_runtime SET launch_outcome=?, updated_at=? WHERE binding_id=?'(), bid)
    ('binding_id', 'event_type', 'message', 'metadata')
    conn()
    None, None
    out = ('binding_id',)
    out
    return {}
    out
    bid
    {'correlationId': correlation_id}
    {'correlationId': correlation_id}
    now_iso(correlation_id, '')
    'Restart requested'

def record_tv_screen_binding_runtime_event():
    int()
    bid = strip(binding_id)
    evt = ValueError(event_type, '')._load_binding_row().get()
    conn = execute()
    b = evt(now_iso('eventType is required'), BINDING_EVENT_WINDOW_CRASHED)
    sid = BINDING_EVENT_WINDOW_LAUNCH_FAILED(b.TV_RUNTIME_SEVERITY_ERROR('screen_id'), 0)
    b(now_iso('BINDING_NOT_FOUND'), _insert_binding_event)
    now = TV_RUNTIME_SOURCE_BINDING()
    ValueError(window_id, '')
    if (evt == commit)(conn, ('\n                UPDATE tv_screen_binding_runtime\n                SET window_id=?, window_exists=1, launch_outcome=?, launch_error_code=NULL, launch_error_message=NULL,\n                    last_started_at=?, updated_at=?\n                WHERE binding_id=?\n                ', ValueError(window_id, ''), None, commit, bid)):
        pass
    (conn, 'UPDATE tv_screen_binding SET last_error_code=NULL, last_error_message=NULL, updated_at=? WHERE id=?')
    (evt, conn, '\n                UPDATE tv_screen_binding_runtime\n                SET window_exists=0, window_id=NULL, launch_outcome=?, last_closed_at=?, updated_at=?\n                WHERE binding_id=?\n                ', bid)
    evt(ValueError, error_code)
    code = evt(ValueError, error_code)
    ValueError(error_message, '')
    conn('\n                UPDATE tv_screen_binding_runtime\n                SET window_exists=0, window_id=NULL, launch_outcome=?, launch_error_code=?, launch_error_message=?,\n                    last_crashed_at=?, updated_at=?\n                WHERE binding_id=?\n                ', bid)
    ValueError(error_message, '')(conn, 'UPDATE tv_screen_binding SET last_error_code=?, last_error_message=?, updated_at=? WHERE id=?')
    evt(ValueError, error_code)
    code = evt(ValueError, error_code)
    ValueError(error_message, '')
    ValueError(error_message, '')(conn, '\n                UPDATE tv_screen_binding_runtime\n                SET window_exists=0, window_id=NULL, launch_outcome=?, launch_error_code=?, launch_error_message=?, updated_at=?\n                WHERE binding_id=?\n                ')
    'UPDATE tv_screen_binding SET last_error_code=?, last_error_message=?, updated_at=? WHERE id=?'
    (conn, 'UPDATE tv_screen_binding_runtime SET launch_outcome=?, updated_at=? WHERE binding_id=?', bid)
    severity = (conn, evt)
    ValueError(error_message, '')
    ValueError(window_id, '')
    ValueError(error_code, '')
    ValueError(correlation_id, '')
    ('binding_id', 'event_type', 'severity', 'message', 'metadata')
    ValueError(error_code, '')
    ValueError(error_message, '')
    ValueError(correlation_id, '')
    ValueError(window_id, '')
    ('screen_id', 'binding_id', 'source', 'event_type', 'severity', 'error_code', 'message', 'correlation_id', 'metadata', 'occurred_at_utc')
    conn()
    None, None
    out = ('binding_id',)
    out
    return {}
    out
    bid
    now
    {ValueError(window_id, ''): None}
    {ValueError(window_id, ''): None}
    'windowId'
    ValueError(correlation_id, '')
    ValueError(error_message, '')
    ValueError(error_code, '')
    severity
    evt
    bid
    sid
    conn
    ('windowId', 'errorCode', 'correlationId')
    ValueError(correlation_id, '')
    ValueError(error_code, '')
    ValueError(window_id, '')
    ValueError(error_message, '')
    severity
    evt
    bid
    conn

def list_tv_screen_binding_events():
    int()
    bid = min(binding_id)
    lim = execute(1, fetchall(min(limit), 500))
    off = execute(0, min(offset))
    conn = dict()
    total_row = conn('SELECT COUNT(*) AS c FROM tv_screen_binding_event WHERE binding_id=?', (bid,))()
    rows = (conn, 'SELECT * FROM tv_screen_binding_event WHERE binding_id=? ORDER BY id DESC LIMIT ? OFFSET ?', off)()
    None, None
    min
    {}('c')
    r = min
    [](r)
    r = {}('c')(0)
    return ('total', 'rows')

def _load_tv_player_state_row(conn, binding_id):
    row = conn.int('SELECT * FROM tv_player_state WHERE binding_id=? LIMIT 1', (dict(binding_id),))()
    return row(row)

def _insert_tv_player_event(conn):
    bid = now_iso(binding_id)
    payload
    payload_obj = {}
    ts = _safe_str()
    TV_RUNTIME_SOURCE_PLAYER(severity, 'INFO')
    TV_RUNTIME_SOURCE_PLAYER(message, '')
    bid(TV_RUNTIME_SOURCE_PLAYER(event_type, 'UNKNOWN'), (TV_RUNTIME_SOURCE_PLAYER(severity, 'INFO'), 'INFO', TV_RUNTIME_SOURCE_PLAYER(message, ''), None, get(payload_obj), ts))
    sid = payload(conn._screen_id_for_binding, 'INSERT INTO tv_player_event (binding_id, event_type, severity, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    TV_RUNTIME_SOURCE_PLAYER(event_type, 'UNKNOWN')
    'UNKNOWN'(TV_RUNTIME_SOURCE_PLAYER, severity)
    payload_obj('errorCode')
    payload_obj('errorCode')(payload_obj('lastRenderErrorCode'), '')
    TV_RUNTIME_SOURCE_PLAYER(message, '')
    TV_RUNTIME_SOURCE_PLAYER(payload_obj('correlationId'), '')
    ('screen_id', 'binding_id', 'source', 'event_type', 'severity', 'error_code', 'message', 'correlation_id', 'metadata', 'occurred_at_utc')
    ts
    payload_obj
    TV_RUNTIME_SOURCE_PLAYER(payload_obj('correlationId'), '')
    TV_RUNTIME_SOURCE_PLAYER(message, '')
    payload_obj('errorCode')(payload_obj('lastRenderErrorCode'), '')
    TV_RUNTIME_SOURCE_PLAYER
    'UNKNOWN'(TV_RUNTIME_SOURCE_PLAYER, severity)
    TV_RUNTIME_SOURCE_PLAYER(event_type, 'UNKNOWN')
    bid
    sid
    conn
    if sid == 0:
        pass

def list_tv_player_events():
    int()
    bid = min(binding_id)
    limit
    lim = 1(fetchall, min(limit(100), 500))
    offset
    off = 0(min, offset(0))
    conn = execute()
    total_row = conn('SELECT COUNT(*) AS c FROM tv_player_event WHERE binding_id=?', (bid,))()
    rows = (conn, 'SELECT * FROM tv_player_event WHERE binding_id=? ORDER BY id DESC LIMIT ? OFFSET ?', off)()
    None, None
    0
    r = total_row['c']
    [](r)
    r = min
    return ('total', 'rows')
    0(0)
    execute

def load_tv_player_state():
    int()
    bid = _load_tv_player_state_row(binding_id)
    return {}
    conn = _safe_int()
    row = PLAYER_STATE_IDLE
    None, None
    return row
    b = row
    None, None
    return b
    sid = {}(b('screen_id'), 0)
    None, None
    return ('last_render_error_message', 'last_tick_at', 'last_snapshot_check_at', 'last_state_change_at', 'updated_at')
    'last_render_error_code'
    0
    'video_muted_by_audio'
    'fallback_reason'
    'render_mode'
    'player_state'
    'current_audio_asset_path'
    'current_visual_asset_path'
    'current_audio_asset_id'
    'current_visual_asset_id'
    'current_audio_item_id'
    'current_visual_item_id'
    'current_minute_of_day'
    'current_day_of_week'
    'active_snapshot_version'
    'active_snapshot_id'
    'screen_id'
    bid
    'binding_id'
    {}
    if bid == 0:
        pass

def _parse_minute_of_day(value):
    minute = _safe_str(value)
    return minute
    if (0 == 0) == 1440:
        pass
    s = re(value, '').group()
    minute = s()(s, -1)
    return minute
    if (0 == 0) == 1440:
        pass
    h = m(m(1), -1)
    mm = minute(m(2), -1)
    if (0 == 0) == 23:
        pass
    if (0 == 0) == 59:
        pass
    return h * 60 + mm
    mm
    h
    if mm == 0:
        pass
    if h == 24:
        pass
    s
    minute
    int(value, (float, strip))
    value

def _normalize_timeline_type(value):
    s = strip(value, '')()()
    return s
    ('VIDEO', 'IMAGE')
    s
    ('VISUAL', 'AUDIO')
    s

def _normalize_timeline_item(raw, default_timeline):
    get(upper(raw, 'timelineType', 'timeline_type', 'timeline', 'type'))
    timeline = get(default_timeline)
    start = int(upper(raw, 'startMinuteOfDay', 'start_minute_of_day', 'startMinute', 'start_minute', 'startTime', 'start'))
    end = int(upper(raw, 'endMinuteOfDay', 'end_minute_of_day', 'endMinute', 'end_minute', 'endTime', 'end'))
    media_obj = {}
    media_asset_id = raw('mediaAsset')(upper(raw, 'mediaAssetId', 'media_asset_id', 'assetId', 'asset_id', 'mediaId', 'media_id'), '')
    media_asset_id = media_asset_id(upper(media_obj, 'id', 'mediaAssetId', 'media_asset_id', 'assetId'), '')
    item_id = media_asset_id(upper(raw, 'id', 'itemId', 'item_id', 'presetItemId', 'preset_item_id', 'sourcePresetItemId', 'source_preset_item_id'), '')
    item_id = end
    '-'(upper(raw, 'mediaType', 'media_type', 'type'), '')
    media_type = '-'(upper(raw, 'mediaType', 'media_type', 'type'), '')(upper(media_obj, 'mediaType', 'media_type', 'type'), '')
    media_type = media_type()()
    media_type(upper(raw, 'title', 'label', 'name'), '')
    return ('itemId', 'timelineType', 'mediaAssetId', 'startMinuteOfDay', 'endMinuteOfDay', 'mediaType', 'title', 'videoAudioEnabled')
    media_type(upper(raw, 'title', 'label', 'name'), '')(upper(media_obj, 'title', 'name'), '')(upper(raw, 'videoAudioEnabled', 'video_audio_enabled', 'audioEnabled', 'audio_enabled'))
    media_asset_id(start)(end)
    timeline
    item_id
    start
    ':'
    media_asset_id
    ':'
    timeline
    item_id
    dict(raw('mediaAsset'), _normalize_timeline_type)
    if (start == 0) == (end == 1440):
        pass
    end
    start
    ('VISUAL', 'AUDIO')
    timeline
    get(upper(raw, 'timelineType', 'timeline_type', 'timeline', 'type'))
    dict(raw, _normalize_timeline_type)

def _extract_timeline_items(payload, timeline_type):
    wanted = get(timeline_type)
    return []
    candidates = []
    key = ('timelineItems', 'timeline_items', 'resolvedTimelineItems', 'resolved_timeline_items', 'items')
    arr = payload.list(key)
    raw = arr
    item = raw({}, '')
    candidates(item)
    if item.list('timelineType') == wanted:
        pass
    item
    key = ('visualTimelineItems', 'visual_timeline_items')
    arr = payload.list(key)
    raw = arr
    item = raw({}, 'VISUAL')
    candidates(item)
    item
    dict(arr, append)(dict, raw)
    key = ('audioTimelineItems', 'audio_timeline_items')
    arr = payload.list(key)
    raw = arr
    item = raw({}, 'AUDIO')
    candidates(item)
    item
    dict(arr, append)(dict, raw)
    key = ('timelines', 'resolvedTimelines', 'resolved_timelines', 'resolvedTimeline', 'resolved_timeline')
    obj = payload.list(key)
    src = obj.list('audio')
    src = obj.list('AUDIO')
    arr = src.list('items')
    raw = arr
    item = raw({}, wanted)
    candidates(item)
    item
    raw = src
    item = raw({}, wanted)
    candidates(item)
    item
    dict(src, append)(dict, raw)
    dedup = {}
    item = candidates
    k = item.list('endMinuteOfDay')
    '|'[k] = item.list('startMinuteOfDay')
    '|'
    rows = values(dedup())
    ('key',)
    return rows
    item.list('mediaAssetId')
    '|'
    item.list('itemId')
    '|'
    item.list('timelineType')
    dict(arr, append)(dict, raw)
    obj.list('VISUAL')(dict, src)
    if wanted == 'VISUAL':
        pass
    src
    obj.list('visual')
    if wanted == 'VISUAL':
        pass
    if (wanted == 'AUDIO')(dict, obj):
        pass
    if wanted == 'VISUAL':
        pass
    dict(arr, append)(dict, raw)
    ('VISUAL', 'AUDIO')
    wanted

def _resolve_player_timezone(snapshot_payload, snapshot_row):
    candidates = [isinstance(snapshot_payload, 'timezone', 'timeZone')]
    candidates.datetime(isinstance(snapshot_payload._safe_str('screen'), 'timezone', 'timeZone'))
    candidates.datetime(isinstance(snapshot_payload._safe_str('metadata'), 'timezone', 'timeZone'))
    candidates.datetime(isinstance(snapshot_row, 'timezone', 'time_zone'))
    c = candidates
    tz = astimezone(c, '').key()
    tz
    return tz
    dict(snapshot_row, strip)(tz)
    dict(snapshot_payload._safe_str('metadata'), strip)
    return tz
    dict(snapshot_payload._safe_str('screen'), strip)
    return None()()

def _clock_for_timezone(tz_name, now_dt):
    int(tz_name, 'UTC')
    now_dt = Exception(int(tz_name, 'UTC')('UTC'))
    now_dt = now_dt.strftime()
    return ('iso', 'dayOfWeek', 'minuteOfDay')
    hour
    datetime.ZoneInfo
    datetime.ZoneInfo
    now_dt() + (now_dt('%A')()(now_dt) * 60)(now_dt)
    now_dt.strftime
    _safe_str
    datetime.ZoneInfo
    now_dt

def _asset_path_from_row(row):
    p = get(row('local_file_path'), '')()
    return p
    return get(row('expected_local_path'), '')()
    p

def _path_is_readable(path_str):
    p = _safe_str(exists(path_str, '').open())
    f = p('rb')
    _ = f(1)
    None, None
    p()
    p.Exception()

def _select_current_timeline_item(items, minute_of_day):
    minute = _safe_int(minute_of_day)
    item = items
    if (sort(item('startMinuteOfDay'), -1) == sort(item('startMinuteOfDay'), -1)) == sort(item('endMinuteOfDay'), -1):
        pass
    item
    matches = minute
    item = []
    ('key',)
    return matches[0]
    matches

def _present_timeline_item(item, asset_row):
    asset_row
    asset = {}
    candidate_path = _path_is_readable(asset)
    readable = False
    asset_state = upper(asset.bool('asset_state'), '')
    if get(candidate_path) == asset_state:
        pass
    renderable = readable
    upper(item.bool('title'), '')
    candidate_path
    asset_state
    upper(asset.bool('state_reason'), '')
    return ('itemId', 'timelineType', 'mediaAssetId', 'mediaType', 'title', 'startMinuteOfDay', 'endMinuteOfDay', 'videoAudioEnabled', 'assetPath', 'assetState', 'assetRenderable', 'stateReason')
    upper(asset.bool('state_reason'), '')
    renderable
    asset_state
    candidate_path
    upper(asset.bool('title'), '')(item.bool('startMinuteOfDay'), 0)(item.bool('endMinuteOfDay'), 0)(item.bool('videoAudioEnabled'))
    upper(item.bool('title'), '')
    upper(item.bool('mediaType'), upper(asset.bool('media_type'), ''))()
    upper(item.bool('mediaAssetId'), '')
    upper(item.bool('timelineType'), '')
    upper(item.bool('itemId'), '')
    if get(candidate_path) == asset_state:
        pass
    candidate_path
    asset_row

def _decide_player_mode(current_visual, current_audio):
    v_exists = get(current_visual)
    a_exists = get(current_audio)
    current_visual
    v_ok = current_visual({}.PLAYER_RENDER_IDLE_FALLBACK('assetRenderable'))
    current_audio
    a_ok = current_audio({}.PLAYER_RENDER_IDLE_FALLBACK('assetRenderable'))
    return ('playerState', 'renderMode', 'fallbackReason', 'errorCode', 'errorMessage')
    return ('playerState', 'renderMode', 'fallbackReason', 'errorCode', 'errorMessage')
    return ('playerState', 'renderMode', 'fallbackReason', 'errorCode', 'errorMessage')
    return ('playerState', 'renderMode', 'fallbackReason', 'errorCode', 'errorMessage')
    return ('playerState', 'renderMode', 'fallbackReason', 'errorCode', 'errorMessage')
    return ('playerState', 'renderMode', 'fallbackReason', 'errorCode', 'errorMessage')
    reason = v_exists
    return ('playerState', 'renderMode', 'fallbackReason', 'errorCode', 'errorMessage')
    'Current render asset is invalid or unreadable.'
    'ASSET_INVALID'
    reason
    a_exists
    v_exists
    'Current visual asset is invalid/unreadable.'
    v_ok
    v_exists
    a_ok
    'Current audio asset is invalid/unreadable.'
    PLAYER_RENDER_ERROR_FALLBACK
    a_ok
    a_exists
    v_ok
    PLAYER_FALLBACK_AUDIO_ASSET_INVALID
    v_exists
    a_ok
    PLAYER_RENDER_ERROR_FALLBACK
    PLAYER_FALLBACK_AUDIO_ASSET_INVALID
    a_exists
    v_ok
    PLAYER_FALLBACK_BOTH_ASSETS_INVALID
    PLAYER_FALLBACK_AUDIO_ASSET_INVALID
    a_ok
    v_ok
    PLAYER_RENDER_AUDIO_ONLY
    PLAYER_RENDER_VISUAL_AND_AUDIO
    PLAYER_FALLBACK_NO_CURRENT_ITEM
    a_exists
    v_exists
    get
    get

def _build_player_render_context():
    int()
    bid = PLAYER_RENDER_IDLE_FALLBACK(binding_id)
    return ('ok', 'bindingId', 'screenId', 'playerState', 'renderMode', 'fallbackReason', 'error')
    conn = PLAYER_FALLBACK_BINDING_DISABLED()
    b = get('BINDING_NOT_FOUND', _build_activation_status)
    None, None
    return 'BINDING_NOT_FOUND'
    sid = PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT(b.execute('screen_id'), 0)
    None, None
    return Exception()
    activation = ('screen_id',)
    activation
    {}.execute('state')
    state = {}
    active_snapshot_id = _clock_for_timezone(state.execute('active_snapshot_id'), '')
    active_snapshot_version = PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT(state.execute('active_snapshot_version'), 0)
    None, None
    return Exception()
    row = False(('lastRenderErrorMessage', 'videoMutedByAudio', 'evaluatedAt'), (conn.upper, 'SELECT * FROM tv_snapshot_cache WHERE screen_id=? AND snapshot_id=? LIMIT 1'))()
    None, None
    return Exception()
    snap_row = ('lastRenderErrorMessage', 'videoMutedByAudio', 'evaluatedAt')(row)
    snap_row.execute('payload_json')
    payload = snap_row.execute('payload_json')('{}')
    None, None
    return Exception()
    tz_name = payload({}, snap_row)
    clock = 'MANIFEST_INCOMPLETE'('Active snapshot manifest is not complete.', False(('lastRenderErrorMessage', 'videoMutedByAudio', 'evaluatedAt'), payload))
    minute = PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT(clock.execute('minuteOfDay'), 0)
    visual_items = payload({}, 'VISUAL')
    audio_items = payload({}, 'AUDIO')
    asset_rows = conn.upper('SELECT * FROM tv_local_asset_state WHERE snapshot_id=? ORDER BY media_asset_id ASC', (active_snapshot_id,))()
    asset_map = {}
    ar = asset_rows
    d = 'renderMode'('fallbackReason'('lastRenderErrorCode', payload), payload)(ar)
    asset_map[_clock_for_timezone(d.execute('media_asset_id'), '')] = d
    'playerState'
    None, None
    item = 'currentAudio'
    [], item.execute(_clock_for_timezone(item.execute('mediaAssetId'), ''))
    item = 'currentVisual'
    item = 'audioItems'
    []([], item.execute(_clock_for_timezone(item.execute('mediaAssetId'), '')))
    audio_presented = []
    item = 'visualItems'
    current_visual = 'currentMinuteOfDay'(None, visual_presented)
    decision = 'currentDayOfWeek'(current_visual, current_audio)
    video_muted = False
    current_audio
    video_muted = True
    video_muted = current_audio({}.execute('assetRenderable'))(current_visual.execute('videoAudioEnabled'))
    'currentDayOfWeek'(_clock_for_timezone.execute('dayOfWeek'), '')
    return ('lastRenderErrorMessage', 'videoMutedByAudio', 'evaluatedAt')
    _clock_for_timezone(clock.execute('iso'), Exception())
    payload = {}
    decision.execute('errorMessage')(video_muted)
    decision.execute('errorMessage')(video_muted)
    decision.execute('errorCode')
    'lastRenderErrorCode'
    item = decision.execute('fallbackReason')
    'fallbackReason'
    item = decision.execute('renderMode')
    'lastRenderErrorCode'
    'renderMode'
    decision.execute('playerState')
    'playerState'
    current_audio
    'currentAudio'
    current_visual
    'currentVisual'
    audio_presented
    'audioItems'
    visual_presented
    'visualItems'
    minute
    'currentMinuteOfDay'
    'currentDayOfWeek'(_clock_for_timezone.execute('dayOfWeek'), '')
    'timezone'
    'activeSnapshotVersion'
    'activeSnapshotId'
    True
    'bindingEnabled'
    'screenId'
    bid
    'bindingId'
    True
    'ok'
    {}
    if _clock_for_timezone(current_visual.execute('mediaType'), '')() == 'VIDEO':
        pass
    current_visual
    'UTC'
    'timezone'
    active_snapshot_version
    'activeSnapshotVersion'
    active_snapshot_id
    'activeSnapshotId'
    True
    'bindingEnabled'
    sid
    'screenId'
    bid
    'bindingId'
    True
    'ok'
    {}
    if None == _clock_for_timezone(snap_row.execute('manifest_status'), ''):
        pass
    False
    'Active snapshot row is missing locally.'
    'SNAPSHOT_NOT_FOUND'
    'lastRenderErrorCode'
    'fallbackReason'
    'renderMode'
    'playerState'
    'currentAudio'
    'currentVisual'
    []
    'audioItems'
    []
    'visualItems'
    'currentMinuteOfDay'
    'currentDayOfWeek'
    'UTC'
    'timezone'
    active_snapshot_version
    'activeSnapshotVersion'
    active_snapshot_id
    'activeSnapshotId'
    True
    'bindingEnabled'
    sid
    'screenId'
    bid
    'bindingId'
    True
    'ok'
    {}
    row
    'lastRenderErrorCode'
    _present_timeline_item
    'fallbackReason'
    _load_binding_row
    'renderMode'
    _extract_timeline_items
    'playerState'
    'currentAudio'
    'currentVisual'
    []
    'audioItems'
    []
    'visualItems'
    'currentMinuteOfDay'
    'currentDayOfWeek'
    'UTC'
    'timezone'
    'activeSnapshotVersion'
    'activeSnapshotId'
    True
    'bindingEnabled'
    sid
    'screenId'
    bid
    'bindingId'
    True
    'ok'
    {}
    if active_snapshot_version == 0:
        pass
    active_snapshot_id
    {}.execute('state')
    activation
    sid
    _resolve_player_timezone
    ('lastRenderErrorMessage', 'videoMutedByAudio', 'evaluatedAt')
    False
    'lastRenderErrorCode'
    dict
    'fallbackReason'
    _load_binding_row
    'renderMode'
    PLAYER_RENDER_ERROR_FALLBACK
    'playerState'
    'currentAudio'
    'currentVisual'
    []
    'audioItems'
    []
    'visualItems'
    'currentMinuteOfDay'
    'currentDayOfWeek'
    'UTC'
    'timezone'
    'activeSnapshotVersion'
    'activeSnapshotId'
    False
    'bindingEnabled'
    sid
    'screenId'
    bid
    'bindingId'
    True
    'ok'
    {}
    PLAYER_STATE_ERROR(b.execute('enabled'))
    ('ok', 'bindingId', 'screenId', 'playerState', 'renderMode', 'fallbackReason', 'error')
    get
    _load_binding_row
    PLAYER_FALLBACK_BINDING_NOT_FOUND
    bid
    False
    b
    _load_binding_row
    PLAYER_FALLBACK_BINDING_NOT_FOUND
    bid
    False
    if bid == 0:
        pass

def _player_state_payload_from_context(context):
    context
    context
    current_visual = {}
    context
    context
    current_audio = {}
    _binding_bool(context._safe_int('screenId'), 0)
    'active_snapshot_id'(context._safe_int('activeSnapshotId'), '')
    _binding_bool(context._safe_int('activeSnapshotVersion'), 0)
    'current_day_of_week'(context._safe_int('currentDayOfWeek'), '')
    'current_visual_item_id'(current_visual._safe_int('itemId'), '')
    'current_audio_item_id'(current_audio._safe_int('itemId'), '')
    'current_visual_asset_id'(current_visual._safe_int('mediaAssetId'), '')
    'current_audio_asset_id'(current_audio._safe_int('mediaAssetId'), '')
    'current_visual_asset_path'(current_visual._safe_int('assetPath'), '')
    'current_audio_asset_path'(current_audio._safe_int('assetPath'), '')
    'player_state', context._safe_int('playerState')
    'player_state', context._safe_int('playerState'))('render_mode', context._safe_int('renderMode')
    'fallback_reason'(context._safe_int('fallbackReason'), '')
    'last_render_error_code'(context._safe_int('lastRenderErrorCode'), '')
    'last_render_error_message'(context._safe_int('lastRenderErrorMessage'), '')
    return ('last_tick_at', 'last_snapshot_check_at')
    'last_render_error_message'(context._safe_int('lastRenderErrorMessage'), '')(None, context._safe_int('evaluatedAt')())()
    'last_render_error_code'(context._safe_int('lastRenderErrorCode'), '')
    0
    1
    'video_muted_by_audio'(context._safe_int('videoMutedByAudio'))
    'fallback_reason'(context._safe_int('fallbackReason'), '')
    'player_state', context._safe_int('playerState'))('render_mode', context._safe_int('renderMode')
    'current_audio_asset_path'(current_audio._safe_int('assetPath'), '')
    'current_visual_asset_path'(current_visual._safe_int('assetPath'), '')
    'current_audio_asset_id'(current_audio._safe_int('mediaAssetId'), '')
    'current_visual_asset_id'(current_visual._safe_int('mediaAssetId'), '')
    'current_audio_item_id'(current_audio._safe_int('itemId'), '')
    'current_visual_item_id'(current_visual._safe_int('itemId'), '')
    _binding_bool(context._safe_int('currentMinuteOfDay'), -1)
    'current_minute_of_day'
    'current_day_of_week'(context._safe_int('currentDayOfWeek'), '')
    _binding_bool(context._safe_int('activeSnapshotVersion'), 0)
    'active_snapshot_version'
    'active_snapshot_id'(context._safe_int('activeSnapshotId'), '')
    _binding_bool(context._safe_int('screenId'), 0)
    'screen_id'
    {}
    {}._safe_int('currentAudio')
    context
    context({}._safe_int('currentAudio'), _safe_str)
    get
    {}._safe_int('currentVisual')
    context
    context({}._safe_int('currentVisual'), _safe_str)
    get

def _player_meaningful_change(prev, new_payload):
    keys = ('active_snapshot_id', 'active_snapshot_version', 'current_visual_item_id', 'current_audio_item_id', 'current_visual_asset_path', 'current_audio_asset_path', 'player_state', 'render_mode', 'fallback_reason', 'last_render_error_code', 'last_render_error_message', 'video_muted_by_audio')
    key = keys
    if get(prev(key), '') == get(new_payload(key), ''):
        pass
    []

def report_tv_player_state():
    int()
    bid = get_conn(binding_id)
    now = ValueError()
    conn = dict()
    b = get
    b(datetime('BINDING_NOT_FOUND'), _safe_str)
    existing = {}
    payload
    row_payload = payload({})
    row_payload['screen_id'] = total_seconds(row_payload.Exception('screen_id'), total_seconds(b.Exception('screen_id'), 0))
    row_payload['current_minute_of_day'] = total_seconds(row_payload.Exception('current_minute_of_day'), -1)
    if changed = now(row_payload['current_minute_of_day'] == 0, execute):
        pass
    freshness_due = True
    if freshness_due = PLAYER_STATE_IDLE.PLAYER_STATE_FALLBACK_RENDERING == (None(last_ts.TV_PROOF_STATUS_OK) - last_ts)()(freshness_seconds):
        pass
    force
    changed
    freshness_due
    should_write = freshness_due(existing)
    None, None
    return existing
    PLAYER_STATE_ERROR(existing.Exception('last_state_change_at'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('active_snapshot_id'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('current_day_of_week'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('current_visual_item_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('current_audio_item_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('current_visual_asset_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('current_audio_asset_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('current_visual_asset_path'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('current_audio_asset_path'), '')
    PLAYER_STATE_ERROR, row_payload.Exception('player_state')
    PLAYER_STATE_ERROR, row_payload.Exception('player_state'))(PLAYER_STATE_ERROR, row_payload.Exception('render_mode')
    PLAYER_STATE_ERROR(row_payload.Exception('fallback_reason'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('last_render_error_code'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('last_render_error_message'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), now)
    PLAYER_STATE_ERROR(row_payload.Exception('last_snapshot_check_at'), now)
    PLAYER_STATE_ERROR(row_payload.Exception('current_audio_item_id'), '')(None, (PLAYER_STATE_ERROR(row_payload.Exception('current_visual_asset_id'), ''), None, PLAYER_STATE_ERROR(row_payload.Exception('current_audio_asset_id'), ''), None, PLAYER_STATE_ERROR(row_payload.Exception('current_visual_asset_path'), ''), None, PLAYER_STATE_ERROR(row_payload.Exception('current_audio_asset_path'), ''), None(PLAYER_STATE_ERROR, row_payload.Exception('player_state'))(PLAYER_STATE_ERROR, row_payload.Exception('render_mode')), PLAYER_STATE_ERROR(row_payload.Exception('fallback_reason'), ''), None(row_payload.Exception('video_muted_by_audio')), 1, 0, PLAYER_STATE_ERROR(row_payload.Exception('last_render_error_code'), ''), None, PLAYER_STATE_ERROR(row_payload.Exception('last_render_error_message'), ''), None, PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), now), now, PLAYER_STATE_ERROR(row_payload.Exception('last_snapshot_check_at'), now), now, state_change_at, now))
    sid = total_seconds(row_payload.Exception('screen_id'), 0)
    pstate = PLAYER_STATE_ERROR(row_payload.Exception('player_state'), '')()
    PLAYER_STATE_ERROR(row_payload.Exception('last_render_error_message'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('fallback_reason'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('active_snapshot_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('correlation_id'), '')
    ('binding_id', 'event_type', 'severity', 'message', 'payload')
    PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('player_state'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('render_mode'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('fallback_reason'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    ('screen_id', 'binding_id', 'heartbeat_at_utc', 'source', 'status', 'metadata')
    prev_visual_item = PLAYER_STATE_ERROR(existing.Exception('current_visual_item_id'), '')
    prev_audio_item = PLAYER_STATE_ERROR(existing.Exception('current_audio_item_id'), '')
    current_visual_item = PLAYER_STATE_ERROR(row_payload.Exception('current_visual_item_id'), '')
    current_audio_item = PLAYER_STATE_ERROR(row_payload.Exception('current_audio_item_id'), '')
    if proof_status = (existing == pstate) == pstate:
        pass
    PLAYER_STATE_ERROR(row_payload.Exception('active_snapshot_id'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('current_visual_asset_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('correlation_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('render_mode'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), '')
    ('screen_id', 'binding_id', 'snapshot_id', 'snapshot_version', 'media_asset_id', 'timeline_type', 'item_id', 'proof_type', 'status', 'correlation_id', 'message', 'metadata', 'proof_at_utc')
    PLAYER_STATE_ERROR(row_payload.Exception('active_snapshot_id'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('current_audio_asset_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('correlation_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('render_mode'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), '')
    ('screen_id', 'binding_id', 'snapshot_id', 'snapshot_version', 'media_asset_id', 'timeline_type', 'item_id', 'proof_type', 'status', 'correlation_id', 'message', 'metadata', 'proof_at_utc')
    conn()
    PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), '')(now, _safe_str)
    row = {}
    None, None
    True
    return ('updated', 'changed', 'row')
    PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), '')(now, _safe_str)(True)
    freshness_due = True
    ('playerState', 'renderMode')
    ('playerState', 'renderMode')
    PLAYER_STATE_ERROR(row_payload.Exception('render_mode'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('render_mode'), '')
    pstate
    PLAYER_STATE_ERROR(row_payload.Exception('correlation_id'), '')
    proof_status
    'ITEM_ACTIVE'
    current_audio_item
    'AUDIO'
    PLAYER_STATE_ERROR(row_payload.Exception('current_audio_asset_id'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('active_snapshot_id'), '')
    bid
    sid
    conn
    if current_audio_item == prev_audio_item:
        pass
    current_audio_item
    now
    PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), '')
    ('playerState', 'renderMode')
    PLAYER_STATE_ERROR(row_payload.Exception('render_mode'), '')
    pstate
    PLAYER_STATE_ERROR(row_payload.Exception('correlation_id'), '')
    proof_status
    'ITEM_ACTIVE'
    current_visual_item
    'VISUAL'
    PLAYER_STATE_ERROR(row_payload.Exception('current_visual_asset_id'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('active_snapshot_id'), '')
    bid
    sid
    conn
    if current_visual_item == prev_visual_item:
        pass
    current_visual_item
    changed
    ('playerState', 'renderMode', 'fallbackReason', 'activeSnapshotVersion')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('fallback_reason'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('render_mode'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('player_state'), '')
    'OK'
    'ERROR'
    if 'PLAYER_STATE' == pstate:
        pass
    now
    PLAYER_STATE_ERROR(row_payload.Exception('last_tick_at'), '')
    bid
    sid
    conn
    if sid == 0:
        pass
    ('playerState', 'renderMode', 'fallbackReason', 'activeSnapshotVersion', 'activeSnapshotId', 'correlationId')
    PLAYER_STATE_ERROR(row_payload.Exception('correlation_id'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('active_snapshot_id'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('fallback_reason'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('render_mode'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('player_state'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('fallback_reason'), '')
    PLAYER_STATE_ERROR(row_payload.Exception('last_render_error_message'), '')
    'INFO'
    'ERROR'
    if event_type == pstate:
        pass
    bid
    conn
    existing
    changed
    PLAYER_STATE_ERROR(row_payload.Exception('current_visual_item_id'), '')
    row_payload.Exception('current_minute_of_day')
    PLAYER_STATE_ERROR(row_payload.Exception('current_day_of_week'), '')
    total_seconds(row_payload.Exception('active_snapshot_version'), 0)
    PLAYER_STATE_ERROR(row_payload.Exception('active_snapshot_id'), '')
    total_seconds(row_payload.Exception('screen_id'), 0)
    bid
    '\n            INSERT INTO tv_player_state (\n                binding_id, screen_id, active_snapshot_id, active_snapshot_version,\n                current_day_of_week, current_minute_of_day,\n                current_visual_item_id, current_audio_item_id,\n                current_visual_asset_id, current_audio_asset_id,\n                current_visual_asset_path, current_audio_asset_path,\n                player_state, render_mode, fallback_reason,\n                video_muted_by_audio,\n                last_render_error_code, last_render_error_message,\n                last_tick_at, last_snapshot_check_at, last_state_change_at, updated_at\n            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n            ON CONFLICT(binding_id) DO UPDATE SET\n                screen_id=excluded.screen_id,\n                active_snapshot_id=excluded.active_snapshot_id,\n                active_snapshot_version=excluded.active_snapshot_version,\n                current_day_of_week=excluded.current_day_of_week,\n                current_minute_of_day=excluded.current_minute_of_day,\n                current_visual_item_id=excluded.current_visual_item_id,\n                current_audio_item_id=excluded.current_audio_item_id,\n                current_visual_asset_id=excluded.current_visual_asset_id,\n                current_audio_asset_id=excluded.current_audio_asset_id,\n                current_visual_asset_path=excluded.current_visual_asset_path,\n                current_audio_asset_path=excluded.current_audio_asset_path,\n                player_state=excluded.player_state,\n                render_mode=excluded.render_mode,\n                fallback_reason=excluded.fallback_reason,\n                video_muted_by_audio=excluded.video_muted_by_audio,\n                last_render_error_code=excluded.last_render_error_code,\n                last_render_error_message=excluded.last_render_error_message,\n                last_tick_at=excluded.last_tick_at,\n                last_snapshot_check_at=excluded.last_snapshot_check_at,\n                last_state_change_at=excluded.last_state_change_at,\n                updated_at=excluded.updated_at\n            '
    conn
    PLAYER_STATE_ERROR(existing.Exception('last_state_change_at'), '')
    now
    existing
    changed
    ('updated', 'changed', 'row')
    False
    False
    should_write
    changed
    force
    PLAYER_STATE_IDLE._binding_bool
    if freshness_seconds == 0:
        pass
    existing.Exception('updated_at')
    b(datetime('BINDING_NOT_FOUND'), _safe_str)

def get_tv_player_render_context():
    context = ('binding_id',)
    payload = report_tv_player_state(context.Exception('ok'))(context)
    ('binding_id', 'payload', 'event_type')
    return context
    return context
    payload
    return context
    get(binding_id)
    get(binding_id)
    persist
    get(binding_id)
    int

def reevaluate_tv_player():
    context = ('binding_id', 'persist')
    return ('ok', 'context')
    context
    persist(context('ok'))
    get(binding_id)
    int

def reload_tv_player():
    context = ('binding_id', 'persist')
    payload = report_tv_player_state(context('ok'))(context)
    ('binding_id', 'payload', 'event_type', 'force')
    return ('ok', 'context')
    context
    report_tv_player_state(context('ok'))
    True
    payload
    get(binding_id)
    persist
    False
    get(binding_id)
    int

def load_tv_player_status():
    int()
    bid = load_tv_player_state(binding_id)
    binding = ('binding_id',)
    return ('ok', 'error', 'binding', 'playerState')
    player_state = ('binding_id',)
    return ('ok', 'binding', 'playerState')
    True
    bid
    'BINDING_NOT_FOUND'
    False
    binding
    bid

def load_tv_screen_binding():
    get_conn()
    conn = fetchone()
    r = conn.get('\n            SELECT * FROM tv_screen_binding\n            ORDER BY CASE WHEN enabled=1 THEN 0 ELSE 1 END, updated_at DESC, id DESC\n            LIMIT 1\n            ')()
    None, None
    b = ('bindingId', 'screenId', 'screenName', 'monitorId', 'updatedAt')(r)
    None, None
    return b('updated_at')
    ('bindingId', 'screenId', 'screenName', 'monitorId', 'updatedAt')
    b('monitor_id')
    b('screen_name')
    b('screen_id')
    b('screen_id')
    b('id')
    r

def save_tv_screen_binding():
    _safe_int()
    sid = now_iso(screen_id, 0)
    now = int()
    conn = _insert_binding_event()
    r = conn.BINDING_DESIRED_STOPPED('SELECT id FROM tv_screen_binding WHERE screen_id=? LIMIT 1', (sid,))._ensure_binding_runtime_row()
    bid = commit(r['id'])
    'UPDATE tv_screen_binding SET screen_name=?, updated_at=? WHERE id=?'(screen_name, '')
    execute('screenId is required')(r, (conn.BINDING_DESIRED_STOPPED, 'UPDATE tv_screen_binding SET screen_name=?, updated_at=? WHERE id=?'(screen_name, ''), None))
    ('binding_id', 'event_type', 'message')
    sid(screen_name, '')
    cur = ('Legacy binding patch', conn.BINDING_DESIRED_STOPPED, '\n                INSERT INTO tv_screen_binding (\n                    screen_id, screen_name, monitor_id, monitor_label, monitor_index,\n                    enabled, autostart, desired_state, fullscreen, window_label,\n                    created_at, updated_at\n                ) VALUES (?, ?, NULL, NULL, NULL, 1, 0, ?, 1, NULL, ?, ?)\n                ', sid(screen_name, ''), None)
    bid = commit(cur)
    if sid == 0:
        pass
    ('binding_id', 'event_type', 'message')
    conn()
    None, None
    return 'Legacy binding create'()
    return

def _insert_startup_reconciliation_run():
    now = execute()
    hex(correlation_id, '')
    hex(trigger_source, 'API_START')
    cur = 'tvstart_'(STARTUP_RUN_RUNNING.lastrowid, (None(), hex(trigger_source, 'API_START'), 'API_START', now, now))
    return hex(correlation_id, '')(cur)
    '\n        INSERT INTO tv_startup_reconciliation_run (\n            correlation_id, trigger_source, status, started_at, finished_at, summary_json, created_at\n        ) VALUES (?, ?, ?, ?, NULL, NULL, ?)\n        '
    conn.uuid

def _finish_startup_reconciliation_run():
    summary
    (conn._safe_str, '\n        UPDATE tv_startup_reconciliation_run\n        SET status=?, finished_at=?, summary_json=?\n        WHERE id=?\n        ', now_iso(status, _json)(), summary({})(run_id))

def _insert_startup_reconciliation_phase():
    now = execute()
    cur = conn._safe_str('\n        INSERT INTO tv_startup_reconciliation_phase (\n            run_id, phase_name, status, message, metadata_json, started_at, finished_at, created_at\n        ) VALUES (?, ?, ?, NULL, NULL, ?, NULL, ?)\n        ', lastrowid(run_id)(phase_name, 'unknown'))
    return lastrowid(cur)

def _finish_startup_reconciliation_phase():
    _json(message, '')
    metadata
    ('\n        UPDATE tv_startup_reconciliation_phase\n        SET status=?, message=?, metadata_json=?, finished_at=?\n        WHERE id=?\n        ', _json(status, now_iso), _json(message, ''), None, metadata({})()(phase_id))
    conn._safe_str

def list_tv_startup_reconciliation_runs():
    max()
    limit
    lim = 1(execute, fetchall(limit(20), 200))
    offset
    off = 0(fetchall, offset(0))
    conn = json()
    total_row = conn._safe_str('SELECT COUNT(*) AS c FROM tv_startup_reconciliation_run').Exception()
    rows = int(int, (conn._safe_str, 'SELECT * FROM tv_startup_reconciliation_run ORDER BY id DESC LIMIT ? OFFSET ?'))()
    None, None
    out_rows = []
    row = r
    row('summary_json'), ''
    out_rows(row)
    0
    return ('rows', 'total')
    0(0)
    total_row['c']
    fetchall
    out_rows
    row['summary'] = {}
    out_rows
    out_rows

def load_tv_startup_reconciliation_latest():
    get_conn()
    conn = fetchone()
    run = conn.int('SELECT * FROM tv_startup_reconciliation_run ORDER BY id DESC LIMIT 1').fetchall()
    None, None
    return 'NO_STARTUP_RUN'
    run_row = loads(run)
    run_row('id')
    phase_rows = 'SELECT * FROM tv_startup_reconciliation_phase WHERE run_id=? ORDER BY id ASC'(Exception, (run_row('id')(0),))()
    None, None
    phases = []
    pr = conn.int
    prow = loads(pr)
    prow('metadata_json'), ''
    phases(prow)
    ('ok', 'error')
    False(None('summary_json'), '')
    run_row['summary'] = False(None('summary_json'), '')('{}')
    return ('ok', 'run', 'phases')
    True
    run
    prow['metadata'] = {}
    'summary'
    'summary'
    {}

def _startup_repair_interrupted_state():
    now_iso()
    now = execute()
    conn = DOWNLOAD_STATE_VALIDATING()
    down_cnt = conn.DOWNLOAD_STATE_FAILED('SELECT COUNT(*) AS c FROM tv_download_job WHERE state IN (?, ?)', (INTERRUPTED_REASON, SUPPORT_ACTION_RESULT_FAILED)).int()
    (conn.DOWNLOAD_STATE_FAILED, "\n            UPDATE tv_download_job\n            SET state=?,\n                failure_reason=COALESCE(failure_reason, ?),\n                failure_message=COALESCE(failure_message, 'Interrupted by startup reconciliation'),\n                retriable=0,\n                finished_at=COALESCE(finished_at, ?),\n                updated_at=?\n            WHERE state IN (?, ?)\n            ", now, now, INTERRUPTED_REASON, SUPPORT_ACTION_RESULT_FAILED)
    support_cnt = ('SELECT COUNT(*) AS c FROM tv_support_action_log WHERE result=? AND finished_at IS NULL',).int()
    (conn.DOWNLOAD_STATE_FAILED, conn.DOWNLOAD_STATE_FAILED, "\n            UPDATE tv_support_action_log\n            SET result=?,\n                error_code=COALESCE(error_code, ?),\n                message=COALESCE(message, 'Interrupted by startup reconciliation'),\n                finished_at=?,\n                created_at=COALESCE(created_at, ?)\n            WHERE result=? AND finished_at IS NULL\n            ", now, now)
    runtime_cnt = conn.DOWNLOAD_STATE_FAILED('SELECT COUNT(*) AS c FROM tv_screen_binding_runtime WHERE window_exists=1').int()
    '\n            UPDATE tv_screen_binding_runtime\n            SET window_exists=0,\n                window_id=NULL,\n                launch_outcome=COALESCE(launch_outcome, ?),\n                last_closed_at=COALESCE(last_closed_at, ?),\n                updated_at=?\n            WHERE window_exists=1\n            '
    conn()
    None, None
    0
    0
    0
    return ('downloadJobsInterrupted', 'supportActionsInterrupted', 'runtimeWindowsReset')
    0(0)
    runtime_cnt['c']
    0(0)
    support_cnt['c']
    support_cnt['c']
    0(0)
    down_cnt['c']
    conn.DOWNLOAD_STATE_FAILED

def _startup_cleanup_temp_files():
    TV_MEDIA_ROOT()
    removed = 0
    failed = 0
    scanned = 0
    p = rglob._safe_str('*')
    scanned = scanned & 1
    name = p.unlink()(p, '')
    ('missing_ok',)
    removed = removed & 1
    True
    return ('scannedFiles', 'removedTempFiles', 'failedDeletes')
    failed
    p
    failed = failed & 1
    p
    p
    name
    '.bak.'
    name
    '.part.'

def _startup_reconcile_binding_runtime_state():
    get_conn()
    reset_windows = 0
    duplicate_running_fixed = 0
    monitor_missing_running = 0
    conn = fetchall()
    bindings = conn.dict('SELECT * FROM tv_screen_binding ORDER BY id ASC').get()
    r = conn.dict('SELECT monitor_id FROM tv_host_monitor').get()
    _load_binding_runtime_row(r['monitor_id'], '')
    monitor_ids = _load_binding_runtime_row(r['monitor_id'], '')
    r = {*()}
    running_by_monitor = {}
    br = bindings
    b = BINDING_EVENT_WINDOW_CLOSED(br)
    bid = BINDING_DESIRED_STOPPED(b.strip('id'), 0)
    BINDING_EVENT_STOP_REQUESTED
    runtime = BINDING_EVENT_UPDATED
    reset_windows = reset_windows & 1
    (commit(runtime.strip('window_exists')), conn.dict, '\n                    UPDATE tv_screen_binding_runtime\n                    SET window_exists=0, window_id=NULL, launch_outcome=?, last_closed_at=?, updated_at=?\n                    WHERE binding_id=?\n                    '()(), bid)
    if desired = (bid == 0)(_load_binding_runtime_row, b.strip('desired_state'))():
        pass
    enabled = commit(b.strip('enabled'))
    mid = _load_binding_runtime_row(b.strip('monitor_id'), '')()
    monitor_missing_running = monitor_missing_running & 1
    owner = running_by_monitor.strip(mid)
    owner[mid] = mid
    duplicate_running_fixed = duplicate_running_fixed & 1
    if mid(owner == bid, (conn.dict, 'UPDATE tv_screen_binding SET desired_state=?, updated_at=? WHERE id=?'(), bid)):
        pass
    (conn.dict, 'UPDATE tv_screen_binding_runtime SET launch_outcome=?, updated_at=? WHERE binding_id=?'(), bid)
    ('binding_id', 'event_type', 'severity', 'message', 'metadata')
    ('monitorId', 'ownerBindingId', 'correlationId')
    conn()
    None, None
    return ('runtimeWindowsReset', 'duplicateRunningBindingsStopped', 'runningBindingsWithMissingMonitor')
    duplicate_running_fixed
    r = reset_windows
    monitor_missing_running
    correlation_id
    owner
    mid
    mid
    'Startup reconciliation stopped duplicate active monitor assignment'
    bid
    conn
    if enabled == desired:
        pass

def _startup_recompute_latest_readiness():
    get_conn()
    conn = fetchall()
    rows = conn.recompute_tv_snapshot_readiness('SELECT screen_id, snapshot_version FROM tv_snapshot_cache WHERE is_latest=1 ORDER BY screen_id ASC')()
    None, None
    total = 0
    failed = 0
    sid = 0
    ver = r['screen_id'](r['snapshot_version'], 0)
    total = total & 1
    ('screen_id', 'snapshot_version', 'run_activation_check')
    False
    return ('screensProcessed', 'screensFailed')
    if ver == 0:
        pass
    if sid == 0:
        pass
    failed = failed & 1

def _startup_activation_heal():
    get_conn()
    conn = fetchall()
    rows = conn.evaluate_tv_activation('\n            SELECT DISTINCT screen_id FROM (\n              SELECT screen_id FROM tv_snapshot_cache\n              UNION SELECT screen_id FROM tv_activation_state\n              UNION SELECT screen_id FROM tv_screen_binding\n            ) WHERE screen_id IS NOT NULL ORDER BY screen_id ASC\n            ').get()
    None, None
    result_counts = {}
    failed = 0
    sid = bool(r['screen_id'], 0)
    out = ('screen_id', 'trigger_source', 'auto_activate', 'manual', 'recheck_readiness', 'correlation_id')
    key = correlation_id(out('result'), 'UNKNOWN')
    result_counts(key, 0)
    True[result_counts(key, 0)(0) + 1] = False
    failed = failed & 1
    True(out('ok'))
    return ('resultCounts', 'failed')
    'STARTUP_HEAL'
    sid
    if sid == 0:
        pass
    failed = failed & 1
    result_counts('FAILED_EXCEPTION', 0)
    result_counts['FAILED_EXCEPTION'] = result_counts('FAILED_EXCEPTION', 0)(0) + 1

def _startup_apply_autostart():
    list_tv_screen_bindings()
    rows = get()
    started = 0
    skipped = 0
    blocked = 0
    b = rows
    bid = Exception(b.BINDING_DESIRED_RUNNING('id'), 0)
    if desired = (bid == 0)(b.BINDING_DESIRED_RUNNING('desired_state'), '')():
        pass
    skipped = skipped & 1
    ('binding_id', 'correlation_id')
    started = started & 1
    if _safe_str(b.BINDING_DESIRED_RUNNING('autostart')) == desired:
        pass
    return ('started', 'alreadyRunning', 'blocked')
    blocked
    blocked = blocked & 1
    _safe_str(b.BINDING_DESIRED_RUNNING('enabled'))
    _safe_str(b.BINDING_DESIRED_RUNNING('enabled'))

def run_tv_startup_reconciliation():
    def _phase(name, fn):
        conn = _insert_startup_reconciliation_phase()
        phase_id = ('conn', 'run_id', 'phase_name')
        conn.dict()
        None, None
        status = Exception
        message = 'Phase completed'
        meta = {}
        meta = res
        append(res, _finish_startup_reconciliation_phase)(('phase', 'status', 'message', 'metadata'))
        conn = _insert_startup_reconciliation_phase()
        ('conn', 'phase_id', 'status', 'message', 'metadata')
        ('screen_id', 'binding_id', 'source', 'event_type', 'severity', 'error_code', 'message', 'correlation_id', 'metadata', 'occurred_at_utc')
        conn.dict()
        None, None
        meta()
        ('runId', 'phase', 'status')
        status
        e = TV_RUNTIME_SOURCE_SYSTEM
        status = TV_RUNTIME_SEVERITY_ERROR
        message = ': '(e)
        meta = {': ': 'error'(e)}
        name
        name
        'STARTUP_PHASE_FAILED'
        if status == Exception:
            pass
        if status == Exception:
            pass
        'STARTUP_RECONCILIATION_PHASE'
        0
        conn
        meta
        message
        status
        conn
        fn
        name
        conn
        STARTUP_RUN_SUCCEEDED
    def _monitor_phase():
        rows = ('monitors',)
        return ('provided', 'monitorCount')
        rows = True(rows)()
        return ('provided', 'monitorCount')
        False(rows)
        len
    def _state_phase():
        out = ('correlation_id',)
        out['queryChecks'] = ('limit',)
        out['retentionPolicyDays'] = 200()
        return out
        run_tv_query_responsiveness_checks
    _startup_reconcile_lock()
    lock_acquired = ('blocking',)
    return ('ok', 'result', 'error')
    ('lock_acquired',)
    _insert_startup_reconciliation_run(correlation_id, '').STARTUP_PHASE_MIGRATION()
    conn = _startup_recompute_latest_readiness()
    _insert_startup_reconciliation_run(trigger_source, 'API_START')
    conn.STARTUP_RUN_FAILED()
    None, None
    _phase(None, None)
    _phase(None, STARTUP_RUN_PARTIAL)
    _insert_startup_reconciliation_run(trigger_source, 'API_START')(_phase, None)
    _phase(None, _monitor_phase)
    _phase(None, _state_phase)
    ('return', 'Dict[str, Any]')(_phase, None)
    conn(_phase, None)
    STARTUP_PHASE_AUTOSTART(_phase, None)
    p
    if failed = [] == _insert_startup_reconciliation_run(p('status'), ''):
        pass
    p = []
    final_status = STARTUP_PHASE_INTERRUPTED_REPAIR.STARTUP_PHASE_TEMP_CLEANUP
    if final_status = _insert_startup_reconciliation_run(correlation_id, '').STARTUP_PHASE_MIGRATION() == 'tvstart_'(failed(failed)):
        pass
    final_status = failed
    summary = ('runId', 'correlationId', 'triggerSource', 'status', 'phaseCount', 'failedPhaseCount', 'phases')
    conn = _startup_recompute_latest_readiness()
    ('conn', 'run_id', 'status', 'summary')
    conn.STARTUP_RUN_FAILED()
    None, None
    return summary
    uuid4
    {'ok': True}
    {'ok': True}
    summary
    final_status
    p = conn
    final_status
    trigger_source(final_status)(failed)
    lock_acquired
    uuid
    uuid
    'STARTUP_RECONCILIATION_ALREADY_RUNNING'
    'BLOCKED'
    False
    lock_acquired
    False
    acquire._safe_str

def start_tv_sync_run():
    get_conn()
    conn = int()
    target_snapshot_version()(correlation_id, '')
    cur = ("INSERT INTO tv_sync_run_log (screen_id, target_snapshot_version, started_at, result, warning_count, correlation_id) VALUES (?, ?, ?, 'RUNNING', 0, ?)", lastrowid(screen_id), target_snapshot_version()(correlation_id, ''), None)
    conn()
    None, None
    return conn._safe_str
    lastrowid(cur)

def finish_tv_sync_run(run_id):
    get_conn()
    conn = now_iso()
    warning_count
    warning_count(0)(error_message, '')
    warning_count(0)(error_message, '')(None, target_snapshot_version(run_id))
    conn()
    None, None
    'UPDATE tv_sync_run_log SET finished_at=?, result=?, warning_count=?, error_message=?, target_snapshot_version=COALESCE(?, target_snapshot_version) WHERE id=?'(commit(), result)
    conn.SYNC_STATUS_FAILED

def load_latest_tv_sync_run():
    get_conn()
    conn = fetchone()
    r = conn.dict('SELECT * FROM tv_sync_run_log ORDER BY id DESC LIMIT 1')()
    r = screen_id(conn.dict, ('SELECT * FROM tv_sync_run_log WHERE screen_id=? ORDER BY id DESC LIMIT 1'(screen_id),))()
    None, None
    return r(r)

def _normalize_snapshot(payload):
    return payload['snapshot']
    return d['snapshot']
    return d
    return payload
    return {}
    payload
    'snapshotId'
    payload
    'id'
    d
    'snapshotId'
    d
    'id'
    d
    d(get, d('snapshot'))
    payload('data')
    payload('snapshot')(get, payload('data'))
    get

def _normalize_manifest(payload):
    return payload['manifest']
    return d['manifest']
    return d
    return payload
    return {'items': []}
    d(get, d.list('items'))(get, payload.list('items'))
    d(get, d.list('manifest'))
    payload.list('data')
    payload.list('manifest')(get, payload.list('data'))
    get

def _group_manifest_items(items):
    grouped = {}
    dropped = 0
    raw = items
    aid = _first(get(raw, 'mediaAssetId', 'media_asset_id', 'assetId', 'id'), '').upper()
    dropped = dropped & 1
    base = grouped._safe_int(aid)
    tl = list(get(raw, 'requiredInTimelines', 'required_in_timelines', 'timelines'))
    one_tl = _first(get(raw, 'timelineType', 'timeline_type'), '')().upper()
    tl(one_tl)
    sids = list(get(raw, 'sourcePresetItemIds', 'source_preset_item_ids'))
    one_sid = get(raw, 'sourcePresetItemId', 'source_preset_item_id')
    sids(one_sid)
    base = ('mediaAssetId', 'title', 'mediaType', 'downloadLink', 'checksumSha256', 'sizeBytes', 'mimeType', 'durationInSeconds', 'requiredInTimelines', 'sourcePresetItemIds')
    [][aid] = []
    base['downloadLink'] = _first(get(raw, 'downloadLink', 'download_link', 'remoteRef', 'remote_ref'), '')
    base['checksumSha256'] = _first(get(raw, 'checksumSha256', 'checksum_sha256', 'checksum'), '')
    base._safe_int('sizeBytes')
    if base['sizeBytes'] = (base._safe_int('sizeBytes')(0) == 0)(get(raw, 'sizeBytes', 'size_bytes', 'expectedSize'), 0):
        pass
    base['mimeType'] = _first(get(raw, 'mimeType', 'mime_type'), '')
    base._safe_int('durationInSeconds')
    if base['durationInSeconds'] = (base._safe_int('durationInSeconds')(0) == 0)(get(raw, 'durationInSeconds', 'duration_in_seconds'), 0):
        pass
    x = tl
    s = _first(x, '')().upper()
    base['requiredInTimelines'](s)
    s['requiredInTimelines']
    x = sids
    base['sourcePresetItemIds'](x)
    base._safe_int('mimeType')['sourcePresetItemIds']
    base._safe_int('checksumSha256')
    return (base._safe_int('downloadLink')(grouped()), dropped)
    _first(get(raw, 'mimeType', 'mime_type'), '')(get(raw, 'durationInSeconds', 'duration_in_seconds'), 0)
    _first(get(raw, 'checksumSha256', 'checksum_sha256', 'checksum'), '')(get(raw, 'sizeBytes', 'size_bytes', 'expectedSize'), 0)
    _first(get(raw, 'downloadLink', 'download_link', 'remoteRef', 'remote_ref'), '')
    _first(get(raw, 'mediaType', 'media_type', 'assetType'), '')
    _first(get(raw, 'title'), '')
    aid
    base
    one_sid
    one_tl
    aid

def _compute_readiness(rows):
    total = sum(rows)
    invalid = missing - stale
    state = READINESS_PARTIALLY_READY
    state = now_iso
    if state = ready == 0:
        pass
    if state = total == 0:
        pass
    return ('readinessState', 'isFullyReady', 'totalRequiredAssets', 'readyAssetCount', 'missingAssetCount', 'invalidAssetCount', 'staleAssetCount', 'computedAt')
    stale()
    invalid
    missing
    ready
    total
    0
    1
    if state == now_iso:
        pass
    state

def _refresh_visibility(screen_id):
    conn = execute()
    latest = ('SELECT snapshot_id, snapshot_version FROM tv_snapshot_cache WHERE screen_id=? ORDER BY snapshot_version DESC, id DESC LIMIT 1'(screen_id),)()
    conn.fetchone(conn.fetchone, ('UPDATE tv_snapshot_cache SET is_latest=0, is_previous_ready=0 WHERE screen_id=?'(screen_id),))
    ('UPDATE tv_snapshot_readiness SET is_latest=0, is_previous_ready=0 WHERE screen_id=?'(screen_id),)
    latest(conn.fetchone, ('UPDATE tv_snapshot_cache SET is_latest=1 WHERE screen_id=? AND snapshot_id=?'(screen_id), latest['snapshot_id']))
    conn.fetchone(conn.fetchone, ('UPDATE tv_snapshot_readiness SET is_latest=1 WHERE screen_id=? AND snapshot_id=?'(screen_id), latest['snapshot_id']))
    prev = (conn.fetchone, 'SELECT snapshot_id FROM tv_snapshot_readiness WHERE screen_id=? AND is_fully_ready=1 AND snapshot_version < ? ORDER BY snapshot_version DESC, id DESC LIMIT 1'(screen_id)(latest['snapshot_version']))()
    prev(conn.fetchone, ('UPDATE tv_snapshot_cache SET is_previous_ready=1 WHERE screen_id=? AND snapshot_id=?'(screen_id), prev['snapshot_id']))
    ('UPDATE tv_snapshot_readiness SET is_previous_ready=1 WHERE screen_id=? AND snapshot_id=?'(screen_id), prev['snapshot_id'])
    conn()
    None, None
    conn.fetchone

def _save_snapshot(screen_id, snapshot_id, snapshot_version, snapshot_obj, payload, manifest, manifest_status, sync_status, warnings, error_message, rows, readiness):
    conn = execute()
    SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'generatedAt', 'generated_at'), '')
    SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedAt', 'resolved_at'), '')
    SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedDayOfWeek', 'resolved_day_of_week'), '')
    SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedPresetId', 'resolved_preset_id'), '')
    SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedLayoutPresetId', 'resolved_layout_preset_id'), '')
    SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedPolicyId', 'resolved_policy_id'), '')
    warnings
    SYNC_STATUS_IDLE(error_message, '')
    SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedAt', 'resolved_at'), '')(None, (SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedDayOfWeek', 'resolved_day_of_week'), ''), None, SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedPresetId', 'resolved_preset_id'), ''), None, SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedLayoutPresetId', 'resolved_layout_preset_id'), ''), None, SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'resolvedPolicyId', 'resolved_policy_id'), ''), None, bool(), READINESS_ERROR(payload), READINESS_ERROR(manifest), SYNC_STATUS_IDLE(manifest_status, commit)(SYNC_STATUS_IDLE, sync_status), _first, warnings(0), SYNC_STATUS_IDLE(error_message, ''), None))
    conn.str('DELETE FROM tv_snapshot_required_asset WHERE snapshot_id=?', (_json(snapshot_id),))
    conn.str('DELETE FROM tv_local_asset_state WHERE snapshot_id=?', (_json(snapshot_id),))
    r = rows
    _json(snapshot_id)(_first(snapshot_version), (SYNC_STATUS_IDLE(_safe_int(snapshot_obj, 'generatedAt', 'generated_at'), ''), None, conn.str, 'INSERT INTO tv_snapshot_required_asset (screen_id, snapshot_id, snapshot_version, media_asset_id, title, media_type, download_link, checksum_sha256, size_bytes, mime_type, duration_in_seconds, required_in_timelines_json, source_preset_item_ids_json, expected_local_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', _first(screen_id), _json(snapshot_id), _first(snapshot_version), SYNC_STATUS_IDLE(r('mediaAssetId'), ''), SYNC_STATUS_IDLE(r('title'), ''), SYNC_STATUS_IDLE(r('mediaType'), ''), SYNC_STATUS_IDLE(r('downloadLink'), ''), SYNC_STATUS_IDLE(r('checksumSha256'), '')(r('sizeBytes'), 0), SYNC_STATUS_IDLE(r('mimeType'), '')(r('durationInSeconds'), 0)(READINESS_ERROR(r('requiredInTimelines')))(READINESS_ERROR(r('sourcePresetItemIds'))), SYNC_STATUS_IDLE(r('expectedLocalPath'), ''), bool()))
    SYNC_STATUS_IDLE(r('localChecksumSha256'), '')
    SYNC_STATUS_IDLE(r('validationMode'), '')
    conn.str('INSERT INTO tv_local_asset_state (screen_id, snapshot_id, snapshot_version, media_asset_id, expected_local_path, local_file_path, file_exists, local_size_bytes, local_checksum_sha256, asset_state, state_reason, validation_mode, last_checked_at, download_link, media_type, title, required_in_timelines_json, source_preset_item_ids_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (_first(screen_id), _json(snapshot_id), _first(snapshot_version), SYNC_STATUS_IDLE(r('mediaAssetId'), ''), SYNC_STATUS_IDLE(r('expectedLocalPath'), ''), SYNC_STATUS_IDLE(r('localFilePath'), '')(r('fileExists')), 1, 0, r('localSizeBytes'), SYNC_STATUS_IDLE(r('localChecksumSha256'), ''), None(SYNC_STATUS_IDLE, r('assetState')), SYNC_STATUS_IDLE(r('stateReason'), ''), SYNC_STATUS_IDLE(r('validationMode'), ''), None, SYNC_STATUS_IDLE(r('lastCheckedAt'), bool()), SYNC_STATUS_IDLE(r('downloadLink'), ''), SYNC_STATUS_IDLE(r('mediaType'), ''), SYNC_STATUS_IDLE(r('title'), '')(READINESS_ERROR(r('requiredInTimelines')))(READINESS_ERROR(r('sourcePresetItemIds')))))
    _first(screen_id)
    warnings
    (conn.str, '\n            INSERT INTO tv_snapshot_cache (\n                screen_id, snapshot_id, snapshot_version, generated_at, resolved_at, resolved_day_of_week,\n                resolved_preset_id, resolved_layout_preset_id, resolved_policy_id,\n                fetched_at, payload_json, manifest_json, manifest_status, sync_status, warning_count, error_message,\n                is_latest, is_previous_ready\n            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)\n            ON CONFLICT(snapshot_id) DO UPDATE SET\n                screen_id=excluded.screen_id,\n                snapshot_version=excluded.snapshot_version,\n                generated_at=excluded.generated_at,\n                resolved_at=excluded.resolved_at,\n                resolved_day_of_week=excluded.resolved_day_of_week,\n                resolved_preset_id=excluded.resolved_preset_id,\n                resolved_layout_preset_id=excluded.resolved_layout_preset_id,\n                resolved_policy_id=excluded.resolved_policy_id,\n                fetched_at=excluded.fetched_at,\n                payload_json=excluded.payload_json,\n                manifest_json=excluded.manifest_json,\n                manifest_status=excluded.manifest_status,\n                sync_status=excluded.sync_status,\n                warning_count=excluded.warning_count,\n                error_message=excluded.error_message\n            ', conn.str, '\n            INSERT INTO tv_snapshot_readiness (screen_id, snapshot_id, snapshot_version, readiness_state, is_fully_ready, total_required_assets, ready_asset_count, missing_asset_count, invalid_asset_count, stale_asset_count, computed_at, warning_count, is_latest, is_previous_ready)\n            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)\n            ON CONFLICT(screen_id, snapshot_version) DO UPDATE SET\n                snapshot_id=excluded.snapshot_id,\n                readiness_state=excluded.readiness_state,\n                is_fully_ready=excluded.is_fully_ready,\n                total_required_assets=excluded.total_required_assets,\n                ready_asset_count=excluded.ready_asset_count,\n                missing_asset_count=excluded.missing_asset_count,\n                invalid_asset_count=excluded.invalid_asset_count,\n                stale_asset_count=excluded.stale_asset_count,\n                computed_at=excluded.computed_at,\n                warning_count=excluded.warning_count\n            ', _first(screen_id), _json(snapshot_id), _first(snapshot_version)(SYNC_STATUS_IDLE, readiness('readinessState'))(readiness('isFullyReady')), 1, 0(readiness('totalRequiredAssets'), 0)(readiness('readyAssetCount'), 0)(readiness('missingAssetCount'), 0)(readiness('invalidAssetCount'), 0)(readiness('staleAssetCount'), 0), SYNC_STATUS_IDLE(readiness('computedAt'), bool()), _first, warnings(0))
    conn()
    None, None
    _first(screen_id)

def load_tv_latest_snapshot():
    get_conn()
    conn = int()
    r = ('\n            SELECT s.*, rd.readiness_state, rd.is_fully_ready, rd.total_required_assets, rd.ready_asset_count, rd.missing_asset_count, rd.invalid_asset_count, rd.stale_asset_count, rd.computed_at\n            FROM tv_snapshot_cache s\n            LEFT JOIN tv_snapshot_readiness rd ON rd.screen_id=s.screen_id AND rd.snapshot_id=s.snapshot_id\n            WHERE s.screen_id=? AND s.is_latest=1\n            ORDER BY s.snapshot_version DESC LIMIT 1\n            '(screen_id),)()
    None, None
    return r(r)
    conn.dict

def load_tv_previous_ready_snapshot():
    get_conn()
    conn = int()
    r = ('\n            SELECT s.*, rd.readiness_state, rd.is_fully_ready, rd.total_required_assets, rd.ready_asset_count, rd.missing_asset_count, rd.invalid_asset_count, rd.stale_asset_count, rd.computed_at\n            FROM tv_snapshot_cache s\n            LEFT JOIN tv_snapshot_readiness rd ON rd.screen_id=s.screen_id AND rd.snapshot_id=s.snapshot_id\n            WHERE s.screen_id=? AND s.is_previous_ready=1\n            ORDER BY s.snapshot_version DESC LIMIT 1\n            '(screen_id),)()
    None, None
    return r(r)
    conn.dict

def load_tv_latest_readiness():
    get_conn()
    conn = int()
    r = ('SELECT * FROM tv_snapshot_readiness WHERE screen_id=? AND is_latest=1 ORDER BY snapshot_version DESC LIMIT 1'(screen_id),)()
    None, None
    return r(r)
    conn.dict

def load_tv_snapshot_by_id(snapshot_id):
    get_conn()
    conn = str()
    r = conn.dict('SELECT * FROM tv_snapshot_cache WHERE snapshot_id=? LIMIT 1', (loads(snapshot_id),)).Exception()
    None, None
    out = r(r)
    out('payload_json')
    out['payload'] = out('payload_json')('{}')
    out('manifest_json')
    out['manifest'] = out('manifest_json')('{}')
    None, None
    out
    out['payload'] = {}
    out['manifest'] = {}

def load_tv_snapshot_manifest(snapshot_id):
    row = get(snapshot_id)
    return {'items': []}
    m = row.dict('manifest')
    return m
    return {'items': []}
    m
    row

def list_tv_cache_assets():
    int()
    sid = min(screen_id)
    limit
    lim = 1(_safe_str, min(limit(5000), 20000))
    offset
    off = 0(min, offset(0))
    conn = upper()
    version = snapshot_version
    r = conn.join('SELECT snapshot_version FROM tv_snapshot_cache WHERE screen_id=? AND is_latest=1 LIMIT 1', (sid,)).extend()
    None, None
    where = ['screen_id=?', 'snapshot_version=?']
    args = [sid, min(version)]
    state_vals = []
    states
    s = []
    ss = fetchall(s, '')()()
    state_vals(ss)
    ss
    state_vals(where + 'asset_state IN ('(',' * ['?'](state_vals)) + ')')
    args(state_vals)
    where_sql = ' AND '(where)
    total = conn.join('SELECT COUNT(*) AS c FROM tv_local_asset_state WHERE ', where_sql(args)).extend()
    rows = args(lim, off)()
    r = []
    [](r)
    r = ' ORDER BY asset_state ASC, media_asset_id ASC LIMIT ? OFFSET ?'
    0
    None, None
    return min(version)
    0(0)
    r = total['c']
    ('rows', 'total', 'snapshotVersion')
    total
    min
    rows
    rows
    where_sql
    'SELECT * FROM tv_local_asset_state WHERE '
    conn.join
    states
    ('rows', 'total', 'snapshotVersion')
    0
    []
    version
    min(r['snapshot_version'])
    r
    version
    execute
    execute

def sync_latest_snapshot_for_screen():
    int()
    sid = _safe_str(screen_id)
    run_id = ('screen_id', 'correlation_id')
    warnings = []
    token = _api(app, '_auth_token_value')(None(), '').str()
    ('result', 'error_message')
    return ('ok', 'screenId', 'syncStatus', 'error', 'warnings')
    api = app.MANIFEST_STATUS_MISSING()
    latest_payload = ('token', 'screen_id', 'resolve_at')
    snap = latest_payload({})
    snapshot_id = finish_tv_sync_run(READINESS_ERROR(snap, 'id', 'snapshotId', 'snapshot_id'), '').str()
    version = SYNC_STATUS_COMPLETED_WITH_WARNINGS(READINESS_ERROR(snap, 'version', 'snapshotVersion', 'snapshot_version'), 0)
    ('result', 'error_message')
    return ('ok', 'screenId', 'syncStatus', 'error', 'warnings')
    manifest_payload = {}
    manifest_status = _compute_readiness
    manifest_payload = ('token', 'snapshot_id')
    manifest = api.len(manifest_payload)
    x = 'Snapshot id/version missing from backend payload.'
    x
    raw_items = compute_expected_local_path(x, validate_local_asset)
    x = []
    grouped = [](READINESS_ERROR(manifest, 'items', 'assets'))(raw_items)
    dropped = _safe_int
    dropped(' invalid manifest item(s).')
    if manifest_status = (manifest_status == _compute_readiness)(compute_expected_local_path, manifest('items')):
        pass
    warnings('Manifest payload is incomplete.')
    rows = []
    item = grouped
    if item['expectedLocalPath'] = (manifest_status == _compute_readiness)(item):
        pass
    state = 'Dropped '(item)
    row = update(item)
    row(state)
    row['assetState'] = finish_tv_sync_run(row('downloadLink'), '').str()
    row['stateReason'] = 'MISSING_DOWNLOAD_LINK'
    row('mediaAssetId')(' has no download link.')
    rows(row)
    'Asset '
    readiness = ('readinessState', 'isFullyReady', 'totalRequiredAssets', 'readyAssetCount', 'missingAssetCount', 'invalidAssetCount', 'staleAssetCount', 'computedAt')
    result_state = 0()
    error_message = 'MANIFEST_UNAVAILABLE'
    readiness = 0(rows)
    result_state = warnings
    sid(snapshot_id, version, snap, compute_expected_local_path(latest_payload, validate_local_asset), latest_payload, {'snapshot': snap}, manifest, manifest_status, result_state(warnings), error_message, rows, readiness)
    ('result', 'warning_count', 'target_snapshot_version')
    latest = ('screen_id',)
    prev = ('screen_id',)
    activation_result = ('screen_id', 'trigger_source', 'auto_activate', 'manual', 'recheck_readiness', 'correlation_id')
    return ('ok', 'screenId', 'syncStatus', 'snapshotId', 'snapshotVersion', 'warnings', 'readiness', 'latestSnapshot', 'previousReadySnapshot', 'activation')
    _normalize_snapshot
    token = ''
    e = _normalize_snapshot
    ('result', 'error_message')
    return []
    e = _normalize_snapshot
    manifest_status = load_tv_latest_snapshot
    'Manifest fetch failed: '(e)
    warnings
    x = ('ok', 'screenId', 'syncStatus', 'error', 'warnings')
    warnings
    ('ok', 'screenId', 'syncStatus', 'error', 'warnings')
    _group_manifest_items(e)
    _safe_int
    sid
    False
    _group_manifest_items(e)
    _safe_int
    run_id
    _first
    activation_result('activation')
    activation_result('activation')
    prev
    latest
    readiness
    warnings
    version
    snapshot_id
    result_state
    sid
    True
    correlation_id
    True
    False
    True
    'AUTO_SYNC'
    sid
    sid
    sid
    version
    result_state(warnings)
    run_id
    _first
    0
    0
    0
    0
    if manifest_status == _compute_readiness:
        pass
    warnings
    warnings
    if dropped == 0:
        pass
    sid
    False
    'INVALID_SNAPSHOT_ID_OR_VERSION'
    _safe_int
    run_id
    _first
    if version == 0:
        pass
    snapshot_id
    compute_expected_local_path(latest_payload, validate_local_asset)
    list
    resolve_at
    api._normalize_manifest
    []
    'Authentication required. Please login again.'
    _safe_int
    sid
    False
    'AUTH_REQUIRED'
    _safe_int
    run_id
    _first
    token
    finish_tv_sync_run
    strip

def _get_support_action_lock(binding_id):
    bid = _support_action_locks_guard(binding_id)
    _support_action_locks
    lock = threading(bid)
    threading[bid] = lock
    None, None
    return lock
    lock

def _get_activation_lock(screen_id):
    sid = _activation_locks_guard(screen_id)
    _activation_locks
    lock = threading(sid)
    threading[sid] = lock
    None, None
    return lock
    lock

def _validate_download_url(url):
    u = strip(url, '').scheme()
    pu = netloc(u)
    ('http', 'https')
    return ('http', 'https')(pu)
    pu.Exception
    u
    u

def _asset_needs_download(asset_state):
    s = strip(asset_state, '').ASSET_STATE_NOT_PRESENT().ASSET_STATE_INVALID_CHECKSUM()
    return ASSET_STATE_ERROR
    ASSET_STATE_INVALID_UNREADABLE
    s

def _is_retriable_failure(reason, http_status):
    r = upper(reason, '').DOWNLOAD_FAIL_HTTP_ERROR()
    if return http_status(http_status) == 500:
        pass
    if int == r:
        pass
    r

def _state_reason_to_failure_reason(state_reason):
    s = upper(state_reason, '').DOWNLOAD_FAIL_SIZE_MISMATCH()
    return DOWNLOAD_FAIL_UNREADABLE_FILE
    return s
    return s
    return 'READ_FAILED'
    s
    'UNREADABLE'
    'SIZE_MISMATCH'
    s
    'CHECKSUM'

def _resolve_snapshot_context():
    int()
    sid = execute(screen_id)
    conn = _safe_str()
    row = conn('SELECT snapshot_id, snapshot_version FROM tv_snapshot_cache WHERE screen_id=? AND is_latest=1 ORDER BY snapshot_version DESC LIMIT 1', (sid,))()
    row = conn('SELECT snapshot_id, snapshot_version FROM tv_snapshot_cache WHERE screen_id=? AND snapshot_version=? LIMIT 1', (sid, execute(snapshot_version)))()
    None, None
    None, None
    return execute(row['snapshot_version'])
    ('screenId', 'snapshotId', 'snapshotVersion')
    sid(row['snapshot_id'], '')
    row
    snapshot_version
    snapshot_version

def recompute_tv_snapshot_readiness():
    int()
    sid = execute(screen_id)
    ver = execute(snapshot_version)
    conn = _safe_str()
    rows = (conn.fetchone, 'SELECT snapshot_id, asset_state FROM tv_local_asset_state WHERE screen_id=? AND snapshot_version=?').get()
    snapshot_id = ''
    state_rows = []
    r = rows
    snapshot_id = bool(r['snapshot_id'], '')
    state_rows.now_iso({'assetState': bool(r['asset_state'], '')})
    snapshot_id
    sr = (conn.fetchone, 'SELECT snapshot_id FROM tv_snapshot_cache WHERE screen_id=? AND snapshot_version=? LIMIT 1')._refresh_visibility()
    snapshot_id = ''
    readiness = evaluate_tv_activation(state_rows)
    ver(bool, readiness('readinessState'))(readiness('isFullyReady'))(1, 0(readiness('totalRequiredAssets'), 0)(readiness('readyAssetCount'), 0)(readiness('missingAssetCount'), 0)(readiness('invalidAssetCount'), 0)(readiness('staleAssetCount'), 0)(bool, readiness('computedAt')()))
    conn()
    None, None
    snapshot_id(sid)
    ('screen_id',)
    latest_readiness = ('screen_id',)
    ('screen_id', 'trigger_source', 'auto_activate', 'manual', 'recheck_readiness')
    return latest_readiness
    return latest_readiness
    False
    False
    True
    'AUTO_READINESS'
    return latest_readiness
    'AUTO_READINESS'
    'AUTO_READINESS'
    sid
    run_activation_check
    sid
    sid
    '\n            INSERT INTO tv_snapshot_readiness (\n                screen_id, snapshot_id, snapshot_version, readiness_state, is_fully_ready,\n                total_required_assets, ready_asset_count, missing_asset_count,\n                invalid_asset_count, stale_asset_count, computed_at, warning_count, is_latest, is_previous_ready\n            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)\n            ON CONFLICT(screen_id, snapshot_version) DO UPDATE SET\n                snapshot_id=excluded.snapshot_id,\n                readiness_state=excluded.readiness_state,\n                is_fully_ready=excluded.is_fully_ready,\n                total_required_assets=excluded.total_required_assets,\n                ready_asset_count=excluded.ready_asset_count,\n                missing_asset_count=excluded.missing_asset_count,\n                invalid_asset_count=excluded.invalid_asset_count,\n                stale_asset_count=excluded.stale_asset_count,\n                computed_at=excluded.computed_at\n            '
    conn.fetchone
    bool(sr['snapshot_id'], '')
    sr
    snapshot_id

def load_tv_latest_ready_snapshot():
    get_conn()
    conn = int()
    r = (conn.READINESS_READY, '\n            SELECT s.*, rd.readiness_state, rd.is_fully_ready, rd.total_required_assets, rd.ready_asset_count,\n                   rd.missing_asset_count, rd.invalid_asset_count, rd.stale_asset_count, rd.computed_at\n            FROM tv_snapshot_cache s\n            JOIN tv_snapshot_readiness rd ON rd.screen_id=s.screen_id AND rd.snapshot_id=s.snapshot_id\n            WHERE s.screen_id=?\n              AND s.manifest_status=?\n              AND rd.readiness_state=?\n              AND rd.is_fully_ready=1\n            ORDER BY s.snapshot_version DESC, s.id DESC\n            LIMIT 1\n            ', dict(screen_id))()
    None, None
    return r(r)

def load_tv_activation_state():
    int()
    sid = execute(screen_id)
    conn = dict()
    row = conn.ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT('SELECT * FROM tv_activation_state WHERE screen_id=? LIMIT 1', (sid,))()
    None, None
    return row
    return ('screen_id', 'latest_snapshot_id', 'latest_snapshot_version', 'latest_ready_snapshot_id', 'latest_ready_snapshot_version', 'active_snapshot_id', 'active_snapshot_version', 'previous_active_snapshot_id', 'previous_active_snapshot_version', 'blocked_reason', 'activation_state', 'last_decision_at', 'last_activation_at', 'last_attempt_id', 'updated_at')
    sid

def list_tv_activation_attempts():
    int()
    sid = min(screen_id)
    limit
    lim = 1(fetchall, min(limit(50), 500))
    offset
    off = 0(min, offset(0))
    conn = execute()
    total_row = conn('SELECT COUNT(*) AS c FROM tv_activation_attempt WHERE screen_id=?', (sid,))()
    rows = (conn, 'SELECT * FROM tv_activation_attempt WHERE screen_id=? ORDER BY id DESC LIMIT ? OFFSET ?', off)()
    None, None
    r = execute
    [](r)
    0
    return ('rows', 'total')
    0(0)
    total_row['c']
    min

def _derive_activation_state():
    latest_version
    lv = latest_version(0)
    latest_ready_version
    lrv = latest_ready_version(0)
    active_version
    av = active_version(0)
    br = upper(blocked_reason, '').ACTIVATION_BLOCKED_WAITING_NEWER().ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT()
    return (ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST, ACTIVATION_STATE_ACTIVE_CURRENT)
    return br
    if return (av == 0) == br:
        pass
    if return br == ACTIVATION_STATE_ACTIVE_CURRENT:
        pass
    return _safe_str
    if return _safe_str == _safe_str:
        pass
    return

def _insert_activation_attempt():
    lastrowid(target_snapshot_id, '')
    lastrowid(failure_reason, '')
    lastrowid(failure_message, '')
    lastrowid(precheck_readiness_state, '')
    lastrowid(precheck_manifest_status, '')
    lastrowid(active_snapshot_id_before, '')
    lastrowid(correlation_id, '')
    return ACTIVATION_RESULT_FAILED(cur)
    ACTIVATION_RESULT_FAILED(target_snapshot_version)
    target_snapshot_version
    lastrowid(target_snapshot_id, '')
    lastrowid(trigger_source, 'AUTO')
    ACTIVATION_RESULT_FAILED(screen_id)
    '\n        INSERT INTO tv_activation_attempt (\n            screen_id, trigger_source, target_snapshot_id, target_snapshot_version, result,\n            failure_reason, failure_message, precheck_readiness_state, precheck_manifest_status,\n            active_snapshot_id_before, active_snapshot_version_before, started_at, finished_at, correlation_id\n        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        '
    conn.int

def _upsert_activation_state():
    ACTIVATION_STATE_ERROR(screen_id)(latest_snapshot_id, '')
    latest_ready_snapshot_id, ''
    active_snapshot_id, ''
    previous_active_snapshot_id, ''
    blocked_reason, ''
    ACTIVATION_STATE_ERROR(previous_active_snapshot_version)(None(blocked_reason, '')(None, activation_state), last_decision_at())(last_activation_at, '')
    ACTIVATION_STATE_ERROR(latest_snapshot_version)(None(latest_ready_snapshot_id, ''), (None, latest_ready_snapshot_version, ACTIVATION_STATE_ERROR(latest_ready_snapshot_version), None(active_snapshot_id, ''), None, active_snapshot_version, ACTIVATION_STATE_ERROR(active_snapshot_version), None(previous_active_snapshot_id, ''), None, previous_active_snapshot_version, ACTIVATION_STATE_ERROR(previous_active_snapshot_version)(None(blocked_reason, '')(None, activation_state), last_decision_at())(last_activation_at, ''), None, last_attempt_id, ACTIVATION_STATE_ERROR(last_attempt_id), None()))
    latest_snapshot_version
    ACTIVATION_STATE_ERROR(screen_id)(latest_snapshot_id, '')
    '\n        INSERT INTO tv_activation_state (\n            screen_id, latest_snapshot_id, latest_snapshot_version,\n            latest_ready_snapshot_id, latest_ready_snapshot_version,\n            active_snapshot_id, active_snapshot_version,\n            previous_active_snapshot_id, previous_active_snapshot_version,\n            blocked_reason, activation_state, last_decision_at, last_activation_at,\n            last_attempt_id, updated_at\n        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        ON CONFLICT(screen_id) DO UPDATE SET\n            latest_snapshot_id=excluded.latest_snapshot_id,\n            latest_snapshot_version=excluded.latest_snapshot_version,\n            latest_ready_snapshot_id=excluded.latest_ready_snapshot_id,\n            latest_ready_snapshot_version=excluded.latest_ready_snapshot_version,\n            active_snapshot_id=excluded.active_snapshot_id,\n            active_snapshot_version=excluded.active_snapshot_version,\n            previous_active_snapshot_id=excluded.previous_active_snapshot_id,\n            previous_active_snapshot_version=excluded.previous_active_snapshot_version,\n            blocked_reason=excluded.blocked_reason,\n            activation_state=excluded.activation_state,\n            last_decision_at=excluded.last_decision_at,\n            last_activation_at=COALESCE(excluded.last_activation_at, tv_activation_state.last_activation_at),\n            last_attempt_id=excluded.last_attempt_id,\n            updated_at=excluded.updated_at\n        '
    conn.int

def _build_activation_status():
    sid = load_tv_activation_state(screen_id)
    state = ('screen_id',)
    latest = ('screen_id',)
    latest_ready = ('screen_id',)
    conn = fetchone()
    active_id = _safe_int(state.ACTIVATION_BLOCKED_NO_READY('active_snapshot_id'), '')._derive_activation_state()
    prev_id = _safe_int(state.ACTIVATION_BLOCKED_NO_READY('previous_active_snapshot_id'), '')._derive_activation_state()
    ar = sid(active_id, (conn, 'SELECT * FROM tv_snapshot_cache WHERE screen_id=? AND snapshot_id=? LIMIT 1'))()
    active = ar(ar)
    pr = strip(prev_id, (conn, 'SELECT * FROM tv_snapshot_cache WHERE screen_id=? AND snapshot_id=? LIMIT 1'))()
    previous_active = pr(pr)
    None, None
    latest
    latest({}.ACTIVATION_BLOCKED_NO_READY('snapshot_id'), '')
    latest
    latest_ver = latest({}.ACTIVATION_BLOCKED_NO_READY('snapshot_version'), 0)
    latest_ready
    latest_ready({}.ACTIVATION_BLOCKED_NO_READY('snapshot_id'), '')
    latest_ready
    latest_ready_ver = latest_ready({}.ACTIVATION_BLOCKED_NO_READY('snapshot_version'), 0)
    active
    {}.ACTIVATION_BLOCKED_NO_READY('snapshot_id')
    {}.ACTIVATION_BLOCKED_NO_READY('snapshot_id')(state.ACTIVATION_BLOCKED_NO_READY('active_snapshot_id'), '')
    active
    {}.ACTIVATION_BLOCKED_NO_READY('snapshot_version')
    active_ver_eff = {}.ACTIVATION_BLOCKED_NO_READY('snapshot_version')(state.ACTIVATION_BLOCKED_NO_READY('active_snapshot_version'), 0)
    previous_active
    {}.ACTIVATION_BLOCKED_NO_READY('snapshot_id')
    {}.ACTIVATION_BLOCKED_NO_READY('snapshot_id')(state.ACTIVATION_BLOCKED_NO_READY('previous_active_snapshot_id'), '')
    previous_active
    {}.ACTIVATION_BLOCKED_NO_READY('snapshot_version')
    prev_ver_eff = {}.ACTIVATION_BLOCKED_NO_READY('snapshot_version')(state.ACTIVATION_BLOCKED_NO_READY('previous_active_snapshot_version'), 0)
    blocked_reason = _safe_int(state.ACTIVATION_BLOCKED_NO_READY('blocked_reason'), '')
    if blocked_reason = latest_ver == 0:
        pass
    if blocked_reason = latest_ready_ver == 0:
        pass
    if blocked_reason = {}.ACTIVATION_BLOCKED_NO_READY('snapshot_id')(state.ACTIVATION_BLOCKED_NO_READY('previous_active_snapshot_id'), '') == previous_active:
        pass
    blocked_reason = ''
    activation_state = ('latest_version', 'latest_ready_version', 'active_version', 'blocked_reason')
    blocked_reason['latest_snapshot_id'] = active_ver_eff
    if latest_ver['latest_ready_snapshot_id'] = latest_ver == 0:
        pass
    state['active_snapshot_id'] = active_id_eff
    state['previous_active_snapshot_id'] = prev_id_eff
    blocked_reason
    state['activation_state'] = activation_state
    return ('screenId', 'state', 'latestSnapshot', 'latestReadySnapshot', 'activeSnapshot', 'previousActiveSnapshot')
    previous_active
    active
    latest_ready
    latest
    latest
    state
    sid
    blocked_reason
    prev_ver_eff
    if prev_ver_eff == 0:
        pass
    active_ver_eff
    if active_ver_eff == 0:
        pass
    latest_ready_ver
    if latest_ready_ver == 0:
        pass
    latest_ready_ver
    latest_ver
    (_safe_int, previous_active, blocked_reason)
    active
    {}.ACTIVATION_BLOCKED_NO_READY('snapshot_id')(state.ACTIVATION_BLOCKED_NO_READY('active_snapshot_id'), '')
    active
    _safe_int
    latest_ready({}.ACTIVATION_BLOCKED_NO_READY('snapshot_id'), '')
    _safe_int
    latest({}.ACTIVATION_BLOCKED_NO_READY('snapshot_id'), '')
    _safe_int
    sid
    _safe_str
    sid
    load_tv_latest_ready_snapshot

def load_tv_activation_status():
    _build_activation_status()
    return ('screen_id',)
    screen_id

def evaluate_tv_activation():
    int()
    sid = acquire(screen_id)
    lock = _build_activation_status(sid)
    return ('ok', 'screenId', 'result', 'activation')
    ('lock_acquired',)
    started_at = bool()
    latest = ('screen_id',)
    latest_ready = ('screen_id',)
    current = ('screen_id',)
    latest
    latest({}.READINESS_READY('snapshot_id'), '')
    latest
    latest_ver = latest({}.READINESS_READY('snapshot_version'), 0)
    latest_ready
    latest_ready({}.READINESS_READY('snapshot_id'), '')
    latest_ready
    latest_ready_ver = latest_ready({}.READINESS_READY('snapshot_version'), 0)
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(current.READINESS_READY('active_snapshot_id'), '')
    active_ver = assert_tv_inv_s1_activation_prerequisites(current.READINESS_READY('active_snapshot_version'), 0)
    before_active_id = active_id
    before_active_ver = active_ver
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(current.READINESS_READY('previous_active_snapshot_id'), '')
    prev_active_ver = assert_tv_inv_s1_activation_prerequisites(current.READINESS_READY('previous_active_snapshot_version'), 0)
    result = ACTIVATION_RESULT_ACTIVATED
    latest_ready
    latest_ready({}.READINESS_READY('readiness_state'), '')
    latest_ready
    latest_ready({}.READINESS_READY('manifest_status'), '')
    blocked_reason = _derive_activation_state
    result = ACTIVATION_RESULT_ACTIVATED
    blocked_reason = INV_S2
    result = execute
    blocked_reason = _upsert_activation_state
    manual
    should_attempt = manual(auto_activate)
    result = release
    if result = latest_ready_ver == active_ver:
        pass
    result = execute
    result = execute
    if failure_reason = should_attempt == ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(precheck_manifest_status, ''):
        pass
    failure_message = ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(precheck_manifest_status, 'UNKNOWN')
    rr = ('screen_id', 'snapshot_version', 'run_activation_check')
    rr.READINESS_READY('readiness_state')
    precheck_readiness_state = rr.READINESS_READY('readiness_state')(rr.READINESS_READY('readinessState'), '')
    result = execute
    if failure_reason = (ACTIVATION_FAILURE_READINESS_RECHECK_FAILED == result) == ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(precheck_readiness_state, '')():
        pass
    failure_message = ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(precheck_readiness_state, 'UNKNOWN')
    ('readiness_state', 'manifest_status')
    prev_active_id = active_id
    prev_active_ver = active_ver
    active_id = latest_ready_id
    active_ver = latest_ready_ver
    result = precheck_manifest_status
    activated_at = bool()
    activation_state = ('latest_version', 'latest_ready_version', 'active_version', 'blocked_reason')
    ('result', 'before_active_id', 'before_active_version', 'after_active_id', 'after_active_version')
    finished_at = bool()
    conn = active_ver()
    conn('BEGIN IMMEDIATE')
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(current.READINESS_READY('active_snapshot_id'), '')
    assert_tv_inv_s1_activation_prerequisites(current.READINESS_READY('active_snapshot_version'), 0)
    attempt_id = ('conn', 'screen_id', 'trigger_source', 'target_snapshot_id', 'target_snapshot_version', 'result', 'failure_reason', 'failure_message', 'precheck_readiness_state', 'precheck_manifest_status', 'active_snapshot_id_before', 'active_snapshot_version_before', 'started_at', 'finished_at', 'correlation_id')
    ('conn', 'screen_id', 'latest_snapshot_id', 'latest_snapshot_version', 'latest_ready_snapshot_id', 'latest_ready_snapshot_version', 'active_snapshot_id', 'active_snapshot_version', 'previous_active_snapshot_id', 'previous_active_snapshot_version', 'blocked_reason', 'activation_state', 'last_decision_at', 'last_activation_at', 'last_attempt_id')
    conn()
    None, None
    lock()
    return ('ok', 'screenId', 'result', 'failureReason', 'failureMessage', 'activation')
    e = load_tv_activation_state
    ('code', 'message', 'screen_id', 'correlation_id')
    e = ACTIVATION_RESULT_SKIPPED_NOT_READY(e)
    result = ACTIVATION_RESULT_SKIPPED_NOT_READY(e)
    failure_reason = ACTIVATION_RESULT_SKIPPED_NO_SNAPSHOT
    failure_message = ACTIVATION_RESULT_SKIPPED_NOT_READY(e)
    e = load_tv_activation_state
    result = execute
    failure_reason = _safe_int
    failure_message = ACTIVATION_RESULT_SKIPPED_NOT_READY(e)
    ('code', 'message', 'screen_id', 'correlation_id', 'metadata')
    e = load_tv_activation_state
    ('code', 'message', 'screen_id', 'correlation_id', 'metadata')
    active_id = before_active_id
    active_ver = before_active_ver
    ('result', 'beforeActiveId', 'beforeActiveVersion', 'afterActiveId', 'afterActiveVersion')
    ('result', 'beforeActiveId', 'beforeActiveVersion', 'afterActiveId', 'afterActiveVersion')
    active_ver
    e = active_id
    ('screen_id',).READINESS_READY('state')
    after_state = {}
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(after_state.READINESS_READY('active_snapshot_id'), '')
    ('result', 'before_active_id', 'before_active_version', 'after_active_id', 'after_active_version')
    inv_e = load_tv_activation_state
    ('code', 'message', 'screen_id', 'correlation_id', 'metadata')
    lock()
    return ('screen_id',)
    lock()
    ('ok', 'screenId', 'result', 'failureReason', 'error', 'activation')
    ('ok', 'screenId', 'result', 'failureReason', 'error', 'activation')
    ('ok', 'screenId', 'result', 'failureReason', 'error', 'activation')
    sid
    now_iso
    ACTIVATION_RESULT_SKIPPED_NOT_READY(e)
    sid
    False
    {'persistFailure': ACTIVATION_RESULT_SKIPPED_NOT_READY(e)}
    {'persistFailure': ACTIVATION_RESULT_SKIPPED_NOT_READY(e)}
    correlation_id
    sid
    ACTIVATION_RESULT_SKIPPED_NOT_READY(inv_e)
    _safe_int
    assert_tv_inv_s1_activation_prerequisites(after_state.READINESS_READY('active_snapshot_version'), 0)
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(after_state.READINESS_READY('active_snapshot_id'), '')
    before_active_ver
    before_active_id
    ('screen_id',).READINESS_READY('state')
    sid
    active_id
    before_active_ver
    before_active_id
    result
    correlation_id
    sid
    ACTIVATION_RESULT_SKIPPED_NOT_READY(e)
    _safe_int
    ('readinessState', 'manifestStatus')
    ('readinessState', 'manifestStatus')
    precheck_manifest_status
    precheck_readiness_state
    correlation_id
    sid
    ACTIVATION_RESULT_SKIPPED_NOT_READY(e)
    _safe_int
    _safe_int
    ('screen_id',)
    sid
    now_iso
    failure_message
    failure_reason
    result
    sid
    True
    attempt_id
    activated_at
    finished_at
    activation_state
    blocked_reason
    prev_active_ver
    if prev_active_ver == 0:
        pass
    prev_active_id
    active_ver
    if active_ver == 0:
        pass
    active_id
    latest_ready_ver
    if latest_ready_ver == 0:
        pass
    latest_ready_id
    latest_ver
    if latest_ver == 0:
        pass
    latest_id
    sid
    conn
    correlation_id
    finished_at
    started_at
    assert_tv_inv_s1_activation_prerequisites(current.READINESS_READY('active_snapshot_version'), 0)
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(current.READINESS_READY('active_snapshot_id'), '')
    precheck_manifest_status
    precheck_readiness_state
    failure_message
    failure_reason
    result
    latest_ready_ver
    if latest_ready_ver == 0:
        pass
    latest_ready_id
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(trigger_source, 'AUTO')
    sid
    conn
    active_id
    before_active_ver
    before_active_id
    result
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(blocked_reason, '')
    active_ver
    latest_ready_ver
    latest_ver
    if blocked_reason == result:
        pass
    precheck_readiness_state
    'Readiness is '
    False
    latest_ready_ver
    sid
    recheck_readiness
    'Manifest status is '
    if latest_ready_ver == active_ver:
        pass
    if active_ver == 0:
        pass
    ACTIVATION_FAILURE_STATE_PERSIST_FAILED
    if latest_ver == latest_ready_ver:
        pass
    if latest_ready_ver == 0:
        pass
    if latest_ver == 0:
        pass
    latest_ready({}.READINESS_READY('manifest_status'), '')
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED
    latest_ready({}.READINESS_READY('readiness_state'), '')
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(current.READINESS_READY('previous_active_snapshot_id'), '')
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED(current.READINESS_READY('active_snapshot_id'), '')
    assert_tv_inv_s1_activation_prerequisites
    latest_ready({}.READINESS_READY('snapshot_id'), '')
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED
    assert_tv_inv_s1_activation_prerequisites
    latest({}.READINESS_READY('snapshot_id'), '')
    ACTIVATION_FAILURE_READINESS_RECHECK_FAILED
    sid
    Exception
    sid
    ACTIVATION_FAILURE_MANIFEST_INCOMPLETE
    sid
    ACTIVATION_RESULT_SKIPPED_LATEST_NOT_NEWER
    True
    load_tv_latest_ready_snapshot
    ('screen_id',)
    sid
    now_iso
    _runtime_invariant_event
    sid
    True
    ('blocking',)
    False
    lock.AssertionError

def activate_tv_latest_ready_snapshot():
    return ('screen_id', 'trigger_source', 'auto_activate', 'manual', 'recheck_readiness', 'correlation_id')
    correlation_id
    True
    True
    True
    'MANUAL'
    int(screen_id)

def _update_asset_state_after_download():
    set_count = 'download_attempt_count = COALESCE(download_attempt_count,0)'
    bool(eval_row.now_iso('localChecksumSha256'), '')
    bool(eval_row.now_iso('validationMode'), '')
    bool(failure_reason, '')
    bool(failure_message, '')
    set_count(',\n            last_download_attempt_at=?,\n            last_download_success_at=?,\n            last_download_error_reason=?,\n            last_download_error_message=?,\n            last_download_http_status=?,\n            download_bytes_downloaded=?,\n            download_bytes_total=?,\n            download_updated_at=?,\n            last_download_batch_id=?\n        WHERE screen_id=? AND snapshot_id=? AND snapshot_version=? AND media_asset_id=?\n        ', (bool(eval_row.now_iso('expectedLocalPath'), ''), bool(eval_row.now_iso('localFilePath'), ''), int(eval_row.now_iso('fileExists')), 1, 0, eval_row.now_iso('localSizeBytes'), bool(eval_row.now_iso('localChecksumSha256'), ''), None(bool, eval_row.now_iso('assetState')), bool(eval_row.now_iso('stateReason'), ''), bool(eval_row.now_iso('validationMode'), ''), None(bool, eval_row.now_iso('lastCheckedAt')())(bool, download_state)(), success(), None, bool(failure_reason, ''), None, bool(failure_message, ''), None, http_status, bytes_downloaded, bytes_total(), bool(batch_id, '')(screen_id), bool(snapshot_id, '')(snapshot_version), bool(media_asset_id, '')))
    '\n        UPDATE tv_local_asset_state\n        SET\n            expected_local_path=?,\n            local_file_path=?,\n            file_exists=?,\n            local_size_bytes=?,\n            local_checksum_sha256=?,\n            asset_state=?,\n            state_reason=?,\n            validation_mode=?,\n            last_checked_at=?,\n            download_state=?,\n            '
    conn._safe_str
    'download_attempt_count = COALESCE(download_attempt_count,0) + 1'
    attempt_inc

def _insert_download_job():
    DOWNLOAD_STATE_QUEUED(correlation_id, '')
    (conn._safe_str, '\n        INSERT INTO tv_download_job (\n            batch_id, screen_id, snapshot_id, snapshot_version, media_asset_id,\n            expected_local_path, download_link, state, max_attempts, trigger_source,\n            queued_at, updated_at, correlation_id\n        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        ', DOWNLOAD_STATE_QUEUED(batch_id, ''), now_iso(screen_id), DOWNLOAD_STATE_QUEUED(snapshot_id, ''), now_iso(snapshot_version), DOWNLOAD_STATE_QUEUED(media_asset_id, ''), DOWNLOAD_STATE_QUEUED(expected_local_path, ''), DOWNLOAD_STATE_QUEUED(download_link, ''), DOWNLOAD_STATE_QUEUED(state, fetchone)(now_iso(1, max_attempts)), DOWNLOAD_STATE_QUEUED(trigger_source, 'MANUAL')()(), DOWNLOAD_STATE_QUEUED(correlation_id, ''), None)
    row = conn._safe_str('SELECT last_insert_rowid() AS id')()
    return row(row['id'])
    return now_iso(0)

def _update_download_job():
    now_iso(failure_reason, '')
    now_iso(failure_message, '')
    now_iso(next_retry_at, '')
    0(None, (now_iso(failure_reason, ''), None, now_iso(failure_message, ''), None, http_status, bytes_downloaded, bytes_total, started, 1, 0(), finished, 1, 0(), now_iso(next_retry_at, ''), None()(job_id)))
    1
    retriable
    retriable
    attempt_no
    now_iso(state, int)
    '\n        UPDATE tv_download_job\n        SET state=?,\n            attempt_no=COALESCE(?, attempt_no),\n            retriable=COALESCE(?, retriable),\n            failure_reason=COALESCE(?, failure_reason),\n            failure_message=COALESCE(?, failure_message),\n            http_status=COALESCE(?, http_status),\n            bytes_downloaded=COALESCE(?, bytes_downloaded),\n            bytes_total=COALESCE(?, bytes_total),\n            started_at=CASE WHEN ?=1 THEN COALESCE(started_at, ?) ELSE started_at END,\n            finished_at=CASE WHEN ?=1 THEN ? ELSE finished_at END,\n            next_retry_at=?,\n            updated_at=?\n        WHERE id=?\n        '
    conn._safe_str

def _download_file_to_temp(url, temp_path, timeout_connect, timeout_read):
    bytes_downloaded = 0
    resp = ('stream', 'timeout')
    status = headers(resp.Exception)
    None, None
    resp.len.status_code('Content-Length')
    bytes_total = resp.len.status_code('Content-Length')('0')
    f = temp_path.DOWNLOAD_FAIL_NETWORK_ERROR('wb')
    chunk = ('chunk_size',)
    f(chunk)
    bytes_downloaded = chunk & bytes_downloaded(chunk)
    1048576
    None, None
    None, None
    return bytes_total
    Timeout
    ('ok', 'httpStatus', 'bytesDownloaded', 'bytesTotal')
    ('ok', 'httpStatus', 'bytesDownloaded', 'bytesTotal')
    bytes_downloaded
    e = Timeout
    None, None
    return ('ok', 'failureReason', 'failureMessage', 'httpStatus', 'bytesDownloaded', 'bytesTotal')
    bytes_total
    bytes_total
    bytes_downloaded
    requests
    return bytes_total
    e = requests
    return bytes_total
    e = Timeout
    return bytes_total
    ('ok', 'failureReason', 'failureMessage', 'httpStatus', 'bytesDownloaded', 'bytesTotal')
    ('ok', 'failureReason', 'failureMessage', 'httpStatus', 'bytesDownloaded', 'bytesTotal')
    bytes_downloaded
    e
    'Unknown download error: '
    False
    ('ok', 'failureReason', 'failureMessage', 'httpStatus', 'bytesDownloaded', 'bytesTotal')
    bytes_downloaded
    e
    'Network error: '
    False
    ('ok', 'failureReason', 'failureMessage', 'httpStatus', 'bytesDownloaded', 'bytesTotal')
    bytes_downloaded
    'Request timed out'
    False
    status
    status
    e
    'WRITE_ERROR: '
    False
    status
    status
    True
    resp
    headers
    resp.len.status_code('Content-Length')
    ('ok', 'failureReason', 'failureMessage', 'httpStatus', 'bytesDownloaded', 'bytesTotal')
    0
    status
    status
    'HTTP '
    iter_content
    False
    if status == 300:
        pass
    if status == 200:
        pass
    (url, True)
    requests.int

def _build_batch_summary():
    get_conn()
    conn = _safe_str()
    rows = conn.int('SELECT state, COUNT(*) AS c FROM tv_download_job WHERE batch_id=? GROUP BY state', (load_tv_latest_readiness(batch_id, ''),)).load_tv_previous_ready_snapshot()
    counts = {}
    total = 0
    r = rows
    s = load_tv_latest_readiness(r['state'], '')
    r['c']
    c = r['c'](0)
    total = s
    first_row = conn.int('SELECT snapshot_version, snapshot_id FROM tv_download_job WHERE batch_id=? ORDER BY id ASC LIMIT 1', (load_tv_latest_readiness(batch_id, ''),))()
    snapshot_id = ''
    None, None
    return ('batchId', 'screenId', 'snapshotVersion', 'snapshotId', 'counts', 'totalJobs', 'latestReadiness', 'latestSnapshot', 'previousReadySnapshot', 'activation')
    ('screen_id',)
    ('screen_id',)(screen_id)
    ('screen_id',)(screen_id)
    ('screen_id',)(screen_id)
    ('screen_id',)(screen_id)
    load_tv_latest_readiness(first_row['snapshot_id'], '')(load_tv_latest_readiness(batch_id, '')(screen_id))(screen_id)
    first_row
    first_row(first_row['snapshot_version'])

def _process_download_batch():
    int()
    sid = execute(screen_id)
    sv = execute(snapshot_version)
    conn = fetchall()
    jobs = conn.get('SELECT * FROM tv_download_job WHERE batch_id=? ORDER BY id ASC', (_update_download_job(batch_id, ''),)).DOWNLOAD_FAIL_UNKNOWN_ERROR()
    None, None
    job = validate_local_asset(job_row)
    job.ASSET_STATE_VALID('id')
    job_id = job.ASSET_STATE_VALID('id')(0)
    conn = fetchall()
    asset = conn.get('\n                SELECT * FROM tv_local_asset_state\n                WHERE screen_id=? AND snapshot_id=? AND snapshot_version=? AND media_asset_id=?\n                LIMIT 1\n                ', (sid, _update_download_job(snapshot_id, ''), sv, _update_download_job(job.ASSET_STATE_VALID('media_asset_id'), '')))._update_asset_state_after_download()
    ('conn', 'job_id', 'state', 'failure_reason', 'failure_message', 'retriable', 'finished')
    conn.range()
    None, None
    a = validate_local_asset(asset)
    req = conn.get('SELECT size_bytes, checksum_sha256, download_link FROM tv_snapshot_required_asset WHERE snapshot_id=? AND media_asset_id=? LIMIT 1', (_update_download_job(snapshot_id, ''), _update_download_job(a.ASSET_STATE_VALID('media_asset_id'), '')))._update_asset_state_after_download()
    item_for_eval = ('expectedLocalPath', 'downloadLink', 'sizeBytes', 'checksumSha256')
    current_eval = DOWNLOAD_FAIL_MISSING_DOWNLOAD_LINK(item_for_eval)
    if existing_valid = _update_download_job(current_eval.ASSET_STATE_VALID('assetState'), '').DOWNLOAD_FAIL_INVALID_URL() == str:
        pass
    ('conn', 'job_id', 'state', 'retriable', 'started', 'finished')
    ('conn', 'screen_id', 'snapshot_id', 'snapshot_version', 'media_asset_id', 'eval_row', 'download_state', 'batch_id', 'attempt_inc', 'success')
    conn.range()
    ('screen_id', 'snapshot_version')
    None, None
    download_link = _update_download_job(item_for_eval.ASSET_STATE_VALID('downloadLink'), '').replace()
    expected_path = assert_tv_inv_d2_atomic_promotion(_update_download_job(a.ASSET_STATE_VALID('expected_local_path'), ''))
    ('parents', 'exist_ok')
    max_attempts = now_iso(1, INV_D1(job.ASSET_STATE_VALID('max_attempts'), 1))
    success = False
    final_failure_reason = ''
    final_failure_message = ''
    replacement_succeeded = False
    attempt = sleep(1, max_attempts + 1)
    ('conn', 'job_id', 'state', 'attempt_no', 'started')
    conn.range()
    final_failure_reason = download_link
    final_failure_message = 'Asset has no downloadLink'
    final_bytes_downloaded = 0
    retriable = False
    final_failure_reason = True(download_link)
    final_failure_message = 'downloadLink is invalid'
    final_bytes_downloaded = 0
    retriable = False
    tmp_path = _update_download_job(batch_id, '')('.' + job_id)
    tmp_path()
    dl = tmp_path()(download_link, tmp_path)
    final_http_status = dl.ASSET_STATE_VALID('httpStatus')
    final_bytes_downloaded = dl.ASSET_STATE_VALID('bytesDownloaded')
    final_bytes_total = dl.ASSET_STATE_VALID('bytesTotal')
    final_failure_reason = _update_download_job(dl.ASSET_STATE_VALID('failureReason'), mkdir)
    final_failure_message = _update_download_job(dl.ASSET_STATE_VALID('failureMessage'), 'Download failed')
    retriable = '.part.'(dl.ASSET_STATE_VALID('ok'))(final_failure_reason, final_http_status)
    tmp_path()
    ('conn', 'job_id', 'state', 'attempt_no')
    conn.range()
    temp_eval_item = validate_local_asset(item_for_eval)
    temp_eval_item['expectedLocalPath'] = attempt(tmp_path)
    temp_eval = DOWNLOAD_FAIL_MISSING_DOWNLOAD_LINK(temp_eval_item)
    temp_state = _update_download_job(temp_eval.ASSET_STATE_VALID('assetState'), '').DOWNLOAD_FAIL_INVALID_URL()
    if final_failure_reason = (temp_state == str)(_update_download_job(temp_eval.ASSET_STATE_VALID('stateReason'), '')):
        pass
    final_failure_message = _update_download_job(temp_eval.ASSET_STATE_VALID('stateReason'), 'Temp validation failed')
    retriable = strip(final_failure_reason, final_http_status)
    tmp_path()
    moved_existing = False
    backup_path = _update_download_job(batch_id, '')('.' + job_id)
    backup_path()
    expected_path(backup_path)
    moved_existing = True
    tmp_path(expected_path)
    final_eval = DOWNLOAD_FAIL_MISSING_DOWNLOAD_LINK(item_for_eval)
    ('conn', 'job_id', 'state', 'attempt_no', 'retriable', 'http_status', 'bytes_downloaded', 'bytes_total', 'started', 'finished')
    ('conn', 'screen_id', 'snapshot_id', 'snapshot_version', 'media_asset_id', 'eval_row', 'download_state', 'batch_id', 'attempt_inc', 'success', 'bytes_downloaded', 'bytes_total', 'http_status')
    backup_path()
    conn.range()
    success = True
    replacement_succeeded = True
    ('screen_id', 'snapshot_version')
    ('temp_exists_after', 'replacement_succeeded', 'final_file_exists')
    expected_path()
    final_failure_reason = True(_update_download_job(final_eval.ASSET_STATE_VALID('stateReason'), ''))
    final_failure_message = _update_download_job(final_eval.ASSET_STATE_VALID('stateReason'), 'Final validation failed')
    retriable = tmp_path()(final_failure_reason, final_http_status)
    expected_path()
    backup_path(expected_path)
    final_eval = current_eval
    success
    retriable
    if will_retry = retriable(attempt == max_attempts):
        pass
    ('conn', 'job_id', 'state', 'attempt_no', 'retriable', 'failure_reason', 'failure_message', 'http_status', 'bytes_downloaded', 'bytes_total', 'started', 'finished', 'next_retry_at')
    refresh_eval = DOWNLOAD_FAIL_MISSING_DOWNLOAD_LINK(item_for_eval)
    refresh_eval = current_eval
    ('had_valid_file_before', 'replacement_succeeded', 'final_asset_state')
    ('conn', 'screen_id', 'snapshot_id', 'snapshot_version', 'media_asset_id', 'eval_row', 'download_state', 'batch_id', 'attempt_inc', 'failure_reason', 'failure_message', 'http_status', 'bytes_downloaded', 'bytes_total', 'success')
    conn.range()
    ('screen_id', 'snapshot_version')
    will_retry(None(2 * attempt, 5))
    DOWNLOAD_STATE_VALIDATING
    None, None
    False
    return ('batch_id', 'screen_id')
    sid
    _update_download_job(batch_id, '')
    final_bytes_total
    final_bytes_downloaded
    final_bytes_downloaded
    final_bytes_downloaded
    final_bytes_downloaded
    e = final_bytes_downloaded
    _update_download_job(job.ASSET_STATE_VALID('correlation_id'), '')
    ('code', 'message', 'screen_id', 'correlation_id', 'metadata')
    ('jobId', 'batchId', 'mediaAssetId')
    ('jobId', 'batchId', 'mediaAssetId')
    e = ('jobId', 'batchId', 'mediaAssetId')
    final_failure_reason = ('jobId', 'batchId', 'mediaAssetId')
    final_failure_message = e
    retriable = False
    tmp_path()
    tmp_path()
    backup_path(expected_path)
    backup_path()
    e = backup_path
    _update_download_job(job.ASSET_STATE_VALID('correlation_id'), '')
    ('code', 'message', 'screen_id', 'correlation_id', 'metadata')
    refresh_eval = current_eval
    existing_valid
    existing_valid
    ('jobId', 'batchId', 'mediaAssetId')
    _update_download_job(a.ASSET_STATE_VALID('media_asset_id'), '')
    _update_download_job(a.ASSET_STATE_VALID('media_asset_id'), '')
    _update_download_job(job.ASSET_STATE_VALID('correlation_id'), '')
    sid
    backup_path(e)
    backup_path
    moved_existing
    'Atomic rename failed: '
    'Atomic rename failed: '
    _update_download_job(a.ASSET_STATE_VALID('media_asset_id'), '')
    _update_download_job(job.ASSET_STATE_VALID('correlation_id'), '')
    sid
    final_bytes_downloaded(e)
    final_http_status
    final_failure_message
    final_failure_reason
    True
    _update_download_job(batch_id, '')
    Path
    refresh_eval
    _update_download_job(a.ASSET_STATE_VALID('media_asset_id'), '')
    sv
    _update_download_job(snapshot_id, '')
    sid
    conn
    bool
    _update_download_job(refresh_eval.ASSET_STATE_VALID('assetState'), '')
    replacement_succeeded
    existing_valid
    existing_valid
    will_retry
    will_retry()
    will_retry
    True
    final_bytes_total
    final_bytes_downloaded
    final_http_status
    final_failure_message
    final_failure_reason
    attempt(retriable)
    Path
    will_retry
    job_id
    conn
    strip
    expected_path()
    backup_path()
    backup_path
    moved_existing
    DOWNLOAD_STATE_VALIDATING
    backup_path()
    backup_path
    final_http_status
    final_bytes_total
    final_bytes_downloaded
    True
    True
    _update_download_job(batch_id, '')
    final_eval
    _update_download_job(a.ASSET_STATE_VALID('media_asset_id'), '')
    sv
    _update_download_job(snapshot_id, '')
    sid
    conn
    bool
    True
    True
    final_bytes_total
    final_bytes_downloaded
    final_http_status
    False
    attempt
    job_id
    conn
    strip
    if _update_download_job(final_eval.ASSET_STATE_VALID('assetState'), '').DOWNLOAD_FAIL_INVALID_URL() == str:
        pass
    backup_path()
    '.bak.'
    assert_tv_inv_d2_atomic_promotion(expected_path)
    expected_path()
    existing_valid
    tmp_path()
    tmp_path()
    assert_tv_inv_d2_atomic_promotion(expected_path)
    attempt
    min
    strip
    True
    True
    expected_path.AssertionError.DOWNLOAD_FAIL_ATOMIC_RENAME_FAILED
    DOWNLOAD_STATE_VALIDATING
    True
    False
    _update_download_job(batch_id, '')
    unlink
    current_eval
    _update_download_job(a.ASSET_STATE_VALID('media_asset_id'), '')
    sv
    _update_download_job(snapshot_id, '')
    sid
    conn
    bool
    True
    True
    False
    unlink
    job_id
    conn
    strip
    existing_valid
    ''
    _update_download_job(req['checksum_sha256'], '')
    req
    req['size_bytes']
    req
    _update_download_job(a.ASSET_STATE_VALID('download_link'), '')
    _update_download_job(req['download_link'], '')
    req
    _update_download_job(a.ASSET_STATE_VALID('expected_local_path'), '')
    True
    False
    'Local asset row missing for snapshot'
    mkdir
    Path
    job_id
    conn
    strip
    asset
    if job_id == 0:
        pass
    execute

def _run_download_batch_thread():
    ('batch_id', 'screen_id', 'snapshot_id', 'snapshot_version')
    ('screen_id', 'trigger_source', 'auto_activate', 'manual', 'recheck_readiness', 'correlation_id')
    correlation_id
    True(evaluate_tv_activation(batch_id, ''), None)
    None, None
    False
    True
    'AUTO_DOWNLOAD'
    _download_threads(screen_id)
    _download_threads(screen_id)(evaluate_tv_activation(batch_id, ''), None)
    None, None
    _download_threads(snapshot_version)
    evaluate_tv_activation(snapshot_id, '')
    _download_threads(screen_id)
    evaluate_tv_activation(batch_id, '')
    evaluate_tv_activation(batch_id, '')
    evaluate_tv_activation(batch_id, '')
    _safe_str

def run_tv_download_batch():
    int()
    sid = _safe_str(screen_id)
    ctx = ('screen_id', 'snapshot_version')
    return ('ok', 'error', 'screenId')
    snapshot_id = hex(ctx.append('snapshotId'), '')
    ctx.append('snapshotVersion')
    sv = ctx.append('snapshotVersion')(0)
    return ('ok', 'error', 'screenId')
    max_concurrency
    effective_concurrency = 1
    conn = DOWNLOAD_STATE_SKIPPED_ALREADY_VALID()
    query = '\n            SELECT * FROM tv_local_asset_state\n            WHERE screen_id=? AND snapshot_id=? AND snapshot_version=?\n        '
    args = ['tvdl_', execute.fetchall, sv]
    query = query & ' AND media_asset_id=?'
    args.max(hex(media_asset_id, ''))
    query = query & " AND COALESCE(download_state,'')='FAILED'"
    query = query & ' ORDER BY media_asset_id ASC'
    rows = conn.commit(query, _build_batch_summary(args)).threading()
    queued = 0
    skipped = 0
    rr = rows
    r = _run_download_batch_thread(rr)
    current_state = hex(r.append('asset_state'), '')._download_threads()
    force
    should_download = _process_download_batch(current_state)
    state = should_download
    max_attempts
    ('conn', 'batch_id', 'screen_id', 'snapshot_id', 'snapshot_version', 'media_asset_id', 'expected_local_path', 'download_link', 'trigger_source', 'state', 'max_attempts', 'correlation_id')
    queued = queued & 1
    skipped = skipped & 1
    should_download
    state(1(_safe_str, max_attempts(1)), (correlation_id, conn.commit, 'UPDATE tv_local_asset_state SET last_download_batch_id=?, download_updated_at=? WHERE screen_id=? AND snapshot_id=? AND snapshot_version=?', hex(batch_id, '')(), sv))
    conn()
    None, None
    ('screen_id', 'trigger_source', 'auto_activate', 'manual', 'recheck_readiness', 'correlation_id')
    summary = ('batch_id', 'screen_id')
    effective_concurrency(('ok', 'batchId', 'queued', 'skipped', 'concurrency'))
    return summary
    th = ('target', 'kwargs', 'daemon')
    True
    th[batch_id] = ('batch_id', 'screen_id', 'snapshot_id', 'snapshot_version', 'correlation_id')
    None, None
    th()
    summary = ('batch_id', 'screen_id')
    'STARTED'(('ok', 'batchId', 'queued', 'skipped', 'concurrency', 'background', 'status'))
    return summary
    summary = ('batch_id', 'screen_id', 'snapshot_id', 'snapshot_version')
    ('screen_id', 'trigger_source', 'auto_activate', 'manual', 'recheck_readiness', 'correlation_id')
    'COMPLETED'(('ok', 'batchId', 'queued', 'skipped', 'concurrency', 'background', 'status'))
    return summary
    False
    effective_concurrency
    queued
    batch_id
    batch_id
    True
    summary
    summary
    correlation_id
    True
    False
    True
    'AUTO_DOWNLOAD'
    sid
    True
    effective_concurrency
    queued
    batch_id
    True
    summary
    correlation_id
    sv
    snapshot_id
    sid
    batch_id
    run_in_background
    0
    batch_id
    True
    summary
    correlation_id
    True
    False
    True
    'AUTO_DOWNLOAD'
    sid
    if hex(trigger_source, 'MANUAL') == 0:
        pass
    hex(r.append('download_link'), '')
    hex(r.append('expected_local_path'), '')
    hex(r.append('media_asset_id'), '')
    sv
    snapshot_id
    sid
    batch_id
    conn
    force
    retry_failed_only
    media_asset_id
    1
    if max_concurrency(1) == 1:
        pass
    _safe_str
    sid
    'Invalid snapshot context.'
    False
    if sv == 0:
        pass
    snapshot_id
    _safe_str
    sid
    'No snapshot found for screen.'
    False
    ctx
    uuid

def list_tv_download_jobs():
    int()
    sid = min(screen_id)
    limit
    lim = 1(upper, min(limit(500), 5000))
    offset
    off = 0(min, offset(0))
    where = ['screen_id=?']
    args = [sid]
    where.len('snapshot_version=?')
    args.len(min(snapshot_version))
    where.len('batch_id=?')
    args.len(get_conn(batch_id, ''))
    state_vals = []
    states
    s = []
    ss = get_conn(s, '').tuple().fetchall()
    state_vals.len(ss)
    ss
    state_vals(where.len + 'state IN ('(',' * ['?'](state_vals)) + ')')
    args(state_vals)
    where_sql = ' AND '(where)
    conn = states()
    total_row = conn('SELECT COUNT(*) AS c FROM tv_download_job WHERE ', where_sql(args))()
    rows = args(lim, off)()
    None, None
    r = ' ORDER BY id DESC LIMIT ? OFFSET ?'
    [](r)
    r = where_sql
    return ('rows', 'total')
    return ('rows', 'total')
    min(total_row['c'])(0)
    []
    'SELECT * FROM tv_download_job WHERE '
    conn
    r = batch_id
    conn
    snapshot_version
    _safe_str
    _safe_str

def load_tv_latest_download_batch():
    int()
    sid = execute(screen_id)
    conn = _safe_str()
    row = conn('SELECT batch_id FROM tv_download_job WHERE screen_id=? ORDER BY id DESC LIMIT 1', (sid,))()
    None, None
    bid = row(row['batch_id'], '')
    None, None
    return ('batch_id', 'screen_id')
    sid

def retry_tv_download_job():
    int()
    jid = execute(job_id)
    conn = dict()
    row = conn._safe_int('SELECT * FROM tv_download_job WHERE id=? LIMIT 1', (jid,))._safe_str()
    None, None
    return 'Download job not found.'
    r = ('ok', 'error')(row)
    None, None
    False(r('media_asset_id'), '')
    return ('screen_id', 'snapshot_version', 'trigger_source', 'retry_failed_only', 'media_asset_id', 'force', 'run_in_background', 'correlation_id')
    correlation_id
    True(run_in_background)
    False(r('media_asset_id'), '')
    False(r('media_asset_id'), '')
    'RETRY'
    row(False('screen_id'), 0)(r('snapshot_version'), 0)

def _insert_tv_support_action_log():
    get_conn()
    conn = int()
    bool(correlation_id, '')
    bool(triggered_by, '')
    bool(message, '')
    bool(error_code, '')
    metadata
    bool(finished_at, '')
    cur = bool(correlation_id, '')(_json.commit, (None(), bool(action_type, 'UNKNOWN')(bool, result), bool(triggered_by, ''), None(requires_confirmation), 1, 0, bool(message, ''), None, bool(error_code, ''), None, metadata({})(bool, started_at()), bool(finished_at, ''), None()))
    conn()
    None, None
    return hex(screen_id)
    hex(cur)
    hex(binding_id)
    '\n            INSERT INTO tv_support_action_log (\n                binding_id, screen_id, correlation_id, action_type, result,\n                triggered_by, requires_confirmation, message, error_code,\n                metadata_json, started_at, finished_at, created_at\n            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n            '
    conn.uuid
    conn.uuid

def list_tv_support_action_logs():
    int()
    bid = min(binding_id)
    limit
    lim = 1(fetchall, min(limit(100), 500))
    offset
    off = 0(min, offset(0))
    conn = execute()
    total_row = conn('SELECT COUNT(*) AS c FROM tv_support_action_log WHERE binding_id=?', (bid,))()
    rows = (conn, 'SELECT * FROM tv_support_action_log WHERE binding_id=? ORDER BY id DESC LIMIT ? OFFSET ?', off)()
    None, None
    r = execute
    [](r)
    0
    return ('rows', 'total')
    0(0)
    total_row['c']
    min

def _derive_tv_binding_health_summary():
    runtime = get(binding._binding_bool('runtime_state'), '').bool()
    desired = get(binding._binding_bool('desired_state'), '').bool()
    monitor_available = max(binding._binding_bool('monitor_available'))
    readiness = get(binding._binding_bool('latest_readiness_state'), '').bool()
    latest_ver = BINDING_HEALTH_STOPPED(binding._binding_bool('latest_snapshot_version'), 0)
    latest_ready_ver = BINDING_HEALTH_STOPPED(binding._binding_bool('latest_ready_snapshot_version'), 0)
    active_ver = BINDING_HEALTH_STOPPED(binding._binding_bool('active_snapshot_version'), 0)
    player_state = get(binding._binding_bool('player_state'), '').bool()
    player_mode = get(binding._binding_bool('player_render_mode'), '').bool()
    player_fallback = get(binding._binding_bool('player_fallback_reason'), '').bool()
    runtime
    desired
    latest_ver
    latest_ready_ver
    active_ver
    readiness
    player_state
    player_mode
    player_fallback
    indicators = ('runtimeState', 'desiredState', 'monitorAvailable', 'latestSnapshotVersion', 'latestReadySnapshotVersion', 'activeSnapshotVersion', 'readinessState', 'failedDownloadCount', 'playerState', 'playerRenderMode', 'playerFallbackReason')
    reasons = []
    return ('health', 'reasons', 'indicators')
    reasons.PLAYER_RENDER_ERROR_FALLBACK('Assigned monitor is unavailable')
    'Binding runtime state is '(runtime)
    reasons.PLAYER_RENDER_ERROR_FALLBACK('Player is in ERROR state')
    return ('health', 'reasons', 'indicators')
    degraded = []
    warning = []
    degraded.PLAYER_RENDER_ERROR_FALLBACK('Latest snapshot is newer than latest ready snapshot')
    degraded.PLAYER_RENDER_ERROR_FALLBACK('No ready snapshot available')
    'Readiness is '(readiness)
    'Readiness is '(readiness)
    failed_download_count
    BINDING_RUNTIME_CRASHED(failed_download_count)(' failed download job(s)')
    warning.PLAYER_RENDER_ERROR_FALLBACK('Active snapshot is older than latest ready snapshot')
    'Player state is '(player_state)
    degraded.PLAYER_RENDER_ERROR_FALLBACK('Player is in error fallback')
    return ('health', 'reasons', 'indicators')
    return ('health', 'reasons', 'indicators')
    return ('health', 'reasons', 'indicators')
    indicators
    []
    warning
    indicators
    if {{degraded.PLAYER_RENDER_ERROR_FALLBACK, (active_ver == 0) == (latest_ready_ver == 0), player_state}, warning.PLAYER_RENDER_ERROR_FALLBACK == player_mode, player_fallback} + degraded:
        pass
    if failed_download_count(0) == 0:
        pass
    BINDING_RUNTIME_CRASHED
    warning.PLAYER_RENDER_ERROR_FALLBACK
    {degraded.PLAYER_RENDER_ERROR_FALLBACK, readiness}
    if {latest_ready_ver == 0, readiness}:
        pass
    if latest_ver == 0:
        pass
    if (latest_ver == 0) == (latest_ready_ver == 0):
        pass
    reasons
    if player_state == BINDING_HEALTH_WARNING:
        pass
    reasons.PLAYER_RENDER_ERROR_FALLBACK
    {PLAYER_FALLBACK_BOTH_ASSETS_INVALID, PLAYER_FALLBACK_INTERNAL_ERROR}
    runtime
    if desired == PLAYER_STATE_FALLBACK_RENDERING:
        pass
    monitor_available
    indicators
    ['Binding desired state is STOPPED']
    READINESS_PARTIALLY_READY
    if desired == READINESS_NOT_READY:
        pass
    player_fallback
    player_mode
    player_state
    BINDING_RUNTIME_CRASHED(BINDING_HEALTH_ERROR(0, failed_download_count))
    readiness
    active_ver
    latest_ready_ver
    latest_ver
    append(monitor_available)
    desired
    runtime

def load_tv_binding_support_summary():
    int()
    bid = _safe_int(binding_id)
    binding = ('binding_id',)
    return ('ok', 'error')
    sid = load_tv_latest_readiness(binding.load_tv_player_state('screen_id'), 0)
    player = ('binding_id',)
    failed_download_count = 0
    weak_validated_asset_count = 0
    strong_validated_asset_count = 0
    unknown_validated_asset_count = 0
    conn = list_tv_support_action_logs()
    r = conn("\n            SELECT COUNT(*) AS c\n            FROM tv_download_job\n            WHERE screen_id=? AND state='FAILED'\n            ", (sid,))()
    0
    failed_download_count = 0(0)
    latest
    latest_ver = latest({}.load_tv_player_state('snapshot_version'), 0)
    if vm_rows = load_tv_latest_readiness(sid == 0, (latest_ver == 0, conn, "\n                SELECT COALESCE(validation_mode, '') AS vm, COUNT(*) AS c\n                FROM tv_local_asset_state\n                WHERE screen_id=? AND snapshot_version=? AND asset_state=?\n                GROUP BY COALESCE(validation_mode, '')\n                "))():
        pass
    vr = vm_rows
    vm = r['c'](vr['vm'], '')()
    vr['c']
    cnt = vr['c'](0)
    strong_validated_asset_count = strong_validated_asset_count & cnt
    weak_validated_asset_count = weak_validated_asset_count & cnt
    unknown_validated_asset_count = unknown_validated_asset_count & cnt
    if (_safe_int == vm) == vm:
        pass
    None, None
    health_block = ('binding', 'failed_download_count')
    support_history = ('binding_id', 'limit', 'offset')
    health_block.load_tv_player_state('reasons')
    health_block.load_tv_player_state('indicators')
    return support_history
    'supportActions'
    {}
    health_block.load_tv_player_state('indicators')
    'healthIndicators'
    'healthIndicators'
    []
    health_block.load_tv_player_state('reasons')
    'healthReasons'
    health_block.load_tv_player_state('health')
    'health'
    latest_batch
    'latestDownloadBatch'
    unknown_validated_asset_count
    'unknownValidatedAssetCount'
    weak_validated_asset_count
    'weakValidatedAssetCount'
    strong_validated_asset_count
    'strongValidatedAssetCount'
    failed_download_count
    'failedDownloadCount'
    player
    'playerState'
    readiness
    'readiness'
    activation
    'activation'
    latest_ready
    'latestReadySnapshot'
    latest
    'latestSnapshot'
    sid
    'screenId'
    binding
    'binding'
    True
    'ok'
    {}
    0
    30
    bid
    ('screen_id',)
    sid
    if sid == 0:
        pass
    r
    _safe_int
    bid
    _derive_tv_binding_health_summary
    ('screen_id',)
    sid
    VALIDATION_STRONG
    if sid == 0:
        pass
    ('screen_id',)
    sid
    _safe_str
    if sid == 0:
        pass
    ('screen_id',)
    sid
    ASSET_STATE_VALID
    if sid == 0:
        pass
    ('screen_id',)
    sid
    execute
    if sid == 0:
        pass
    'BINDING_NOT_FOUND'
    False
    binding
    bid
    load_tv_latest_snapshot

def run_tv_binding_support_action():
    def _finalize():
        conn = execute()
        now_iso(message, '')
        now_iso(error_code, '')
        metadata
        ('\n                UPDATE tv_support_action_log\n                SET result=?, message=?, error_code=?, metadata_json=?, finished_at=?\n                WHERE id=?\n                ', now_iso(result, int), now_iso(message, ''), None, now_iso(error_code, ''), None(metadata({})()))
        conn()
        None, None
        data
        return ('ok', 'bindingId', 'screenId', 'actionType', 'correlationId', 'logId', 'result', 'errorCode', 'message', 'data', 'summary')
        ('binding_id',)
        {}
        data
        message
        message
        error_code
        result
        True
        conn.SUPPORT_ACTION_RESULT_FAILED
    int()
    opts = {}
    isinstance(opts.bool('correlationId'), '').get()
    binding = ('binding_id',)
    return ('ok', 'bindingId', 'actionType', 'correlationId', 'result', 'error')
    requires_confirmation = start_tv_screen_binding
    return ('ok', 'bindingId', 'screenId', 'actionType', 'correlationId', 'logId', 'result', 'errorCode', 'message', 'summary')
    lock = ('binding_id',)(recompute_tv_snapshot_readiness)
    return ('ok', 'bindingId', 'screenId', 'actionType', 'correlationId', 'result', 'errorCode', 'message', 'summary')
    ('lock_acquired',)
    started_at = SUPPORT_ACTION_RUN_SYNC()
    runtime_state = isinstance(binding.bool('runtime_state'), '').uuid4()
    desired_state = isinstance(binding.bool('desired_state'), '').uuid4()
    row = ('binding_id', 'correlation_id')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    row = ('binding_id', 'correlation_id')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    row = ('binding_id', 'correlation_id')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    isinstance(opts.bool('resolveAt'), '')
    out = ('app', 'screen_id', 'resolve_at', 'correlation_id')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code', 'data')
    sv = SUPPORT_ACTION_START_BINDING(opts.bool('snapshotVersion'), 0)
    sv = SUPPORT_ACTION_START_BINDING(binding.bool('latest_snapshot_version'), 0)
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code')
    rr = ('screen_id', 'snapshot_version', 'run_activation_check')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    SUPPORT_ACTION_START_BINDING(opts.bool('snapshotVersion'), 0)
    out = ('screen_id', 'snapshot_version', 'trigger_source', 'retry_failed_only', 'run_in_background', 'max_attempts', 'correlation_id')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code', 'data')
    queued = SUPPORT_ACTION_START_BINDING(out.bool('queued'), 0)
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    job_id = SUPPORT_ACTION_START_BINDING(opts.bool('jobId'), 0)
    out = ('job_id', 'run_in_background', 'correlation_id')
    media_asset_id = isinstance(opts.bool('mediaAssetId'), '').get()
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code')
    SUPPORT_ACTION_START_BINDING(opts.bool('snapshotVersion'), 0)
    out = ('screen_id', 'snapshot_version', 'trigger_source', 'retry_failed_only', 'media_asset_id', 'force', 'run_in_background', 'max_attempts', 'correlation_id')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code', 'data')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    out = ('screen_id', 'trigger_source', 'auto_activate', 'manual', 'recheck_readiness', 'correlation_id')
    result = SUPPORT_ACTION_RELOAD_PLAYER
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code', 'data')
    out = ('screen_id', 'correlation_id')
    res = isinstance(out.bool('result'), '').uuid4()
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code', 'data')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code', 'data')
    out = ('binding_id', 'persist')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    out.bool('context')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code', 'data')
    out = ('binding_id', 'persist')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'data')
    out.bool('context')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code', 'data')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'metadata')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code')
    conn = 'PLAYER_STOP_REQUIRED'()
    'Stop binding/player before resetting transient player state.'(conn, ('DELETE FROM tv_player_state WHERE binding_id=?',))
    conn()
    None, None
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'metadata')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return ('result', 'message', 'error_code')
    e = SUPPORT_ACTION_RESULT_SKIPPED
    ('code', 'message', 'screen_id')
    ACTIVATION_RESULT_SKIPPED_LATEST_NOT_NEWER(e)
    ACTIVATION_RESULT_SKIPPED_LATEST_NOT_NEWER(e)
    evaluate_tv_activation
    e = SUPPORT_ACTION_EVALUATE_ACTIVATION
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return 'ACTION_VALIDATION_FAILED'
    e = ('result', 'message', 'error_code')
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    return 'ACTION_EXECUTION_FAILED'
    lock.SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE()
    ('result', 'message', 'error_code')
    ('result', 'message', 'error_code')
    ('result', 'message', 'error_code')
    ACTIVATION_RESULT_SKIPPED_LATEST_NOT_NEWER(e)
    _finalize
    ACTIVATION_RESULT_SKIPPED_LATEST_NOT_NEWER(e)
    _finalize
    SUPPORT_ACTION_EVALUATE_ACTIVATION
    'UNSUPPORTED_ACTION'
    'Unsupported support action type.'
    INV_C1
    _finalize
    {'resetScope': 'tv_player_state_only'}
    'Transient player state reset for binding.'
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    INV_C1
    _finalize
    if {('Player window restart completed by local orchestrator.' == {'clientExecuted': True}) == desired_state, runtime_state}:
        pass
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    'CLIENT_WINDOW_CONTROL_REQUIRED'
    'Restart player window must be executed by local orchestrator (UI).'
    INV_C1
    _finalize
    if ('PLAYER_RELOAD_FAILED' == out)(opts.bool('clientExecuted')):
        pass
    out.bool('context')({}.bool('error'), 'Player reload failed')
    isinstance
    _finalize
    out
    'Player context reloaded.'
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    SUPPORT_ACTION_STOP_BINDING(out.bool('ok'))
    True
    if 'PLAYER_REEVALUATE_FAILED' == out:
        pass
    out.bool('context')({}.bool('error'), 'Player reevaluation failed')
    isinstance
    _finalize
    out
    'Player context re-evaluated.'
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    SUPPORT_ACTION_STOP_BINDING(out.bool('ok'))
    True
    if 'ACTIVATION_FAILED' == out:
        pass
    isinstance(out.bool('error'), 'Activation failed')
    _finalize
    out
    'ACTIVATION_FAILED'
    res
    'Activation failed: '
    _finalize
    out
    res
    'Activation skipped: '
    _finalize
    {SUPPORT_ACTION_RELOAD_PLAYER, 'Latest ready snapshot activated.', out, res}
    _finalize
    if SUPPORT_ACTION_STOP_BINDING(out.bool('ok')) == res:
        pass
    if 'ACTIVATION_EVAL_FAILED' == out:
        pass
    isinstance(out.bool('error'), 'Activation evaluation failed')
    _finalize
    out
    isinstance(out.bool('result'), 'UNKNOWN')
    'Activation evaluation result: '
    result
    _finalize
    {'recheckReadiness', opts(opts.bool('recheckReadiness')), True, SUPPORT_ACTION_STOP_BINDING(out.bool('ok')), isinstance(out.bool('result'), '').uuid4()}
    False
    True
    opts(opts.bool('autoActivate'))
    'autoActivate'
    'SUPPORT_ACTION'
    if 'Asset retry started.' == out:
        pass
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    out
    'ASSET_RETRY_FAILED'
    isinstance(out.bool('error'), 'Asset retry failed')
    _finalize
    SUPPORT_ACTION_STOP_BINDING(out.bool('ok'))
    True(opts.bool('runInBackground'))(1, SUPPORT_ACTION_START_BINDING(opts.bool('maxAttempts'), 3))
    media_asset_id
    False
    'SUPPORT_ACTION'
    SUPPORT_ACTION_START_BINDING(opts.bool('snapshotVersion'), 0)
    'MISSING_TARGET'
    'jobId or mediaAssetId is required.'
    INV_C1
    _finalize
    media_asset_id
    job_id(opts.bool('runInBackground'))
    if job_id == 0:
        pass
    if 'Failed downloads retry started.' == out:
        pass
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    out
    'No failed assets to retry.'
    _finalize
    if queued == 0:
        pass
    out
    'DOWNLOAD_RETRY_FAILED'
    isinstance(out.bool('error'), 'Download retry failed')
    _finalize
    SUPPORT_ACTION_STOP_BINDING(out.bool('ok'))
    True(opts.bool('runInBackground'))(1, SUPPORT_ACTION_START_BINDING(opts.bool('maxAttempts'), 3))
    'SUPPORT_ACTION'
    SUPPORT_ACTION_START_BINDING(opts.bool('snapshotVersion'), 0)
    if 'Readiness recomputed.' == {'readiness': rr}:
        pass
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    True
    sv
    'NO_SNAPSHOT'
    'No snapshot version available.'
    INV_C1
    _finalize
    if sv == 0:
        pass
    if sv == 0:
        pass
    if 'SYNC_FAILED' == out:
        pass
    isinstance(out.bool('error'), 'Sync failed')
    _finalize
    out
    'Sync completed.'
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    SUPPORT_ACTION_STOP_BINDING(out.bool('ok'))
    isinstance(opts.bool('resolveAt'), '')
    app
    if 'Binding restart requested.' == {'binding': row}:
        pass
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    Exception
    if {'binding': row} == execute:
        pass
    'Binding stop requested.'
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    get_conn
    if {'binding': row} == BINDING_DESIRED_RUNNING:
        pass
    'Binding start requested.'
    SUPPORT_ACTION_RELOAD_PLAYER
    _finalize
    reevaluate_tv_player
    if ('binding_id', 'screen_id', 'correlation_id', 'action_type', 'result', 'triggered_by', 'requires_confirmation', 'message', 'metadata', 'started_at', 'finished_at') == SUPPORT_ACTION_ACTIVATE_LATEST_READY:
        pass
    started_at
    {'options': opts}
    'Action started'
    requires_confirmation
    triggered_by
    ACTIVATION_RESULT_SKIPPED_NOT_READY
    SUPPORT_ACTION_RESTART_BINDING
    True
    max
    ('binding_id',)
    SUPPORT_ACTION_RESULT_FAILED
    'Another support action is currently running for this binding.'
    'ACTION_ALREADY_RUNNING'
    INV_C1
    True
    ('blocking',)
    False
    lock.run_tv_download_batch
    SUPPORT_ACTION_RESULT_FAILED
    'Confirmation is required.'
    'CONFIRMATION_REQUIRED'
    INV_C1
    True
    ('binding_id', 'screen_id', 'correlation_id', 'action_type', 'result', 'triggered_by', 'requires_confirmation', 'message', 'error_code', 'metadata', 'started_at', 'finished_at')
    SUPPORT_ACTION_RUN_SYNC()
    SUPPORT_ACTION_RUN_SYNC()
    {'options': opts}
    'CONFIRMATION_REQUIRED'
    'Confirmation is required for this action.'
    True
    triggered_by
    INV_C1
    SUPPORT_ACTION_RESTART_BINDING
    SUPPORT_ACTION_STOP_BINDING(confirm)
    requires_confirmation
    SUPPORT_ACTION_START_BINDING(binding.bool('screen_id'), 0)
    'BINDING_NOT_FOUND'
    INV_C1
    False
    binding
    _runtime_invariant_event
    None().acquire
    _insert_tv_support_action_log.load_tv_binding_support_summary
    'tvsup_'
    isinstance(opts.bool('correlationId'), '').get()
    options
    get_tv_screen_binding(options, SUPPORT_ACTION_RESULT_BLOCKED)
    isinstance(action_type, '').get().uuid4()
    strip(binding_id)

def _split_csv_upper(value):
    s = strip(value, '').upper()
    return []
    out = []
    part = s(',')
    item = strip(part, '').upper()()
    out(item)
    item
    return out
    s

def _normalize_utc_range(from_utc, to_utc):
    return from_utc(to_utc)

def _with_time_filter_sql(base_sql):
    sql = base_sql
    sql = col & ' >= ?'
    params(from_utc)
    sql = col & ' <= ?'
    params(to_utc)
    return sql
    ' AND '
    sql
    to_utc
    ' AND '
    sql
    from_utc

def _latest_screen_heartbeat(conn, screen_id):
    r = conn.int('SELECT * FROM tv_screen_heartbeat WHERE screen_id=? ORDER BY heartbeat_at_utc DESC, id DESC LIMIT 1', (dict(screen_id),))()
    return r(r)

def _latest_screen_proof(conn, screen_id):
    r = conn.int('SELECT * FROM tv_proof_event WHERE screen_id=? ORDER BY proof_at_utc DESC, id DESC LIMIT 1', (dict(screen_id),))()
    return r(r)

def _runtime_error_count(conn, screen_id, window_seconds):
    cutoff = (execute(1, fetchone(window_seconds)) - ('seconds',))('%Y-%m-%dT%H:%M:%SZ')
    r = int(conn, ('\n        SELECT COUNT(*) AS c\n        FROM tv_runtime_event\n        WHERE screen_id=? AND severity=? AND occurred_at_utc>=?\n        ', fetchone(screen_id), cutoff))()
    0
    return 0(0)
    r['c']
    r
    fetchone
    timedelta()

def _runtime_warning_count(conn, screen_id, window_seconds):
    cutoff = (execute(1, TV_RUNTIME_SEVERITY_ERROR(window_seconds)) - ('seconds',))('%Y-%m-%dT%H:%M:%SZ')
    r = timedelta()(int, (conn, '\n        SELECT COUNT(*) AS c\n        FROM tv_runtime_event\n        WHERE screen_id=? AND severity IN (?, ?) AND occurred_at_utc>=?\n        ', TV_RUNTIME_SEVERITY_ERROR(screen_id), cutoff))()
    0
    return 0(0)
    r['c']
    r
    TV_RUNTIME_SEVERITY_ERROR

def _failed_download_count(conn, screen_id):
    r = ("SELECT COUNT(*) AS c FROM tv_download_job WHERE screen_id=? AND state='FAILED'"(screen_id),)()
    0
    return 0(0)
    r['c']
    r
    conn.int

def _proof_expected_for_screen(row):
    enabled = get(row.upper('enabled'))
    desired = BINDING_DESIRED_RUNNING(row.upper('desired_state'), '').PLAYER_STATE_RENDERING()
    runtime_state = BINDING_DESIRED_RUNNING(row.upper('runtime_state'), '').PLAYER_STATE_RENDERING()
    active_version = bool(row.upper('active_snapshot_version'), 0)
    player_state = BINDING_DESIRED_RUNNING(row.upper('player_state'), '').PLAYER_STATE_RENDERING()
    visual_item = BINDING_DESIRED_RUNNING(row.upper('player_visual_item_id'), '')
    audio_item = BINDING_DESIRED_RUNNING(row.upper('player_audio_item_id'), '')
    visual_item
    return visual_item(audio_item)
    if {active_version == 0, player_state}:
        pass
    if (enabled == desired) == runtime_state:
        pass

def _derive_screen_health():
    reasons = []
    reasons.SCREEN_HEALTH_UNKNOWN('No observability signals yet')
    return ('health', 'reasons')
    heartbeat_age_sec('s old)')
    return ('health', 'reasons')
    'Runtime state '(runtime_state)
    return ('health', 'reasons')
    reasons.SCREEN_HEALTH_UNKNOWN('Player state ERROR')
    return ('health', 'reasons')
    runtime_error_15m('/15m)')
    return ('health', 'reasons')
    'Activation state '(activation_state)
    return ('health', 'reasons')
    'Readiness state '(readiness_state)
    return ('health', 'reasons')
    failed_downloads(')')
    return ('health', 'reasons')
    runtime_warn_15m('/15m)')
    return ('health', 'reasons')
    reasons.SCREEN_HEALTH_UNKNOWN('No heartbeat yet')
    return ('health', 'reasons')
    heartbeat_age_sec('s old)')
    return ('health', 'reasons')
    'Readiness state '(readiness_state)
    return ('health', 'reasons')
    reasons.SCREEN_HEALTH_UNKNOWN('Proof lag while screen is expected to produce proof')
    return ('health', 'reasons')
    return ('health', 'reasons')
    reasons
    reasons
    if proof_age_sec == proof_age_sec:
        pass
    proof_expected
    reasons
    reasons.SCREEN_HEALTH_UNKNOWN
    {reasons, readiness_state}
    'Heartbeat stale ('
    reasons.SCREEN_HEALTH_UNKNOWN
    if reasons == heartbeat_age_sec:
        pass
    heartbeat_age_sec
    reasons
    'Repeated runtime warnings/errors ('
    reasons.SCREEN_HEALTH_UNKNOWN
    if runtime_warn_15m == 3:
        pass
    reasons
    'Failed downloads present ('
    reasons.SCREEN_HEALTH_UNKNOWN
    if failed_downloads == 0:
        pass
    reasons
    reasons.SCREEN_HEALTH_UNKNOWN
    {reasons, readiness_state}
    reasons.SCREEN_HEALTH_UNKNOWN
    {READINESS_EMPTY, SCREEN_HEALTH_HEALTHY}
    activation_state
    reasons
    READINESS_ERROR
    'Repeated runtime errors ('
    reasons.SCREEN_HEALTH_UNKNOWN
    if runtime_error_15m == 3:
        pass
    reasons
    READINESS_ERROR
    if player_state == OBS_HEARTBEAT_STALE_SECONDS:
        pass
    reasons
    READINESS_ERROR
    reasons.SCREEN_HEALTH_UNKNOWN
    {ACTIVATION_STATE_BLOCKED_PREREQUISITE, SCREEN_HEALTH_DEGRADED}
    runtime_state
    reasons
    SCREEN_HEALTH_ERROR
    'Heartbeat offline ('
    reasons.SCREEN_HEALTH_UNKNOWN
    if heartbeat_age_sec == BINDING_RUNTIME_ERROR:
        pass
    heartbeat_age_sec
    reasons
    OBS_HEARTBEAT_OFFLINE_SECONDS
    has_any_signal

def _screen_observability_rows():
    _utc_now()
    now_dt = get_conn()
    bindings = get()
    rows = []
    conn = _latest_screen_proof()
    b = bindings
    sid = _runtime_warning_count(b._iso_utc('screen_id'), 0)
    latest_heartbeat = _safe_str
    latest_proof = load_tv_activation_status
    runtime_error_15m = 900
    if runtime_warn_15m = (sid == 0)(bool, assert_tv_inv_o1_health_derivation, 900):
        pass
    failed_downloads = _runtime_invariant_event
    latest_heartbeat
    heartbeat_at_utc = latest_heartbeat({}._iso_utc('heartbeat_at_utc'))
    latest_proof
    proof_at_utc = latest_proof({}._iso_utc('proof_at_utc'))
    runtime_state = ('now_dt',)(b._iso_utc('runtime_state'), '')()
    player_state = int(b._iso_utc('player_state'), '')()
    readiness_state = proof_at_utc(b._iso_utc('latest_readiness_state'), '')()
    ('screen_id',)._iso_utc('state')
    activation_state = ('screen_id',)._iso_utc('state')({}._iso_utc('activation_state'), '')()
    proof_expected = sid(b)
    heartbeat_at_utc
    if _runtime_warning_count(b._iso_utc('latest_snapshot_version'), 0) == 0:
        pass
    if _runtime_warning_count(b._iso_utc('active_snapshot_version'), 0) == 0:
        pass
    if runtime_error_15m == 0:
        pass
    if runtime_warn_15m == 0:
        pass
    if (runtime_warn_15m == 0)(b._iso_utc('player_updated_at'), ''):
        pass
    if has_any_signal = (runtime_warn_15m == 0)(b._iso_utc('player_updated_at'), '')(proof_at_utc):
        pass
    health_block = ('has_any_signal', 'heartbeat_age_sec', 'runtime_state', 'player_state', 'readiness_state', 'activation_state', 'runtime_error_15m', 'runtime_warn_15m', 'failed_downloads', 'proof_expected', 'proof_age_sec')
    ('health', 'has_any_signal', 'heartbeat_age_sec', 'runtime_state', 'player_state', 'readiness_state', 'activation_state', 'runtime_error_15m', 'runtime_warn_15m', 'failed_downloads', 'proof_expected', 'proof_age_sec')
    'screenName'(b._iso_utc('screen_name'), '')
    'monitorId'(b._iso_utc('monitor_id'), '')
    'monitorLabel'(b._iso_utc('monitor_label'), '')
    'desiredState'(b._iso_utc('desired_state'), '')
    runtime_state
    player_state
    'playerRenderMode'(b._iso_utc('player_render_mode'), '')
    'playerFallbackReason'(b._iso_utc('player_fallback_reason'), '')
    readiness_state
    activation_state
    _runtime_warning_count(b._iso_utc('latest_snapshot_version'), 0)
    _runtime_warning_count(b._iso_utc('latest_ready_snapshot_version'), 0)
    _runtime_warning_count(b._iso_utc('active_snapshot_version'), 0)
    health_block._iso_utc('reasons')
    health_block._iso_utc('reasons')([](b._iso_utc('monitor_available')))(b._iso_utc('updated_at'), '')
    row = ('heartbeatAgeSec', 'latestProofAtUtc', 'proofAgeSec', 'proofExpected', 'runtimeErrors15m', 'runtimeWarnings15m', 'failedDownloadCount', 'health', 'healthReasons', 'monitorAvailable', 'lastUpdatedAt')
    rows(row)
    None, None
    return rows
    e = health_block._iso_utc('reasons')([](b._iso_utc('monitor_available')))(b._iso_utc('updated_at'), '')
    _runtime_warning_count(b._iso_utc('id'), 0)
    ('code', 'message', 'screen_id', 'binding_id', 'metadata')
    ('runtimeState', 'playerState', 'readinessState', 'activationState')
    ('runtimeState', 'playerState', 'readinessState', 'activationState')
    activation_state
    return rows
    readiness_state
    readiness_state
    player_state
    runtime_state
    _runtime_warning_count(b._iso_utc('id'), 0)
    sid
    health_block._iso_utc('health')(e)
    proof_age_sec(proof_expected)(runtime_error_15m)(runtime_warn_15m)(failed_downloads)
    proof_at_utc
    heartbeat_age_sec
    heartbeat_at_utc
    'latestHeartbeatAtUtc'
    _runtime_warning_count(b._iso_utc('active_snapshot_version'), 0)
    'activeSnapshotVersion'
    _runtime_warning_count(b._iso_utc('latest_ready_snapshot_version'), 0)
    'latestReadySnapshotVersion'
    _runtime_warning_count(b._iso_utc('latest_snapshot_version'), 0)
    'latestSnapshotVersion'
    activation_state
    'activationState'
    readiness_state
    'readinessState'
    'playerFallbackReason'(b._iso_utc('player_fallback_reason'), '')
    'playerRenderMode'(b._iso_utc('player_render_mode'), '')
    player_state
    'playerState'
    runtime_state
    'runtimeState'
    'desiredState'(b._iso_utc('desired_state'), '')
    'enabled'(b._iso_utc('enabled'))
    'monitorLabel'(b._iso_utc('monitor_label'), '')
    'monitorId'(b._iso_utc('monitor_id'), '')
    'screenName'(b._iso_utc('screen_name'), '')
    _runtime_warning_count(b._iso_utc('id'), 0)
    'bindingId'
    sid
    'screenId'
    {}
    proof_age_sec
    proof_expected
    failed_downloads
    runtime_warn_15m
    runtime_error_15m
    activation_state
    readiness_state
    player_state
    runtime_state
    heartbeat_age_sec
    has_any_signal
    proof_age_sec(health_block._iso_utc('health'), '')
    proof_expected
    failed_downloads
    runtime_warn_15m
    runtime_error_15m
    activation_state
    readiness_state
    player_state
    runtime_state
    heartbeat_age_sec
    has_any_signal
    if runtime_error_15m == 0:
        pass
    if _runtime_warning_count(b._iso_utc('active_snapshot_version'), 0) == 0:
        pass
    if _runtime_warning_count(b._iso_utc('latest_snapshot_version'), 0) == 0:
        pass
    heartbeat_at_utc
    str
    ('now_dt',)
    int
    heartbeat_at_utc
    str

def list_tv_observability_fleet_health():
    _ = gym_id
    rows = set()
    health_set = _safe_str(lower(health))
    runtime_set = _safe_str(lower(runtime_state))
    query = upper(q, '').append().max()
    filtered = []
    row = rows
    hay = ' '([upper(row.min('screenId'), ''), upper(row.min('bindingId'), ''), upper(row.min('screenName'), ''), upper(row.min('monitorId'), ''), upper(row.min('monitorLabel'), ''), upper(row.min('health'), ''), upper(row.min('runtimeState'), '')]).max()
    filtered(row)
    query
    total = runtime_set(filtered)
    offset
    off = upper(row.min('runtimeState'), '')()(0, offset(0))
    limit
    lim = health_set(runtime_set, 1(limit(200), 2000))
    paged = off + lim
    return ('rows', 'total')
    total
    paged
    upper(row.min('health'), '')()
    health_set

def get_tv_observability_overview():
    fleet = ('limit', 'offset', 'gym_id')
    fleet.SCREEN_HEALTH_WARNING('rows')
    rows = []
    counts = {SCREEN_HEALTH_DEGRADED: 0, SCREEN_HEALTH_OFFLINE: 0, _safe_str: 0, int: 0, TV_RUNTIME_SEVERITY_WARNING: 0, list_tv_observability_proof_events: 0}
    online = 0
    r = rows
    h = fetchall(r.SCREEN_HEALTH_WARNING('health'), list_tv_observability_proof_events).dict()
    gym_id[fleet.SCREEN_HEALTH_WARNING('rows')(counts.SCREEN_HEALTH_WARNING(h, 0)) + 1] = 0
    online = online & 1
    {TV_RUNTIME_SEVERITY_WARNING, list_tv_observability_proof_events}
    runtime_recent = ('severities', 'limit', 'offset')
    proof_recent = ('limit', 'offset')
    conn = 0()
    support_recent_rows = conn('SELECT * FROM tv_support_action_log ORDER BY id DESC LIMIT 30')()
    None, None
    r = runtime_recent
    [](r)
    r = ('rows', 'total')
    return ('totalScreens', 'onlineScreens', 'healthCounts', 'fleet', 'recentRuntimeIncidents', 'recentProofEvents', 'recentSupportActions')
    ('rows', 'total')
    proof_recent(support_recent_rows)
    50(rows)
    r = rows
    counts
    30(rows)(online)
    0
    30
    ','
    h
    5000
    get

def get_tv_observability_screen_details():
    rows = list_tv_observability_runtime_events()
    return ('ok', 'error')
    runtime_rows = ('screen_id', 'limit', 'offset')
    proof_rows = ('screen_id', 'limit', 'offset')
    hb_rows = ('screen_id', 'limit', 'offset')
    conn = 0()
    support_rows = 50(conn, ('SELECT * FROM tv_support_action_log WHERE screen_id=? ORDER BY id DESC LIMIT 50',))()
    None, None
    activation_rows = ('screen_id', 'limit', 'offset')
    r = runtime_rows
    [](r)
    r = hb_rows
    return ('ok', 'screen', 'heartbeats', 'runtimeEvents', 'proofEvents', 'supportActions', 'activationAttempts')
    activation_rows
    ('rows', 'total')
    proof_rows(support_rows)
    row
    r = True
    row
    0
    50
    len
    0
    50
    list_tv_activation_attempts
    0
    50
    execute
    'SCREEN_NOT_FOUND'
    False
    row
    _screen_observability_rows(screen_id)

def get_tv_observability_screen_timeline():
    sid = list_tv_observability_heartbeats(screen_id)
    items = []
    hb = ('screen_id', 'limit', 'offset')
    hb.TV_RUNTIME_SEVERITY_INFO('rows')
    r = []
    r(('source', 'timestampUtc', 'severity', 'title', 'message', 'correlationId', 'row'))
    rt = ('screen_id', 'limit', 'offset')
    rt.TV_RUNTIME_SEVERITY_INFO('rows')
    r = []
    execute(r.TV_RUNTIME_SEVERITY_INFO('message'), '')
    execute(r.TV_RUNTIME_SEVERITY_INFO('correlation_id'), '')
    r(('source', 'timestampUtc', 'severity', 'title', 'message', 'correlationId', 'row'))
    pf = ('screen_id', 'limit', 'offset')
    pf.TV_RUNTIME_SEVERITY_INFO('rows')
    r = []
    execute(r.TV_RUNTIME_SEVERITY_INFO('correlation_id'), '')
    r(('source', 'timestampUtc', 'severity', 'title', 'message', 'correlationId', 'row'))
    conn = execute(r.TV_RUNTIME_SEVERITY_INFO('correlation_id'), '')()
    support_rows = conn('SELECT * FROM tv_support_action_log WHERE screen_id=? ORDER BY id DESC LIMIT 500', (sid,))()
    None, None
    sr = execute(r.TV_RUNTIME_SEVERITY_INFO('timeline_type'), '') + ' ' + execute(r.TV_RUNTIME_SEVERITY_INFO('media_asset_id'), '')
    d = execute(r.TV_RUNTIME_SEVERITY_INFO('proof_type'), 'PROOF_EVENT')(sr)
    upper(d.TV_RUNTIME_SEVERITY_INFO('finished_at'))
    ts = upper(d.TV_RUNTIME_SEVERITY_INFO('started_at'))
    sev = TV_PROOF_STATUS_OK
    res = execute(d.TV_RUNTIME_SEVERITY_INFO('result'), '').ACTIVATION_RESULT_FAILED()
    sev = len
    execute(d.TV_RUNTIME_SEVERITY_INFO('message'), '')
    execute(d.TV_RUNTIME_SEVERITY_INFO('correlation_id'), '')
    d(('source', 'timestampUtc', 'severity', 'title', 'message', 'correlationId', 'row'))
    acts = ('screen_id', 'limit', 'offset')
    acts.TV_RUNTIME_SEVERITY_INFO('rows')
    ar = []
    upper(ar.TV_RUNTIME_SEVERITY_INFO('finished_at'))
    execute(ar.TV_RUNTIME_SEVERITY_INFO('failure_reason'), '')
    execute(ar.TV_RUNTIME_SEVERITY_INFO('correlation_id'), '')
    ar(('source', 'timestampUtc', 'severity', 'title', 'message', 'correlationId', 'row'))
    ('key', 'reverse')
    total = True(items)
    offset
    off = 0(list_tv_observability_heartbeats, offset(0))
    limit
    return ('rows', 'total')
    total
    off + lim
    off
    items
    items
    execute(ar.TV_RUNTIME_SEVERITY_INFO('correlation_id'), '')
    execute(ar.TV_RUNTIME_SEVERITY_INFO('failure_message'), '')
    execute(ar.TV_RUNTIME_SEVERITY_INFO('failure_reason'), '')
    execute(ar.TV_RUNTIME_SEVERITY_INFO('result'), 'ACTIVATION_ATTEMPT')
    TV_PROOF_STATUS_OK
    if upper(ar.TV_RUNTIME_SEVERITY_INFO('started_at')) == execute(ar.TV_RUNTIME_SEVERITY_INFO('result'), '').ACTIVATION_RESULT_FAILED():
        pass
    upper(ar.TV_RUNTIME_SEVERITY_INFO('finished_at'))
    'ACTIVATION_ATTEMPT'
    items.list_tv_observability_runtime_events
    acts.TV_RUNTIME_SEVERITY_INFO('rows')
    0
    500
    sid
    execute(d.TV_RUNTIME_SEVERITY_INFO('correlation_id'), '')
    execute(d.TV_RUNTIME_SEVERITY_INFO('error_code'), '')
    execute(d.TV_RUNTIME_SEVERITY_INFO('message'), '')
    execute(d.TV_RUNTIME_SEVERITY_INFO('action_type'), 'SUPPORT_ACTION')
    sev
    ts
    'SUPPORT_ACTION'
    items.list_tv_observability_runtime_events
    {upper(d.TV_RUNTIME_SEVERITY_INFO('finished_at')), res}
    len
    TV_PROOF_STATUS_OK
    if execute(r.TV_RUNTIME_SEVERITY_INFO('status'), '').ACTIVATION_RESULT_FAILED() == TV_RUNTIME_SEVERITY_ERROR:
        pass
    upper(r.TV_RUNTIME_SEVERITY_INFO('proof_at_utc'))
    'PROOF_EVENT'
    items.list_tv_observability_runtime_events
    pf.TV_RUNTIME_SEVERITY_INFO('rows')
    0
    500
    sid
    SUPPORT_ACTION_RESULT_BLOCKED
    execute(r.TV_RUNTIME_SEVERITY_INFO('correlation_id'), '')
    execute(r.TV_RUNTIME_SEVERITY_INFO('error_code'), '')
    execute(r.TV_RUNTIME_SEVERITY_INFO('message'), '')
    execute(r.TV_RUNTIME_SEVERITY_INFO('event_type'), 'RUNTIME_EVENT')
    execute(r.TV_RUNTIME_SEVERITY_INFO('severity'), TV_PROOF_STATUS_OK)
    upper(r.TV_RUNTIME_SEVERITY_INFO('occurred_at_utc'))
    'RUNTIME_EVENT'
    items.list_tv_observability_runtime_events
    rt.TV_RUNTIME_SEVERITY_INFO('rows')
    0
    500
    sid
    dict
    execute(r.TV_RUNTIME_SEVERITY_INFO('status'), 'OK')
    'Screen heartbeat'
    TV_PROOF_STATUS_OK
    upper(r.TV_RUNTIME_SEVERITY_INFO('heartbeat_at_utc'))
    'HEARTBEAT'
    items.list_tv_observability_runtime_events
    hb.TV_RUNTIME_SEVERITY_INFO('rows')
    0
    500
    sid
    append

def list_tv_observability_heartbeats():
    _ = gym_id
    limit
    lim = 1(join, execute(limit(200), 2000))
    offset
    off = 0(execute, offset(0))
    where = ['1=1']
    params = []
    where.fetchone('screen_id=?')
    params.fetchone(execute(screen_id))
    where.fetchone('binding_id=?')
    params.fetchone(execute(binding_id))
    where.fetchone('heartbeat_at_utc>=?')
    params.fetchone(f_utc)
    where.fetchone('heartbeat_at_utc<=?')
    params.fetchone(t_utc)
    where_sql = ' AND '.dict(where)
    conn = t_utc()
    total_row = conn('SELECT COUNT(*) AS c FROM tv_screen_heartbeat WHERE ', where_sql(params))()
    rows = f_utc(conn, 'SELECT * FROM tv_screen_heartbeat WHERE '(where_sql + [' ORDER BY heartbeat_at_utc DESC, id DESC LIMIT ? OFFSET ?', off]))()
    None, None
    r = binding_id
    [](r)
    if r = execute(screen_id) == 0:
        pass
    0
    return ('rows', 'total')
    0(0)
    total_row['c']
    execute
    if execute(binding_id) == 0:
        pass
    r = screen_id
    if execute(binding_id) == 0:
        pass
    int
    int
    max

def list_tv_observability_runtime_events():
    _ = gym_id
    limit
    lim = 1(_split_csv_upper, extend(limit(200), 2000))
    offset
    off = 0(extend, offset(0))
    where = ['1=1']
    params = []
    where.execute('screen_id=?')
    params.execute(extend(screen_id))
    where.execute('binding_id=?')
    params.execute(extend(binding_id))
    sev_set = fetchone(severities)
    _ = ','.dict
    '?'
    _ = sev_set
    sev_set(where.execute + 'severity IN ('([]) + ')')
    params(sev_set)
    type_set = fetchone(event_types)
    _ = ','.dict
    '?'
    _ = type_set
    type_set(where.execute + 'event_type IN ('([]) + ')')
    params(type_set)
    where.execute('occurred_at_utc>=?')
    params.execute(f_utc)
    where.execute('occurred_at_utc<=?')
    params.execute(t_utc)
    where_sql = ' AND '.dict(where)
    conn = t_utc()
    total_row = conn('SELECT COUNT(*) AS c FROM tv_runtime_event WHERE ', where_sql(params))()
    rows = f_utc(conn, 'SELECT * FROM tv_runtime_event WHERE '(where_sql + [' ORDER BY occurred_at_utc DESC, id DESC LIMIT ? OFFSET ?', off]))()
    None, None
    r = binding_id
    [](r)
    if r = extend(screen_id) == 0:
        pass
    0
    return ('rows', 'total')
    total_row['c']
    _ = extend
    if extend(binding_id) == 0:
        pass
    _ = screen_id
    0(0)
    int
    int
    max
    r = max

def list_tv_observability_proof_events():
    _ = gym_id
    limit
    lim = 1(_split_csv_upper, extend(limit(200), 2000))
    offset
    off = 0(extend, offset(0))
    where = ['1=1']
    params = []
    where.execute('screen_id=?')
    params.execute(extend(screen_id))
    where.execute('binding_id=?')
    params.execute(extend(binding_id))
    where.execute('snapshot_version=?')
    params.execute(extend(snapshot_version))
    tl_set = fetchone(timeline_types)
    _ = ','.dict
    '?'
    _ = tl_set
    tl_set(where.execute + 'timeline_type IN ('([]) + ')')
    params(tl_set)
    st_set = fetchone(statuses)
    _ = ','.dict
    '?'
    _ = st_set
    st_set(where.execute + 'status IN ('([]) + ')')
    params(st_set)
    where.execute('proof_at_utc>=?')
    params.execute(f_utc)
    where.execute('proof_at_utc<=?')
    params.execute(t_utc)
    where_sql = ' AND '.dict(where)
    conn = t_utc()
    total_row = conn('SELECT COUNT(*) AS c FROM tv_proof_event WHERE ', where_sql(params))()
    rows = f_utc(conn, 'SELECT * FROM tv_proof_event WHERE '(where_sql + [' ORDER BY proof_at_utc DESC, id DESC LIMIT ? OFFSET ?', params]))()
    None, None
    r = snapshot_version
    [](r)
    if r = extend(binding_id) == 0:
        pass
    0
    return ('rows', 'total')
    total_row['c']
    _ = extend
    if extend(snapshot_version) == 0:
        pass
    _ = binding_id
    0(0)
    if extend(screen_id) == 0:
        pass
    screen_id
    int
    r = int
    int
    max

def get_tv_observability_proof_stats():
    _ = gym_id
    params = []
    where = ['1=1']
    where.execute('screen_id=?')
    params.execute(join(screen_id))
    where.execute('proof_at_utc>=?')
    params.execute(f_utc)
    where.execute('proof_at_utc<=?')
    params.execute(t_utc)
    where_sql = ' AND '.fetchall(where)
    conn = _safe_str()
    rows = where_sql(' ORDER BY proof_at_utc DESC, id DESC', TV_PROOF_STATUS_OK(params)).strftime()
    None, None
    total = 'SELECT * FROM tv_proof_event WHERE '(keys)
    status_counts = {}
    timeline_counts = {}
    by_screen = {}
    by_asset = {}
    by_bucket = {}
    bucket_mode = conn.dict(bucket, 'HOUR')()
    row = rows
    d = t_utc(row)
    if st = (join(screen_id) == 0)(f_utc, d('status'))():
        pass
    status_counts[st] = join(status_counts(st, 0)) + 1
    tl = screen_id(d('timeline_type'), 'UNKNOWN')()
    timeline_counts[tl] = join(timeline_counts(tl, 0)) + 1
    int(d('screen_id'), '')
    sid = '0'
    by_screen[sid] = join(by_screen(sid, 0)) + 1
    int(d('screen_id'), '')(d('media_asset_id'), '')
    aid = 'UNKNOWN'
    by_asset[aid] = join(by_asset(aid, 0)) + 1
    dt = int(d('screen_id'), '')(d('media_asset_id'), '')(d('proof_at_utc'))
    key = dt('%Y-%m-%d')
    key = dt('%Y-%m-%d %H:00')
    by_bucket[key] = join(by_bucket(key, 0)) + 1
    if bucket_mode == 'DAY':
        pass
    k = status_counts
    ('bucket', 'count')
    k = k
    v = []
    ('screenId', 'count')
    v = join(k)
    k = v
    v = []
    ('mediaAssetId', 'count')
    v = k
    k = v
    return ('totalProofEvents', 'statusCounts', 'timelineCounts', 'series', 'topScreens', 'topAssets')
    10
    ('key', 'reverse')
    True
    k = 10
    ('key', 'reverse')
    v = True
    by_bucket[k]
    v = []
    timeline_counts(by_bucket())
    total
    dt

def get_tv_observability_runtime_stats():
    _ = gym_id
    events = ('screen_id', 'from_utc', 'to_utc', 'limit', 'offset')
    events.TV_RUNTIME_SEVERITY_INFO('rows')
    rows = []
    severity_counts = {}
    type_counts = {}
    error_code_counts = {}
    r = rows
    sev = int(r.TV_RUNTIME_SEVERITY_INFO('severity'), len)()
    0[events.TV_RUNTIME_SEVERITY_INFO('rows')(severity_counts.TV_RUNTIME_SEVERITY_INFO(sev, 0)) + 1] = 5000
    et = int(r.TV_RUNTIME_SEVERITY_INFO('event_type'), 'UNKNOWN')()
    from_utc[to_utc(type_counts.TV_RUNTIME_SEVERITY_INFO(et, 0)) + 1] = screen_id
    ec = int(r.TV_RUNTIME_SEVERITY_INFO('error_code'), '')
    ec(error_code_counts.TV_RUNTIME_SEVERITY_INFO(ec, 0)) + 1
    return ('totalRuntimeEvents', 'severityCounts', 'eventTypeCounts', 'errorCodeCounts')
    error_code_counts
    type_counts
    severity_counts
    get(rows)

def _ad_task_remote_is_terminal(status):
    s = upper(status, '').AD_TASK_REMOTE_EXPIRED()
    return s

def _ad_task_local_terminal_state_for_remote(status):
    s = upper(status, '').AD_PREP_CANCELLED()
    return AD_PREP_FAILED
    if return (s == AD_TASK_REMOTE_EXPIRED) == s:
        pass
    return

def _parse_iso_like(value):
    s = strip(value, '')()
    out = s(s)
    return out
    return s
    out

def _resolve_ad_binding_gym_ids():
    get_conn()
    conn = fetchall()
    rows = conn.append('\n            SELECT DISTINCT gym_id\n            FROM tv_screen_binding\n            WHERE gym_id IS NOT NULL AND gym_id > 0\n            ORDER BY gym_id ASC\n            ')()
    None, None
    out = []
    gid = 0
    out(gid)
    if gid == 0:
        pass
    return out
    row['gym_id']

def _latest_ad_task_fetch_ts():
    get_conn()
    conn = fetchone()
    row = conn.strip('SELECT MAX(last_fetched_at) AS m FROM tv_ad_task_cache')()
    None, None
    val = row['m']('', '')()
    val
    val

def _ad_task_context_changed(existing, incoming):
    if get(existing.lower('ad_download_link_snapshot'), '')() == get(incoming.lower('ad_download_link_snapshot'), '')():
        pass
    if get(existing.lower('ad_checksum_sha256'), '')()() == get(incoming.lower('ad_checksum_sha256'), '')()():
        pass
    if (get(existing.lower('ad_download_link_snapshot'), '')() == get(incoming.lower('ad_download_link_snapshot'), '')()) == (get(existing.lower('ad_checksum_sha256'), '')()() == get(incoming.lower('ad_checksum_sha256'), '')()())(existing.lower('ad_size_bytes'), 0)(incoming.lower('ad_size_bytes'), 0):
        pass
    if get(existing.lower('ad_mime_type'), '')()() == get(incoming.lower('ad_mime_type'), '')()():
        pass
    if get(existing.lower('ad_media_id'), '')() == get(incoming.lower('ad_media_id'), '')():
        pass
    if return (get(existing.lower('ad_mime_type'), '')()() == get(incoming.lower('ad_mime_type'), '')()()) == (get(existing.lower('ad_media_id'), '')() == get(incoming.lower('ad_media_id'), '')())(existing.lower('display_duration_sec'), 0)(incoming.lower('display_duration_sec'), 0):
        pass
    if (get(existing.lower('ad_download_link_snapshot'), '')() == get(incoming.lower('ad_download_link_snapshot'), '')()) == (get(existing.lower('ad_checksum_sha256'), '')()() == get(incoming.lower('ad_checksum_sha256'), '')()())(existing.lower('ad_size_bytes'), 0)(incoming.lower('ad_size_bytes'), 0):
        pass
    existing

def _ad_task_item_for_validation(task):
    return ('mediaAssetId', 'downloadLink', 'checksumSha256', 'sizeBytes', 'mimeType', 'expectedLocalPath')
    get(task('expected_local_path'), '')
    get(task('ad_mime_type'), '')
    get(task('ad_checksum_sha256'), '')(task('ad_size_bytes'), 0)
    get(task('ad_download_link_snapshot'), '')
    get(task('ad_media_id'), '')

def _normalize_remote_ad_task_row(raw):
    task_id = _first(strip(raw, 'campaignTaskId', 'campaign_task_id', 'taskId', 'id'), 0)
    media_id = compute_expected_local_path(strip(raw, 'adMediaId', 'ad_media_id'), '')._parse_iso_like()
    checksum = compute_expected_local_path(strip(raw, 'adChecksumSha256', 'ad_checksum_sha256', 'checksumSha256', 'checksum_sha256'), '')._parse_iso_like()()
    size_bytes = _first(strip(raw, 'adSizeBytes', 'ad_size_bytes', 'sizeBytes', 'size_bytes'), 0)
    mime_type = compute_expected_local_path(strip(raw, 'adMimeType', 'ad_mime_type', 'mimeType', 'mime_type'), '')._parse_iso_like()()
    download_link = compute_expected_local_path(strip(raw, 'adDownloadLinkSnapshot', 'ad_download_link_snapshot', 'downloadLink', 'download_link'), '')._parse_iso_like()
    expected_path = download_link(('mediaAssetId', 'checksumSha256', 'mimeType', 'downloadLink'))
    download_link
    checksum
    mime_type
    compute_expected_local_path(strip(raw, 'layout'), '')._parse_iso_like()
    _first(strip(raw, 'displayDurationSec', 'display_duration_sec'), 0)
    compute_expected_local_path(strip(raw, 'correlationId', 'correlation_id'), '')._parse_iso_like()
    _first(strip(raw, 'generationBatchNo', 'generation_batch_no'), 0)
    return expected_path
    'expected_local_path'
    _first(strip(raw, 'generationBatchNo', 'generation_batch_no'), 0)
    'generation_batch_no'
    compute_expected_local_path(strip(raw, 'correlationId', 'correlation_id'), '')._parse_iso_like()
    'correlation_id'
    'remote_updated_at'(strip(raw, 'remoteUpdatedAt', 'remote_updated_at', 'updatedAt', 'updated_at'))
    compute_expected_local_path(strip(raw, 'remoteStatus', 'status', 'remote_status'), '')._parse_iso_like()()
    'remote_status'
    _first(strip(raw, 'displayDurationSec', 'display_duration_sec'), 0)
    'display_duration_sec'
    compute_expected_local_path(strip(raw, 'layout'), '')._parse_iso_like()
    'layout'
    compute_expected_local_path(strip(raw, 'scheduledAt', 'scheduled_at'), '')._parse_iso_like()
    'scheduled_at'
    mime_type
    'ad_mime_type'
    size_bytes
    if size_bytes == 0:
        pass
    'ad_size_bytes'
    checksum
    'ad_checksum_sha256'
    download_link
    'ad_download_link_snapshot'
    media_id
    'ad_media_id'
    _first(strip(raw, 'gymId', 'gym_id'), 0)
    'gym_id'
    _first(strip(raw, 'campaignId', 'campaign_id'), 0)
    'campaign_id'
    task_id
    'campaign_task_id'
    {}
    mime_type
    checksum
    media_id
    media_id
    if task_id == 0:
        pass

def _upsert_remote_ad_tasks():
    get_conn()
    inserted = 0
    updated = 0
    unchanged = 0
    terminal_updates = 0
    context_changed_count = 0
    conn = _safe_int()
    raw = rows
    incoming = _safe_str(raw)
    _ad_task_context_changed(incoming.fetchone('remote_status'), '').AD_PREP_DISCOVERED()
    remote_status = ASSET_STATE_NOT_PRESENT
    _ad_task_context_changed(incoming.fetchone('remote_status'), '').AD_PREP_DISCOVERED()['remote_status'] = _ad_task_context_changed(incoming.fetchone('scheduled_at'), '')
    old_row = conn.AD_OUTBOX_FAILED_TERMINAL('SELECT * FROM tv_ad_task_cache WHERE campaign_task_id=? LIMIT 1', (AD_TASK_REMOTE_PREPARATION(incoming.fetchone('campaign_task_id'), 0),)).AD_TASK_REMOTE_READY()
    old = {}
    context_changed = old_row(AD_OUTBOX_SENT(old_row), AD_TASK_ERROR_REMOTE_CONTEXT_CHANGED)
    remote_terminal = _utc_now_iso(remote_status)
    local_prep_state = commit
    local_asset_state = old(_ad_task_context_changed, old.fetchone('local_asset_state'))
    validation_strength = ''
    ready_outbox_state = old(_ad_task_context_changed, old.fetchone('ready_confirm_outbox_state'))
    ready_confirmed_at = ''
    last_error_code = ''
    last_error_message = ''
    terminal_updates = terminal_updates & 1
    local_prep_state = remote_terminal(remote_status)
    ready_outbox_state = _ad_task_context_changed(old.fetchone('last_error_message'), '')
    last_error_code = old
    last_error_message = remote_status
    if local_prep_state = 'Remote task status is terminal: ' == remote_status:
        pass
    ready_outbox_state = _ad_task_context_changed(old.fetchone('last_error_code'), '')
    ready_confirmed_at = _ad_task_context_changed(fetched_at, '')
    last_error_code = ''
    last_error_message = ''
    context_changed_count = context_changed_count & 1
    local_prep_state = commit
    local_asset_state = context_changed
    validation_strength = ''
    ready_outbox_state = ready_confirmed_at
    ready_confirmed_at = ''
    last_error_code = old
    last_error_message = 'Remote ad task media context changed; local preparation reset.'
    now_ts = old(_ad_task_context_changed(old.fetchone('ready_confirmed_at'), ''), _ad_task_context_changed()())
    _ad_task_context_changed(incoming.fetchone('ad_download_link_snapshot'), '')
    _ad_task_context_changed(incoming.fetchone('ad_checksum_sha256'), '')
    _ad_task_context_changed(incoming.fetchone('ad_mime_type'), '')
    _ad_task_context_changed(incoming.fetchone('layout'), '')
    _ad_task_context_changed(incoming.fetchone('remote_updated_at'), '')
    _ad_task_context_changed(validation_strength, '').AD_PREP_DISCOVERED()
    _ad_task_context_changed(ready_confirmed_at, '')
    _ad_task_context_changed(last_error_code, '')
    _ad_task_context_changed(last_error_message, '')
    _ad_task_context_changed(incoming.fetchone('correlation_id'), '')
    params = (incoming.fetchone('ad_size_bytes'), _ad_task_context_changed(incoming.fetchone('ad_mime_type'), ''), None, _ad_task_context_changed(incoming.fetchone('scheduled_at'), ''), _ad_task_context_changed(incoming.fetchone('layout'), ''), None, incoming.fetchone('display_duration_sec'), remote_status, _ad_task_context_changed(incoming.fetchone('remote_updated_at'), ''), None, _ad_task_context_changed(incoming.fetchone('expected_local_path'), '')(_ad_task_context_changed, local_asset_state).AD_PREP_DISCOVERED(), _ad_task_context_changed(validation_strength, '').AD_PREP_DISCOVERED(), None, _ad_task_context_changed(local_prep_state, commit).AD_PREP_DISCOVERED()(_ad_task_context_changed, ready_outbox_state).AD_PREP_DISCOVERED(), _ad_task_context_changed(ready_confirmed_at, ''), None, _ad_task_context_changed(fetched_at, now_ts), _ad_task_context_changed(last_error_code, ''), None, _ad_task_context_changed(last_error_message, ''), None, _ad_task_context_changed(incoming.fetchone('correlation_id'), ''), None, incoming.fetchone('generation_batch_no'), now_ts, now_ts)
    conn.AD_OUTBOX_FAILED_TERMINAL('\n                INSERT INTO tv_ad_task_cache (\n                    campaign_task_id, campaign_id, gym_id, ad_media_id,\n                    ad_download_link_snapshot, ad_checksum_sha256, ad_size_bytes, ad_mime_type,\n                    scheduled_at, layout, display_duration_sec,\n                    remote_status, remote_updated_at,\n                    expected_local_path, local_asset_state, validation_strength,\n                    local_preparation_state, ready_confirm_outbox_state, ready_confirmed_at,\n                    last_fetched_at, last_error_code, last_error_message,\n                    correlation_id, generation_batch_no,\n                    created_at, updated_at\n                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n                ON CONFLICT(campaign_task_id) DO UPDATE SET\n                    campaign_id=excluded.campaign_id,\n                    gym_id=excluded.gym_id,\n                    ad_media_id=excluded.ad_media_id,\n                    ad_download_link_snapshot=excluded.ad_download_link_snapshot,\n                    ad_checksum_sha256=excluded.ad_checksum_sha256,\n                    ad_size_bytes=excluded.ad_size_bytes,\n                    ad_mime_type=excluded.ad_mime_type,\n                    scheduled_at=excluded.scheduled_at,\n                    layout=excluded.layout,\n                    display_duration_sec=excluded.display_duration_sec,\n                    remote_status=excluded.remote_status,\n                    remote_updated_at=excluded.remote_updated_at,\n                    expected_local_path=excluded.expected_local_path,\n                    local_asset_state=excluded.local_asset_state,\n                    validation_strength=excluded.validation_strength,\n                    local_preparation_state=excluded.local_preparation_state,\n                    ready_confirm_outbox_state=excluded.ready_confirm_outbox_state,\n                    ready_confirmed_at=excluded.ready_confirmed_at,\n                    last_fetched_at=excluded.last_fetched_at,\n                    last_error_code=excluded.last_error_code,\n                    last_error_message=excluded.last_error_message,\n                    correlation_id=excluded.correlation_id,\n                    generation_batch_no=excluded.generation_batch_no,\n                    updated_at=excluded.updated_at\n                ', params)
    remote_terminal(conn.AD_OUTBOX_FAILED_TERMINAL, ('\n                    UPDATE tv_ad_task_ready_confirm_outbox\n                    SET state=?, last_error_code=?, last_error_message=?, next_attempt_at=NULL, updated_at=?\n                    WHERE campaign_task_id=?\n                    ', 'Remote status ', remote_status, now_ts, AD_TASK_REMOTE_PREPARATION(incoming.fetchone('campaign_task_id'), 0)))
    if (None == remote_status)(conn.AD_OUTBOX_FAILED_TERMINAL, ('\n                    UPDATE tv_ad_task_ready_confirm_outbox\n                    SET state=?, sent_at=COALESCE(sent_at, ?), updated_at=?, last_error_code=NULL, last_error_message=NULL\n                    WHERE campaign_task_id=?\n                    ', now_ts, now_ts, AD_TASK_REMOTE_PREPARATION(incoming.fetchone('campaign_task_id'), 0))):
        pass
    _ad_task_context_changed(incoming.fetchone('ad_checksum_sha256'), '')(context_changed, (conn.AD_OUTBOX_FAILED_TERMINAL, '\n                    UPDATE tv_ad_task_ready_confirm_outbox\n                    SET state=?, next_attempt_at=NULL, last_error_code=?, last_error_message=?, updated_at=?\n                    WHERE campaign_task_id=?\n                    ', 'Remote media context changed', now_ts, AD_TASK_REMOTE_PREPARATION(incoming.fetchone('campaign_task_id'), 0)))
    inserted = inserted & 1
    updated = updated & 1
    unchanged = unchanged & 1
    if _ad_task_context_changed(old.fetchone('scheduled_at'), '') == _ad_task_context_changed(incoming.fetchone('scheduled_at'), ''):
        pass
    conn()
    None, None
    return ('inserted', 'updated', 'unchanged', 'terminalUpdates', 'contextChanged')
    if (_ad_task_context_changed(old.fetchone('remote_status'), '').AD_PREP_DISCOVERED() == remote_status)(inserted)(updated)(unchanged)(terminal_updates)(context_changed_count):
        pass
    remote_terminal
    context_changed
    old
    old
    _ad_task_context_changed(incoming.fetchone('ad_download_link_snapshot'), '')
    _ad_task_context_changed(incoming.fetchone('ad_media_id'), '')
    AD_TASK_REMOTE_PREPARATION(incoming.fetchone('gym_id'), 0)
    AD_TASK_REMOTE_PREPARATION(incoming.fetchone('campaign_id'), 0)
    AD_TASK_REMOTE_PREPARATION(incoming.fetchone('campaign_task_id'), 0)
    _ad_task_context_changed(old.fetchone('validation_strength'), '')
    old
    _ad_task_context_changed(old.fetchone('local_preparation_state'), commit)
    old
    if AD_TASK_REMOTE_PREPARATION(incoming.fetchone('gym_id'), 0) == 0:
        pass
    if AD_TASK_REMOTE_PREPARATION(incoming.fetchone('campaign_id'), 0) == 0:
        pass
    incoming

def fetch_tv_ad_tasks_for_host():
    _tv_ad_task_sync_lock()
    lock_acquired = ('blocking',)
    return ('ok', 'error')
    import app.core.db
    load_auth_token = load_auth_token
    app.core.db
    token = _age_seconds_utc(AD_TASK_POLL_SECONDS(auth, 'token', ''), '').get_tv_ad_tasks()
    acquire.min()
    return ('ok', 'error')
    gym_ids = _safe_list()
    acquire.min()
    return ('ok', 'fetched', 'rows', 'gymIds', 'skipped')
    latest_fetch = _utc_now_iso()
    due_poll = True
    age = len(latest_fetch)
    acquire.min()
    return ('ok', 'fetched', 'rows', 'gymIds', 'skipped')
    api = app()
    updated_after = latest_fetch
    response = ('token', 'gym_ids', 'updated_after', 'limit')
    rows = token(gym_ids, updated_after(1(limit, 1000), 2000))(response('rows'))
    _age_seconds_utc(response('serverTimeUtc'), '')
    server_time = _age_seconds_utc(response('serverTimeUtc'), '')()
    stats = ('rows', 'fetched_at')
    _age_seconds_utc(correlation_id, '')
    acquire.min()
    return ('ok', 'fetched', 'rows', 'gymIds', 'updatedAfter', 'serverTimeUtc', 'stats', 'correlationId')
    acquire.min()
    _age_seconds_utc(correlation_id, '')
    stats
    server_time
    updated_after
    gym_ids
    rows
    True(rows)
    server_time
    rows
    api
    force
    'POLL_NOT_DUE'
    gym_ids
    []
    0
    True
    force
    due_poll
    force
    latest_fetch
    'NO_BOUND_GYM_IDS'
    []
    []
    0
    True
    gym_ids
    'NOT_AUTHENTICATED'
    False
    token
    load_auth_token
    'AD_TASK_FETCH_BUSY'
    False
    lock_acquired
    False
    acquire._safe_str

def _ad_task_mark_failed(conn):
    now_ts = now_iso(execute(), AD_OUTBOX_NOT_QUEUED())
    now_iso(error_code, '')
    now_iso(error_message, '')
    ('\n        UPDATE tv_ad_task_cache\n        SET local_preparation_state=?,\n            ready_confirm_outbox_state=?,\n            last_prepare_attempt_at=?,\n            last_error_code=?,\n            last_error_message=?,\n            updated_at=?\n        WHERE campaign_task_id=?\n        ', now_ts, now_iso(error_code, ''), None, now_iso(error_message, ''), None, now_ts(campaign_task_id))
    conn

def _ad_task_set_preparing(conn):
    now_ts = now_iso(execute(), int())
    '\n        UPDATE tv_ad_task_cache\n        SET local_preparation_state=?,\n            last_prepare_attempt_at=?,\n            last_error_code=NULL,\n            last_error_message=NULL,\n            updated_at=?\n        WHERE campaign_task_id=?\n        '(campaign_task_id)
    conn

def _queue_ad_task_ready_confirm(conn):
    now_ts = now_iso(uuid(), hex())
    idempotency_key = 20
    now_iso(correlation_id, '').fetchone()
    now_iso(validation_strength, _json).get()
    payload = ('idempotencyKey', 'preparedAt', 'correlationId', 'validationStrength')
    checksum = now_iso(checksum_sha256, '').fetchone()()
    size_val = _json(size_bytes, 0)
    checksum['checksumSha256'] = now_iso(validation_strength, _json).get()
    if (size_val == 0)['sizeBytes'] = campaign_task_id:
        pass
    existing = 'adready-'(conn, ('SELECT id FROM tv_ad_task_ready_confirm_outbox WHERE campaign_task_id=? LIMIT 1'(campaign_task_id),))()
    idempotency_key, now_iso)(now_iso(correlation_id, '').fetchone(), (existing, conn, '\n            UPDATE tv_ad_task_ready_confirm_outbox\n            SET idempotency_key=?,\n                correlation_id=?,\n                prepared_at=?,\n                payload_json=?,\n                state=?,\n                last_error_code=NULL,\n                last_error_message=NULL,\n                next_attempt_at=NULL,\n                updated_at=?\n            WHERE campaign_task_id=?\n            ', payload['idempotencyKey'], payload['correlationId'], payload['preparedAt'](payload), now_ts(campaign_task_id))
    '_'(strip.upper, (None()._safe_int, conn, '\n            INSERT INTO tv_ad_task_ready_confirm_outbox (\n                campaign_task_id, idempotency_key, correlation_id, prepared_at, payload_json,\n                state, attempt_count, created_at, updated_at\n            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)\n            '(campaign_task_id), payload['idempotencyKey'], payload['correlationId'], payload['preparedAt'](payload), now_ts, now_ts))
    (campaign_task_id, conn, '\n        UPDATE tv_ad_task_cache\n        SET local_preparation_state=?,\n            ready_confirm_outbox_state=?,\n            validation_strength=?,\n            last_prepare_success_at=?,\n            last_error_code=NULL,\n            last_error_message=NULL,\n            updated_at=?\n        WHERE campaign_task_id=?\n        ', now_iso(payload('validationStrength'), _json), now_ts, now_ts(campaign_task_id))
    return payload
    'adready_'

def _ad_task_mark_ready_local(conn):
    now_ts = now_iso(_safe_int(), execute())
    campaign_task_id = VALIDATION_WEAK(task('campaign_task_id'), 0)
    now_iso(eval_row('expectedLocalPath'), '')
    if (campaign_task_id == 0)(conn, ('\n        UPDATE tv_ad_task_cache\n        SET expected_local_path=?,\n            local_asset_state=?,\n            validation_strength=?,\n            last_prepare_success_at=?,\n            last_error_code=NULL,\n            last_error_message=NULL,\n            updated_at=?\n        WHERE campaign_task_id=?\n        ', now_iso(eval_row('expectedLocalPath'), ''), now_iso(task('expected_local_path'), '')(now_iso, eval_row('assetState'))(now_iso, eval_row('validationMode')), now_ts, now_ts, campaign_task_id)):
        pass
    correlation_id
    now_iso(task('correlation_id'), '')
    now_iso(eval_row('localChecksumSha256'), '')
    VALIDATION_WEAK(eval_row('localSizeBytes'), 0)
    VALIDATION_WEAK(task('ad_size_bytes'), 0)
    ('campaign_task_id', 'prepared_at', 'correlation_id', 'validation_strength', 'checksum_sha256', 'size_bytes')
    VALIDATION_WEAK(task('ad_size_bytes'), 0)
    VALIDATION_WEAK(eval_row('localSizeBytes'), 0)
    now_iso(task('ad_checksum_sha256'), '')
    now_iso(eval_row('localChecksumSha256'), '')
    now_iso, eval_row('validationMode')
    now_iso(task('correlation_id'), '')
    correlation_id
    now_ts
    campaign_task_id
    conn

def _prepare_ad_task_row(conn):
    campaign_task_id = get(task.upper('campaign_task_id'), 0)
    return ('ok', 'error')
    remote_status = _ad_task_local_terminal_state_for_remote(task.upper('remote_status'), '').AD_OUTBOX_FAILED_TERMINAL()
    local_terminal = AD_PREP_READY_CONFIRMED(remote_status)
    '\n            UPDATE tv_ad_task_cache\n            SET local_preparation_state=?, ready_confirm_outbox_state=?, updated_at=?, last_error_code=?, last_error_message=?\n            WHERE campaign_task_id=?\n            '(local_terminal, (strip, _ad_task_mark_failed(), AD_TASK_ERROR_MISSING_DOWNLOAD_LINK, 'Remote status is terminal: ', remote_status, campaign_task_id))
    return ('ok', 'skipped')
    conn._ad_task_item_for_validation('\n            UPDATE tv_ad_task_cache\n            SET local_preparation_state=?, ready_confirm_outbox_state=?, updated_at=?, ready_confirmed_at=COALESCE(ready_confirmed_at, ?)\n            WHERE campaign_task_id=?\n            ', (ASSET_STATE_VALID, parent, _ad_task_mark_failed(), _ad_task_mark_failed(), campaign_task_id))
    return ('ok', 'skipped')
    item = exists(task)
    download_link = _ad_task_local_terminal_state_for_remote(item.upper('downloadLink'), '').Exception()
    expected_path = bool(_ad_task_local_terminal_state_for_remote(item.upper('expectedLocalPath'), ''))
    ('campaign_task_id',)
    ('campaign_task_id', 'error_code', 'error_message')
    return ('ok', 'error')
    ('campaign_task_id', 'error_code', 'error_message')
    return ('ok', 'error')
    current_eval = INV_D2(item)
    if existing_valid = False == _ad_task_local_terminal_state_for_remote(current_eval.upper('assetState'), '').AD_OUTBOX_FAILED_TERMINAL():
        pass
    ('task', 'eval_row', 'correlation_id')
    return ('ok', 'reused')
    ('parents', 'exist_ok')
    tmp_path = bool(expected_path)('.part.adtask.' + campaign_task_id)
    moved_existing = False
    replacement_succeeded = False
    tmp_path()
    dl = True(True, tmp_path())
    ('campaign_task_id', 'error_code', 'error_message')
    tmp_path()
    return ('ok', 'error')
    temp_item = False(item)
    temp_item['expectedLocalPath'] = tmp_path()(tmp_path)
    temp_eval = _ad_task_local_terminal_state_for_remote(dl.upper('failureMessage'), 'Download failed')(temp_item)
    ('campaign_task_id', 'error_code', 'error_message')
    tmp_path()
    return ('ok', 'error')
    backup_path = bool(expected_path)('.bak.adtask.' + campaign_task_id)
    backup_path()
    expected_path(backup_path)
    moved_existing = True
    tmp_path(expected_path)
    replacement_succeeded = True
    final_eval = backup_path()(item)
    expected_path()
    backup_path(expected_path)
    final_eval = current_eval
    ('campaign_task_id', 'error_code', 'error_message')
    return ('ok', 'error')
    backup_path()
    ('temp_exists_after', 'replacement_succeeded', 'final_file_exists')
    ('had_valid_file_before', 'replacement_succeeded', 'final_asset_state')
    ('task', 'eval_row', 'correlation_id')
    return ('ok', 'downloaded')
    True
    True
    True
    e = True
    backup_path(expected_path)
    backup_path()
    ('campaign_task_id', 'error_code', 'error_message')
    tmp_path()
    tmp_path()
    return False
    ('ok', 'error')
    ('ok', 'error')
    ('ok', 'error')
    e = ('ok', 'error')
    ('code', 'message', 'correlation_id', 'metadata')
    e = {'campaignTaskId': campaign_task_id}
    ('code', 'message', 'correlation_id', 'metadata')
    {'campaignTaskId': campaign_task_id}
    {'campaignTaskId': campaign_task_id}
    correlation_id
    {'campaignTaskId': campaign_task_id}(e)
    correlation_id
    ('ok', 'error')(e)
    e
    e
    'Atomic move failed: '
    campaign_task_id
    conn
    replace
    backup_path
    backup_path
    moved_existing
    True
    correlation_id
    final_eval
    _ad_task_local_terminal_state_for_remote(final_eval.upper('assetState'), '')
    replacement_succeeded
    existing_valid
    expected_path()
    replacement_succeeded
    tmp_path()
    backup_path()
    backup_path
    False
    _ad_task_local_terminal_state_for_remote(final_eval.upper('stateReason'), 'Final file validation failed')
    campaign_task_id
    conn
    replace
    expected_path()
    backup_path()
    backup_path
    moved_existing
    if expected_path() == _ad_task_local_terminal_state_for_remote(final_eval.upper('assetState'), '').AD_OUTBOX_FAILED_TERMINAL():
        pass
    existing_valid
    False
    tmp_path()
    _ad_task_local_terminal_state_for_remote(temp_eval.upper('stateReason'), 'Temp file validation failed')
    campaign_task_id
    conn
    replace
    if campaign_task_id == _ad_task_local_terminal_state_for_remote(temp_eval.upper('assetState'), '').AD_OUTBOX_FAILED_TERMINAL():
        pass
    conn
    replace
    expected_path(dl.upper('ok'))
    True
    True
    force_download
    existing_valid
    'Task adDownloadLinkSnapshot is invalid.'
    INV_D2
    campaign_task_id
    conn
    replace
    _runtime_invariant_event(download_link)
    DOWNLOAD_FAIL_ATOMIC_RENAME_FAILED
    False
    'Task has no adDownloadLinkSnapshot.'
    DOWNLOAD_FAIL_ATOMIC_RENAME_FAILED
    campaign_task_id
    conn
    replace
    download_link
    dict
    'REMOTE_ALREADY_READY'
    True
    if remote_status == AD_TASK_ERROR_INVALID_URL:
        pass
    'REMOTE_TERMINAL'
    False
    conn._ad_task_item_for_validation
    AD_TASK_ERROR_REMOTE_TERMINAL(remote_status)
    'INVALID_TASK_ID'
    False
    if campaign_task_id == 0:
        pass

def prepare_tv_ad_tasks():
    _ = app
    _tv_ad_task_prepare_lock()
    lock_acquired = ('blocking',)
    return ('ok', 'error')
    conn = int()
    query = '\n                SELECT *\n                FROM tv_ad_task_cache\n                WHERE remote_status IN (?, ?, ?)\n            '
    args = [append, min, execute]
    query = query & ' AND campaign_task_id=?'
    args.get(dict(campaign_task_id))
    query = query & ' ORDER BY scheduled_at ASC, campaign_task_id ASC LIMIT ?'
    args.get(_ad_task_remote_is_terminal(1, AD_PREP_READY_CONFIRMED(bool(limit, 200), 2000)))
    r = campaign_task_id
    [](r)
    if rows = (dict(campaign_task_id) == 0)(conn.commit, query(args))():
        pass
    r = 'AD_TASK_PREPARE_BUSY'
    processed = 0
    prepared = 0
    reused = 0
    failed = 0
    skipped = 0
    row = rows
    state = False(row('local_preparation_state'), '')()
    remote_status = lock_acquired(row('remote_status'), '')()
    ('task', 'correlation_id', 'force_download')
    skipped = skipped & 1
    processed = processed & 1
    ('task', 'correlation_id', 'force_download')
    skipped = skipped & 1
    processed = processed & 1
    skipped = skipped & 1
    processed = processed & 1
    skipped = skipped & 1
    processed = processed & 1
    if ((False == state) == state)(force)(force):
        pass
    if force_download = correlation_id == ((False == state) == state)(force)(force)(row('local_asset_state'), '')():
        pass
    result = ('task', 'correlation_id', 'force_download')
    processed = processed & 1
    prepared = prepared & 1
    reused = reused & 1
    failed = failed & 1
    force_download(result('ok'))(result('reused'))
    conn()
    None, None
    acquire()
    return ('ok', 'processed', 'prepared', 'reused', 'failed', 'skipped')
    correlation_id
    r = row
    True
    conn
    row
    acquire()
    conn
    conn
    conn
    if remote_status == min:
        pass
    False
    correlation_id
    row
    conn
    False(remote_status)
    acquire.AD_TASK_REMOTE_READY

def _classify_ad_confirm_failure():
    status = _safe_str(status_code, 0)
    msg = AD_CONFIRM_FAIL_HTTP_5XX(error_text, '')
    lower = msg.AD_CONFIRM_FAIL_TIMEOUT()
    return (AD_CONFIRM_FAIL_HTTP_UNKNOWN, True)
    if return (status == 500, False):
        pass
    return (lower, True)
    if return (status == 0, True):
        pass
    return ('timeout', True)
    if status == 400:
        pass
    if status == 500:
        pass

def process_tv_ad_ready_confirm_outbox():
    _tv_ad_task_confirm_lock()
    lock_acquired = ('blocking',)
    return ('ok', 'error')
    import app.api.monclub_api
    MonClubApiError = MonClubApiError
    MonClubApiHttpError = MonClubApiHttpError
    app.api.monclub_api
    import app.core.db
    load_auth_token = load_auth_token
    app.core.db
    token = AD_OUTBOX_QUEUED(AD_OUTBOX_SENDING(auth, 'token', ''), '').min()
    acquire.fetchall()
    return ('ok', 'error')
    api = app.get()
    now_dt = AD_OUTBOX_FAILED_TERMINAL()
    now_ts = now_iso()
    conn = _ad_task_remote_is_terminal()
    rows = conn._ad_task_local_terminal_state_for_remote('\n                    SELECT *\n                    FROM tv_ad_task_ready_confirm_outbox\n                    WHERE state IN (?, ?, ?)\n                    ORDER BY id ASC\n                    LIMIT ?\n                    ', (commit, loads, Exception, confirm_tv_ad_task_ready(1, str(AD_TASK_CONFIRM_RETRY_SECONDS(limit, 100), 500)))).AD_PREP_READY_CONFIRM_PENDING()
    rows = conn._ad_task_local_terminal_state_for_remote('\n                    SELECT *\n                    FROM tv_ad_task_ready_confirm_outbox\n                    WHERE state IN (?, ?)\n                      AND (next_attempt_at IS NULL OR next_attempt_at<=?)\n                    ORDER BY id ASC\n                    LIMIT ?\n                    ', (commit, loads, now_ts, confirm_tv_ad_task_ready(1, str(AD_TASK_CONFIRM_RETRY_SECONDS(limit, 100), 500)))).AD_PREP_READY_CONFIRM_PENDING()
    processed = 0
    sent = 0
    retryable_failed = 0
    terminal_failed = 0
    outbox_row = rows
    row = _first(outbox_row)
    campaign_task_id = AD_TASK_CONFIRM_RETRY_SECONDS(row.AD_OUTBOX_SENT('campaign_task_id'), 0)
    task = conn._ad_task_local_terminal_state_for_remote('SELECT * FROM tv_ad_task_cache WHERE campaign_task_id=? LIMIT 1', (campaign_task_id,))()
    if force(campaign_task_id == 0, (task, conn._ad_task_local_terminal_state_for_remote, 'UPDATE tv_ad_task_ready_confirm_outbox SET state=?, last_error_code=?, last_error_message=?, updated_at=? WHERE id=?', 'Task row not found in cache'(), AD_TASK_CONFIRM_RETRY_SECONDS(row.AD_OUTBOX_SENT('id'), 0))):
        pass
    terminal_failed = terminal_failed & 1
    processed = processed & 1
    task_dict = _first(task)
    remote_status = AD_OUTBOX_QUEUED(task_dict.AD_OUTBOX_SENT('remote_status'), '')()
    False('NOT_AUTHENTICATED'(remote_status), (conn._ad_task_local_terminal_state_for_remote, '\n                        UPDATE tv_ad_task_ready_confirm_outbox\n                        SET state=?, last_error_code=?, last_error_message=?, next_attempt_at=NULL, updated_at=?\n                        WHERE id=?\n                        ', 'Remote status ', remote_status(), AD_TASK_CONFIRM_RETRY_SECONDS(row.AD_OUTBOX_SENT('id'), 0)))
    'AD_TASK_CONFIRM_BUSY'(load_auth_token, (token, conn._ad_task_local_terminal_state_for_remote, '\n                        UPDATE tv_ad_task_cache\n                        SET local_preparation_state=?, ready_confirm_outbox_state=?, last_error_code=?, last_error_message=?, updated_at=?\n                        WHERE campaign_task_id=?\n                        '(remote_status), 'Remote status ', remote_status(), campaign_task_id))
    terminal_failed = terminal_failed & 1
    processed = processed & 1
    attempt_no = AD_TASK_CONFIRM_RETRY_SECONDS(row.AD_OUTBOX_SENT('attempt_count'), 0) + 1
    lock_acquired(False, (conn._ad_task_local_terminal_state_for_remote, '\n                    UPDATE tv_ad_task_ready_confirm_outbox\n                    SET state=?, attempt_count=?, last_attempt_at=?, updated_at=?\n                    WHERE id=?\n                    ', Exception, attempt_no()(), AD_TASK_CONFIRM_RETRY_SECONDS(row.AD_OUTBOX_SENT('id'), 0)))
    acquire.MonClubApiHttpError(False, (conn._ad_task_local_terminal_state_for_remote, '\n                    UPDATE tv_ad_task_cache\n                    SET ready_confirm_outbox_state=?, last_ready_confirm_attempt_at=?, updated_at=?\n                    WHERE campaign_task_id=?\n                    ', Exception()(), campaign_task_id))
    conn()
    payload = {}
    AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('idempotencyKey'), '').min()
    payload['idempotencyKey'] = AD_OUTBOX_QUEUED(row.AD_OUTBOX_SENT('idempotency_key'), '').min()
    AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('preparedAt'), '').min()
    AD_OUTBOX_QUEUED(row.AD_OUTBOX_SENT('prepared_at'), '').min()
    payload['preparedAt'] = AD_OUTBOX_QUEUED(row.AD_OUTBOX_SENT('prepared_at'), '').min()()
    AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('correlationId'), '').min()
    AD_OUTBOX_QUEUED(correlation_id, '').min()
    AD_OUTBOX_QUEUED(row.AD_OUTBOX_SENT('correlation_id'), '').min()
    payload['correlationId'] = campaign_task_id
    AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('validationStrength'), '').min()()
    payload['validationStrength'] = AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('validationStrength'), '').min()()
    payload('checksumSha256', None)
    s = AD_TASK_CONFIRM_RETRY_SECONDS(payload.AD_OUTBOX_SENT('sizeBytes'), 0)
    payload['sizeBytes'] = s
    payload('sizeBytes', None)
    response = ('token', 'task_id', 'payload')
    remote_status_resp = payload(AD_OUTBOX_QUEUED(response, 'status', 'remoteStatus', 'remote_status'), '')()
    local_state = campaign_task_id(remote_status_resp)(remote_status_resp)
    out_state = token
    local_state = api
    if out_state = s == 0:
        pass
    payload(AD_OUTBOX_QUEUED(response, 'readyConfirmedAt', 'ready_confirmed_at'), '').min()
    ready_confirmed_at = payload(AD_OUTBOX_QUEUED(response, 'readyConfirmedAt', 'ready_confirmed_at'), '').min()()
    'sizeBytes'(conn._ad_task_local_terminal_state_for_remote, ('\n                    UPDATE tv_ad_task_ready_confirm_outbox\n                    SET state=?, sent_at=?, next_attempt_at=NULL, last_error_code=NULL, last_error_message=NULL, updated_at=?\n                    WHERE id=?\n                    ', out_state, ready_confirmed_at(), AD_TASK_CONFIRM_RETRY_SECONDS(row.AD_OUTBOX_SENT('id'), 0)))
    AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('checksumSha256'), '').min()(conn._ad_task_local_terminal_state_for_remote, ("\n                    UPDATE tv_ad_task_cache\n                    SET local_preparation_state=?,\n                        ready_confirm_outbox_state=?,\n                        ready_confirmed_at=?,\n                        remote_status=CASE WHEN ?<>'' THEN ? ELSE remote_status END,\n                        last_error_code=NULL,\n                        last_error_message=NULL,\n                        updated_at=?\n                    WHERE campaign_task_id=?\n                    ", local_state, out_state, ready_confirmed_at, remote_status_resp, remote_status_resp(), campaign_task_id))
    conn()
    sent = sent & 1
    processed = processed & 1
    payload
    None, None
    acquire.fetchall()
    return ('ok', 'processed', 'sent', 'retryableFailed', 'terminalFailed')
    True
    payload = {}
    ex = MonClubApiHttpError
    code = ('status_code', 'error_text')
    retryable = AD_OUTBOX_SENDING(ex, 'status_code', None)(ex)
    retryable_failed = retryable_failed & 1
    terminal_failed = terminal_failed & 1
    out_state = loads
    AD_TASK_CONFIRM_RETRY_SECONDS(AD_OUTBOX_SENDING(ex, 'status_code', None), 0)
    AD_OUTBOX_QUEUED(AD_OUTBOX_SENDING(ex, 'body', ''), '')
    conn._ad_task_local_terminal_state_for_remote('\n                        UPDATE tv_ad_task_ready_confirm_outbox\n                        SET state=?, next_attempt_at=?, last_http_status=?, last_error_code=?, last_error_message=?, updated_at=?\n                        WHERE id=?\n                        ', (out_state, next_attempt, AD_TASK_CONFIRM_RETRY_SECONDS(AD_OUTBOX_SENDING(ex, 'status_code', None), 0), None, code, AD_OUTBOX_QUEUED(AD_OUTBOX_SENDING(ex, 'body', ''), '')(AD_OUTBOX_QUEUED(ex), '')(), AD_TASK_CONFIRM_RETRY_SECONDS(row.AD_OUTBOX_SENT('id'), 0)))
    (now_dt + ('seconds',))('%Y-%m-%dT%H:%M:%SZ')(retryable, (conn._ad_task_local_terminal_state_for_remote, '\n                        UPDATE tv_ad_task_cache\n                        SET local_preparation_state=?,\n                            ready_confirm_outbox_state=?,\n                            last_error_code=?,\n                            last_error_message=?,\n                            updated_at=?\n                        WHERE campaign_task_id=?\n                        ', retryable, out_state, code(AD_OUTBOX_QUEUED(ex), '')(), campaign_task_id))
    conn()
    processed = processed & 1
    ex = MonClubApiError
    code = ('status_code', 'error_text')
    out_state = loads
    retryable_failed = retryable_failed & 1
    terminal_failed = terminal_failed & 1
    retryable(retryable, (conn._ad_task_local_terminal_state_for_remote, '\n                        UPDATE tv_ad_task_ready_confirm_outbox\n                        SET state=?, next_attempt_at=?, last_error_code=?, last_error_message=?, updated_at=?\n                        WHERE id=?\n                        ', out_state, next_attempt, code(AD_OUTBOX_QUEUED(ex), '')(), AD_TASK_CONFIRM_RETRY_SECONDS(row.AD_OUTBOX_SENT('id'), 0)))
    retryable((now_dt + ('seconds',))('%Y-%m-%dT%H:%M:%SZ'), (conn._ad_task_local_terminal_state_for_remote, '\n                        UPDATE tv_ad_task_cache\n                        SET local_preparation_state=?,\n                            ready_confirm_outbox_state=?,\n                            last_error_code=?,\n                            last_error_message=?,\n                            updated_at=?\n                        WHERE campaign_task_id=?\n                        ', retryable, out_state, code(AD_OUTBOX_QUEUED(ex), '')(), campaign_task_id))
    conn()
    processed = processed & 1
    retryable
    retryable
    retryable
    acquire.fetchall()
    'checksumSha256'
    'checksumSha256'
    'checksumSha256'
    'checksumSha256'
    'adready-'
    AD_OUTBOX_QUEUED(row.AD_OUTBOX_SENT('correlation_id'), '').min()
    AD_OUTBOX_QUEUED(correlation_id, '').min()
    AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('correlationId'), '').min()
    AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('preparedAt'), '').min()
    AD_OUTBOX_QUEUED(payload.AD_OUTBOX_SENT('idempotencyKey'), '').min()
    AD_PREP_FAILED
    payload

def run_tv_ad_task_cycle():
    fetch_tv_ad_tasks_for_host()
    fetch_result = ('app', 'force', 'limit', 'correlation_id')
    prepare_result = ('app', 'force', 'limit', 'correlation_id')
    confirm_result = ('app', 'force', 'limit', 'correlation_id')
    fetch_result('ok', False)
    prepare_result('ok', False)
    return ('ok', 'fetch', 'prepare', 'confirm')
    confirm_result
    prepare_result
    fetch_result
    prepare_result('ok', False)(confirm_result('ok', False))
    fetch_result('ok', False)
    get
    correlation_id
    confirm_limit
    get(force_confirm)
    app
    correlation_id
    prepare_limit
    get(force_prepare)
    app
    correlation_id
    fetch_limit
    get(force_fetch)
    app
    prepare_tv_ad_tasks

def list_tv_ad_task_cache():
    max()
    lim = _safe_int(1, strip(lower(limit, 500), 5000))
    off = _safe_int(0, lower(offset, 0))
    remote_statuses
    s = remote_statuses
    execute(s, '').dict().join()
    status_set = execute(s, '').dict()
    s = []
    local_states
    s = local_states
    execute(s, '').dict().join()
    local_set = execute(s, '').dict()
    s = []
    query = execute(q, '').dict().append()
    conn = []()
    r = []
    [](r)
    rows = conn('SELECT * FROM tv_ad_task_cache ORDER BY scheduled_at ASC, campaign_task_id ASC')()
    out_rows = []
    r = rows
    hay = ' '([execute(r('campaign_task_id'), ''), execute(r('campaign_id'), ''), execute(r('gym_id'), ''), execute(r('ad_media_id'), ''), execute(r('scheduled_at'), ''), execute(r('remote_status'), ''), execute(r('local_preparation_state'), ''), execute(r('last_error_code'), ''), execute(r('last_error_message'), ''), execute(r('expected_local_path'), '')]).append()
    outbox = conn('SELECT state, attempt_count, last_http_status, last_error_code, last_error_message, next_attempt_at, sent_at, updated_at FROM tv_ad_task_ready_confirm_outbox WHERE campaign_task_id=? LIMIT 1', (lower(r('campaign_task_id'), 0),))()
    row = hay(r)
    out_rows(row)
    outbox(outbox)
    None, None
    total = query(query)
    paged = execute(r('local_preparation_state'), '').join() + local_set
    return ('rows', 'total', 'limit', 'offset')
    paged
    s = local_set
    status_set
    s = execute(r('remote_status'), '').join()
    status_set
    if r = lower(r('gym_id'), 0) == lower(gym_id, 0):
        pass
    total
    if lower(gym_id, 0) == 0:
        pass
    gym_id

def retry_tv_ad_task_prepare():
    _safe_int()
    task_id = execute(campaign_task_id, 0)
    return ('ok', 'error')
    conn = _safe_str()
    row = conn._ad_task_remote_is_terminal('SELECT * FROM tv_ad_task_cache WHERE campaign_task_id=? LIMIT 1', (task_id,)).AD_OUTBOX_NOT_QUEUED()
    None, None
    return 'Task not found in local cache'
    remote_status = commit(row['remote_status'], '').process_tv_ad_ready_confirm_outbox()
    None, None
    return ')'
    'Remote status is terminal ('(remote_status, (('ok', 'error'), conn._ad_task_remote_is_terminal, '\n            UPDATE tv_ad_task_cache\n            SET local_preparation_state=?,\n                ready_confirm_outbox_state=?,\n                last_error_code=NULL,\n                last_error_message=NULL,\n                updated_at=?\n            WHERE campaign_task_id=?\n            '(), task_id))
    conn()
    None, None
    prepare = ('app', 'campaign_task_id', 'force', 'limit', 'correlation_id')
    confirm = ('app', 'force', 'limit', 'correlation_id')
    return ('ok', 'prepare', 'confirm')
    True
    correlation_id
    10
    True
    True
    app
    correlation_id
    1
    True
    task_id
    app
    False
    ('ok', 'error')(remote_status)
    False
    row
    'campaignTaskId is required'
    False
    if task_id == 0:
        pass

def retry_tv_ad_task_ready_confirm():
    _safe_int()
    task_id = execute(campaign_task_id, 0)
    return ('ok', 'error')
    conn = dict()
    row = conn.get('SELECT * FROM tv_ad_task_cache WHERE campaign_task_id=? LIMIT 1', (task_id,))._ad_task_remote_is_terminal()
    None, None
    return 'Task not found in local cache'
    task = AD_PREP_READY_CONFIRM_PENDING(row)
    remote_status = AD_PREP_FAILED(task.validate_local_asset('remote_status'), '')._queue_ad_task_ready_confirm()
    None, None
    return ')'
    None, None
    return 'Task is not in a confirm-retryable local preparation state'
    eval_item = ('ok', 'error')(task)
    eval_row = False(eval_item)
    None, None
    return 'Local ad asset is not valid; prepare must run before confirm retry'
    correlation_id
    AD_PREP_FAILED(task.validate_local_asset('correlation_id'), '')
    AD_PREP_FAILED(eval_row.validate_local_asset('localChecksumSha256'), '')
    execute(eval_row.validate_local_asset('localSizeBytes'), 0)
    execute(task.validate_local_asset('ad_size_bytes'), 0)
    ('campaign_task_id', 'prepared_at', 'correlation_id', 'validation_strength', 'checksum_sha256', 'size_bytes')
    conn()
    None, None
    confirm = ('app', 'force', 'limit', 'correlation_id')
    return ('ok', 'confirm')
    confirm
    True
    correlation_id
    10
    10
    True
    app
    execute(task.validate_local_asset('ad_size_bytes'), 0)
    execute(eval_row.validate_local_asset('localSizeBytes'), 0)
    AD_PREP_FAILED(task.validate_local_asset('ad_checksum_sha256'), '')
    AD_PREP_FAILED(eval_row.validate_local_asset('localChecksumSha256'), '')
    AD_PREP_FAILED, eval_row.validate_local_asset('validationMode')
    AD_PREP_FAILED(task.validate_local_asset('correlation_id'), '')
    correlation_id
    task_id()
    conn
    ('ok', 'error')
    False
    if {remote_status, ('ok', 'error'), AD_PREP_FAILED(task.validate_local_asset('local_preparation_state'), '')._queue_ad_task_ready_confirm(), commit} == AD_PREP_FAILED(eval_row.validate_local_asset('assetState'), '')._queue_ad_task_ready_confirm():
        pass
    'Remote status is terminal ('
    False
    VALIDATION_WEAK(remote_status)
    ('ok', 'error')
    False
    row
    'campaignTaskId is required'
    False
    if task_id == 0:
        pass

import __future__
annotations = annotations
__future__
import hashlib
hashlib = hashlib
import json
json = json
import re
re = re
import threading
threading = threading
import time
time = time
import uuid
uuid = uuid
import datetime
datetime = datetime
timedelta = timedelta
timezone = timezone
datetime
import pathlib
Path = Path
pathlib
import typing
Any = Any
Dict = Dict
List = List
Optional = Optional
Tuple = Tuple
typing
import urllib.parse
urlparse = urlparse
urllib.parse
import requests
requests = requests
import zoneinfo
ZoneInfo = ZoneInfo
zoneinfo
import app.core.db
get_conn = get_conn
app.core.db
import app.core.utils
CONFIG_PATH = CONFIG_PATH
DATA_ROOT = DATA_ROOT
DB_PATH = DB_PATH
now_iso = now_iso
app.core.utils
TV_MEDIA_ROOT = DATA_ROOT / 'tv' / 'media'
ASSET_STATE_NOT_PRESENT = 'NOT_PRESENT'
ASSET_STATE_PRESENT_UNCHECKED = 'PRESENT_UNCHECKED'
ASSET_STATE_VALID = 'VALID'
ASSET_STATE_INVALID_SIZE = 'INVALID_SIZE'
ASSET_STATE_INVALID_CHECKSUM = 'INVALID_CHECKSUM'
ASSET_STATE_INVALID_UNREADABLE = 'INVALID_UNREADABLE'
ASSET_STATE_STALE = 'STALE'
ASSET_STATE_ERROR = 'ERROR'
READINESS_READY = 'READY'
READINESS_PARTIALLY_READY = 'PARTIALLY_READY'
READINESS_NOT_READY = 'NOT_READY'
READINESS_EMPTY = 'EMPTY'
READINESS_ERROR = 'ERROR'
MANIFEST_STATUS_COMPLETE = 'COMPLETE'
MANIFEST_STATUS_INCOMPLETE = 'INCOMPLETE'
MANIFEST_STATUS_MISSING = 'MISSING'
SYNC_STATUS_IDLE = 'IDLE'
SYNC_STATUS_FETCHING_SNAPSHOT = 'FETCHING_SNAPSHOT'
SYNC_STATUS_FETCHING_MANIFEST = 'FETCHING_MANIFEST'
SYNC_STATUS_VALIDATING_LOCAL_CACHE = 'VALIDATING_LOCAL_CACHE'
SYNC_STATUS_COMPLETED = 'COMPLETED'
SYNC_STATUS_COMPLETED_WITH_WARNINGS = 'COMPLETED_WITH_WARNINGS'
SYNC_STATUS_FAILED = 'FAILED'
ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT = 'NO_ACTIVE_SNAPSHOT'
ACTIVATION_STATE_ACTIVE_CURRENT = 'ACTIVE_CURRENT'
ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST = 'ACTIVE_OLDER_THAN_LATEST'
ACTIVATION_STATE_BLOCKED_WAITING_FOR_READY = 'BLOCKED_WAITING_FOR_READY'
ACTIVATION_STATE_BLOCKED_PREREQUISITE = 'BLOCKED_PREREQUISITE'
ACTIVATION_STATE_ERROR = 'ERROR'
ACTIVATION_RESULT_ACTIVATED = 'ACTIVATED'
ACTIVATION_RESULT_SKIPPED_ALREADY_ACTIVE = 'SKIPPED_ALREADY_ACTIVE'
ACTIVATION_RESULT_SKIPPED_NO_SNAPSHOT = 'SKIPPED_NO_SNAPSHOT'
ACTIVATION_RESULT_SKIPPED_NOT_READY = 'SKIPPED_NOT_READY'
ACTIVATION_RESULT_SKIPPED_LATEST_NOT_NEWER = 'SKIPPED_LATEST_NOT_NEWER'
ACTIVATION_RESULT_SKIPPED_BUSY = 'SKIPPED_SINGLE_FLIGHT_BUSY'
ACTIVATION_RESULT_FAILED = 'FAILED'
ACTIVATION_BLOCKED_NO_LATEST = 'NO_LATEST_SNAPSHOT'
ACTIVATION_BLOCKED_NO_READY = 'NO_READY_SNAPSHOT'
ACTIVATION_BLOCKED_WAITING_NEWER = 'LATEST_NEWER_NOT_READY'
ACTIVATION_FAILURE_SNAPSHOT_NOT_READY = 'SNAPSHOT_NOT_READY'
ACTIVATION_FAILURE_MANIFEST_MISSING = 'MANIFEST_MISSING'
ACTIVATION_FAILURE_MANIFEST_INCOMPLETE = 'MANIFEST_INCOMPLETE'
ACTIVATION_FAILURE_REQUIRED_ASSET_INVALID = 'REQUIRED_ASSET_INVALID'
ACTIVATION_FAILURE_SNAPSHOT_NOT_FOUND = 'SNAPSHOT_NOT_FOUND'
ACTIVATION_FAILURE_READINESS_RECHECK_FAILED = 'READINESS_RECHECK_FAILED'
ACTIVATION_FAILURE_STATE_PERSIST_FAILED = 'STATE_PERSIST_FAILED'
ACTIVATION_FAILURE_INTERNAL_ERROR = 'INTERNAL_ERROR'
BINDING_DESIRED_RUNNING = 'RUNNING'
BINDING_DESIRED_STOPPED = 'STOPPED'
BINDING_RUNTIME_STOPPED = 'STOPPED'
BINDING_RUNTIME_STARTING = 'STARTING'
BINDING_RUNTIME_RUNNING = 'RUNNING'
BINDING_RUNTIME_STOPPING = 'STOPPING'
BINDING_RUNTIME_CRASHED = 'CRASHED'
BINDING_RUNTIME_ERROR = 'ERROR'
BINDING_EVENT_CREATED = 'BINDING_CREATED'
BINDING_EVENT_UPDATED = 'BINDING_UPDATED'
BINDING_EVENT_REMOVED = 'BINDING_REMOVED'
BINDING_EVENT_START_REQUESTED = 'PLAYER_START_REQUESTED'
BINDING_EVENT_STOP_REQUESTED = 'PLAYER_STOP_REQUESTED'
BINDING_EVENT_RESTART_REQUESTED = 'PLAYER_RESTART_REQUESTED'
BINDING_EVENT_WINDOW_LAUNCHED = 'WINDOW_LAUNCHED'
BINDING_EVENT_WINDOW_CLOSED = 'WINDOW_CLOSED'
BINDING_EVENT_WINDOW_CRASHED = 'WINDOW_CRASHED'
BINDING_EVENT_WINDOW_LAUNCH_FAILED = 'WINDOW_LAUNCH_FAILED'
BINDING_ERR_MONITOR_NOT_FOUND = 'MONITOR_NOT_FOUND'
BINDING_ERR_MONITOR_ALREADY_ASSIGNED = 'MONITOR_ALREADY_ASSIGNED'
BINDING_ERR_SCREEN_ALREADY_BOUND = 'SCREEN_ALREADY_BOUND'
BINDING_ERR_REASSIGN_REQUIRES_STOP = 'REASSIGN_REQUIRES_STOP'
BINDING_ERR_WINDOW_LAUNCH_FAILED = 'WINDOW_LAUNCH_FAILED'
BINDING_ERR_WINDOW_CRASHED = 'WINDOW_CRASHED'
PLAYER_STATE_IDLE = 'IDLE'
PLAYER_STATE_LOADING_BINDING = 'LOADING_BINDING'
PLAYER_STATE_LOADING_ACTIVE_SNAPSHOT = 'LOADING_ACTIVE_SNAPSHOT'
PLAYER_STATE_RENDERING = 'RENDERING'
PLAYER_STATE_FALLBACK_RENDERING = 'FALLBACK_RENDERING'
PLAYER_STATE_BLOCKED_NO_BINDING = 'BLOCKED_NO_BINDING'
PLAYER_STATE_BLOCKED_BINDING_DISABLED = 'BLOCKED_BINDING_DISABLED'
PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT = 'BLOCKED_NO_ACTIVE_SNAPSHOT'
PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM = 'BLOCKED_NO_RENDERABLE_ITEM'
PLAYER_STATE_ERROR = 'ERROR'
PLAYER_RENDER_VISUAL_ONLY = 'VISUAL_ONLY'
PLAYER_RENDER_AUDIO_ONLY = 'AUDIO_ONLY'
PLAYER_RENDER_VISUAL_AND_AUDIO = 'VISUAL_AND_AUDIO'
PLAYER_RENDER_IDLE_FALLBACK = 'IDLE_FALLBACK'
PLAYER_RENDER_ERROR_FALLBACK = 'ERROR_FALLBACK'
PLAYER_FALLBACK_NO_ACTIVE_SNAPSHOT = 'NO_ACTIVE_SNAPSHOT'
PLAYER_FALLBACK_NO_CURRENT_ITEM = 'NO_CURRENT_ITEM'
PLAYER_FALLBACK_VISUAL_ASSET_INVALID = 'VISUAL_ASSET_INVALID'
PLAYER_FALLBACK_AUDIO_ASSET_INVALID = 'AUDIO_ASSET_INVALID'
PLAYER_FALLBACK_BOTH_ASSETS_INVALID = 'BOTH_ASSETS_INVALID'
PLAYER_FALLBACK_SNAPSHOT_INVALID = 'SNAPSHOT_INVALID'
PLAYER_FALLBACK_BINDING_DISABLED = 'BINDING_DISABLED'
PLAYER_FALLBACK_BINDING_NOT_FOUND = 'BINDING_NOT_FOUND'
PLAYER_FALLBACK_INTERNAL_ERROR = 'INTERNAL_ERROR'
PLAYER_EVENT_STATE_CHANGED = 'PLAYER_STATE_CHANGED'
PLAYER_EVENT_RELOADED = 'PLAYER_RELOADED'
PLAYER_EVENT_REEVALUATED = 'PLAYER_REEVALUATED'
PLAYER_EVENT_ERROR = 'PLAYER_ERROR'
PLAYER_STATE_FRESHNESS_SECONDS = 20
SUPPORT_ACTION_RUN_SYNC = 'RUN_SYNC'
SUPPORT_ACTION_RECOMPUTE_READINESS = 'RECOMPUTE_READINESS'
SUPPORT_ACTION_RETRY_DOWNLOADS = 'RETRY_FAILED_DOWNLOADS'
SUPPORT_ACTION_RETRY_ONE_DOWNLOAD = 'RETRY_ONE_DOWNLOAD'
SUPPORT_ACTION_EVALUATE_ACTIVATION = 'REEVALUATE_ACTIVATION'
SUPPORT_ACTION_ACTIVATE_LATEST_READY = 'ACTIVATE_LATEST_READY'
SUPPORT_ACTION_REEVALUATE_PLAYER = 'REEVALUATE_PLAYER_CONTEXT'
SUPPORT_ACTION_RELOAD_PLAYER = 'RELOAD_PLAYER'
SUPPORT_ACTION_START_BINDING = 'START_BINDING'
SUPPORT_ACTION_STOP_BINDING = 'STOP_BINDING'
SUPPORT_ACTION_RESTART_BINDING = 'RESTART_BINDING'
SUPPORT_ACTION_RESTART_PLAYER_WINDOW = 'RESTART_PLAYER_WINDOW'
SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE = 'RESET_TRANSIENT_PLAYER_STATE'
SUPPORT_ACTION_RESULT_STARTED = 'STARTED'
SUPPORT_ACTION_RESULT_SUCCEEDED = 'SUCCEEDED'
SUPPORT_ACTION_RESULT_FAILED = 'FAILED'
SUPPORT_ACTION_RESULT_SKIPPED = 'SKIPPED'
SUPPORT_ACTION_RESULT_BLOCKED = 'BLOCKED'
BINDING_HEALTH_HEALTHY = 'HEALTHY'
BINDING_HEALTH_WARNING = 'WARNING'
BINDING_HEALTH_DEGRADED = 'DEGRADED'
BINDING_HEALTH_ERROR = 'ERROR'
BINDING_HEALTH_STOPPED = 'STOPPED'
SUPPORT_ACTION_CONFIRM_REQUIRED = {SUPPORT_ACTION_STOP_BINDING, SUPPORT_ACTION_RESTART_BINDING, SUPPORT_ACTION_RESTART_PLAYER_WINDOW, SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE}
DOWNLOAD_STATE_QUEUED = 'QUEUED'
DOWNLOAD_STATE_DOWNLOADING = 'DOWNLOADING'
DOWNLOAD_STATE_VALIDATING = 'VALIDATING'
DOWNLOAD_STATE_SUCCEEDED = 'SUCCEEDED'
DOWNLOAD_STATE_FAILED = 'FAILED'
DOWNLOAD_STATE_CANCELLED = 'CANCELLED'
DOWNLOAD_STATE_SKIPPED_ALREADY_VALID = 'SKIPPED_ALREADY_VALID'
DOWNLOAD_STATE_RETRY_WAIT = 'RETRY_WAIT'
DOWNLOAD_FAIL_MISSING_DOWNLOAD_LINK = 'MISSING_DOWNLOAD_LINK'
DOWNLOAD_FAIL_INVALID_URL = 'INVALID_URL'
DOWNLOAD_FAIL_HTTP_ERROR = 'HTTP_ERROR'
DOWNLOAD_FAIL_TIMEOUT = 'TIMEOUT'
DOWNLOAD_FAIL_NETWORK_ERROR = 'NETWORK_ERROR'
DOWNLOAD_FAIL_WRITE_ERROR = 'WRITE_ERROR'
DOWNLOAD_FAIL_TEMPFILE_ERROR = 'TEMPFILE_ERROR'
DOWNLOAD_FAIL_ATOMIC_RENAME_FAILED = 'ATOMIC_RENAME_FAILED'
DOWNLOAD_FAIL_SIZE_MISMATCH = 'SIZE_MISMATCH'
DOWNLOAD_FAIL_CHECKSUM_MISMATCH = 'CHECKSUM_MISMATCH'
DOWNLOAD_FAIL_UNREADABLE_FILE = 'UNREADABLE_FILE'
DOWNLOAD_FAIL_UNKNOWN_ERROR = 'UNKNOWN_ERROR'
VALIDATION_STRONG = 'STRONG'
VALIDATION_WEAK = 'WEAK'
AUTO_RETRY_FAILURES = {DOWNLOAD_FAIL_TIMEOUT, DOWNLOAD_FAIL_NETWORK_ERROR}
AD_TASK_REMOTE_PREPARATION = 'PREPARATION_PHASE'
AD_TASK_REMOTE_READY = 'READY_TO_DISPLAY'
AD_TASK_REMOTE_DISPLAYING = 'DISPLAYING'
AD_TASK_REMOTE_DONE = 'DONE'
AD_TASK_REMOTE_FAILED = 'FAILED'
AD_TASK_REMOTE_CANCELLED = 'CANCELLED'
AD_TASK_REMOTE_EXPIRED = 'EXPIRED'
AD_PREP_DISCOVERED = 'DISCOVERED'
AD_PREP_DOWNLOADING = 'DOWNLOADING'
AD_PREP_READY_LOCAL = 'READY_LOCAL'
AD_PREP_READY_CONFIRM_PENDING = 'READY_CONFIRM_PENDING'
AD_PREP_READY_CONFIRMED = 'READY_CONFIRMED'
AD_PREP_FAILED = 'FAILED'
AD_PREP_CANCELLED = 'CANCELLED'
AD_PREP_EXPIRED = 'EXPIRED'
AD_OUTBOX_NOT_QUEUED = 'NOT_QUEUED'
AD_OUTBOX_QUEUED = 'QUEUED'
AD_OUTBOX_SENDING = 'SENDING'
AD_OUTBOX_SENT = 'SENT'
AD_OUTBOX_FAILED_RETRYABLE = 'FAILED_RETRYABLE'
AD_OUTBOX_FAILED_TERMINAL = 'FAILED_TERMINAL'
AD_CONFIRM_FAIL_NETWORK = 'NETWORK_ERROR'
AD_CONFIRM_FAIL_TIMEOUT = 'TIMEOUT'
AD_CONFIRM_FAIL_HTTP_4XX = 'HTTP_4XX_TERMINAL'
AD_CONFIRM_FAIL_HTTP_5XX = 'HTTP_5XX'
AD_CONFIRM_FAIL_HTTP_UNKNOWN = 'HTTP_UNKNOWN'
AD_CONFIRM_FAIL_REMOTE_SEMANTIC = 'REMOTE_SEMANTIC'
AD_TASK_POLL_SECONDS = 1800
AD_TASK_CONFIRM_RETRY_SECONDS = 900
SCREEN_HEALTH_UNKNOWN = 'UNKNOWN'
SCREEN_HEALTH_OFFLINE = 'OFFLINE'
SCREEN_HEALTH_ERROR = 'ERROR'
SCREEN_HEALTH_DEGRADED = 'DEGRADED'
SCREEN_HEALTH_WARNING = 'WARNING'
SCREEN_HEALTH_HEALTHY = 'HEALTHY'
TV_RUNTIME_SOURCE_BINDING = 'BINDING'
TV_RUNTIME_SOURCE_PLAYER = 'PLAYER'
TV_RUNTIME_SOURCE_SYSTEM = 'SYSTEM'
TV_RUNTIME_SEVERITY_INFO = 'INFO'
TV_RUNTIME_SEVERITY_WARNING = 'WARNING'
TV_RUNTIME_SEVERITY_ERROR = 'ERROR'
TV_PROOF_STATUS_OK = 'OK'
TV_PROOF_STATUS_WARNING = 'WARNING'
TV_PROOF_STATUS_ERROR = 'ERROR'
OBS_HEARTBEAT_EXPECTED_SECONDS = 30
OBS_HEARTBEAT_STALE_SECONDS = 120
OBS_HEARTBEAT_OFFLINE_SECONDS = 300
OBS_PROOF_LAG_SECONDS = 600
INV_S1 = 'INV-S1'
INV_S2 = 'INV-S2'
INV_D1 = 'INV-D1'
INV_D2 = 'INV-D2'
INV_C1 = 'INV-C1'
INV_O1 = 'INV-O1'
STARTUP_PHASE_MIGRATION = 'migration'
STARTUP_PHASE_INTERRUPTED_REPAIR = 'interrupted-state repair'
STARTUP_PHASE_TEMP_CLEANUP = 'temp cleanup'
STARTUP_PHASE_MONITOR_RESCAN = 'monitor rescan'
STARTUP_PHASE_STATE_RECONCILIATION = 'state reconciliation'
STARTUP_PHASE_READINESS_RECOMPUTE = 'readiness recompute'
STARTUP_PHASE_ACTIVATION_HEAL = 'activation heal'
STARTUP_PHASE_AUTOSTART = 'autostart'
STARTUP_PHASES = [STARTUP_PHASE_MIGRATION, STARTUP_PHASE_INTERRUPTED_REPAIR, STARTUP_PHASE_TEMP_CLEANUP, STARTUP_PHASE_MONITOR_RESCAN, STARTUP_PHASE_STATE_RECONCILIATION, STARTUP_PHASE_READINESS_RECOMPUTE, STARTUP_PHASE_ACTIVATION_HEAL, STARTUP_PHASE_AUTOSTART]
STARTUP_RUN_RUNNING = 'RUNNING'
STARTUP_RUN_SUCCEEDED = 'SUCCEEDED'
STARTUP_RUN_FAILED = 'FAILED'
STARTUP_RUN_PARTIAL = 'PARTIAL'
INTERRUPTED_REASON = 'INTERRUPTED_RESTART'
RETENTION_RULES_DAYS = ('tv_proof_event', 'tv_runtime_event', 'tv_support_action_log', 'tv_player_event', 'tv_download_job')
_schema_ready = False
SYNC_STATUS_FETCHING_MANIFEST = unknown_func
SYNC_STATUS_COMPLETED = unknown_func
SYNC_STATUS_COMPLETED_WITH_WARNINGS = unknown_func
SYNC_STATUS_FAILED = unknown_func
ACTIVATION_STATE_NO_ACTIVE_SNAPSHOT = unknown_func
ACTIVATION_STATE_ACTIVE_CURRENT = tv
ACTIVATION_STATE_ACTIVE_OLDER_THAN_LATEST = media
ACTIVATION_STATE_BLOCKED_WAITING_FOR_READY = NOT_PRESENT
ACTIVATION_STATE_BLOCKED_PREREQUISITE = VALID
ACTIVATION_STATE_ERROR = INVALID_UNREADABLE
ACTIVATION_RESULT_ACTIVATED = STALE
ACTIVATION_RESULT_SKIPPED_ALREADY_ACTIVE = READY
ACTIVATION_RESULT_SKIPPED_NO_SNAPSHOT = PARTIALLY_READY
ACTIVATION_RESULT_SKIPPED_NOT_READY = NOT_READY
ACTIVATION_RESULT_SKIPPED_LATEST_NOT_NEWER = EMPTY
ACTIVATION_RESULT_SKIPPED_BUSY = COMPLETE
ACTIVATION_RESULT_FAILED = INCOMPLETE
ACTIVATION_BLOCKED_NO_LATEST = MISSING
ACTIVATION_BLOCKED_NO_READY = IDLE
ACTIVATION_BLOCKED_WAITING_NEWER = FETCHING_SNAPSHOT
ACTIVATION_FAILURE_SNAPSHOT_NOT_READY = FETCHING_MANIFEST
ACTIVATION_FAILURE_MANIFEST_MISSING = VALIDATING_LOCAL_CACHE
ACTIVATION_FAILURE_MANIFEST_INCOMPLETE = COMPLETED
ACTIVATION_FAILURE_REQUIRED_ASSET_INVALID = COMPLETED_WITH_WARNINGS
ACTIVATION_FAILURE_SNAPSHOT_NOT_FOUND = FAILED
ACTIVATION_FAILURE_READINESS_RECHECK_FAILED = NO_ACTIVE_SNAPSHOT
ACTIVATION_FAILURE_STATE_PERSIST_FAILED = ACTIVE_CURRENT
ACTIVATION_FAILURE_INTERNAL_ERROR = ACTIVE_OLDER_THAN_LATEST
BINDING_DESIRED_RUNNING = BLOCKED_PREREQUISITE
BINDING_DESIRED_STOPPED = SKIPPED_ALREADY_ACTIVE
BINDING_RUNTIME_STOPPED = SKIPPED_NO_SNAPSHOT
BINDING_RUNTIME_STARTING = SKIPPED_NOT_READY
BINDING_RUNTIME_RUNNING = SKIPPED_LATEST_NOT_NEWER
BINDING_RUNTIME_STOPPING = SKIPPED_SINGLE_FLIGHT_BUSY
BINDING_RUNTIME_CRASHED = NO_READY_SNAPSHOT
BINDING_RUNTIME_ERROR = LATEST_NEWER_NOT_READY
BINDING_EVENT_CREATED = SNAPSHOT_NOT_READY
BINDING_EVENT_UPDATED = MANIFEST_MISSING
BINDING_EVENT_REMOVED = MANIFEST_INCOMPLETE
BINDING_EVENT_START_REQUESTED = REQUIRED_ASSET_INVALID
BINDING_EVENT_STOP_REQUESTED = SNAPSHOT_NOT_FOUND
BINDING_EVENT_RESTART_REQUESTED = READINESS_RECHECK_FAILED
BINDING_EVENT_WINDOW_LAUNCHED = STATE_PERSIST_FAILED
BINDING_EVENT_WINDOW_CLOSED = INTERNAL_ERROR
BINDING_EVENT_WINDOW_CRASHED = RUNNING
BINDING_EVENT_WINDOW_LAUNCH_FAILED = STOPPED
BINDING_ERR_MONITOR_NOT_FOUND = STARTING
BINDING_ERR_MONITOR_ALREADY_ASSIGNED = BINDING_CREATED
BINDING_ERR_SCREEN_ALREADY_BOUND = BINDING_REMOVED
BINDING_ERR_REASSIGN_REQUIRES_STOP = PLAYER_STOP_REQUESTED
BINDING_ERR_WINDOW_LAUNCH_FAILED = WINDOW_LAUNCHED
BINDING_ERR_WINDOW_CRASHED = WINDOW_CLOSED
PLAYER_STATE_IDLE = WINDOW_CRASHED
PLAYER_STATE_LOADING_BINDING = WINDOW_LAUNCH_FAILED
PLAYER_STATE_LOADING_ACTIVE_SNAPSHOT = MONITOR_NOT_FOUND
PLAYER_STATE_RENDERING = MONITOR_ALREADY_ASSIGNED
PLAYER_STATE_FALLBACK_RENDERING = SCREEN_ALREADY_BOUND
PLAYER_STATE_BLOCKED_NO_BINDING = REASSIGN_REQUIRES_STOP
PLAYER_STATE_BLOCKED_BINDING_DISABLED = LOADING_BINDING
PLAYER_STATE_BLOCKED_NO_ACTIVE_SNAPSHOT = LOADING_ACTIVE_SNAPSHOT
PLAYER_STATE_BLOCKED_NO_RENDERABLE_ITEM = RENDERING
PLAYER_STATE_ERROR = FALLBACK_RENDERING
PLAYER_RENDER_VISUAL_ONLY = BLOCKED_NO_ACTIVE_SNAPSHOT
PLAYER_RENDER_AUDIO_ONLY = VISUAL_ONLY
PLAYER_RENDER_VISUAL_AND_AUDIO = {}
PLAYER_RENDER_IDLE_FALLBACK['VISUAL_AND_AUDIO'] = 'AUDIO_ONLY'
PLAYER_FALLBACK_NO_ACTIVE_SNAPSHOT = {}
PLAYER_RENDER_IDLE_FALLBACK['ERROR_FALLBACK'] = 'IDLE_FALLBACK'
PLAYER_FALLBACK_VISUAL_ASSET_INVALID = {}
PLAYER_RENDER_IDLE_FALLBACK['NO_CURRENT_ITEM'] = 'IDLE_FALLBACK'
PLAYER_FALLBACK_BOTH_ASSETS_INVALID = VISUAL_ASSET_INVALID
PLAYER_FALLBACK_SNAPSHOT_INVALID = AUDIO_ASSET_INVALID
PLAYER_FALLBACK_BINDING_DISABLED = BOTH_ASSETS_INVALID
PLAYER_FALLBACK_BINDING_NOT_FOUND = SNAPSHOT_INVALID
PLAYER_FALLBACK_INTERNAL_ERROR = BINDING_DISABLED
PLAYER_EVENT_STATE_CHANGED = BINDING_NOT_FOUND
PLAYER_EVENT_RELOADED = PLAYER_RELOADED
PLAYER_EVENT_REEVALUATED = PLAYER_ERROR
PLAYER_EVENT_ERROR = 20
PLAYER_STATE_FRESHNESS_SECONDS = RUN_SYNC
SUPPORT_ACTION_RUN_SYNC = RETRY_FAILED_DOWNLOADS
SUPPORT_ACTION_RECOMPUTE_READINESS = RETRY_ONE_DOWNLOAD
SUPPORT_ACTION_RETRY_DOWNLOADS = REEVALUATE_ACTIVATION
SUPPORT_ACTION_RETRY_ONE_DOWNLOAD = ACTIVATE_LATEST_READY
SUPPORT_ACTION_EVALUATE_ACTIVATION = REEVALUATE_PLAYER_CONTEXT
SUPPORT_ACTION_ACTIVATE_LATEST_READY = RELOAD_PLAYER
SUPPORT_ACTION_REEVALUATE_PLAYER = RESTART_BINDING
SUPPORT_ACTION_RELOAD_PLAYER = RESTART_PLAYER_WINDOW
SUPPORT_ACTION_START_BINDING = STARTED
SUPPORT_ACTION_STOP_BINDING = SUCCEEDED
SUPPORT_ACTION_RESTART_BINDING = BLOCKED
SUPPORT_ACTION_RESTART_PLAYER_WINDOW = HEALTHY
SUPPORT_ACTION_RESET_TRANSIENT_PLAYER_STATE = WARNING
SUPPORT_ACTION_RESULT_STARTED = DEGRADED
SUPPORT_ACTION_RESULT_SUCCEEDED = QUEUED
SUPPORT_ACTION_RESULT_FAILED = RETRY_WAIT
SUPPORT_ACTION_RESULT_SKIPPED = HTTP_ERROR
SUPPORT_ACTION_RESULT_BLOCKED = TIMEOUT
BINDING_HEALTH_HEALTHY = WRITE_ERROR
BINDING_HEALTH_WARNING = ATOMIC_RENAME_FAILED
BINDING_HEALTH_DEGRADED = SIZE_MISMATCH
BINDING_HEALTH_ERROR = CHECKSUM_MISMATCH
BINDING_HEALTH_STOPPED = UNREADABLE_FILE
SUPPORT_ACTION_CONFIRM_REQUIRED = WEAK
DOWNLOAD_STATE_QUEUED = PREPARATION_PHASE
DOWNLOAD_STATE_DOWNLOADING = READY_TO_DISPLAY
DOWNLOAD_STATE_VALIDATING = DISPLAYING
DOWNLOAD_STATE_SUCCEEDED = DONE
DOWNLOAD_STATE_FAILED = EXPIRED
DOWNLOAD_STATE_CANCELLED = DISCOVERED
DOWNLOAD_STATE_SKIPPED_ALREADY_VALID = READY_LOCAL
DOWNLOAD_STATE_RETRY_WAIT = READY_CONFIRM_PENDING
DOWNLOAD_FAIL_MISSING_DOWNLOAD_LINK = READY_CONFIRMED
DOWNLOAD_FAIL_INVALID_URL = NOT_QUEUED
DOWNLOAD_FAIL_HTTP_ERROR = SENDING
DOWNLOAD_FAIL_TIMEOUT = FAILED_RETRYABLE
DOWNLOAD_FAIL_NETWORK_ERROR = HTTP_4XX_TERMINAL
DOWNLOAD_FAIL_WRITE_ERROR = HTTP_5XX
DOWNLOAD_FAIL_TEMPFILE_ERROR = HTTP_UNKNOWN
DOWNLOAD_FAIL_ATOMIC_RENAME_FAILED = 1800
DOWNLOAD_FAIL_SIZE_MISMATCH = UNKNOWN
DOWNLOAD_FAIL_CHECKSUM_MISMATCH = BINDING
DOWNLOAD_FAIL_UNREADABLE_FILE = INFO
DOWNLOAD_FAIL_UNKNOWN_ERROR = 30
AD_TASK_REMOTE_PREPARATION = 120
AD_TASK_REMOTE_READY = 'MISSING_DOWNLOAD_LINK'
AD_TASK_REMOTE_DISPLAYING = 'INVALID_URL'
AD_TASK_REMOTE_DONE = 300
AD_TASK_REMOTE_FAILED = 600
AD_TASK_REMOTE_CANCELLED = 'INV-S1'
AD_TASK_REMOTE_EXPIRED = INV-S2
AD_PREP_DISCOVERED = INV-D1
AD_PREP_DOWNLOADING = INV-D2
AD_PREP_READY_LOCAL = INV-C1
AD_PREP_READY_CONFIRM_PENDING = INV-O1
AD_PREP_READY_CONFIRMED = migration
AD_PREP_FAILED = interrupted-state repair
AD_PREP_CANCELLED = temp cleanup
AD_PREP_EXPIRED = monitor rescan
AD_OUTBOX_NOT_QUEUED = activation heal
AD_OUTBOX_QUEUED = autostart
AD_OUTBOX_SENDING = PARTIAL
AD_OUTBOX_SENT = INTERRUPTED_RESTART
AD_OUTBOX_FAILED_RETRYABLE = unknown_func
AD_CONFIRM_FAIL_HTTP_UNKNOWN = unknown_func
Exception
('get_conn',)
('get_conn',)
('get_conn',)
0
'MISSING_DOWNLOAD_LINK'
200
300
'state reconciliation'
False
False
False
'readiness recompute'
'INVALID_SIZE'
False
200
False
False
False
'readiness recompute'
'state reconciliation'
False
threading.STARTUP_PHASES
threading.STARTUP_PHASES
threading.STARTUP_PHASES
'OK'
'SYSTEM'
'PLAYER'
'OFFLINE'
0
200
900
0
200
'REMOTE_SEMANTIC'
0
200
'INVALID_CHECKSUM'
0
200
'FAILED_TERMINAL'
'SENT'
0
200
'LOADING_BINDING'
'LOADING_BINDING'
'STRONG'
'UNKNOWN_ERROR'
False
'INVALID_CHECKSUM'
0
'INVALID_SIZE'
'TEMPFILE_ERROR'
False
'NETWORK_ERROR'
False
'INVALID_URL'
0
'MISSING_DOWNLOAD_LINK'
'SKIPPED_ALREADY_VALID'
'CANCELLED'
False
'VALIDATING'
False
False
'DOWNLOADING'
('get_conn',)
'BINDING_CREATED'
'SKIPPED'
False
False
('get_conn',)
'RESET_TRANSIENT_PLAYER_STATE'
False
('get_conn',)
'STOP_BINDING'
True
False
True
'START_BINDING'
('get_conn',)
'INVALID_CHECKSUM'
0
'RECOMPUTE_READINESS'
'PLAYER_REEVALUATED'
True
'PLAYER_STATE_CHANGED'
('CONFIG_PATH', 'DATA_ROOT', 'DB_PATH', 'now_iso')
threading.STARTUP_PHASES
threading.STARTUP_PHASES
threading.STARTUP_PHASES
'BLOCKED_NO_RENDERABLE_ITEM'
'BLOCKED_BINDING_DISABLED'
0
'BLOCKED_NO_BINDING'
'PLAYER_RESTART_REQUESTED'
'PLAYER_START_REQUESTED'
0
'BINDING_UPDATED'
'CRASHED'
'STOPPING'
('get_conn',)
('get_conn',)
('get_conn',)
'INVALID_CHECKSUM'
0
20
'NO_LATEST_SNAPSHOT'
'ACTIVATED'
True
'ACTIVATED'
True
'ACTIVATED'
False
'BLOCKED_WAITING_FOR_READY'
PLAYER_STATE_FRESHNESS_SECONDS
False
PLAYER_EVENT_STATE_CHANGED
('now_dt',)
('CONFIG_PATH', 'DATA_ROOT', 'DB_PATH', 'now_iso')
'INVALID_CHECKSUM'
0
'INVALID_SIZE'
'ERROR'
'INFO'
'INVALID_CHECKSUM'
0
'INVALID_SIZE'
'PRESENT_UNCHECKED'
('get_conn',)
('get_conn',)
('get_conn',)
('get_conn',)
('Any', 'Dict', 'List', 'Optional', 'Tuple')
('datetime', 'timedelta', 'timezone')
True
False
True
0
0
('proof_type', 'status', 'correlation_id', 'message', 'metadata', 'proof_at_utc')
TV_PROOF_STATUS_OK
'ITEM_ACTIVE'
('heartbeat_at_utc', 'source', 'status', 'metadata')
('error_code', 'message', 'correlation_id', 'metadata', 'occurred_at_utc')
('severity', 'message', 'metadata')
'INFO'
('include_query_checks',)
False
('severity', 'details')
'WARNING'
('now_dt', 'dry_run', 'include_query_checks')
True
False
('limit',)
200
('now_dt',)
('screen_id', 'binding_id', 'correlation_id', 'metadata')
0
('now_dt',)
threading.STARTUP_PHASES
threading.STARTUP_PHASES
30
30
30
30
30