"""Access-owned facade over the live Access SQLite store."""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict

import app.core.db as _legacy_access_db
from access.storage import current_access_runtime_db_path
from shared.desktop_paths import get_desktop_path_layout
from shared.storage_migration import (
    ACCESS_OWNED_TABLES,
    migrate_component_tables,
    read_component_storage_status,
)

_log = logging.getLogger(__name__)
_access_store_ready = False
_access_store_lock = threading.Lock()


def init_db() -> None:
    global _access_store_ready
    if _access_store_ready:
        return
    with _access_store_lock:
        if _access_store_ready:
            return
        _legacy_access_db.init_db()
        layout = get_desktop_path_layout()
        migrate_component_tables(
            component="access",
            live_db_path=current_access_runtime_db_path(),
            legacy_source_db_path=layout.legacy_combined_db_path,
            owned_tables=ACCESS_OWNED_TABLES,
            logger=_log,
        )
        # L-003: Second init_db() ensures any new schema columns are added after
        # migration (migration may import old schema from legacy DB). Uses IF NOT EXISTS
        # and ALTER ADD COLUMN so it's idempotent and safe.
        _legacy_access_db.init_db()
        _access_store_ready = True


def get_access_storage_status() -> Dict[str, Any]:
    layout = get_desktop_path_layout()
    return read_component_storage_status(
        component="access",
        live_db_path=current_access_runtime_db_path(),
        legacy_source_db_path=layout.legacy_combined_db_path,
        owned_tables=ACCESS_OWNED_TABLES,
    )


_ensure_column = _legacy_access_db._ensure_column
get_optional_sync_state = _legacy_access_db.get_optional_sync_state
save_optional_sync_state = _legacy_access_db.save_optional_sync_state
delete_passed_optional_events = _legacy_access_db.delete_passed_optional_events
replace_optional_events = _legacy_access_db.replace_optional_events
replace_optional_products = _legacy_access_db.replace_optional_products
replace_optional_deals = _legacy_access_db.replace_optional_deals
list_optional_upcoming_events = _legacy_access_db.list_optional_upcoming_events
list_optional_products = _legacy_access_db.list_optional_products
list_optional_deals = _legacy_access_db.list_optional_deals
archive_offline_creation = _legacy_access_db.archive_offline_creation
cancel_offline_creation = _legacy_access_db.cancel_offline_creation
claim_offline_creation_for_processing = _legacy_access_db.claim_offline_creation_for_processing
classify_failure = _legacy_access_db.classify_failure
clear_auth_token = _legacy_access_db.clear_auth_token
count_offline_creations = _legacy_access_db.count_offline_creations
create_device_door_preset = _legacy_access_db.create_device_door_preset
delete_device_door_preset = _legacy_access_db.delete_device_door_preset
delete_fingerprint = _legacy_access_db.delete_fingerprint
duplicate_offline_creation = _legacy_access_db.duplicate_offline_creation
get_conn = _legacy_access_db.get_conn
get_offline_creation = _legacy_access_db.get_offline_creation
get_recent_access_history = _legacy_access_db.get_recent_access_history
get_sync_device = _legacy_access_db.get_sync_device
get_sync_device_payload = _legacy_access_db.get_sync_device_payload
insert_access_history_batch = _legacy_access_db.insert_access_history_batch
insert_offline_creation = _legacy_access_db.insert_offline_creation
list_pending_access_history_for_sync = _legacy_access_db.list_pending_access_history_for_sync
list_device_door_presets = _legacy_access_db.list_device_door_presets
list_fingerprints = _legacy_access_db.list_fingerprints
list_offline_creations = _legacy_access_db.list_offline_creations
list_offline_creations_due_for_retry = _legacy_access_db.list_offline_creations_due_for_retry
list_sync_devices_payload = _legacy_access_db.list_sync_devices_payload
list_sync_gym_access_credentials = _legacy_access_db.list_sync_gym_access_credentials
load_device_attendance_state = _legacy_access_db.load_device_attendance_state
load_auth_token = _legacy_access_db.load_auth_token
load_sync_cache = _legacy_access_db.load_sync_cache
mark_access_history_sync_failure = _legacy_access_db.mark_access_history_sync_failure
mark_access_history_synced = _legacy_access_db.mark_access_history_synced
mark_offline_creation_failure = _legacy_access_db.mark_offline_creation_failure
mark_offline_creation_success = _legacy_access_db.mark_offline_creation_success
prune_access_history = _legacy_access_db.prune_access_history
save_auth_token = _legacy_access_db.save_auth_token
save_device_attendance_state = _legacy_access_db.save_device_attendance_state
save_sync_cache = _legacy_access_db.save_sync_cache
set_offline_creation_try_to_create = _legacy_access_db.set_offline_creation_try_to_create
update_offline_creation_payload = _legacy_access_db.update_offline_creation_payload


__all__ = [
    "_ensure_column",
    "get_optional_sync_state",
    "save_optional_sync_state",
    "delete_passed_optional_events",
    "replace_optional_events",
    "replace_optional_products",
    "replace_optional_deals",
    "list_optional_upcoming_events",
    "list_optional_products",
    "list_optional_deals",
    "archive_offline_creation",
    "cancel_offline_creation",
    "claim_offline_creation_for_processing",
    "classify_failure",
    "clear_auth_token",
    "count_offline_creations",
    "create_device_door_preset",
    "current_access_runtime_db_path",
    "delete_device_door_preset",
    "delete_fingerprint",
    "duplicate_offline_creation",
    "get_access_storage_status",
    "get_conn",
    "get_offline_creation",
    "get_recent_access_history",
    "get_sync_device",
    "get_sync_device_payload",
    "init_db",
    "insert_access_history_batch",
    "insert_offline_creation",
    "list_device_door_presets",
    "list_fingerprints",
    "list_offline_creations",
    "list_offline_creations_due_for_retry",
    "list_pending_access_history_for_sync",
    "list_sync_devices_payload",
    "list_sync_gym_access_credentials",
    "load_device_attendance_state",
    "load_auth_token",
    "load_sync_cache",
    "mark_access_history_sync_failure",
    "mark_access_history_synced",
    "mark_offline_creation_failure",
    "mark_offline_creation_success",
    "prune_access_history",
    "save_auth_token",
    "save_device_attendance_state",
    "save_sync_cache",
    "set_offline_creation_try_to_create",
    "update_offline_creation_payload",
]
