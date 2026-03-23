# app/core/app_const.py
"""
Centralized backend API configuration for MonClub.

*** THIS IS THE SINGLE SOURCE OF TRUTH FOR ALL BACKEND URLS ***

To point the application at a different server, edit only MONCLUB_BASE_URL.
Every endpoint constant is derived from it automatically — nothing else
needs to be touched.

Backend URLs are NOT configurable at runtime and NOT editable from the UI.
"""

from __future__ import annotations

# ── Backend base URL ──────────────────────────────────────────────────────────
# Edit this one constant to redirect all API calls to a different server.
MONCLUB_BASE_URL: str = "https://monclubwigo.tn"

_API_V1: str = f"{MONCLUB_BASE_URL}/api/v1"

# ── Access / shared endpoints ─────────────────────────────────────────────────
API_LOGIN_URL: str = f"{_API_V1}/public/access/v1/gym/login"
API_SYNC_URL: str = f"{_API_V1}/manager/gym/access/v1/users/get_gym_users"
API_CREATE_USER_FINGERPRINT_URL: str = f"{_API_V1}/manager/userFingerprint/create"
API_ACCESS_CREATE_MEMBERSHIP_URL: str = f"{_API_V1}/manager/gym/access/v1/activeMembership/create"
API_ACCESS_CREATE_ACCOUNT_MEMBERSHIP_URL: str = f"{_API_V1}/manager/gym/access/v1/account-and-activeMembership/create"
API_LATEST_RELEASE_URL: str = f"{_API_V1}/manager/access/getLatestAccessSoftwareRelease"
API_OPTIONAL_CONTENT_SYNC_URL: str = f"{_API_V1}/manager/gym/access/v1/content/sync"

# ── TV endpoints ──────────────────────────────────────────────────────────────
# Template placeholders use {screenId} / {snapshotId} / {taskId} —
# they are substituted at call-time inside MonClubApi._format_url_template().
API_TV_SNAPSHOT_LATEST_URL: str = f"{_API_V1}/manager/tv/screens/{{screenId}}/snapshots/latest"
API_TV_SNAPSHOT_MANIFEST_URL: str = f"{_API_V1}/manager/tv/snapshots/{{snapshotId}}/asset-manifest"
API_TV_AD_TASKS_FETCH_URL: str = f"{_API_V1}/manager/gym/access/v1/tv/ad-tasks"
API_TV_AD_TASK_CONFIRM_READY_URL: str = f"{_API_V1}/manager/gym/access/v1/tv/ad-tasks/{{taskId}}/confirm-ready"
API_TV_AD_TASK_SUBMIT_PROOF_URL: str = f"{_API_V1}/manager/gym/access/v1/tv/ad-tasks/{{taskId}}/submit-proof"
