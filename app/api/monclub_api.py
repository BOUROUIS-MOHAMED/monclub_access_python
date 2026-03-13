# monclub_access_python/app/api/monclub_api.py
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests


@dataclass
class ApiEndpoints:
    login_url: str
    sync_url: str
    create_user_fingerprint_url: str
    latest_release_url: str  # NEW
    access_create_membership_url: str = ""
    access_create_account_membership_url: str = ""
    tv_snapshot_latest_url: str = ""
    tv_snapshot_manifest_url: str = ""
    tv_ad_tasks_fetch_url: str = ""
    tv_ad_task_confirm_ready_url: str = ""

class MonClubApiError(RuntimeError):
    pass

class MonClubApiHttpError(MonClubApiError):
    def __init__(self, message: str, *, status_code: int, body: str = "") -> None:
        super().__init__(message)
        self.status_code = int(status_code)
        self.body = str(body or "")



def _now_epoch_ms() -> str:
    # backend-friendly numeric timestamp (string)
    return str(int(time.time() * 1000))


def _extract_trace_info(txt: str) -> str:
    """
    Best-effort extraction of traceId/timestamp/path from the backend JSON error.
    Doesn't throw.
    """
    try:
        import json

        j = json.loads(txt or "{}")
        details = j.get("details") or {}
        trace_id = details.get("traceId") or j.get("traceId")
        ts = details.get("timestamp") or j.get("timestamp")
        path = details.get("path") or j.get("path")
        if trace_id or ts or path:
            return f" | traceId={trace_id} | ts={ts} | path={path}"
    except Exception:
        pass
    return ""


class MonClubApi:
    def __init__(self, endpoints: ApiEndpoints, logger):
        self.endpoints = endpoints
        self.logger = logger
        self._session = requests.Session()

    def login(self, *, email: str, password: str, timeout: int = 15) -> str:
        url = (self.endpoints.login_url or "").strip()
        if not url:
            raise MonClubApiError("Login URL is empty (check Configuration).")

        payload = {"email": email, "password": password}

        self.logger.info("API login -> %s", url)
        try:
            r = self._session.post(url, json=payload, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"Login request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiError(f"Login failed: HTTP {r.status_code} -> {txt[:300]}{extra}")

        token = (r.text or "").strip()
        if not token:
            raise MonClubApiError("Login response is empty (no token returned).")

        return token

    def get_sync_data(self, *, token: str, timeout: int = 20) -> Dict[str, Any]:
        url = (self.endpoints.sync_url or "").strip()
        if not url:
            raise MonClubApiError("Sync URL is empty (check Configuration).")

        # IMPORTANT: backend expects numeric timestamp-like value
        params = {"lastCheckTimeStamp": _now_epoch_ms()}

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        self.logger.info("API getSyncData -> %s params=%s", url, params)
        try:
            r = self._session.get(url, params=params, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"getSyncData request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiError(f"getSyncData failed: HTTP {r.status_code} -> {txt[:400]}{extra}")

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(
                f"getSyncData returned non-JSON response: {e} -> {(r.text or '')[:300]}"
            ) from e

        if not isinstance(data, dict):
            raise MonClubApiError("getSyncData JSON is not an object/dict.")

        return data

    def create_user_fingerprint(self, *, token: str, payload: Dict[str, Any], timeout: int = 25) -> Dict[str, Any]:
        url = (self.endpoints.create_user_fingerprint_url or "").strip()
        if not url:
            raise MonClubApiError("Create fingerprint URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        self.logger.info("API createUserFingerprint -> %s", url)
        try:
            r = self._session.post(url, json=payload, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"createUserFingerprint request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiError(f"createUserFingerprint failed: HTTP {r.status_code} -> {txt[:500]}{extra}")

        try:
            data = r.json()
        except Exception:
            data = {"raw": (r.text or "").strip()}

        if not isinstance(data, dict):
            return {"raw": data}
        return data



    def get_latest_access_software_release(
        self,
        *,
        token: str,
        platform: str = "WINDOWS",
        channel: str = "stable",
        release_id: Optional[str] = None,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = (self.endpoints.latest_release_url or "").strip()
        if not url:
            raise MonClubApiError("Latest release URL is empty (check Configuration).")

        params: Dict[str, Any] = {}
        if platform:
            params["platform"] = platform
        if channel:
            params["channel"] = channel
        if release_id:
            params["releaseId"] = release_id

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        self.logger.info("API getLatestAccessSoftwareRelease -> %s params=%s", url, params)
        try:
            r = self._session.get(url, params=params, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"getLatestAccessSoftwareRelease request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiError(f"getLatestAccessSoftwareRelease failed: HTTP {r.status_code} -> {txt[:400]}{extra}")

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(f"getLatestAccessSoftwareRelease returned non-JSON: {e} -> {(r.text or '')[:200]}") from e

        if not isinstance(data, dict):
            raise MonClubApiError("getLatestAccessSoftwareRelease JSON is not an object/dict.")

        return data


    def _post_access_creation(self, *, url: str, token: str, payload: Dict[str, Any], timeout: int = 25) -> Dict[str, Any]:
        u = (url or "").strip()
        if not u:
            raise MonClubApiError("Access creation URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self.logger.info("API access creation -> %s", u)
        try:
            r = self._session.post(u, json=(payload or {}), headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"Access creation request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiHttpError(
                f"Access creation failed: HTTP {r.status_code} -> {txt[:500]}{extra}",
                status_code=r.status_code,
                body=txt,
            )

        try:
            data = r.json()
        except Exception:
            raw = (r.text or "").strip()
            if not raw:
                return {"ok": True}
            return {"ok": True, "raw": raw}

        if isinstance(data, dict):
            return data
        return {"ok": True, "raw": data}

    def create_access_membership(self, *, token: str, payload: Dict[str, Any], timeout: int = 25) -> Dict[str, Any]:
        return self._post_access_creation(
            url=self.endpoints.access_create_membership_url,
            token=token,
            payload=payload,
            timeout=timeout,
        )

    def create_access_account_and_membership(self, *, token: str, payload: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        return self._post_access_creation(
            url=self.endpoints.access_create_account_membership_url,
            token=token,
            payload=payload,
            timeout=timeout,
        )


    def _format_url_template(self, url: str, **kwargs: Any) -> str:
        u = (url or "").strip()
        if not u:
            return ""
        for key, value in kwargs.items():
            if value is None:
                continue
            s = quote(str(value), safe="")
            u = u.replace("{" + str(key) + "}", s)
        return u

    def get_tv_latest_snapshot(
        self,
        *,
        token: str,
        screen_id: int,
        resolve_at: Optional[str] = None,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = self._format_url_template(
            self.endpoints.tv_snapshot_latest_url,
            screenId=screen_id,
            screen_id=screen_id,
        )
        if not url:
            raise MonClubApiError("TV latest snapshot URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        params: Dict[str, Any] = {}
        if resolve_at and str(resolve_at).strip():
            params["resolveAt"] = str(resolve_at).strip()

        self.logger.info("API getTvLatestSnapshot -> %s params=%s", url, params)
        try:
            r = self._session.get(url, params=params, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"getTvLatestSnapshot request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiError(f"getTvLatestSnapshot failed: HTTP {r.status_code} -> {txt[:400]}{extra}")

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(f"getTvLatestSnapshot returned non-JSON: {e} -> {(r.text or '')[:200]}") from e

        if not isinstance(data, dict):
            raise MonClubApiError("getTvLatestSnapshot JSON is not an object/dict.")
        return data

    def get_tv_snapshot_manifest(
        self,
        *,
        token: str,
        snapshot_id: str,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = self._format_url_template(
            self.endpoints.tv_snapshot_manifest_url,
            snapshotId=snapshot_id,
            snapshot_id=snapshot_id,
        )
        if not url:
            raise MonClubApiError("TV snapshot manifest URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        self.logger.info("API getTvSnapshotManifest -> %s", url)
        try:
            r = self._session.get(url, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"getTvSnapshotManifest request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiError(f"getTvSnapshotManifest failed: HTTP {r.status_code} -> {txt[:400]}{extra}")

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(f"getTvSnapshotManifest returned non-JSON: {e} -> {(r.text or '')[:200]}") from e

        if not isinstance(data, dict):
            raise MonClubApiError("getTvSnapshotManifest JSON is not an object/dict.")
        return data


    def get_tv_ad_tasks(
        self,
        *,
        token: str,
        gym_ids: list[int],
        updated_after: Optional[str] = None,
        limit: int = 500,
        timeout: int = 25,
    ) -> Dict[str, Any]:
        url = (self.endpoints.tv_ad_tasks_fetch_url or "").strip()
        if not url:
            raise MonClubApiError("TV ad tasks fetch URL is empty (check Configuration).")

        dedup_ids = []
        seen = set()
        for gid in (gym_ids or []):
            try:
                g = int(gid)
            except Exception:
                continue
            if g <= 0 or g in seen:
                continue
            seen.add(g)
            dedup_ids.append(g)

        if not dedup_ids:
            raise MonClubApiError("At least one valid gym id is required to fetch TV ad tasks.")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        params: Dict[str, Any] = {
            "gymIds": ",".join(str(x) for x in dedup_ids),
            "limit": max(1, min(int(limit or 500), 2000)),
        }
        if updated_after and str(updated_after).strip():
            params["updatedAfter"] = str(updated_after).strip()

        self.logger.info("API getTvAdTasks -> %s params=%s", url, params)
        try:
            r = self._session.get(url, params=params, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"getTvAdTasks request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiHttpError(
                f"getTvAdTasks failed: HTTP {r.status_code} -> {txt[:400]}{extra}",
                status_code=r.status_code,
                body=txt,
            )

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(f"getTvAdTasks returned non-JSON: {e} -> {(r.text or '')[:200]}") from e

        if not isinstance(data, dict):
            raise MonClubApiError("getTvAdTasks JSON is not an object/dict.")
        return data

    def confirm_tv_ad_task_ready(
        self,
        *,
        token: str,
        task_id: int,
        payload: Dict[str, Any],
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = self._format_url_template(
            self.endpoints.tv_ad_task_confirm_ready_url,
            taskId=task_id,
            task_id=task_id,
        )
        if not url:
            raise MonClubApiError("TV ad task confirm-ready URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self.logger.info("API confirmTvAdTaskReady -> %s", url)
        try:
            r = self._session.post(url, json=(payload or {}), headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"confirmTvAdTaskReady request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiHttpError(
                f"confirmTvAdTaskReady failed: HTTP {r.status_code} -> {txt[:500]}{extra}",
                status_code=r.status_code,
                body=txt,
            )

        try:
            data = r.json()
        except Exception:
            raw = (r.text or "").strip()
            if not raw:
                return {"ok": True}
            return {"ok": True, "raw": raw}

        if isinstance(data, dict):
            return data
        return {"ok": True, "raw": data}


