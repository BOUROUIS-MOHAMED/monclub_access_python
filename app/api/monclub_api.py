# monclub_access_python/app/api/monclub_api.py
from __future__ import annotations

import json
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
    sync_access_history_url: str = ""
    tv_screens_url: str = ""
    tv_screen_by_id_url: str = ""
    tv_screen_content_plan_url: str = ""
    tv_screen_snapshots_url: str = ""
    tv_snapshot_latest_url: str = ""
    tv_snapshot_by_id_url: str = ""
    tv_snapshot_manifest_url: str = ""
    tv_ad_tasks_fetch_url: str = ""
    tv_ad_task_confirm_ready_url: str = ""
    tv_ad_task_submit_proof_url: str = ""
    optional_content_sync_url: str = ""

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


def _load_error_payload(txt: str) -> Dict[str, Any]:
    try:
        data = json.loads(txt or "{}")
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _extract_trace_info(txt: str) -> str:
    """
    Best-effort extraction of traceId/timestamp/path from the backend JSON error.
    Doesn't throw.
    """
    j = _load_error_payload(txt)
    details = j.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    trace_id = details.get("traceId") or j.get("traceId")
    ts = details.get("timestamp") or j.get("timestamp")
    path = details.get("path") or j.get("path")
    if trace_id or ts or path:
        return f" | traceId={trace_id} | ts={ts} | path={path}"
    return ""


def _build_login_error_message(status_code: int, txt: str) -> str:
    payload = _load_error_payload(txt)
    error_msg = str(
        payload.get("errorMsg")
        or payload.get("message")
        or payload.get("error")
        or ""
    ).strip()
    code = str(payload.get("code") or "").strip().upper()
    normalized = error_msg.lower()

    if status_code == 401 or code == "UNAUTHORIZED":
        if "invalid email or password" in normalized:
            return "Email ou mot de passe incorrect."
        if error_msg:
            return error_msg
        return "Connexion refusee. Verifiez vos identifiants puis reessayez."

    if error_msg:
        return f"Connexion impossible: {error_msg}"

    if status_code >= 500:
        return "Le serveur MonClub est indisponible pour le moment. Reessayez dans un instant."

    return f"Connexion impossible (HTTP {status_code})."


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
            self.logger.warning("API login failed: HTTP %s -> %s%s", r.status_code, txt[:600], extra)
            raise MonClubApiHttpError(
                _build_login_error_message(r.status_code, txt),
                status_code=r.status_code,
                body=txt,
            )

        token = (r.text or "").strip()
        if not token:
            raise MonClubApiError("Login response is empty (no token returned).")

        return token

    def get_sync_data(self, *, token: str, version_tokens: dict | None = None, timeout: int = 20) -> Dict[str, Any]:
        url = (self.endpoints.sync_url or "").strip()
        if not url:
            raise MonClubApiError("Sync URL is empty (check Configuration).")

        # IMPORTANT: backend expects numeric timestamp-like value
        params = {"lastCheckTimeStamp": _now_epoch_ms()}
        if version_tokens:
            params.update(version_tokens)

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
            self.logger.info(extra)
            self.logger.debug("getSyncData response body: %s", txt[:500])
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

    def validate_statistics_password(self, *, token: str, password: str, timeout: int = 10) -> bool:
        """Validate the gym statistics/admin-agent password against the backend.

        Returns True if the password is correct, False if wrong (401).
        Raises MonClubApiHttpError for unexpected HTTP errors.
        """
        from urllib.parse import urlparse
        parsed = urlparse(self.endpoints.login_url)
        # Extract scheme + host + first two path segments (e.g. /api/v1)
        path_parts = [p for p in parsed.path.split('/') if p]
        prefix = ('/' + '/'.join(path_parts[:2])) if len(path_parts) >= 2 else ''
        base = f"{parsed.scheme}://{parsed.netloc}{prefix}"
        url = f"{base}/connected/account/openStatisticsInfo"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            r = self._session.post(url, json={"password": password}, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"validate_statistics_password request failed: {e}") from e

        if r.status_code == 200:
            return True
        if r.status_code == 401:
            return False
        txt = (r.text or "").strip()
        raise MonClubApiHttpError(
            f"validate_statistics_password: HTTP {r.status_code}",
            status_code=r.status_code,
            body=txt,
        )

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



    def get_latest_software_release(
        self,
        *,
        token: str,
        platform: str = "WINDOWS",
        channel: str = "stable",
        release_id: Optional[str] = None,
        current_version: Optional[str] = None,
        target: Optional[str] = None,
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
        if current_version:
            params["currentVersion"] = current_version
        if target:
            params["target"] = target

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        self.logger.info("API getLatestSoftwareRelease -> %s params=%s", url, params)
        try:
            r = self._session.get(url, params=params, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"getLatestSoftwareRelease request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiError(f"getLatestSoftwareRelease failed: HTTP {r.status_code} -> {txt[:400]}{extra}")

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(f"getLatestSoftwareRelease returned non-JSON: {e} -> {(r.text or '')[:200]}") from e

        if not isinstance(data, dict):
            raise MonClubApiError("getLatestSoftwareRelease JSON is not an object/dict.")

        return data

    def get_latest_access_software_release(
        self,
        *,
        token: str,
        platform: str = "WINDOWS",
        channel: str = "stable",
        release_id: Optional[str] = None,
        current_version: Optional[str] = None,
        target: Optional[str] = None,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        return self.get_latest_software_release(
            token=token,
            platform=platform,
            channel=channel,
            release_id=release_id,
            current_version=current_version,
            target=target,
            timeout=timeout,
        )


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

    def sync_access_history(self, *, token: str, payload: Any, timeout: int = 30) -> Dict[str, Any]:
        url = (self.endpoints.sync_access_history_url or "").strip()
        if not url:
            raise MonClubApiError("Access history sync URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self.logger.info("API syncAccessHistory -> %s", url)
        try:
            r = self._session.post(url, json=(payload if payload is not None else []), headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"syncAccessHistory request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiHttpError(
                f"syncAccessHistory failed: HTTP {r.status_code} -> {txt[:500]}{extra}",
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

    def _get_json_dict(
        self,
        *,
        url: str,
        token: str,
        operation_name: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        final_url = (url or "").strip()
        if not final_url:
            raise MonClubApiError(f"{operation_name} URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        safe_params = dict(params or {})
        self.logger.info("API %s -> %s params=%s", operation_name, final_url, safe_params)
        try:
            r = self._session.get(final_url, params=safe_params or None, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"{operation_name} request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiHttpError(
                f"{operation_name} failed: HTTP {r.status_code} -> {txt[:400]}{extra}",
                status_code=r.status_code,
                body=txt,
            )

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(f"{operation_name} returned non-JSON: {e} -> {(r.text or '')[:200]}") from e

        if not isinstance(data, dict):
            raise MonClubApiError(f"{operation_name} JSON is not an object/dict.")
        return data

    def get_tv_screens(
        self,
        *,
        token: str,
        q: Optional[str] = None,
        gym_id: Optional[int] = None,
        enabled: Optional[bool] = None,
        orientation: Optional[str] = None,
        has_layout: Optional[bool] = None,
        include_archived: Optional[bool] = None,
        page: int = 0,
        size: int = 50,
        sort_by: str = "name",
        sort_dir: str = "asc",
        timeout: int = 20,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "page": max(0, int(page or 0)),
            "size": max(1, min(int(size or 50), 200)),
            "sortBy": str(sort_by or "name").strip() or "name",
            "sortDir": str(sort_dir or "asc").strip() or "asc",
        }
        if q and str(q).strip():
            params["q"] = str(q).strip()
        if gym_id is not None and int(gym_id) > 0:
            params["gymId"] = int(gym_id)
        if enabled is not None:
            params["enabled"] = bool(enabled)
        if orientation and str(orientation).strip():
            params["orientation"] = str(orientation).strip()
        if has_layout is not None:
            params["hasLayout"] = bool(has_layout)
        if include_archived is not None:
            params["includeArchived"] = bool(include_archived)

        return self._get_json_dict(
            url=self.endpoints.tv_screens_url,
            token=token,
            operation_name="getTvScreens",
            params=params,
            timeout=timeout,
        )

    def get_tv_screen_by_id(
        self,
        *,
        token: str,
        screen_id: int,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = self._format_url_template(
            self.endpoints.tv_screen_by_id_url,
            screenId=screen_id,
            screen_id=screen_id,
        )
        return self._get_json_dict(
            url=url,
            token=token,
            operation_name="getTvScreenById",
            timeout=timeout,
        )

    def get_tv_screen_content_plan(
        self,
        *,
        token: str,
        screen_id: int,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = self._format_url_template(
            self.endpoints.tv_screen_content_plan_url,
            screenId=screen_id,
            screen_id=screen_id,
        )
        return self._get_json_dict(
            url=url,
            token=token,
            operation_name="getTvScreenContentPlan",
            timeout=timeout,
        )

    def get_tv_screen_snapshots(
        self,
        *,
        token: str,
        screen_id: int,
        page: int = 0,
        size: int = 20,
        sort_by: str = "version",
        sort_dir: str = "desc",
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = self._format_url_template(
            self.endpoints.tv_screen_snapshots_url,
            screenId=screen_id,
            screen_id=screen_id,
        )
        return self._get_json_dict(
            url=url,
            token=token,
            operation_name="getTvScreenSnapshots",
            params={
                "page": max(0, int(page or 0)),
                "size": max(1, min(int(size or 20), 100)),
                "sortBy": str(sort_by or "version").strip() or "version",
                "sortDir": str(sort_dir or "desc").strip() or "desc",
            },
            timeout=timeout,
        )

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
        params: Dict[str, Any] = {}
        if resolve_at and str(resolve_at).strip():
            params["resolveAt"] = str(resolve_at).strip()
        return self._get_json_dict(
            url=url,
            token=token,
            operation_name="getTvLatestSnapshot",
            params=params,
            timeout=timeout,
        )

    def get_tv_snapshot_by_id(
        self,
        *,
        token: str,
        snapshot_id: str,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = self._format_url_template(
            self.endpoints.tv_snapshot_by_id_url,
            snapshotId=snapshot_id,
            snapshot_id=snapshot_id,
        )
        return self._get_json_dict(
            url=url,
            token=token,
            operation_name="getTvSnapshotById",
            timeout=timeout,
        )

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
        return self._get_json_dict(
            url=url,
            token=token,
            operation_name="getTvSnapshotManifest",
            timeout=timeout,
        )


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

    def get_optional_content_sync(
        self,
        *,
        token: str,
        events_last_version_at: Optional[str] = None,
        products_last_version_at: Optional[str] = None,
        deals_last_version_at: Optional[str] = None,
        timeout: int = 25,
    ) -> Dict[str, Any]:
        url = (self.endpoints.optional_content_sync_url or "").strip()
        if not url:
            raise MonClubApiError("Optional content sync URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body: Dict[str, Any] = {}
        if events_last_version_at is not None:
            body["eventsLastVersionAt"] = events_last_version_at
        if products_last_version_at is not None:
            body["productsLastVersionAt"] = products_last_version_at
        if deals_last_version_at is not None:
            body["dealsLastVersionAt"] = deals_last_version_at

        self.logger.info("API getOptionalContentSync -> %s", url)
        try:
            r = self._session.post(url, json=body, headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"getOptionalContentSync request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiError(f"getOptionalContentSync failed: HTTP {r.status_code} -> {txt[:400]}{extra}")

        try:
            data = r.json()
        except Exception as e:
            raise MonClubApiError(f"getOptionalContentSync returned non-JSON: {e} -> {(r.text or '')[:200]}") from e

        if not isinstance(data, dict):
            raise MonClubApiError("getOptionalContentSync JSON is not an object/dict.")
        return data

    def submit_tv_ad_task_proof(
        self,
        *,
        token: str,
        task_id: int,
        payload: Dict[str, Any],
        timeout: int = 20,
    ) -> Dict[str, Any]:
        url = self._format_url_template(
            self.endpoints.tv_ad_task_submit_proof_url,
            taskId=task_id,
            task_id=task_id,
        )
        if not url:
            raise MonClubApiError("TV ad task submit-proof URL is empty (check Configuration).")

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self.logger.info("API submitTvAdTaskProof -> %s", url)
        try:
            r = self._session.post(url, json=(payload or {}), headers=headers, timeout=timeout)
        except Exception as e:
            raise MonClubApiError(f"submitTvAdTaskProof request failed: {e}") from e

        if r.status_code < 200 or r.status_code >= 300:
            txt = (r.text or "").strip()
            extra = _extract_trace_info(txt)
            raise MonClubApiHttpError(
                f"submitTvAdTaskProof failed: HTTP {r.status_code} -> {txt[:500]}{extra}",
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

