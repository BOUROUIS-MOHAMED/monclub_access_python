from __future__ import annotations

import base64
import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.core.utils import DB_PATH, ensure_dirs, now_iso


# -----------------------------
# SQLite connection helpers
# -----------------------------
def get_conn() -> sqlite3.Connection:
    ensure_dirs()
    # check_same_thread=False because we read/write from worker threads too
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------
# Optional DPAPI protection (Windows)
# -----------------------------
def _dpapi_encrypt(plain: str) -> str:
    """
    Best-effort: encrypt using Windows DPAPI (CryptProtectData).
    If it fails, store raw.
    """
    try:
        import ctypes
        from ctypes import wintypes

        crypt32 = ctypes.WinDLL("crypt32.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        def _bytes_to_blob(b: bytes) -> DATA_BLOB:
            buf = (ctypes.c_byte * len(b))(*b)
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

        def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
            cb = int(blob.cbData)
            if cb <= 0:
                return b""
            data = ctypes.string_at(blob.pbData, cb)
            kernel32.LocalFree(blob.pbData)
            return data

        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPCWSTR,
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptProtectData.restype = wintypes.BOOL

        plain_bytes = plain.encode("utf-8")
        in_blob = _bytes_to_blob(plain_bytes)
        out_blob = DATA_BLOB()

        ok = crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
        if not ok:
            return "raw:" + plain

        enc = _blob_to_bytes(out_blob)
        return "dpapi:" + base64.b64encode(enc).decode("ascii")

    except Exception:
        return "raw:" + plain


def _dpapi_decrypt(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith("raw:"):
        return stored[len("raw:") :]
    if not stored.startswith("dpapi:"):
        # legacy
        return stored

    try:
        import ctypes
        from ctypes import wintypes

        crypt32 = ctypes.WinDLL("crypt32.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        def _bytes_to_blob_alloc(b: bytes) -> DATA_BLOB:
            buf = (ctypes.c_byte * len(b))(*b)
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

        def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
            cb = int(blob.cbData)
            if cb <= 0:
                return b""
            data = ctypes.string_at(blob.pbData, cb)
            kernel32.LocalFree(blob.pbData)
            return data

        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(DATA_BLOB),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL

        enc = base64.b64decode(stored[len("dpapi:") :].encode("ascii"))
        in_blob = _bytes_to_blob_alloc(enc)
        out_blob = DATA_BLOB()

        ok = crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
        if not ok:
            return ""

        dec = _blob_to_bytes(out_blob)
        return dec.decode("utf-8", errors="replace")

    except Exception:
        return ""


# -----------------------------
# DB init
# -----------------------------
def init_db() -> None:
    with get_conn() as conn:
        # --- fingerprints (existing) ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                label TEXT,
                pin TEXT,
                card_no TEXT,
                finger_id INTEGER NOT NULL,
                template_version INTEGER NOT NULL,
                template_encoding TEXT NOT NULL,
                template_data TEXT NOT NULL,
                template_size INTEGER NOT NULL
            );
            """
        )

        # --- auth state ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_state (
                id INTEGER PRIMARY KEY CHECK (id=1),
                email TEXT,
                token_protected TEXT,
                last_login_at TEXT
            );
            """
        )

        # --- sync cache raw payload ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_cache (
                id INTEGER PRIMARY KEY CHECK (id=1),
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            """
        )

        # --- sync meta ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_meta (
                id INTEGER PRIMARY KEY CHECK (id=1),
                contract_status INTEGER NOT NULL,
                contract_end_date TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )

        # --- sync entities ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_users (
                user_id INTEGER,
                membership_id INTEGER,
                full_name TEXT,
                phone TEXT,
                email TEXT,
                valid_from TEXT,
                valid_to TEXT,
                first_card_id TEXT,
                second_card_id TEXT,
                image TEXT,

                -- legacy single fingerprint (kept for backward compatibility)
                fingerprint TEXT,

                -- NEW: full list of fingerprints as JSON string
                fingerprints_json TEXT,

                face_id TEXT,
                qr_code_payload TEXT
            );
            """
        )

        # migration for older DBs (if they miss fingerprints_json)
        try:
            conn.execute("ALTER TABLE sync_users ADD COLUMN fingerprints_json TEXT;")
        except Exception:
            pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_memberships (
                id INTEGER,
                title TEXT,
                description TEXT,
                price TEXT,
                duration_in_days INTEGER
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_devices (
                id INTEGER,
                name TEXT,
                description TEXT,
                allowed_memberships_json TEXT,
                active INTEGER,
                access_device INTEGER,
                ip_address TEXT,
                mac_address TEXT,
                password TEXT,
                port_number TEXT,
                model TEXT,
                installed_models_json TEXT,
                door_ids_json TEXT,
                zone TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_infrastructures (
                id INTEGER,
                name TEXT,
                gym_agent_json TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            """
        )

        conn.commit()


# -----------------------------
# Fingerprints (existing local SQLite enroll list)
# -----------------------------
@dataclass
class FingerprintRecord:
    id: int
    created_at: str
    label: str
    pin: str
    card_no: str
    finger_id: int
    template_version: int
    template_encoding: str
    template_data: str
    template_size: int


def insert_fingerprint(
    *,
    label: str,
    pin: str,
    card_no: str,
    finger_id: int,
    template_version: int,
    template_encoding: str,
    template_data: str,
    template_size: int,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO fingerprints
            (created_at, label, pin, card_no, finger_id, template_version, template_encoding, template_data, template_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now_iso(), label, pin, card_no, finger_id, template_version, template_encoding, template_data, template_size),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_fingerprints() -> List[FingerprintRecord]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM fingerprints ORDER BY id DESC").fetchall()
        return [FingerprintRecord(**dict(r)) for r in rows]


def get_fingerprint(fp_id: int) -> Optional[FingerprintRecord]:
    with get_conn() as conn:
        r = conn.execute("SELECT * FROM fingerprints WHERE id=?", (fp_id,)).fetchone()
        return FingerprintRecord(**dict(r)) if r else None


def delete_fingerprint(fp_id: int) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM fingerprints WHERE id=?", (fp_id,))
        conn.commit()


# -----------------------------
# Auth token state
# -----------------------------
@dataclass
class AuthTokenState:
    email: str
    token: str
    last_login_at: str


def save_auth_token(*, email: str, token: str, last_login_at: str | None = None) -> None:
    last_login_at = last_login_at or now_iso()
    protected = _dpapi_encrypt(token)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO auth_state (id, email, token_protected, last_login_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                email=excluded.email,
                token_protected=excluded.token_protected,
                last_login_at=excluded.last_login_at
            """,
            (email, protected, last_login_at),
        )
        conn.commit()


def load_auth_token() -> AuthTokenState | None:
    with get_conn() as conn:
        r = conn.execute("SELECT email, token_protected, last_login_at FROM auth_state WHERE id=1").fetchone()
        if not r:
            return None
        email = (r["email"] or "").strip()
        token = _dpapi_decrypt(r["token_protected"] or "")
        last_login_at = r["last_login_at"] or ""
        if not token:
            return None
        return AuthTokenState(email=email, token=token, last_login_at=last_login_at)


def clear_auth_token() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM auth_state WHERE id=1")
        conn.commit()


# -----------------------------
# Sync cache
# -----------------------------
@dataclass
class SyncCacheState:
    contract_status: bool
    contract_end_date: str
    users: List[Dict[str, Any]]
    membership: List[Dict[str, Any]]
    devices: List[Dict[str, Any]]
    infrastructures: List[Dict[str, Any]]
    updated_at: str


def save_sync_cache(data: Dict[str, Any]) -> None:
    """
    Saves:
      - raw payload_json (overwrite)
      - sync_meta (overwrite)
      - sync_* tables (overwrite)
    """
    payload_json = json.dumps(data or {}, ensure_ascii=False)
    updated_at = now_iso()

    contract_status = bool(data.get("contractStatus", False))
    contract_end_date = (data.get("contractEndDate") or "").strip()

    users = data.get("users") or []
    memberships = data.get("membership") or data.get("memberships") or []
    devices = data.get("devices") or []
    infrastructures = data.get("infrastructures") or data.get("infrastructure") or []

    with get_conn() as conn:
        cur = conn.cursor()

        # raw cache
        cur.execute(
            """
            INSERT INTO sync_cache (id, updated_at, payload_json)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                updated_at=excluded.updated_at,
                payload_json=excluded.payload_json
            """,
            (updated_at, payload_json),
        )

        # meta
        cur.execute(
            """
            INSERT INTO sync_meta (id, contract_status, contract_end_date, updated_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                contract_status=excluded.contract_status,
                contract_end_date=excluded.contract_end_date,
                updated_at=excluded.updated_at
            """,
            (1 if contract_status else 0, contract_end_date, updated_at),
        )

        # overwrite entity tables
        cur.execute("DELETE FROM sync_users")
        cur.execute("DELETE FROM sync_memberships")
        cur.execute("DELETE FROM sync_devices")
        cur.execute("DELETE FROM sync_infrastructures")

        # users
        for u in users:
            if not isinstance(u, dict):
                continue

            fps = u.get("fingerprints") or []
            if not isinstance(fps, list):
                fps = []

            cur.execute(
                """
                INSERT INTO sync_users (
                    user_id, membership_id, full_name, phone, email, valid_from, valid_to,
                    first_card_id, second_card_id, image,
                    fingerprint, fingerprints_json,
                    face_id, qr_code_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    u.get("userId"),
                    u.get("membershipId"),
                    u.get("fullName"),
                    u.get("phone"),
                    u.get("email"),
                    u.get("validFrom"),
                    u.get("validTo"),
                    u.get("firstCardId"),
                    u.get("secondCardId"),
                    u.get("image"),
                    # legacy
                    u.get("fingerprint"),
                    # NEW
                    json.dumps(fps, ensure_ascii=False),
                    u.get("faceId"),
                    u.get("qrCodePayload"),
                ),
            )

        # memberships
        for m in memberships:
            if not isinstance(m, dict):
                continue
            cur.execute(
                """
                INSERT INTO sync_memberships (id, title, description, price, duration_in_days)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    m.get("id"),
                    m.get("title"),
                    m.get("description"),
                    m.get("price"),
                    m.get("durationInDays"),
                ),
            )

        # devices
        for d in devices:
            if not isinstance(d, dict):
                continue
            cur.execute(
                """
                INSERT INTO sync_devices (
                    id, name, description, allowed_memberships_json,
                    active, access_device, ip_address, mac_address, password, port_number,
                    model, installed_models_json, door_ids_json, zone, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    d.get("id"),
                    d.get("name"),
                    d.get("description"),
                    json.dumps(d.get("allowedMemberships") or [], ensure_ascii=False),
                    1 if bool(d.get("active", True)) else 0,
                    1 if bool(d.get("accessDevice", True)) else 0,
                    d.get("ipAddress"),
                    d.get("macAddress"),
                    d.get("password"),
                    d.get("portNumber"),
                    d.get("model"),
                    json.dumps(d.get("installedModels") or [], ensure_ascii=False),
                    json.dumps(d.get("doorIds") or [], ensure_ascii=False),
                    d.get("zone"),
                    d.get("createdAt"),
                    d.get("updatedAt"),
                ),
            )

        # infrastructures
        for inf in infrastructures:
            if not isinstance(inf, dict):
                continue
            cur.execute(
                """
                INSERT INTO sync_infrastructures (id, name, gym_agent_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    inf.get("id"),
                    inf.get("name"),
                    json.dumps(inf.get("gymAgent") or {}, ensure_ascii=False),
                    inf.get("createdAt"),
                    inf.get("updatedAt"),
                ),
            )

        conn.commit()


def _coerce_user_row_to_payload(u: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fixes the 'missing user data' issue by normalizing snake_case DB rows
    into the same camelCase keys you expect in UI (and backend payload).
    """

    def g(*keys, default=None):
        for k in keys:
            if k in u:
                return u.get(k)
        return default

    # fingerprints list
    fps_raw = g("fingerprints", "fingerprints_json", default=None)
    fps: List[Dict[str, Any]] = []
    if isinstance(fps_raw, list):
        fps = fps_raw
    elif isinstance(fps_raw, str) and fps_raw.strip():
        try:
            x = json.loads(fps_raw)
            if isinstance(x, list):
                fps = x
        except Exception:
            fps = []
    else:
        fps = []

    return {
        "userId": g("userId", "userid", "user_id", "id"),
        "membershipId": g("membershipId", "membership_id", "activeMembershipId", "active_membership_id"),
        "fullName": g("fullName", "full_name", "name"),
        "phone": g("phone"),
        "email": g("email"),
        "validFrom": g("validFrom", "valid_from"),
        "validTo": g("validTo", "valid_to"),
        "firstCardId": g("firstCardId", "first_card_id"),
        "secondCardId": g("secondCardId", "second_card_id"),
        "image": g("image"),
        "fingerprints": fps,
        "faceId": g("faceId", "face_id"),
        "qrCodePayload": g("qrCodePayload", "qr_code_payload"),
    }


def _expand_device_json_fields(d: Dict[str, Any]) -> Dict[str, Any]:
    dd = dict(d or {})
    try:
        dd["allowed_memberships"] = json.loads(dd.get("allowed_memberships_json") or "[]")
    except Exception:
        dd["allowed_memberships"] = []
    try:
        dd["installed_models"] = json.loads(dd.get("installed_models_json") or "[]")
    except Exception:
        dd["installed_models"] = []
    try:
        dd["door_ids"] = json.loads(dd.get("door_ids_json") or "[]")
    except Exception:
        dd["door_ids"] = []
    return dd


def _coerce_device_row_to_payload(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize device row to camelCase style (API-like) for other pages.
    Keeps data as strings where the backend may send them as strings (portNumber often).
    """

    def g(*keys, default=None):
        for k in keys:
            if k in d:
                return d.get(k)
        return default

    allowed = g("allowedMemberships", "allowed_memberships", default=None)
    if allowed is None:
        allowed = []
    installed = g("installedModels", "installed_models", default=None)
    if installed is None:
        installed = []
    doors = g("doorIds", "door_ids", default=None)
    if doors is None:
        doors = []

    return {
        "id": g("id"),
        "name": g("name"),
        "description": g("description"),
        "allowedMemberships": allowed,
        "active": bool(int(g("active", default=1) or 1)) if isinstance(g("active", default=1), (int, str)) else bool(g("active", default=True)),
        "accessDevice": bool(int(g("access_device", "accessDevice", default=1) or 1))
        if isinstance(g("access_device", "accessDevice", default=1), (int, str))
        else bool(g("access_device", "accessDevice", default=True)),
        "ipAddress": g("ipAddress", "ip_address"),
        "macAddress": g("macAddress", "mac_address"),
        "password": g("password"),
        "portNumber": g("portNumber", "port_number"),
        "model": g("model"),
        "installedModels": installed,
        "doorIds": doors,
        "zone": g("zone"),
        "createdAt": g("createdAt", "created_at"),
        "updatedAt": g("updatedAt", "updated_at"),
    }


def load_sync_cache() -> SyncCacheState | None:
    with get_conn() as conn:
        meta = conn.execute("SELECT contract_status, contract_end_date, updated_at FROM sync_meta WHERE id=1").fetchone()
        if not meta:
            raw = conn.execute("SELECT updated_at, payload_json FROM sync_cache WHERE id=1").fetchone()
            if not raw:
                return None
            try:
                data = json.loads(raw["payload_json"] or "{}")
            except Exception:
                return None

            users = list(data.get("users") or [])
            # normalize users to include fingerprints list consistently
            norm_users: List[Dict[str, Any]] = []
            for u in users:
                if isinstance(u, dict):
                    norm_users.append(_coerce_user_row_to_payload(u))

            # devices: keep as-is (API style) when coming from raw payload
            devs = list(data.get("devices") or [])

            return SyncCacheState(
                contract_status=bool(data.get("contractStatus", False)),
                contract_end_date=(data.get("contractEndDate") or ""),
                users=norm_users,
                membership=list(data.get("membership") or data.get("memberships") or []),
                devices=devs,
                infrastructures=list(data.get("infrastructures") or data.get("infrastructure") or []),
                updated_at=(raw["updated_at"] or ""),
            )

        contract_status = bool(int(meta["contract_status"]))
        contract_end_date = meta["contract_end_date"] or ""
        updated_at = meta["updated_at"] or ""

        # load entities
        users_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_users").fetchall()]
        users = [_coerce_user_row_to_payload(u) for u in users_rows]

        membership = [dict(r) for r in conn.execute("SELECT * FROM sync_memberships").fetchall()]

        devices_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_devices").fetchall()]
        devices_rows = [_expand_device_json_fields(d) for d in devices_rows]

        infrastructures = [dict(r) for r in conn.execute("SELECT * FROM sync_infrastructures").fetchall()]

        # expand json fields for infrastructures
        for inf in infrastructures:
            try:
                inf["gym_agent"] = json.loads(inf.get("gym_agent_json") or "{}")
            except Exception:
                inf["gym_agent"] = {}

        return SyncCacheState(
            contract_status=contract_status,
            contract_end_date=contract_end_date,
            users=users,
            membership=membership,
            devices=devices_rows,
            infrastructures=infrastructures,
            updated_at=updated_at,
        )


# Convenience list helpers (for Local DB page)
def list_sync_users() -> List[Dict[str, Any]]:
    cache = load_sync_cache()
    return list(cache.users) if cache else []


def list_sync_memberships() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM sync_memberships").fetchall()]


def list_sync_devices() -> List[Dict[str, Any]]:
    """
    Returns DB rows (snake_case keys) with expanded *_json => arrays under expanded keys.
    """
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sync_devices").fetchall()]
        out: List[Dict[str, Any]] = []
        for d in rows:
            for k in ("allowed_memberships_json", "installed_models_json", "door_ids_json"):
                if k in d and d[k] is None:
                    d[k] = "[]"
            out.append(_expand_device_json_fields(d))
        return out


def get_sync_device(device_id: int) -> Optional[Dict[str, Any]]:
    """
    Returns one device row (snake_case keys) + expanded arrays.
    """
    try:
        did = int(device_id)
    except Exception:
        return None

    with get_conn() as conn:
        r = conn.execute("SELECT * FROM sync_devices WHERE id=?", (did,)).fetchone()
        if not r:
            return None
        return _expand_device_json_fields(dict(r))


def list_sync_devices_payload() -> List[Dict[str, Any]]:
    """
    Returns devices in API-like camelCase style for other pages to reuse easily.
    """
    rows = list_sync_devices()
    return [_coerce_device_row_to_payload(d) for d in rows]


def get_sync_device_payload(device_id: int) -> Optional[Dict[str, Any]]:
    d = get_sync_device(device_id)
    if not d:
        return None
    return _coerce_device_row_to_payload(d)


def list_sync_infrastructures() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sync_infrastructures").fetchall()]
        for inf in rows:
            try:
                inf["gym_agent"] = json.loads(inf.get("gym_agent_json") or "{}")
            except Exception:
                inf["gym_agent"] = {}
        return rows
