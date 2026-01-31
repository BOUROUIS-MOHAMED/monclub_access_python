# monclub_access_python/app/core/db.py
from __future__ import annotations

import base64
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Iterable

from app.core.utils import DB_PATH, ensure_dirs, now_iso


# -----------------------------
# SQLite connection helpers
# -----------------------------
def get_conn() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------
# Optional DPAPI protection (Windows)
# -----------------------------
def _dpapi_encrypt(plain: str) -> str:
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
# DB schema helpers / migrations
# -----------------------------
def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [r["name"] for r in rows]  # type: ignore[index]
    except Exception:
        return []


def _sync_users_has_legacy_fingerprint(conn: sqlite3.Connection) -> bool:
    cols = _table_columns(conn, "sync_users")
    return "fingerprint" in cols


def _rebuild_sync_users_without_legacy_fingerprint(conn: sqlite3.Connection) -> None:
    if not _sync_users_has_legacy_fingerprint(conn):
        return

    cols_old = set(_table_columns(conn, "sync_users"))

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_users_new (
            user_id INTEGER,
            active_membership_id INTEGER,
            membership_id INTEGER,
            full_name TEXT,
            phone TEXT,
            email TEXT,
            valid_from TEXT,
            valid_to TEXT,
            first_card_id TEXT,
            second_card_id TEXT,
            image TEXT,
            fingerprints_json TEXT,
            face_id TEXT,
            qr_code_payload TEXT
        );
        """
    )

    def sel(col: str, default_sql: str = "NULL") -> str:
        return col if col in cols_old else default_sql

    fps_expr = sel("fingerprints_json", "'[]'")

    conn.execute(
        f"""
        INSERT INTO sync_users_new (
            user_id, active_membership_id, membership_id,
            full_name, phone, email, valid_from, valid_to,
            first_card_id, second_card_id, image,
            fingerprints_json,
            face_id, qr_code_payload
        )
        SELECT
            {sel("user_id")},
            {sel("active_membership_id")},
            {sel("membership_id")},
            {sel("full_name")},
            {sel("phone")},
            {sel("email")},
            {sel("valid_from")},
            {sel("valid_to")},
            {sel("first_card_id")},
            {sel("second_card_id")},
            {sel("image")},
            {fps_expr},
            {sel("face_id")},
            {sel("qr_code_payload")}
        FROM sync_users;
        """
    )

    conn.execute("DROP TABLE sync_users;")
    conn.execute("ALTER TABLE sync_users_new RENAME TO sync_users;")


# -----------------------------
# DB init
# -----------------------------
def init_db() -> None:
    with get_conn() as conn:
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

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_cache (
                id INTEGER PRIMARY KEY CHECK (id=1),
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            """
        )

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

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_users (
                user_id INTEGER,
                active_membership_id INTEGER,
                membership_id INTEGER,
                full_name TEXT,
                phone TEXT,
                email TEXT,
                valid_from TEXT,
                valid_to TEXT,
                first_card_id TEXT,
                second_card_id TEXT,
                image TEXT,
                fingerprints_json TEXT,
                face_id TEXT,
                qr_code_payload TEXT
            );
            """
        )

        try:
            conn.execute("ALTER TABLE sync_users ADD COLUMN fingerprints_json TEXT;")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE sync_users ADD COLUMN active_membership_id INTEGER;")
        except Exception:
            pass

        try:
            _rebuild_sync_users_without_legacy_fingerprint(conn)
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

        # --- NEW: Gym access credentials (TOTP/credential secrets) ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_gym_access_credentials (
                id INTEGER,
                gym_id INTEGER,
                account_id INTEGER,
                secret_hex TEXT,
                enabled INTEGER,
                rotated_at TEXT,
                created_at TEXT,
                updated_at TEXT,
                granted_active_membership_ids_json TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_gac_gym_id ON sync_gym_access_credentials(gym_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sync_gac_account_id ON sync_gym_access_credentials(account_id);")

        # --- Door presets per device (existing) ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_door_presets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                door_number INTEGER NOT NULL,
                pulse_seconds INTEGER NOT NULL,
                door_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(device_id, door_number, door_name)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_device_door_presets_device_id ON device_door_presets(device_id);")

        # --- NEW: Realtime RTLog last cursor/time per device ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_rtlog_state (
                device_id INTEGER PRIMARY KEY,
                last_event_at TEXT,
                last_event_id TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )

        # --- NEW: Access history (realtime engine) ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_id TEXT NOT NULL,
                device_id INTEGER,
                door_id INTEGER,
                card_no TEXT,
                event_time TEXT,
                event_type TEXT,
                allowed INTEGER,
                reason TEXT,
                poll_ms REAL,
                decision_ms REAL,
                cmd_ms REAL,
                cmd_ok INTEGER,
                cmd_error TEXT,
                raw_json TEXT,
                UNIQUE(event_id)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_history_device_time ON access_history(device_id, event_time);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_history_created_at ON access_history(created_at);")

        # --- NEW: DeviceSync per-device+pin applied state (hash-based incremental sync) ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_sync_state (
                device_id INTEGER NOT NULL,
                pin TEXT NOT NULL,
                desired_hash TEXT,
                last_ok INTEGER NOT NULL DEFAULT 1,
                last_error TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (device_id, pin)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_device_sync_state_device ON device_sync_state(device_id);")

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
# Door presets per device (existing)
# -----------------------------
@dataclass
class DeviceDoorPreset:
    id: int
    device_id: int
    door_number: int
    pulse_seconds: int
    door_name: str
    created_at: str
    updated_at: str


def _clamp_int(v: Any, default: int, min_v: int, max_v: int) -> int:
    try:
        x = int(str(v).strip())
    except Exception:
        x = default
    if x < min_v:
        x = min_v
    if x > max_v:
        x = max_v
    return x


def list_device_door_presets(device_id: int) -> List[DeviceDoorPreset]:
    did = int(device_id)
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM device_door_presets
            WHERE device_id=?
            ORDER BY door_number ASC, id ASC
            """,
            (did,),
        ).fetchall()
        return [DeviceDoorPreset(**dict(r)) for r in rows]


def create_device_door_preset(
    *,
    device_id: int,
    door_number: int,
    pulse_seconds: int,
    door_name: str,
    max_per_device: int = 10,
) -> int:
    did = int(device_id)
    dn = _clamp_int(door_number, 1, 1, 64)
    ps = _clamp_int(pulse_seconds, 3, 1, 60)
    name = (door_name or "").strip()
    if not name:
        raise ValueError("Door name is required.")

    with get_conn() as conn:
        cur = conn.execute("SELECT COUNT(*) AS c FROM device_door_presets WHERE device_id=?", (did,))
        c = int(cur.fetchone()["c"])  # type: ignore[index]
        if c >= int(max_per_device):
            raise ValueError(f"Max presets per device is {max_per_device}.")

        now = now_iso()
        cur2 = conn.execute(
            """
            INSERT INTO device_door_presets
            (device_id, door_number, pulse_seconds, door_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (did, dn, ps, name, now, now),
        )
        conn.commit()
        return int(cur2.lastrowid)


def update_device_door_preset(
    *,
    preset_id: int,
    device_id: int,
    door_number: int,
    pulse_seconds: int,
    door_name: str,
    max_per_device: int = 10,
) -> None:
    pid = int(preset_id)
    did = int(device_id)
    dn = _clamp_int(door_number, 1, 1, 64)
    ps = _clamp_int(pulse_seconds, 3, 1, 60)
    name = (door_name or "").strip()
    if not name:
        raise ValueError("Door name is required.")

    with get_conn() as conn:
        r = conn.execute("SELECT id, device_id FROM device_door_presets WHERE id=?", (pid,)).fetchone()
        if not r:
            raise ValueError("Preset not found.")

        old_did = int(r["device_id"])  # type: ignore[index]
        if old_did != did:
            cur = conn.execute("SELECT COUNT(*) AS c FROM device_door_presets WHERE device_id=?", (did,))
            c = int(cur.fetchone()["c"])  # type: ignore[index]
            if c >= int(max_per_device):
                raise ValueError(f"Max presets per device is {max_per_device}.")

        conn.execute(
            """
            UPDATE device_door_presets
            SET device_id=?, door_number=?, pulse_seconds=?, door_name=?, updated_at=?
            WHERE id=?
            """,
            (did, dn, ps, name, now_iso(), pid),
        )
        conn.commit()


def delete_device_door_preset(preset_id: int) -> None:
    pid = int(preset_id)
    with get_conn() as conn:
        conn.execute("DELETE FROM device_door_presets WHERE id=?", (pid,))
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
    gym_access_credentials: List[Dict[str, Any]] = field(default_factory=list)
    updated_at: str = ""


def save_sync_cache(data: Dict[str, Any]) -> None:
    payload_json = json.dumps(data or {}, ensure_ascii=False)
    updated_at = now_iso()

    contract_status = bool(data.get("contractStatus", False))
    contract_end_date = (data.get("contractEndDate") or "").strip()

    users = data.get("users") or []
    memberships = data.get("membership") or data.get("memberships") or []
    devices = data.get("devices") or []
    infrastructures = data.get("infrastructures") or data.get("infrastructure") or []
    gym_access_credentials = data.get("gymAccessCredentials") or data.get("gym_access_credentials") or []

    with get_conn() as conn:
        cur = conn.cursor()

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

        cur.execute("DELETE FROM sync_users")
        cur.execute("DELETE FROM sync_memberships")
        cur.execute("DELETE FROM sync_devices")
        cur.execute("DELETE FROM sync_infrastructures")
        cur.execute("DELETE FROM sync_gym_access_credentials")

        for u in users:
            if not isinstance(u, dict):
                continue

            fps = u.get("fingerprints") or []
            if not isinstance(fps, list):
                fps = []

            am_id = u.get("activeMembershipId")
            m_id = u.get("membershipId")
            if am_id is None or str(am_id).strip() == "":
                am_id = m_id

            cur.execute(
                """
                INSERT INTO sync_users (
                    user_id,
                    active_membership_id,
                    membership_id,
                    full_name, phone, email, valid_from, valid_to,
                    first_card_id, second_card_id, image,
                    fingerprints_json,
                    face_id, qr_code_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    u.get("userId"),
                    am_id,
                    m_id,
                    u.get("fullName"),
                    u.get("phone"),
                    u.get("email"),
                    u.get("validFrom"),
                    u.get("validTo"),
                    u.get("firstCardId"),
                    u.get("secondCardId"),
                    u.get("image"),
                    json.dumps(fps, ensure_ascii=False),
                    u.get("faceId"),
                    u.get("qrCodePayload"),
                ),
            )

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

        for c in gym_access_credentials:
            if not isinstance(c, dict):
                continue

            granted_ids = c.get("grantedActiveMembershipIds")
            if not isinstance(granted_ids, list):
                granted_ids = []

            def _to_int_or_none(v: Any) -> int | None:
                try:
                    if v is None:
                        return None
                    s = str(v).strip()
                    if not s:
                        return None
                    return int(s)
                except Exception:
                    return None

            cid = _to_int_or_none(c.get("id"))
            gym_id = _to_int_or_none(c.get("gymId") if "gymId" in c else c.get("gym_id"))
            account_id = _to_int_or_none(c.get("accountId") if "accountId" in c else c.get("account_id"))
            secret_hex = (c.get("secretHex") if "secretHex" in c else c.get("secret_hex")) or ""
            enabled = 1 if bool(c.get("enabled", False)) else 0

            cur.execute(
                """
                INSERT INTO sync_gym_access_credentials (
                    id, gym_id, account_id, secret_hex, enabled,
                    rotated_at, created_at, updated_at,
                    granted_active_membership_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cid,
                    gym_id,
                    account_id,
                    str(secret_hex or ""),
                    enabled,
                    c.get("rotatedAt") or c.get("rotated_at"),
                    c.get("createdAt") or c.get("created_at"),
                    c.get("updatedAt") or c.get("updated_at"),
                    json.dumps(granted_ids, ensure_ascii=False),
                ),
            )

        conn.commit()


def _coerce_user_row_to_payload(u: Dict[str, Any]) -> Dict[str, Any]:
    def g(*keys, default=None):
        for k in keys:
            if k in u:
                return u.get(k)
        return default

    fps_raw = g("fingerprints", "fingerprints_json", default=None)
    fps: List[Dict[str, Any]] = []
    if isinstance(fps_raw, list):
        fps = fps_raw  # type: ignore[assignment]
    elif isinstance(fps_raw, str) and fps_raw.strip():
        try:
            x = json.loads(fps_raw)
            if isinstance(x, list):
                fps = x  # type: ignore[assignment]
        except Exception:
            fps = []
    else:
        fps = []

    active_membership_id = g("activeMembershipId", "active_membership_id", default=None)
    membership_id = g("membershipId", "membership_id", default=None)

    return {
        "userId": g("userId", "userid", "user_id", "id"),
        "activeMembershipId": active_membership_id,
        "membershipId": membership_id,
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
    def g(*keys, default=None):
        for k in keys:
            if k in d:
                return d.get(k)
        return default

    allowed = g("allowedMemberships", "allowed_memberships", default=None) or []
    installed = g("installedModels", "installed_models", default=None) or []
    doors = g("doorIds", "door_ids", default=None) or []

    def _boolish(v: Any, default: bool) -> bool:
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
            return default
        if isinstance(v, (int, float)):
            return int(v) != 0
        if isinstance(v, bool):
            return v
        return default

    return {
        "id": g("id"),
        "name": g("name"),
        "description": g("description"),
        "allowedMemberships": allowed,
        "active": _boolish(g("active", default=1), True),
        "accessDevice": _boolish(g("access_device", "accessDevice", default=1), True),
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


def _expand_gym_access_credential_json_fields(c: Dict[str, Any]) -> Dict[str, Any]:
    cc = dict(c or {})
    raw = cc.get("granted_active_membership_ids_json")
    if raw is None:
        raw = cc.get("grantedActiveMembershipIds")
    try:
        cc["granted_active_membership_ids"] = json.loads(raw or "[]") if isinstance(raw, str) else (raw or [])
        if not isinstance(cc["granted_active_membership_ids"], list):
            cc["granted_active_membership_ids"] = []
    except Exception:
        cc["granted_active_membership_ids"] = []
    return cc


def _coerce_gym_access_credential_row_to_payload(c: Dict[str, Any]) -> Dict[str, Any]:
    def g(*keys, default=None):
        for k in keys:
            if k in c:
                return c.get(k)
        return default

    enabled_raw = g("enabled", default=False)
    if isinstance(enabled_raw, str):
        enabled = enabled_raw.strip().lower() in ("1", "true", "yes", "y", "on")
    elif isinstance(enabled_raw, (int, float)):
        enabled = int(enabled_raw) != 0
    else:
        enabled = bool(enabled_raw)

    granted = g("grantedActiveMembershipIds", "granted_active_membership_ids", default=None)
    if not isinstance(granted, list):
        granted = []

    return {
        "id": g("id"),
        "gymId": g("gymId", "gym_id"),
        "accountId": g("accountId", "account_id"),
        "secretHex": g("secretHex", "secret_hex"),
        "enabled": enabled,
        "rotatedAt": g("rotatedAt", "rotated_at"),
        "createdAt": g("createdAt", "created_at"),
        "updatedAt": g("updatedAt", "updated_at"),
        "grantedActiveMembershipIds": granted,
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
            norm_users: List[Dict[str, Any]] = []
            for u in users:
                if isinstance(u, dict):
                    norm_users.append(_coerce_user_row_to_payload(u))

            devs = list(data.get("devices") or [])
            creds = list(data.get("gymAccessCredentials") or data.get("gym_access_credentials") or [])

            return SyncCacheState(
                contract_status=bool(data.get("contractStatus", False)),
                contract_end_date=(data.get("contractEndDate") or ""),
                users=norm_users,
                membership=list(data.get("membership") or data.get("memberships") or []),
                devices=devs,
                infrastructures=list(data.get("infrastructures") or data.get("infrastructure") or []),
                gym_access_credentials=[c for c in creds if isinstance(c, dict)],
                updated_at=(raw["updated_at"] or ""),
            )

        contract_status = bool(int(meta["contract_status"]))
        contract_end_date = meta["contract_end_date"] or ""
        updated_at = meta["updated_at"] or ""

        users_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_users").fetchall()]
        users = [_coerce_user_row_to_payload(u) for u in users_rows]

        membership = [dict(r) for r in conn.execute("SELECT * FROM sync_memberships").fetchall()]

        devices_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_devices").fetchall()]
        devices_rows = [_expand_device_json_fields(d) for d in devices_rows]

        infrastructures = [dict(r) for r in conn.execute("SELECT * FROM sync_infrastructures").fetchall()]
        for inf in infrastructures:
            try:
                inf["gym_agent"] = json.loads(inf.get("gym_agent_json") or "{}")
            except Exception:
                inf["gym_agent"] = {}

        creds_rows = [dict(r) for r in conn.execute("SELECT * FROM sync_gym_access_credentials").fetchall()]
        creds_rows = [_expand_gym_access_credential_json_fields(c) for c in creds_rows]
        creds_payload = [_coerce_gym_access_credential_row_to_payload(c) for c in creds_rows]

        return SyncCacheState(
            contract_status=contract_status,
            contract_end_date=contract_end_date,
            users=users,
            membership=membership,
            devices=devices_rows,
            infrastructures=infrastructures,
            gym_access_credentials=creds_payload,
            updated_at=updated_at,
        )


def list_sync_users() -> List[Dict[str, Any]]:
    cache = load_sync_cache()
    return list(cache.users) if cache else []


def list_sync_memberships() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM sync_memberships").fetchall()]


def list_sync_devices() -> List[Dict[str, Any]]:
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


# -----------------------------
# NEW: Gym access credentials (from ActiveMemberResponse)
# -----------------------------
def list_sync_gym_access_credentials() -> List[Dict[str, Any]]:
    cache = load_sync_cache()
    return list(cache.gym_access_credentials) if cache else []


# -----------------------------
# NEW: DeviceSync per-device+pin state (hash-based incremental sync)
# -----------------------------
def list_device_sync_hashes(*, device_id: int) -> Dict[str, str]:
    did = int(device_id)
    with get_conn() as conn:
        rows = conn.execute("SELECT pin, desired_hash FROM device_sync_state WHERE device_id=?", (did,)).fetchall()
        out: Dict[str, str] = {}
        for r in rows:
            p = str(r["pin"] or "")
            h = str(r["desired_hash"] or "")
            if p:
                out[p] = h
        return out


def list_device_sync_pins(*, device_id: int) -> List[str]:
    did = int(device_id)
    with get_conn() as conn:
        rows = conn.execute("SELECT pin FROM device_sync_state WHERE device_id=?", (did,)).fetchall()
        return [str(r["pin"] or "") for r in rows if str(r["pin"] or "").strip()]


def save_device_sync_state(*, device_id: int, pin: str, desired_hash: str | None, ok: bool, error: str | None) -> None:
    did = int(device_id)
    p = str(pin or "").strip()
    if not p:
        return

    err = (str(error or "")[:1000]) if error else None
    ok_i = 1 if bool(ok) else 0
    dh = str(desired_hash or "").strip() if desired_hash else ""

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO device_sync_state (device_id, pin, desired_hash, last_ok, last_error, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id, pin) DO UPDATE SET
                desired_hash = CASE
                    WHEN excluded.last_ok = 1 THEN excluded.desired_hash
                    ELSE device_sync_state.desired_hash
                END,
                last_ok = excluded.last_ok,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at
            """,
            (did, p, dh, ok_i, err, now_iso()),
        )
        conn.commit()


def delete_device_sync_state(*, device_id: int, pin: str) -> None:
    did = int(device_id)
    p = str(pin or "").strip()
    if not p:
        return
    with get_conn() as conn:
        conn.execute("DELETE FROM device_sync_state WHERE device_id=? AND pin=?", (did, p))
        conn.commit()


def prune_device_sync_state(*, device_id: int, keep_pins: Iterable[str]) -> int:
    did = int(device_id)
    keep = {str(x).strip() for x in (keep_pins or []) if str(x).strip()}
    existing = set(list_device_sync_pins(device_id=did))
    to_remove = sorted([p for p in existing if p not in keep])
    if not to_remove:
        return 0

    deleted = 0
    with get_conn() as conn:
        CHUNK = 300
        for i in range(0, len(to_remove), CHUNK):
            chunk = to_remove[i : i + CHUNK]
            q = ",".join(["?"] * len(chunk))
            cur = conn.execute(
                f"DELETE FROM device_sync_state WHERE device_id=? AND pin IN ({q})",
                (did, *chunk),
            )
            deleted += int(cur.rowcount or 0)
        conn.commit()
    return deleted


# -----------------------------
# NEW: Realtime RTLog cursor/state
# -----------------------------
@dataclass
class AgentRtlogState:
    device_id: int
    last_event_at: str
    last_event_id: str
    updated_at: str


def load_agent_rtlog_state(device_id: int) -> Optional[AgentRtlogState]:
    did = int(device_id)
    with get_conn() as conn:
        r = conn.execute(
            "SELECT device_id, last_event_at, last_event_id, updated_at FROM agent_rtlog_state WHERE device_id=?",
            (did,),
        ).fetchone()
        if not r:
            return None
        return AgentRtlogState(
            device_id=int(r["device_id"]),  # type: ignore[index]
            last_event_at=str(r["last_event_at"] or ""),
            last_event_id=str(r["last_event_id"] or ""),
            updated_at=str(r["updated_at"] or ""),
        )


def save_agent_rtlog_state(*, device_id: int, last_event_at: str, last_event_id: str) -> None:
    did = int(device_id)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO agent_rtlog_state (device_id, last_event_at, last_event_id, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                last_event_at=excluded.last_event_at,
                last_event_id=excluded.last_event_id,
                updated_at=excluded.updated_at
            """,
            (did, str(last_event_at or ""), str(last_event_id or ""), now_iso()),
        )
        conn.commit()


# -----------------------------
# NEW: Access history (realtime engine)
# -----------------------------
@dataclass
class AccessHistoryRow:
    id: int
    created_at: str
    event_id: str
    device_id: int
    door_id: int
    card_no: str
    event_time: str
    event_type: str
    allowed: int
    reason: str
    poll_ms: float
    decision_ms: float
    cmd_ms: float
    cmd_ok: int
    cmd_error: str
    raw_json: str


def access_history_exists(event_id: str) -> bool:
    eid = str(event_id or "").strip()
    if not eid:
        return False
    try:
        with get_conn() as conn:
            r = conn.execute("SELECT 1 FROM access_history WHERE event_id=? LIMIT 1", (eid,)).fetchone()
            return bool(r)
    except Exception:
        return False


def insert_access_history(
    *,
    event_id: str,
    device_id: int | None,
    door_id: int | None,
    card_no: str | None,
    event_time: str | None,
    event_type: str | None,
    allowed: bool,
    reason: str | None,
    poll_ms: float | None,
    decision_ms: float | None,
    cmd_ms: float | None,
    cmd_ok: bool | None,
    cmd_error: str | None,
    raw: Dict[str, Any] | None,
) -> None:
    if not str(event_id or "").strip():
        return

    with get_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO access_history (
                    created_at, event_id, device_id, door_id, card_no,
                    event_time, event_type,
                    allowed, reason,
                    poll_ms, decision_ms, cmd_ms,
                    cmd_ok, cmd_error,
                    raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now_iso(),
                    str(event_id),
                    int(device_id) if device_id is not None else None,
                    int(door_id) if door_id is not None else None,
                    (str(card_no) if card_no is not None else None),
                    (str(event_time) if event_time is not None else None),
                    (str(event_type) if event_type is not None else None),
                    1 if bool(allowed) else 0,
                    (str(reason or "")[:500]),
                    float(poll_ms) if poll_ms is not None else None,
                    float(decision_ms) if decision_ms is not None else None,
                    float(cmd_ms) if cmd_ms is not None else None,
                    (1 if bool(cmd_ok) else 0) if cmd_ok is not None else None,
                    (str(cmd_error or "")[:1000]) if cmd_error else None,
                    json.dumps(raw or {}, ensure_ascii=False),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return


def prune_access_history(*, retention_days: int) -> int:
    days = int(retention_days)
    if days < 1:
        days = 1
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM access_history
            WHERE julianday('now') - julianday(created_at) > ?
            """,
            (days,),
        )
        conn.commit()
        return int(cur.rowcount or 0)
