from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import List, Optional

from app.core.utils import DB_PATH, ensure_dirs, now_iso


def get_conn() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
        conn.commit()


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
        rows = conn.execute(
            "SELECT * FROM fingerprints ORDER BY id DESC"
        ).fetchall()
        return [FingerprintRecord(**dict(r)) for r in rows]


def get_fingerprint(fp_id: int) -> Optional[FingerprintRecord]:
    with get_conn() as conn:
        r = conn.execute("SELECT * FROM fingerprints WHERE id=?", (fp_id,)).fetchone()
        return FingerprintRecord(**dict(r)) if r else None


def delete_fingerprint(fp_id: int) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM fingerprints WHERE id=?", (fp_id,))
        conn.commit()
