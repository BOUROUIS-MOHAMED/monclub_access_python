"""Verify anti-fraud columns exist in sync_devices and round-trip correctly."""
import pytest
from app.core.db import get_conn, init_db


@pytest.fixture(autouse=True, scope="module")
def _ensure_db():
    """Run migrations before any test in this module."""
    init_db()


def test_sync_devices_has_anti_fraud_columns():
    with get_conn() as conn:
        cursor = conn.execute("PRAGMA table_info(sync_devices)")
        columns = {row["name"] for row in cursor.fetchall()}
    assert "anti_fraude_card" in columns
    assert "anti_fraude_qr_code" in columns
    assert "anti_fraude_duration" in columns


def test_anti_fraud_column_defaults():
    """A freshly inserted device should have default anti-fraud values."""
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO sync_devices (id, name) VALUES (99999, 'test-af')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT anti_fraude_card, anti_fraude_qr_code, anti_fraude_duration "
            "FROM sync_devices WHERE id = 99999"
        ).fetchone()
        conn.execute("DELETE FROM sync_devices WHERE id = 99999")
        conn.commit()
    assert row["anti_fraude_card"] == 1
    assert row["anti_fraude_qr_code"] == 1
    assert row["anti_fraude_duration"] == 30
