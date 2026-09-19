"""P3b-1 Part F: the offline_revoke_grace_days client setting and the /api/v2/status clock
surface. No UI here (tauri-ui is TypeScript, verified separately) -- config round-trip, the
generic PATCH handler, and _build_status_payload_uncached's session block.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import app.core.config as cfgmod
import app.core.db as dbmod
import shared.config as shared_config_mod
from access.config import load_access_app_config, save_access_app_config, serialize_access_config
from app.api import local_access_api_v2
from app.core.config import AppConfig
from shared.config import ACCESS_CONFIG_FIELDS
from shared.desktop_paths import get_desktop_path_layout


# ============================================================================== fixtures
@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "_DB_PATH", str(tmp_path / "p3b1_f.db"), raising=False)
    dbmod._shutdown_db_writer_for_tests()
    dbmod.init_db()
    yield dbmod
    dbmod.invalidate_sync_cache(clear_cached=True)
    dbmod._shutdown_db_writer_for_tests()


def _exec(sql: str, params=()) -> None:
    def _w(conn, _profile):
        conn.execute(sql, params)
    dbmod._run_db_write_sync("test", _w)


# ============================================================================== 1. the config field
def test_offline_revoke_grace_days_is_part_of_access_config_fields() -> None:
    assert "offline_revoke_grace_days" in ACCESS_CONFIG_FIELDS


def test_field_default_is_zero_expire_on_time_even_offline() -> None:
    assert AppConfig().offline_revoke_grace_days == 0


def test_normaliser_accepts_a_positive_value() -> None:
    assert cfgmod.offline_revoke_grace_days(SimpleNamespace(offline_revoke_grace_days=3)) == 3
    assert cfgmod.offline_revoke_grace_days(SimpleNamespace(offline_revoke_grace_days="4")) == 4


def test_normaliser_clamps_negative_to_zero() -> None:
    assert cfgmod.offline_revoke_grace_days(SimpleNamespace(offline_revoke_grace_days=-5)) == 0


@pytest.mark.parametrize(
    "raw",
    [True, False, None, "abc", object()],
    ids=["bool_true", "bool_false", "none", "non_numeric_str", "garbage_object"],
)
def test_normaliser_rejects_bools_none_and_non_numeric(raw) -> None:
    # A bool is an int in Python (isinstance(True, int) is True) -- it must be
    # rejected explicitly, not coerced to 1/0 through max(0, int(value)).
    assert cfgmod.offline_revoke_grace_days(SimpleNamespace(offline_revoke_grace_days=raw)) == 0


def test_normaliser_defaults_to_zero_when_the_attribute_is_missing() -> None:
    assert cfgmod.offline_revoke_grace_days(SimpleNamespace()) == 0


def test_app_config_from_dict_normalises_an_invalid_stored_value() -> None:
    cfg = AppConfig.from_dict({"offline_revoke_grace_days": True})
    assert cfg.offline_revoke_grace_days == 0

    cfg = AppConfig.from_dict({"offline_revoke_grace_days": "10"})
    assert cfg.offline_revoke_grace_days == 10

    cfg = AppConfig.from_dict({})
    assert cfg.offline_revoke_grace_days == 0


def test_access_config_section_carries_a_non_default_value() -> None:
    # Regression: _build_access_section_from_cfg must read the field, not fall back
    # to AccessConfigSection's own "= 0" default (which would pass a test that only
    # ever checks the default).
    cfg = AppConfig.from_dict({"offline_revoke_grace_days": 9})
    serialized = serialize_access_config(cfg)
    assert serialized["offline_revoke_grace_days"] == 9


def test_offline_revoke_grace_days_round_trips_through_save_and_load(tmp_path, monkeypatch) -> None:
    # save_access_app_config/load_access_app_config write real JSON through
    # shared.config's module-level DesktopPathLayout (computed once at import time
    # from MONCLUB_ACCESS_DATA_ROOT, so it cannot be redirected by re-pointing that
    # env var mid-test). Point only access_config_path at a tmp_path file instead --
    # this is the file this test actually exercises, and it never touches whatever
    # real access config the running process resolved at import time.
    fake_layout = replace(get_desktop_path_layout(), access_config_path=tmp_path / "access_config.json")
    monkeypatch.setattr(shared_config_mod, "get_desktop_path_layout", lambda: fake_layout)

    cfg = load_access_app_config()
    cfg.offline_revoke_grace_days = 3
    save_access_app_config(cfg)

    reloaded = load_access_app_config()
    assert reloaded.offline_revoke_grace_days == 3


# ============================================================================== 2. the PATCH handler
class _ConfigCtx:
    def __init__(self, app, body: dict) -> None:
        self.app = app
        self._body = body
        self.responses: list[tuple[int, object]] = []

    def body(self) -> dict:
        return dict(self._body)

    def send_json(self, status: int, payload: object) -> None:
        self.responses.append((status, payload))


def _config_app(cfg: AppConfig) -> SimpleNamespace:
    return SimpleNamespace(cfg=cfg, logger=MagicMock(), persist_config=MagicMock())


def test_config_get_reports_the_stored_offline_revoke_grace_days() -> None:
    app = _config_app(AppConfig.from_dict({"offline_revoke_grace_days": 7}))
    ctx = _ConfigCtx(app, body={})

    local_access_api_v2._handle_config_get(ctx)

    status, payload = ctx.responses[-1]
    assert status == 200
    assert payload["offline_revoke_grace_days"] == 7


def test_config_patch_sets_offline_revoke_grace_days_and_persists() -> None:
    app = _config_app(AppConfig())
    ctx = _ConfigCtx(app, body={"offline_revoke_grace_days": 5})

    local_access_api_v2._handle_config_patch(ctx)

    status, payload = ctx.responses[-1]
    assert status == 200
    assert payload["changed"]["offline_revoke_grace_days"] == 5
    assert payload["config"]["offline_revoke_grace_days"] == 5
    assert app.cfg.offline_revoke_grace_days == 5
    app.persist_config.assert_called_once()


# ============================================================================== 3. the status payload
class _StatusApp:
    def __init__(self) -> None:
        self._sync_work_running = False
        self._last_sync_at = None
        self._last_sync_ok = True
        self._last_sync_error = None
        self._last_device_sync_at = None
        self._last_device_sync_ok = True
        self._last_device_sync_error = None
        self._agent_engine = None
        self._ultra_engine = None

    def _restriction_reasons(self) -> list[str]:
        return []

    def _compute_expiry_warnings(self) -> dict:
        return {}

    def get_access_mode_summary(self) -> dict:
        return {"DEVICE": 0, "AGENT": 0, "ULTRA": 0, "UNKNOWN": 0}


@contextmanager
def _patched_status_deps():
    with ExitStack() as stack:
        stack.enter_context(patch("access.store.load_auth_token", return_value=None))
        stack.enter_context(patch("app.core.db.load_sync_contract_meta", return_value={}))
        stack.enter_context(patch("app.core.db.list_sync_devices_payload", return_value=[]))
        stack.enter_context(
            patch.object(
                local_access_api_v2,
                "_build_update_status_payload",
                return_value={
                    "updateAvailable": False, "downloaded": False, "downloading": False,
                    "progress": None, "progressPercent": None, "currentReleaseId": None,
                    "lastCheckAt": None, "lastError": None,
                },
            )
        )
        yield


def test_status_session_defaults_when_no_v2_state_row_exists(db) -> None:
    app = _StatusApp()
    with _patched_status_deps():
        payload = local_access_api_v2._build_status_payload_uncached(app)

    session = payload["session"]
    assert session["clockSuspectWarning"] is False
    assert session["clockSuspectReason"] is None
    assert session["gymDate"] is None
    assert session["accessDatesTrusted"] is False


def test_status_session_surfaces_a_suspect_clock(db) -> None:
    _exec(
        "INSERT INTO access_v2_state (id, trusted, applied_date, clock_suspect, clock_reason) "
        "VALUES (1, 1, '2026-09-20', 1, 'behind')"
    )
    app = _StatusApp()
    with _patched_status_deps():
        payload = local_access_api_v2._build_status_payload_uncached(app)

    session = payload["session"]
    assert session["clockSuspectWarning"] is True
    assert session["clockSuspectReason"] == "behind"
    assert session["gymDate"] == "2026-09-20"
    assert session["accessDatesTrusted"] is True


def test_status_session_normalises_an_empty_clock_reason_to_null(db) -> None:
    # clock_reason is TEXT and access_dates writes "" for "no reason" -- "" must
    # surface as null on the wire, not as an empty (truthy-looking) string.
    _exec(
        "INSERT INTO access_v2_state (id, trusted, applied_date, clock_suspect, clock_reason) "
        "VALUES (1, 0, '2026-09-19', 0, '')"
    )
    app = _StatusApp()
    with _patched_status_deps():
        payload = local_access_api_v2._build_status_payload_uncached(app)

    assert payload["session"]["clockSuspectReason"] is None
    assert payload["session"]["clockSuspectWarning"] is False
    assert payload["session"]["accessDatesTrusted"] is False


# ============================================================================== 4. tauri-ui (text-level only)
# No node_modules / typecheck command available offline (see report) -- these confirm the
# four strings the task asks for actually landed, the way test_config_page_save_button.py
# text-asserts on the same files.
def test_tauri_ui_carries_the_new_status_fields_and_pill_copy() -> None:
    types_ts = Path("tauri-ui/src/api/types.ts").read_text(encoding="utf-8")
    assert "clockSuspectWarning" in types_ts
    assert "clockSuspectReason" in types_ts
    assert "gymDate" in types_ts
    assert "accessDatesTrusted" in types_ts
    assert "offline_revoke_grace_days: number" in types_ts

    main_layout = Path("tauri-ui/src/layouts/MainLayout.tsx").read_text(encoding="utf-8")
    assert "Horloge du PC suspecte" in main_layout
    assert "clockSuspectWarning" in main_layout


def test_tauri_ui_config_page_carries_the_grace_days_input() -> None:
    config_page = Path("tauri-ui/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")
    assert "offline_revoke_grace_days" in config_page
    assert "Délai de grâce hors ligne (jours)" in config_page
    assert "0 = les abonnements expirent à l'heure même sans internet" in config_page


def test_tauri_ui_popup_window_carries_the_not_allowed_today_reason() -> None:
    popup_window = Path("tauri-ui/src/pages/PopupWindow.tsx").read_text(encoding="utf-8")
    assert "DENY_NOT_ALLOWED_TODAY" in popup_window
    assert "Abonnement non valable aujourd'hui" in popup_window


def test_status_session_never_500s_when_the_v2_state_read_fails(monkeypatch) -> None:
    def _boom():
        raise RuntimeError("db locked")

    monkeypatch.setattr(dbmod, "get_access_v2_state", _boom)
    app = _StatusApp()
    with _patched_status_deps():
        payload = local_access_api_v2._build_status_payload_uncached(app)

    session = payload["session"]
    assert session["clockSuspectWarning"] is False
    assert session["clockSuspectReason"] is None
    assert session["gymDate"] is None
    assert session["accessDatesTrusted"] is False
