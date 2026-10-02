"""Which engine drives each device, applied without restarting Access (ULTRA merge, spec 2026-10-02
section 6 "Taking effect", D2).

Two entry points, both under MainApp._ultra_lock, both AGENT first, then ULTRA: the AGENT engine
joins the worker of a device that left AGENT before a ULTRA worker connects to the same turnstile
(realtime_agent.AgentRealtimeEngine.refresh_devices joins every worker it stops).

- refresh_running_ultra_devices: a GYM_DEVICE fast patch or a sync save changed the device rows.
  While the ULTRA engine runs, a device that became ULTRA (in service, driven by this PC) gets its
  worker, a device that left ULTRA or went out of service loses it, every other worker gets its
  new row. A worker whose lease is away keeps running with a fresh copy (review R1-F5). With no
  ULTRA engine running nothing is read: the sync tick the fast patch requests starts it.
- apply_modes_on_tick: the sync tick. Starts the engine for the first ULTRA device, adds and stops
  single workers while it runs (no engine restart), stops it when no ULTRA device is left.

Moved out of app/ui/app.py (MainApp._refresh_running_ultra_devices and the sync tick's mode block),
which now call here (spec section 9).
"""
from __future__ import annotations

from typing import Any, Dict, List

from app.core.ultra_worker_pool import devices_to_drive


def _is_ultra(device: Any) -> bool:
    return isinstance(device, dict) and str(device.get("accessDataMode", "")).strip().upper() == "ULTRA"


def _refresh_agent_engine(app: Any) -> None:
    agent = getattr(app, "_agent_engine", None)
    try:
        if agent is not None and agent.is_running():
            agent.refresh_devices()
    except Exception as exc:
        app.logger.warning("[AGENT] refresh_devices error: %s", exc)


def _device_rows() -> List[Dict[str, Any]]:
    try:
        from app.core.db import list_sync_devices_payload

        return list(list_sync_devices_payload() or [])
    except Exception:
        from app.core.db import load_sync_cache

        cache = load_sync_cache()
        return list((getattr(cache, "devices", []) or []) if cache else [])


def _start_history_consumer(app: Any) -> None:
    if getattr(app, "_ultra_history_consumer", None):
        return
    from app.core.realtime_agent import HistoryService
    from app.core.settings_reader import get_backend_global_settings

    app._ultra_history_consumer = HistoryService(
        logger=app.logger,
        history_q=app._ultra_engine.history_q,
        global_settings=get_backend_global_settings,
    )
    app._ultra_history_consumer.start()


def _stop_engine(app: Any, why: str) -> None:
    app.logger.info("[ULTRA] %s, stopping engine", why)
    app._ultra_engine.stop()
    consumer = getattr(app, "_ultra_history_consumer", None)
    if consumer:
        consumer.stop()
        app._ultra_history_consumer = None


def refresh_running_ultra_devices(app: Any, *, reason: str) -> bool:
    """Hand the running ULTRA workers the device rows the database holds now, starting or stopping
    single workers for a mode or In-service change. True when done, or when no ULTRA engine runs;
    False when the rows could not be read or applied (logged)."""
    with app._ultra_lock:
        engine = getattr(app, "_ultra_engine", None)
        if engine is None or not getattr(engine, "running", False):
            return True
        try:
            from app.core.db import list_sync_devices_payload

            ultra = [d for d in list_sync_devices_payload() if _is_ultra(d)]
            _refresh_agent_engine(app)
            counts = engine.reconcile_devices(ultra, stop_undriven=False)
        except Exception:
            app.logger.warning("[ULTRA] worker device rows not refreshed (%s)", reason, exc_info=True)
            return False
    app.logger.info(
        "[ULTRA] refreshed %d worker device row(s) (%s); workers started=%d stopped=%d",
        int(counts.get("refreshed", 0)), reason, int(counts.get("started", 0)), int(counts.get("stopped", 0)),
    )
    return True


def apply_modes_on_tick(app: Any, *, refresh: Dict[str, Any]) -> bool:
    """The sync tick's mode step. Returns True only when it started the ULTRA engine (the tick then
    does not request the pass a fresh start already runs)."""
    started = False
    try:
        with app._ultra_lock:
            _refresh_agent_engine(app)
            summary = app.get_access_mode_summary()
            ultra_count = summary.get("ULTRA", 0)
            app.logger.info("[ULTRA] sync_tick: mode_summary=%s", summary)
            engine = app._ultra_engine
            wanted: List[Dict[str, Any]] = []
            if ultra_count > 0:
                rows = _device_rows()
                wanted = devices_to_drive(rows)
                app.logger.info(
                    "[ULTRA] sync_tick: all_devices=%d ultra_devices=%d ids=%s",
                    len(rows), len(wanted), [d.get("id") for d in wanted],
                )
            if ultra_count > 0 and not engine.running:
                if wanted:
                    engine.start(wanted)
                    started = bool(engine.running)
                    if started:
                        _start_history_consumer(app)
            elif ultra_count > 0 and engine.running:
                if not wanted:
                    _stop_engine(app, "No ULTRA device in service on this PC")
                elif {int(d.get("id", 0)) for d in wanted} != set(engine._workers.keys()):
                    counts = engine.reconcile_devices(
                        wanted, stop_undriven=True, refresh_copies=bool(refresh.get("devices")))
                    app.logger.info(
                        "[ULTRA] workers changed in place: started=%d stopped=%d",
                        int(counts.get("started", 0)), int(counts.get("stopped", 0)),
                    )
                elif refresh.get("devices"):
                    try:
                        engine.refresh_devices(wanted)
                    except Exception as exc:
                        app.logger.warning("[ULTRA] refresh_devices error: %s", exc)
            if ultra_count == 0 and engine.running:
                _stop_engine(app, "No ULTRA devices remaining")
    except Exception as ex:
        app.logger.exception(f"[ULTRA] Unexpected error in sync_tick: {ex}")
    return started
