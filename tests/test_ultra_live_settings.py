"""Polling settings apply without a restart (ULTRA merge plan 2, Task 11; spec sections 3, 4, 5)."""
from __future__ import annotations

import queue
import threading

import app.core.ultra_engine as _ue
from app.core.settings_reader import normalize_device_settings
from tests.test_ultra_engine import _make_worker


def test_polling_settings_apply_on_a_device_refresh():
    w = _make_worker()
    s = normalize_device_settings({"busySleepMinMs": 5, "emptySleepMinMs": 40,
                                   "emptyBackoffFactor": 2.0, "emptyBackoffMaxMs": 900})
    w.update_device(w._device, s)
    assert (w._busy_min, w._empty_min, w._backoff, w._backoff_cap) == (5, 40, 2.0, 900)


def test_a_device_switched_to_pc_cards_polls_at_most_every_300_ms():
    w = _make_worker()
    w.update_device(w._device, normalize_device_settings({"accessDataMode": "ULTRA", "cardDecision": "PC",
                                                          "emptyBackoffMaxMs": 2000}))
    assert w._backoff_cap == 300


def test_a_new_worker_reads_the_same_knobs():
    s = normalize_device_settings({"busySleepMinMs": 7, "emptyBackoffMaxMs": 1200})
    w = _ue.UltraDeviceWorker({"id": 3, "name": "x"}, s, queue.Queue(), queue.Queue(), threading.Event())
    assert (w._busy_min, w._backoff_cap, w._empty_sleep_ms) == (7, 1200, float(w._empty_min))
