"""Tests for AntiFraudGuard."""
import time
import threading
import pytest
from app.core.anti_fraud import AntiFraudGuard


def make_guard() -> AntiFraudGuard:
    return AntiFraudGuard()


class TestCheckNotBlocked:
    def test_new_token_not_blocked(self):
        g = make_guard()
        blocked, remaining = g.check(1, "ABC123", "card")
        assert blocked is False
        assert remaining == 0.0

    def test_different_device_not_blocked(self):
        g = make_guard()
        g.record(1, "ABC", "card", 60.0)
        blocked, _ = g.check(2, "ABC", "card")
        assert blocked is False

    def test_different_kind_not_blocked(self):
        g = make_guard()
        g.record(1, "ABC", "card", 60.0)
        blocked, _ = g.check(1, "ABC", "qr")
        assert blocked is False

    def test_different_token_not_blocked(self):
        g = make_guard()
        g.record(1, "ABC", "card", 60.0)
        blocked, _ = g.check(1, "XYZ", "card")
        assert blocked is False


class TestCheckBlocked:
    def test_blocked_immediately_after_record(self):
        g = make_guard()
        g.record(1, "ABC", "card", 30.0)
        blocked, remaining = g.check(1, "ABC", "card")
        assert blocked is True
        assert 29.0 < remaining <= 30.0

    def test_not_blocked_after_expiry(self):
        g = make_guard()
        g.record(1, "ABC", "card", 0.05)
        time.sleep(0.1)
        blocked, remaining = g.check(1, "ABC", "card")
        assert blocked is False
        assert remaining == 0.0

    def test_record_extends_window(self):
        g = make_guard()
        g.record(1, "ABC", "card", 0.05)
        time.sleep(0.03)
        g.record(1, "ABC", "card", 30.0)  # extend
        blocked, remaining = g.check(1, "ABC", "card")
        assert blocked is True
        assert remaining > 29.0


class TestEviction:
    def test_stale_entries_evicted_on_record(self):
        g = make_guard()
        g.record(1, "OLD", "card", 0.02)
        time.sleep(0.05)
        g.record(1, "NEW", "card", 60.0)  # triggers eviction
        with g._lock:
            assert (1, "OLD", "card") not in g._entries

    def test_active_entries_not_evicted(self):
        g = make_guard()
        g.record(1, "KEEP", "card", 60.0)
        g.record(1, "OTHER", "card", 60.0)  # triggers eviction of stale only
        with g._lock:
            assert (1, "KEEP", "card") in g._entries


class TestThreadSafety:
    def test_concurrent_record_and_check(self):
        g = make_guard()
        errors = []

        def worker(device_id: int):
            try:
                for i in range(50):
                    g.record(device_id, f"token{i}", "card", 0.5)
                    g.check(device_id, f"token{i}", "card")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
