from app.api.monclub_api import MonClubApiHttpError


def detector():
    from app.core.offline_mode import OfflineDetector
    return OfflineDetector()


def test_four_network_failures_go_offline():
    d = detector()
    for _ in range(3):
        d.network_error()
        assert not d.state()["offline"]
    d.network_error()
    assert d.state()["offline"] and d.state()["since"]


def test_5xx_does_not_go_offline(monkeypatch):
    from app.core import staff_session
    monkeypatch.setattr(staff_session, "kv_get", lambda k: None)
    session = staff_session.StaffSession()
    class Api:
        def get_staff_current(self, token):
            raise MonClubApiHttpError("server unavailable", status_code=503)
    for _ in range(6):
        session.poll_once(Api(), "gym")
    assert not session.offline_detector.state()["offline"]


def test_two_successes_come_back():
    d = detector()
    for _ in range(4):
        d.network_error()
    d.success()
    assert d.state()["offline"]
    d.success()
    assert d.state() == {"offline": False, "manual": False, "since": None}


def test_manual_flag():
    d = detector()
    d.set_manual(True)
    d.success()
    d.success()
    assert d.state()["offline"] and d.state()["manual"]
    d.set_manual(False)
    assert not d.state()["offline"]


def test_http_error_breaks_consecutive_network_failures():
    d = detector()
    for _ in range(3):
        d.network_error()
    d.http_error()
    d.network_error()
    assert not d.state()["offline"]


def test_invalid_staff_answer_breaks_network_failure_streak(monkeypatch):
    from app.core import staff_session
    from types import SimpleNamespace
    monkeypatch.setattr(staff_session, "kv_get", lambda k: None)
    session = staff_session.StaffSession()
    for _ in range(3):
        session.offline_detector.network_error()
    session.poll_once(SimpleNamespace(get_staff_current=lambda **kw: {"ok": False}), "gym")
    session.offline_detector.network_error()
    assert not session.offline_detector.state()["offline"]
