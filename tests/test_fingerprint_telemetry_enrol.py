"""Session C (2026-09-04): telemetry for the ENROL and SYNC halves of the chain.

Companion to ``test_fingerprint_telemetry.py`` (push + verify). Covers:

  * ZK9500 capture       -- ENROLL_SCANNER / ENROLL_SAMPLE / ENROLL_MERGE
  * the backend save     -- ENROLL_BACKEND (the only layer that sees the status)
  * the orchestration    -- ENROLL_START / ENROLL_BACKEND_REQ / ENROLL_MEMBER_SYNC
                            and the single terminal ENROLL_DONE
  * template arrival     -- FP_ARRIVED

HARD RULE: nothing here may reach the real
``C:\\ProgramData\\MonClub Access\\access\\access.db``. Every ``app.core.db``
entry point the enrolment worker calls is patched, and the sync helper is a pure
function called directly.
"""
from __future__ import annotations

import logging
import threading
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from tests.test_fingerprint_telemetry import tel_calls, tel_names


# --------------------------------------------------------------------------- #
# 1. Capture — app/sdk/zkfinger.py
# --------------------------------------------------------------------------- #

class TestCaptureTelemetry:
    """NOTE: this SDK exposes NO image-quality value -- ZKFPM_AcquireFingerprint
    returns (rc, template_length) and nothing else -- so a sample line reports
    SIZE, plus a db_match score only on the rejection path where one exists.
    Quality is genuinely unavailable here. [UNVERIFIED]"""

    @pytest.fixture
    def zf_tel(self, monkeypatch):
        import app.sdk.zkfinger as zf
        fake = MagicMock()
        monkeypatch.setattr(zf, "_tel", fake)
        return fake

    def _scanner(self, sizes=(300, 300, 300), match_scores=None):
        import app.sdk.zkfinger as zf
        zk = zf.ZKFinger.__new__(zf.ZKFinger)
        zk._log = MagicMock()
        zk.enroll_id = "e00042-abcd"
        zk.device_handle = object()
        zk.db_handle = object()
        zk.get_device_params = lambda: (256, 360, 92160)
        seq = list(sizes)
        scores = list(match_scores or [])

        def acquire(img_buf, tpl_buf):
            n = seq.pop(0)
            for i in range(min(n, len(tpl_buf))):
                tpl_buf[i] = (i % 251) + 1
            return 0, n

        zk._acquire_once = acquire
        zk.db_match = lambda a, b: (scores.pop(0) if scores else 100)
        zk.db_merge = lambda a, b, c: b"MERGED" * 20
        return zk

    def test_each_captured_sample_emits_size_and_the_enroll_id(self, zf_tel, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *_a: None)
        zk = self._scanner(sizes=(301, 302, 303))
        zk.enroll_3_samples(enroll_id="e00042-abcd")

        s = tel_calls(zf_tel, "ENROLL_SAMPLE")
        assert [x["sample"] for x in s] == [1, 2, 3]
        assert [x["size"] for x in s] == [301, 302, 303]
        assert all(x["result"] == "captured" for x in s)
        assert all(x["enroll_id"] == "e00042-abcd" for x in s)   # correlation key

    def test_a_rejected_sample_is_recorded_with_its_match_score(self, zf_tel, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *_a: None)
        # sample 2 scores below match_threshold -> rejected, then retried and kept
        zk = self._scanner(sizes=(300, 300, 300, 300), match_scores=[0, 90, 90])
        zk.enroll_3_samples(enroll_id="e1", match_threshold=1)

        rejected = [x for x in tel_calls(zf_tel, "ENROLL_SAMPLE") if x["result"] == "rejected"]
        assert len(rejected) == 1
        assert rejected[0]["score"] == 0
        assert rejected[0]["sample"] == 2

    def test_no_same_finger_check_still_emits_a_clean_captured_line(self, zf_tel, monkeypatch):
        """`score` is bound only inside the require_same_finger branch. With the
        check off, db_match is never called, so the captured line must not read it."""
        monkeypatch.setattr("time.sleep", lambda *_a: None)
        zk = self._scanner(sizes=(311, 312, 313))

        def must_not_run(*_a, **_k):
            raise AssertionError("db_match called with require_same_finger=False")

        zk.db_match = must_not_run
        zk.enroll_3_samples(enroll_id="e1", require_same_finger=False)

        s = tel_calls(zf_tel, "ENROLL_SAMPLE")
        assert len(s) == 3
        assert all(x["result"] == "captured" for x in s)
        assert all("score" not in x for x in s)

    def test_merge_success_reports_size_and_sample_count(self, zf_tel, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *_a: None)
        zk = self._scanner()
        reg = zk.enroll_3_samples(enroll_id="e1")

        m = tel_calls(zf_tel, "ENROLL_MERGE")
        assert len(m) == 1
        assert m[0]["ok"] is True
        assert m[0]["size"] == len(reg)
        assert m[0]["samples"] == 3

    def test_merge_failure_is_recorded_and_the_error_still_propagates(self, zf_tel, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *_a: None)
        import app.sdk.zkfinger as zf
        zk = self._scanner()

        def boom(a, b, c):
            raise zf.ZKFingerError("merge exploded")

        zk.db_merge = boom
        with pytest.raises(zf.ZKFingerError):
            zk.enroll_3_samples(enroll_id="e1")

        m = tel_calls(zf_tel, "ENROLL_MERGE")
        assert len(m) == 1 and m[0]["ok"] is False

    def test_capture_never_logs_template_bytes(self, zf_tel, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda *_a: None)
        zk = self._scanner()
        zk.db_merge = lambda a, b, c: b"SECRET-TEMPLATE-BYTES"
        zk.enroll_3_samples(enroll_id="e1")
        for _meth, args, kwargs in zf_tel.mock_calls:
            for v in list(args) + list(kwargs.values()):
                assert "SECRET-TEMPLATE-BYTES" not in str(v)


# --------------------------------------------------------------------------- #
# 2. Backend save — app/api/monclub_api.py
# --------------------------------------------------------------------------- #

class TestBackendCallTelemetry:
    """This is the ONLY layer that sees the raw HTTP status and error body; the
    caller receives them flattened into a MonClubApiError message."""

    @pytest.fixture
    def api_tel(self, monkeypatch):
        import app.api.monclub_api as ma
        fake = MagicMock()
        monkeypatch.setattr(ma, "_tel", fake)
        return fake

    def _api(self, status=200, body='{"status":true}'):
        import app.api.monclub_api as ma
        api = ma.MonClubApi.__new__(ma.MonClubApi)
        api.logger = MagicMock()
        api.endpoints = SimpleNamespace(create_user_fingerprint_url="https://example.invalid/fp")
        resp = MagicMock()
        resp.status_code = status
        resp.text = body
        resp.json = lambda: {"ok": True}
        api._session = MagicMock()
        api._session.post = MagicMock(return_value=resp)
        return api

    def _payload(self):
        return {"activeMembershipId": 30008, "fingerId": 1, "templateVersion": 10,
                "templateEncoding": "BASE64", "templateData": "SECRETTPL", "enabled": True}

    def test_success_records_status_and_the_membership_it_was_for(self, api_tel):
        api = self._api(status=201)
        api.create_user_fingerprint(token="t", payload=self._payload())

        ev = tel_calls(api_tel, "ENROLL_BACKEND")
        assert len(ev) == 1
        assert ev[0]["status"] == 201
        assert ev[0]["result"] == "ok"
        # correlation with the caller's ENROLL_BACKEND_REQ is by (am_id, finger_id)
        assert ev[0]["am_id"] == 30008
        assert ev[0]["finger_id"] == 1

    def test_rejection_records_the_status_and_the_error_body(self, api_tel):
        import app.api.monclub_api as ma
        body = ('{"status":false,"errorMsg":"You can only manage fingerprints for '
                'memberships in your own gym.","code":"FORBIDDEN"}')
        api = self._api(status=403, body=body)
        with pytest.raises(ma.MonClubApiError):
            api.create_user_fingerprint(token="t", payload=self._payload())

        ev = tel_calls(api_tel, "ENROLL_BACKEND")
        assert len(ev) == 1
        assert ev[0]["status"] == 403
        assert ev[0]["result"] == "rejected"
        # the BODY is the diagnostic: this exact 403 has twice been a wrong
        # activeMembershipId, not an actual permission problem.
        assert "own gym" in ev[0]["body"]

    def test_transport_failure_is_distinguished_from_a_rejection(self, api_tel):
        import app.api.monclub_api as ma
        api = self._api()
        api._session.post = MagicMock(side_effect=OSError("connection reset"))
        with pytest.raises(ma.MonClubApiError):
            api.create_user_fingerprint(token="t", payload=self._payload())

        ev = tel_calls(api_tel, "ENROLL_BACKEND")[0]
        assert ev["result"] == "request_failed"
        assert ev["status"] is None

    def test_backend_line_never_carries_the_template(self, api_tel):
        api = self._api()
        api.create_user_fingerprint(token="t", payload=self._payload())
        for _meth, args, kwargs in api_tel.mock_calls:
            for v in list(args) + list(kwargs.values()):
                assert "SECRETTPL" not in str(v)


# --------------------------------------------------------------------------- #
# 3. Orchestration — app/ui/app.py::_remote_enroll_worker
# --------------------------------------------------------------------------- #

def _main_app():
    try:
        from app.ui.app import MainApp
    except Exception as e:            # heavy module (Tkinter/scanner)
        pytest.skip(f"MainApp import unavailable: {e}")
    return MainApp


class _FakeScanner:
    """Stands in for ZKFinger. Records the enroll_id it was handed."""

    last: Dict[str, Any] = {}

    def __init__(self, *a, **kw):
        self.enroll_id = ""
        _FakeScanner.last = {"instance": self}

    def init(self):
        return None

    def open_device(self, index=0):
        return None

    def enroll_3_samples(self, **kw):
        _FakeScanner.last["enroll_id_at_capture"] = kw.get("enroll_id")
        return b"TEMPLATEBYTES"

    def close_device(self):
        return None

    def terminate(self):
        return None


def _run_enroll(monkeypatch, *, users, api=None, scanner=_FakeScanner,
                user_id=35, finger_id=1, am_override=None, enroll_id="e00001-aaaa",
                restrictions=None, sync_request=None):
    """Drive the real _remote_enroll_worker with every I/O edge stubbed."""
    MainApp = _main_app()
    import app.ui.app as app_module

    monkeypatch.setattr(app_module, "load_sync_cache",
                        lambda: SimpleNamespace(users=users), raising=False)
    monkeypatch.setattr(app_module, "load_auth_token",
                        lambda: SimpleNamespace(token="tok", email="op@example.invalid"),
                        raising=False)
    monkeypatch.setattr(app_module, "save_sync_cache", lambda *_a, **_k: None, raising=False)
    monkeypatch.setattr(app_module, "insert_offline_subresource",
                        lambda **_k: None, raising=False)
    monkeypatch.setattr(app_module, "ZKFinger", scanner, raising=False)
    monkeypatch.setattr(app_module, "to_b64", lambda b: "B64TEMPLATE", raising=False)
    monkeypatch.setattr(app_module, "to_hex", lambda b: "HEXTEMPLATE", raising=False)
    monkeypatch.setattr(app_module, "_encoding_to_backend", lambda e: "BASE64", raising=False)

    api = api or MagicMock()
    if not isinstance(api.create_user_fingerprint, MagicMock):
        pass

    self_obj = SimpleNamespace(
        logger=logging.getLogger("test-enroll-telemetry"),
        cfg=SimpleNamespace(zkfp_dll_path="libzkfp.dll", template_version=10,
                            template_encoding="base64", login_email="op@example.invalid"),
        _enroll_state_lock=threading.Lock(),
        _enroll_cancel_event=threading.Event(),
        _enroll_running=True,
        _restriction_reasons=lambda: (restrictions or []),
        _api=lambda: api,
        _request_running_ultra_sync=(sync_request or (lambda **_k: None)),
    )
    self_obj._find_user_membership = lambda uid: MainApp._find_user_membership(self_obj, uid)

    MainApp._remote_enroll_worker(
        self_obj, user_id, finger_id, "", "zk9500", am_override, enroll_id,
    )
    return self_obj


def _user(user_id, am_id, membership_id=30, name="Member"):
    return {"userId": user_id, "activeMembershipId": am_id,
            "membershipId": membership_id, "fullName": name}


@pytest.fixture
def app_tel(monkeypatch):
    import app.ui.app as app_module
    fake = MagicMock()
    monkeypatch.setattr(app_module, "_tel", fake)
    return fake


class TestEnrolStartTelemetry:
    def test_records_the_chosen_membership_and_its_source(self, monkeypatch, app_tel):
        _run_enroll(monkeypatch, users=[_user(35, 30008)])

        st = tel_calls(app_tel, "ENROLL_START")
        assert len(st) == 1
        assert st[0]["enroll_id"] == "e00001-aaaa"
        assert st[0]["user_id"] == 35
        assert st[0]["finger_id"] == 1
        assert st[0]["am_id"] == 30008
        assert st[0]["am_source"] == "local-cache"

    def test_multi_membership_candidates_are_named(self, monkeypatch, app_tel):
        """20 of 914 members at OXYGENE_FIT carry two active memberships and the
        newest is picked. Which candidates were on the table has to be in the log,
        because a wrong pick is otherwise a silent wrong write."""
        _run_enroll(monkeypatch, users=[_user(35, 29849), _user(35, 30008)])

        st = tel_calls(app_tel, "ENROLL_START")[0]
        assert st["am_id"] == 30008              # the newest
        assert st["candidates"] == 2
        assert "29849" in st["candidate_ids"] and "30008" in st["candidate_ids"]

    def test_an_explicit_caller_id_is_recorded_as_such(self, monkeypatch, app_tel):
        _run_enroll(monkeypatch, users=[_user(35, 29849), _user(35, 30008)],
                    am_override=29849)
        st = tel_calls(app_tel, "ENROLL_START")[0]
        assert st["am_id"] == 29849
        assert st["am_source"] == "caller"


class TestScannerTelemetry:
    """ENROLL_SCANNER is emitted at two layers: the driver names the DLL PATH it
    actually initialised (rc=-1 is almost always an unresolved runtime-loaded
    dependency, so the folder used IS the diagnostic), and the orchestrator names
    the device-open result."""

    def test_init_reports_rc_and_the_dll_path(self, monkeypatch):
        import app.sdk.zkfinger as zf
        from pathlib import Path
        fake = MagicMock()
        monkeypatch.setattr(zf, "_tel", fake)

        zk = zf.ZKFinger.__new__(zf.ZKFinger)
        zk._log = MagicMock()
        zk.enroll_id = "e00003-dddd"
        zk._dll = SimpleNamespace(ZKFPM_Init=lambda: 0)
        zk._runtime = zf.ZKFingerRuntime(dll_path=Path("C:/app/sdk/libzkfp.dll"),
                                         dll_dir=Path("C:/app/sdk"))
        zk.load = lambda: None
        zk.init()

        ev = tel_calls(fake, "ENROLL_SCANNER")
        assert len(ev) == 1
        assert ev[0]["phase"] == "init"
        assert ev[0]["rc"] == 0 and ev[0]["ok"] is True
        assert ev[0]["enroll_id"] == "e00003-dddd"
        assert "libzkfp.dll" in ev[0]["dll_path"]
        assert ev[0]["dll_dir"].endswith("sdk")

    def test_init_failure_records_the_rc_and_still_raises(self, monkeypatch):
        import app.sdk.zkfinger as zf
        from pathlib import Path
        fake = MagicMock()
        monkeypatch.setattr(zf, "_tel", fake)

        zk = zf.ZKFinger.__new__(zf.ZKFinger)
        zk._log = MagicMock()
        zk.enroll_id = "e1"
        zk._dll = SimpleNamespace(ZKFPM_Init=lambda: -1)
        zk._runtime = zf.ZKFingerRuntime(dll_path=Path("C:/app/sdk/libzkfp.dll"),
                                         dll_dir=Path("C:/app/sdk"))
        zk._preloaded = {}
        zk.load = lambda: None
        with pytest.raises(zf.ZKFingerError):
            zk.init()

        ev = tel_calls(fake, "ENROLL_SCANNER")[0]
        assert ev["rc"] == -1 and ev["ok"] is False

    def test_device_open_success_is_recorded(self, monkeypatch, app_tel):
        _run_enroll(monkeypatch, users=[_user(35, 30008)])
        ev = [e for e in tel_calls(app_tel, "ENROLL_SCANNER") if e["phase"] == "open"]
        assert len(ev) == 1
        assert ev[0]["ok"] is True
        assert ev[0]["enroll_id"] == "e00001-aaaa"

    def test_device_open_failure_is_recorded_as_a_capture_fault(self, monkeypatch, app_tel):
        class NoDevice(_FakeScanner):
            def open_device(self, index=0):
                raise RuntimeError("no scanner attached")

        _run_enroll(monkeypatch, users=[_user(35, 30008)], scanner=NoDevice)

        ev = [e for e in tel_calls(app_tel, "ENROLL_SCANNER") if e["phase"] == "open"]
        assert len(ev) == 1 and ev[0]["ok"] is False
        assert "no scanner attached" in ev[0]["err"]
        assert tel_calls(app_tel, "ENROLL_DONE")[0]["outcome"] == "capture_failed"


class TestEnrolBackendRequestTelemetry:
    def test_request_summary_carries_a_digest_never_the_template(self, monkeypatch, app_tel):
        _run_enroll(monkeypatch, users=[_user(35, 30008)])

        req = tel_calls(app_tel, "ENROLL_BACKEND_REQ")
        assert len(req) == 1
        assert req[0]["am_id"] == 30008
        assert req[0]["finger_id"] == 1
        assert req[0]["encoding"] == "BASE64"
        assert req[0]["template_version"] == 10
        assert req[0]["tpl_chars"] == len("B64TEMPLATE")
        assert len(req[0]["tpl_sha1"]) == 8      # sha1[:8], not the payload
        for _m, args, kwargs in app_tel.mock_calls:
            for v in list(args) + list(kwargs.values()):
                assert "B64TEMPLATE" not in str(v)


class TestEnrolMemberSyncTelemetry:
    def test_the_targeted_sync_request_is_recorded(self, monkeypatch, app_tel):
        seen = {}
        _run_enroll(monkeypatch, users=[_user(35, 30008)],
                    sync_request=lambda **kw: seen.update(kw))

        ms = tel_calls(app_tel, "ENROLL_MEMBER_SYNC")
        assert len(ms) == 1
        assert ms[0]["ok"] is True
        assert ms[0]["am_id"] == 30008
        assert seen["reason"] == "FINGERPRINT_ENROLLED"

    def test_a_failed_sync_request_is_visible_but_does_not_flip_the_outcome(
            self, monkeypatch, app_tel):
        """Best-effort by design -- the backend save really happened. But an
        invisible failure means the member is refused at the turnstile until the
        next periodic full sync while every screen says success."""
        def boom(**_kw):
            raise RuntimeError("worker not running")

        _run_enroll(monkeypatch, users=[_user(35, 30008)], sync_request=boom)

        ms = tel_calls(app_tel, "ENROLL_MEMBER_SYNC")[0]
        assert ms["ok"] is False
        assert "worker not running" in ms["err"]
        assert tel_calls(app_tel, "ENROLL_DONE")[0]["outcome"] == "ok"


class TestEnrolDoneTelemetry:
    """ONE terminal line per enrolment, on every exit path."""

    def test_success(self, monkeypatch, app_tel):
        _run_enroll(monkeypatch, users=[_user(35, 30008)])
        d = tel_calls(app_tel, "ENROLL_DONE")
        assert len(d) == 1
        assert d[0]["outcome"] == "ok"
        assert d[0]["enroll_id"] == "e00001-aaaa"
        assert d[0]["am_id"] == 30008
        assert isinstance(d[0]["total_ms"], int)

    def test_backend_rejection(self, monkeypatch, app_tel):
        import app.api.monclub_api as ma
        api = MagicMock()
        api.create_user_fingerprint.side_effect = ma.MonClubApiError(
            "createUserFingerprint failed: HTTP 403 -> forbidden")
        _run_enroll(monkeypatch, users=[_user(35, 30008)], api=api)

        d = tel_calls(app_tel, "ENROLL_DONE")
        assert len(d) == 1
        assert d[0]["outcome"] == "backend_rejected"
        assert tel_calls(app_tel, "ENROLL_BACKEND_ERR")[0]["am_id"] == 30008

    def test_capture_failure(self, monkeypatch, app_tel):
        import app.sdk.zkfinger as zf

        class Failing(_FakeScanner):
            def enroll_3_samples(self, **kw):
                raise zf.ZKFingerError("Timeout waiting for fingerprint sample 1/3")

        _run_enroll(monkeypatch, users=[_user(35, 30008)], scanner=Failing)

        d = tel_calls(app_tel, "ENROLL_DONE")
        assert len(d) == 1
        assert d[0]["outcome"] == "capture_failed"

    def test_cancelled_capture_is_not_reported_as_a_capture_fault(self, monkeypatch, app_tel):
        import app.sdk.zkfinger as zf

        class Cancelling(_FakeScanner):
            def enroll_3_samples(self, **kw):
                raise zf.ZKFingerError("Cancelled.")

        _run_enroll(monkeypatch, users=[_user(35, 30008)], scanner=Cancelling)
        # It still lands on the capture family -- the point is that ONE line exists.
        assert len(tel_calls(app_tel, "ENROLL_DONE")) == 1

    def test_no_membership_resolves_to_its_own_outcome(self, monkeypatch, app_tel):
        api = MagicMock()
        api.get_sync_data.return_value = {"users": []}
        _run_enroll(monkeypatch, users=[_user(99, 30008)], api=api, user_id=35)

        d = tel_calls(app_tel, "ENROLL_DONE")
        assert len(d) == 1
        assert d[0]["outcome"] == "no_membership"
        assert d[0]["am_id"] is None
        # it never reached the scanner or the backend
        assert tel_calls(app_tel, "ENROLL_BACKEND_REQ") == []

    def test_restricted_contract_resolves_to_its_own_outcome(self, monkeypatch, app_tel):
        _run_enroll(monkeypatch, users=[_user(35, 30008)],
                    restrictions=["contract inactif"])
        d = tel_calls(app_tel, "ENROLL_DONE")
        assert len(d) == 1
        assert d[0]["outcome"] == "restricted"

    def test_pre_flight_sync_failure_resolves_to_sync_failed(self, monkeypatch, app_tel):
        api = MagicMock()
        api.get_sync_data.side_effect = RuntimeError("network down")
        _run_enroll(monkeypatch, users=[], api=api, user_id=35)

        d = tel_calls(app_tel, "ENROLL_DONE")
        assert len(d) == 1
        assert d[0]["outcome"] == "sync_failed"

    def test_the_enroll_id_reaches_the_scanner(self, monkeypatch, app_tel):
        _run_enroll(monkeypatch, users=[_user(35, 30008)], enroll_id="e00007-zzzz")
        assert _FakeScanner.last["enroll_id_at_capture"] == "e00007-zzzz"
        assert _FakeScanner.last["instance"].enroll_id == "e00007-zzzz"

    def test_every_line_of_one_enrolment_shares_the_key(self, monkeypatch, app_tel):
        _run_enroll(monkeypatch, users=[_user(35, 30008)], enroll_id="e00009-kkkk")
        emitted = [name for name in tel_names(app_tel) if name.startswith("ENROLL_")]
        assert {"ENROLL_START", "ENROLL_BACKEND_REQ",
                "ENROLL_MEMBER_SYNC", "ENROLL_DONE"} <= set(emitted)
        for _m, args, kwargs in app_tel.mock_calls:
            if args and str(args[0]).startswith("ENROLL_"):
                assert kwargs.get("enroll_id") == "e00009-kkkk", args[0]


# --------------------------------------------------------------------------- #
# 4. Sync — template arrival (app/core/db.py::_log_incoming_templates)
# --------------------------------------------------------------------------- #

class TestTemplateArrivalTelemetry:
    @pytest.fixture
    def db_tel(self, monkeypatch):
        import app.core.db as db
        fake = MagicMock()
        monkeypatch.setattr(db, "_tel", fake)
        return fake

    def _users(self, n_with, n_without=0, fingers=1):
        out: List[Dict[str, Any]] = []
        for i in range(n_with):
            out.append({
                "userId": 100 + i, "activeMembershipId": 30000 + i,
                "fingerprints": [{"fingerId": f, "templateData": "T" * 700,
                                  "templateVersion": 10} for f in range(fingers)],
            })
        for i in range(n_without):
            out.append({"userId": 900 + i, "activeMembershipId": 40000 + i,
                        "fingerprints": []})
        return out

    def test_delta_names_exactly_who_changed(self, db_tel):
        import app.core.db as db
        db._log_incoming_templates(self._users(3, n_without=2), True)

        ev = tel_calls(db_tel, "FP_ARRIVED")
        assert len(ev) == 1
        assert ev[0]["delta_mode"] is True
        assert ev[0]["incoming_users"] == 5
        assert ev[0]["members_with_tpl"] == 3
        assert ev[0]["templates"] == 3
        # in a delta every incoming user IS a changed user, so the ids are the answer
        assert ev[0]["am_ids"] == "30000;30001;30002"

    def test_a_full_refresh_reports_counts_and_says_ids_were_omitted(self, db_tel):
        import app.core.db as db
        db._log_incoming_templates(self._users(200), False)

        ev = tel_calls(db_tel, "FP_ARRIVED")[0]
        assert ev["delta_mode"] is False
        assert ev["members_with_tpl"] == 200
        assert ev["am_ids"] is None
        assert ev["ids_omitted"] is True

    def test_multi_finger_members_are_counted_per_template(self, db_tel):
        import app.core.db as db
        db._log_incoming_templates(self._users(2, fingers=3), True)
        ev = tel_calls(db_tel, "FP_ARRIVED")[0]
        assert ev["members_with_tpl"] == 2
        assert ev["templates"] == 6

    def test_silent_when_no_templates_arrived(self, db_tel):
        import app.core.db as db
        db._log_incoming_templates(self._users(0, n_without=50), True)
        assert tel_calls(db_tel, "FP_ARRIVED") == []

    def test_never_logs_template_bytes(self, db_tel):
        import app.core.db as db
        users = [{"userId": 1, "activeMembershipId": 2,
                  "fingerprints": [{"fingerId": 0, "templateData": "SECRETBIOMETRIC"}]}]
        db._log_incoming_templates(users, True)
        for _m, args, kwargs in db_tel.mock_calls:
            for v in list(args) + list(kwargs.values()):
                assert "SECRETBIOMETRIC" not in str(v)

    def test_malformed_payloads_never_raise(self, db_tel):
        import app.core.db as db
        for bad in (None, "not a list", [None, 3, "x"],
                    [{"fingerprints": "not-a-list"}], [{"fingerprints": [None]}]):
            db._log_incoming_templates(bad, True)     # must not raise
