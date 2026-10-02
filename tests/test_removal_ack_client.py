"""The removal-request acknowledgement client (ULTRA merge plan 3, Task 4; backend plan 1 Task 9):
one endpoint for D11 and D13, the gym JWT, three outcomes. A fake session: nothing leaves the PC."""
from __future__ import annotations

import json
import logging

import pytest

from app.api import monclub_api as m

RID = "0f8fad5b-d9cb-469f-a165-70867728950e"


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self.text = body if isinstance(body, str) else json.dumps(body)


class _Session:
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "json": json, "headers": dict(headers or {}), "timeout": timeout})
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _api(answer):
    api = m.MonClubApi(m.ApiEndpoints(
        login_url="https://api.example.test/api/v1/public/access/v1/gym/login",
        sync_url="https://api.example.test/api/v1/manager/gym/access/v1/users/get_gym_users",
        create_user_fingerprint_url="", latest_release_url=""), logging.getLogger("t"))
    api._session = _Session(answer)
    return api


def _ack(api, **kw):
    args = dict(token="jwt", device_id=12, request_id=RID, result_code="ERASED",
                result_detail="templatev10=40 template=0")
    args.update(kw)
    return api.ack_removal_request(**args)


def test_the_ack_posts_to_the_one_endpoint_with_the_gym_token():
    api = _api(_Resp(200, {"requestId": RID, "kind": "FINGERPRINTS", "status": "DONE", "changed": True}))
    out = _ack(api)
    [call] = api._session.calls
    assert call["url"] == ("https://api.example.test/api/v1/manager/gym/access/v1/devices/12/"
                           f"removal-requests/{RID}/ack")
    assert call["headers"]["Authorization"] == "Bearer jwt"
    assert call["json"] == {"resultCode": "ERASED", "resultDetail": "templatev10=40 template=0"}
    assert out["outcome"] == m.ACK_DONE and out["status"] == "DONE" and out["httpStatus"] == 200


def test_a_late_ack_of_a_cancelled_request_also_stops_the_retries():
    api = _api(_Resp(200, {"requestId": RID, "kind": "CARDS", "status": "CANCELLED", "changed": False}))
    out = _ack(api)
    assert out["outcome"] == m.ACK_DONE and out["status"] == "CANCELLED"


def test_the_result_fields_are_cut_to_the_server_columns():
    api = _api(_Resp(200, {"status": "DONE"}))
    _ack(api, result_code="X" * 50, result_detail="d" * 400)
    body = api._session.calls[0]["json"]
    assert len(body["resultCode"]) == 32 and len(body["resultDetail"]) == 255


def test_a_404_naming_the_request_is_gone_not_retried():
    api = _api(_Resp(404, {"status": False, "errorMsg": "not found", "code": "REMOVAL_REQUEST_NOT_FOUND"}))
    assert _ack(api)["outcome"] == m.ACK_GONE


@pytest.mark.parametrize("answer", [
    _Resp(404, "<html>Not Found</html>"),                      # a backend without the route
    _Resp(401, {"status": False, "code": "UNAUTHORIZED"}),
    _Resp(503, "busy"),
    ConnectionError("offline"),
])
def test_every_other_answer_is_retried_later(answer):
    out = _ack(_api(answer))
    assert out["outcome"] == m.ACK_RETRY and out["detail"]
