"""Negative-cache regression tests for app.core.popup_image_cache.

Prod evidence (2026-06-24): ~31 roster image URLs permanently 404, but a 404 was
never persisted, so prefetch()'s os.path.isfile() skip-guard never tripped and
the same doomed URLs were re-fetched every 5-min cycle on both workers, AND every
popup serve miss paid a fresh 200-850ms doomed round-trip. These tests pin the
negative cache that fixes that: hard 404/410 -> long TTL, transient -> short
backoff, success -> cleared.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import app.core.popup_image_cache as pic


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    # Point the cache dir at a temp folder and reset the module-global neg cache.
    monkeypatch.setattr(pic, "_cache_dir_cached", str(tmp_path))
    with pic._neg_lock:
        pic._neg_cache.clear()
    yield
    with pic._neg_lock:
        pic._neg_cache.clear()


def _resp(status: int, content: bytes = b"PNGDATA"):
    r = MagicMock()
    r.status_code = status
    r.content = content
    return r


def _norm(u: str) -> str:
    return pic.normalize_url(u)


def test_404_marks_known_bad_and_prefetch_skips():
    url = _norm("https://res.cloudinary.com/x/accounts/1/y.png.png")
    with patch.object(pic, "requests") as rq:
        rq.get.return_value = _resp(404)
        assert pic.fetch_and_cache(url) is None
    assert pic.is_known_bad(url) is True
    # prefetch() must now short-circuit BEFORE submitting to the pool.
    with patch.object(pic, "_get_pool") as gp:
        pic.prefetch(url)
        gp.assert_not_called()


def test_410_is_hard_bad():
    url = _norm("https://res.cloudinary.com/x/gone.png")
    with patch.object(pic, "requests") as rq:
        rq.get.return_value = _resp(410)
        pic.fetch_and_cache(url)
    assert pic.is_known_bad(url) is True


def test_5xx_is_transient_but_currently_bad():
    url = _norm("https://res.cloudinary.com/x/flaky.png")
    with patch.object(pic, "requests") as rq:
        rq.get.return_value = _resp(503)
        pic.fetch_and_cache(url)
    # marked bad now (short backoff) so we don't hammer a struggling backend...
    assert pic.is_known_bad(url) is True


def test_transient_ttl_expires_so_flaky_link_recovers(monkeypatch):
    url = _norm("https://res.cloudinary.com/x/recover.png")
    monkeypatch.setattr(pic, "_NEG_TTL_TRANSIENT_SEC", 0.0)  # expire immediately
    with patch.object(pic, "requests") as rq:
        rq.get.return_value = _resp(500)
        pic.fetch_and_cache(url)
    # ...but the short TTL means a retry is allowed almost immediately.
    assert pic.is_known_bad(url) is False


def test_success_clears_prior_failure():
    url = _norm("https://res.cloudinary.com/x/ok.png")
    pic._neg_mark(url, hard=True)
    assert pic.is_known_bad(url) is True
    with patch.object(pic, "requests") as rq:
        rq.get.return_value = _resp(200, content=b"REALPNGBYTES")
        out = pic.fetch_and_cache(url)
    assert out is not None and out[0] == b"REALPNGBYTES"
    assert pic.is_known_bad(url) is False  # recovered -> forgiven


def test_unknown_url_is_not_bad():
    assert pic.is_known_bad(_norm("https://res.cloudinary.com/x/fresh.png")) is False


def test_cache_dir_is_memoized_stable(tmp_path):
    # The fixture pinned _cache_dir_cached to tmp_path; cache_dir() must return
    # that memoized value on every call without re-resolving.
    a = pic.cache_dir()
    b = pic.cache_dir()
    assert a == b == str(tmp_path)


def test_cache_dir_resolves_under_images_when_unmemoized(monkeypatch):
    # With no memoized value, it resolves to the real <data>/cache/images dir.
    monkeypatch.setattr(pic, "_cache_dir_cached", None)
    assert pic.cache_dir().replace("\\", "/").endswith("cache/images")
