"""shared/update_versions.py against the shared version table (D29, D38)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.update_versions import compare_versions, installed_version_text, is_newer, parse_version

TABLE = json.loads((Path(__file__).parent / "fixtures" / "semver_precedence.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("a,b", TABLE["ascending"])
def test_shared_table_ascending_pairs(a, b):
    assert compare_versions(a, b) == -1
    assert compare_versions(b, a) == 1
    assert is_newer(b, a) is True
    assert is_newer(a, b) is False


@pytest.mark.parametrize("a,b", TABLE["equal"])
def test_shared_table_equal_pairs(a, b):
    assert compare_versions(a, b) == 0
    assert is_newer(a, b) is False


@pytest.mark.parametrize("value", TABLE["invalid"])
def test_shared_table_invalid_versions(value):
    assert parse_version(value) is None
    assert compare_versions(value, "1.0.0") is None
    assert is_newer(value, "0.0.1") is False
    assert is_newer("9.9.9", value) is False


def test_a_prerelease_is_parsed_not_ignored():
    assert parse_version("1.4.36-beta") == (1, 4, 36, ("beta",))
    assert is_newer("1.4.36-beta", "1.4.35") is True


def test_installed_version_text_drops_a_codename():
    assert installed_version_text("1.4.35 Orion") == "1.4.35"
    assert installed_version_text("  1.5.0  ") == "1.5.0"
    assert installed_version_text(None) == ""


def test_a_trailing_newline_is_not_a_version():
    assert parse_version("1.5.0\n") is None
