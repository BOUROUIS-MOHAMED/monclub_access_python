"""The one version parser / comparator of the updater (design section 5.2; D29, D38).

``MAJOR.MINOR.PATCH[-pre]`` with SemVer 2.0 precedence: ``1.5.0-beta.1 < 1.5.0``.
No ``v`` prefix, no ``+build`` metadata, no surrounding spaces. The backend (L1) uses the
same rules; tests/fixtures/semver_precedence.json is the shared table.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

ParsedVersion = Tuple[int, int, int, Tuple[str, ...]]


def parse_version(value: object) -> Optional[ParsedVersion]:
    """(major, minor, patch, pre-release identifiers) or None when not a valid version."""
    if not isinstance(value, str):
        return None
    m = _VERSION_RE.match(value)
    if not m:
        return None
    pre = tuple(m.group(4).split(".")) if m.group(4) else ()
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def installed_version_text(raw: object) -> str:
    """The version part of a version.json value such as ``"1.4.35"`` or ``"1.4.35 Orion"``."""
    text = str(raw or "").strip()
    return text.split()[0] if text else ""


def _compare_pre(a: Tuple[str, ...], b: Tuple[str, ...]) -> int:
    if a == b:
        return 0
    if not a:
        return 1  # a release ranks above any of its pre-releases
    if not b:
        return -1
    for x, y in zip(a, b):
        if x == y:
            continue
        x_num, y_num = x.isdigit(), y.isdigit()
        if x_num and y_num:
            return -1 if int(x) < int(y) else 1
        if x_num != y_num:
            return -1 if x_num else 1  # numeric identifiers rank lower
        return -1 if x < y else 1
    return -1 if len(a) < len(b) else 1


def compare_versions(a: str, b: str) -> Optional[int]:
    """-1 / 0 / 1 for a < b / a == b / a > b; None when either is not a valid version."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    if pa[:3] != pb[:3]:
        return -1 if pa[:3] < pb[:3] else 1
    return _compare_pre(pa[3], pb[3])


def is_newer(candidate: str, installed: str) -> bool:
    """True only when both parse and candidate > installed."""
    return compare_versions(candidate, installed) == 1


__all__ = ["compare_versions", "installed_version_text", "is_newer", "parse_version"]
