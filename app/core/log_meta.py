"""Metadata derived from finalized log contents."""
from __future__ import annotations

from datetime import datetime
import re

_VERSION = re.compile(r'=== MonClub Access (\S+) ')


def scan_log_text(text: str) -> dict:
    lines = text.splitlines()
    first = last = None
    versions = []
    for line in lines:
        try:
            stamp = datetime.strptime(line[:23], '%Y-%m-%d %H:%M:%S,%f').isoformat(timespec='seconds')
            if first is None:
                first = stamp
            last = stamp
        except ValueError:
            pass
        match = _VERSION.search(line)
        if match and match[1] not in versions and len(versions) < 5:
            versions.append(match[1][:64])
    return {
        'lines': len(lines),
        'errors': sum('| ERROR |' in line or '| CRITICAL |' in line for line in lines),
        'warnings': sum('| WARNING |' in line for line in lines),
        'firstLineAt': first, 'lastLineAt': last, 'appVersions': versions,
    }


def build_header_text(app_version: str, pc_name: str | None, os_version: str, arch: str) -> str:
    parts = [f'MonClub Access {app_version}']
    if pc_name:
        parts.append(pc_name)
    return ' · '.join([*parts, os_version, arch])
