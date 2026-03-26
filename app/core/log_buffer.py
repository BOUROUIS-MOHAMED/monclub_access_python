"""
Lightweight log buffer with adjacent-duplicate collapsing.

The Access and TV shells both feed their in-memory logs through this buffer,
so improving it here upgrades the experience for both apps at once.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Dict, List, Optional, Tuple


_TIMESTAMP_FORMATS: Tuple[str, ...] = (
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)

_TOKEN_PATTERNS: Dict[str, Tuple[re.Pattern[str], ...]] = {
    "door": (
        re.compile(r"(?i)\bdoor(?:id|number)?\s*=\s*([^\s|,;]+)"),
        re.compile(r"(?i)\bauthorizedoorid\s*=\s*([^\s|,;]+)"),
    ),
    "cardId": (
        re.compile(r"(?i)\bcardid\s*=\s*([^\s|,;]+)"),
        re.compile(r"(?i)\bcardno\s*=\s*([^\s|,;]+)"),
        re.compile(r"(?i)\bcode\s*=\s*([^\s|,;]+)"),
    ),
    "deviceId": (
        re.compile(r"(?i)\bdeviceid\s*=\s*([^\s|,;]+)"),
    ),
    "userId": (
        re.compile(r"(?i)\buserid\s*=\s*([^\s|,;]+)"),
    ),
    "mode": (
        re.compile(r"(?i)\bmode\s*=\s*([^\s|,;]+)"),
    ),
}


def _normalize_level(level: str) -> str:
    return str(level or "INFO").strip().upper() or "INFO"


def _normalize_text(line: str) -> str:
    txt = str(line or "")
    txt = txt.replace("\r", " ").replace("\n", " ")
    txt = re.sub(r"\s+", " ", txt).strip()
    return txt or "(empty log line)"


def _normalize_timestamp(value: Optional[str]) -> str:
    raw = str(value or "").strip()
    if raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat(timespec="milliseconds")
        except Exception:
            pass
        for fmt in _TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(raw, fmt).isoformat(timespec="milliseconds")
            except Exception:
                continue
    return datetime.now().isoformat(timespec="milliseconds")


def _detect_category(level: str, text: str, tokens: Dict[str, str]) -> str:
    lower = text.lower()
    if any(key in tokens for key in ("door", "cardId", "userId")):
        return "ACCESS"
    if any(word in lower for word in ("snapshot", "binding", "player", "screen", "monitor", "[tv", "monclub tv", "host")):
        return "TV"
    if "update" in lower:
        return "UPDATE"
    if any(word in lower for word in ("login", "logout", "auth")):
        return "AUTH"
    if "api" in lower:
        return "API"
    if level in {"ERROR", "WARNING", "WARN", "CRITICAL"}:
        return "ALERT"
    return "SYSTEM"


def _extract_tokens(level: str, text: str) -> Dict[str, str]:
    tokens: Dict[str, str] = {"level": _normalize_level(level)}
    for key, patterns in _TOKEN_PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                value = match.group(1).strip()
                if value:
                    tokens[key] = value
                break
    tokens["category"] = _detect_category(level, text, tokens)
    return tokens


def _format_text(raw_text: str, repeat_count: int) -> str:
    if repeat_count <= 1:
        return raw_text
    return f"{raw_text} (x{repeat_count})"


@dataclass(slots=True)
class LogEntry:
    id: int
    revision: int
    level: str
    raw_text: str
    text: str
    repeat_count: int
    first_seen_at: str
    last_seen_at: str
    tokens: Dict[str, str]

    def clone(self) -> "LogEntry":
        return replace(self, tokens=dict(self.tokens))


class LogBuffer:
    """Thread-safe ring buffer for structured log lines."""

    def __init__(self, max_lines: int = 5000):
        self._buffer: List[LogEntry] = []
        self._lock = threading.Lock()
        self._max_lines = max_lines
        self._next_id = 1
        self._revision = 0

    def append_log(self, level: str, line: str, timestamp: Optional[str] = None) -> None:
        lvl = _normalize_level(level)
        raw_text = _normalize_text(line)
        seen_at = _normalize_timestamp(timestamp)

        with self._lock:
            if self._buffer:
                last = self._buffer[-1]
                if last.level == lvl and last.raw_text == raw_text:
                    self._revision += 1
                    last.revision = self._revision
                    last.repeat_count += 1
                    last.last_seen_at = seen_at
                    last.text = _format_text(last.raw_text, last.repeat_count)
                    return

            self._revision += 1
            entry = LogEntry(
                id=self._next_id,
                revision=self._revision,
                level=lvl,
                raw_text=raw_text,
                text=_format_text(raw_text, 1),
                repeat_count=1,
                first_seen_at=seen_at,
                last_seen_at=seen_at,
                tokens=_extract_tokens(lvl, raw_text),
            )
            self._next_id += 1
            self._buffer.append(entry)
            if len(self._buffer) > self._max_lines:
                self._buffer = self._buffer[-self._max_lines:]

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
            self._revision += 1

    def snapshot(self) -> List[LogEntry]:
        with self._lock:
            return [entry.clone() for entry in self._buffer]

    def changes_since(self, revision: int) -> Tuple[int, List[LogEntry]]:
        with self._lock:
            current_revision = self._revision
            if revision >= current_revision:
                return current_revision, []
            changed = [entry.clone() for entry in self._buffer if entry.revision > revision]
            return current_revision, changed

    def get_revision(self) -> int:
        with self._lock:
            return self._revision

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)
