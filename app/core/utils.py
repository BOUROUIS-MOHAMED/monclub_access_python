from __future__ import annotations

import base64
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple


APP_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = APP_DIR / "data"
LOG_DIR = DATA_DIR / "logs"
CONFIG_PATH = DATA_DIR / "config.json"
DB_PATH = DATA_DIR / "app.db"


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def now_iso() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def encode_ansi(s: str) -> bytes:
    # Windows ANSI codepage
    return s.encode("mbcs", errors="replace")


def decode_ansi(b: bytes) -> str:
    return b.decode("mbcs", errors="replace")


def mask_password(pwd: str) -> str:
    if not pwd:
        return ""
    return "*" * min(8, len(pwd))


def safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def from_b64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def to_hex(data: bytes) -> str:
    return data.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def parse_device_text(text: str) -> List[Dict[str, str]]:
    """
    PullSDK GetDeviceData output can be:
    - key=value\\tkey=value format (one record per line)
    - OR CSV-like with header line

    Returns list of dict rows.
    """
    lines = [ln.strip() for ln in text.replace("\r", "").split("\n") if ln.strip()]
    if not lines:
        return []

    first = lines[0]
    rows: List[Dict[str, str]] = []

    if "=" in first and "\t" in first:
        # key=value tab format
        for ln in lines:
            kv: Dict[str, str] = {}
            parts = [p for p in ln.split("\t") if "=" in p]
            for p in parts:
                k, v = p.split("=", 1)
                kv[k.strip()] = v.strip()
            if kv:
                rows.append(kv)
        return rows

    # CSV-like
    headers = [h.strip() for h in first.split(",")]
    for ln in lines[1:]:
        cols = [c.strip() for c in ln.split(",")]
        kv: Dict[str, str] = {}
        for i in range(min(len(headers), len(cols))):
            if headers[i]:
                kv[headers[i]] = cols[i]
        if kv:
            rows.append(kv)
    return rows


def dict_union_keys(rows: List[Dict[str, str]]) -> List[str]:
    seen: List[str] = []
    for r in rows:
        for k in r.keys():
            if k not in seen:
                seen.append(k)
    return seen


def load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
