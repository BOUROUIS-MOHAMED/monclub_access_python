import os

with open('tmp/tv_player_block.pyfrag', 'r', encoding='utf-8') as f:
    code = f.read()

code = code.replace('PLAYER_RENDER_', 'RENDER_MODE_')
code = code.replace('PLAYER_FALLBACK_', 'FALLBACK_REASON_')
code = code.replace('_load_binding_row(conn, bid)', 'get_tv_screen_binding(binding_id=bid)')
code = code.replace('_load_binding_row(conn, int(binding_id))', 'get_tv_screen_binding(binding_id=int(binding_id))')
code = code.replace('_build_activation_status(screen_id=sid)', 'evaluate_tv_activation(screen_id=sid)')
code = code.replace('state = (activation or {}).get("state") or {}', 'state = activation')
code = code.replace('_load_tv_player_state_row(conn, bid)', 'load_tv_player_state(binding_id=bid)')
code = code.replace('PLAYER_STATE_FRESHNESS_SECONDS', '60')

start_idx = code.find('def _parse_minute_of_day')
if start_idx == -1:
    print("Could not find start index")
    exit(1)

code = code[start_idx:]

prepend = """
# ---------------------------------------------------------------------------
# 14) tv_player_state Core Processing Helpers (A6)
# ---------------------------------------------------------------------------

import re
from datetime import datetime
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

def _safe_str(v, default=""):
    if v is None:
        return default
    return str(v).strip()

def _binding_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).lower().strip()
    return s in ("1", "true", "yes", "on", "y")

def _first(d, *keys):
    if not isinstance(d, dict):
        return None
    for k in keys:
        if k in d and d.get(k) is not None:
            return d[k]
    return None

"""

with open('app/core/tv_local_cache.py', 'a', encoding='utf-8') as f:
    f.write('\\n' + prepend + code)

print("Injected successfully!")
