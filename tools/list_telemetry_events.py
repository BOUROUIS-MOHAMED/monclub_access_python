#!/usr/bin/env python3
"""List every `[T]` telemetry event name emitted under app/.

Why this exists: there is no runtime registry of event names, so
``guide_for_agents_and_dev.md`` §10 is the only index — and an index nobody can
check drifts silently. This makes "is §10 still complete?" a command.

A naive ``grep '_tel.event("NAME"'`` MISSES most of them, two ways:

  1. multi-line calls -- ``_tel.event(\\n    "NAME", worker=...)`` is the common
     shape once an event has more than three fields;
  2. helper-emitted calls -- ``_enroll_tel("NAME", enroll_id, ...)`` in
     app/sdk/zkfinger.py wraps _tel so the driver can stamp the correlation key.

Both are why the count below (100+) is far higher than a single-line grep finds.

Usage:
    python tools/list_telemetry_events.py            # one name per line
    python tools/list_telemetry_events.py --where    # name -> file:line sites
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# _tel.event( / _tel.warn( / _tel.snapshot_event( / _tel.timed( / _tel.profile(
# / _tel.span(, plus the _enroll_tel( helper. `re.S` is not needed: \s* already
# spans the newline in a wrapped call.
_PATTERNS = (
    re.compile(r"""_tel\.(?:event|warn|snapshot_event|timed|profile|span)\(\s*["']([A-Z][A-Z0-9_]+)["']"""),
    re.compile(r"""_enroll_tel\(\s*["']([A-Z][A-Z0-9_]+)["']"""),
)


def main() -> int:
    root = Path(__file__).resolve().parent.parent / "app"
    if not root.is_dir():
        print(f"[telemetry] app/ not found at {root}", file=sys.stderr)
        return 2

    show_where = "--where" in sys.argv
    sites: dict[str, list[str]] = {}

    for path in sorted(root.rglob("*.py")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = path.relative_to(root.parent).as_posix()
        for pat in _PATTERNS:
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                sites.setdefault(m.group(1), []).append(f"{rel}:{line}")

    for name in sorted(sites):
        if show_where:
            print(f"{name}\n    " + "\n    ".join(sites[name]))
        else:
            print(name)

    print(f"\n[telemetry] {len(sites)} distinct event names emitted under app/",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
