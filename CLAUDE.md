# MonClub Access

**Before changing anything under `app/sdk/`, `app/core/device_*`, `app/core/ultra_engine.py`,
`app/core/realtime_agent.py`, or `app/api/local_access_api_v2.py`, read
[`guide_for_agents_and_dev.md`](guide_for_agents_and_dev.md).**

Three files are the source of truth. `README.md` is stale — ignore it.

| File | Read it when |
|---|---|
| [`guide_for_agents_and_dev.md`](guide_for_agents_and_dev.md) | Always first — modes, protocol routing, capability flags |
| [`pullsdk_guide.md`](pullsdk_guide.md) | Touching `plcommpro.dll` / C2-400 / C3-200 panels |
| [`zkemkeeper_guide.md`](zkemkeeper_guide.md) | Touching zkemkeeper COM / MB2000 terminals |

All three grade every claim `[CODE]` / `[TEST]` / `[FIELD]` / `[COMMENT]` /
`[UNVERIFIED]` / `[UNKNOWN]`. **A docstring is a claim, not evidence** — grade what the
executable statements do, never what the prose says they do. Keep the three consistent.

The short version of what that guide protects against:

- This app drives **two different ZKTeco SDKs** — `plcommpro.dll` (PullSDK, poll-based,
  table-oriented) and `zkemkeeper` (COM, push-based, STA-threaded). They are not
  interchangeable. Never branch on device *model*; branch on protocol or on a
  capability flag.
- `app/sdk/pullsdk.py` defines **two** classes — the low-level `PullSDK` DLL wrapper and
  the portable `PullSDKDevice` driver. Code written against the low-level one is
  PullSDK-only by construction and must **refuse** other protocols, not route them.
- A `ZK_STANDALONE` device in `DEVICE` mode receives **no roster from any engine**. It
  must be `accessDataMode=ULTRA`.

This is production access-control software for live gyms. **Do not invent, assume, or
estimate.** Every claim and change must be grounded in the code or in real evidence.
If something is unproven, say so and mark it `[UNVERIFIED]` — the guide has a section
for exactly that.

Verify with:

```bash
python -m pytest tests/ -q --ignore=tests/_pydeps
python tools/check_sql_arity.py
```

If you change behaviour the guide describes, **update the guide in the same change**
(see its §0 maintenance contract).
