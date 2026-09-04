# v1.4.26 field-test follow-ups — handoff plan

**Source:** OXYGENE_FIT client PC, 2026-08-30, MonClub Access v1.4.26 (MB2000 / zkemkeeper).
**Audience:** an agent (Codex) working in `C:\Users\mohaa\Desktop\monclub_access_python`.

---

## 0. Read this before touching anything

This is **production access-control software for live gyms.**

1. Read [`CLAUDE.md`](../../CLAUDE.md) first, then whichever applies:
   [`guide_for_agents_and_dev.md`](../../guide_for_agents_and_dev.md) (modes, routing),
   [`pullsdk_guide.md`](../../pullsdk_guide.md), [`zkemkeeper_guide.md`](../../zkemkeeper_guide.md).
   `README.md` is stale — ignore it.
2. **Do not invent, assume, or estimate.** Every claim must be grounded in code or in
   the field evidence quoted here. If something is unproven, say so and mark it
   `[UNVERIFIED]`. A docstring is a *claim*, not evidence.
3. If you change behaviour a guide describes, **update that guide in the same change**
   (each guide has a §0 maintenance contract).
4. Verify with **both**:
   ```bash
   python -m pytest tests/ -q --ignore=tests/_pydeps
   python tools/check_sql_arity.py
   ```
   `--ignore=tests/_pydeps` is **required** (vendored packages break collection; there is
   no `pytest.ini`). Baseline at handoff: **857 passed**, arity **PASS**.
5. Every task below must land with a regression test that **fails before** the fix.
   A test that passes on the broken code is worthless — prove it fails first.

### Already fixed — do NOT redo these

| Fix | Where |
|---|---|
| ZKFinger runtime-DLL preload (`ZKFPM_Init rc=-1` mechanism) | `app/sdk/zkfinger.py` |
| Slow user list — `include_templates` opt-out | `app/core/db.py`, `app/api/local_access_api_v2.py`, `tauri-ui/src/pages/LocalDbPage.tsx` |
| Template-refusal UNKNOWN → RESOLVED | `zkemkeeper_guide.md` §8 |

### Confirmed NOT broken — do not "fix" these

- **`fingerprints` table = 0 is CORRECT.** It is the *local ZK9500 enrolment store*
  (`db.py`, `CREATE TABLE ... fingerprints`). Backend fingerprints live in
  `sync_users.fingerprints_json` and are present — proved by `templates_for=853`.
- **The MB2000 roster push works.** `pushed=928 failed=0 templates_failed=0`.
- **The enrolment failure is not CORS.** At 14:05:06 `OPTIONS /api/v2/enroll/start`
  returned **204** and the `POST` **202** — it reached the server and then failed on the
  scanner.

---

## Task 1 — HistoryService is reported dead and force-started, defeating H-002

**Severity:** low impact, high confidence. Do this one first; it is the cleanest.

### Evidence

Client log, three consecutive lines, 2 ms apart:

```
13:50:34,889 | INFO  | [RT] History service not started (AGENT mode writes history directly)
13:50:34,890 | ERROR | [RT] HistoryService died — restarting
13:50:34,891 | INFO  | [RT] HistoryService restarted OK
```

### Cause (verified in code)

In `app/core/realtime_agent.py`, inside `AgentRealtimeEngine`:

- `self._hist = HistoryService(...)` — **constructed** (~line 1880).
- Decision **H-002**: it is deliberately **never started** in AGENT mode, because
  `DecisionService` writes history directly. Logged as "History service not started"
  (~line 1899).
- The health check in `_check_thread_health` (~line 2027) reads:
  ```python
  if self._hist is not None and hasattr(self._hist, 'is_alive') and not self._hist.is_alive():
  ```
  A constructed-but-never-started thread satisfies this, so it logs a **false ERROR**
  and then **starts the very service H-002 chose not to start**.

### What to do

Make "deliberately not started" distinguishable from "died". Two acceptable shapes —
pick one and state why in the commit:

- leave `self._hist = None` when H-002 declines to start it, and construct it only where
  it is actually started; **or**
- add an explicit flag (e.g. `self._hist_started = False`) and require it in the health
  check.

Whichever you choose, the health check must not resurrect a service the engine
deliberately declined.

### Watch out for

`app/ui/app.py` (~line 2680) constructs and starts a **separate** `HistoryService` for
ULTRA (`history_q=self._ultra_engine.history_q`). That one is correct and must keep
working. They are different queues — do not merge them.

### Done when

- No ERROR line is emitted on a clean AGENT-mode start.
- A test asserts the health check does **not** start a service that was intentionally
  not started, and **does** still restart one that genuinely died.

---

## Task 2 — Login handler spends ~2.25 s after the backend already answered

**Severity:** medium. This is the user-visible "5–8 s and I can click Connecter again".

### Evidence

```
13:50:30,161 | >> POST /api/v2/auth/login
13:50:32,361 | [T] API_LOGIN dur_ms=2172          <- backend call finished here
13:50:34,610 | Access config saved to access/config.json.
13:50:34,642 | Login OK via API v2.
13:50:34,716 | << POST /api/v2/auth/login  4562ms
```

**2172 ms is the backend** (not ours). The remaining **~2.25 s is local work** between
`API_LOGIN` finishing and `persist_config()` completing.

### Where

`app/api/local_access_api_v2.py::_handle_auth_login`. Between those two log points it
runs, in order: `save_auth_token(...)`, `mirror_access_auth_to_tv(...)`,
`ctx.app.cfg.login_email = email`, `ctx.app.persist_config()`.

### What to do

1. **Measure first.** Wrap each of the three with the existing telemetry helper
   (`app/core/telemetry.py`, `[T]` events — follow the surrounding style) and state which
   one dominates. **Do not optimise before you have the number.**
2. Then reduce the dominant one. Likely candidates, all to be confirmed rather than
   assumed: secure-store encryption on `save_auth_token`, the TV auth mirror doing disk
   I/O, `persist_config()` rewriting the whole config.
3. Anything not needed to answer the HTTP request should move **off** the request path
   (the handler already uses `_schedule_sync_request` + `ctx.app.after(...)` for exactly
   this — follow that pattern).

### Context on the re-click window

`tauri-ui/src/pages/LoginPage.tsx` already does `disabled={loading}` with a spinner, and
`AppContext.login()` is `POST /auth/login` then `refreshStatus()`. The button re-enables
correctly when the promise resolves — the extra perceived time is the dashboard's own
first render running slow queries. **Do not add a second guard to the button**; fix the
latency instead.

### Done when

- A `[T]` event breaks the post-API login time into its parts.
- The handler's own time is materially reduced, with before/after numbers quoted.
- No behaviour change to what login persists.

---

## Task 3 — `push_batch_history` is empty after a successful push

**Severity:** medium. **Investigation first — do not "fix" until you can reproduce.**

### Evidence

The push succeeded:

```
13:51:35 [ZKEM:8] push_roster START users=928 templates_for=853 chunks=93 bracket=False
13:58:34 [ZKEM:8] push_roster DONE ok=True pushed=928 failed=0 templates_failed=0 in 419s
         FULL_SYNC_DONE worker=ULTRA:8 reason=startup ok=True dur_ms=424351 pushed=928 failed=0
```

The client's Base-locale screen showed `push_batch_history 0` and `push_pin_history 0`.

### What is already known

- `app/core/ultra_engine.py::_run_standalone_full_sync` calls `insert_push_batch(...)`
  unconditionally inside its `try`, then `update_push_batch(...)` at the end.
- `insert_push_batch` writes to the `push_batch_history` table.
- **Neither** `"push-batch row not recorded"` nor `"push-batch row not finalised"`
  appears anywhere in the client logs — so no swallowed exception was logged.

### Honest gap

The screenshot's timestamp is unknown, so **"the screenshot predates the 13:58 completion"
has not been ruled out.** Establish that before assuming a code defect.

### What to do

1. Reproduce locally: drive `_run_standalone_full_sync` against a fake standalone driver
   (see `tests/test_zk_standalone_driver.py` for the fake-device pattern) and assert a
   row lands in `push_batch_history` and is finalised.
2. If it lands locally, the defect is not here — say so, and instead make the timing
   answerable: have the Base-locale / push-history view show the row's `created_at` and
   `status` so an operator can tell "not yet" from "never".
3. If it does **not** land, fix it and pin it with the test from step 1.

### Done when

Either a reproduced-and-fixed defect with a failing-first test, or a written statement
(with evidence) that the write path is sound plus the observability improvement.

---

## Task 4 — `list_projected_offline_users` costs ~500 ms on every full user page

**Severity:** low-medium. Cheap win.

### Evidence

From the client's own `DB_READ_users_split` telemetry (12 samples):

```
DB_READ_users_split rows=934 select_ms=6828 coerce_ms=47  projected_ms=562
DB_READ_users_split rows=934 select_ms=1187 coerce_ms=63  projected_ms=594
DB_READ_users_split rows=934 select_ms=703  coerce_ms=93  projected_ms=594
```

`projected_ms` sits at **~500–670 ms consistently**, while every offline queue on that
machine is empty (`offline_creation_queue`, `offline_mutation_queue`,
`offline_subresource_queue` all 0).

### Where

`app/core/db.py::list_sync_users_page` — the `include_projected_offline` branch calling
`list_projected_offline_users(base_users=users)`.

### What to do

Short-circuit when there is nothing pending: a cheap `COUNT(*)`/`EXISTS` on the relevant
queue table(s) before doing the projection work. Keep the result **identical** when
something *is* pending.

### Watch out for

`select_ms` is now much smaller for callers passing `templates=0` (see the already-fixed
work), so `projected_ms` is a **larger** share of what remains. Do not remove the
projection — offline-created members must still appear.

### Done when

`projected_ms` is ~0 with empty queues, a test proves projected members still appear when
the queue is non-empty, and the returned payload is byte-identical in both paths.

---

## Task 5 — Chrome blocks the dashboard → localhost enrolment call (Private Network Access)

**Severity:** medium. **This is not a code defect in this repo.** Scope carefully.

### Evidence

Browser console, from `https://monclubwigo.tn`:

```
Access to fetch at 'http://127.0.0.1:8788/api/v2/enroll/start' from origin
'https://monclubwigo.tn' has been blocked by CORS policy: Permission was denied
for this request to access the `loopback` address space.
```

HAR: the `OPTIONS` preflight has **`status=0`** — the browser never sent it.

But at **14:05:06** the same call succeeded (`OPTIONS` → **204**, `POST` → **202**). So it
is **intermittent**, and it depends on Chrome's PNA permission prompt being accepted.

### What is already correct

`app/api/local_access_api_v2.py::_cors_headers` already emits
`Access-Control-Allow-Private-Network: true` when the preflight asks for it — that is the
**old** PNA spec and it is implemented correctly. Chrome 130+ additionally gates loopback
behind a **user permission prompt**, which no server header can satisfy.

### What to do (in this order)

1. **Confirm the current Chrome version's actual requirement** from primary sources
   before changing anything. Do not guess the header set.
2. Make the failure legible instead of silent: when the dashboard's localhost call fails
   this way, surface an explicit operator-facing message naming the permission prompt.
   Today it reads as "enrollment failed".
3. Document it in the operator notes.

### Do NOT

- Do not disable or weaken origin checks.
- Do not add a permissive `Access-Control-Allow-Origin: *` on the local API.
- Do not conclude this is why enrolment failed — it is not (see Task 6).

---

## Task 6 — HARDWARE-GATED: verify the ZKFinger fix on the client PC

**Cannot be completed by an agent.** Listed so it is not forgotten.

### Background

`ZKFPM_Init failed: -1 (Failed to initialize the algorithm library)` blocked enrolment
from **both** the dashboard and the desktop Enrôlement page.

Established by binary inspection:

- The real chain is `libzkfp.dll → fpslib.dll → zkfpslibLow.dll → fppswsk12.dll`, and
  **only the first hop is a static import** (verified with the repo's own `_pe_imports`).
- The later hops load by **bare name** from inside vendor DLLs, so they use the process
  search order (exe dir, System32, cwd, PATH) — which does **not** include
  `<install>\sdk`. `os.add_dll_directory()` does not help, because `AddDllDirectory`
  only affects loads passing `LOAD_LIBRARY_SEARCH_*` flags.
- **Refuted:** "missing DLLs". `app/sdk` was byte-compared against the known-good
  `tools/mb2000_scripts/sdk`; every DLL in the real chain is present and identical.
  (`zkfinger10.dll` is a renamed `fpslib.dll` — same sha256; `zkfinger10-32.dll` is
  referenced by nothing shipped.)

### The fix already shipped

`app/sdk/zkfinger.py` now preloads `zkfpslibLow.dll` and `fppswsk12.dll` by **absolute
path** and prepends the sdk dir to `PATH` unconditionally.

### The decisive on-site test

On the client PC, run:

```
tools/mb2000_scripts/4_enroll_zk9500.ps1
```

- Script **works**, app still fails → app-side loading; re-open `zkfinger.py`.
- Script **also fails** → the fault is the ZK9500 **driver or hardware**, not this app.
  Reinstall the ZKFinger driver from the same SDK package and confirm the scanner
  enumerates.

Report the new `ZKFPM_Init rc=` line either way — the improved error hint now prints
`dll_dir`, the preloaded+pinned list, and any missing runtime dependency.

---

## Not this repo — backend (`monclubwigo.tn`)

These cannot be fixed here. Hand them to whoever owns the backend.

### B1 — `accessServerHost` is `"172.0.0.1"` (typo for `127.0.0.1`)

From the live `get_gym_users` response:

```json
"accessSoftwareSettings": { "accessServerHost": "172.0.0.1", "accessServerPort": 8788 }
```

`172.0.0.1` is a routable public address, not loopback. **Harmless today** — the desktop
app binds `127.0.0.1:8788` from its own config and never reads this value — but it is a
trap for anything that starts consuming it. Fix the stored value.

### B2 — `bulk_save_gym_access_history` rejects the payload

```
API syncAccessHistory -> .../users/bulk_save_gym_access_history
[DeviceAttendance] access history upload failed (http): HTTP 400 ->
{"status":false,"errorMsg":"Invalid access history payload.","code":"BAD_REQUEST",
 "traceId":"0496cf04307d4132"}
```

Access history is therefore **not reaching the dashboard** from this gym. Use
`traceId=0496cf04307d4132` to find which field the backend rejected, then decide whether
the desktop payload or the backend validation is wrong. Do not change the desktop payload
shape speculatively — get the backend's rejection reason first.

---

## Suggested order

1. **Task 1** — smallest, clearest, real.
2. **Task 4** — cheap measured win.
3. **Task 2** — measure, then optimise.
4. **Task 3** — investigate before changing anything.
5. **Task 5** — research first; mostly UX + docs.
6. **Task 6** — needs the client PC.
7. **B1 / B2** — backend team.

Each task ships independently. After every one:

```bash
python -m pytest tests/ -q --ignore=tests/_pydeps
python tools/check_sql_arity.py
```

and update any guide whose claims your change touched.
