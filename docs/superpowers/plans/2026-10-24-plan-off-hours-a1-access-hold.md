> Execution copy in the A1 worktree: the source plan in the backend docs worktree stays unchanged under the work-only-in-A1 rule. Deviations and validation: ../reports/2026-10-26-off-hours-a1-report.md

# Plan off-hours A1 — Access PC hold, release and QR refusal — Implementation Plan

> **For Codex:** work task by task; steps use checkbox syntax. Tick a box only when the step is really done.

**Goal:** the Access PC takes members of a closed plan off the turnstiles at the window start and puts them back 5 minutes before it ends, on time and offline, keeping fingerprints; a Wigo QR is refused with `OFF_HOURS` while the plan is closed.

**Architecture:** the plan hours arrive on the protocol-2 windows (B2) and are stored in the two window tables. A minute pass computes who is held now (pure planner, gym-local clock from the stored UTC offset). Held rows move `sync_users` -> `sync_users_held` with `held_reason = 'off_hours'` (the date flip's mechanism, so fingerprints stay and a release is local), recorded in a small intent table because every roster save deletes held rows. The device side uses the existing **targeted per-member channel** (`UltraEngine.request_sync_now(changed_ids=…, revoked_ids=…)` -> `request_member_revoke` / `request_member_sync`): ownership-gated, no percentage ceiling, one member per worker-loop iteration (doors keep working), both drivers, and not suppressed by manual sync mode. The full-sync removal steps are taught to leave the off-hours-held set out of their ceiling count.

**Tech Stack:** Python (32-bit 3.14 venv), sqlite3, pytest; tauri-ui React for the popup text.

**Spec:** section 6 (and 2: D2, D3, D5, D9, D10). Contract: `2026-10-24-plan-off-hours-index.md`. Depends on the B2 payload shape (`offHours` on window objects).

## Read first (the repo's own rule)

`CLAUDE.md` says to read `guide_for_agents_and_dev.md` before touching `app/core/device_*`, `app/core/ultra_engine.py`, `app/core/realtime_agent.py`. Read its sections on the date flip / held rows (`grep -n "sync_users_held\|date flip\|apply_local_date_flips" guide_for_agents_and_dev.md`), the removal ceiling and ownership (`§3.4`), pinScheme ACCOUNT (`§3.2b`), manual sync (`§3.6`) and the maintenance contract (`§0`). Every claim you add to the guide carries a grade tag (`[CODE]`/`[TEST]`/`[UNVERIFIED]`); a docstring is a claim, not evidence.

## Global Constraints

- Worktree from current `master`: `git -C D:\Monclub\monclub_access_python worktree add D:\Monclub\monclub_access_python\.worktrees\off-hours-a1 -b claude/off-hours-a1 master` (if `.worktrees` is not git-ignored, add it to `.git/info/exclude`, do not edit `.gitignore`). Never git checkout/reset/stash/clean in `D:\Monclub\monclub_access_python`; never push, merge or release; do not run the real app, never touch a device or the gym data root.
- Tests: the main checkout owns the venv. From the worktree root, with a fresh empty data root:
  ```powershell
  $py = "D:\Monclub\monclub_access_python\.venv\Scripts\python.exe"
  $env:MONCLUB_ACCESS_DATA_ROOT = (New-Item -ItemType Directory -Force "$env:TEMP\off-hours-a1-data").FullName   # empty folder
  & $py -m pytest tests/test_off_hours_planner.py -q -p no:cacheprovider --ignore=tests/_pydeps
  & $py tools/check_sql_arity.py
  ```
  One test file per call is fine; never the full suite (3700 tests). Light testing: write the five new test files below plus run the listed regression files once at the end (Task 6); re-run only failures. The suite has known order-dependent flakes (`test_logging_reaches_the_app_log.py`, `test_door_open_deadline.py`): ignore them, do not run them.
- Every new SQL statement that adds or reorders columns must keep `python tools/check_sql_arity.py` green.
- Fail-open everywhere: no offset, no trusted windows, a suspect clock, an unreadable table, an exception -> nothing is held and everything held is released. A bug here must never lock members out.
- The normal sync must not get slower: the minute pass is one cheap `SELECT 1` unless some window carries hours or an intent row exists.

## Review Focus

1. No roster save, date flip, fast patch or logout leaves a row both held by the intent table and live on the turnstile for more than one pass (every writer of `sync_users_held` deletes held rows: `_reconcile_held_rows :1698`, the untrusted branch `:1966`, `upsert_delta_users`, `_save_sync_cache :5236`, `_forget_protocol2_membership :6064`, `save_sync_cache_delta`).
2. Date holds and off-hours holds never undo each other, in both orders (Task 2 tests).
3. A big plan closing (40 % of the roster) is removed, while 12 unrelated stale pins over the floor are still refused by the ceiling.
4. Under pinScheme ACCOUNT, a person with an open and a closed membership keeps their pin.
5. Manual sync mode: only the held/released members are touched, nothing else pending is pushed.

---

### Task 1: Pure planner `app/core/off_hours.py`

**Files:** Create `app/core/off_hours.py`, `tests/test_off_hours_planner.py`.

- [x] **Step 1: Module** (stdlib only, no db, no clock):
  ```python
  LEAD_MINUTES = 5
  DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")

  @dataclass(frozen=True)
  class OffWindow:
      day: int          # MON=0
      start: int        # minute of day 0..1439
      duration: int     # minutes 15..1425

  def parse_windows(raw) -> tuple[OffWindow, ...]:
      """Lenient, never raises: `raw` is a list of {"day","startMinute","durationMinutes"}; entries that are not
      well formed are dropped; at most 7 are kept. Bad hours must never make a window or a payload invalid."""
  def encode_windows(ws) -> str | None      # JSON of the wire shape (None when empty) for the sqlite column
  def decode_windows(text) -> tuple[OffWindow, ...]

  def local_week_minute(epoch: float, utc_offset_sec: int) -> tuple[int, int]:
      """(weekday MON=0, minute of day) of the gym-local time. 1970-01-01 was a Thursday."""
      days, sec = divmod(int(epoch) + int(utc_offset_sec), 86400)
      return (days + 3) % 7, sec // 60

  def _covers(ws, weekday, minute, lead):
      for w in ws:
          dur = w.duration - lead
          if dur <= 0: continue
          if w.day == weekday and w.start <= minute < w.start + dur: return True
          if w.day == (weekday + 6) % 7 and w.start + dur > 1440 and minute < w.start + dur - 1440: return True
      return False
  def held(ws, weekday, minute) -> bool:   return _covers(ws, weekday, minute, LEAD_MINUTES)   # turnstile: off at start, back at end-5
  def closed(ws, weekday, minute) -> bool: return _covers(ws, weekday, minute, 0)              # QR: exact window
  ```
  Same rule as the index contract, byte for byte.
- [x] **Step 2: The plan function** (pure):
  ```python
  @dataclass(frozen=True)
  class OffHoursPlan:
      active: bool
      target: frozenset[int]        # membership ids that must be off the turnstile now
      newly_held: frozenset[int]    # target - intent
      released: frozenset[int]      # intent - target
      retry: frozenset[int]         # target & intent (the caller re-checks the devices)

  def plan_off_hours(*, now_epoch, utc_offset_sec, trusted, clock_suspect,
                     windows_by_am: Mapping[int, tuple[OffWindow, ...]],
                     known_ids: Collection[int],          # memberships this PC holds: sync_users + sync_users_held
                     intent_ids: Collection[int]) -> OffHoursPlan
  ```
  `active = trusted and not clock_suspect and utc_offset_sec is not None`; inactive -> `target = frozenset()`. Active: `target = {am for am, ws in windows_by_am.items() if ws and am in known_ids and held(ws, *local_week_minute(...))}`. An intent id that is no longer known (forgotten membership) is in `released`; the caller will find no device pin for it.
- [x] **Step 3: Tests** (`tests/test_off_hours_planner.py`, plain pytest, offset 3600 = Tunis):
  - `local_week_minute`: epoch of 2026-10-26 00:00:00 UTC+1 (a Monday) -> (0, 0); one second before -> (6, 1439); offset 0 vs 3600 at the same epoch differ by one hour; a negative offset still divmods correctly.
  - `held` / `closed` table: MON 22:00 + 8 h -> closed at Tue 05:59, open Tue 06:00; held ends Tue 05:55; SUN 23:00 + 120 spills into Monday 00:59; no spill for a daytime window; duration 15 -> held for 10 minutes; two windows; empty tuple.
  - `parse_windows`: junk entries dropped, > 7 truncated, wrong types never raise, `None`/`""`/non-list -> empty.
  - `plan_off_hours`: newly_held / released / retry sets; fail-open: untrusted, `clock_suspect`, offset `None` -> empty target, everything in intent is released; an id not in `known_ids` is never targeted.

---

### Task 2: Storage — windows, intent table, the hold itself

**Files:** `app/core/access_dates.py` (`AccessWindow :54`, `parse_window :62`, `AccessDaysSnapshot :425`), `app/core/db.py`, `tests/test_off_hours_db.py`.

- [x] **Step 1: Window type.** `AccessWindow` gets `off_hours: tuple = ()` as its LAST field (default keeps every constructor call valid). `parse_window` fills it with `off_hours.parse_windows(obj.get("offHours"))` and must never return `None` because of it (a malformed `offHours` is ignored, the date window stays valid; `parse_v2_payload` rejects the whole payload on a `None` window). `access_dates` imports the pure `off_hours` module (no cycle: `off_hours` imports nothing from the app).
- [x] **Step 2: Columns.** In `db.py`: add `off_hours_json TEXT` to the CREATE of `member_access_window` (`:1312`) and `sync_upcoming_users` (`:1323`) and an `_ensure_column(conn, table, "off_hours_json", "off_hours_json TEXT")` next to them for existing databases (`_ensure_column :726`). Extend `_window_columns :1603` to return the 5th element (`off_hours.encode_windows(w.off_hours)`), then fix its two INSERT sites (`_replace_member_access_windows :1633`, `_replace_sync_upcoming :1648`) and the two SELECTs in `_read_protocol2_windows :1442` (+ `_window_from_columns :1432` takes `off_hours_json` last). Run `python tools/check_sql_arity.py`. The raw upcoming row in `payload_json` already contains `offHours` as sent; nothing else reads it.
- [x] **Step 3: Intent table.** `CREATE TABLE IF NOT EXISTS off_hours_hold (active_membership_id INTEGER PRIMARY KEY, held_at TEXT NOT NULL)` in `init_db :2272` (same block style as `member_access_window`). Clear it wherever the windows are cleared wholesale (`:5236-5237` in `_save_sync_cache`, logout / hard-reset paths: `grep -n "DELETE FROM member_access_window\|sync_users_held" app/core/db.py`) and in `_forget_protocol2_membership :6064` (add it to the tuple of tables).
- [x] **Step 4: Date flip must not touch off-hours rows.** In `apply_local_date_flips`, the `held_ids` query (`:1984`) becomes `SELECT active_membership_id FROM sync_users_held WHERE COALESCE(held_reason,'') <> 'off_hours'` so `plan_flip` never restores one. (The untrusted branch `:1966` restoring everything is correct and stays: no trust, no hold.)
- [x] **Step 5: `apply_off_hours(*, pc_now_epoch: float, source: str) -> dict`** in `db.py`, one write job through `_run_db_write_sync("apply_off_hours", _write)` like `apply_local_date_flips :1884`:
  1. read `access_v2_state` (`trusted`, `clock_suspect`, `utc_offset_sec`); no row -> `{"skipped": "no_state"}`;
  2. windows: `today, upcoming, _ = _read_protocol2_windows(conn)`; `windows_by_am = {am: w.off_hours for am, w in {**upcoming, **today}.items() if w.off_hours}`;
  3. `on_roster` (sync_users ids), `held_rows` ({id: reason}), `intent` (ids); `known = on_roster | set(held_rows)`;
  4. `plan = off_hours.plan_off_hours(...)`; the epoch passed in is the app's `_date_flip_now()` (injectable, like the date flip);
  5. moves, column for column with `_SYNC_USER_COLUMNS` (copy the SQL of `:2003-2024`): every `am in plan.target & on_roster` -> `INSERT OR REPLACE INTO sync_users_held (…, held_reason, held_for_date, held_at) SELECT …, 'off_hours', ?, ? FROM sync_users WHERE active_membership_id = ?` then delete from `sync_users`. Rows held for a DATE reason are never moved by this function (a target id that is date-held stays date-held; when the date clears the date flip restores it and the next minute pass moves it again).
     **Releasing is not blindly restoring.** The date flip does not look at off-hours rows (Step 4), and it only runs when the gym date changes, so a membership that expired or froze WHILE held would otherwise go back on the turnstile until midnight. For every held row with `held_reason == 'off_hours'` and `am not in plan.target`, first evaluate its stored date window the way the flip does: `status = access_dates.window_status(w, applied_date, horizon_end=…, server_today=…, grace_days=…)` using the window from `today_windows`/`upcoming_windows` and the state row's `applied_date`, `horizon_end`, `server_today`, `grace_days` (a row with no stored window, or no `applied_date`, counts as `ok`: restore). `ok`/`grace` -> restore into `sync_users`, delete from held, and the id stays in `released` (a device add is needed). Anything else (`expired`, `not_started`, `frozen`) -> do NOT restore: `UPDATE sync_users_held SET held_reason = <status>, held_for_date = <applied_date> WHERE active_membership_id = ?`, drop the id from `released` (it is already off the device; list it in `released_to_date`), so the date flip owns it from now on. This is what makes "a row held for both stays held until both clear" true. Call `_refresh_member_account_links(cur)` when anything was restored (as `:2042`);
  6. intent: delete every id of `plan.released` (including the relabelled ones), insert `plan.newly_held` (`held_at = now_iso()`);
  7. return `{"active", "newly_held": sorted, "released": sorted (restored only), "released_to_date": sorted, "retry": sorted, "moved": n_moves, "skipped": None}`; afterwards, if anything moved or the intent changed: `bump_local_state_generation()` and `invalidate_sync_cache()` (as `:2059-2061`) so the QR snapshot and every worker's roster see it.
  Also `def off_hours_in_play() -> bool`: `SELECT 1` on `member_access_window`/`sync_upcoming_users` `WHERE off_hours_json IS NOT NULL` or any `off_hours_hold` row (try/except -> False), and `def list_off_hours_held_rows() -> list[dict]` (the held rows with reason `off_hours`, full `sync_users` shape, for Task 4).
- [x] **Step 6: Snapshot for the QR.** `AccessDaysSnapshot` gets `utc_offset_sec: Optional[int] = None` and `clock_suspect: bool = False`; `load_access_days_snapshot :1466` fills them from the state row. (The QR check reads the hours from `snapshot.windows`, which already carries them; it does not need the intent ids, so the snapshot's staleness per generation does not matter for who is held.)
- [x] **Step 7: Tests** (`tests/test_off_hours_db.py`; copy the fixtures of `tests/test_protocol2_save_and_flip.py` — a temp db, a v2 save with windows, `apply_local_date_flips`):
  - a v2 save with `offHours` on `users[]`, `memberWindows[]` and `upcoming[]` rows round-trips through both tables; a save without it leaves `off_hours` empty; a malformed `offHours` leaves the date window valid;
  - `apply_off_hours` at MON 23:00 holds the closed membership (`held_reason == 'off_hours'`, fingerprints_json intact, intent row written), at TUE 05:55 restores it and clears the intent; running it twice changes nothing the second time;
  - coexistence, both orders: (a) a membership frozen by a date window AND closed: the date flip holds it (reason `frozen`), `apply_off_hours` leaves it, the freeze ends -> the date flip restores it -> the next `apply_off_hours` holds it for off-hours; (b) held for off-hours, then its date window expires (the stored window's `accessUntil` passes `applied_date`) -> `apply_local_date_flips` does NOT restore it; at release `apply_off_hours` does NOT restore it either: the row stays in `sync_users_held` relabelled `expired`, is reported in `released_to_date` and NOT in `released`, and no date flip runs in between (the test must not call it); the same for `frozen` (an `offDays` entry on the applied date) and `not_started`; a row whose window is still `ok` is restored and is in `released`;
  - a full roster save (which deletes `sync_users_held`) followed by `apply_off_hours` re-holds the closed membership without reporting it as `newly_held` (it is already in the intent);
  - untrusted state or `clock_suspect` or no offset: everything in the intent is released and restored.

---

### Task 3: Orchestration and the device channel (`app/ui/app.py`)

**Files:** `app/ui/app.py` (`_DATE_FLIP_TICK_MS :149`, startup `:671-672`, first tick armed `:706`, `_date_flip_tick :1909`, `_apply_date_flips :1714`, `_after_date_flip_moved :1785`, `_request_running_ultra_sync :1127`), new `app/core/off_hours_push.py`, `tests/test_off_hours_app_wiring.py`.

- [x] **Step 1: Run the DB step inside `_apply_date_flips`**, so every existing caller (start-up `:672`, the sync worker `:3296`, the fast patch `:2037`, the save paths `:3437/:3471/:4455`, midnight) re-applies holds right after a save, before anything is dispatched. After `out = _db.apply_local_date_flips(...)` returns and BEFORE `if moved > 0: ultra_requested = self._after_date_flip_moved(source)`:
  ```python
  off = self._apply_off_hours_db(now_epoch, source)      # never raises; returns {} on failure (logged, telemetry OFF_HOURS_FAILED)
  ```
  **Do not add `off["moved"]` to `moved`.** `moved > 0` makes `_after_date_flip_moved :1785` ask a running ULTRA engine for a FULL pass (`request_sync_now(changed_ids=None)`) and emit `DATE_FLIP` telemetry: a full pass at every window edge is exactly what the targeted channel avoids (it would push every pending diff, break the removal ceiling and, in manual mode, is suppressed anyway). Instead, when `off["moved"]` or the intent changed, do only the cache part of `_after_date_flip_moved` (`_db.invalidate_sync_cache(clear_cached=True)`, `_db.refresh_sync_cache_async()`, `self.reset_runtime_fast_patch_caches()`; factor those three lines into a helper both use) and emit a separate telemetry event `OFF_HOURS` (`held`, `released`, `retry`, `dur_ms`, `source`). Then, after the existing date-flip telemetry block: `self._dispatch_off_hours(off, source)`. If a real date move also happened in the same call, the existing full pass runs as today (the roster it builds already excludes the held rows). Keep the whole thing inside the existing `with self._date_flip_lock:` (the same lock serialises both). If the date flip raised (`return None`), the off-hours step is skipped this minute and retried the next.
- [x] **Step 2: Minute tick.** Add `_OFF_HOURS_TICK_MS = 60 * 1000` and `_off_hours_tick` beside `_date_flip_tick` (same arming at `:706`, same re-arm in `finally`, same stop-event check). The tick must NOT call `_apply_date_flips` unconditionally: that runs `apply_local_date_flips`, a `BEGIN IMMEDIATE` write that updates `access_v2_state`, once a minute, which is what the `_date_flip_needed` precheck (`:1867`) exists to prevent. Split the body of `_apply_date_flips` so the tick can run the steps separately under the same `_date_flip_lock`: `status = _db.gym_date_status(pc_now_epoch=...)`; if `self._date_flip_needed(status)` run the date flip as today; then, if `_db.off_hours_in_play() or self._off_hours_pending`, run the off-hours step and its dispatch. Otherwise the tick does nothing (one read-only `SELECT`). Hold/release therefore happen within 60 s of the window edge (the tick is not aligned to the minute): state that in the guide, it is the documented precision.
- [x] **Step 3: `_dispatch_off_hours(off, source)`** (in `off_hours_push.py` as a function taking the app, to keep `app.py` small): 
  ```python
  hold = set(off.get("newly_held") or ()) | still_on_devices(off.get("retry") or (), limit=50)
  release = set(off.get("released") or ())
  hold |= self._off_hours_pending["hold"]; release |= self._off_hours_pending["release"]        # carried over
  if not hold and not release: return
  ok = self._request_running_ultra_sync(refresh={"members": True, "devices": False},
                                        changed_ids=release, revoked_ids=hold, reason="off_hours")
  self._off_hours_pending = {"hold": set(), "release": set()} if ok else {"hold": hold, "release": release}
  ```
  This is the targeted channel: `UltraEngine.request_sync_now(changed_ids, revoked_ids)` (`ultra_engine.py:8680`) turns `revoked_ids` into `request_member_revoke` and `changed_ids` into `request_member_sync` on every usable worker (`:8770-8786`); `_drain_member_sync_commands :2014` handles them one at a time, PullSDK ULTRA workers through `DeviceSyncEngine.sync_member_on_connected_sdk` (`device_sync.py:1519`, ownership gate `:1637-1697`, ACCOUNT collapse via `person_rows_for_membership`), standalone MB2000 workers through `_run_standalone_member_revoke :4920` / `_run_standalone_member_sync :4478`. **It is not gated by manual sync mode**: `_request_running_ultra_sync` checks nothing about it (only the callers `_should_push` do), and this dispatch is planned, so it must NOT go through `_should_push`. `_request_running_ultra_sync` returns False when the ULTRA engine is not running yet (start-up): the ids stay in `_off_hours_pending` and ride the next tick; a restart before ULTRA ran loses the release ids, which the non-manual start-up full sync covers (the rows are back on `sync_users`); in manual mode the admin's next "Sync data" covers it (document).
  `still_on_devices(ids, limit)`: ids whose device pin is still `ownership_confirmed` on some ULTRA device — `db.list_confirmed_device_sync_pins(device_id=…)` (`db.py:8946`) with the pin from `device_sync.derive_member_pin(row, device_pin_scheme(device))` using the held row; bounded to `limit` per pass. This is the retry for a hold whose revoke failed (device off, ownership unreadable): the intent table says held, the device still has the pin.
  Not covered, say so in the guide: DEVICE-mode PullSDK devices (`DeviceSyncEngine` workers, not ULTRA) are not reached by `request_sync_now`; they drop the held members at the next normal sync (the stale step, ceiling included). `[UNVERIFIED]` whether any gym still runs DEVICE mode; gyms run ULTRA only per the owner.
- [x] **Step 4: Tests** (`tests/test_off_hours_app_wiring.py`, copy the pattern of `tests/test_p3b1_app_wiring.py`: a bare app object with fakes): (a) `_apply_date_flips` calls the off-hours DB step after the date flip; an off-hours-only move invalidates the caches but does NOT call `_after_date_flip_moved` (no `request_sync_now(changed_ids=None)`) and emits no `DATE_FLIP`; the minute tick does not call `apply_local_date_flips` when `_date_flip_needed` is False and does nothing at all when `off_hours_in_play()` is False; (b) manual sync mode ON: `_dispatch_off_hours` still calls `_request_running_ultra_sync` with only the held ids in `revoked_ids` and the released ids in `changed_ids`, and `refresh` never asks for devices; (c) ULTRA not running (`False`) keeps the ids pending and the next tick re-sends them; (d) a failing DB step does not raise and does not stop the date flip's own dispatch.

---

### Task 4: The removal steps must not count the off-hours set

**Files:** `app/core/off_hours.py` (helper), `app/core/push_safety.py`, `app/core/ultra_engine.py` (`_neutralise_revoked_pins :5048`, the call at `:5186`), `app/core/device_sync.py` (stale step `:3462-3640`, the call at `:3636`), `tests/test_off_hours_removal_bound.py`.

Why: the date flip asks a running ULTRA engine for a FULL pass (`_after_date_flip_moved`), and any later full pass (timer, "Sync data") sees held pins as departed (`owned − desired`). Their removal is checked against `max(10, 25 % of the roster)` (`push_safety.py:60-83`): a plan closing 40 % of a gym would abort the real leavers' removal too, and an all-closed roster is read as "empty roster, refused". Spec 6: the off-hours set has its own exact bound, the other pins keep the ceiling.

- [x] **Step 1: Helper.** `off_hours.held_pins_for_device(device) -> set[str]`: read `db.list_off_hours_held_rows()` plus the rows of the intent table that are currently in `sync_users_held`, map each with `device_sync.derive_member_pin(row, device_sync.device_pin_scheme(device))` (digits only). `off_hours.split_removals(pins, held_pins) -> (unplanned: list[str], planned: list[str])`.
- [x] **Step 2: ULTRA revoke step** (`ultra_engine.py:5152-5211`): after `revoked = sorted(...)` compute `unplanned, planned = split_removals(revoked, held_pins_for_device(self._device))`; judge `_push_safety.check_bulk_removal(count=len(unplanned), roster_count=roster_count + len(planned), …)` (`path` unchanged, the sample stays `revoked`); the guard `if roster_count <= 0` at `:5105` becomes `if roster_count + len(held_pins_owned) <= 0` where `held_pins_owned = held_pins ∩ owned` (so an all-closed roster is not read as a failed build, while a really empty roster with nothing held still is). Everything actually removed is still `revoked` (planned + unplanned); only the count handed to the ceiling changes. A read error in the helper returns empty sets (the ceiling then applies as before, fail-closed for removals).
- [x] **Step 3: PullSDK stale step** (`device_sync.py:3636`): the same split on the stale list before `check_bulk_removal`. Read `:3462-3640` first; the stale set is `device_pins ∩ tracked_server_pins − desired_pins` and does not use `ownership_confirmed`: do not change that, only the count.
- [x] **Step 4: Tests** (`tests/test_off_hours_removal_bound.py`; copy the fixtures of `tests/test_revoke_ownership_skip.py` for the ULTRA step and `tests/test_removal_ceiling_pullsdk.py` for the stale step): roster 100, 40 owned pins that are off-hours-held and no longer desired -> removed, no `REVOKE_ABORTED`; 40 stale pins NOT held -> still aborted; 30 held + 12 unrelated stale (12 > floor 10 after the 25 % of 70) -> the unrelated count judges the ceiling and the pass aborts; everyone held (desired empty) -> removal proceeds; `split_removals` unit cases; helper read failure -> ceiling applies unchanged.

---

### Task 5: QR refusal `OFF_HOURS`

**Files:** `app/core/access_dates.py`, `app/core/access_verification.py` (`verify_totp :641`, roster check `:846-886`, `_MATCHED_REFUSALS :208`), `tauri-ui/src/pages/PopupWindow.tsx` (`A_DENY :316-335`), `tests/test_off_hours_qr.py`.

Why in `verify_totp`: the AGENT path (`realtime_agent.py:1145-1151`) never calls `card_decision.decide_qr`, and a held member is absent from `users_by_am`, so today's result for them is `ROSTER_NOT_IN`, which trial mode ALLOWS. The ULTRA rescue (`ultra_engine._handle_totp_rescue :6638`) calls `verify_totp_resilient` then `decide_qr`, which passes a refused result's reason through (`card_decision.py:163-164`).

- [x] **Step 1: Pure verdict** in `access_dates.py`:
  ```python
  def qr_off_hours_refused(snapshot, *, grants, users_by_am, now_epoch) -> bool:
      """True when every membership the QR grants that is live today is closed by its plan's hours right now.
      Live today = deliverable by its date window, or on the roster. No trusted snapshot, no offset or a suspect clock -> False
      (fail-open). A grant with no hours is open."""
  ```
  Candidates = grants `g` with `snapshot.deliverable(g) is True or g in users_by_am` (NOT "held for off-hours": every id the planner holds has a stored window, so the first clause already covers it, and a member who is date-expired AND inside a closed window must keep getting `DENY_NOT_ALLOWED_TODAY`, which the existing date check returns first for them); none -> False. For each candidate: windows = `snapshot.windows[g].off_hours` (empty -> open); `closed = off_hours.closed(windows, *local_week_minute(now_epoch, offset))`. Refuse iff all candidates are closed. Exact window (no 5-minute lead), as spec section 4: in the last five minutes the member is back on the turnstile for cards and faces but a QR is still refused.
- [x] **Step 2: Wire.** In `verify_totp`, right after `roster_check`/`roster_mode` are computed (before the `ROSTER_NOT_IN` enforce return at `:872`):
  ```python
  _snap = access_days_index if (used_index and access_days_index is not None) else access_days
  if qr_off_hours_refused(_snap, grants=grants, users_by_am=users_by_am,
                          now_epoch=(now_unix if now_unix is not None else time.time())):
      return {"allowed": False, "reason": "OFF_HOURS", "scanMode": "QR_TOTP", "accountId": account_id, "credId": cred_id,
              "matchedCounter": matched_ctr, "ageSeconds": age, "activeMembershipId": chosen_am_id,
              "rosterCheck": roster_check, "rosterCheckMode": roster_mode, "tookMs": …, "user": user}
  ```
  Add `"OFF_HOURS"` to `_MATCHED_REFUSALS :208` (no pointless wall-clock retry). Keep the reason literally `OFF_HOURS` (the spec's contract; the dashboard shows it with the same key); nothing in `app/` keys on a `DENY` prefix.
- [x] **Step 3: Popup text.** In `tauri-ui/src/pages/PopupWindow.tsx` add to `A_DENY` (copy the shape of the `DENY_NOT_ALLOWED_TODAY` line `:326`): `OFF_HOURS: { title: "Hors horaires de votre formule", action: "Revenez pendant les horaires de votre formule ou présentez-vous à l'accueil.", short: "Hors horaires" }`. Check the other places `aDenyCopy :339` feeds (history list, notification) show the key text without further mapping: `grep -rn "A_DENY\|aDenyCopy" tauri-ui/src`.
- [x] **Step 4: Tests** (`tests/test_off_hours_qr.py`, copy fixtures from `tests/test_qr_allowed_days.py` and `tests/test_totp_roster_check.py`): closed member (absent from `users_by_am`, window deliverable by date with MON 22:00+8 h hours, scan at Mon 23:00 local) -> `allowed False`, `reason "OFF_HOURS"`, in BOTH roster modes (trial and enforce); scan at Tue 05:57 (inside the 5-minute lead, row back on the roster) -> still `OFF_HOURS`; scan at Tue 06:00 -> allowed; a person with two grants, one open -> allowed; a date-expired member inside a closed window -> `DENY_NOT_ALLOWED_TODAY`, not `OFF_HOURS`; untrusted / suspect clock / no offset -> allowed; a plan with no hours unaffected; `verify_totp_resilient` does not retry on `OFF_HOURS`; `decide_qr` returns the reason as a refusal.
- [x] **Step 5:** `cd tauri-ui; npx tsc --noEmit -p .` (master already has 4 errors in `PopupWindow.tsx` / `AccessFeedbackProvider.tsx`: add none) and `npm test` there if it runs offline.

---

### Task 6: Version, guide, final run, report

- [x] **Step 1: Version.** `git tag --list` and `update.json` (`access.version = "1.4.37"`): bump to the next free patch (`1.4.38`) in `update.json` only; `packaging/sync_tauri_version_files.py` propagates to `tauri-ui/package.json`, `src-tauri/tauri.conf.json`, `Cargo.toml`, `Cargo.lock` (run it as `build_tauri_shell.ps1:20-32` does, or edit the four files to the same value and check `git diff --stat`). This is the first version that applies hours: the dashboard warns PCs below it. **The number is the owner's to confirm:** the guide (`:6319`, `:6543-6549`) names an unshipped `1.5.0` ("the first v2 / updater release"), so the release that first contains this part may be `1.4.38` or `1.5.0` depending on what ships first. Put the number you used at the top of your report; D1's constant `OFF_HOURS_MIN_ACCESS_VERSION` must equal the first released version that contains A1. Do not build or publish a release.
- [x] **Step 2: Guide.** Add a short "Off-hours hold (1.4.38)" subsection next to the date-flip section of `guide_for_agents_and_dev.md` (§0 contract): the window columns, the intent table, the minute pass and its 60 s precision, the targeted channel and why not the full pass, the ceiling exemption, the QR rule (exact window, `OFF_HOURS`), the fail-open rules, manual-mode behaviour, DEVICE-mode limitation; update the QR table at `:918`. Grade every line.
- [x] **Step 3: Release notes text** (the dashboard's release form takes hand-typed HTML; no file in the repo): put these three French lines in your report for the owner: « Horaires d'accès par formule : les adhérents d'une formule fermée sont retirés des tourniquets à l'heure de début et remis 5 minutes avant la fin, même sans internet. », « Un QR Wigo est refusé pendant la fermeture (« Hors horaires de votre formule »). », « Aucun changement pour les clubs qui n'utilisent pas cette option. »
- [x] **Step 4: Run once, one file per call** (with the env from Global Constraints): the five new files, then the regression set `tests/test_protocol2_save_and_flip.py`, `tests/test_access_dates.py`, `tests/test_p3b1_app_wiring.py`, `tests/test_push_safety_foundation.py`, `tests/test_removal_ceiling_pullsdk.py`, `tests/test_revoke_ownership_skip.py`, `tests/test_authoritative_revocation_pipeline.py`, `tests/test_account_pin_device_sites.py`, `tests/test_access_verification.py`, `tests/test_qr_allowed_days.py`, `tests/test_totp_roster_check.py`, `tests/test_card_decision.py`; then `python tools/check_sql_arity.py`. Re-run only failures; if a regression file fails on an assertion about `AccessWindow` equality, `_window_columns` arity or the `held_ids` query, fix the code, not the test, unless the test pins the exact old column list.
- [x] **Step 5: Commit** (no `--no-verify`): `feat(off-hours): planner`, `feat(off-hours): window columns, intent table, hold`, `feat(off-hours): minute pass and targeted dispatch`, `feat(off-hours): removal steps leave the held set out of the ceiling`, `feat(off-hours): QR OFF_HOURS refusal`, `release: MonClub Access 1.4.38 (off-hours)`.
- [x] **Step 6: Report**: branch, commits, per-file test counts, deviations from this plan, and every `[UNVERIFIED]` point. Expected unverified: behaviour on real hardware (300 members measured at about 3 minutes by the owner, not re-measured), the exact timing precision, DEVICE-mode gyms, whether the `request_member_revoke` path emits operator-visible `SKIPPED_NOT_OWNED` noise for members already removed by a date hold (filter `newly_held` to owned pins if it does), restart in manual mode before ULTRA ran.
