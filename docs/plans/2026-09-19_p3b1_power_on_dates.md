# P3b-1 — protocol 2 windows, power-on / offline date flips, QR allowed days, renewal ordering

Branch `claude/p3b1-power-on-dates` (from master `ca1e29a`). Backend contract: `monclub_backend`
main `2b75ddb3` (read-only): `ActiveMemberResponseV2`, `ActiveMemberUserV2Dto`, `AccessWindowDto`,
`AccessSyncMetaDto`, `UpcomingGymAccessCredentialDto`, `AccessDeliverability`,
`GymAccessController.getGymAccessUsers` (protocol 2 section).

Status markers as in the guide (§1). Every fact below was read from executable code unless marked.

## 0. Facts the design rests on

| # | Fact | Evidence |
|---|---|---|
| F1 | Under the default `pushingToDevicePolicy` the device roster has **no date filter**: `_filter_users_for_device` compares `validFrom/validTo` only for `VALID_ONLY`. Every cached member is pushed. | `[CODE: device_sync.py::_filter_users_for_device, _deliverable]` |
| F2 | Every roster reader goes through `sync_users`: `load_sync_cache` (`SELECT * FROM sync_users`, no WHERE), `list_sync_users_page` (QR/card `load_local_state`), `list_sync_users_by_active_membership_ids` (targeted member sync on both SDKs), `list_sync_users_by_main_account_ids` (ACCOUNT collapse). | `[CODE: db.py]` |
| F3 | An expiry today reaches the turnstile only through a server sync (delta `validMemberIds` → row deleted → shadow revocation). Offline, nothing on the PC ever removes an expired member. | `[CODE: db.py::save_sync_cache_delta; app.py::_apply_member_shadow_sync]` |
| F4 | The backend **renew** action updates the SAME `ActiveMembership` (new start/end, same id → same MEMBERSHIP pin). A new id for the same person comes from selling ANOTHER plan (`startMembership`, which refuses the same plan twice); the new row gets the same `user` entity, i.e. the same `userId`. | `[CODE: backend ActiveMembershipService.renewActiveMembership (sub.setStartDate/save), ::startMembership (findByMembershipIdAndUserId → 409; am.setUser(...))]` |
| F5 | The 32-bit venv has no `tzdata`: `zoneinfo.ZoneInfo('Africa/Tunis')` raises. `syncMeta.serverTime` carries the Tunis offset (`uuuu-MM-dd'T'HH:mm:ss.SSSXXX`). | `[measured 2026-09-19; CODE: backend SYNC_META_INSTANT_FORMAT]` |
| F6 | The first ULTRA/AGENT worker starts from the first sync tick's `work()` (t≈250 ms, after the fetch), i.e. after `MainApp.__init__` returns. A statement in `__init__` after `init_db()` provably runs before any worker. | `[CODE: app.py::__init__, ::_sync_tick; access/runtime.py]` |
| F7 | `get_local_state_generation()` is in-process; bumped by `save_sync_cache_delta` (members/credentials) and `UltraDeviceWorker.reset_fast_patch_caches`. The shared TOTP index is used only when its generation `>=` the worker's. AGENT's `DecisionService` cache is TTL-only (30 s) and cleared by its own `reset_fast_patch_caches`. | `[CODE: db.py; ultra_engine.py::_handle_totp_rescue; realtime_agent.py]` |
| F8 | The server enables an upcoming-only account's QR row at 00:16 Tunis (`DailyScheduleService.nightlySyncGymAccessCredentialEnabledStatus`, cron `0 16 0 * * *`). | `[CODE: backend]` |

## 1. Storage (new tables, `init_db`)

- `access_v2_state` (one row, id=1): `trusted`, `server_today`, `horizon_days`, `horizon_end`,
  `server_time`, `server_epoch`, `utc_offset_sec`, `snapshot_at`, `reconcile_sec`,
  `capabilities_json`, `pc_epoch_at_sync`, `skew_sec`, `floor_date` (highest gym date applied
  since the last v2 sync), `max_pc_epoch`, `applied_date`, `clock_suspect`, `clock_reason`,
  `updated_at`. **Not** cleared by `clear_version_tokens` (logout/hard reset clear the lists, not
  the clock floor).
- `member_access_window(active_membership_id PK, access_from, access_until, off_days_json,
  off_days_beyond_horizon)` — the windows of today's set, replaced whole on every members section.
- `sync_upcoming_users(active_membership_id PK, payload_json, access_from, access_until,
  off_days_json, off_days_beyond_horizon, qr_account_id)` — `upcoming[]` exactly as last sent.
- `sync_upcoming_credentials` — `upcomingCredentials` exactly as last sent (same columns as
  `sync_gym_access_credentials`), stored disabled.
- `sync_users_held` — same columns as `sync_users` + `held_reason`, `held_for_date`, `held_at`:
  rows of today's set the PC took off its roster for a later gym date (expired, frozen day).
- `member_person_link(active_membership_id PK, user_id, main_account_id, updated_at)` — written
  with `member_account_link` at the end of every `sync_users` write; never deleted. Renewal
  ordering needs the person of a pin whose row is gone. Keyed on `user_id` with NO
  `main_account_id IS NOT NULL` filter (MEMBERSHIP-pin gyms are where that column can still be
  NULL, guide §3.2d) and a plain upsert (a row whose only change is `user_id` must update).
  Back-filled from `sync_users` once in `init_db`.
- Counting: every place that COUNTS the member cache against the server counts held rows too —
  the self-heal (`app.py` `member_cache_is_stale(count_sync_users(), …)`: ratio 0.5 of the token's
  count, gyms ≥ 50, `sync_scope.py`), and the H-006 guards (`save_sync_cache` `old_count > 10`, the
  delta branch's `ids_to_remove`). A long closure must not turn into a FULL member refresh on every
  tick, and an empty payload must not slip under H-006 because rows were held.
- Logout (`save_sync_cache(None)`) clears the new lists (held, windows, upcoming, upcoming
  credentials) and sets `trusted=0`; it keeps the clock floor.
- `windowsVersion` lives in `sync_version_tokens` (so logout/hard reset drop it and the request
  sends it back like the other tokens) but is written/deleted **inside the same transaction** as
  the windows and the upcoming lists (contract: "together or not at all"). It is NOT in `app.py`'s
  `new_tokens` mapping.

## 2. The request

`MonClubApi.get_sync_data` always sends `protocol=2` and stamps `_clientReceivedAtEpoch`
(`time.time()` right after the response) into the returned dict. `windowsVersion` rides in
`version_tokens` from the table. Old server / switch off: the server ignores `protocol` and
answers v1.

## 3. The save (inside `save_sync_cache_delta`'s `_write`, and `save_sync_cache`)

1. v1 answer (no `syncMeta`), or a malformed v2 part: `trusted=0`, delete `windowsVersion`;
   `[T] SYNC_V2_REJECTED reason=…` for a malformed one. v1 data applied as today.
2. v2 answer: update `syncMeta` state (server today, horizon, server time, offset, skew). Clock
   check at sync (§5). Reset `floor_date` to `server_today` (server authority), `max_pc_epoch` to the
   PC time when the skew is sane, else to `server_epoch`.
3. Members section applied with a valid authority (not H-006 refused, authority valid):
   - **held rows**: delta — rows whose id is in `validMemberIds` and not in `users[]` are restored
     into `sync_users` (the server still counts them as delivered and will not resend them); the
     rest dropped. Full — all dropped (the full list supersedes them).
   - v2: replace `member_access_window` with `users[]` windows ∪ `memberWindows`; when `upcoming`
     is present (it must come with `upcomingIds` equal to its sorted ids, else rejected), replace
     both upcoming tables; store `windowsVersion`; `trusted=1`.
4. Members section skipped (v2): keep windows/upcoming; keep `trusted`.
5. After the commit: `apply_local_date_flips(source="save")`.

`save_sync_cache` (full replace; reached by the enrolment fallback `app.py` `get_sync_data(token=…)`
with no tokens, which now answers v2) runs the same v2 step inside its own `with get_conn()` …
`conn.commit()` transaction (it is not on the `_run_db_write_sync` writer): full list, so held rows
are dropped, and the windows, upcoming lists and `windowsVersion` are written with the users.

## 4. The flip — `apply_local_date_flips(source)`

One write job (read-compute-write in one `BEGIN IMMEDIATE`), idempotent, recomputed from full state:

- Gym date G (§5). Nothing moves unless `trusted=1` and G is known.
- Deliverable(m, G): `access_from <= G <= access_until` and `G ∉ off_days`. For G after
  `horizon_end`, `off_days` is unknown: a row with `off_days_beyond_horizon` is treated as
  deliverable inside its window (**policy, owner decision**, §9). Offline grace
  (`offline_revoke_grace_days` = N, default 0): only when G > `server_today`, a row with
  `access_until < G <= access_until + N` stays.
- `sync_users` rows with a window that is not deliverable on G → moved to `sync_users_held`
  (reason `expired` / `frozen` / `not_started`). Rows with no window (fast patch, a v1 period)
  are left alone.
- Held rows deliverable on G → moved back.
- Upcoming rows deliverable on G and not in `sync_users` → copied in (`_upsert_sync_user_row`);
  the upcoming list itself is never changed.
- `member_shadow` is not touched: the server's own revocation still arrives with the next sync
  (and finds the pin already gone: a known `SKIPPED_NOT_OWNED` residual, guide §7 R3-15).
- If anything moved: invalidate the sync cache, bump the local state generation, reset both
  engines' decision caches, and ask the running ULTRA engine for a full re-evaluation by calling
  `UltraEngine.request_sync_now(changed_ids=None, reason="date-flip")` directly (NOT
  `app._request_running_ultra_sync`, which returns early without a `refresh` dict), only when the
  engine is running and the gym is not in manual-sync mode (same gate as a server revocation).
  `[T] DATE_FLIP gym_date source removed restored promoted held dur_ms`.

**Triggers.** (a) `MainApp.__init__` right after `init_db()`, synchronously, before any worker can
start (F6); (b) a one-shot timer at 00:00:05 gym time, re-armed after each run; (c) a 60 s tick
that runs it when G moved (covers sleep, clock changes) — armed from `__init__`, NOT from
`_daily_sync_check` (started by `show_app()`, i.e. only when logged in and not restricted); (d) the
top of every sync tick's `work()` and every heartbeat, when G moved; (e) after every save. A
failure is logged (`[T] DATE_FLIP_FAILED`) and never stops start-up; the previous roster stays.

**The headline renewal case is produced by the flip itself**: a member whose current plan ends on
day D-1 and who bought another plan starting on D (a different `activeMembershipId`, F4) — at
00:00:05 or at power-on on D, offline, the old row is held out and the upcoming row promoted in
the same flip, so the same full-sync pass must write the new pin and remove the old one.

**00:16.** When a flip or a save leaves a stored membership starting on G and gym time is before
00:17, arm one automatic sync at 00:17:00 gym time (F8). The regular timer is the second chance.

## 5. Gym date and clock safety — `evaluate_gym_date(state, pc_now)`

- Offset from the last `serverTime` (F5). P = the PC's Tunis date from its UTC epoch.
- S = last `server_today`; A = `floor_date` (highest G applied since the last v2 sync).
- behind = `pc_now < max(server_epoch, max_pc_epoch) - 300 s` (policy tolerance);
  ahead = skew at the last sync `> 86400 s`. CLOCK_SUSPECT = behind or ahead.
- G = max(S, A) when suspect, else max(P, S, A). G never goes below S or A: a flat clock battery
  cannot re-admit anyone, and dates advance only up to what was already applied.
- Not suspect: `max_pc_epoch`, `floor_date` advance and are persisted.
- `[T] CLOCK_SUSPECT reason pc_utc server_utc skew_s gym_date` on entering, `[T] CLOCK_OK` on
  leaving; `/api/v2/status` `session.clockSuspectWarning` + reason; a pill in the Access UI.

## 6. QR allowed days (`verify_totp`, ALLOW step only)

`verify_totp(..., access_days=None)`. When given and trusted: the credential opens only if
(a) one of its grants has a window deliverable on the applied G, or (b) a grant is on the roster
with no window (v1 row), or (c) the by-account second chance finds a roster row of the same
account (a renewal with stale grants). When every grant has a window that is not deliverable on G:
`DENY_NOT_ALLOWED_TODAY` (both roster modes; `dateCheck` field on every QR result). A grant with no
window and no roster row is `unchecked` -- the roster check and its trial/enforce switch decide it
(review round 2: refusing it by date refused, in trial, a renewal whose stored grants are stale). A date refusal is final in `verify_totp_resilient` (no
wall-clock re-run). Never in `_iter_eligible_totp_creds` / `build_totp_index`.
`load_local_state` augments the credential list (same list feeds the loop and the index):
upcoming credentials whose grants are deliverable on G are added enabled; a main credential gains
the upcoming memberships whose `qrAccountId` is its account and that are deliverable on G. The
flip bumps the generation, so neither a stale index nor a stale list is used.

## 7. Renewal ordering (MEMBERSHIP pins, full-sync passes only)

A **hold** is an owned pin that left the desired roster, is not an explicit revocation of this
pass, and whose person (`member_person_link.user_id`) has a desired pin that is not confirmed on
the device at the start of the pass (needs a push, or in retry backoff). The removal ceiling is
checked on the whole removal set, holds included (unchanged count). Leavers are removed first as
today. After the push, a hold whose person's desired pins are now all confirmed is removed; the
rest stay (state kept, never pruned) until a later pass confirms the new pin. MB2000:
`_run_standalone_full_sync` / `_neutralise_revoked_pins`. PullSDK: `_sync_one_device` stale step.
ACCOUNT pins: nothing to do (a renewal keeps the account pin).

## 8. Client setting

`offline_revoke_grace_days` (int ≥ 0, default 0) in the Access config (`AppConfig`,
`ACCESS_CONFIG_FIELDS`, `AccessConfigSection`), editable through `PATCH /api/v2/config`.

## 8a. Tests (written first) and measurements

Tests: pure logic (`access_dates.py`: windows, deliverability incl. horizon/grace, clock evaluation,
flip planning); DB (every new table; save of v1/v2/malformed/skipped answers; held reconciliation
in delta and full; hold/restore round-trips all 20 `sync_users` columns; promotion; counts incl.
held; logout clear); the app wiring (startup flip before the first worker, the 00:00:05 timer, the
60 s tick, the 00:17 sync, manual mode, the ULTRA request); QR (`dateCheck`, upcoming credentials,
renewal grants, index = loop, resilient re-run); renewal ordering on both SDKs (hold, post-push
removal, ceiling unchanged, leavers first, prune keeps holds, failure of the new pin keeps the old).
The guide's §3.2b/§3.4 R3-21 claim that "a renewal is a new membership id" is corrected (F4).

Measurements (harnesses kept OUT of the repo, like §3.4e's `measure_door_wait.py`), base
`ca1e29a` (exported tree) vs this branch, same data (synthetic 1,800 members / credentials):
card verification, QR with the speed index, QR without it (loop), the ULTRA rescue path
(`_handle_totp_rescue`); process start → first `[ULTRA] Worker thread started` with the network
stubbed; the start-up flip on a 1,800-row roster.

## 9. Owner decisions and residuals (to be graded in the guide)

- Beyond the 7-day horizon, a freeze day the server did not send cannot be known; such a member
  is kept inside the window (end date still enforced). Owner may prefer the opposite.
- A server revocation of the old plan served by the TARGETED revoke while the new pin is not yet
  confirmed still removes the old pin first (outside "the same pass"); the date-driven case at
  midnight/power-on is handled by the flip's full sync before any server revocation arrives.
- A sync between 00:00 and 00:16 followed by an outage until opening leaves a new member's QR
  disabled until the next sync (the server's own rule, F8).
- Manual-sync-mode gyms: flips update the PC's roster and QR at once; the turnstile waits for the
  operator's "Sync data", as every other change does there.
- Held members (expired or frozen for the gym date) are not in the Access UI members list
  (`list_members_roster` reads `sync_users`) until the next sync drops or restores them.
