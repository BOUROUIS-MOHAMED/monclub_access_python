# get_gym_users latency + logout/token fixes — implementation plan (2026-09-04)

Source of truth for two implementation sessions (Access repo, backend repo). Every claim
below was read from code or from the gym's own logs on 2026-09-02..04; grades follow
`guide_for_agents_and_dev.md` (`[CODE]` `[TEST]` `[FIELD]` `[COMMENT]` `[UNVERIFIED]`).

**Read first:** `CLAUDE.md`, `guide_for_agents_and_dev.md` (§0 maintenance contract — if
you change behaviour the guide describes, update the guide in the same change).

**Non-negotiables**
- Two gym types must keep working: PullSDK C2-400 gyms (RFID + TOTP QR, no fingerprints,
  client v1.4.19) and the zkemkeeper MB2000 gym (fingerprints + RFID, v1.4.28). A third gym
  (RFID + fingerprints) is coming.
- Tests MUST patch `app.core.db` to a temp DB or they hit the real
  `C:\ProgramData\MonClub Access\access\access.db` (fixture patterns:
  `tests/test_mirror_pushing_policy.py::_patch_db`, `tests/test_zk_standalone_driver.py::_make_sync_worker`).
- Verify with:
  `python -m pytest tests/ -q --ignore=tests/_pydeps --ignore-glob='**/pytest_tmp_*' --ignore-glob='**/.tmp_pytest*'`
  (baseline 908 passed on 2026-09-02) and `python tools/check_sql_arity.py` (PASS).
- Do not commit unless the operator asks in your session.

---

## Why (measured, `[FIELD]`, Desktop\Gmail\app-2026-08-30-from-13-to-14.txt.log, v1.4.26, 4 GB gym PC)

| Sync | Tokens sent | API_GETSYNCDATA | CACHE_SAVE_DELTA | upsert_member_shadow |
|---|---|---|---|---|
| 13:50 fresh install FULL | none | 6266 ms | 6651 ms (members 4765, credentials 1207, commit 267) | 1535 ms |
| 14:01 delta | all five | 891 ms | 59 ms | small |
| 14:03 delta | all five | 829 ms | 114 ms | small |

Steady state is already ~1 s. The expensive path is the token-less FULL refresh. The PC is
memory-starved (sys_mem_load 83-93%, MonClub Python RSS only 34-80 MB, a pure-Python step
stalled 3281 ms once) and plain `SELECT`s of the 934-row `sync_users` table with templates
took 0.7-6.8 s each, ~10× in 15 min (`DB_READ_users_split select_ms=6828 coerce_ms=47`).

FULL refresh triggers `[CODE]` (both member tokens absent): empty `sync_version_tokens`
(fresh install / hard-reset), SYNC-HEAL after logout (`app/ui/app.py:2252-2263`),
manual-sync-mode explicit sync — Sync-data click AND the 22:00 daily sync
(`app/ui/app.py:2282-2283`, `app/core/sync_observability.py:48`), hard-reset endpoint,
follow-up clears (`app/ui/app.py:2371/2390`).

---

## Item 1 — Logout must clear the version tokens (Access repo) — DO FIRST

**Defect `[CODE]`.** `POST /api/v2/auth/logout` → `_handle_auth_logout`
(`app/api/local_access_api_v2.py:1281-1313`) calls `clear_auth_token()` and
`save_sync_cache(None)` (`app/core/db.py:3121-3131`: DELETEs sync_cache, sync_meta,
sync_users, sync_memberships, sync_devices, sync_infrastructures,
**sync_gym_access_credentials** = the TOTP secrets read by
`app/core/access_verification.py:704`, sync_device_door_presets) but never
`clear_version_tokens()` (`app/core/db.py:1824`). The Tauri logout is only
`post("/auth/logout")` (`tauri-ui/src/context/AppContext.tsx:68-71`). Login schedules the
sync with hint `{"reason": "AUTH_LOGIN"}` (`local_access_api_v2.py:1000-1005`), which
`apply_trigger_hint_to_version_tokens` leaves untouched (`app/core/sync_scope.py:85-131`).
Next sync therefore sends the OLD credentialsVersion/devicesVersion → backend
`GymAccessController.java:618` answers refreshCredentials=false / refreshDevices=false →
those tables stay EMPTY. Members are rescued only by SYNC-HEAL, which requires the token's
member count ≥ 50 (`sync_scope.py:148,180`): a gym under 50 members stays at an empty
roster after logout→login. `force_login`/`clear_auth` (`app/ui/app.py:1247/1262`) were the
intended fix and are dead code (zero callers).

**Change.** In `_handle_auth_logout`, after `save_sync_cache(None)`, call
`clear_version_tokens()` (import from `app.core.db`). Keep `member_shadow` and
`device_sync_state` untouched (they are content hashes; the standalone incremental push
then re-pushes only pins whose hash changed). Optional cleanup: line 1283 references a
non-existent `ctx.app._on_click_logout` (AttributeError swallowed) — remove; decide whether
to delete the dead `force_login`/`clear_auth` or leave them.

**Tests.** With a temp DB: seed all five version tokens + rows in sync_users,
sync_gym_access_credentials, sync_devices; invoke the logout handler (or the function it
calls) with a minimal fake `ctx`; assert `load_version_tokens()` is empty AND the three
tables are empty. Add a second test proving the pre-fix hole: tokens present + empty tables
⇒ the request builder (`app/api/monclub_api.py:334-336`) would send credentialsVersion
(so the fix is the only thing preventing it). Existing coverage of the pure helpers:
`tests/test_sync_scope.py`.

**Cost.** Post-login sync becomes a proper FULL for every section — the heal already forces
that for members on big gyms; credentials/devices were silently broken before.

---

## Item 2 — Backend: fingerprint DELETE must be visible to the delta (backend repo)

Repo: `D:\projects\MonClub\monclub_backend`. Read its `CLAUDE.md` first (profile footgun,
credentials file). Test baseline 2026-09-02: 3495 run, 0 failures, 1 error
(`PassSchemaMigrationIT`, needs Docker), 1 skipped.

**Defect `[CODE]`.** `Controllers/UserFingerprintController.java:357`
`repository.deleteById(existing.getId())` bumps neither ActiveMembership nor User
`updatedAt`. `GymAccessController.buildDeltaChangedAmIds` (`:1609-1650`) collects changed
members from AM.updatedAt, User.updatedAt, image links and
`UserFingerprintRepository.findActiveMembershipIdsChangedAfter` (`:71`, JPQL
`fp.updatedAt > :since`) — a deleted row can no longer match. fpCount in
`currentMembersVersion` (`:1656-1675`) drops → refreshMembers=true → delta with that member
absent → client saves the token → the revoked finger stays in `fingerprints_json` and on
the MB2000 until a FULL refresh. CREATE/UPDATE are fine (`UserFingerprint.java:22,113`
`@EntityListeners(AuditingEntityListener)` + `@LastModifiedDate`, modifyOnCreation=true in
spring-data-commons 3.2.5).

**Change.** In the delete path, bump the owning ActiveMembership's `updatedAt` and save it
so it is `> since` for the next delta (verify how AM.updatedAt is maintained — if it is
`@LastModifiedDate`, an explicit set may need a real dirty change or `saveAndFlush`; read
`ActiveMembership.java`). Also fires `AccessSyncEntityListener` if AM has it (check).
Alternative (client-only, not preferred): force FULL when the fpCount segment of
`currentMembersVersion` decreases while `users=[]`.

**Tests.** A behavioural test that: creates a member with a fingerprint, computes the delta
since a watermark, deletes the fingerprint, asserts the member's AM id is in
`buildDeltaChangedAmIds(...)` for a watermark taken before the delete. Existing tests
(`GymAccessControllerDeltaWatermarkTest`, `GymAccessControllerMembersVersionTest`) are
trivial and do not cover this. Run `mvnw.cmd test`.

Related, do NOT fix blindly (design decision): scope-entry hole — a member whose freeze ends
or whose start date is reached appears in `validMemberIds` but not in `users`; the client
only deletes absent ids, never adds missing ones (`app/core/db.py:4082-4102`). Watermark
race: `membersDeltaWatermark = now()` at `:620` is taken ~0.5 s AFTER the scope query at
`:438-441`.

---

## Item 3 — Template-free reads on non-push paths + shadow write restricted to the diff (Access repo)

**3a. `load_local_state()`** — `app/core/access_verification.py:710` `users = list_sync_users()`
reads `fingerprints_json` (~2 MB of the ~2.3 MB row set) although the state indexes only
`activeMembershipId`/`userId` and card fields (`:714-747`). Consumers of this state in
`app/core/ultra_engine.py` (`_get_cached_local_state()` at 1997, 2281, 2387, 2651 →
creds/users_by_am/users_by_card; `_prefetch_member_images` reads image keys only) never
read `fingerprints` (grep of access_verification.py, ultra_engine.py, realtime_agent.py for
`fingerprints` = one comment at ultra_engine.py:1152). The PUSH path takes templates from
`load_sync_cache()` (`ultra_engine.py:1282/1434/1684/3800/3892` → `db.py:5086`) and
`DeviceSyncEngine._collect_templates_for_pin` (`app/core/device_sync.py:1297`), NOT from
local state. Each worker reloads its own copy after every sync (generation bump) and on a
300 s TTL — these are the 0.7-6.8 s reads in the log.

Change: `users, _ = list_sync_users_page(limit=0, offset=0, include_templates=False)`
(`app/core/db.py:5312`; limit=0 = no LIMIT; the projected-offline merge still applies at
offset 0). Add a comment at the call site citing the CAUTION docstring: every user in this
state has `fingerprints == []` and no consumer may count or push from it.

**3b. `list_members_roster`** — `app/core/db.py:5463` `users = list_sync_users()`; the
enrich loop (`:5463-5560`) never reads fingerprints. Same change. (Tauri: `hooks.ts:89`
and `LocalDbPage.tsx:341` still fetch the users endpoint with templates by default — check
whether either displays fingerprint counts before touching them; `LocalDbPage.tsx:304`
already passes `templates: "0"`.)

**3c. Shadow write** — `app/ui/app.py:809-832`: `diff_member_shadow(...)` is computed
(`:809`), `_shadow_changed = set(_diff["new"] + _diff["modified"])` (`:813`), then
`upsert_member_shadow(users=_incoming_users)` (`:832`) rewrites ALL 934 rows
(`app/core/db.py:2141-2204`, one INSERT…ON CONFLICT per row, 1535 ms on the gym PC).
Pass only the incoming users whose activeMembershipId ∈ new ∪ modified. Caveat `[CODE]`:
`diff_member_shadow` (`db.py:2386-2409`) does not compare `membership_id`, so a plan-only
change would leave `member_shadow.membership_id` stale — no reader outside db.py uses that
column today; either also include rows whose membership_id differs, or document it.
`member_shadow` has a real PRIMARY KEY (`active_membership_id`).

**Tests.** (a) `load_local_state` issues the template-free projection (patch
`list_sync_users_page` and assert `include_templates=False`, or inspect the SQL via
`set_trace_callback`) and still indexes cards/am ids identically; (b) roster unchanged;
(c) `upsert_member_shadow` receives exactly the diffed users; (d) keep green:
`tests/test_sync_users_page_templates.py` (15), `tests/test_delta_user_cache.py`,
`tests/test_standalone_incremental_sync.py` (30), `tests/test_ultra_engine.py`.
Expected effect: direction `[CODE]`+`[FIELD]`; magnitude on the gym PC `[UNVERIFIED]`.

---

## Item 4 — Per-row diff in full-replace mode (Access repo) — LAST, only after 1-3 are green

Helps only FULL refreshes against a POPULATED cache (manual-mode click / 22:00 daily sync /
hard-reset). Zero gain on fresh install or post-logout (old_count = 0, guard bypassed at
`db.py:4156`).

`app/core/db.py:4110-4235` full-replace branch: when the content hashes differ it does
`DELETE FROM sync_users` (`:4195`) + per-row `INSERT OR REPLACE` of all rows. Replace with:
key rows on the PAIR `(user_id, active_membership_id)` (matches the partial UNIQUE index
`db.py:862` and the hash sort key `:4136`); upsert new/changed rows; **DELETE rows whose key
is absent from the incoming set** — NOT via `validMemberIds`, which is null in full mode
(`GymAccessController.java:739`) and skipped by the delta branch (`db.py:4082`); explicitly
delete NULL-key rows (outside the partial index, `INSERT OR REPLACE` never replaces them);
keep the H-006 zero-users guard (`:4117-4123`); reproduce the hash's string normalisation
(TEXT-affinity columns return str; `userProfileImage` default `''` vs DB None) or every row
compares as changed; add sub-timers like delta mode has (`:4103-4108`). Nothing depends on
DELETE+INSERT semantics: no triggers, no rowid readers, `device_sync_state.desired_hash` is
a content hash, `bump_local_state_generation()` is unconditional (`:4289-4290`).
Failure mode of a wrong delete-absent = an ex-member's card stays ALLOW at the turnstile
(`access_verification.py:224-244`) and their pin stays in every device roster — tests are
mandatory: changed row rewritten; unchanged row untouched (rowid stable, pattern
`tests/test_delta_user_cache.py:150-200`); absent row deleted; user with two rows
(superseded + current membership) preserved; NULL-amid row not duplicated across two
refreshes; `users=[]` guard; `test_delta_user_cache.py:116` full-mode semantics still hold.

---

## What NOT to do (refuted, 2026-09-02 adversarial pass)
- "Members first, templates later" — needs a backend param; existing writer erases cached
  templates; MB2000 double-push of 872 pins; a fingerprint-enabled PullSDK panel DELETES
  every template on the device until the second pass (`device_sync.py:758,1701-1704,831`).
- Server-side template delta inside FULL mode — no per-template timestamp; member-level
  merge resurrects deleted fingers.
- Keep membersUpdatedAfter across logout — token already survives; the cache is wiped.
- Delay/throttle the image prefetch — cannot start before the roster is saved; 0 ms.
- executemany / commit tuning — one transaction per job, commit = 4% of the write.
