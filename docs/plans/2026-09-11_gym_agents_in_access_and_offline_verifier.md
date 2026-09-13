# Gym agents in MonClub Access + the Offline Mode Verifier — design & compatibility plan

**Status:** proposal, awaiting approval. **No code written yet.**
**Date:** 2026-09-11. **Author:** agent session, from a six-area parallel map of all three repos
plus a three-lens adversarial audit.
**Repos:** `monclub_access_python` (HEAD `a6be482`, "1.4.33", 71 commits past tag `access_1.4.31`),
`monclub_backend`, `mon_club_dashboard`.

---

## 0. Read this before touching anything

This is **production access-control software for live gyms.**

1. Read [`CLAUDE.md`](../../CLAUDE.md) first, then
   [`guide_for_agents_and_dev.md`](../../guide_for_agents_and_dev.md).
2. **Do not invent, assume, or estimate.** Every claim below is graded `[CODE]` (read in the
   source), `[FIELD]` (observed on a real install) or `[UNVERIFIED]`. A docstring is a *claim*,
   not evidence.
3. Verify with **both**:
   ```bash
   python -m pytest tests/ -q --ignore=tests/_pydeps
   python tools/check_sql_arity.py
   ```

---

## 1. Headline: this feature is not new work, it is a repair

**MonClub Access's membership-lifecycle mutations are already failing in production, today,
for exactly the reason this feature exists.** `[CODE]`

The chain, every link read in source:

| # | Fact | Evidence |
|---|---|---|
| 1 | Access sends lifecycle mutations to `/gym/activeMembership/renew`, `/gym/activeMembership/updateActiveMembership`, `/activeMembershipFreezes/create`, `/activeMembershipTaxes/*` | `app/api/monclub_api.py:704-716` (`_LIFECYCLE_ROUTES`) |
| 2 | Those paths resolve to `ActiveMembershipController` | `Helper/ApiConstants.java:38-39` |
| 3 | `renew` is handled at line 528; for a `Role.GYM` caller it calls `requireAgentFromCookieIfGym` at line 534. `updateActiveMembership` does the same at 509/515 | `Controllers/ActiveMembershipController.java:509-546` |
| 4 | That helper throws **HTTP 400** — `"Please choose a gym agent first (cookie 'currentAgentId' is missing)."` — whenever the caller's role is `GYM` and the cookie is absent | `Controllers/ActiveMembershipController.java:88-106` |
| 5 | Access authenticates **as a GYM account** | `GymAccessController.java:1071-1081` forwards to `signInDashboard` |
| 6 | Access has **never** sent an agent cookie. A repo-wide grep for an outbound agent identity across `app/` and `access/` returns nothing | `[CODE]` grep `gymAgentId\|agentId\|agent_id\|gym_agent` — only inbound `sync_infrastructures.gym_agent_json` |
| 7 | The lifecycle queue is **live UI**, not dead code | `tauri-ui/src/pages/UsersPage.tsx:464`, `:1476-1500` ("Lifecycle changes queue") |
| 8 | The UI call reaches the backend synchronously — full chain traced | `UsersPage` → `POST /api/v2/members/mutation` (`local_api_routes.py:74`) → `_handle_member_mutation` (`local_access_api_v2.py:3573`) → `submit_offline_mutation` (`app/ui/app.py:2244`) → `attempt_offline_mutation` → `api.apply_lifecycle_mutation` → `_LIFECYCLE_ROUTES[op]` |

Therefore every membership **edit, freeze and tax** action taken at an Access desk returns 400.
`db.py:9251-9276` classifies 400 as `{failure_type:'validation', recommendation:'modify',
countable:True}`, and `submit_offline_mutation` returns `needsFix` for anything that is not
`save_later` — *"validation / modify-required: surface to operator, do not queue a doomed
retry."* `[CODE]` So it fails **loudly, to the operator's face**, and is not silently queued.

**Scope caveat on `renew` specifically.** `renew` is present in `_LIFECYCLE_ROUTES`
(`monclub_api.py:708`) and its backend handler is agent-gated (`ActiveMembershipController:528`,
`:534`), but `op_kind` is supplied generically by the UI body and the `UsersPage` comment lists
only *edit / delete / freeze*. Whether the UI ever emits `opKind:"renew"` is **`[UNVERIFIED]`**.
Lead with `edit`, which is confirmed on both ends.

> **Action before anything else:** grep production backend logs for
> `"Please choose a gym agent first"`. The count and date range settle, in minutes, whether this
> has been broken for a year or whether those UI paths are unused in the field. **The answer
> changes the priority order of everything below.** `[UNVERIFIED]` until run.

This reframes the request: adding agents to Access is not a risky new gate on a working path.
On the lifecycle family it is **the fix for a path that is already broken.**

---

## 2. Corrections to the premises we started from

Stated plainly, because the plan depends on them.

### 2.1 "Adding agents will fix the offline feature" — not mechanically, but the instinct is right

There is **no causal link**. `[CODE]` Offline has three separate, real defects, none of which
involves operator identity:

1. **A 30-day app-entry lockout.** `_restriction_reasons()` (`app/ui/app.py:3123-3168`) gates on
   `auth.last_login_at` vs `cfg.max_login_age_minutes` (default 43200 min = 30 days,
   `config.py:182`). Past it, `show_restricted()` fires and — uniquely in AGENT mode —
   **stops the engine**, and `apply_realtime_agent_from_config()` (`app.py:3291-3312`) re-stops
   it after every sync tick, undoing a manual `/agent/start`.
   Note: every successful token refresh resets `last_login_at` (`monclub_api.py:313` omits it,
   `db.py:2936` defaults to now), so this clock measures **offline duration**, not time since a
   human typed a password.
2. **No offline login at all.** `MonClubApi.login` (`monclub_api.py:190-206`) is a blocking
   `requests.post(timeout=15)` that raises on any network failure.
3. **Money mutations queue but never replay** — `self._offline_money_mutations_enabled = False`
   (`app.py:629`), with the code's own reason: *"NOT attempted until the backend idempotency
   layer is deployed — else a retry double-charges."*

**But your design answers #3 directly, and that is the real win.** I owe you a correction here:
I told you earlier that "replay safety already exists." That was half right. `IdempotencyService`
+ `IdempotencyKey` + `X-Idempotency-Key` **do** exist — but a grep for
`clientRequestId|Idempotency-Key` across `src/main/java` finds handlers **only** in
`EventReservationController` and `PassManagementController`. `ActiveMembershipController`
returns **zero hits**. `[CODE]` The idempotency layer Access is waiting for was never wired to
the membership/money path.

**And the client half is already built.** `submit_offline_mutation` mints a `uuid4` per mutation
as `client_request_id` and the drain *"retries with the SAME idempotency key"*
(`app/ui/app.py:2244-2258`, `insert_offline_mutation(..., client_request_id=rid)`) `[CODE]`.
The Access client has been sending an idempotency key this whole time; the backend's membership
path simply never looked for one.

Your **Offline Mode Verifier replaces auto-replay with human approval** — which sidesteps the
double-charge problem rather than solving it with a key TTL. (`IdempotencyService.TTL_HOURS = 48`
would in any case be far too short for a gym offline for a week.) That is a better answer than
the one the code was waiting for.

**Much of Stage 3's client side already exists**, which materially reduces its cost: a full
offline-mutation queue with states, conflict detection against `expectedVersion`, a countable
failure ceiling, and operator resolution (`abort` / `rebase` with a fresh key) is implemented and
exposed over `/api/v2/mutations/*` — list, process-due, retry, cancel, resolve
(`local_access_api_v2.py:3611-3650`, `app/ui/app.py:2307-2330`). `[CODE]` Stage 3 is mostly
*server-side mirroring plus a dashboard*, not a new client subsystem.

### 2.2 Agents make offline *harder* before they make it better

A second credential is a second way to be locked out. And the offline queues
(`offline_creation_queue`, `offline_subresource_queue`, `offline_mutation_queue`) carry **no
actor column at all** `[CODE]` — so agents create a brand-new question: a row captured at 14:00
by agent A that drains at 19:00 while agent B is signed in belongs to whom? See §5, decision D2.

### 2.3 Access already writes a *false* attribution — worse than none

`ActiveMembershipService.java:1047-1048` sets **both** `am.setGymAgent(agent)` **and**
`am.setCreatedByGymAgentId(agent.getId())`, and `:1117` stamps the `MoneyTransaction` too — where
`agent` on the unattended path is *the plan's configured agent*, because `resolveRequiredAgent`
is reached with the requested id forced to null (`:1198-1201`, `:1298-1300`). `[CODE]`

So today a desk sale is attributed in three tables to an employee who was not there. This is the
business case for the feature, and it is stronger than "we have no attribution."

### 2.4 The fleet-version signal already exists on the wire

The synthesis claimed there is none; the audit falsified that and I verified it. `[CODE]`
`ComponentUpdateManager._run_check_and_download` (`shared/update_runtime.py:436-452`) passes
`current_version` into `get_latest_software_release`, which sends it as the **`currentVersion`
query param** (`app/api/monclub_api.py:537-538`), on a default 3-hour timer
(`update_runtime.py:311-312`).

**Every logged-in install already reports its version every 3 hours.** The backend simply does
not record it. A *backend-only* change — no client rollout, no fleet upgrade — yields a complete
fleet-version picture within one 3-hour window.

> **Do this first, in parallel with everything else.** It is small, it is zero-risk, and it
> converts the single biggest unknown in this plan into a fact. There is also a per-PC
> `appVersion` column already written by `GymAccessPcService` `[UNVERIFIED — write path
> confirmed, service not read in full]`.

### 2.5 Two live defects in the exact flow being copied

Fix both **before** porting the dashboard pattern to Access, or they ship to every gym PC:

- **One mistyped passcode signs the whole gym out.** `GymAgentService.loginGymAgent` sets no
  `skipAuthRedirect` (verified: zero matches in that file); `/agent` is absent from
  `PUBLIC_AUTH_PATHS` (`axiosConfig.ts:36`); so 401 → silent refresh succeeds (the gym JWT is
  live) → replay the same wrong passcode → 401 → `_retry` already true →
  `window.location.replace('/sign-in')`. `[CODE]`
- **A disabled agent returns 403, not 401** (`GymAgentController.java:446`) with no
  `AGENT_SESSION_REQUIRED` code, so it falls past the agent-gate branch. `[CODE]`
- Bonus, same area: a gym with a blank `statisticsPassword` and no admin agent gets **HTTP 500**
  from `ensureAdminAgentIfEmpty` (`GymAgentController.java:256-258`) — on the agent gate itself.
  `[CODE]`

### 2.6 Access already knows the admin agent's passcode

`validate_statistics_password` (`app/api/monclub_api.py:426-428`) POSTs
`/connected/account/openStatisticsInfo`. `GymAgentController.java:255-271`
(`ensureAdminAgentIfEmpty`) creates an admin agent whose `.password(...)` **is** the account's
statistics password. `[CODE]` So a link between Access and `GymAgent` already exists — the new
flow extends it rather than inventing it.

---

## 3. Non-negotiable compatibility rules

The fleet cannot be force-upgraded: updates auto-download but install only on an explicit
UI-triggered `launch_updater_and_exit()`, and `minCompatibleVersion` is stored
(`update_runtime.py:479`) and displayed (`local_access_api_v2.py:6265`) but **never compared to
the running version anywhere** `[CODE]`. So:

- **R1 — Purely additive on the backend.** Never add an agent requirement to an endpoint an old
  Access build already calls successfully. Follow the existing precedent verbatim:
  `AgentPermission.java:104-105` deliberately leaves `gym-device` update/getById ungated
  *"because the deployed access software calls it on every re-entry toggle."* Do not tidy that
  carve-out away.
- **R2 — Backend ships first and is backward-compatible alone.** Clients follow. Accept the agent
  identity when present; behave exactly as today when absent.
- **R3 — The agent step must never be able to stop a door decision.** Door verification is
  offline-capable in all three `accessDataMode` values (`access_verification.load_local_state()`
  / `verify_card()` / `verify_totp_resilient()`, local SQLite only) `[CODE]`. Keep it that way.
  AGENT mode is already the one mode torn down by the staleness gate — the most fragile place to
  add a credential.
- **R4 — Never cache password hashes on gym PCs.** Local secret storage is user-scope DPAPI with
  `CryptProtectData flags=0` (`shared/auth_state.py:80-90`) `[CODE]`. Offline agent identity, if
  ever needed, uses a short-lived server-issued token, not a BCrypt hash.
- **R5 — Prefer reusing existing `AgentPermission` constants.** `gym_agent_permissions.permission`
  is a **native MySQL `enum(...)` frozen at table creation**; every new constant is a latent
  **503 DATABASE_UNAVAILABLE** until `ops/ddl/2026-09-07_phase3_agent_permissions.sql` is
  regenerated and run. Its own header cites commit `140892a8`, where exactly this broke Guest
  Visits and Passes in production. If a new constant is unavoidable, the DDL is a **blocking
  pre-deploy step** with `SHOW CREATE TABLE gym_agent_permissions` verified afterwards.
  ⚠️ **Confirm first whether that DDL has ever been applied to production** — nothing in the repo
  records it, and if it has not, the whole Phase-3 permission block is *already* a live 503.

---

## 4. The design, in three shippable stages

Staged so each lands value alone and nothing is half-built.

### Stage 1 — Backend: accept an explicit agent id, additively (no client change)

The transport problem: the agent identity is a signed httpOnly cookie, and
`AgentSessionCookieFilter` / `GymAgentHelper.readAgentIdCookie` read only
`request.getCookies()` `[CODE]`. A Python `requests.Session` sending a `Cookie:` header alongside
`Authorization: Bearer` *should* work, but was not executed end-to-end `[UNVERIFIED]` — reverse
proxies and Spring cookie parsing untested.

**Use the in-repo precedent instead of inventing a transport.**
`EventController.java:445-478` (`resolveActingAgentForGymWithFallback`) already tries the cookie
first and, on failure, accepts a **client-supplied agent id** from a request param or body field
— today restricted to ADMIN callers. `[CODE]` Extend that pattern to the Access lifecycle and
sale paths, keeping a role/authority restriction so a gym JWT cannot impersonate arbitrary agents
without proof.

- Accept an optional `gymAgentId` on the Access-reachable lifecycle + sale endpoints.
- When absent → behave **exactly as today** (R1/R2). Old clients unaffected.
- When present → validate agent ∈ gym, `enabled`, and holds the right permission; stamp it.
- Start recording `currentVersion` (§2.4) and expose it on the dashboard.
- Fix the three defects in §2.5.

**Stage 1 alone repairs the §1 production breakage** once clients can supply the id, and gives
real attribution instead of the false stamp in §2.3.

### Stage 2 — Access: two-step login + true attribution

- **Naming:** `agent` is already taken in this repo — `app/core/realtime_agent.py` and
  `AgentPage.tsx` mean the **device** agent. Use **`operator`** for the human throughout new
  Access code, and say so in `guide_for_agents_and_dev.md`. This repo's `CLAUDE.md` is explicit
  about not conflating concepts.
- **Local schema:** `auth_state` is a hard singleton (`INSERT ... VALUES (1) ... ON CONFLICT(id)`,
  `SELECT ... WHERE id=1`, `db.py:2935-3024`) `[CODE]` — no room for a second identity. Needs a
  new table plus migration-on-upgrade, written so an older build reading a migrated DB still
  works (mixed-version and downgrade safety).
- **UX:** roster from `getGymAgents`, then a passcode — a **free-text password**, not a numeric
  PIN (`agent-gate-passcode.tsx:259-278`, "anyCharacters" copy). Hard gate on app entry, per your
  decision, but **subject to R3**: the door keeps deciding regardless.
- **Offline:** per your answer, offline reuses the **last signed-in operator** — no local
  credential verification, no cached hashes (R4). The session persists; actions are attributed to
  that operator and queued.
- Send `gymAgentId` on every mutation, including a **capture-time** stamp on queue rows (D2).

### Stage 3 — Offline queue + the Offline Mode Verifier

- **Backend model:** generalize the existing `KioskPendingWalkIn` shape `[CODE]` — a serialized
  DTO `payload TEXT`, `gymId`, a staff-facing `displayName`, `createdAt`. Add `operatorAgentId`
  (capture-time), `actionType`, `capturedAt` (client clock, distinct from `createdAt`),
  `status`, `decidedByAgentId`, `decidedAt`, `decisionReason`, and its **own** idempotency key —
  **not** the 48-hour `IdempotencyService` cache, which a week-long outage outlives.
- **Client clock is untrusted.** Store `capturedAt` as reported *and* server receipt time; show
  both in the verifier and flag implausible skew.
- **Apply/refuse endpoints**, gated by permission (R5 — prefer reusing
  `ACTIVE_MEMBERSHIP_MANAGEMENT` / `MONEY_TRANSACTION_MANAGEMENT` over minting a constant).
- **Dashboard page** listing pending offline actions grouped by operator and gym, with apply /
  refuse / bulk review, and a visible count badge so nothing rots unnoticed.
- Only now flip `_offline_money_mutations_enabled` — approval, not auto-replay, is what makes it
  safe.
- Feed decisions into the existing `AccountActionAudit` (`Models/AccountActionAudit.java:40-43`
  already carries a nullable `agent_id` with an index on `(agent_id, created_at)`) `[CODE]`.

---

## 5. Open decisions

| id | Decision | Recommendation |
|---|---|---|
| **D1** | Does Stage 2 hard-gate app entry, or ship read-only attribution first? | You chose hard gate. I'd still ship **Stage 1 + attribution** first and turn the gate on second — the gate is the only part that can lock a gym out, and R3 makes it safe only for the door, not for the desk. |
| **D2** | Which operator owns a queued row — capture-time or drain-time? | **Capture-time**, stamped on the queue row. Drain-time attribution is actively misleading, which is worse than today's honest blank. Requires Stage 1's explicit `gymAgentId` on the wire. |
| **D3** | New `AgentPermission` for the verifier, or reuse? | **Reuse** this round (R5). A new constant imposes strict DDL-before-deploy ordering on every environment. |
| **D4** | What happens to queued actions when the capturing operator is **disabled** server-side before approval? | Not yet decided. Recommend: still show them, clearly flagged, and let the approver decide — silently dropping a disabled operator's work loses real desk activity. |
| **D5** | Rollout switch: per-gym setting, or on for everyone? | Per-gym flag on `GymAccessSoftwareSettings`. ⚠️ Note it is **client-enforced** (an old client ignores it), and writing it needs `GYM_SETTINGS_MANAGEMENT` — itself a **Phase-3 constant** subject to the R5 503 risk. |

---

## 6. Things to fix that this work will otherwise trip over

- **`_AUTH_EXEMPT` is 14 handlers, not two** (`local_access_api_v2.py:7050-7071`) — and some
  **write**: `_handle_sync_now`, `_handle_sync_fast_patch_bundle`, `_handle_enroll_start`,
  `_handle_enroll_retry_push`. `[CODE]` An operator gate on the Access UI means little while these
  are reachable unauthenticated on loopback.
- **The dashboard drives the Access PC directly over that identity-free loopback** —
  `mon_club_dashboard/src/sections/services/LocalAccessService.ts` calls
  `http://127.0.0.1:8788/api/v2/scan/start`, `/sync/now`, `/sync/fast-patch-bundle`. `[CODE]`
  These are not two clients of one backend; decide whether operator identity applies here too.
- **Seven dashboard files still write a plain `document.cookie` `currentAgentId`** (e.g.
  `active-membership-form.tsx:391-397`, `reservation-form-helpers.ts:65-68`), while
  `tests/page-agent-cookie-ownership.test.ts` bans it with a 2-file allowlist. `[CODE]` Not a
  security hole — the filter verifies the signature and strips anything unverifiable — but it is
  a same-named duplicate cookie that will waste hours the moment anyone debugs agent sessions.
  Delete the writes, widen the allowlist.
- **At least five distinct acting-agent resolution paths exist**, not one:
  `requireActingAgentFromCookieForGym` (73 call sites / 28 files — *not* the 111 first claimed),
  `requireAgentFromCookieIfGym` (7 controllers), `getAgentFromCookies` + hand-rolled checks,
  `resolveActingAgentForGymWithFallback`, and `AgentGuard.java` vs `GymAgentHelper.java`
  duplication of unclear intent. `[CODE]` A change keyed to one name misses the other four.
- **`classify_failure` cannot distinguish "backend unreachable" from "my token was rejected"** —
  both are `save_later` (`db.py:9251-9257`). `[CODE]` An error-taxonomy bug that will make every
  rollout problem in this project hard to diagnose.

---

## 7. Verification plan

1. `grep` production logs for `"Please choose a gym agent first"` → settles §1.
2. Confirm `ops/ddl/2026-09-07_phase3_agent_permissions.sql` has been applied
   (`SHOW CREATE TABLE gym_agent_permissions`) → settles R5's latent-503 risk.
3. Record `currentVersion` server-side → real fleet picture within 3 hours.
4. Execute a `Cookie:` + `Authorization: Bearer` request end-to-end against the deployed
   environment before relying on cookie transport at all (or skip it via §4 Stage 1's param path).
5. Per change: `python -m pytest tests/ -q --ignore=tests/_pydeps` and
   `python tools/check_sql_arity.py`; backend `mvnw.cmd test` (baseline 2026-09-02: 3495 run,
   0 failures, 1 error — `PassSchemaMigrationIT`, needs Docker).
6. A regression test asserting old-client shape: the Access-reachable endpoints must still
   succeed with **no** agent id supplied, for as long as R1 holds.

---

## 8. Known unknowns

- What versions are actually installed, and in how many gyms. Not determinable from any repo
  (`update.json` is a dev-tree source — `shared/update_runtime.py:44-56` reads it only when not
  frozen; installed exes read their own baked `version.json`). §2.4 is the cheapest way to learn.
- Whether the Phase-3 DDL has ever run in production.
- Whether any gym still runs the genuinely pre-Tauri build (tag `stable`, v1.0, 2026-01-31),
  which parses the login response as raw text (`token = r.text.strip()`) and has no auto-update
  code at all — if the backend now returns JSON it is already broken and could never
  self-upgrade. `[UNVERIFIED]`
- Whether `GymAccessPcService` does anything with its per-PC `appVersion` beyond storing it.
- Whether `AgentGuard.java` vs `GymAgentHelper.java` duplication is a deliberate migration or
  drift.
