# Offers phase 2: two small follow-ups (Prélèvement filter, Access PC successor)

Date: 2026-11-12. Owner asked to build them now. Repos: `monclub_backend` (be), `mon_club_dashboard` (dash),
`monclub_access_python` (access). Builds on the merged tidy-up (`docs/membership-offers-phase2/spec.md`, be 753b57ee1,
dash f61bbde2). No DDL in either part.

## F1. « Prélèvement » filter on /gym-users

Why: staff find their prélèvement members by PLAN NAME today (« Prélèvement 12 mois »), which is why the tidy-up must
leave those plans alone. Since 10-30 every period (membership_term) carries `debt_collection_type` (PRELEVEMENT / OTHER),
and the dashboard edits it with the prélèvement switch. A real filter frees the plan name.

Rule: a membership is « prélèvement » when its CURRENT period is: the term with status ACTIVE, else the newest
non-cancelled term (highest `seq`), has `debt_collection_type = PRELEVEMENT`. A membership with no term at all uses
`active_membership.debt_collection_type = PRELEVEMENT`.

Backend (copy the `queuedTermOnly` filter end to end; it is the newest one of the same kind):
- `MemberQueueFilters`: add `boolean prelevementOnly` (keep the existing constructors working; NONE = false).
- `ActiveMembershipController`: `@RequestParam(defaultValue = "false") boolean prelevementOnly` on every list endpoint
  that already takes `queuedTermOnly` (and the facet/count endpoints that take the queue filters), passed through.
- `ActiveMembershipService`: one set query `prelevementMembershipIds(gymId)` (native or JPQL, grouped, NOT per row)
  implementing the rule above, used by `queueSpec` (`root.get("id").in(ids)`, `cb.disjunction()` when empty) and by the
  facet rows (`FacetRow.prelevement`, counted like `queueQueuedTerm` as `queuePrelevement` in the facets response).
- Tests: a JPA test with 4 memberships: ACTIVE term PRELEVEMENT (in), ACTIVE term OTHER + older term PRELEVEMENT (out),
  only a QUEUED/ENDED newest term PRELEVEMENT and no ACTIVE term (in), no terms and am PRELEVEMENT (in). Plus the
  facet count.

Dashboard (`src/sections/ActiveMembership/view/active-membership-view.tsx`, `src/sections/services/ActiveMembershipService.ts`):
- A queue chip « Prélèvement » (EN « Direct debit ») next to the existing ones (Kids / Staff / Groupes / Période en
  attente), with its count from `queuePrelevement`, sending `prelevementOnly`. Same look and behaviour as the others
  (URL state, reset, export if the others are exported).
- i18n FR + EN; i18n audit green; node tests for any pure helper changed.

## F2. Access PC: renewal starts on the replacement plan (tidy-up A1)

Why: after a tidy-up archives a plan, the Access PC renew dialog still opens on the member's (archived) plan, or on the
first plan when the archived one is not in the synced list, and the server refuses an archived plan (409). The tidy-up
records the replacement plan (`membership_plan_tidy_item`, actions REPLACE / OFFER_ENDED / OFFER_RUNNING, live item =
`active_plan_id` not null, target = `target_plan_id`); the backend already resolves it, with chains, in
`PlanTidyCommandService.successor`.

Backend:
- Find the endpoint(s) that feed the Access PC's synced membership plans (the access app stores them in SQLite table
  `sync_memberships` via `_replace_sync_memberships` in `app/core/db.py`; follow the payload key back to the backend
  DTO / service). Add a nullable `successorPlanId` per plan: for an archived plan with a live REPLACE / OFFER_* tidy
  item, the first plan along the target chain (max 5 steps) that is usable at the desk; else null. Compute it for the
  whole list with ONE grouped read of the gym's live tidy items (no per-plan query). Put the chain logic in one shared
  method reused by `PlanTidyCommandService.successor` (no duplicate rule).
- Old Access versions ignore unknown JSON fields: check the access app's parsing does not reject them.
- Test: the payload carries `successorPlanId` for an archived tidied plan, null otherwise, chain followed.

Access app (`monclub_access_python`):
- SQLite: `_ensure_column(conn, "sync_memberships", "successor_plan_id", "successor_plan_id INTEGER")`; write it in every
  INSERT into `sync_memberships` (there are several: grep them all); `list_sync_memberships` returns it.
- `tauri-ui/src/components/RenewDialog.tsx` (Online AND Offline dialogs): `StaffPlan` gets `successor_plan_id?`
  (match the real key the API returns). Initial plan = the member's plan when it is in the list and has no successor;
  else the successor plan when it is in the list; else today's fallback. When the successor is used, show a one-line
  note above the plan list: « Ancienne formule « X » rangée : renouvellement sur « Y ». » (French, like the rest of the
  Access UI). The staff can still pick any plan.
- Tests: the access repo's existing test style for the UI (vitest/node tests under tauri-ui if any) and Python tests for
  the db column (tests/). Run what exists for those files.
- Do not bump the app version or build an installer (the owner releases Access separately).

## Rules for the implementer

- No DDL on the backend. Keep every existing behaviour when the new flags/fields are absent.
- Commit messages describe the change only (no tool names, no trailers). The reviewer commits.
