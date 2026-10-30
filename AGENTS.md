# Notes for agents

Read CLAUDE.md in this folder too: it holds the repo rules for every agent.

## MonClub changelog (owner rule, 2026-10-30)

After the owner accepts a finished feature or fix, ask: "Add this to the MonClub changelog?" On yes, follow
`monclub_backend/docs/changelog-tracking/README.md`. In short: draft the FR + EN entry, give the owner a Claude
Design prompt to check it, then append it to the dashboard `src/sections/changelog/data/changelog-entries.ts` with
the next `seq` and `release: 'next'` (Access items also in `tauri-ui/src/whats-new/access-changelog.ts`), and write
`docs/changelog-tracking/changelog_<slug>_<date>.md` in the backend repo. At a dashboard deploy, replace every
`'next'` with the deploy date. In a background build started from a plan, do not ask and do not add entries: the
reviewer does it after the review.
