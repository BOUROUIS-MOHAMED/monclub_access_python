# Fingerprint chain — field grep cheatsheet

One grep per question, for the day of a field test. Nothing here needs a rebuild.

Status markers follow the repo convention (`CLAUDE.md`, `guide_for_agents_and_dev.md` §1):
`[CODE]` `[TEST]` `[FIELD]` `[COMMENT]` `[UNVERIFIED]` `[UNKNOWN]`.

---

## 0. Where the logs are

**On the gym PC** `[CODE: app/core/utils.py::_pick_data_root, app/core/logger.py::setup_logging]`

```
C:\ProgramData\MonClub Access\data\logs\
```

Falls back to `%LOCALAPPDATA%\MonClub Access\data\logs` when `%PROGRAMDATA%` is not
writable, and `MONCLUB_ACCESS_DATA_ROOT` overrides both.

**File names** `[CODE: logger.py::active_log_name_for, _LOG_FILE_RE]`

| Pattern | What it is |
|---|---|
| `app-YYYY-MM-DD-from-HH-to-HH.log` | current window |
| `app-YYYY-MM-DD-from-HH-to-HH.N.log` | same window, after a 50 MiB size rotation |
| `app-YYYY-MM-DD-am.log` / `-pm.log` | legacy, pre-rollout — still uploaded and cleaned up |

**19 windows per day, and they are NOT all hourly.** `[CODE: logger.py::_WINDOW_START_HOURS]`

```python
(0, 3, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
```

19 entries ⇒ 19 files a day. The first three are multi-hour — `00-03`, `03-06`, `06-08` —
then it is hourly from `08` to `23`, and the last window runs `23-24`. A test at 09:40 is
in `app-<date>-from-09-to-10.log`. **Do not tell an operator "one file per hour".**

Each file is uploaded when its window closes, so the newest window is still open and not
yet uploaded. Sibling marker files track that: `<logname>.pending`, `.uploaded`, `.failed`
`[CODE: app/core/log_uploader.py]`.

**In the dashboard:** the Access logs page lists the uploaded windows (19 a day, so use
its "Load more" — a single page does not hold a full day). `[UNVERIFIED]` — the dashboard
lives in another repo and was not read for this note; the file names above are the ones
the desktop app writes and uploads.

**Line shape** `[CODE: logger.py:256, telemetry.py::event]`

```
2026-09-04 09:12:03,441 | INFO | [T] ENROLL_DONE enroll_id=e41273-9ab2 outcome=ok ...
```

Every telemetry line starts `[T] `. To see only telemetry: `grep -F "[T] "`.

---

## 1. Did the enrolment reach the backend?

```bash
grep -F "[T] ENROLL_" app-2026-09-04-from-09-to-10.log
```

One enrolment = one `enroll_id` (e.g. `e41273-9ab2`), on every line of it. Once you have
the id, follow just that one:

```bash
grep -F "enroll_id=e41273-9ab2" app-2026-09-04-from-*.log
```

Expected sequence for a healthy enrolment:

| Event | Says |
|---|---|
| `ENROLL_START` | `am_id` chosen, `am_source` (`caller` \| `local-cache`), `candidates` |
| `ENROLL_SCANNER phase=init` | `rc`, and the `dll_path` / `dll_dir` actually loaded |
| `ENROLL_SCANNER phase=open` | scanner opened |
| `ENROLL_SAMPLE` ×3 | `sample=1..3 result=captured size=…` |
| `ENROLL_MERGE` | `ok=True size=…` |
| `ENROLL_BACKEND_REQ` | `am_id finger_id template_version encoding tpl_chars tpl_sha1` |
| `ENROLL_BACKEND` | **`status=` the real HTTP code** |
| `ENROLL_MEMBER_SYNC` | the targeted push was asked for |
| `ENROLL_DONE` | `outcome=` and per-phase `_ms` |

**Straight to the answer:**

```bash
grep -F "[T] ENROLL_BACKEND " app-*.log        # note the trailing space
```

`result=ok` + `status=200/201` ⇒ it reached the backend and was accepted.
`result=rejected` ⇒ `status=` and `body=` carry the refusal verbatim.
`result=request_failed` ⇒ it never got there (`err=`).

> `ENROLL_BACKEND` is emitted by the API layer and carries **no `enroll_id`** — that layer
> is shared with other callers. Correlate it with `ENROLL_BACKEND_REQ` on
> `(am_id, finger_id)`. `[CODE: app/api/monclub_api.py::create_user_fingerprint]`

**HTTP 403 here is usually not a permissions problem.** `[FIELD: 2026-08-30, OXYGENE_FIT]`
Twice it has been a wrong `activeMembershipId`: a plan id, or the wrong row of a member
holding two active memberships. Compare `ENROLL_START`'s `am_id` / `candidate_ids` with
what the dashboard shows.

**Outcomes** (`ENROLL_DONE outcome=`) `[CODE: app/ui/app.py::_remote_enroll_worker]`

`ok` · `ok_deferred_offline` · `capture_failed` · `backend_rejected` · `sync_failed`
(the pre-flight sync, not the targeted one) · `no_membership` · `restricted` ·
`not_logged_in` · `cancelled` · `no_pending_record` · `error`

Every exit path passes through it, so `grep -c "ENROLL_DONE"` counts every enrolment
attempted on that PC. `[TEST: tests/test_fingerprint_telemetry_enrol.py::TestEnrolDoneTelemetry]`

> **No image quality is logged, because this SDK does not expose one.**
> `ZKFPM_AcquireFingerprint` returns `(rc, template_length)` only. `ENROLL_SAMPLE` reports
> `size`, and a `score` only on a `result=rejected` line (a `db_match` against the previous
> sample). `[CODE: app/sdk/zkfinger.py::_acquire_once]`

---

## 2. Did the template arrive from the backend?

```bash
grep -F "[T] FP_ARRIVED" app-*.log
```

`members_with_tpl=` and `templates=` say how many arrived in that sync.
`delta_mode=True` ⇒ `am_ids=` lists exactly whose templates changed (a delta carries only
changed users, so that list *is* the answer).
`delta_mode=False` (full refresh) ⇒ `ids_omitted=True`, counts only. This is deliberate:
a full refresh carries every member, and a per-row loop there is a latency change on the
gym PC, not instrumentation. Use `FP_DELTA` below for per-pin detail on that path.

Which pin's template changed, per device:

```bash
grep -E "FP_DELTA|FP_DELTA_USER" app-*.log
```

`FP_DELTA … fields={'tplh': N}` ⇒ N members' template hash changed.
`FP_DELTA_USER pin=… fields=['tplh']` names them (first 8).
`[CODE: app/core/ultra_engine.py::_log_fingerprint_delta]`

---

## 3. Was the template pushed to pin X?

```bash
grep -F "[T] ZKEM_PUSH" app-*.log
```

| Event | Says |
|---|---|
| `ZKEM_PUSH_CHUNK` | one per chunk of 10: `first_pin`..`last_pin`, `tpl_attempted`, `tpl_ok`, `dur_ms` |
| `ZKEM_PUSH_DONE` | whole roster: `pushed`, `failed`, `tpl_attempted`, `tpl_ok`, `tpl_failed` |
| `ZKEM_PUSH_FAILED_PINS` | **which pins did not land, and why** |

**Straight to the answer for one pin:**

```bash
grep -F "[T] ZKEM_PUSH_FAILED_PINS" app-*.log
```

`pins=` is `pin=reason` pairs. Reasons `[CODE: app/sdk/zk_standalone.py::_do_push_roster]`:

| Reason | Means |
|---|---|
| `set_user_info_false` | the terminal refused the **member row**; no template was even tried |
| `template_refused_fN` | the member row landed, finger **N** was refused — this member cannot verify |
| `finger_remove_false_fN` | the terminal refused removal of tracked vacated slot **N**; revocation is unconfirmed |
| `finger_remove_exception_fN` | removal of tracked vacated slot **N** raised; revocation is unconfirmed |
| `exception:<Type>` | the push raised part-way through that member |
| `chunk_wedged_or_unconfirmed` | the whole chunk wedged; nothing in it was confirmed |
| `not_attempted` | the push stopped early (3 wedges or a failed reconnect) before this member's chunk was sent — nothing was written |
| `template_version_mismatch_fN` | finger **N**'s template is of another algorithm version than the terminal's (`~ZKFPVersion`), so it was NOT uploaded (P3a-2) — re-enrol that finger |

A pin absent from every `ZKEM_PUSH_FAILED_PINS` line, in a push whose `ZKEM_PUSH_DONE`
says `ok=True`, was pushed. `[TEST: tests/test_fingerprint_telemetry.py::TestPushFailedPinsTelemetry]`

**A member missing from the roster entirely on an ACCOUNT-pin device:**

```bash
grep -F "[T] PIN_SCHEME_ACCOUNT_WITHHELD" app-*.log
```

`withheld=N` members were deliverable to `device_id` but their cached row carries no
`mainAccountId`, so no pin could be derived under `pinScheme=ACCOUNT`. They are not pushed
under their membership id on purpose (that number can be another person's account pin on
the same terminal). The WARNING line just above it in the log lists a sample of `userId` /
`activeMembershipId`. A full member refresh fills the field.
`[CODE: app/core/device_sync.py::_filter_users_for_device]`

**When did a device switch pin scheme?**

```bash
grep -F "[T] PIN_SCHEME_SWITCH" app-*.log
```

`previous=` / `scheme=` / `cleared_rows=` for `device_id`. From that moment the client pushes the new
scheme's pins; the terminal keeps the old scheme's users until an operator wipes it. Door events stamped
before the switch are read under `previous`. `[CODE: app/core/db.py::_record_device_pin_scheme_switch]`

**Did a push stop because the scheme changed under it?**

```bash
grep -F "[T] PIN_SCHEME_PASS_STOPPED" app-*.log
```

`worker=ULTRA:<id>` (the ULTRA worker of that turnstile: an MB2000, or a PullSDK panel at `path=full_sync`)
or `device_id=` (the PullSDK sync engine), `path=`, `scheme=` the scheme the stopped pass had derived its
pins under. Nothing more was written by that pass; the next pass pushes the new scheme. One or two of
these right after a `PIN_SCHEME_SWITCH` are expected. On the MB2000 the chunk already in flight (at most 10
members) may still have gone out under the old scheme; the cutover runbook's cables-out interlock and its
proven restart are what keep that from ever reaching a turnstile. `[CODE: app/core/device_sync.py::pin_scheme_superseded; guide §3.2e]`

> **Per-pin success lines are deliberately not emitted.** The STA thread pumps no COM
> messages while a command runs and the log handler writes inline, so a line per member on
> a 928-member push would widen that window — a behaviour change, not instrumentation.
> Detail is aggregated at chunk boundaries. The existing capped `push trace pin=…` lines
> (`_PUSH_TRACE_MEMBERS=3`, `_PUSH_TRACE_TEMPLATES=5`) still give call-by-call visibility
> for the first few, and are written **before** each call so a hang names its culprit.
> `[CODE: zkemkeeper_guide.md §5]`

**Why a template was refused:**

```bash
grep -F "[T] ZKEM_PUSH_TPL_REFUSED" app-*.log
```

Carries `size`, `template_version`, `device_fp_version`, `fp_used`/`fp_capacity`. The two
documented causes are a **full fingerprint store** (`fp_used` == `fp_capacity` — normal on
a gym migrating from older software) and an **algorithm-version disagreement**, which gets
its own line:

```bash
grep -F "[T] ZKEM_TPL_VERSION_MISMATCH" app-*.log
```

**Why a template was refused — on a PullSDK panel (C2/C3/C4/inBio):**

```bash
grep -F "[T] PULLSDK_PUSH_TPL_REFUSED" app-*.log
```

Carries `device_id`, `pin`, `fingers` (how many the member has) and `errs` (how many
were refused). The parallel of `ZKEM_PUSH_TPL_REFUSED` above, for the other SDK.

> **New since 2026-09-11, and it will look like a regression.** Before this, a refused
> template on a PullSDK panel was a `logger.warning` and nothing more: the pin was still
> recorded `last_ok=1`, `push_pin_history.status=SUCCESS` and
> `device_content_mirror.push_ok=1`, so the dashboard showed the member **green** while
> their finger did not open the door — and because a stored success also stores the
> content hash, the pin was never selected for retry again.
>
> Those members now show **FAILED / amber**, and a batch that previously read SUCCESS
> may read PARTIAL. Nothing got worse; a failure that was always there stopped hiding.
> A gym that has been quietly refusing templates for months will surface all of them on
> the first sync after upgrading.

**A departed member the terminal refused to delete:** (P3a-2)

```bash
grep -F "[T] REMOVAL_RETRY_SCHEDULED" app-*.log
```

`pins=N delay_s=D` means N removals failed and the worker will try again by itself in D seconds (30, then doubling, never more than 300) — it no longer waits for the roster to change. Removals are never subject to the push backoff below.

**A member who keeps failing and then goes quiet:**

```bash
grep -F "[T] SYNC_RETRY_BACKOFF" app-*.log
```

Because a refused template is now a real failure, a pin that can never succeed would be
re-pushed on **every** sync run forever — each retry costing a firmware-cache clear plus a
ten-call probe per finger, inline on the worker with the door queue blocked. So after
**3 free attempts** on unchanged content the retry backs off: 15 min, doubling, capped at
6 h (24 h before P3a-2). `pins=` is how many were held back this run; the same count also appears as
`backoff_skipped=` on the `[DeviceSync] … DONE` summary line.

Two things deliberately defeat the backoff, so a real fix is never delayed:

- **a re-enrolment** — new content changes the desired hash, and the backoff only applies
  when the hash is byte-identical to the attempt that failed;
- **a full or forced resync** (`FULL_REPLACE`, which since P3a-2 clears the panel only when its
  rows fit under the removal ceiling — see `REVOKE_ABORTED` below), which rebuilds the push set wholesale.

**A push that stalled:**

```bash
grep -E "ZKEM_PUSH_WEDGED|ZKEM_PUSH_RECONNECT|ZKEM_PUSH_ABANDONED|ZKEM_STA_WEDGED" app-*.log
```

`ZKEM_PUSH_WEDGED` names the chunk and its member count; `ZKEM_PUSH_RECONNECT ok=` says
whether the link came back; `ZKEM_PUSH_ABANDONED` means three consecutive wedges stopped
the roster. `ZKEM_STA_WEDGED` is the driver abandoning the STA thread.

> The abandon reason exists in **two spellings** and they are load-bearing for matching:
> `command '<op>' timed out after <n>s` (inside `ZKEM_STA_WEDGED reason=`, truncated to 120
> chars) and `zkemkeeper command '<op>' timed out after <n>s` (the raised error). Grep for
> the wrong one and you find nothing. `[CODE: zkemkeeper_guide.md §2]`

**The terminal is locked and nobody can badge in:**

```bash
grep -F "[T] ZKEM_DEVICE_LEFT_LOCKED" app-*.log
```

The 22:00 / manual full reconcile locks the terminal UI for the whole roster
(`EnableDevice(False)`) and releases it at the end. If the release fails — or the
push wedges or the process dies before reaching it — the terminal stays locked, and
on most sites it is the only thing on the door.

**It recovers by itself on the next connect**: since 2026-09-11 every successful
connect issues `EnableDevice(True)`, so the 1800 s `CONN_REFRESH`, a wedge-recovery
reconnect, or restarting MonClub Access all clear it. Restarting the app is the
fastest manual fix. Before that change the lock survived until the next nightly
reconcile.

**Terminal occupancy, before and after:**

```bash
grep -F "[T] ZKEM_DEVICE_COUNTERS" app-*.log
```

Emitted at every worker connect (no extra device round-trip), so two consecutive lines
bracket a push. `c_fingerprints` is the terminal's fingerprint count.

> `label_source=driver._STATUS_FIELDS` is on every line on purpose. The driver's
> index→name table **disagrees** with `tools/mb2000_scripts/3_get_device_info.ps1` and
> `12_force_open_door.ps1`, which label index 6 as attendance logs and 8 as face templates.
> Nothing in the repo settles which is right, so treat the *names* as unproven and the
> *numbers* as real. `[UNVERIFIED]`

---

## 4. Was an authoritative member revocation confirmed?

```bash
grep -F "[T] MEMBER_REVOKE" app-*.log
```

`MEMBER_REVOKE_REQUESTED` starts the device action. `MEMBER_REVOKE_DONE mode=deleted`
means whole-user deletion was consistently confirmed; `mode=neutralised` means the
disabled blank-card row and every locally tracked finger-slot clear were confirmed.
`MEMBER_REVOKE_FAILED` keeps local ownership state and schedules full reconciliation.
`MEMBER_REVOKE_SKIPPED_NOT_OWNED` (since P3a-2; replaces `MEMBER_REVOKE_OWNERSHIP_MISSING`) means MonClub
has no proof it wrote that pin, so it made no destructive device call and FINISHED the revocation — the
member may still be on the terminal (another system's user, or a push MonClub never confirmed). It no longer
blocks later syncs. The push-history page shows `SKIPPED_NOT_OWNED=n (...)`.
`MEMBER_REVOKE_DONE mode=repushed` (pinScheme=ACCOUNT devices) means the member lost ONE membership
but still holds another this device accepts: the person's pin stayed and its row was re-pushed without the
revoked plan. `MEMBER_REVOKE_PIN_UNKNOWN` means the membership could not be mapped to a person's pin, so
nothing was removed and a full sync was requested.
`[CODE: app/core/ultra_engine.py::_run_standalone_member_revoke]`

For full reconciliation, `REVOKE_DONE deleted= neutralised= slots= ok=` counts only
confirmed outcomes. `ok=False` means at least one PIN or local-state cleanup remains
for retry.
`REVOKE_SKIP_INCOMPLETE_ROSTER withheld=N` means the pass did not run at all: N deliverable members on an
ACCOUNT-pin device have no `mainAccountId`, so departed pins cannot be told apart from theirs.

**Did a crash leave a member MonClub could not prove it owned?** (P3a-2, both SDKs)

```bash
grep -E "\[T\] PUSH_INTENT_(FAILED|READBACK)" app-*.log
```

Before every push MonClub records what it is about to write (the "intent"). `PUSH_INTENT_FAILED` means
that record could not be written, so NOTHING was pushed that pass. `PUSH_INTENT_READBACK` is the check,
once a day on an MB2000 (after the morning sync) or inside a C3 sync, of pushes that were never confirmed
for members who have since left: `promoted=` were found on the terminal exactly as MonClub wrote them and
will be removed; `dropped=` never reached it; `mismatched=` hold a different user and are left alone.
`ok=False` means the terminal listing failed, or was not trusted (`reason=no_owned_pin_listed`: it showed none
of MonClub's own members), and nothing changed. A listing that misses any of MonClub's members still
promotes exact matches but drops nothing. `missing_owned=N` counts MonClub members that are NOT on the
terminal although MonClub thinks they are (deleted there by another system, or the listing was cut
short; the WARNING line just before names up to 20 pins). MonClub does not push them back by itself:
check those pins on the terminal and report them to support. This check runs only while some departed
member's write is unconfirmed, so NO line does not mean nothing is missing; while missing members and
such writes both exist, it runs every day. `dur_ms` is how long the door waited for it.

**Was a removal refused as too large?** (P3a-2, both SDKs)

```bash
grep -F "[T] REVOKE_ABORTED" app-*.log
```

`REVOKE_ABORTED path=… count=N roster=R ceiling=C reason=…` means one removal step would have taken N
users off the terminal against a desired roster of R, above the one shared ceiling `max(10, 25 % of R)`
(or R is 0: `reason=empty_roster`). Nothing was removed, the local record of those pins was kept, and the
rest of the sync still ran. `path=stale` is a C3 panel's stale pins, `path=table_clear` a FULL_REPLACE
panel clear, `path=standalone_revoke` an MB2000's departed members. It repeats on every sync until the
cause is found (a truncated roster, a pin-scheme cutover that needs the manual wipe, or a real mass
departure an operator must confirm). The push-history page shows it as `REVOKE_ABORTED=N (…)`.
`[CODE: app/core/push_safety.py::check_bulk_removal]`

**Is a removal waiting for a driver lease?** (P3b-2)

```bash
grep -F "[T] REMOVAL_DEFERRED" app-*.log
grep -F "[T] REMOVAL_CONFIRMED" app-*.log
```

`REMOVAL_DEFERRED … reason=add_only` means this PC drives the turnstile under a new or forced lease and has
not yet restored (or read back) the record of who MonClub put on it: removals wait, additions go on. It clears
by itself once the PC is online. `reason=handover_release` means the turnstile is being handed to another PC.
Neither is a `REVOKE_ABORTED` and neither offers "Confirm removal". `REMOVAL_CONFIRMED` is a removal above the
ceiling the owner confirmed for exactly that list. The roles and the socket are on the « Pilote / Lecteur »
page; `[V2]` log lines tell what the realtime layer did.
`[CODE: app/core/push_safety.py, app/core/v2/]`

---

## 4b. Is the terminal full? Unusable templates? (P3a-2)

```bash
grep -E "\[T\] (CAPACITY_FULL|TEMPLATE_VERSION_MISMATCH)" app-*.log
```

`CAPACITY_FULL users_free=U fingerprints_free=F skipped=N withheld_fingers=K` means the terminal reported no room: N new members were NOT written at all (no free user slot), and K fingers were not written (no free fingerprint slot) — those members DID get their card and name, so they can badge in; only the missing fingers wait. Both are retried at the next sync, and removals still ran. To make room, remove users that are no longer needed — on gym 45's shared terminals the other system's users belong to its operator: never delete them without that operator's agreement (MonClub itself never deletes them). `TEMPLATE_VERSION_MISMATCH skipped=N device_fp_version=V` means N fingerprints were recorded with a different algorithm version than the terminal uses and were not uploaded (they could not have matched); the connect line's `deviceFpVersion=` shows the terminal's version.

---

## 4c. Did the door wait behind a push? (P3a-2)

```bash
grep -E "\[T\] (FULL_SYNC_CAPPED|PUSH_YIELD|SYNC_DOOR_YIELD|WORKER_STALL|WORKER_LINK_LOST|ZKEM_DELETE_DONE)" app-*.log
```

During a push to the MB2000 the PC now stops every 10 members to decide the scans that came in
(QR codes, staff cards), to open the doors pressed at the desk, and to push or remove one member
waiting for it. `PUSH_YIELD member_updates=1 pins=1` is one such member served in the middle of a
push. `FULL_SYNC_CAPPED pushing=50 left=N` means the terminal needed more than 50 members written:
50 now, the rest in the next passes, one after another (the push-history page says
`PUSH_CAPPED=N`). `WORKER_STALL state=full_sync` should now appear only if ONE group of 10 members
takes more than 25 s — a real problem, not a long push. `ZKEM_DELETE_DONE dur_ms=` is how long a
removal kept the door waiting (removals still go in one command). `WORKER_LINK_LOST` means the PC lost its link to the terminal (a command never answered) and rebuilt it — at once the first time; if the link keeps dying right after each reconnect it waits 2, 4, 8 s … (`delay_s=`, `streak=`), and meanwhile the desk's Open answers "device unreachable". Scans made just before the loss are still recorded (history, popup); a QR code scanned at that very moment may not open the door and the member scans again. Before, QR codes and the desk button could stay dead for up to 30 minutes after such a loss. The desk's Open button can still
answer "timed out" when pressed during a push; the door is then NOT opened later.

---

## 4a. Was a deleted finger cleared from the MB2000? (P3a-2)

```bash
grep -F "[T] FINGER_SWEEP" app-*.log
```

MonClub clears, once per member, every finger slot 0-9 the member does not use — right after a targeted
push, or (up to 100 members a day) in the quiet moments after the morning sync. `cleared=N` slots held a
template and were emptied (a finger deleted in the dashboard, or one left over from before 2026-09-05);
`empty=N` were already empty (the terminal answers "no" for those — that is normal, not an error);
`ok=False` means a call raised or the terminal stopped answering, and that member is tried again later.
`source=targeted|daily`. Only members MonClub itself put on the terminal are ever swept.

---

## 5. Did the terminal reject a finger?

```bash
grep -F "[T] ZKEM_VERIFY" app-*.log
```

`ZKEM_VERIFY_OK` — the terminal accepted a scan. `ZKEM_VERIFY_INVALID` — it refused one.
Both carry `pin`, `verify_method`, `scan_mode_hint`, `age_s`, `event_id`; the invalid line
adds `att_state`.

For one member (find their pin from the push lines):

```bash
grep -E "ZKEM_VERIFY_(OK|INVALID) .*pin=1234 " app-*.log
```

> **The name says which branch fired, not why the terminal refused.** The driver stamps
> the literal `eventType="zkem_invalid"` on any event whose `IsInValid` is non-zero — that
> routing is `[CODE]`. What a given `IsInValid`, `att_state` or `verify_method` value
> *means* on the MB2000 is **`[UNVERIFIED]`/`[UNKNOWN]`**: `verify_method`'s value space
> shifts between the terminal's normal mode (`0`=password, `1`=fingerprint, `2`=card) and
> its multi-verify modes (`0`=FP, `1`=PIN, `2`=PW, `3`=RF), so **`0` is genuinely
> ambiguous**. The raw values are logged side by side for exactly that reason. Do not read
> a cause out of them. `[CODE: guide_for_agents_and_dev.md §7, zkemkeeper_guide.md §8]`

**`age_s` is how you tell a live scan from a replayed backlog.** On 2026-08-30 the terminal
replayed events ~3500 s old at 13:51 `[FIELD]`. A live scan is a few seconds old at most:

```bash
grep -F "[T] ZKEM_VERIFY" app-*.log | grep -vE "age_s=[0-9]{1,2}\b"
```

lists the scans that were **not** fresh.

---

## 6. Was the door command issued, and what did ACUnlock return?

```bash
grep -F "[T] DOOR_OPEN" app-*.log
```

Two layers, two vocabularies — grep both or you see half the story `[CODE: §5.1, §7]`:

| Layer | Key | `result` values |
|---|---|---|
| local API | `device_id=` | `200_ok`, `409_unsupported`, `429_cooldown`, `503_timeout`, `500_sent_no_answer`, `500_failed` |
| driver | `worker=ZKEM:<id>` | `ok`, `false`, `exception`, `timeout`, `unsupported` (+ `delay_ds`, `dur_ms`, `clamped`) |

`500_sent_no_answer` means the worker handed the command to the driver and no answer came in
time — the door may have opened; check it before pressing again. On an MB2000 it pairs with a
driver line `result=timeout` (the driver stopped waiting for its `open_door` command, which may or
may not have reached `ACUnlock`). `[CODE: guide §3.1a]`

Whether the command was even allowed:

```bash
grep -F "[T] DOOR_OPEN_SWITCH" app-*.log
```

`enabled=` and `source=` (`env` \| `local` \| `default`), emitted at every worker connect.

> ### `result=ok` does **not** mean the door opened.
> It means `ACUnlock` returned `True`. Whether that releases *this* turnstile is
> **`[UNVERIFIED — HARDWARE-GATED]`** until the operator reports a PASS from
> `tools/mb2000_scripts/12_force_open_door.ps1` (or `9_unlock_door.ps1`) on site.
> `ACUnlock` returning `True` with no physical release is a **wiring** fault, not an SDK
> one. `[CODE: guide_for_agents_and_dev.md §7, zkemkeeper_guide.md §8]`

---

## 6a. QR codes from members who are no longer on the PC's list (trial counts)

Since 2026-09-18 every QR code the PC checks gets a roster verdict (guide §3.1b). In the
default **trial** mode nobody is refused; the would-be refusals are only counted.

```bash
# running totals, at most one line an hour
grep -F "[T] QR_ROSTER_SUMMARY" app-*.log | tail -1

# each scan that was not on the list (trial: still let in; enforce: refused)
grep -F "[T] QR_ROSTER_CHECK" app-*.log
```

| Field | Meaning |
|---|---|
| `in_roster` | QR scans whose membership is on the PC's list |
| `in_roster_by_account` | QR scans whose cached membership id is out of date (e.g. a renewal) but whose account is on the list — never refused. Since 2026-09-18 the PC writes new grants when they arrive, so a count that keeps growing points to them not arriving (guide §3.1b) |
| `not_in_roster` | QR scans whose membership is **not** on the list — the would-be refusals in trial |
| `roster_empty` | QR scans checked while the PC's list was empty — never refused, in any mode |
| `roster_behind` | QR scans not on the list, but the list was older than the codes being checked (a refresh was catching up) — never refused |
| `refused` | QR scans actually refused by the list check (only in enforce mode) |
| `not_today` | QR scans refused because none of the code's memberships may enter today (expired, a freeze day, not started) — **in both modes**, once protocol 2 is on (P3b-1, guide §3.1b "Allowed days") |
| `since` | when the counts started — they restart with the app |

```bash
# each QR scan refused on the allowed days (no member name or id in the line)
grep -F "[T] QR_DATE_CHECK" app-*.log
```

The popup then reads « Abonnement non valable aujourd'hui ». `[CODE: access_verification.py::record_totp_roster_check]`

To read it without visiting the gym: press "Sync logs now" in the dashboard header, wait
up to ~10 min for the PC to upload, then open the newest window on the Access logs page and
search `QR_ROSTER`. **In the dashboard the Access logs page is in the admin-only menu** — a
gym account's dashboard shows only whether the upload happened. (The backend also lets a gym
account fetch its own files through `/api/v1/gym/access/logs`, but no dashboard page uses it
yet.) The first summary line appears an hour after the app starts.
`[CODE: app/core/log_sync_request_poller.py, app/core/log_uploader.py; dashboard
config-nav-dashboard.tsx; backend AccessLogGymController]`

To switch one device to enforce, its `deviceCapabilities` JSON must contain
`"totpRosterCheckMode": "enforce"` (guide §3.1b). No dashboard field edits that JSON yet.

---

## 6b. Power-on dates, the PC clock, renewals (P3b-1)

Once the server sends protocol 2 (switch `monclub.access.v2.enabled`), the PC applies the members'
days itself — at start-up before any turnstile work, at 00:00:05, every minute when the date
moved, and after every sync (guide §3.8).

```bash
# was protocol 2 refused (malformed answer)? the PC then behaves as before (no date changes)
grep -F "[T] SYNC_V2_REJECTED" app-*.log

# every date change the PC applied: who left (held), came back (restored), started (promoted)
grep -F "[T] DATE_FLIP" app-*.log

# the PC clock: suspect (behind the last sync, or more than a day ahead) and back to normal
grep -E "\[T\] (CLOCK_SUSPECT|CLOCK_OK)" app-*.log

# a renewing member's old pin kept until the new one was written (MEMBERSHIP pins)
grep -F "[T] RENEWAL_HOLD" app-*.log
```

| Line | Field | Meaning |
|---|---|---|
| `DATE_FLIP` | `held` / `restored` / `promoted` | members taken off the list for the day (expired, freeze day) / put back (freeze over) / added (first day of a pre-sold plan) |
| `DATE_FLIP` | `source` / `ultra` / `skipped` | what ran it (`startup`, `midnight`, `tick`, `sync-tick`, `save`, `fast-patch`, `heartbeat`) / `True` = the turnstiles were asked to update (never in manual sync mode) / at start-up only: why nothing could move (`no_state` = no protocol-2 sync yet, `untrusted` = the last answer was v1 or refused) |
| `DATE_FLIP_FAILED` | `err` | the date change failed (e.g. database busy); nothing changed, the next minute retries |
| `CLOCK_SUSPECT` | `reason` | `behind`: the PC clock is earlier than a time it already saw (flat battery, wrong manual change); `ahead`: more than a day ahead of the server at the last sync. The day then stays at the last known one; nobody is re-admitted |
| `RENEWAL_HOLD` | `held` / `removed_after_push` / `kept` | old pins of renewing members set aside / removed once the new pin landed / still kept (the new pin failed or waits, or too many removals this pass — then `REVOKE_ABORTED path=renewal_release`; the member still enters, a later pass removes it) |

The Access UI shows « Horloge du PC suspecte » while the clock is suspect; fix the Windows date and
time. `[CODE: app/core/db.py::apply_local_date_flips; access_dates.py::evaluate_gym_date]`

---

## 6c. A member the server lists and the PC lacks (lane B)

After every successful sync the PC compares the server's member list with its own (guide §3.6 "The
missing-member check").

```bash
grep -F "[T] MEMBERS_MISSING" app-*.log
```

| `action` | Means |
|---|---|
| `full_refresh` | `count` members (`sample` = their membership ids) are on the server's list and not on this PC: the next sync re-downloads the whole member list. A second line right after it for the same ids should not appear -- if it does as `suppressed`, see below |
| `probe` | (PCs without trusted protocol-2 dates) the token's id-set digest disagrees with the PC's list: one extra delta sync names the difference. Once per token |
| `suppressed` | members the server's FULL list carried that the PC still did not store: another refresh cannot fix them, so they are reported once per start and left. Send the log to a developer |

`source` says what was compared: `delta` / `full` (a members section), `windows` (protocol-2 days, no
members section), `digest` (the token). `[CODE: app/ui/app.py::_check_missing_members]`

---

## 7. One-liners

```bash
# every telemetry line, one file
grep -F "[T] " app-2026-09-04-from-09-to-10.log

# every enrolment outcome today
cat app-2026-09-04-from-*.log | grep -F "[T] ENROLL_DONE"

# everything that went wrong today
cat app-2026-09-04-from-*.log | grep -E "\| (WARNING|ERROR) \|.*\[T\] "

# follow one enrolment end to end
grep -F "enroll_id=e41273-9ab2" app-2026-09-04-from-*.log

# follow one member across sync, push and verify (pin, then am_id)
grep -E "pin=1234( |$)" app-2026-09-04-from-*.log
grep -F "am_id=30008" app-2026-09-04-from-*.log

# is the worker alive at all
grep -E "\[T\] (WORKER_HB|WORKER_STALL|PROC_HB)" app-*.log | tail -20
```

**Correlation keys, by layer** — there is no single global key, and a grep on the wrong one
finds nothing `[CODE]`:

| Layer | Key |
|---|---|
| enrolment (UI + capture) | `enroll_id=` |
| backend API | `am_id=` + `finger_id=` |
| member / sync | `am_id=`, `pin=` |
| standalone driver | `worker=ZKEM:<device id>` |
| ULTRA engine | `worker=ULTRA:<device id>` |
| local API | `device_id=` |

---

## 8. Sending logs back

The current window is still open and has not uploaded yet. To capture it immediately,
either wait for the window to close or copy the file directly off
`C:\ProgramData\MonClub Access\data\logs\`.

`12_force_open_door.ps1` writes its own record under `tools/mb2000_scripts/logs/` — that
one is the door evidence, and it is separate from the app log.
