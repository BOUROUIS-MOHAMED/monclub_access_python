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
| `exception:<Type>` | the push raised part-way through that member |
| `chunk_wedged_or_unconfirmed` | the whole chunk wedged; nothing in it was confirmed |

A pin absent from every `ZKEM_PUSH_FAILED_PINS` line, in a push whose `ZKEM_PUSH_DONE`
says `ok=True`, was pushed. `[TEST: tests/test_fingerprint_telemetry.py::TestPushFailedPinsTelemetry]`

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

## 4. Did the terminal reject a finger?

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

## 5. Was the door command issued, and what did ACUnlock return?

```bash
grep -F "[T] DOOR_OPEN" app-*.log
```

Two layers, two vocabularies — grep both or you see half the story `[CODE: §5.1, §7]`:

| Layer | Key | `result` values |
|---|---|---|
| local API | `device_id=` | `200_ok`, `409_unsupported`, `429_cooldown`, `503_timeout`, `500_failed` |
| driver | `worker=ZKEM:<id>` | `ok`, `false`, `exception`, `timeout`, `unsupported` (+ `delay_ds`, `dur_ms`, `clamped`) |

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

## 6. One-liners

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

## 7. Sending logs back

The current window is still open and has not uploaded yet. To capture it immediately,
either wait for the window to close or copy the file directly off
`C:\ProgramData\MonClub Access\data\logs\`.

`12_force_open_door.ps1` writes its own record under `tools/mb2000_scripts/logs/` — that
one is the door evidence, and it is separate from the app log.
