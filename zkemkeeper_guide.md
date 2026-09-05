# zkemkeeper Guide — standalone terminals / `ZK_STANDALONE`

Reference for the **zkemkeeper** half of MonClub Access. Companion files:
[`guide_for_agents_and_dev.md`](guide_for_agents_and_dev.md) (system orientation) and
[`pullsdk_guide.md`](pullsdk_guide.md) (the other SDK). The three are meant to agree;
if they disagree, one of them is wrong and must be fixed, not worked around.

This SDK is **under active field test**. More of this file is `[UNVERIFIED]` than in
the PullSDK guide, and that is deliberate — the unknowns are listed as unknowns.

---

## 0. Maintenance contract

**Every claim carries a status marker and a way to check it.** Update the row in the
same change as the code. If you cannot verify a claim, mark it `[UNVERIFIED]` or leave
it out — omission is correct, approximation is a defect.

| Marker | Means |
|---|---|
| `[SIG]` | Signature, quoted verbatim from the `def` line. |
| `[CODE]` | **Executable statements** prove it. |
| `[COMMENT]` | Only a docstring or comment asserts it. **Not evidence of behaviour.** |
| `[TEST]` | A named test actually exercises it. |
| `[FIELD]` | A specific **measurement** plus a **date or version**. |
| `[UNVERIFIED]` | Stated as unproven by the source. Usually hardware-gated. |
| `[UNKNOWN]` | Open question. Stated so nobody assumes an answer exists. |

Rules for editing:

1. Quote **COM call expressions verbatim, with argument order.** A future agent needs
   `SetUserTmpExStr(1, pin, finger_idx, 1, tmp)`, not "the template upload call".
2. Never soften §3 (the must-not-call) or §8 (the unknowns) without hardware evidence.
3. A docstring is a claim, not evidence. This file's source has extensive comments and
   several were found overstated — see §9.

---

## 1. What this SDK is

`zkemkeeper` — ZKTeco's **standalone SDK**, a **COM server**, driven through `pywin32`.
Used for MB2000-class multi-bio terminals, which `plcommpro.dll` **cannot** drive.

- **It is a COM server, so shipping the DLL is not enough — it must be REGISTERED**
  (`regsvr32`, **elevated**, **32-bit**), along with its dependencies.
  `[FIELD: an unregistered COM server was one of the two root causes of the MB2000
  outage; registering it on the client PC was part of the remedy]`
- **Bitness: 32-bit**, hosted in-process. A 32-bit subprocess sidecar remains the
  designed fallback if in-process COM fails on real hardware; only `_com_factory` would
  change. `[COMMENT]`
- **Event model: PUSH** — `RegEvent` + a COM sink, drained by polling.
- **There is no transaction table.** Events exist only as they arrive.
- **zkemkeeper has no call timeout.** This single fact drives the entire threading
  design (§2).

The COM object is created with **`DispatchWithEvents`** (not plain `Dispatch`), binding
an `_AttEvents` sink class; three ProgIDs are tried in order until one succeeds. `[CODE]`

---

## 2. The STA threading model — the rules you must not break

COM interfaces must not be used across apartments, and the worker calls driver methods
from *its* thread. So:

> **One STA thread per device owns EVERY COM call.** Every public method posts a
> command onto an internal queue and blocks on a deadline. Nothing else may touch the
> COM object. `[CODE]`

### Constants — exact values `[CODE]`

| Constant | Value | Meaning |
|---|---|---|
| `_DEFAULT_CMD_TIMEOUT_SEC` | `10.0` | Default per-command deadline |
| `_CONNECT_TIMEOUT_SEC` | `20.0` | Connect deadline |
| `_EVENT_QUEUE_MAX` | `4096` | Event queue depth |
| `_STA_LOOP_IDLE_SLEEP_SEC` | `0.25` | Idle sleep in the STA loop |
| `_PUSH_CHUNK_MEMBERS` | `10` | Members per STA command during a roster push |
| `_PUSH_TRACE_MEMBERS` | `3` | Members traced call-by-call |
| `_PUSH_TRACE_TEMPLATES` | `5` | Template uploads traced, counted **separately** and carried across chunks |
| `_PUSH_MAX_CONSECUTIVE_WEDGES` | `3` | Give up after this many back-to-back wedged chunks |
| `_MAX_PIN_DIGITS` | `9` | MB2000 user-ID space `[COMMENT: "vendor datasheet"]` |
| `_REGEVENT_ATT_TRANSACTION` | `1` | `RegEvent` bitmask for `OnAttTransaction(Ex)` |

### The wedge problem and the generation fence

A terminal that stops answering blocks the COM call **forever**, and Python cannot
interrupt it. The driver therefore cannot kill the thread — it **abandons** it:

`_call()` waits on `cmd.done.wait(timeout=timeout)`. On expiry it calls
`_abandon_sta_thread(...)`, which bumps `self._sta_gen` under `_pin_map_lock`, drops
the thread reference and clears the connected flag. `_sta_main` tests
`if gen != self._sta_gen:` at the **top of each loop iteration** and exits. `[CODE]`

> The fence blocks **subsequent** command servicing. A command already executing still
> runs to completion and still sets `cmd.done` in its `finally`. `[CODE]`

**Added 2026-08-31 — the superseded-thread race.** Until then the generation was
checked **only at the top of the loop**, and two shared things were touched
unconditionally. A thread abandoned while merely *slow* (not stuck in COM — plausible
on the 4 GB client PC) was still sitting in `_cmd_queue.get()`, so it **stole the
successor's `connect`**, serviced it on its own COM object, then exited and **cleared
the shared connected flag** in its `finally`. Observed in a harness: `connect()` →
`True` with `is_connected` → `False`, and every later command answered
`"not connected"`. `[CODE]` `[TEST: test_standalone_incremental_sync.py::
TestDriverReportsFailedPins::test_reconnect_after_abandon_is_serviced_by_the_new_thread]`

Now: `[CODE]`
- the generation is re-checked **after every dequeue**; a superseded thread puts the
  command **back** and exits, so the successor services it;
- only the **current owner** (`gen == self._sta_gen`) may clear `_connected_flag` —
  in the pump-error path and in the thread's `finally`. Disconnecting its *own* COM
  object stays unconditional (that is local state).

That the abandoned thread **leaks until the call returns or the process exits** is
stated by the source but has no executable statement behind it. `[COMMENT]`

> ⚠️ **The two timeout messages differ, and the difference is load-bearing for log
> matching.** `[CODE]`
> - Abandon reason (→ truncated to 120 chars into `ZKEM_STA_WEDGED` telemetry):
>   `command {op!r} timed out after {timeout}s`
> - Raised exception: `zkemkeeper command {op!r} timed out after {timeout}s`
>
> The `TimeoutError` carries a leading `zkemkeeper ` that the telemetry reason does
> not. Grep for the wrong one and you will find nothing.

### The STA loop

Each iteration is strictly sequential: service **at most one** command, then
`_pump_events_once(zk)` (only while connected), then `self._pump()`. An exception from
the event pump is treated as a **disconnect** — it clears the connected state and emits
`_tel.warn("ZKEM_EVT_SINK_DOWN", ...)` rather than crashing the thread. `[CODE]`

Because the loop is sequential, **one command is a window in which no COM message is
pumped and no device event is drained.** That is why the roster push is chunked (§5).

---

## 3. ⛔ `SSR_DeleteEnrollData` — MUST NOT be called for finger slots

**This is the most expensive thing an agent could re-introduce.**

> On this firmware, **`SSR_DeleteEnrollData` with a finger backup number NEVER
> RETURNS.** `[FIELD: v1.4.25 field trace — 12 of 19 STA-thread wedges had
> `SSR_DeleteEnrollData(f=1)` as the last call made, 2 more had `f=2`, and finger 0
> always returned normally. Recorded at the call site AND in the test suite, which
> names the gym OXYGENE_FIT.]`

Clear a fingerprint slot with **`SSR_DelUserTmpExt`** instead:

```python
zk.SSR_DelUserTmpExt(1, pin, int(finger_idx))
```

This is the sequence proven on this hardware by
`tools/mb2000_scripts/5_push_member_to_device.ps1`. `[COMMENT]` The test suite asserts
`SSR_DeleteEnrollData` is **absent** from the slot-clear path.
`[TEST: test_zk_standalone_driver.py::TestSlotClearUsesTheProvenApi]`

> A previous comment in this file claimed `SSR_DeleteEnrollData` was "proven by scripts
> 5/7". That is wrong for script 5. Script 7 uses it for **whole-user / face / password**
> backup numbers (11/12/13) — a different operation.

### ⚠️ Unresolved tension — read before touching either path

`_do_delete_users` still calls `SSR_DeleteEnrollData(1, pin, 12)` (12 = whole user) for
MIRROR deletes. `[CODE]`

The hang was observed **only at finger indices 1 and 2**. Whether backup number **12**
is also affected is **`[UNKNOWN]`** — it has neither been observed hanging nor proven
safe. The blanket phrasing "backupNumber >= 1 never returns" in the source comment
would forbid 12, yet the code calls it. **Do not resolve this tension by editing the
comment.** Resolve it with hardware evidence, then update this section.

That backup number 12 means the whole user (fingerprints + card + password) is
`[COMMENT]` — docstring and inline comment only.

### `SSR_DelUserTmpExt` against an ALREADY-EMPTY slot — measured

It **returns normally**, in **~71–171 ms**. `[FIELD: Oxyfit MB2000, 2026-09-05]`

Evidence, from the field log — finger 2 had never been written for pin 34439 (both
earlier enrolments were finger 0), so the slot was empty when the clear was issued:

```
13:42:57,248 [ZKEM:9] push trace pin=34439 -> SSR_DelUserTmpExt(f=2)
13:42:57,329 [ZKEM:9] push trace pin=34439 -> SetUserTmpExStr(f=2 len=1504)   # +81 ms
   -> ZKEM_PUSH_CHUNK ... tpl_attempted=2 tpl_ok=2 dur_ms=859 ok=True, chunks_wedged=0
```
Device 8 the same, +71 ms. A second instance at 12:58:02 (finger 0, the member's
first-ever fingerprint) took +108 ms / +169 ms.

This is what makes slot removal shippable: the clear is safe on an empty slot, so a
removal set computed from stored state cannot wedge the STA thread if it is slightly
stale. It does **not** license a blanket 0..9 sweep — see §5.

---

## 4. The COM call layer — verbatim

Every zkemkeeper call the driver makes. Machine number is hard-coded `1` throughout.
`[CODE]` unless noted.

### Connect

```python
zk.SetCommPassword(int(self.comm_key) if self.comm_key.isdigit() else self.comm_key)
zk.Connect_Net(self.ip, self.port)          # -> bool
zk.RegEvent(1, _REGEVENT_ATT_TRANSACTION)   # bitmask 1 = OnAttTransaction(Ex)
```
`SetCommPassword` runs **only when a comm key is configured**, and **before**
`Connect_Net`; a failure only warns and does not abort the connect. `[CODE]`

After a successful connect, in this order: read the fingerprint algorithm version, then
the device status, then log, then run the fullness warning. `[CODE]`

### Events

```python
zk.ReadRTLog(1)          # transfer device events into the PC buffer
zk.GetRTLog(1)           # drain one; falsy when empty — looped up to 256 times
```
`GetRTLog` fires the registered sink synchronously. `[COMMENT]`

Sink signature: `[SIG]`
```python
OnAttTransactionEx(self, EnrollNumber, IsInValid, AttState, VerifyMethod,
                   Year, Month, Day, Hour, Minute, Second, WorkCode=0)
```

### Door

```python
zk.ACUnlock(1, int(delay_ds))    # -> bool ; delay is in DECISECONDS
```
`open_door` converts `delay_ds = round(pulse_time_ms / 100)` and **clamps it to
1…600 ds** (0.1…60 s), logging a warning and stamping `clamped=True` on the telemetry
line when it does. 600 ds is the app's own ceiling (the local API clamps `pulseSeconds`
to 1–60 and `PullSDKDevice` clamps its seconds to 1–60); **the firmware's maximum for
this argument is `[UNKNOWN]`** — nothing in this repo states it. The STA command
deadline is `max(2.0, timeout_ms / 1000.0)` seconds. `[CODE: _pulse_ms_to_delay_ds,
open_door]` `[TEST: test_mb2000_force_open.py::TestDriverDoorCommand::
test_decisecond_conversion_and_clamp]`

The call goes through `_call()` like every other STA command, so the generation fence
and wedge recovery of §2 apply unchanged: an `ACUnlock` that never returns is abandoned
at the deadline (`ZKEM_STA_WEDGED`, `_sta_gen` bumped, `result=timeout`) and the next
`connect()` rebuilds the thread. `[TEST: ::test_wedged_acunlock_times_out_abandons_sta_
and_reports_timeout, ::test_recovery_after_wedge_is_serviced_by_the_new_thread]`

Every attempt emits one telemetry line — `_tel.event` for `ok`, `_tel.warn` otherwise:

```
[T] DOOR_OPEN worker=ZKEM:<id> door=<n> result=<r> delay_ds=<ds> dur_ms=<ms> [clamped=True] source=<env|local|default> [err=<ExcName>]
```
`result ∈ {ok, false, exception, timeout, unsupported}` — a closed set,
`_DOOR_OPEN_RESULTS`. `unsupported` = the switch was OFF and **no COM call was made**;
`false` = `ACUnlock` answered `False` **or the driver was not connected** (the STA loop
answers `False` without calling COM in that case). `[CODE]` `[TEST]`

`door_id` is informational only: the machine number is always `1` and the MB2000 has
one lock relay. `[CODE]`

**Whether the switch allows the call is §6; whether the relay releases is §8.**

### Time

```python
res = zk.GetDeviceTime(1)                                    # -> (ok, y, mo, d, h, mi, s)
zk.SetDeviceTime2(1, t.year, t.month, t.day, t.hour, t.minute, t.second)   # -> bool
```
win32com maps the six ByRef out-params to a returned tuple. Any failure → `None` /
`False`. `[CODE]`

### Roster push — the ordering constraints

**Per member, in this exact order:** `[CODE]` `[TEST]`

```python
zk.SetStrCardNumber(card)   # or SetStrCardNumber("") — MUST precede SSR_SetUserInfo
zk.SSR_SetUserInfo(1, pin, name, "", 0, True)    # -> bool
```

**Per finger, in this exact order:** `[CODE]`

```python
zk.SSR_DelUserTmpExt(1, pin, int(finger_idx))         # clear the slot first
zk.SetUserTmpExStr(1, pin, finger_idx, 1, tmp)        # Flag=1 ; -> bool
```

- The slot-clear is wrapped in a bare `except: pass`. `[CODE]`
- An **empty** `templateData` `continue`s **before** the slot-clear, so neither call is
  issued for that finger. `[CODE]`
- ZKTeco FAQ: upload requires the slot to be EMPTY — delete-first makes re-enrolment
  deterministic. `[COMMENT]`
- `name` is truncated to 24 characters; `card` is reduced to digits only. `[CODE]`

**Bracket (destructive full reconcile only):** `[CODE]` `[TEST:
test_zk_standalone_driver.py::TestPushRoster::test_bracketed_push_enables_around_batch]`

```python
zk.EnableDevice(1, False)   # first — ONLY when bracket=True; failure is recorded, push proceeds
...
zk.EnableDevice(1, True)    # last
zk.RefreshData(1)           # in the same finally, AFTER the re-enable, UNCONDITIONALLY
                            # (bracketed or not), exception swallowed
```

> `EnableDevice(False)` **locks the terminal UI**, and it is the gym's sole verifier.
> Only the 22:00 / manual full reconcile may set `bracket_enable_device=True`. A default
> daytime push issues no `EnableDevice` call at all. `[CODE]` `[TEST]`

### Enumerate users

```python
zk.ReadAllUserID(1)                              # False -> fail closed
zk.SSR_GetAllUserInfo(1, "", "", "", 0, 0)       # -> (ok, pin, name, password, privilege, enabled)
zk.GetStrCardNumber("")                          # per row
```
Falls back to `zk.SSR_GetAllUserInfo(1)` on `TypeError`. `[COMMENT for the tuple
order]` — the win32com marshalling of the `[out]` params is firmware/typelib-dependent
and confirming the exact order on real MB2000 hardware is an on-hardware gate.
`[UNVERIFIED]`

**Fails closed.** A failed enumeration must NEVER read as an empty device — that would
delete every member under MIRROR. `[CODE]`
`[TEST — but check what each asserts: only `test_list_users_readall_false_is_not_empty`
asserts `users == []`; `test_list_users_midloop_raise_fails_closed` and
`test_list_users_unexpected_shape_fails_closed` assert only `ok is False`]`

### Delete users

```python
zk.SSR_DeleteEnrollData(1, pin, 12)   # 12 = whole user — see §3 tension
zk.RefreshData(1)
```
Applies the **same** pin guard as push, but counts a rejected pin as **`failed`**, not
`skipped`. `[COMMENT for the equivalence claim]`

### Diagnostics

```python
zk.GetSysOption(1, "~ZKFPVersion", out)   # fingerprint ALGORITHM version, e.g. "9"/"10"
zk.GetDeviceStatus(1, int(idx), box)      # occupancy / capacity
```
Both try **two win32com shapes** (`VARIANT` ByRef, then a returned tuple) because the
mapping differs across builds, and give up quietly. Best-effort diagnostics, never
gates. `[CODE]`

`_STATUS_FIELDS` has **ELEVEN** entries — indices **1–5 and 7–12**; **index 6 is
absent**, and the highest index is 12. `[CODE]`

| idx | name | idx | name |
|---|---|---|---|
| 1 | `admins` | 8 | `user_capacity` |
| 2 | `users` | 9 | `attendance_capacity` |
| 3 | `fingerprints` | 10 | `fingerprints_free` |
| 4 | `attendance_records` | 11 | `users_free` |
| 5 | `passwords` | 12 | `attendance_free` |
| 7 | `fingerprint_capacity` | | |

Any index that will not read is simply **omitted** — an unreadable status must never
invent a capacity. `[CODE]` `[TEST]`

**The `.ps1` lab contradicts this table on two indices.** `tools/mb2000_scripts/`
scripts `3_get_device_info.ps1` and `12_force_open_door.ps1` label **6 = att logs** and
**8 = face templates**, but `_STATUS_FIELDS` has **no index 6 at all** and maps
**4 = `attendance_records`**, **8 = `user_capacity`**. One side is wrong; nothing in the
repo settles which. `[UNVERIFIED]` Resolve on the MB2000 by reading indices 1–12 and
comparing against the terminal's own on-screen counts. Until then the driver's `4` and
the scripts' `6`/`8` labels are both suspect, and neither should be quoted to an
operator as fact. The scripts' index→label *pairing* is at least mechanically correct
as of 2026-09-04 — before that, both scripts indexed an `[ordered]` hashtable with an
integer, which returns by **position, not key**, and silently printed each count under
the wrong heading. `[TEST: fake-COM harness under 32-bit Windows PowerShell 5.1]`

---

## 5. `push_roster` — behaviour

```python
def push_roster(self, users, templates_by_pin=None, *,
                remove_fingers_by_pin=None,
                bracket_enable_device: bool = False,
                timeout_sec: float = 600.0) -> Dict[str, Any]        # [SIG]
```

- `users`: `[{"pin": str, "name": str, "card": str}]`. Pins must be numeric and
  ≤ 9 digits; violations are **skipped and counted**, never pushed.
  `[TEST: test_zk_standalone_driver.py::TestPushRoster::test_pin_over_9_digits_is_skipped]`
- `templates_by_pin`: `pin -> [{fingerId, templateVersion, templateData, templateSize}]`
- `remove_fingers_by_pin`: `pin -> [fingerId, ...]` — slots this member **used to**
  have and no longer does. Omitting it keeps the old additive behaviour exactly
  (zero extra COM calls). `[CODE]`

### ⛔ The mirror WAS write-only — what that cost, and what fixed it

> Until 2026-09-05 the only slot clear sat **inside** the loop over the templates a
> member still had, so an empty desired set meant the loop body never ran and **no COM
> call was ever issued for a vacated slot**. A fingerprint deleted in the dashboard
> kept opening the turnstile.
> `[FIELD: Oxyfit, 2026-09-05 — pin 34439. 12:58 push `templates_for=1` issued
> `SSR_DelUserTmpExt(f=0)` + `SetUserTmpExStr`; the 13:14 push after the deletion was
> `templates_for=0` and issued only `SetStrCardNumber('')` + `SSR_SetUserInfo`, then
> reported `pushed=1 failed=0 tpl_attempted=0 ok=True`. The revoked finger still
> produced `ZKEM_VERIFY_OK` / rtlog ALLOW at 13:34–13:37.]`

Two properties of the old code made it invisible:
- the clear's return value was a **bare expression** inside `except Exception: pass`,
  so the driver could not tell *cleared* from *refused* from *threw*;
- `ok = failed == 0 and templates_failed == 0` was True, so `device_sync_state` was
  stamped with the post-deletion hash and the pin was **skipped forever after**.

The removal set is computed by the engine from `device_sync_state.pushed_finger_ids`
(**NULL = UNKNOWN, `''` = known-empty** — the distinction is load-bearing) and applied
**before** the template loop, so a stale removal set can never delete a template that
was just written. `[CODE]`
`[TEST: test_zk_standalone_template_removal.py, test_standalone_finger_removal_state.py,
test_db_pushed_finger_ids.py]`

**Do not "simplify" this into a blanket 0..9 sweep.** At the measured ~100 ms/call
(§3) that is ~9 000 extra COM calls on a ~900-pin bracketed roster ≈ **+15 min** on a
push already taking 416 s, against a 600 s single-command deadline — while
`EnableDevice(False)` is held, i.e. with the gym's sole verifier dead.

**Still open:** whole-user removals (member deleted, membership expired or frozen, PIN
changed by a renewal) do **not** reach the terminal under the default `PRESERVE`
policy. Those all funnel into `SSR_DeleteEnrollData(1, pin, 12)`, whose hang status is
`[UNKNOWN]` (§3), so they are **not** fixed by this work.

### Chunking

A bracketed push is **one** command spanning the whole roster (its own deliberate
window). Everything else is chunked at `_PUSH_CHUNK_MEMBERS` (10). `[CODE]`

Per-chunk deadline: `[CODE]`
```python
chunk_timeout = min(timeout_sec, max(45.0, len(part) * 5.0))
```
The caller's `timeout_sec` is a **hard cap**. The 45 s floor protects a small final
chunk. That a member costs ~1–2 s on real hardware (making 5 s ≈ 3× headroom) is
`[COMMENT]` — no date, no version.

### What a wedged chunk actually does — read carefully

A wedged chunk does **not always** continue. There are **three `break` statements** in
the wedge handler that abort the remaining roster: `[CODE]`

1. `consecutive_wedges >= _PUSH_MAX_CONSECUTIVE_WEDGES` (3)
2. `self.connect()` returns falsy → *"reconnect failed after a wedge -- stopping"*
3. the reconnect **raises** → *"reconnect raised after a wedge -- stopping"*

The `continue` is reached **only when none of those fire**. `consecutive_wedges` resets
to 0 after any successful chunk.

> The comment claiming a wedged chunk simply carries on is `[COMMENT]` and is
> **incomplete** as written. Do not restate it.

### Result dict

Keys: `ok`, `pushed`, `failed`, `templates_failed`, `skipped_pin`, `chunks_wedged`,
`errors`, **`failed_pins`**, and **`del_attempted` / `del_ok`** (added 2026-09-05).
`[CODE]`

`del_attempted` counts every `SSR_DelUserTmpExt` issued — both the delete-before-write
of a desired slot and the removal of a vacated one. `del_ok` counts the ones the
terminal **confirmed**. A gap between them is the only signal that a revocation did
not land; before this existed the call's result was discarded entirely. Unlike the
other counters below, these two **are** on the aggregate return, because the removal
tests assert on them. Nothing decides on them. `[CODE]`

Each *chunk* result additionally carries `failed_reasons`, `tpl_attempted`, `tpl_ok`
and `chunk_ms` (added 2026-09-04). These are **telemetry only** — `push_roster` folds
them into `ZKEM_PUSH_CHUNK` / `ZKEM_PUSH_FAILED_PINS` and **nothing decides on them**.
They are not present on the aggregate `push_roster` return. `[CODE]`
`[TEST: tests/test_fingerprint_telemetry.py::TestPushFailedPinsTelemetry]`

- **`failed_pins`** (added 2026-08-31) — every pin **not confirmed** on the terminal:
  a refused `SSR_SetUserInfo`, a refused template (`SetUserTmpExStr` → `False`), an
  exception mid-member, and **every member of a wedged chunk** (nothing in a wedged
  chunk came back confirmed). Deduplicated — a member with two refused fingers is one
  entry. The engine uses it to mark only those pins as needing retry; a driver that
  omits the key, or reports `ok=False` with an empty list, is read conservatively as
  "every attempted pin unconfirmed". `[CODE]`
  Two more places apply the same rule inside the driver: a chunk answered
  `"not connected"` by the STA loop names **every** pin of that chunk, and the
  `push_roster` merge treats a failed chunk that *lacks* the key as "all of its pins
  failed". `[CODE]` `[TEST: ::test_failed_chunk_without_failed_pins_confirms_nothing]`

### Incremental full sync (engine side) — added 2026-08-31

`push_roster` itself has no diff; it sends whatever it is given. Until 2026-08-31 the
ULTRA worker gave it the **whole roster on every full sync** — 928 members, 419 s on
the OXYGENE_FIT MB2000 `[FIELD: v1.4.26]` — and a targeted member sync never updated
the scheduler's roster-hash baseline (`_last_hash` is only set when a *full* sync
finishes), so one new fingerprint made the next hash evaluation conclude "roster
changed" and queue that 7-minute push. `[FIELD: v1.4.28 operator report]`

Now `ultra_engine.py` keeps one row per `(device, pin)` in the same `device_sync_state`
table the PullSDK path uses: `[CODE: _standalone_pins_needing_push,
_record_standalone_pin_state, _standalone_pin_hash]`

- The hash covers **exactly what the driver sends** — name cut at 24 chars, card
  reduced to digits, templates sorted — *not* the PullSDK payload (door bitmask,
  clamped card), which the terminal never receives.
- A non-bracketed full sync pushes only pins that are **new, changed, or failed last
  time**; when nothing differs it sends **no COM calls** and still completes with full
  bookkeeping, so the scheduler records the hash.
- **Bracketed** syncs (`user-sync`, `daily-forced-sync`, `hard-reset`) still push
  every pin — their semantics are unchanged.
- A member sync records its pin as synced, so the post-enrolment cascade becomes a
  no-op reconcile.
- **Safety direction:** a state *read* failure ⇒ push everything; a state *write*
  failure ⇒ logged and ignored. MIRROR always receives the **full desired roster**,
  never the incremental subset (passing the subset would delete every unchanged
  member). Deleted and no-longer-desired pins have their state forgotten.
`[TEST: tests/test_standalone_incremental_sync.py]`

- **`templates_failed` is counted separately from `failed`.** A member row can be
  written fine while its finger upload is refused — and that member then cannot get
  through the turnstile. Before this existed, such a member was reported synced, the
  roster hash was stamped, and every later cycle was skipped as "fingerprint
  unchanged". `[CODE]`
- `templates_failed` is summed into the aggregate but is **never tested against
  `agg["ok"]` directly** — it influences `ok` only transitively via each chunk's own
  flag. `[CODE]`
- ⚠️ **`errors` is NOT capped at 5.** The per-chunk merge and wedge paths guard with
  `if len(agg["errors"]) < 5`, but the *abandon* path appends **unconditionally**. A
  roster with 5 merge errors that then hits 3 consecutive wedges ends with **6**
  entries. The DONE log merely slices `[:5]` for display. `[CODE]`

### Trace budgets

`_PUSH_TRACE_MEMBERS` and `_PUSH_TRACE_TEMPLATES` are **separate** budgets carried
**across chunks**, not per chunk. `[CODE]`
`[TEST: test_device_sync_protocol_guard.py — chunk 2 starts one lower on each]`

Why separate: the first members of a roster often have no fingerprints at all, so a
member-only budget is exhausted before a single `SetUserTmpExStr` is reached — which is
exactly how the wedging call stayed invisible in the field. `[COMMENT]`

Each traced call is logged **before** it is made, because zkemkeeper has no call
timeout and a post-hoc log would never be written — the last line in the log names the
culprit. `[COMMENT for the rationale; the pre-call ordering itself is `[CODE]`]`

### The event pump inside the push loop

`self._pump()` runs inside the member loop — but **not** once per member. Two
`continue` statements skip it: `[CODE]`

- the pin guard (rejected pins), and
- a falsy `SSR_SetUserInfo` — **the load-bearing one**, because `SetStrCardNumber` and
  `SSR_SetUserInfo` have already been issued, so COM work happened with no pump.

It **does** run after a member that completed normally and after one whose push raised
(the `except` falls through to it).

---

## 6. Capability flags

```python
owns_event_source = True                            # [CODE]
supports_device_params = False                      # [CODE]
supports_open_door = _OPEN_DOOR_FAMILY_DEFAULT      # [CODE] True; re-resolved per instance — see below and §8
supports_transaction_table = False                  # [CODE]
```

`supports_open_door` is **not a constant on this driver**. Every instance sets it in
`__init__` from `resolve_open_door_switch(device_id, payload)` and can change it live
through `apply_open_door_switch(local_value)`: `[CODE]` `[TEST:
test_mb2000_force_open.py::TestOpenDoorSwitchResolution]`

1. env `MONCLUB_ZK_STANDALONE_OPEN_DOOR` — `1|true|yes|on|all` ⇒ ON for all,
   `0|false|no|off|none` ⇒ OFF for all, `8,12` ⇒ ON for those ids and OFF for the rest,
   blank ⇒ no override, anything else ⇒ **logged and ignored**;
2. the persisted per-device switch, `payload["openDoorEnabled"]` (from
   `db.device_local_settings`, set from the Devices page control panel or
   `POST /api/v2/devices/{id}/open-door-switch`);
3. `_OPEN_DOOR_FAMILY_DEFAULT = True` — operator decision 2026-09-04.

The effective value and its source are logged at construction (= every worker connect)
and emitted as `[T] DOOR_OPEN_SWITCH worker=ZKEM:<id> enabled=… source=…`; the driver
keeps it in `_open_door_source`, which the worker snapshot exposes as
`open_door_source`. `[CODE]`

`read_transaction_rows` / `get_table_count` / `delete_all_transaction_rows` are
**inert** — callers must gate on `supports_transaction_table` and **skip the device**,
never act on the return values. Clearing the terminal's own log would destroy records
never persisted to SQLite. `[CODE]` `[TEST: test_device_sync_protocol_guard.py::
TestTransactionTableCapability]`

---

## 7. Identity, events, direction

The terminal reports the user **PIN** (`EnrollNumber`) for both fingerprint and card
verifies. Downstream (cooldown, member resolution, history, popup photo) keys on the
**RFID card number**, so the driver keeps a `pin -> card` map — refreshed on connect
and at every roster push — and emits `cardNo`. `[CODE]`

Unknown pins emit **`ZKPIN:<pin>`** plus a one-shot `ZKEM_PIN_UNMAPPED` telemetry warn.
Never dropped silently. `[CODE]`

`normalize_att_event` produces the **same dict shape PullSDK emits** — `eventId`,
`doorId`, `eventType`, `cardNo`, `eventTime`, `table`, `rawRow` — so the ULTRA worker
runs unchanged. `eventTime` is `"%04d-%02d-%02d %02d:%02d:%02d"`. `[CODE]`

Standalone rows additionally carry **`rawRow["scan_mode_hint"]`**, which PullSDK rows
do not. `[CODE]`

Event queue backpressure is **newest-wins**: when the 4096-slot queue is full it drops
the **oldest** event and inserts the new one, with a warning. `[CODE]`

Lane direction from the synced door preset is stamped into `rawRow["direction"]`, so
the existing attendance uploader carries it with zero changes. `[CODE]`

---

## 8. Unverified and unknown — do not treat as settled

### `ACUnlock` releases the MB2000 turnstile `[UNVERIFIED — HARDWARE-GATED]`

`ACUnlock` is documented SDK-wide but has **never been confirmed on MB2000 hardware**.
**This section stays `[UNVERIFIED]` until the operator reports that script 12 (or 9)
passed on site** — a `DOOR_OPEN result=ok` line in the app log does **not** settle it:
it proves the COM call returned `True`, not that the relay clicked or the turnstile
released.

What changed on 2026-09-04: the command is now **issued** instead of refused — the
switch is ON for the family by operator decision (§6), after the desk was refused on
every press while it shipped OFF `[FIELD: 2026-08-30, 13× DOOR_OPEN
result=409_unsupported in ten seconds]`. `_do_open_door` implements the real call; the
switch only decides whether the app is **allowed** to make it, and every attempt is
loud (§4 Door: log line + `DOOR_OPEN` telemetry, French HTTP 500 to the desk on a
`False`). `[CODE]` `[TEST: test_mb2000_force_open.py]`

The env var is kept as an override in **both** directions:

```
MONCLUB_ZK_STANDALONE_OPEN_DOOR
```
`1｜true｜yes｜on｜all` forces ON everywhere, `0｜false｜no｜off｜none` forces OFF
everywhere, a device-id list like `8` or `8,12` is an allowlist (ON for those, OFF for
the rest). Blank = no override; anything else is **logged and ignored**. Parsed **per
call**, so an operator can flip it without restarting. `[CODE: _open_door_env_override]`

**Still verify** with the on-site script pack — two scripts fire the identical
`ACUnlock(mn, ds)` call:

- `tools/mb2000_scripts/9_unlock_door.ps1` — the minimal one-shot: fire once, ask
  whether the relay clicked. Unchanged.
- `tools/mb2000_scripts/12_force_open_door.ps1` — the **sustained** variant, added
  2026-09-04: duration in seconds → deciseconds, `-Repeat`/`-IntervalSeconds` to hold
  the door open, device info before/after, `-Auto` for the desk, and **every attempt
  appended to `tools/mb2000_scripts/logs/force_open_*.log`** so the operator can send
  the result back. Exit codes `0`/`1`/`2`/`3` = all TRUE / setup failure / some FALSE /
  some call threw.

Either way: listen for the relay **and** confirm the turnstile physically releases —
`ACUnlock` returning `True` with no release is a wiring fault, not an SDK one.
`[COMMENT]`

No PASS has been reported from either script, so this section does not move:
`ACUnlock` stays `[UNVERIFIED]` on the MB2000 until an operator reports one with a log
(the *switch* being ON is a software decision — §6 — not evidence). What script 12
adds is a **record**, not a result. `[CODE: 12_force_open_door.ps1]`

Two limits of that record, stated in the script header so nobody over-reads it:
the elapsed ms it prints is the duration of the **COM call**, not of the relay; and
the app hardcodes `ACUnlock(1, ds)`, so a PASS obtained with a different machine
number does not transfer. The **maximum** delay `ACUnlock` accepts is `[UNKNOWN]` —
nothing in this guide documents one, so the script's own 600 ds ceiling is sourced
from the app's `pulseSeconds 1..60` clamp and is labelled as an app limit, not an SDK
one — the driver clamps at the same 600 ds (§4 Door). This SDK also exposes **no
reason** for a `False` return; the script reports `FALSE` and no more, and the app
reports `DOOR_OPEN result=false`. `[UNKNOWN]`

### Which `verifyMethod` integer means what `[UNKNOWN]`

The value space **shifts** between the terminal's normal mode (`0`=password,
`1`=fingerprint, `2`=card) and multi-verify modes (`0`=FP, `1`=PIN, `2`=PW, `3`=RF), so
**`0` is genuinely ambiguous**. Both tables are mapped defensively and the **raw value
is always kept** in `rawRow` pending an on-site fidelity table. `[CODE]`

Do not write logic depending on a specific integer until it is confirmed on the
terminal.

### `SSR_GetAllUserInfo` out-param tuple order `[UNVERIFIED]`

Firmware/typelib-dependent. Both conventions are handled and the code fails closed on
any unexpected shape, but the exact order on real MB2000 hardware is an on-hardware
gate.

### ~~Why fingerprint templates were refused~~ — **RESOLVED 2026-08-30**

This section previously listed two unproven candidates: a full fingerprint store, and an
algorithm-version mismatch. **Both are now dead.** Do not resurrect either.

A clean field run at **v1.4.26** pushed the whole roster with zero refusals: `[FIELD]`

```
[ZKEM:8] push_roster START users=928 templates_for=853 chunks=93 bracket=False
[ZKEM:8] push_roster DONE ok=True pushed=928 failed=0 templates_failed=0
                       skipped_pin=0 chunks_wedged=0 in 419s
```

853 template sets uploaded, **`templates_failed=0`**, against the same terminal that
still holds the previous software's enrolments. So the store was never full and the
algorithm versions never disagreed.

**The actual cause was the `SSR_DeleteEnrollData` hang (§3).** Every wedge killed the
STA thread mid-roster; the refusals were a downstream symptom of the roster never
completing, not a rejection by the terminal. Fixing the slot-clear API and chunking the
push removed both.

`_read_fp_version` / `_read_device_status` / `_warn_if_device_full` stay — they are
cheap, and they are what made this answerable. `_warn_if_device_full` emits an **ERROR**
at 0 free and a **WARNING** at ≥ 90 % full. `[CODE]`

> Note for the roster path: a `templates_for=N` well below the member count is normal —
> only members who actually have enrolments carry templates (here 853 of 928).

### Others `[UNVERIFIED — HARDWARE-GATED]`

Declared by the module docstring: in-process COM viability, event field semantics,
template portability, and the card-number space.

---

## 9. Comments that overstate the code

Found by verification. Trust the code, not these. `[CODE — each checked]`

- ❌ "A wedged chunk does not abort the roster." — three `break`s do (§5).
- ❌ "`self._pump()` runs after each member." — two `continue`s skip it (§5).
- ❌ "`errors` is capped at 5." — the abandon path appends unconditionally (§5).
- ❌ "`_STATUS_FIELDS` has 12 entries." — it has **11**; index 6 is absent (§4).
- ❌ "`SSR_DeleteEnrollData` proven by scripts 5/7." — wrong for script 5 (§3).
- ⚠️ The abandon reason and the `TimeoutError` text differ by a leading `zkemkeeper `
  (§2).

---

## 9.1 Telemetry emitted by this driver

The canonical index of every `[T]` event, its fields and the rules for adding one is
`guide_for_agents_and_dev.md` §10; the operator-facing greps are
`docs/field/fingerprint_telemetry_cheatsheet.md`. **Update both in the same change.**

From this file: `ZKEM_PUSH_DONE`, `ZKEM_PUSH_CHUNK`, `ZKEM_PUSH_FAILED_PINS`,
`ZKEM_PUSH_TPL_REFUSED`, `ZKEM_TPL_VERSION_MISMATCH`, `ZKEM_PUSH_WEDGED`,
`ZKEM_PUSH_RECONNECT`, `ZKEM_PUSH_ABANDONED`, `ZKEM_DEVICE_COUNTERS`,
`ZKEM_DELETE_DONE`, `ZKEM_PIN_UNMAPPED`, `ZKEM_STA_WEDGED`, `ZKEM_EVT_SINK_DOWN`,
`DOOR_OPEN`, `DOOR_OPEN_SWITCH`. All keyed `worker=ZKEM:<device id>`. `[CODE]`

**The push loop must not gain a per-member or per-finger telemetry line.** §2 is the
reason: the STA loop services **one command with no COM pump for its duration**, and
the logging handler writes synchronously inline on the calling thread. A line per
member on a 928-member roster widens that no-pump window — that is a behaviour change,
not instrumentation. Per-pin outcomes are accumulated **in memory** and emitted at
**chunk** boundaries (~93 lines for a full roster). The rare failure paths (a refused
template, a wedge) may write inline. The capped `_PUSH_TRACE_MEMBERS` /
`_PUSH_TRACE_TEMPLATES` lines remain the only per-call visibility, and remain
pre-call. `[CODE]` `[TEST: ::test_no_per_pin_event_inside_the_member_loop]`

`ZKEM_DEVICE_COUNTERS` is emitted **inside `_do_connect`**, from the `_read_fp_version`
/ `_read_device_status` values that connect already read — it adds **no device
round-trip**. Its `c_<name>` labels come from `_STATUS_FIELDS`, which §4 records as
**contradicted** by scripts 3 and 12; the event therefore ships `label_source=` so the
provenance travels with the numbers. Treat the names as unproven, the values as real.
`[UNVERIFIED]`

`ZKEM_VERIFY_OK` / `ZKEM_VERIFY_INVALID` are emitted by the **engine**
(`ultra_engine._process_event`), not here, but they are built from this file's
`normalize_att_event` output. The name reflects the `eventType` this driver stamps
(`"zkem_invalid"` when `IsInValid` is non-zero) — a routing fact. It is **not** a claim
about why the terminal refused: per §8, `IsInValid` and `AttState` semantics are
`[UNVERIFIED]` and `verifyMethod` is `[UNKNOWN]`. The event carries `verify_method`,
`att_state` and `scan_mode_hint` **raw and side by side**; never collapse them into one
decoded reason. `[CODE]`

---

## 10. Test coverage

**Covered.** `[TEST — `tests/test_zk_standalone_driver.py` and
`tests/test_device_sync_protocol_guard.py`]`
- push sequence: card **before** userinfo; slot-clear **before** template
- `SSR_DeleteEnrollData` **absent** from the slot-clear path
- chunking, wedge recovery, consecutive-wedge cap, cross-chunk trace budgets
- `EnableDevice` bracket order (first `False`, last `True`); unbracketed issues none
- pin guard (> 9 digits skipped)
- `list_users` fail-closed (three cases — but see §4 for what each asserts)
- device occupancy reporting, including that an unreadable status invents no capacity
- capability flags; `delete_all_transaction_rows` inertness
- the door command end to end `[TEST — tests/test_mb2000_force_open.py]`: switch
  resolution (env > local > default), `ACUnlock(1, ds)` argument values, the
  1…600 ds clamp, every `DOOR_OPEN` result, the fence/abandon/rebuild on a wedged
  `ACUnlock`, `_open_door_with_retry` and the worker command queue on this driver,
  `POST /door/open` → 200/409/500/503/429, the switch endpoints, persistence and
  payload projection, and a regression pin that the PullSDK door path is unchanged
- protocol conformance via `isinstance` (a conformance check only — exercises no
  behaviour)
- the fingerprint-chain telemetry `[TEST — tests/test_fingerprint_telemetry.py]`:
  per-chunk aggregation, `failed_pins` reasons for all four causes, template-refusal
  and version-mismatch events, wedge / reconnect / abandon events, device counters,
  both verify events with event age, that a template byte **never** reaches a log
  line, and that no per-pin event is emitted inside the member loop

**NOT covered.** `[UNVERIFIED]`
> Every test drives a **fake COM object**. No test has ever talked to an MB2000. Nothing
> in §8 is settled by the suite, and the COM argument orders in §4 are proven only as
> *what the code sends* — not as what the firmware accepts.

---

## 11. Verifying this guide

```bash
python -m pytest tests/ -q --ignore=tests/_pydeps
```
`--ignore=tests/_pydeps` is **required** (vendored packages break collection; there is
no `pytest.ini`). Last run: **1071 passed**, 2026-09-04 (after the fingerprint-telemetry
session; add `--ignore-glob='**/pytest_tmp_*' --ignore-glob='**/.tmp_pytest*'` when stale
permission-denied temp folders exist under `tests/`).

```bash
python -m pytest tests/test_zk_standalone_driver.py tests/test_device_sync_protocol_guard.py tests/test_mb2000_force_open.py tests/test_fingerprint_telemetry.py -q
```

List every `[T]` event this driver emits, and check §9.1 against it:

```bash
python tools/list_telemetry_events.py --where
```

Confirm §3 — the must-not-call — still holds. Match **calls** (`zk.`-prefixed), not the
bare words, which also appear in the explanatory comments:

```bash
grep -rn "zk\.SSR_DeleteEnrollData\|zk\.SSR_DelUserTmpExt" app/ --include=*.py
```

**Expected, exactly three lines** (was two before the 2026-09-05 removal work):
`zk.SSR_DelUserTmpExt(1, pin, int(finger_idx))` **twice** in `_do_push_roster` — once
clearing a **vacated** slot (before the template loop) and once as the
delete-before-write of a **desired** slot (inside it) — and
`zk.SSR_DeleteEnrollData(1, pin, 12)` — backup number **12**, the whole-user delete —
in `_do_delete_users`. **Any `SSR_DeleteEnrollData` call with a finger index is the
v1.4.25 hang being re-introduced.**

Confirm the roster rule of the main guide (§3.2 there) — every call site must be in
`ultra_engine.py`:

```bash
grep -rn "\.push_roster(" app/ --include=*.py
```

On-site ground truth before changing driver code — `tools/mb2000_scripts/` (`0_MENU.ps1`
plus 12 scripts: COM registration, device info, ZK9500 enrol, push, live monitor,
unlock, backup/restore, portability test, force-open).
