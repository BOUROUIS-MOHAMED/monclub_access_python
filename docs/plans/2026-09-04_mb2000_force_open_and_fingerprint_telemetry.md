# MB2000 force-open + fingerprint telemetry — plan for three sessions (2026-09-04)

Repo: `C:\Users\mohaa\Desktop\monclub_access_python`. Read `CLAUDE.md`,
`guide_for_agents_and_dev.md` (§0 maintenance contract, §5 capability flags) and
`zkemkeeper_guide.md` (§3 MUST-NOT-CALL list, ACUnlock notes) before touching
`app/sdk/zk_standalone.py`, `app/core/ultra_engine.py` or `app/api/local_access_api_v2.py`.
Grade every claim `[CODE]` `[TEST]` `[FIELD]` `[COMMENT]` `[UNVERIFIED]` `[UNKNOWN]`.
Tests must patch `app.core.db` to a temp DB (see `tests/test_zk_standalone_driver.py::_make_sync_worker`).
Verify: `python -m pytest tests/ -q --ignore=tests/_pydeps --ignore-glob='**/pytest_tmp_*' --ignore-glob='**/.tmp_pytest*'`
(baseline 908) and `python tools/check_sql_arity.py`. Do not commit unless the operator asks.

**Ordering.** Session A (scripts) can run any time. Session B (force-open in Access) and
Session C (telemetry) both edit `zk_standalone.py` and `ultra_engine.py`: run B first, merge,
then C. The already-running "logout token hole" session edits `local_access_api_v2.py`,
`app/ui/app.py`, `db.py`, `access_verification.py` — merge it before B/C or expect conflicts.

---

## Facts (2026-09-04)

- `tools/mb2000_scripts/` is the CANONICAL script lab (PowerShell only, `0_MENU.ps1` + 11
  scripts, `_common.ps1` with `Connect-Zkem`/`Assert-32Bit`/`Get-Config`). The operator's
  USB copy `C:\Users\mohaa\Desktop\mb2000_scripts\mb2000_scripts\mb2000_scripts` is
  byte-identical except for a saved `config.json` (device IP). Keep both in sync.
- `9_unlock_door.ps1` already exists: `ACUnlock(machineNumber, delayDeciseconds)` once,
  asks the operator whether the relay clicked. It is a one-shot test, not a force-open tool.
- Access door-open chain `[CODE]`: `POST /api/v2/devices/{id}/door/open` →
  `local_access_api_v2.py:3880-3950` (AGENT engine first, then ULTRA worker command queue;
  1 s cooldown → 429 at :3873-3875; refuses with 409 "l'ouverture de porte est désactivée
  pour ce modèle" at :3933-3945 when the driver's `supports_open_door` is False) →
  `UltraDeviceWorker` `self._sdk.open_door(...)` at `ultra_engine.py:916` (command) and
  `:2599` inside `_open_door_with_retry` (TOTP/RFID rescue) → `ZKStandaloneDevice.open_door`
  `zk_standalone.py:444` → STA command → `_do_open_door` `:1091` `zk.ACUnlock(1, delay_ds)`.
  `supports_open_door = False` class default at `:252` (GATE 4: ACUnlock unverified on the
  MB2000); per-machine override via env `MONCLUB_ZK_STANDALONE_OPEN_DOOR` (`:104-125`,
  applied at `:294-300` with a loud warning). The worker exposes the flag at `:3406-3417`.
- Field `[FIELD]` 2026-08-30 (Desktop\Gmail logs): 13× `DOOR_OPEN result=409_unsupported`
  and 8× `429_cooldown` in ten seconds at 14:02 — the desk pressed "open" repeatedly and
  was refused every time. Device 8 "Sortie" 192.168.1.247:4370, worker init `totp=False rfid=False`.
- Whether `ACUnlock` physically releases THIS turnstile is `[UNKNOWN]` until script 9/12
  passes on site. `ACUnlock` returning True with no release = wiring, not SDK (`[COMMENT]`).
- Fingerprint chain `[CODE]`: enrol = `app/ui/app.py` `begin_remote_enroll`/`_remote_enroll_worker`
  (~3213-3400: resolve membership via `_find_user_membership`, ZK9500 capture in
  `app/sdk/zkfinger.py`, `create_user_fingerprint` `app/api/monclub_api.py:460`, then
  targeted ULTRA member sync) with EnrollOverlay progress over the local API
  (`_handle_enroll_start` + SSE); sync = template arrives through get_gym_users delta →
  `save_sync_cache_delta` (`db.py:3972`), `FP_DELTA` telemetry in `device_sync.py`
  (detail_out/fields_out) and `ultra_engine._log_fingerprint_delta`; push =
  `_run_standalone_full_sync` / `_run_standalone_member_sync` (`ultra_engine.py` ~1270-1460,
  `_standalone_pin_hash`, `device_sync_state`, `failed_pins`) → `zk_standalone._do_push_roster`
  (per pin `SSR_SetUserInfo`, `SSR_DelUserTmpExt` only inside the template loop,
  `SetUserTmpExStr`; `ZKEM_PUSH_DONE` at `:648`); verify = `_on_att_event` `:1062` →
  `normalize_att_event` `:150` (`IsInValid` → eventType `zkem_invalid`) → `_process_event`
  `ultra_engine.py:2014` (a `zkem_invalid` event today only produces the generic warning
  "unrecognised eventType" at `:2084`); device counters `_device_status` / `_read_fp_version`.
  Telemetry module `app/core/telemetry.py` (`_tel.event/warn/timed/profile`, `[T]` prefix;
  existing names: `ZKEM_PUSH_DONE`, `ZKEM_DELETE_DONE`, `ZKEM_PIN_UNMAPPED`, `POPUP_ENQUEUE`,
  `HISTORY_RECORD`, `WORKER_STALL`, `FULL_SYNC_START`, `DOOR_OPEN`).

---

## Session A — force-open script in the lab (+ USB copy)

1. Add `12_force_open_door.ps1` next to `9_unlock_door.ps1`, using `_common.ps1`
   (`Assert-32Bit`, `Get-Config`, `Connect-Zkem`, `Disconnect-Zkem`, `Write-*`): parameters
   for duration (seconds → deciseconds, clamp to the SDK maximum you can prove from
   `zkemkeeper_guide.md`; do not invent a maximum), repeat count and interval for a sustained
   "force open"; print `ACUnlock` return, `GetLastError` if the guide documents it, elapsed ms,
   and device info (`3_get_device_info` fields) before/after; write every attempt to a
   timestamped log file in the lab folder so the operator can send it back; no-prompt mode
   (`-Auto`) for the desk. Read `zkemkeeper_guide.md` for the exact `ACUnlock` semantics;
   anything not proven there is `[UNVERIFIED]` in the script header.
2. Register it in `0_MENU.ps1` and `README.md` (what PASS/FAIL means; "TRUE + no release =
   wiring"). Keep script 9 unchanged as the minimal test.
3. Copy the result to the USB folder and confirm the two folders differ only by `config.json`.
   Do not overwrite the USB `config.json`.
4. Update `zkemkeeper_guide.md` where it references script 9 for GATE 4 (mention 12).

## Session B — make force-open work for the MB2000 in Access

Goal: the desk's "open door" button and the ULTRA rescue paths issue `ACUnlock` on the
standalone family, are observable, and never fail silently. The physical proof stays on
site (Session A's script); the software must be correct and loud.

1. Replace the env-var-only gate with a persisted, per-device switch that is ON for the
   standalone family by operator decision: read it from the device payload / backend
   `deviceCapabilities` if a suitable field exists (grep `deviceCapabilities`, `capabilities`
   in `app/core/device_sync.py`, `db.py` device columns, `settings_reader.py`); otherwise add
   a local per-device setting exposed in the Devices page control panel (existing per-device
   panel: memory `project_device_control_panel`, `GET /devices/{id}/settings`). Keep
   `MONCLUB_ZK_STANDALONE_OPEN_DOOR` as an override that can force OFF or ON. Whatever the
   source, log the effective value at worker start.
2. Trace and test the chain end to end with the fake COM pattern from
   `tests/test_zk_standalone_driver.py`: local API → worker command queue → STA → `ACUnlock`
   with the right machine number and deciseconds; `_open_door_with_retry` on the standalone
   worker; the 409 path only when the switch is OFF; a False return surfaces as a clear
   French message and a `DOOR_OPEN` telemetry event with `result` ∈ {ok, false, exception,
   timeout, unsupported, cooldown} plus `dur_ms` and `delay_ds`; the STA generation fence
   (`_sta_gen`) and wedge recovery must not be bypassed by the door command (read
   `zkemkeeper_guide.md` superseded-thread section).
3. Check `pulseSeconds` handling: local API clamps 1-60 s (`:3881-3884`); `ACUnlock` takes
   deciseconds — verify the conversion and the SDK's maximum from the guide, clamp, and log
   when clamped.
4. Update `guide_for_agents_and_dev.md` §5 (capability flag semantics + how it is enabled)
   and `zkemkeeper_guide.md` (ACUnlock status stays `[UNVERIFIED]` on hardware until the
   operator reports script 12 PASS; say so explicitly). Update `tests/`.
5. Do not touch PullSDK door-open code paths; add a regression test that the PullSDK
   `open_door` path is unchanged.

## Session C — logs + telemetry across the whole fingerprint process

Goal: tomorrow, any failure anywhere in enrol → backend → sync → push → verify is
locatable from the log with one grep, without a rebuild.

Rules: never log template bytes (log length, encoding, sha1[:8], `templateVersion`);
INFO-level `[T]` events with stable names and a correlation key on every line
(`enroll_id` for enrolments, `pin`/`am_id` for members, `device_id`/worker id for pushes);
no new DB reads on the live worker thread; no behaviour change; every new event has a test
asserting it fires (capture pattern: look at how existing tests assert on `_tel`).

Instrument, at minimum:
- Enrol: start (membership resolved, candidates, chosen am_id — extend the existing WARNING),
  ZK9500 init/open result and DLL path (`zkfinger.py`), each capture sample (quality, size),
  merge result, backend `create_user_fingerprint` request summary and HTTP status + error
  body, elapsed per phase, the targeted member sync request, and a single terminal
  `ENROLL_DONE` line with outcome ∈ {ok, capture_failed, backend_rejected, sync_failed}.
- Sync: when a delta/full response carries templates, log per member changed:
  am_id, finger ids, template sizes, encoding, `templateVersion`; log `FP_DELTA` decisions.
- Push: per pin on the standalone family, result of `SSR_SetUserInfo`, each
  `SetUserTmpExStr` (finger id, size, ok), failed_pins with reason; per chunk timing; STA
  wedge/abandon/reconnect as named events; device counters before/after
  (`_device_status`, fp version) and any template-version mismatch as a WARN event.
- Verify: turn the generic "unrecognised eventType" at `ultra_engine.py:2084` into a named
  `ZKEM_VERIFY_INVALID` event carrying pin, verify_method, att_state, event age; add
  `ZKEM_VERIFY_OK` (pin, verify_method, age) at DEBUG/INFO for accepted fingerprint scans
  if not already covered by `POPUP_ENQUEUE`; log event age vs now so terminal backlog
  replays (seen at 13:51 on 08-30: events 3500 s old) are distinguishable from live scans.
- Door: covered by Session B's `DOOR_OPEN` results.
- Write `docs/field/fingerprint_telemetry_cheatsheet.md`: one grep per question
  ("did the enrolment reach the backend?", "was the template pushed to pin X?", "did the
  terminal reject a finger?", "was the door command issued and what did ACUnlock return?").
  Note the 19 hourly log windows per day and where they are in the dashboard.
