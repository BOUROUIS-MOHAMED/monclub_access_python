# ULTRA merge release 1 — field tests of plan 3 (Access extras)

For the owner, on a real turnstile, before the gate `MONCLUB_ULTRA_MERGE_MIN_ACCESS_VERSION` is set
(spec 2026-10-02 §10 "Field gates", §12 "Unverified"). Plan 2's gates (scan-to-open ≤ 2 s, the
repeat block, In service off) are in plan 2; this file covers what plan 3 adds.

Every expected result below is a code fact; what the hardware does is not known until you run it.
Those points are marked **[UNVERIFIED — hardware]**. Write every answer in the "Result" lines and
send the file back: the answers decide the next work (F1 decides plan 3 Task 10; F2 decides D10).

Before any test:
- the PC runs the release-1 Access build (plan 2 + plan 3);
- the turnstile is in ULTRA, In service, driven by this PC;
- you know its device id and IP (dashboard /gym-devices);
- Access writes its log to the usual log folder (Access → Logs).

---

## F1 — C3: are scans made while the PC was off replayed? (spec §5, §12)

Why: if the C3 live feed replays them, nothing is built. If not, plan 3 Task 10
(`offline_log_harvest.py`) is built — only then.

You need a C3 turnstile with cards decided **by the turnstile** (cards = TURNSTILE), one card the
panel holds (a member), one card it does not hold, and a watch.

1. Access running. Scan the member card once. The Access log shows `rtlog ALLOW: card=...`, and the
   entry is in Access's local history. This proves the feed works.
2. Quit Access (tray icon → Quit). Run the read-only export once
   (`tools\c3_panel_scripts\START_EXPORT.cmd -DeviceIp <ip> -Label f1_before -Auto`). Write down
   the `transaction` count: **N0 = ____**.
3. With Access still closed, at known times (write each one down to the second):
   - member card, 3 times, 15 s apart: ____ / ____ / ____
   - unknown card, 2 times, 15 s apart: ____ / ____
4. Run the export again (`-Label f1_after`). **N1 = ____**. N1 − N0 = 5 means the panel stored the
   scans. **[UNVERIFIED — hardware]**
5. Start Access. Wait 3 minutes. Search the Access log for the two card numbers.
   - Each line that names one of them: copy its `event_id`/time and the time the line was written.
   - In Access's local history, look for the 5 scans of step 3, at their own times.
6. Answer:
   - **Result F1-a:** the 5 scans of step 3 appear in Access's history after the restart:
     yes / no / some (which ones: ____).
   - **Result F1-b:** for each replayed scan, the delay between its scan time and the log line:
     ____ s. (This sets the "event age" guard, plan 3 OD-5.)
   - **Result F1-c:** did any door open on its own when Access restarted? yes / no.
   - **Result F1-d:** N1 − N0 = ____.
7. Only if F1-a is "yes" or "some": repeat steps 2-6 on a C3 whose cards the PC decides (cards = PC),
   with an UNKNOWN card and a member card. **Result F1-e:** when Access restarted, did the door open
   for a scan made while it was closed? yes / no. A "yes" means a refused card from the past opened
   the door now: send the log before release (plan 3 OD-5).

What the answers decide:

| F1-a | Then |
|---|---|
| yes, all 5 | Nothing to build. Plan 3 Task 10 is closed. Answer OD-5 (event age) from F1-b. |
| no | Plan 3 Task 10 opens. Before any code: one real `transaction` row must be read (Task 10 step 1). |
| some | Send the log. Do not decide alone. |

---

## F2 — MB2000: does `OnHIDNum` carry the number of a card the terminal does not hold? (spec D10)

Why: today an MB2000 reports a card it does not hold without its number
(`app/sdk/zk_standalone.py`, `normalize_att_event`: the card is looked up from the pin), so the PC
cannot decide it, and "cards decided by the PC" is offered on C3 panels only. If `OnHIDNum` carries
the number, it can be offered on MB2000 too.

You need an MB2000, one card it holds (a member), one card it does not hold, and the gym PC with the
32-bit Python runtime `tools\mb2000_onsite_gates.py` runs with (its `preflight` checks it; driver
plan §6).

1. Quit Access on this PC (tray icon → Quit). The probe refuses to run while it is open. Other PCs
   must not drive this terminal during the test (driver plan gate G5: a second connection is
   untested).
2. Run:
   `python tools\mb2000_hidnum_probe.py --ip <ip> --seconds 120 --out f2_hidnum.csv`
   (add `--commkey <key>` if /gym-devices shows a device password).
3. While it runs, 5 s apart: the card the terminal **holds**, the card it **does not hold**, then an
   enrolled finger.
4. Answer (from the screen or `f2_hidnum.csv`):
   - **Result F2-a:** an `OnHIDNum` line appeared for the held card: yes / no; its argument: ____
   - **Result F2-b:** an `OnHIDNum` line appeared for the card the terminal does NOT hold: yes / no;
     its argument: ____ ; does it equal the number printed on / known for the card? yes / no
   - **Result F2-c:** the `OnAttTransactionEx` line of the unknown card: arguments ____
   - The 2048 bit that registers `OnHIDNum` comes from this repo's driver plan
     (`docs/plans/mb2000_zk_standalone_driver_plan.md` §5), not from a measurement.
     **[UNVERIFIED — hardware]** If no `OnHIDNum` line appears at all, say so: the bit may differ.

What the answers decide: F2-b "yes, equals the card number" → D10 can open the PC choice on MB2000
(plan 2's "What plan 3 relies on" lists the three changes; they are a separate, reviewed change).
Anything else → MB2000 keeps TURNSTILE / OFF only.

---

## F3 — Fingerprints switched ON → OFF erase every template (D11; spec §10 field gate)

Needs plan 4's screen (or an API save with `fingerprintEraseConfirmed=true`): a save without the
confirmation erases nothing (D11, plan 1 OD-1).

C3 panel:
1. Quit Access; export (`-Label f3_before`): `templatev10` = ____, `template` = ____. Start Access.
2. On the dashboard, switch the device's fingerprints OFF and confirm.
3. At the earliest 2 minutes after the PC receives the change (plan 3 SD-10), the Access log shows
   `[REMOVAL] turnstile <id>: FINGERPRINTS request <id> done: ERASED templatev10=<n> template=<m>`.
4. Quit Access; export (`-Label f3_after`). **Result F3-a:** `templatev10` = ____ (expected 0),
   `template` = ____ (expected 0 or absent).
5. **Result F3-b:** a member's finger on the turnstile is refused: yes / no.
6. **Result F3-c:** the dashboard no longer shows a pending erase for the device: yes / no.

MB2000 terminal (the administrators keep their fingers, plan 3 OD-3):
1. On the terminal's menu note the fingerprint count: ____ ; administrators: ____.
2. Do this outside opening hours. Switch fingerprints OFF on the dashboard and confirm. The run
   sweeps 10 finger slots of every non-administrator user, three slots per terminal command, and the
   terminal serves the door only between commands (the driver measured 71-171 ms per slot,
   `app/sdk/zk_standalone.py`, `sweep_finger_slots`). Time it: ____ min for ____ users. During the
   run, open the door with a valid finger or card three times: delay before it opens ____ / ____ /
   ____ s. After the sweep a full rewrite pass follows (plan 3 SD-11): time it too: ____ min.
   **[UNVERIFIED — hardware]**
3. **Result F3-d:** the terminal's fingerprint count after = the administrators' fingers: yes / no.
4. **Result F3-e:** an administrator's finger still opens the terminal menu: yes / no.
5. **Result F3-f:** a member finger enrolled BY HAND on the terminal is refused now: yes / no.

---

## F4 — Cards moved away from TURNSTILE: "MonClub removes them" (D13)

Needs plan 4's screen (or an API save with `cardRemovalChoice=MONCLUB_REMOVES`).

1. On the turnstile, add one user BY HAND with a card (not through MonClub). Card: ____
2. Pick two MonClub members with cards on this turnstile. Cards: ____ / ____
3. On the dashboard move the device's cards to OFF (or PC on a C3), choose "MonClub removes them".
4. The Access log shows `[REMOVAL] ... CARDS request <id> done: REMOVED users=<n> records=<m>`.
   `users=0` means this PC holds no record of writing anyone to that turnstile (for example a PC
   reinstalled since): nothing was removed. Use the Erase wizard then.
5. **Result F4-a:** the two members' cards are refused by the turnstile: yes / no.
6. **Result F4-b:** the hand-added card still opens: yes / no (expected yes).
7. With fingerprints ON on that device: the members are written back without cards by the pass that
   follows. **Result F4-c:** time until a member's finger opens again: ____ min.
   **[UNVERIFIED — hardware]** (plan 3 OD-4).

---

## F5 — Desk alerts (spec §5, D4)

1. Daily pass alert: set the device's daily limit to 2. The same member passes 3 times.
   **Result F5-a:** the "anti-fraude daily limit" sound plays on the 3rd pass: yes / no.
   It never blocks: the 3rd pass opens.
2. Repeat block: a member block of 30 s on a device whose QR (or PC cards) the PC decides. The same
   member's QR twice within 30 s. **Result F5-b:** the 2nd is refused, with the popup and the
   "anti-fraude durée" sound: yes / no.
3. Windows notification: the device's "Windows notification" switch on. **Result F5-c:** one Windows
   toast per scan: yes / no. Read plan 3 OD-1 before enabling it on a busy gym.
