# MB2000 finger-slot sweep — field notes, 2026-09-30 (gym 45, PC "Accueil", 1.4.35)

Companion to `guide_for_agents_and_dev.md` §3.4c (moved out for the file-size rule). Grading as in the guide.

`[FIELD]` These observations do not change the design, but they contradict three figures of
the guide's §3.4c:
- *Wedges.* Two sweep commands out of about 800 ran past the 10-s `_call` deadline: `[ZKEM:8] STA
  thread WEDGED (command 'sweep_fingers' …)` at 00:10:24, and `[ZKEM:10]` at 17:46:39. The first
  stalled on the third command of pin 69451 (the one that carries `RefreshData`). The second stalled
  on the second command of pin 71726 (no `RefreshData`), so no single call is the common factor.
  Both recovered through the dead-link rebuild (guide §3.4e: `WORKER_LINK_LOST`, reconnect 7.7 s and
  7.8 s). The pin is not marked swept and is retried another day. That turnstile was blind for about
  10 s plus the reconnect time, each time. The PROC_HB thread count did not grow, which suggests the
  abandoned call returned `[UNVERIFIED]`.
- *The cap.* `_sweep_state` is in memory, so "≤ 100 pins a day" is really ≤ 100 per worker per
  PROCESS-day. On 30-09 the batch ran at 00:00, 07:50, 15:38 and 17:44, once after each restart.
- *`cleared`.* Most pins report `cleared=3`–`4` (returned `True`) for slots that should be empty.
  Yet both terminals hold 901 fingerprints for 822 users, and they were empty at 23:56 before 1.4.35
  pushed them. Either this firmware answers `True` for some empty slots (contrary to the 09-06
  measurement, §3 of the zkemkeeper guide) or those slots were occupied: `[UNVERIFIED]`.
