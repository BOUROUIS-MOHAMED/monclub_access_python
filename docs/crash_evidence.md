# A process that ends without "App shutting down" — the crash evidence (2026-09-30)

Moved out of `guide_for_agents_and_dev.md` (file-size rule); the guide's grading rules apply: `[CODE]` / `[TEST]` / `[FIELD]` / `[UNVERIFIED]` / `[UNKNOWN]`.

**Field.** Gym 45, PC "Accueil", 1.4.35: the app log stops at 07:50:31, mid-way through its 5-second
dashboard cadence. A new process starts at 07:50:48 (`startup_arg=False`) on the SAME Windows boot:
`monotonic_s` is 1040069, which continues the previous run's 1011100 + uptime. There is no shutdown
line, no traceback and no watchdog line. The last `PROC_HB` (07:49:41) shows `private_mb=107.8`,
`sys_avail_mb=728`, `sys_avail_pagefile_mb=2921`. The 285 MB low of that day came at 09:10, after the
restart. The cause is `[UNKNOWN]`. `[FIELD]`

**What existed.** `access/main.py` enables faulthandler at start, and a windowed build points
stderr at `%TEMP%\MonClubAccess.log` (`_ensure_console_streams`). So a native crash already left a
dump, but only in a temp file that nobody collects, that is never truncated, and that also receives a
full DEBUG copy of the app log (the console `StreamHandler` in `logger.py::setup_logging`). `[CODE]`

**What `crash_capture` adds.** `install()` is called once by `access/main.py::main`, AFTER the
single-instance guard (a second start must not wipe the running instance's files). It does three
things:
- It moves faulthandler to `<data root>/access/crash/faulthandler.txt`, truncated at each start
  once the previous content has been read.
- It writes a run marker, `running.json` (pid, start time, boot estimate = wall time minus
  monotonic). Only a normal interpreter exit (`atexit`) removes it, and it logs
  `[CRASH] interpreter exiting normally`.
- It logs unhandled exceptions of the main thread (`sys.excepthook`) and of every other thread
  (`threading.excepthook`) to the app log -- type and frames only (`safe_summary`), never the
  message, which can carry member data; the previous hooks still print the full traceback to the
  local stderr file.

**An exception out of the app itself** (`run_access_app`) unwinds through `atexit` -- a "normal"
interpreter exit that would remove the marker -- and may come before the app log exists (`init_db`,
`app.py:477`, runs before `setup_logging`, `:510`) or bypass `sys.excepthook` (a windowed
bootloader). So `access/main.py::main` catches it (`except BaseException`, a zero/None `SystemExit`
excepted), calls `crash_capture.record_fatal` and re-raises. `record_fatal` writes the full traceback
to `crash/fatal.txt` on the PC, adds `safe_summary` (type + frames, never the message) to the
marker and keeps the marker through `atexit`. The next start reports it at ERROR: a recorded
exception is proof of a crash. `[TEST: test_crash_capture.py::test_an_unhandled_exception_in_the_app_is_reported_at_the_next_start]`

`setup_logging` then calls `report_previous` once. A marker left behind becomes ONE `[CRASH] previous
run … ended WITHOUT a clean exit` line in the app log, which the uploader ships. The line carries the
last 16 KB of that run's faulthandler output. Its level depends on the case:
- ERROR only for an exception `record_fatal` recorded (below): that is proof of a crash.
- WARNING when the boot estimate matches ("same boot"). This is NOT proof that Windows kept running:
  with Fast Startup (`HiberbootEnabled=1`, the Windows default) a "shutdown" hibernates the kernel
  session, and the QPC-based `time.monotonic()` may continue across it `[UNVERIFIED]`. The Accueil
  PC's `monotonic_s=1011100` (11.7 days) at 29-09 23:47, at a gym whose PCs are said to be off
  every night, is consistent with that `[UNVERIFIED]`. So the marker also stores the time this boot
  spent asleep or hibernated (`interrupt_sleep_100ns`: `QueryInterruptTime` minus
  `QueryUnbiasedInterruptTime`, which Microsoft documents as excluding sleep and hibernation). The
  message says "the PC slept or hibernated N s in between" when that total grew by more than 60 s,
  and it is then INFO without a dump. Whether a Fast Startup shutdown really grows this total is
  `[UNVERIFIED]` on a real PC: until it is, "same boot, no sleep recorded" stays a WARNING whose
  text says so.
- WARNING (with a dump) or INFO (without one) when Windows restarted since. This is the daily
  power-off at most gyms.

On Windows faulthandler also prints first-chance exceptions that were handled later, so a dump alone is
not proof of a crash. An external kill (Task Manager, `taskkill`) leaves the marker and no dump.
`quit_app`'s 15-s shutdown fallback calls `crash_capture.forced_exit(1)` (in `app.py`, same line
count), which marks the marker before `os._exit`: the next start reports it at INFO as a forced
exit, not a crash. Only the last 16 KB of the dump is read (a seek, not the whole file).
`[TEST: test_crash_capture.py]` (subprocess `faulthandler._sigsegv()`, then a second start.)
