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
  (`threading.excepthook`) to the app log. The previous hooks still run after it.

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
- ERROR when the boot estimate matches, i.e. Windows kept running: a native crash, a fatal Python
  error, or an external kill.
- WARNING (with a dump) or INFO (without one) when Windows restarted since. This is the daily
  power-off at most gyms.

On Windows faulthandler also prints first-chance exceptions that were handled later, so a dump alone is
not proof of a crash; the marker is. An external kill (Task Manager, `taskkill`) or `os._exit` (the
15-s shutdown fallback in `quit_app`) leaves the marker and no dump.
`[TEST: test_crash_capture.py]` (subprocess `faulthandler._sigsegv()`, then a second start.)
