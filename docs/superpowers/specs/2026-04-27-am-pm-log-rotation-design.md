# AM/PM Log Rotation Design

## Goal

Change MonClub Access logging from generic numbered backups (`app.log.1`, `app.log.2`) to date-and-half-day log files that are easier to inspect during support work.

## Current Behavior

The app configures logging in `app/core/logger.py` through `RotatingFileHandler`. It writes to `C:\ProgramData\MonClub Access\data\logs\app.log`, rotates each file at 5 MB, and keeps 5 backups.

## Desired Behavior

Logs should be written under the existing log directory:

```text
C:\ProgramData\MonClub Access\data\logs\
```

The active file name should include the calendar date and half-day period:

```text
app-2026-04-27-am.log
app-2026-04-27-pm.log
```

AM covers `00:00:00` through `11:59:59`. PM covers `12:00:00` through `23:59:59`.

Each AM/PM file may grow to 50 MB. If a half-day file exceeds 50 MB, the logger should rotate within the same half-day using numeric suffixes:

```text
app-2026-04-27-am.log
app-2026-04-27-am.1.log
app-2026-04-27-am.2.log
```

The active file is always the unsuffixed file for the current date/period. Older chunks for the same period use `.1`, `.2`, etc.

## Retention

Keep logs for the last 7 calendar days, including all AM/PM chunks for those days. Delete files matching the new log naming pattern when their date is older than the retention window.

The cleanup should only target files matching:

```text
app-YYYY-MM-DD-am.log
app-YYYY-MM-DD-pm.log
app-YYYY-MM-DD-am.N.log
app-YYYY-MM-DD-pm.N.log
```

Legacy files such as `app.log`, `app.log.1`, and `app.log.2` should not be deleted by the new cleanup. They can age out manually or be removed later by a separate migration/maintenance decision.

## Architecture

Create a focused custom handler in `app/core/logger.py` or a small adjacent helper module. It should subclass `logging.FileHandler` or `logging.handlers.BaseRotatingHandler` and own three behaviors:

1. Resolve the correct active path for the current local date and AM/PM period.
2. Roll the current active file to the next available numeric suffix when it reaches 50 MB.
3. Remove new-pattern log files older than 7 calendar days.

`setup_logging()` should keep its public signature and continue returning the `zkapp` logger. Console logging and optional Tk queue logging should remain unchanged.

## Error Handling

If cleanup fails for one file, logging should continue and skip that file. If the log directory does not exist, the existing `ensure_dirs()` call should create it before the handler opens a file.

If the system clock crosses noon or midnight while the app is running, the next emitted record should switch to the new AM/PM file automatically.

## Testing

Add unit tests for the handler path and rotation behavior using a temporary directory:

- AM and PM filename selection.
- Date/period switch opens a new file.
- Size rotation creates `.1.log`, `.2.log`, etc.
- Retention deletes only matching new-pattern files older than 7 days.
- Legacy `app.log*` files are left untouched.

## Out Of Scope

This change does not add UI controls for log retention or max size. The requested values are fixed at 7 days and 50 MB.
