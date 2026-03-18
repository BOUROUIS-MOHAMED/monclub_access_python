import sys
import faulthandler

# In windowed (no-console) PyInstaller builds sys.stderr/stdout are None.
# Redirect them to a log file so faulthandler and print() don't crash.
import os
import tempfile

if sys.stderr is None or sys.stdout is None:
    _log_path = os.path.join(tempfile.gettempdir(), "MonClubAccess.log")
    _log_file = open(_log_path, "a", buffering=1, encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = _log_file
    if sys.stdout is None:
        sys.stdout = _log_file

faulthandler.enable(all_threads=True)

print("step 1: starting main.py", flush=True)

if __name__ == "__main__":
    print("step 2: before importing run_app", flush=True)
    from app.ui.app import run_app
    print("step 3: after importing run_app", flush=True)
    run_app()
    print("step 4: after run_app()", flush=True)