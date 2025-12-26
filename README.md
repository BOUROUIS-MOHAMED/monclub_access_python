# ZK Turnstile Manager (PullSDK + ZK9500)

This is a Windows desktop app (Tkinter) that:
- Loads ZKTeco PullSDK (plcommpro.dll) to connect to controllers (C3/C4/inBio family).
- Browses device tables: user, userauthorize, timezone, holiday, transaction, templatev10, etc.
- Adds/updates users with CardNo and userauthorize.
- Enrolls fingerprints from ZK9500 (ZKFinger SDK) and stores templates locally in SQLite.
- Pushes fingerprint templates to controller via template table (templatev10).

## Important constraints
1) If your plcommpro.dll is 32-bit, you MUST run this app with 32-bit Python.
2) Fingerprint template pushing requires that:
   - your panel supports the template table (templatev10 for "fingerprint 10.0")
   - the template encoding matches what the panel expects (often base64-like text, but verify by reading back an enrolled template first).

## Setup (recommended)
1) Install Python 3.10/3.11 (32-bit) on Windows
2) Put plcommpro.dll (and required PullSDK DLL dependencies) in a known folder.
3) Put ZKFinger SDK DLL (often zkfp.dll) in a known folder.
4) Open PowerShell/cmd in this folder and run:
   - python -m venv .venv
   - .venv\Scripts\activate
   - pip install -r requirements.txt
5) Run:
   - run_app.bat

## Notes
- This project logs everything to: data/logs/app.log
- Config is saved in: data/config.json
- Local DB is saved in: data/app.db
