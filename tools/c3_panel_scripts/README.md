# C3 panel scripts (PullSDK) -- read-only

For the gym 58 cutover ([`docs/plans/2026-09-26_gym58_cutover_plan.md`](../../docs/plans/2026-09-26_gym58_cutover_plan.md)).
The MB2000 (zkemkeeper) scripts are in [`../mb2000_scripts`](../mb2000_scripts); they cannot talk to a
C3 panel (guide §2).

| File | What |
|---|---|
| `START_EXPORT.cmd` | starts the export in 32-bit PowerShell; pass the arguments after it |
| `export_c3_panel_readonly.ps1` | reads ONE panel into `exports\panel_<label>_<time>.json` + `.sha256` |
| `_pullsdk_read.ps1` | the only file that touches `plcommpro.dll`: six entry points, all reads |

## Use

**Quit MonClub Access on every PC of the gym first** (tray icon > Quit). The script refuses to run while
`MonClubAccess.exe` runs on its own PC; other PCs cannot be checked from here.

```
.\START_EXPORT.cmd -DeviceIp 192.168.0.202 -Label device5 -Auto
.\START_EXPORT.cmd -DeviceIp 192.168.0.203 -Label device6 -Auto
```

Type each IP in full. Add `-Password <device password>` when /gym-devices shows one for the panel, and
`-DllPath <path>\plcommpro.dll` when no `plcommpro.dll` is found: it looks in `.\sdk\`,
`..\mb2000_scripts\sdk\` and the installed MonClub Access, in that order. Copy the whole `tools` folder
(or at least this folder and `mb2000_scripts\sdk`) to the gym PC.

Exit codes: 0 complete, 1 setup or connect failure (nothing read), 2 a table read failed (partial file,
`complete: false`). A refused connection prints `CONNECT FAILED`: that is also the proof that a
firewall block works (gym 58 plan §3.2).

## What it reads, and why it cannot write

Parameters (the list Access itself reads for its device page), the clock (`DateTime`), the row counts of
`user`, `userauthorize`, `transaction`, `templatev10`, `template`, `timezone`, `holiday`, every `user` row
(pin, name, card, whether a password is set -- never its value -- and the other columns), every
`userauthorize` row, and per pin the finger ids of `templatev10` (never the template).

`_pullsdk_read.ps1` declares `Connect`, `Disconnect`, `GetDeviceData`, `GetDeviceDataCount`,
`GetDeviceParam`, `PullLastError` and no other `plcommpro.dll` function; the real-time log is not read.
`tests/test_c3_panel_export_readonly.py` checks that and runs the shipped script against a fake panel
that has only those six calls. It has never been run against a real panel: what a C3-400 answers, and
how long it takes, is known after the first run (the file records `timings` and `errors`).

## Then

Compare with MonClub on any PC with Python 3.9+:

```
python tools\gym45_cutover\compare_terminal_export.py --gym-id 58 --export 5=<file> --export 6=<file> --access-db <copy>\access.db --detail-csv cards58.csv
```

The `cards` section counts the members whose card is on the panel but will not be written by MonClub;
`cards58.csv` names them (personal data).
