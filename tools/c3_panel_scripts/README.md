# C3 panel scripts (PullSDK) -- read-only

> **Erasing a panel is not done here.** Since lane 1 (2026-09-27) MonClub Access has an **Erase content**
> wizard on its Devices page (the bin icon on a turnstile's row): it counts the tables, writes a verified
> backup file, erases only the tables you tick (`user`, `userauthorize`, `templatev10`, `template` -- ticking
> `user` ticks the rights and fingerprint tables too; never the door log `transaction`, parameters, time zones
> or holidays), checks they are empty, and can hold the panel until you press « Remplir ». The erase AND
> « Remplir » both need the internet (the server checks the admin password each time). Admin password, the
> typed device name and a tick box "MonClub Access is closed on every other PC of this gym until the refill"
> are required -- the hold only binds the PC that erases (lane 1b). Never uninstall or reinstall Access while
> a panel is on hold: the uninstaller deletes the hold and the backups. See `guide_for_agents_and_dev.md`
> §3.2h. These scripts stay the read-only survey tool.

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

Exit codes: 0 complete, 1 setup or connect failure, or MonClub Access running on this PC (nothing
read, no file), 2 a table read failed or the count of `user`, `userauthorize` or `templatev10` failed
(partial file, `complete: false`). A failed count is written as `null` (never as a number) and listed
in `errors`, which the screen prints as `error: …` lines; a failed count of another table is in
`errors` only. **Read `errors` even when the file says complete.**

A refused connection prints `CONNECT FAILED … (PullLastError=<code>, <n> ms)`. It is the proof that a
pulled cable or a firewall block works (gym 58 plan §3.2) only when the code is the one a **known**
unreachable panel gives: take that reference first (runbook step A2b / C3b: the panel's cable
unplugged at the panel, link light off, the export run once) and write the code down. A different
code at the interlock check means something else refused the connection -- for example another PC
still holding the panel (whether a C3-400 refuses a second client is `[UNVERIFIED]`). The check that
MonClub Access is not running covers **this PC only**.

**Personal data.** Each `exports\panel_*.json` holds every user's name and card number (a card number
may be enough to copy a card; the card technology is `[UNVERIFIED]`). Keep the files private and
delete them from all three places they end up once the cutover is verified: the gym PC's copy of this
folder (`exports\`), the USB key, and the laptop that ran the comparison. Better: run the tool from
the USB key and never copy it to the gym PC. `.gitignore` keeps `exports/` and every `*.csv` out of
a commit.

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
python tools\gym45_cutover\compare_terminal_export.py --gym-id 58 --export 5=<file> --export 6=<file> --access-db <copy>\access.db --detail-csv <USB key>\cards58.csv
```

The `cards` section counts the members whose card is on the panel but will not be written by MonClub;
`cards58.csv` names them (personal data: write it to the USB key, not into the repo). The line under
`== cards` is the **card self-check**: on the pins MonClub owns, how many panel cards equal the card
MonClub wrote. Below 90 % (or not measured) the list may only show that the panel returns cards in
another form than MonClub writes them: do not act on it, call the developer. In the CSV, only a row
whose note ends `no card in MonClub` may be entered at the desk; every other row names a card MonClub
already holds (first or second card), which must not be overwritten, or a card MonClub holds on another
member, which must not be entered (see the runbook, A6).
