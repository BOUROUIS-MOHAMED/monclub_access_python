# PullSDK Guide — `plcommpro.dll` / `ZK_PULLSDK`

Reference for the **PullSDK** half of MonClub Access. Companion files:
[`guide_for_agents_and_dev.md`](guide_for_agents_and_dev.md) (system orientation) and
[`zkemkeeper_guide.md`](zkemkeeper_guide.md) (the other SDK). The three are meant to
agree; if they disagree, one of them is wrong and must be fixed, not worked around.

`README.md` is stale and describes a tool that no longer exists. Ignore it.

---

## 0. Maintenance contract

**Every claim in this file carries a status marker and a way to check it.** If you
change the code, update the row in the same change. If you cannot verify a claim you
are about to write, mark it `[UNVERIFIED]` or leave it out — omission is correct,
approximation is a defect.

| Marker | Means | How to check |
|---|---|---|
| `[SIG]` | The signature, quoted verbatim from the `def` line. | Read the `def` line. |
| `[CODE]` | **Executable statements** prove it. | Read the statements, not the docstring. |
| `[COMMENT]` | Only a docstring or comment asserts it. **Not evidence of behaviour.** | — |
| `[TEST]` | A named test actually exercises it. | Run the named test. |
| `[FIELD]` | A specific **measurement** plus a **date or version** exists. | Read the cited source. |
| `[UNVERIFIED]` | Stated as unproven by the source itself. | — |

**The rule that matters most:** a docstring is a *claim*, not evidence. This codebase
has unusually rich explanatory comments; several are subtly wrong about the code they
sit next to. Grade what the statements do, not what the prose says they do.

Rules for editing:

1. Quote signatures **verbatim**. A symbol name does not tell the next agent that
   `open_door` takes `pulse_time_ms` while the parameter written to the panel is
   spelled `Door{N}Drivertime`.
2. Never state a universal ("every method…") without checking every case. Four such
   claims were written for this file and all four were false — see §9.
3. Do not promote `[COMMENT]` to `[CODE]` because the comment sounds authoritative.

---

## 1. What this SDK is

`plcommpro.dll` — ZKTeco's **Pull SDK**, a native Windows DLL loaded with `ctypes`.

- **Calling convention: stdcall.** Loaded as `ctypes.WinDLL`, not `CDLL`. `[CODE]`
- **Transport:** one TCP connection per panel, opened with a comma-separated
  connection string (§4.1).
- **Event model: POLL.** The app asks the panel for new real-time log rows. Nothing
  is pushed.
- **Data model: TABLES.** The panel exposes named tables (`user`, `userauthorize`,
  `transaction`, `templatev10`, …) read and written as delimited text.
- **Bitness: 32-bit.** `build_release.ps1` throws when `Requires32BitPython` is set
  and the interpreter is not 32-bit. `[CODE]`

---

## 2. Models — graded by evidence that actually exists

Do not widen this table without adding evidence. **The strength of evidence is not
what you would guess**: the model the operator is most confident about has the least
support *in the code*, and vice versa. Both facts are recorded honestly below.

| Model | Grade | Evidence |
|---|---|---|
| **C3-200** | `[FIELD]` | The only PullSDK panel with a dated production measurement: **2026-06-24, two turnstiles measured 38–74 s behind the PC clock**, causing scan-time TOTP to always fail and ~50 % `DENY_NO_MATCH`. Named at four further sites (handle leak, ~225 ms `SetDeviceParam`, `ControlDevice` param3 ignored, idle-socket drop) — those four are `[COMMENT]`. |
| **C2-400** | `[COMMENT]` in code, **operator-confirmed in production at v1.4.19** | In the source it appears **only in prose** — as sharing C3-200 idle-socket behaviour, and as the baseline whose output must not change. No measurement, no date. Its real support is the operator's own report, which is outside this repo. |

> **C2-400 and C3-200 are not ranked — they answer different questions.** C3-200 has a
> *documented measurement* (one dated number about one behaviour). C2-400 has
> *operational confirmation* (a gym running on it in production for months), which is
> the stronger evidence that the panel **works** and the weaker evidence about any
> **specific** behaviour. Do not "upgrade" C2-400 by inventing a measurement, and do not
> read C3-200's `[FIELD]` as meaning it is better supported overall.
| **C3-400** | `[COMMENT]` | Referenced for 4-door bitmask math (`1｜2｜4｜8 = 15`) and the `fingerprintEnabled=false` path. No dated measurement. |
| **ZK9500** (desk enrolment scanner, not a panel) | `[CODE]` | Named in executable code — the desktop enrolment flow labels its init step before constructing `ZKFinger`. That it captures **algorithm v10** is `[COMMENT]` only. |
| ~~C4 / inBio~~ | **Do not claim.** | Named only in the `DeviceProtocol` docstring and one `delete_device_data_batch` docstring citing *ZKTeco PullSDK User Guide V2.0*. Both are author prose. Removed from all three guides. |

> **No code anywhere branches on a PullSDK model.** Routing is by protocol; behaviour
> differences are handled by runtime probes (§3.3) and capability flags. Keep it that
> way — see the main guide §2.

---

## 3. The two classes — the single most costly confusion in this repo

`app/sdk/pullsdk.py` defines **two** classes. They are not interchangeable and the
distinction is load-bearing.

### 3.1 `PullSDK` — the low-level DLL wrapper

Raw `ctypes` over `plcommpro.dll`. Exposes the panel's table surface
(`get_device_data_rows`, `set_device_data`, `delete_device_data`, `control_device`,
`get_device_param`).

**No other driver implements this surface.** Code written against it is PullSDK-only
by construction.

Constructed directly by `device_sync.py` and `local_access_api_v2.py`. `[CODE]`

```python
def __init__(self, dll_path: str, logger):     # [SIG] positional, both required
```

Construction does **no** loading and **no** connecting — it only assigns attributes,
leaving `_dll` and `_h` as `None`. `[CODE]`

### 3.2 `PullSDKDevice` — the portable driver

Implements the `DeviceDriver` protocol from `app/sdk/device_driver.py`. This is what
`get_driver()` returns. Wraps a `PullSDK` instance.

```python
def __init__(self, device_payload: Dict[str, Any], logger=None):    # [SIG]
```

There is **no `ip`/`port` parameter** — connection data is picked out of the payload,
accepting several key spellings: `ip｜ipAddress｜ipaddress｜ip_address｜host｜address`,
`port｜portNumber｜port_number｜devicePort` (default **4370**), `password｜passwd｜pass｜
devicePassword`, `timeoutMs｜timeout｜connectTimeoutMs` (default **3000**). `[CODE]`

A freshly constructed driver reports `is_connected is False` — construction has no
side effects.
`[TEST: test_device_driver_factory.py::TestGetDriver::test_payload_is_passed_through]`

### 3.3 `supports_*` means THREE different things — check which one you are looking at

This naming collision has caused real errors. There is no shared mechanism.

| Form | Where | Mechanism |
|---|---|---|
| `PullSDK.supports_get_rtlog()`, `supports_get_rtlog_ext()`, `supports_delete_device_data()`, `supports_control_device()`, `supports_get_device_param()`, `supports_set_device_param()` | low-level class | **Runtime DLL export probe** — literally `self.load()` then `hasattr(self._dll, "SymbolName")`. Answers "does this particular `plcommpro.dll` build export the symbol". `[CODE]` |
| `PullSDKDevice.supports_get_device_param()` / `supports_set_device_param()` | driver | **Delegation** — `return self._sdk is not None and self._sdk.supports_…()`. Returns `False` when not connected. No lock, no `ensure_connected`. `[CODE]` |
| `PullSDKDevice.supports_transaction_table = True`, `ZKStandaloneDevice.supports_transaction_table = False` | class body | **Static capability declaration.** A plain class attribute; no instance ever reassigns it. `[CODE: pullsdk.py:1193, zk_standalone.py:325 — every other hit under app/ is a getattr read]` |
| `ZKStandaloneDevice.supports_open_door` | class body, **re-resolved per instance** | **Per-device switch, mutable at runtime** — the one `supports_*` that is NOT static. The class body holds only the family default (`_OPEN_DOOR_FAMILY_DEFAULT = True` since 2026-09-04; it was `False` before). `__init__` re-resolves it for each device (env > the operator's per-device switch > family default) and the local API reassigns it on the **live** driver when the switch is flipped. Read it off the **instance**, never off the class: the class value ignores an operator's per-device OFF. `[CODE: zk_standalone.py:117/320/363, ::apply_open_door_switch; local_access_api_v2.py::_handle_device_open_door_switch_set]` — full priority table in `guide_for_agents_and_dev.md` §5.1 |

Consumers read declarations defensively — `getattr(sdk_device, "supports_transaction_table", True)`
— so a driver that omits the flag is treated as **having** the capability. `[CODE]`

`PullSDKDevice` declares **no** `owns_event_source` attribute at all; the ULTRA engine
reads it with a `getattr(..., False)` default. Note it selects a *sync path*, not event
acquisition. `[CODE]`

---

## 4. Wire formats

Getting these wrong produces a panel that accepts the call and does nothing.

### 4.1 Connection string

```
protocol=TCP,ipaddress={ip},port={port},timeout={timeout_ms},passwd={password}
```
Built by joining exactly those five parts with `,`. `[CODE]`

**The keys `plcommpro.dll` actually accepts** — read out of the shipped DLL's own
connection-key table, which sits contiguously in `.rdata` next to `pltcpcomm.dll` /
`plusbcomm.dll`: `[CODE — binary inspection]`

```
ipaddress   port   deviceid   baudrate   passwd   protocol
```

(`timeout` is a separate nearby string.) The app uses five of these; **`deviceid` and
`baudrate` are accepted by the DLL but never sent** — `baudrate` belongs to the serial
transport.

> ⚠️ **There is no `platform` key. Do not add one.** Every one of the **101**
> `plcommpro.dll` copies in this repo is the same build (sha256 `82bda08d…`, 254 464
> bytes) and contains **zero** occurrences of the byte string `platform` in any casing.
> `[CODE — verified across all copies]`
>
> A `platform` parameter existed until **2026-08-29**: the first version appended it to
> `parts`, commit `0548a1d` removed the append but left the signature and a log
> fragment behind, so for every release since, callers passed a value, the log rendered
> `,platform=X` as though it were sent, and the DLL never received it. It is now
> **removed**, not re-wired — pushing an unrecognised token into the connection string
> of live C2-400 / C3-200 panels would be risk for no benefit.
> `[TEST: test_pullsdk_connect_string.py::TestConnectionStringContents]`
>
> The backend still sends a per-device `platform` field and the UI displays it. It is
> **informational only** and reaches no SDK call.

### 4.2 Table row data

Rows are `\r\n`-terminated, **including the last one**: `"\r\n".join(chunk) + "\r\n"`.
`[CODE]` A row is tab-separated `Key=Value` pairs.

### 4.3 Fields and filters

Both are normalized before use. `[CODE]`

- **Fields** — empty or `*` → `*`. Otherwise `;` and `,` become `\t`; PullSDK v2.2+
  expects tab-separated field names.
- **Filters** — spaces around `=` are stripped, `,` becomes `\t`, and repeated tabs
  collapse. So a caller may pass comma- **or** tab-separated conditions.

### 4.4 Device parameters

`items` is a comma-separated `K=V` list. Note the spelling actually written for the
door pulse is **`Door{N}Drivertime`** — not `DriveTime`, despite the surrounding
comment. Quote it from the code, not the prose. `[CODE]`

### 4.5 String encoding

Every `char*` argument is encoded `mbcs` with `errors="replace"` — characters that
are not ANSI-representable are **silently replaced, not rejected**. `[CODE]`

Buffers are decoded `mbcs` strict → `utf-8` strict → `latin-1` with `errors="replace"`,
so decoding never raises. `[CODE]`

### 4.6 One person, two PINs — ship it, do not "fix" it

The `PIN`/`UserId` written to a device row is the `activeMembershipId`, falling back to
`userId` only when the member has no active membership at all —
`app/core/device_sync.py:1377-1380`. A person is not one PIN; a *membership* is. So a
member holding two date-valid memberships at one gym occupies **two PINs on the same
terminal**, each carrying its own copy of that person's fingerprint templates. `[CODE]`
Measured on the OXYGENE_FIT payload (2026-08-31): **20 of 914 members carry two
`activeMembershipId`s, both rows legitimately valid** —
`app/ui/app.py:3507-3519`. `[FIELD]`

This is enforced, not incidental: `sync_users` carries a unique index on
`(user_id, active_membership_id)`, **not** on `user_id` alone —
`app/core/db.py:877` (`uq_sync_users_uid_amid`). `[CODE]` Collapsing the two PINs into
one would mean dropping a roster row, and a roster row missing a positive-integer
`activeMembershipId` sets `users_valid = False` (`app/core/db.py:4638-4647`) →
`delete_refused = True` (`app/core/db.py:4825`), which refuses **all** member
deletions for that sync. `[CODE]` Fail-open on revocations is a worse bug than a
duplicated template, so this is a known, accepted shape, not a defect to chase.

**What this means for anything keyed by PIN:**

- **The 10-fingerprint cap is intended to be per `(gym, account)`, never per PIN or
  per device slot — so a person with two memberships can occupy up to 20 device-row
  slots for the same 10 templates.** `[UNVERIFIED]` — this is the account-level-
  fingerprints design (`docs/superpowers/specs/2026-09-11-account-level-fingerprints-
  design.md` §4.5, §3.5), not yet shipped: as of this writing `monclub_backend` main
  has no `GymFingerprintEnrolment`/`gym_fingerprint_enrolment`, so the cap today is
  still whatever the pre-existing per-`activeMembershipId` enforcement is. Re-check
  this bullet once that backend work ships. Either way: do not "fix" a terminal that
  looks like it is carrying double the expected fingerprint count for one person —
  check membership count first.
- `fingerprint_push_status`'s primary key is `(pin, finger_id, device_id)` and
  `fingerprint_push_reported`'s is `(pin, finger_id)` — `app/core/db.py:1461-1483`.
  `[CODE]` Because `pin` is part of both keys and two memberships are two different
  PINs (above), the two rows a two-membership person produces are never merged or
  deduplicated by this schema — each PIN's outcome is tracked, and would be reported
  upstream, completely independently of the other's. Two rows per template for such a
  person is correct, not a duplicate-row bug.

---

## 5. `PullSDK` — low-level reference

### Loading

```python
def load(self) -> None:                                              # [SIG]
```
Returns immediately when `_dll` is already set. Reads a **class-level** `_dll_cache`
(keyed on the `Path`-normalized dll path) on a lock-free fast path, then falls into
`_load_lock` with double-checked locking for the real `WinDLL` load. `[CODE]`

`_dll_cache` and `_load_lock` are shared by **all** instances. `[CODE]`

> Not every method calls `load()`. `disconnect()` and `pull_last_error()` do not —
> they guard on `_dll is None` directly. `[CODE]`

Registered prototypes include: `Connect(char*) -> void*`, `Disconnect(void*) -> int`,
`GetDeviceData(void*, void*, int, char*, char*, char*, char*) -> int`,
`SetDeviceData(void*, char*, char*, char*) -> int`,
`DeleteDeviceData(void*, char*, char*, char*) -> int`,
`ControlDevice(void*, int, int, int, int, int, char*) -> int`,
`GetRTLog(void*, void*, int) -> int`, `GetRTLogExt(void*, void*, int) -> int`. Optional
symbols are prototyped only when `hasattr` finds them. `[CODE]`

### Connection

```python
def connect(self, *, ip, port, timeout_ms, password) -> None                  # [SIG]
def disconnect(self) -> None                                                  # [SIG]
```
`connect()` raises `PullSDKError` when the DLL returns a falsy handle. `disconnect()`
discards `Disconnect`'s return code entirely and always clears the handle. `[CODE]`

`PullSDKError` subclasses `RuntimeError`, so `except RuntimeError` catches it. `[CODE]`

#### ⛔ The handle must not be freed under an in-flight call

**Added 2026-09-11.** `_h` is a **raw native pointer**, and every wrapper captures it
into a local *before* entering the DLL:

```python
h = self._require_handle()                                  # captured here
rc = int(self._dll.GetRTLogExt(c_void_p(h), buf, sz))       # used here
```

So clearing `_h` fences nothing that is already inside plcommpro.dll. `[CODE]`

That matters because **`disconnect()` is called from a thread that is not the one
using the handle, by design.** Both poll watchdogs — `ultra_engine._poll_with_watchdog`
and the inline one in `realtime_agent` — abandon a blocked poll, leave that thread
running, and then disconnect, on the stated reasoning that *"the SDK disconnect should
unblock the orphan thread"*. `[COMMENT: ultra_engine.py, at the top of
_poll_with_watchdog — never graded, and not verifiable without the hardware]`

Freeing the session there is a **use-after-free in native code**: the orphan is still
inside `GetRTLog`/`GetRTLogExt` and the DLL goes on to write the RTLog payload through a
released context. Same class of defect, and the same delayed-access-violation
signature, as the zkemkeeper apartment teardown (`zkemkeeper_guide.md` §2).

`disconnect()` therefore now: `[CODE]`

1. takes `_h_lock` (a short bookkeeping lock, **never** held across a native call),
2. clears `_h` immediately, so no NEW call can take it,
3. frees natively **only if** `_inflight == 0`,
4. otherwise records `_pending_free` and returns — the last caller out runs the free
   in `_exit_handle_use`.

Every method that reaches the DLL holding the handle is marked `@_holds_handle`, which
takes the lease for the whole call. All ten are decorated, and a test asserts that any
future `_require_handle` user is too.
`[TEST: test_pullsdk_handle_lifetime.py — 3 of its 8 cases fail against the pre-fix
source, including the core "no Disconnect while a call is in flight"]`

> **Why not just put `disconnect()` under `_sdk_lock`?** It was the only SDK method
> that skipped it, so that looks like the obvious fix. It is not: `_sdk_lock` is held
> across the blocked native call, so the watchdog would block forever behind the very
> call it is trying to escape — deadlocking the worker or agent thread instead of
> corrupting the heap. See §6 *Locking*.

**The deliberate trade.** If the orphan never returns, its session and socket leak
until the process restarts. That is accepted: a bounded leak we log beats memory
corruption we cannot see. It does mean the callers can no longer rely on `disconnect()`
unblocking anything, so progress has to come from a fresh connection instead — which is
why `_poll_with_watchdog` now retires a hung poll thread as a **bounded orphan**
(`_MAX_ORPHAN_POLL_THREADS = 3`) and polls on the new connection, rather than returning
`None` forever. `[CODE]` Before that change, deferring the free would have left the
device permanently unpolled — a silently dead turnstile, strictly worse than the crash.

> `[UNVERIFIED]` Whether `Disconnect(h)` actually unblocks a concurrent
> `GetRTLogExt(h, …)` on this DLL is **unknown** and cannot be settled without a C3
> panel. The design above is safe either way: if the orphan returns, the deferred free
> runs; if it never does, the orphan fence keeps the device polling regardless.
> **This change has not been exercised against real PullSDK hardware.**

#### ⛔ A wedged poll poisons the *device object*, not just the connection

`_sdk_lock` is created in `PullSDKDevice.__init__` and **never rebuilt**. `connect()`
builds a fresh `PullSDK` — a new handle — but reuses the same lock. `[CODE]`

An orphan wedged inside `poll_rtlog_once` holds that lock for as long as it is stuck, and
every other SDK entry point queues behind it: `open_door`, `get_device_time`,
`set_device_time`, `get_device_param`, `set_device_param`, `get_table_count`,
`read_table_rows`, `delete_table_rows`. `[CODE]` **`open_door` is on that list**, so
reconnecting is not recovery — the door stays unopenable and the thread that asks hangs
with it, indefinitely.

Recovery therefore requires a **new `PullSDKDevice`**, not a reconnect:

| Caller | Device lifetime | Wedge recovery |
|---|---|---|
| `ultra_engine` | new driver per connect cycle (`get_driver` in `_connect`) | free — the new object has a new lock |
| `realtime_agent` | **one driver for the worker's life** (`__init__`) | must swap explicitly — `_retire_orphan_and_rebuild()` |

The orphan keeps its reference to the old object and drains its own deferred free if it
ever returns. `[CODE]`
`[TEST: test_poll_orphan_fence.py::test_a_wedge_replaces_the_driver_rather_than_reusing_it]`

> Acquisition is **untimed** (`with self._sdk_lock:`), so this is a permanent block, not a
> slow path. Anything new that takes `_sdk_lock` inherits that, and anything that holds a
> long-lived `PullSDKDevice` inherits the swap obligation.

#### ⛔ Refusing at the orphan cap must not remove the throttle

The agent's cap raises once `_MAX_ORPHAN_POLL_THREADS` orphans are stuck. That
`RuntimeError` lands in `run()`'s outer `except`, which disconnects and sleeps **0.25 s**,
and `ensure_connected()` then *succeeds* — the panel is healthy, only the poll threads are
wedged — so the connect-failure backoff never arms. `[CODE]`

Raising immediately therefore converts a ~15 s reconnect cadence into roughly **four
`Connect`/`Disconnect` cycles a second, indefinitely**. At ~1 OS handle + ~280 KB leaked
per cycle (§ reconnect cost), a 32-bit process exhausts its address space in hours and
ends in the `can't start new thread` lockup. `_refuse_if_orphans_at_cap()` waits
`poll_timeout_sec` on `stop_event` first, preserving the cadence the 15 s join used to
provide while keeping shutdown prompt. `[CODE]`
`[TEST: test_poll_orphan_fence.py::test_at_the_cap_it_waits_before_refusing]`

### Error reporting

```python
def pull_last_error(self) -> int                                     # [SIG]
```
Reads a **global, non-thread-local** DLL variable. Under concurrent multi-device use
the value may belong to another thread. **Diagnostics only — every correctness
decision must use the call's own `rc`.** `[COMMENT: the method's own docstring says
so; nothing enforces it]`

Returns the literal `-9999` when the DLL is not loaded. `[CODE]`

### Buffer growth

```python
def _call_with_growing_buffer(self, *, fn_name, call, sizes, debug_label) -> Tuple[int, str]
```
Retries the call with progressively larger buffers. A caller-supplied `initial_size` is
prepended and only larger ladder steps are kept. `[CODE]`

> **The ladder is NOT uniform — check the caller.** `[CODE]`
>
> | Caller | Ladder |
> |---|---|
> | `get_rtlog_text`, `get_rtlog_ext_text`, `get_device_param` | 64 KB → 128 KB → 256 KB → 512 KB → **1 MB** |
> | `get_device_data_text` (the **table read**) | 1 MB → 2 MB → 4 MB → **8 MB** |
>
> The table read starts where the others stop. Sizing a table read against the 64 KB
> ladder would be wrong by two orders of magnitude.

Retries **only** on `rc in (-3, -112, -114, -115)`; any other negative rc raises
`PullSDKError` immediately, and exhausting the ladder also raises. `[CODE]`
(-3 = buffer insufficient, -112 = recv buffer insufficient documented; -114/-115 are
noted as observed in the wild `[COMMENT]`.)

### Tables

```python
def get_device_data_text(...)                                        # [SIG in source]
def get_device_data_rows(...)                                        # [SIG in source]
def get_device_data_count(self, *, table, filter_expr="", options="") -> int
def set_device_data(self, *, table, data, options="") -> int
def clear_device_table(self, *, table: str) -> int
def delete_device_data(self, *, table, data, options="") -> int
```

`clear_device_table` deletes **every row** by calling `DeleteDeviceData(handle, table,
"", "")` — an empty data string. `[CODE]` It has two callers. An explicit `FULL_REPLACE` policy,
only when the panel's rows fit under the shared removal ceiling (`guide_for_agents_and_dev.md`
§3.2g); the INCREMENTAL "nuke-and-repave" heuristic that used it automatically is gone (P3a-2). And,
since lane 1 (2026-09-27), the Erase-content wizard, through `PullSDKDevice.erase_table`, on the
tables an operator chose among `user`, `userauthorize`, `templatev10` and `template` — never a
parameter, timezone, holiday or `transaction` table — after a verified backup (main guide §3.2h).
`[CODE: app/core/erase_wizard.py::C3_ERASE_ORDER]` Be certain before calling it.

#### ⛔ `set_device_data` redacts `Template=` before logging

**Added 2026-09-11.** `data` for `table="template"` / `"templatev10"` carries a full
base64 **fingerprint template**. It used to be written to `app.log` verbatim at INFO
— a 512-byte template rendered a 771-character line containing the whole biometric.

`app.log` is **not local**. Three sinks consume that line:

- the rotated log file on the gym PC,
- `log_uploader.py`, which ships finalized logs **off-site** (Cloudinary
  `POST_MULTIPART` / R2),
- `log_buffer.py`'s ring, which the dashboard's live-log view reads.

So every roster sync exported one biometric per finger to a third-party CDN. `[CODE]`

Both emit sites now route through `_redact_template_field`, which rewrites only the
`Template=` value as `Template=<redacted:len=N:sha1=XXXXXXXX>`:

- `set_device_data`'s INFO log. `[CODE]`
- `set_device_data_batch`'s row-by-row fallback warning — which **redacts before
  slicing**. The old `row[:80]` sliced first, and since `Template=` begins around
  offset 33 of a typical row, it published ~31 characters of the template. That was a
  second, independent leak. `[CODE]`

**The wire is unchanged.** `encode_ansi(data)` still hands the real, unredacted string
to `plcommpro.dll`; this is a log-only transform. `[TEST]`

**Everything else is logged byte-for-byte** — `Pin`, `FingerID`, `Valid`, `Size`, the
table name, the rc code, and every non-template table (`user`, `userauthorize`). The
structural-error diagnosis above (`rc=-100`/`-101`/`-102`/`-103`) still sees exactly
what was sent. A logging-handler filter was rejected because it would have had to
re-enumerate all three sinks; fixing the two emit sites closes them at once. `[CODE]`

> **Deliberate diagnostic loss.** Raw template base64 can no longer be eyeballed in
> the log for corruption (bad padding, truncation, embedded control characters). The
> `len` + `sha1[:8]` tag replaces it, and matches the shape the enrol path already
> emits (`ENROLL_BACKEND_REQ`), so the same template can be correlated across enrol
> and push lines. `[CODE]`

`[TEST: tests/test_pullsdk_setdevicedata_template_redaction.py — 6 cases; asserts the
template reaches the DLL but never the log, that non-template tables are untouched,
and that the batch fallback leaks no fragment.]`

#### ⛔ `Template=` is BASE64 ASCII — a HEX-stored row must be converted

**Added 2026-09-11.** The backend stores each fingerprint's `TemplateEncoding`
per row (`BASE64` or `HEX`) and used to deliver a HEX row as **hex text**. The
Access client dropped the encoding entirely — `_collect_templates_for_pin` emitted
only `{fingerId, templateVersion, templateData, templateSize}` — and copied that
text straight onto the device wire, which accepts nothing but base64.

The terminal then holds a template it can never match: **the member is refused at
the door while Access reports the push as done.** `[CODE]`

HEX is reachable in production through the GMS legacy migration
(`CsvLegacySourceAdapter` accepts HEX, `GmsMigrationService` persists
`TemplateEncoding.HEX`) — i.e. exactly the migrated gyms.

Fixed on both sides, and the two halves are independent:

- **Client** — `device_sync._template_wire(text, encoding)` converts HEX to base64
  and returns the decoded byte count (so `Size=` is the byte count, not the text
  length). Anything that is not HEX passes through untouched. `[CODE]`
- **Backend** — the two Access-facing emitters
  (`UserFingerprintController.toFingerprintDto`,
  `AccessPatchBundleService.toFingerprintDto`) now always emit BASE64 and report
  `templateEncoding="BASE64"`, describing the WIRE rather than the stored row.
  `toFull` still reports the STORED encoding: the dashboard round-trips
  `templateData` back through `update()`. `[CODE]`

**Deployment order is free and double conversion is impossible:** once the backend
sends `BASE64`, `_template_wire` passes the data through. The client half is *not*
redundant — the backend delta keys on `updatedAt`, and changing an encoder bumps no
timestamp, so an already-delivered HEX row is never re-sent. The client conversion
is what repairs an existing poisoned cache.

The decode is deliberately as tolerant as the backend's own (`0x` prefix and
embedded whitespace accepted); an undecodable HEX template is **dropped with a
warning** rather than pushed, so a finger slot is never occupied by something
unmatchable.

> **Known gap.** A dropped template is logged but is **not** attributed to the pin
> as a failed sync — `_collect_templates_for_pin` has no access to `pin_outcomes`.
> Grep `template DROPPED` to find them. `[UNVERIFIED: never observed in the field;
> it needs a HEX row whose text is corrupt, which the backend's own decoder would
> also have rejected.]`

`[TEST: tests/test_template_wire_encoding.py]`

#### Driver leases (P3b-2)

`DeviceSyncEngine` never opens a session on a panel another PC drives (`_sync_one_device`,
`_run_single_device_sync`, the DEVICE-mode device list), writes nothing to one being handed over, and the
stale step / targeted delete defer on an add-only panel — `guide_for_agents_and_dev.md` §3.9. The local
API's low-level `PullSDK` handlers are wrapped by the same lease gate (409 `notDriver`). `[CODE]`

#### The user-table read-back (P3a-2)

Besides the per-sync `Pin` read, the write-ahead intent (`guide_for_agents_and_dev.md` §3.4a) reads
`fields="Pin\tCardNo"` — the whole table once, only when an intent of a departed member is on the
panel, or `filter_expr="Pin=N"` for one pin on a targeted revoke — to prove a push MonClub never got
to confirm. `[UNVERIFIED]` on a C3-400: that `CardNo` is returned for this read and in what form
(the comparison ignores leading zeros), and that the `Pin=N` filter is honoured. FIELD-TEST before
relying on it. A failed read changes nothing and, on a targeted revoke, is a retry
(`OWNERSHIP_UNREADABLE`), never the final `SKIPPED_NOT_OWNED`; an empty answer — to the one-pin read,
or a whole-table read with no rows — drops no intent (review round 1, R1-12/R1-30).

### Batched writes

```python
def set_device_data_batch(...)      # chunked, with row-by-row fallback
def delete_device_data_batch(...)   # returns (ok_count, failed_pins)
```

On a chunk failure `set_device_data_batch` falls back to row-by-row for that chunk. If
the **first** row of a chunk fails with a *structural* error — `rc=-100`, `-101`,
`-102`, `-103` — it short-circuits: the rest of the chunk and **all later chunks** are
marked failed without being attempted. `[CODE]` A progress callback fires after every
chunk, successful or fallback. `[CODE]`

**Door rights on the batch path (lane 1, 2026-09-27).** `_push_userauthorize` never raises: it answers
`(ok_count, error)`, `(0, error)` when no field pattern worked. Phase B's pattern discovery (the first pin) and
its per-pin fallback used to ignore that answer, so a pin whose `userauthorize` row the panel refused was
recorded in sync and never retried. Both now record it FAILED. Each pin's last push result (main guide §3.9) is
`true` on this path only when its user row and its door rights were explicitly confirmed. `[CODE]`
`[TEST: tests/test_v2_last_push.py::TestPullSdk]`

A full sync (`DeviceSyncEngine._sync_one_device`) deletes its stale pins through
`_bulk_delete_pins` BEFORE writing the user rows (Phase A) — except, since P3b-1, the old
MEMBERSHIP pin of a person whose new pin that pass still has to write: it is deleted after Phase D,
only once the new pin's row landed (`guide_for_agents_and_dev.md` §3.4f). `[CODE]`
`[TEST: tests/test_renewal_ordering.py::TestPullSdkRenewal]`

#### Structural vs transient, and why the firmware cache depends on it

**Added 2026-09-11.** Those four rc codes are now a shared constant,
`pullsdk.STRUCTURAL_ERROR_CODES`, because a SECOND decision depends on them: the
firmware-profile cache in `device_sync`.

`_push_templates` / `_push_userauthorize` learn a working (table, body) combination
over up to ten probe calls and cache it. When the cached combination later fails,
the driver used to clear that cache unconditionally -- `try_set` swallowed every
exception identically, so a network blip, a timeout or an auth error was
indistinguishable from "this firmware has no such table". A single blip therefore
discarded an expensively-learned profile and forced ten more SDK calls per finger,
on a device that had been answering correctly a moment earlier. `[CODE]`

`device_sync._is_structural_sdk_error` now splits the two:

- **structural** (`rc=-100`/`-101`/`-102`/`-103`) -- the firmware genuinely rejected
  the payload shape, so the cached combination is wrong. Clear it and re-probe.
- **anything else** -- keep the cache. The probe still runs, so the push is not
  abandoned; only the learned state survives.

> The default is deliberately "transient": keeping a stale cache costs one wasted
> call plus a fall-through to the probe, whereas clearing a good one costs every
> later push. An error that embeds no `rc=` at all is therefore treated as transient.

`[UNVERIFIED]` The rc-code set is observed firmware behaviour, not published ZKTeco
documentation. `set_device_data_batch`'s structural short-circuit already relied on
it; this change only gave it a name and a second consumer. If the set changes, both
consumers change together.

`[TEST: tests/test_firmware_profile_cache.py -- the clearing tests assert
`clear_firmware_profile` WAS called and the transient tests assert it was NOT.
Asserting the end-state profile cannot tell them apart: the probe re-saves a winner
either way.]`

Multi-row `DeleteDeviceData` is called the documented bulk pattern, citing *ZKTeco
PullSDK User Guide V2.0*. `[COMMENT — a documentation citation, not a device
measurement]`

### Door and device control

```python
def control_device(self, *, operation_id, param1, param2, param3, param4, options="") -> int
```
Raises `PullSDKError` on `rc < 0`. Verified operation IDs, from the three wrappers:
`[CODE]`

| Wrapper | Call |
|---|---|
| `door_pulse_open(*, door, seconds=3)` | `op=1, p1=door, p2=1, p3=seconds, p4=0` — `seconds` clamped to **1…60** |
| `cancel_alarm()` | `op=2, p1..p4=0` |
| `set_door_normal_open(*, door, enabled)` | `op=4, p1=door, p2=1｜0, p3=0, p4=0` |

### Device parameters

```python
def get_device_param(self, *, items, initial_size=None) -> str       # [SIG]
def set_device_param(self, *, items: str) -> int                     # [SIG]
```

`set_device_param` raises `PullSDKError` on empty `items`. It keeps a **per-instance**
`_applied_params` cache and, when *every* `K=V` pair in the request was already written
with the same value on this instance, **skips the DLL round-trip and returns `0`**
(rc ≥ 0 means success). An unparseable token with no `=` forces the write. `[CODE]`

Because `PullSDKDevice.connect()` builds a **new** `PullSDK` per connection, the cache
is connection-scoped in practice — a reconnect re-applies everything once.
`[COMMENT for the rationale]` `[TEST: test_pullsdk_param_cache.py::test_reconnect_resets_cache
— builds a real `PullSDK` and asserts the repeat write is skipped and a fresh instance
writes again]`

Why it exists: on the antivirus-slow gym PC each `SetDeviceParam` is a ~200 ms
round-trip and 5–10 of them blocked the live worker ~1.8 s per sync. `[COMMENT —
numbers, but no date or version at that site]`

---

## 6. `PullSDKDevice` — driver reference

### Lifecycle

```python
@property
def is_connected(self) -> bool          # flag AND inner object; no lock, no I/O  [CODE]
def ensure_connected(self) -> bool      # short-circuits, else connect(); NO lock  [CODE]
def connect(self) -> bool               # [SIG]
def disconnect(self) -> None            # [SIG]
```

`connect()` returns `False` on any `Exception` rather than raising — note it is a bare
`except Exception`, so `BaseException` (e.g. `KeyboardInterrupt`) still propagates.
`[CODE]` It first calls `self.disconnect()`, then rejects an empty ip or non-positive
port. On failure it calls `disconnect()` on the pending `PullSDK` to avoid a DLL handle
leak. `[CODE]`

**The process-wide `_GLOBAL_SDK_LOCK` is held only around `load()`** — the DLL load and
prototype registration. The TCP connect runs **outside** it, so devices connect in
parallel. `[CODE]` (`_GLOBAL_SDK_LOCK` is module-level and is *not* acquired anywhere
inside the `PullSDK` class, which uses its own `_load_lock`. `[CODE]`)

On success `connect()` clears `_door_drivetime_set`. `[CODE]` The *consequence* — that
the next `open_door` re-pushes the pulse time — is **conditional**, not guaranteed: the
re-push is gated on `supports_set_device_param()`, which is `False` when the loaded DLL
lacks the export. `[COMMENT for the unconditional phrasing]`

### Locking

`open_door`, `get_device_time`, `set_device_time`, `get_device_param`,
`set_device_param`, `get_table_count`, `read_table_rows`, `delete_table_rows` and
`poll_rtlog_once` all call `ensure_connected()` **while already holding** the
non-reentrant `_sdk_lock` (`threading.Lock`, not `RLock`). `[CODE]`

> This does not self-deadlock **only because** `ensure_connected` / `connect` /
> `disconnect` / `is_connected` never take that lock themselves. If you add a lock
> acquisition to any of those four, every one of the nine methods above deadlocks.

`PullSDKDevice.disconnect()` skipping `_sdk_lock` therefore is **not** an oversight to
be tidied up — the lock is held across blocked native calls, so taking it here would
wedge the poll watchdogs behind the exact call they exist to escape. The real hazard
that skipping it creates (freeing the session under an in-flight call) is handled one
layer down, in `PullSDK.disconnect()`'s deferred free — see §5 *Connection*. `[CODE]`

### Door

```python
def open_door(self, *, door_id: int, pulse_time_ms: int, timeout_ms: int = 4000) -> bool
```
`timeout_ms` is accepted and **unused** — the Pull SDK door pulse is synchronous; it is
kept for API symmetry with the standalone driver. `[CODE]`

`pulse_time_ms` is converted with `ceil(ms / 1000)` and clamped to 1…60 seconds. Before
pulsing, the driver writes `Door{door_id}Drivertime={seconds}` — but **only once per
connection or when the value changes**, because it is a ~225 ms round-trip and the
controller retains it. `[CODE]` It is skipped entirely when
`supports_set_device_param()` is `False`, and a failure there is logged at debug and
ignored. `[CODE]`

Rationale: many C3-200 firmware versions ignore `ControlDevice` param3 and use the
stored `DoorNDriveTime`. `[COMMENT]`

### Time

```python
def get_device_time(self) -> Optional[float]
def set_device_time(self, epoch: float) -> bool
```
The rule that callers must only correct toward a trusted clock (a wrong PC clock breaks
TOTP consistently) is stated in the docstring only — **nothing enforces a drift
threshold or an opt-in gate here**. `[COMMENT]` The gate lives in the ULTRA worker.

### Events

```python
def poll_rtlog_once(self) -> List[Dict[str, Any]]
```
Prefers `GetRTLogExt`. Rows whose `type` is not `rtlog` (e.g. `rtstate` door/alarm
state) are **skipped**. `[CODE]`

Emitted dict shape — the contract the ULTRA worker consumes, and the shape the
standalone driver deliberately mimics: `[CODE]`

| Key | Source |
|---|---|
| `eventId` | synthesised — the panel supplies no id: `time｜cardno｜event｜eventaddr｜pin｜inoutstatus｜verifytype｜seq:idx` |
| `doorId` | `eventaddr` or `None` |
| `eventType` | `event` or the literal `"RTLOG"` |
| `cardNo` | `cardno`, falling back to **`pin`** when empty (PIN-only / fingerprint events) |
| `eventTime`, `table`, `rawRow` | as read |

PullSDK rows carry **no** `scan_mode_hint` key — that is standalone-only, and its
absence is what keeps C2-400/C3-200 output unchanged. `[CODE]`

### Strict table calls (the Erase-content wizard, lane 1, 2026-09-27)

```python
def count_table_strict(self, *, table: str) -> int                              # [SIG]
def read_table_strict(self, *, table: str, fields: str = "*") -> List[Dict[str, str]]
def erase_table(self, *, table: str) -> int
```

`get_table_count`, `read_table_rows` and `delete_table_rows` swallow every failure (`-1`, `[]`,
`-1`), so a failed read looks like an empty table. These three raise instead: a negative count
(`PullSDKError`), any exception of `get_device_data_rows` (the 1-8 MB ladder included), a negative rc
of `clear_device_table`. Each takes `_sdk_lock` and calls `ensure_connected()` like its neighbours.
Only the wizard calls them, through the ULTRA worker's own connection (`request_run_sdk`). `[CODE]`
`[TEST: tests/test_device_hold.py::test_the_strict_panel_calls_raise_instead_of_reading_empty]`
Never run against a C3-400 `[UNVERIFIED]`: whether `DeleteDeviceData(h, "user", "", "")` also empties
`userauthorize` on that firmware is not known; the wizard erases each chosen table itself and counts
each one after.

### Transactions

```python
supports_transaction_table = True                                    # [CODE]
def read_transaction_rows(self, *, options="new record", initial_size=None)
def delete_all_transaction_rows(self) -> int
```
Real operations here, unlike the standalone driver where they are inert.

---

## 7. Known firmware behaviour (PullSDK panels)

| Behaviour | Grade |
|---|---|
| **C3-200 RTC drift.** 2026-06-24: two production turnstiles measured **38–74 s behind** the PC. Breaks scan-time TOTP and causes ~50 % `DENY_NO_MATCH`. Auto-correction defaults **ON**. | `[FIELD]` |
| **`plcommpro.dll` handle leak.** ~1 OS handle + ~280 KB **per `Connect`/`Disconnect` cycle**; handle count tracks connect count at ~1.0 per connect and private bytes climb ~175 MB/h. ~680 reconnects/hour exhausted the 32-bit address space in ~a day. Fixed by holding a persistent connection. | `[COMMENT: "measured in prod" with numbers, but no date or version at that site]` |
| **Idle sockets dropped unpredictably** by C2-400 / C3-200 firmware, hence the proactive hot-window close. | `[COMMENT]` |
| **`ControlDevice` param3 ignored** by many C3-200 firmwares, which use the stored `DoorNDriveTime` instead. | `[COMMENT]` |
| **~225 ms** per `SetDeviceParam` round-trip on the C3-200 — about half the door-open latency. | `[COMMENT]` |

Note how few of these are `[FIELD]`. The numbers are real measurements someone took,
but without a date or version in the source they cannot be tied to a firmware, so they
are recorded at comment strength. **If you re-measure one, add the date and promote it.**

---

## 8. Fixed defects

**`PullSDK.connect(platform=...)` had no effect — FIXED 2026-08-29.** The parameter was
accepted, rendered into the log as though sent, and never added to the connection
string. Introduced by `0548a1d`, which removed the `parts.append(f"platform=…")` line
but left the signature and the log fragment.

Resolved by **removing** the parameter, not re-wiring it: the DLL has no such key
(§4.1). The pass-through in `PullSDKDevice.connect()` and the `self.platform` attribute
went with it. Wire-level no-op — the value was always empty in practice, and it was
never in the connection string anyway.
`[TEST: test_pullsdk_connect_string.py]`

The generalised invariant is now pinned: **the connect log's key set must equal the
connection string's key set.** Verified to fire against the pre-fix code.
`[TEST: ::TestLogMatchesTheWire::test_logged_keys_are_exactly_the_sent_keys]`

> If you add a connection option, add it to `parts` **and** the log, and that test will
> tell you if you did only one.

---

## 9. Universals that were checked and found FALSE

Recorded so nobody re-derives them. Each of these reads as an obvious invariant and is
not one. `[CODE — each has a named counterexample]`

- ❌ "Every method calls `load()`." — `disconnect()` and `pull_last_error()` do not.
- ❌ "Every device-touching method goes through `_require_handle()`." — `disconnect()`
  passes `c_void_p(self._h)` directly; `connect()` assigns `_h` with no check.
- ❌ "Every DLL-calling method treats `rc < 0` as failure and raises." — `disconnect()`
  discards its rc entirely; `pull_last_error()` returns the DLL value unchecked.
- ❌ "`set_device_param` is the only failure message that echoes its argument." —
  `GetDeviceData`, `SetDeviceData`, `ClearDeviceTable` and `DeleteDeviceData` all echo
  `table=`.

---

## 10. Test coverage

What is actually pinned, and what is not.

**Covered.** `[TEST]`
- The connection string's exact contents, the absence of a `platform` key, and the
  log-equals-wire invariant, against a **real** `PullSDK` driving a fake DLL —
  `tests/test_pullsdk_connect_string.py`
- `set_device_param` skip-if-unchanged and reset-on-reconnect, against a **real**
  `PullSDK` instance — `tests/test_pullsdk_param_cache.py`
- Driver factory / protocol resolution, all standalone aliases, and that a `PullSDKDevice`
  is returned for PullSDK payloads — `tests/test_device_driver_factory.py`
- `supports_transaction_table is True` and protocol-guard behaviour —
  `tests/test_device_sync_protocol_guard.py`
- Batch push and the `fingerprintEnabled=false` gate — `tests/test_batch_device_push.py`
- The 2-door fallback `[1, 2]` — `tests/test_device_control_settings.py`
- The read-only panel export `tools/c3_panel_scripts/export_c3_panel_readonly.ps1` (32-bit
  PowerShell, its own P/Invoke of six read entry points, the table-read ladder and connection string
  of §4-§5) — `tests/test_c3_panel_export_readonly.py`: static checks of both files, and the export script run
  with the helper REPLACED by a fake panel (including its refusal while `MonClubAccess` runs on the PC,
  and a negative `GetDeviceDataCount` recorded as an error and a `null` count), so the helper's DLL calls, buffer ladder and 32-bit
  relaunch are checked only statically and by reading them against §4-§5. A smoke run of the real
  helper on the development PC (the pack's `plcommpro.dll`, `Connect` to 127.0.0.1:1 where no device
  listens) returned handle 0 and `PullLastError=-307` after 2.3 s with `timeout=2000`
  `[TEST: 2026-09-26, not committed]`. It has never read a real panel.

**NOT covered — hardware-gated.** `[UNVERIFIED]`
> **No test calls `open_door`, `poll_rtlog_once`, `get_device_time` or `set_device_time`
> on a real `PullSDKDevice` instance.**
>
> Enumerated, not assumed. Nine test files mention those method names —
> `test_anti_fraud_daily_limit_integration`, `test_decision_service_anti_fraud`,
> `test_device_actor_mailbox`, `test_device_actor_runtime`, `test_device_control_settings`,
> `test_device_sync_protocol_guard`, `test_launch_safety_regressions`,
> `test_ultra_engine`, `test_zk_standalone_driver` — and in every case the receiver is
> an ULTRA worker, an actor adapter, a fake/`MagicMock` SDK, or the **standalone**
> driver. A real `PullSDKDevice` is constructed in only two files, and neither calls
> these four: `test_device_driver_factory` (`isinstance` checks via `get_driver`) and
> `test_device_sync_protocol_guard` (class-attribute checks).
>
> Re-check with:
> ```bash
> grep -rln "open_door\|poll_rtlog_once\|get_device_time\|set_device_time" tests/*.py
> grep -rn "PullSDKDevice" tests/*.py
> ```
>
> So their runtime behaviour against firmware is **unproven by the suite**. It is proven
> only by the C2-400 and C3-200 gyms running in production.

---

## 11. Verifying this guide

```bash
python -m pytest tests/ -q --ignore=tests/_pydeps
```
`--ignore=tests/_pydeps` is **required** (vendored packages break collection; there is
no `pytest.ini`). Last run: **1071 passed**, 2026-09-04 — suite count only; this
file's own claims were last swept 2026-08-29.

```bash
python tools/check_sql_arity.py
```

```bash
python -m pytest tests/test_pullsdk_connect_string.py tests/test_pullsdk_param_cache.py tests/test_device_driver_factory.py tests/test_device_sync_protocol_guard.py -q
```

Re-derive §4.1's key table straight from the shipped DLL — this is the check that
settles any future "does PullSDK accept option X?" question without guessing:

```bash
python -c "import re,io; d=io.open('app/sdk/plcommpro.dll','rb').read(); i=d.find(b'ipaddress'); print([t.decode() for t in re.findall(rb'[\x20-\x7e]{3,}', d[i-40:i+60])]); print('platform present:', b'platform' in d.lower())"
```

Expected: the key list `ipaddress port deviceid baudrate passwd protocol`, and
`platform present: False`.

Confirm the class split of §3 still holds — both must still exist, and the low-level
class must still be constructed directly by the two callers named:

```bash
grep -n "^class PullSDK\|^class PullSDKDevice" app/sdk/pullsdk.py
```

```bash
grep -rn "PullSDK(" app/ --include=*.py
```
