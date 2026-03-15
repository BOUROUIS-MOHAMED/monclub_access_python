# MonClub Access - Project Description

**Last Updated:** 2026-03-15

---

## 1. Project Overview

**MonClub Access** is a comprehensive Windows desktop application for managing gym/facility access control systems. It integrates with ZKTeco hardware devices (access controllers, fingerprint readers) and provides a modern UI for managing users, enrolling fingerprints, tracking access events, and syncing data with the MonClub backend.

### Key Characteristics:
- **Platform:** Windows (32-bit or 64-bit Python depending on DLL architecture)
- **Architecture:** Headless Python core + Tauri + React UI
- **Primary Use:** Gym/facility access control management
- **Hardware:** ZKTeco controllers (C3/C4/inBio family) + ZK9500 fingerprint scanner
- **Deployment:** Desktop application with automatic updates

---

## 2. Technology Stack

### Backend (Python Core)
- **Language:** Python 3.10+ (32-bit or 64-bit)
- **Web Framework:** Flask/HTTP server (localhost API)
- **Database:** SQLite (local caching)
- **Key Libraries:**
  - `pystray` - System tray integration
  - `pillow` - Image processing
  - `winotify` - Windows notifications
  - Standard library: `tkinter`, `ctypes`, `sqlite3`, `logging`

### Hardware Integration
- **PullSDK** - ZKTeco controller communication (plcommpro.dll)
- **ZKFinger SDK** - Fingerprint enrollment (ZKFPCap.dll, libzkfp.dll)
- **Biometric templates** - Local storage and synchronization

### Frontend (UI)
- **Framework:** Tauri 2.x + React 19
- **Styling:** Tailwind CSS 4.x
- **Component Library:** Material-UI (MUI) 6.x + Radix UI
- **State Management:** React Context API
- **Build Tool:** Vite 6.x
- **TypeScript:** 5.7+
- **Router:** React Router 7.x

### DevOps & Distribution
- **Installer:** Inno Setup (.iss scripts)
- **Updater:** .NET 8.0 (C#) standalone updater
- **Release Management:** GitHub releases
- **Version Control:** Git

---

## 3. Project Structure

```
monclub_access_python/
├── app/                           # Python backend core
│   ├── sdk/                       # Hardware SDKs (DLLs + Python wrappers)
│   │   ├── plcommpro.dll          # ZKTeco PullSDK (controller communication)
│   │   ├── ZKFPCap.dll            # ZK9500 fingerprint scanner
│   │   ├── libzkfp.dll            # Fingerprint library
│   │   ├── libzkfpcsharp.dll      # C# wrapper
│   │   ├── pullsdk.py             # Python PullSDK wrapper
│   │   └── zkfinger.py            # Python ZKFinger wrapper
│   │
│   ├── api/                       # HTTP API implementation
│   │   ├── local_access_api.py    # Main localhost API server (v1)
│   │   ├── local_access_api_v2.py # Alternative/updated implementation
│   │   └── monclub_api.py         # MonClub backend API client
│   │
│   ├── core/                      # Core business logic
│   │   ├── runtime.py             # Application runtime & lifecycle
│   │   ├── config.py              # Configuration management
│   │   ├── db.py                  # SQLite database schema & helpers
│   │   ├── logger.py              # Logging setup
│   │   ├── log_buffer.py          # In-memory log buffering
│   │   ├── secure_store.py        # Secure credential storage
│   │   ├── settings_reader.py     # Backend settings sync
│   │   │
│   │   ├── device_sync.py         # Device sync engine (DEVICE mode)
│   │   ├── realtime_agent.py      # Realtime event agent (AGENT mode)
│   │   │
│   │   ├── tv_local_cache.py      # Primary cache layer
│   │   ├── tv_local_cache_*.py    # Cache recovery/versioning
│   │   │
│   │   ├── update_manager.py      # Update checking/installation
│   │   ├── arch.py                # Platform architecture detection
│   │   └── utils.py               # Utility functions
│   │
│   └── ui/                        # Legacy Tkinter UI (being replaced)
│       └── ... (older UI code)
│
├── tauri-ui/                      # Modern Tauri + React UI
│   ├── src/
│   │   ├── api/
│   │   │   ├── client.ts          # HTTP client for localhost API
│   │   │   ├── hooks.ts           # React hooks for data fetching
│   │   │   ├── types.ts           # TypeScript API response types
│   │   │   └── tv.ts              # Cache client
│   │   │
│   │   ├── components/            # Reusable React components
│   │   │   ├── DeviceCard.tsx
│   │   │   ├── LogViewer.tsx
│   │   │   ├── StatusChip.tsx
│   │   │   ├── SyncButton.tsx
│   │   │   ├── theme-provider.tsx
│   │   │   └── ...
│   │   │
│   │   ├── context/
│   │   │   └── AppContext.tsx     # Global app state (auth, status)
│   │   │
│   │   ├── hooks/
│   │   │   └── useTrayIntegration.ts
│   │   │
│   │   ├── layouts/
│   │   │   └── MainLayout.tsx
│   │   │
│   │   ├── pages/                 # Route pages
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Devices.tsx
│   │   │   ├── Enrollment.tsx
│   │   │   └── ...
│   │   │
│   │   ├── App.tsx                # Main app component
│   │   └── index.css              # Global styles
│   │
│   ├── src-tauri/                 # Tauri backend (Rust)
│   │   ├── Cargo.toml
│   │   └── src/main.rs            # App window & lifecycle
│   │
│   ├── package.json               # NPM dependencies
│   └── tauri.conf.json            # Tauri configuration
│
├── installer/                     # Inno Setup installer config
│   ├── assets/
│   │   └── monclub_logo.png
│   └── *.iss                      # Installer scripts
│
├── updater/                       # .NET 8.0 updater executable
│   └── MonClubAccessUpdater/
│       └── bin/Release/net8.0/win-x64/
│           └── MonClubAccessUpdater.exe
│
├── build/                         # Build artifacts
├── dist/                          # Distribution packages
├── release/                       # Release builds
│
├── tests/                         # Test files
│   └── _test_integration.py
│
├── docs/                          # Documentation
│
├── README.md                      # Basic setup guide
├── TAURI_API_CONTRACT.md          # API specification (critical!)
├── MonClubAccess.spec             # PyInstaller spec
├── requirements.txt               # Python dependencies
├── run_app.bat                    # Launch script
├── build_release.ps1              # Release build script
├── build_installer.ps1            # Installer build script
├── generate_installer.ps1         # Installer generation
├── publish_github_release.ps1     # Release publishing
└── verify_release.ps1             # Release verification
```

---

## 4. Core Functionality

### 4.1 Hardware Integration

#### PullSDK (ZKTeco Controller Communication)
- **File:** `app/sdk/pullsdk.py`
- **DLL:** `plcommpro.dll` (32-bit or 64-bit)
- **Purpose:** Communicate with ZK access controllers (C3, C4, inBio family)
- **Operations:**
  - Connect to device (IP, port, password)
  - Fetch controller tables (user, userauthorize, timezone, holiday, transaction, templatev10)
  - Push user records with card numbers and fingerprint templates
  - Open doors (pulse relay)
  - Retrieve device information and parameters
  - Delete users from devices

#### ZKFinger SDK (Fingerprint Enrollment)
- **File:** `app/sdk/zkfinger.py`
- **DLL:** `ZKFPCap.dll`, `libzkfp.dll`
- **Purpose:** Enroll fingerprints from ZK9500 scanner
- **Operations:**
  - Connect to scanner device
  - Capture fingerprint images
  - Generate fingerprint templates (binary or text-encoded)
  - Store templates locally
  - Upload templates to controllers

### 4.2 Local Database (SQLite)

**Location:** `data/app.db`

**Main Tables:**
- `fingerprints` - Local enrolled templates with metadata
- `users` - Cached user data from MonClub backend
- `memberships` - Membership information
- `infrastructures` - Gym locations/infrastructure
- `access_history` - Local transaction log
- `device_sync_state` - Sync progress per device
- `door_presets` - Local door configuration presets
- `rtlog_state` - Realtime log state tracking

### 4.3 Configuration Management

**Location:** `data/config.json` (encrypted at rest via `secure_store.py`)

**Settings:**
- API credentials (email, token)
- Device IP/port/password
- Sync interval (default 300s)
- Timezone and locale
- Feature flags (agent enabled, realtime logging)
- Enrollment settings
- Logger level

### 4.4 Device Sync Engine (DEVICE Mode)

**File:** `app/core/device_sync.py`

**Purpose:** Periodically synchronize users and fingerprint templates to connected controllers.

**Workflow:**
1. Query MonClub backend for active members
2. Fetch current device user table
3. Compare and identify missing/outdated records
4. Push new users with card numbers and fingerprint templates
5. Log results and sync state

**Frequency:** Configurable (default 5 minutes)

### 4.5 Realtime Agent (AGENT Mode)

**File:** `app/core/realtime_agent.py`

**Purpose:** Monitor access events in real-time and apply business rules.

**Features:**
- Listen to transaction logs from connected devices
- Process access decisions (allow/deny/notify)
- Integrate with backend business rules
- Send notifications on access events
- Track event queue and decision latency
- Support multiple devices simultaneously

**Event Types:**
- `access-event` - User card/fingerprint scan
- `notification` - Alert or warning
- `status-change` - Device/agent state changes

### 4.6 Local API Server

**File:** `app/api/local_access_api.py` (or v2)

**Purpose:** Provide REST API for Tauri UI to control the headless Python core.

**Binding:** `127.0.0.1:8788` (configurable port)

**Authentication:** `X-Local-Auth` header token (generated at startup)

**Key Endpoints:**
- **Health & Status:** `/api/v1/access/health`, `/api/v1/access/status`
- **Auth:** `/api/v1/access/auth/login`, `/api/v1/access/auth/logout`
- **Config:** `/api/v1/access/config` (GET/PATCH)
- **Sync:** `/api/v1/access/sync/trigger`, `/api/v1/access/sync/status`
- **Cache:** `/api/v1/access/cache/*` (users, memberships, credentials, history)
- **Devices:** `/api/v1/access/devices`, `/api/v1/access/devices/{id}`
- **PullSDK:** `/api/v1/access/pullsdk/*` (connect, disconnect, fetch, door-open, push-user)
- **Device Sync:** `/api/v1/access/device-sync/run`, `/api/v1/access/device-sync/status`
- **Agent:** `/api/v1/access/agent/*` (start, stop, status, events)
- **Enrollment:** `/api/v1/access/enroll/start`, `/api/v1/access/enroll/events` (SSE)
- **Logs:** `/api/v1/access/logs`, `/api/v1/access/logs/events` (SSE)
- **Updates:** `/api/v1/access/updates/status`, `/api/v1/access/updates/check`

**Full Specification:** See `TAURI_API_CONTRACT.md`

### 4.7 MonClub Backend API Client

**File:** `app/api/monclub_api.py`

**Purpose:** Communicate with remote MonClub backend for:
- User authentication
- Fetching user/membership data
- Submitting fingerprints
- Syncing access history
- Retrieving device settings and rules

### 4.8 Update Manager

**File:** `app/core/update_manager.py`

**Purpose:** Check for and install application updates.

**Workflow:**
1. Periodically check GitHub releases
2. Compare local version with latest
3. Download installer if newer version available
4. Launch `.NET updater` executable
5. Updater installs and restarts app

**Updater Location:** `updater/MonClubAccessUpdater/bin/Release/net8.0/win-x64/`

### 4.9 Logging & Diagnostics

**File:** `app/core/logger.py`, `app/core/log_buffer.py`

**Location:** `data/logs/app.log` (rotating)

**Features:**
- Console and file logging
- In-memory buffer for API streaming
- Log level control (DEBUG, INFO, WARNING, ERROR)
- Rotation by size/date
- Diagnostic endpoints for troubleshooting

---

## 5. Modern UI (Tauri + React)

### 5.1 Architecture

The new UI is a **Tauri 2.x desktop app** with **React 19** frontend.

**Key Separation:**
- Python core runs **headless** (no Tkinter windows)
- Tauri/React UI is the **only user-facing interface**
- Communication via **localhost HTTP API** only
- Tauri's HTTP client (native) for secure request handling
- Optional SSE streaming for real-time events

### 5.2 Main Components

#### AppContext (Global State)
- **File:** `src/context/AppContext.tsx`
- **Manages:**
  - User authentication status
  - Core health/uptime
  - Active device
  - Sync/agent status
  - Notifications queue

#### Pages
- **Dashboard** - Overview of system status
- **Devices** - List and manage controllers
- **Users** - Search and manage users
- **Enrollment** - Fingerprint enrollment workflow
- **Logs** - Real-time log viewer
- **Settings** - Configuration UI
- **Diagnostics** - Health check tools

#### Key Hooks
- `useStatus()` - Fetch status from core
- `useDevices()` - List controllers
- `useUsers()` - Search users cache
- `useEnrollment()` - Manage enrollment jobs
- `useLogs()` - Stream logs via SSE
- `useTrayIntegration()` - System tray integration

#### Styling
- **Tailwind CSS** for utilities
- **Material-UI** for rich components
- **Radix UI** for accessible primitives
- Dark/light theme support (next-themes)

### 5.3 Build & Development

**Development:**
```bash
npm run dev       # Start dev server (Vite + Tauri dev)
npm run build     # Production build
npm run tauri     # Direct Tauri CLI access
```

**Output:** Signed `.exe` installer + portable executable

---

## 6. Data Flows

### 6.1 User Sync Flow (DEVICE Mode)

```
MonClub Backend
    ↓ (fetch users)
Local API `/api/v1/access/sync/trigger`
    ↓
Device Sync Engine (device_sync.py)
    ├─ Fetch active members from backend
    ├─ Query controller user table via PullSDK
    ├─ Compare → identify missing/outdated
    └─ Push users + templates to controller via PullSDK
    ↓
SQLite (cache state + push results)
    ↓
Tauri UI (poll `/sync/status` or SSE stream)
```

### 6.2 Fingerprint Enrollment Flow

```
Tauri UI → `/api/v1/access/enroll/start`
    ↓
Job created (LOCAL_SQLITE, BACKEND, or REMOTE type)
    ↓
ZKFinger Scanner (ZKFPCap.dll)
    ├─ Capture fingerprint
    ├─ Generate template
    └─ Return binary/text encoding
    ↓
Backend (if BACKEND type)
    └─ Call MonClub API `create_user_fingerprint`
    ↓
Local DB (if LOCAL_SQLITE type)
    └─ Store in `fingerprints` table
    ↓
Tauri UI (poll `/enroll/jobs/{id}` or SSE `/enroll/events`)
```

### 6.3 Realtime Access Event Flow (AGENT Mode)

```
ZK Controller
    ↓ (card/fingerprint scan)
Realtime Agent (realtime_agent.py)
    ├─ Poll transaction log
    ├─ Process event against rules
    └─ Emit decision (allow/deny/notify)
    ↓
Local API (SSE `/agent/events`)
    ↓
Tauri UI
    └─ Display notification + log
```

### 6.4 Local API to UI Communication

```
Tauri App (React)
    ↓ (HTTP request with X-Local-Auth header)
Local API Server (127.0.0.1:8788)
    ├─ Verify token
    ├─ Route request
    └─ Execute core logic
    ↓
Response (JSON)
    ↓
Tauri App (update state + UI)
```

---

## 7. Important Configuration Files

### `TAURI_API_CONTRACT.md`
**CRITICAL:** Defines the complete REST API contract between Python core and Tauri UI.
- All endpoints, request/response formats
- Security model (token auth, CORS)
- Error handling standards
- Optional/minimum-viable subsets

### `requirements.txt`
Python dependencies (minimal):
- `pystray` - System tray
- `pillow` - Image handling
- `winotify` - Windows notifications
- Mostly stdlib

### `tauri.conf.json`
Tauri desktop app configuration:
- Window properties
- Deep linking
- App version
- Updater settings
- Build output

### `theme_settings.json`
UI theme preferences (stored locally).

---

## 8. Build & Deployment

### 8.1 Development Setup

```bash
# Python backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Tauri UI
cd tauri-ui
npm install
npm run dev

# Launch both:
# Terminal 1: python run_app.bat
# Terminal 2: npm run dev (in tauri-ui)
```

### 8.2 Building Release

**Scripts Available:**
- `build_release.ps1` - Build Python + UI
- `build_installer.ps1` - Create Inno Setup installer
- `generate_installer.ps1` - Generate .iss scripts
- `publish_github_release.ps1` - Publish to GitHub
- `verify_release.ps1` - Verify release integrity

**Output:**
- `.exe` installer (Inno Setup)
- `.zip` portable build
- GitHub release artifacts

### 8.3 Update Distribution

**Mechanism:**
1. Build new version → commit to Git
2. Create GitHub release with .exe and .zip
3. App checks release page periodically
4. Downloads + launches `.NET updater`
5. Updater replaces files + restarts app

---

## 9. Key Design Decisions

### 9.1 Per-Device `accessDataMode`
Instead of global mode:
- Each device has `DEVICE` (PullSDK sync) or `AGENT` (realtime events) mode
- Stored in SQLite cache from backend
- UI filters features based on per-device mode
- Reduces coupling, supports mixed environments

### 9.2 Localhost-Only API
- Binds to `127.0.0.1`, never `0.0.0.0`
- No network exposure
- Local token auth (X-Local-Auth header)
- Browser CORS not needed (Tauri HTTP plugin is native)
- Simplifies security model

### 9.3 Headless Core
- Python core runs without UI windows
- Single responsibility: business logic + API
- Tauri UI is optional (UI can be swapped)
- Core continues running if UI crashes
- Easier testing and scripting

### 9.4 Modular SDK Wrappers
- `pullsdk.py` wraps `plcommpro.dll`
- `zkfinger.py` wraps ZK fingerprint DLLs
- Abstracts low-level ctypes/COM details
- Easier to mock/test
- Future replacement without core refactor

---

## 10. Important Constraints

### 10.1 DLL Bitness
- If `plcommpro.dll` is 32-bit → **must use 32-bit Python**
- If 64-bit → use 64-bit Python
- Mismatch = runtime crash
- Check with `arch.py` utility

### 10.2 Template Encoding
- Fingerprint templates from ZK9500 are **binary**
- Controller expects specific encoding (often base64-like text)
- **Must verify** by reading back an enrolled template first
- Different controllers may expect different formats

### 10.3 Single PullSDK Connection
- Only **one active connection** to controllers at a time
- Enforced server-side in API
- Connect to new device → auto-disconnect previous
- Simplifies state management

### 10.4 Sync Interval Tuning
- Default 5 minutes (300s)
- Balance between responsiveness and load
- Configurable per deployment
- Device sync requires device connectivity

---

## 11. Typical Workflows

### 11.1 Initial Setup
1. Install `.exe` on gym workstation
2. Launch app → Tauri window + Python core starts
3. Login with MonClub account credentials
4. Configure device IP, port, password
5. Trigger first sync
6. Enroll fingerprints from ZK9500
7. Verify users pushed to controller

### 11.2 Daily Operation
1. App monitors transactions via agent (if enabled)
2. Periodic device sync pushes new members
3. Fingerprint templates synced to devices
4. Access events logged in real-time
5. Logs viewable in UI + streamed via API

### 11.3 Enrollment Workflow
1. User opens "Enroll Fingerprint" in UI
2. UI calls `/api/v1/access/enroll/start` (type: LOCAL_SQLITE, BACKEND, or REMOTE)
3. Backend opens ZK9500 device
4. User places finger on scanner
5. Template captured → stored locally or uploaded
6. Result reported via SSE stream
7. UI shows success/failure

### 11.4 Update Flow
1. Core checks GitHub for new release
2. Newer version found → downloads .exe
3. User notified in UI
4. User clicks "Install" → launches updater
5. Updater closes core, replaces files, restarts
6. App resumes with new version

---

## 12. Testing & Diagnostics

### 12.1 Test Files
- `_test_integration.py` - Integration tests (database, API calls)
- `totp_file_test.py` - Test TOTP/2FA

### 12.2 Diagnostic Endpoints
- `GET /api/v1/access/diagnostics/platform` - OS/Python info
- `GET /api/v1/access/diagnostics/db-info` - Database status
- `POST /api/v1/access/diagnostics/check-pullsdk` - Check PullSDK DLL
- `POST /api/v1/access/diagnostics/check-zkfinger` - Check ZKFinger DLL

### 12.3 Log Analysis
- All logs written to `data/logs/app.log` (rotating)
- Real-time logs available via SSE at `/api/v1/access/logs/events`
- Buffered logs queryable at `GET /api/v1/access/logs?limit=1000&level=ALL`

---

## 13. Security Considerations

### 13.1 Credential Storage
- **Secure Store:** `app/core/secure_store.py`
- Encrypts sensitive data (passwords, tokens) at rest
- Uses Windows Data Protection API (DPAPI) for encryption
- Credentials cleared from memory after use

### 13.2 API Authentication
- **Local Token:** Generated at core startup, stored locally
- **Header:** `X-Local-Auth: <token>`
- **Scope:** All API endpoints except `/health` require token
- **SSE:** Optional query param `?token=<token>` for EventSource (browser)

### 13.3 CORS Policy
- **No `*` origin allowed** (strict security)
- Dev: `http://localhost:1420` (Tauri dev mode)
- Prod: `tauri://localhost` or no CORS needed (native plugin)
- Optional: Specific dashboard domain if browser access required

### 13.4 Certificate Pinning
- Tauri HTTP client is native (no browser CORS issues)
- API binds to localhost only (network isolation)
- Future: TLS for future network exposure (not in current scope)

---

## 14. Performance & Scaling

### 14.1 Local Cache Size
- SQLite database grows with sync history
- Typical gyms: 500-5000 users → ~10-100 MB DB
- Device transactions: Archived daily/weekly to backend
- Local retention: Configurable (default 30 days)

### 14.2 Sync Timing
- Device sync: 5-10 minute intervals (configurable)
- SSE streams: Low latency, event-driven
- Agent polling: Configurable (default 2-5 seconds per device)
- Total CPU impact: <5% on modern workstation

### 14.3 UI Responsiveness
- API responses typically <200ms (local operations)
- PullSDK operations: 500ms-5s depending on controller/network
- Enrollment: 10-30 seconds per fingerprint
- UI remains responsive (async API calls, loading indicators)

---

## 15. Known Limitations & Future Work

### 15.1 Current
- Single-device connection (PullSDK) at a time
- Manual device IP/port configuration
- Limited rule engine (backend-driven mostly)
- No multi-language UI (English only)

### 15.2 Future Enhancements
- [ ] Multi-device simultaneous PullSDK connections
- [ ] Advanced local rule builder
- [ ] RTSP camera integration
- [ ] Mobile companion app
- [ ] Database compression/archival
- [ ] Custom branding/theming
- [ ] Audit log with tamper detection

---

## 16. Dependencies Summary

### Python
```
pystray          - System tray menu
pillow           - Image processing (logo, etc.)
winotify         - Windows notifications
sqlite3          - Database (stdlib)
ctypes           - DLL interop (stdlib)
logging          - Logging framework (stdlib)
```

### Node.js / Frontend
```
React 19         - UI framework
Tauri 2.x        - Desktop wrapper
Tailwind CSS     - Utility styling
Material-UI      - Component library
Radix UI         - Accessible primitives
TypeScript       - Type safety
Vite             - Build tool
React Router     - Routing
```

### System (Windows)
```
plcommpro.dll    - ZKTeco PullSDK
ZKFPCap.dll      - ZK9500 scanner
libzkfp.dll      - Fingerprint lib
.NET 8.0         - Updater runtime
```

---

## 17. Quick Command Reference

### Python Core
```bash
# Activate virtual environment
.venv\Scripts\activate

# Run app (launches core + UI)
python run_app.bat

# Build executable (PyInstaller)
python -m PyInstaller MonClubAccess.spec

# Run tests
python -m pytest tests/
```

### Tauri UI
```bash
# Development
npm run dev           # Starts Vite dev server + Tauri in dev mode

# Production build
npm run build         # Builds optimized React + Tauri executable

# Direct Tauri commands
npm run tauri -- --help
```

### Build & Release
```bash
# Release build
.\build_release.ps1

# Create installer
.\build_installer.ps1

# Publish to GitHub
.\publish_github_release.ps1

# Verify release
.\verify_release.ps1
```

---

## 18. Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| DLL not found | 32/64-bit mismatch | Check `arch.py`, use matching Python |
| Cannot connect to device | IP/port/password wrong | Verify network connectivity, check config |
| Fingerprints not enrolling | ZKFinger DLL missing/old | Copy correct `ZKFPCap.dll` to `sdk/` |
| UI blank on startup | API not responding | Check `data/logs/app.log` for core errors |
| Updates fail | No GitHub access | Check network, firewall, release availability |
| Sync not progressing | Device offline | Verify device IP, reconnect, check logs |

---

## 19. References & Documentation

- **[TAURI_API_CONTRACT.md](./TAURI_API_CONTRACT.md)** - Complete API specification (CRITICAL READ)
- **[README.md](./README.md)** - Setup and basic usage
- **Python Docs:** [logging](https://docs.python.org/3/library/logging.html), [sqlite3](https://docs.python.org/3/library/sqlite3.html)
- **Tauri Docs:** [https://tauri.app](https://tauri.app)
- **React Docs:** [https://react.dev](https://react.dev)
- **ZKTeco PullSDK:** Vendor documentation (included in DLL comments)
- **ZKFinger SDK:** Vendor documentation (included in DLL comments)

---

## 20. Contact & Support

For issues, features, or contributions:
- **GitHub Issues:** [monclub-access-python issues](https://github.com/...)
- **Documentation:** See `/docs` directory
- **Logs:** Check `data/logs/app.log` for detailed error traces

---

**Last Updated:** 2026-03-15
**Project Status:** Active Development
**Version:** 0.1.0+
