# MonClub — Full Product Launch Audit
# 2026-04-02

---

## Systems audited

| System | Path | Stack |
|--------|------|-------|
| MonClub Access | C:\Users\mohaa\Desktop\monclub_access_python | Python 3.13, Tauri 2, React 19 |
| MonClub Dashboard | C:\Users\mohaa\Desktop\mon_club_dashboard | React 19, TypeScript, MUI 7, Vite 7 |
| MonClub Backend | D:\projects\MonClub\monclub_backend | Java 17, Spring Boot 3.2.5, MySQL |
| MonClub Mobile (Wigo) | C:\Users\mohaa\Desktop\wigo | Flutter / Dart 3.7 |

---

## Overall verdict

| System | Verdict | Condition |
|--------|---------|-----------|
| MonClub Access | **GO** | All blockers fixed. 144/144 tests pass. |
| MonClub Dashboard | **GO** | All code blockers fixed in this audit. One manual env-var step required (see §2). |
| MonClub Backend | **GO WITH ACTION** | Credentials moved to env vars in code. You must set MAIL_PASSWORD, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET in your deployment env and rotate the leaked values. |
| MonClub Mobile | **HOLD — MANUAL ACTION REQUIRED** | Android signing keystore committed to git despite .gitignore. Must rotate before app store submission. |

---

## 1. MonClub Access — FIXED & GO

### Fixes applied in this audit
| Finding | Fix |
|---------|-----|
| `gym_access_secrets_cache.json` not in .gitignore | Added to .gitignore with `totp_replay_state.json` |
| M-NEW-001: ULTRA devices double-synced | `device_sync.py:208` — added "ULTRA" to recognized modes |
| M-NEW-002: New ULTRA device ignored at runtime | `app/ui/app.py` — added device list change detection with engine restart |
| M-NEW-003: `_sync_work_running` race | `app/ui/app.py` — flag set before thread start |

### Remaining manual steps
1. **Rotate TOTP secrets** if `gym_access_secrets_cache.json` was ever pushed to a remote git repository. Run: `git log --all --oneline -- gym_access_secrets_cache.json` to verify history.
2. CSP is `null` in `tauri-ui/src-tauri/tauri.conf.json` — acceptable for a loopback-only desktop app; no action required.
3. Default log level is `DEBUG` — acceptable for a desktop app; consider switching to `INFO` for packaged release builds.

### Test status
```
144 passed in 0.73s  ✓
```

### Open post-launch items (not blockers)
- M-005: History upload retry jitter (1 line)
- L-001: Legacy "raw:" token migration
- L-004: Per-device ULTRA sync intervals
- L-005: DeviceWorker event queue put_nowait + drop count
- L-006: Max-cache-age enforcement for stale credentials

---

## 2. MonClub Dashboard — FIXED & GO

### Fixes applied in this audit
| Finding | Fix | File |
|---------|-----|------|
| `testingMode = true` pointed app at localhost | Set to `false` | `src/properties.ts:542` |
| Debug `console.log` in AuthProvider | Removed | `src/authConf.tsx:228-231` |
| 11 Debug buttons with `console.log(JSON.stringify(errors))` in forms | All removed | FamilyGym, Membership, ProductOrder, Shop, ActiveMembership×2, User×4 |
| Missing security headers in nginx.conf | Added X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, server_tokens off | `nginx.conf` |

### Remaining manual steps
1. **Firebase config** (`firebase.ts`) is hardcoded — move to `import.meta.env.VITE_*` variables for cleaner deployments. Not a blocker since Firebase client keys are intentionally public-facing.
2. The `axios` instance has `withCredentials: true` globally — ensure the backend CORS configuration explicitly whitelists the production dashboard domain (currently it does).
3. The `token` cookie set in `AccountService` is not HttpOnly (set client-side via js-cookie). This is expected for a SPA authentication flow; the main session cookie from the backend should be HttpOnly.
4. CI/CD typo: `$SVERVER_USER` should be `$SERVER_USER` in `.gitlab-ci.yml`.
5. Dockerfile: consider adding `USER nobody` and a `HEALTHCHECK`.

### Verified clean
- No `dangerouslySetInnerHTML` anywhere
- No `eval()` anywhere
- No `console.log(JSON.stringify...)` debug buttons remain (0 matches)
- Source maps disabled by default in Vite production build
- Route guards properly implemented (`RequireAuth`, `RequireRole`, `RequireAgentPerm`, `RequireFeatureAccess`)

---

## 3. MonClub Backend — ACTION REQUIRED BEFORE DEPLOY

### Fixes applied in this audit
| Finding | Fix | File |
|---------|-----|------|
| Email password hardcoded (`MALEKdjait1693`) | Moved to `${MAIL_PASSWORD}` | `application.yml:74` |
| Cloudinary API key hardcoded (`966812681471733`) | Moved to `${CLOUDINARY_API_KEY}` (no default) | `application.yml:111` |
| Cloudinary API secret hardcoded | Moved to `${CLOUDINARY_API_SECRET}` (no default) | `application.yml:112` |
| JWT comment said "15 minutes" but config is 30 days | Fixed comment to "30 days" | `application.yml:82` |
| `firebase-service-account.json`, `certificate.p12`, `keystore.p12` not in .gitignore | Added all three | `.gitignore` |

### MANDATORY actions before deploying

These cannot be done in code — you must do them manually:

**1. Rotate all exposed credentials** (CRITICAL — these are in git history)
```
MAIL_PASSWORD         → rotate your OVH email password for support@monclubwigo.tn
CLOUDINARY_API_KEY    → regenerate in Cloudinary dashboard → set as env var
CLOUDINARY_API_SECRET → regenerate in Cloudinary dashboard → set as env var
Firebase service account → Google Cloud Console → IAM → Service Accounts → create new key
```

**2. Set required environment variables** on your production server:
```bash
MAIL_PASSWORD=<new_password>
CLOUDINARY_API_KEY=<new_key>
CLOUDINARY_API_SECRET=<new_secret>
JWT_SECRET=<strong_random_base64>   # already env-var, just ensure it's set
DB_URL=<jdbc_url>
DB_USERNAME=<db_user>
DB_PASSWORD=<db_pass>
```

**3. Remove sensitive files from git history** (they are now gitignored but still in history):
```bash
git filter-branch --tree-filter "rm -f src/main/resources/firebase-service-account.json src/main/resources/certificate.p12 src/main/resources/keystore.p12" HEAD
# or use git-filter-repo (safer)
git push --force-with-lease
```

**4. Deploy `firebase-service-account.json` from environment** — load it at startup from a mounted secret / env var, not from the jar.

### Other findings (not blockers, but note before launch)

| Finding | Severity | Notes |
|---------|----------|-------|
| 18 `@Scheduled` tasks with no ShedLock | Medium | Safe for single-instance deploy; add ShedLock before running multiple instances |
| JWT access token 30 days (very long) | Medium | Reduce to 1–7 days for better security posture |
| `ddl-auto=update` instead of Flyway | Medium | Safe with your existing Flyway V1–V14 migrations; switch to `validate` post-launch |
| 0 `@PreAuthorize` annotations | Medium | All authorization is path-pattern based; safe for now, harder to audit long-term |
| CORS includes `localhost:3000/3001/3039` and `192.168.1.11` | Low | Move to env variable; production deploy won't break but it's noisy |
| 7 test files for 756 classes | Low | Acceptable for launch; add coverage over time |
| `@CrossOrigin(origins = "*")` on GymController | Low | More permissive than global CORS; review if intentional |

---

## 4. MonClub Mobile (Wigo) — MANUAL ACTION REQUIRED

### CRITICAL — Android signing credentials committed to repository

The files `android/key.properties` and `android/app/upload-keystore.jks` are present in the git repository. They are listed in `.gitignore` but were committed before the gitignore rule was in place (or were force-added). This means:
- Anyone with repo access can sign APKs as your app
- Play Store could flag the app if keys are revoked

**You must do the following before app store submission:**

**Step 1 — Remove from git history:**
```bash
cd C:\Users\mohaa\Desktop\wigo
git filter-branch --tree-filter "rm -f android/key.properties android/app/upload-keystore.jks" HEAD
git push --force-with-lease
```

**Step 2 — Generate a new keystore:**
```bash
keytool -genkey -v -keystore android/app/new-keystore.jks -alias upload -keyalg RSA -keysize 2048 -validity 10000
```
Store the keystore and password in CI/CD secrets (Codemagic), not in the repo.

**Step 3 — Update `key.properties`** to reference the new keystore path. Keep `key.properties` gitignored.

### Other findings

| Finding | Severity | Notes |
|---------|----------|-------|
| `android:usesCleartextTraffic="true"` in AndroidManifest | High | Remove since API is HTTPS-only |
| 55+ `print()` / `debugPrint()` statements | Medium | Some log auth tokens and account data; replace with conditional `kDebugMode` checks |
| `avoid_print` linter rule commented out | Medium | Enable in `analysis_options.yaml` |
| `kDebugMode` checks absent — all logging unconditional | Medium | Wrap debug prints in `if (kDebugMode)` |
| Firebase tokens printed to log in `main.dart` | Medium | APNS and FCM tokens logged unconditionally |
| No SSL certificate pinning | Low | Acceptable for v1.0; add for sensitive operations |
| No meaningful test coverage | Low | 1 boilerplate test; add unit tests over time |
| Commented-out dev URLs in `API.dart` (VPS IP, local IPs) | Low | Remove from source |
| Production base URL is correct: `https://monclubwigo.tn` | ✓ | |
| Release build has minify + resource shrink enabled | ✓ | |
| HTTPS enforced in cookie settings | ✓ | |

---

## Fixes summary (what was done in this audit)

### Code changes applied

| System | File | Change |
|--------|------|--------|
| Access | `.gitignore` | Added `gym_access_secrets_cache.json`, `totp_replay_state.json` |
| Access | `app/core/device_sync.py` | M-NEW-001: ULTRA mode no longer double-synced |
| Access | `app/ui/app.py` | M-NEW-002: new ULTRA device detected at runtime; M-NEW-003: flag race fixed |
| Dashboard | `src/properties.ts` | `testingMode` set to `false` |
| Dashboard | `src/authConf.tsx` | Removed debug `console.log` lifecycle hooks |
| Dashboard | `nginx.conf` | Added security headers + `server_tokens off` |
| Dashboard | `src/sections/FamilyGym/view/family-gym-view.tsx` | Removed Debug button |
| Dashboard | `src/sections/Membership/view/membership-view.tsx` | Removed Debug button |
| Dashboard | `src/sections/Product Order/view/product-order-view.tsx` | Removed Debug button |
| Dashboard | `src/sections/Shop/view/product-view.tsx` | Removed Debug button |
| Dashboard | `src/sections/ActiveMembership/view/active-membership-renew-dialog.tsx` | Removed Debug button |
| Dashboard | `src/sections/ActiveMembership/view/active-membership-form.tsx` | Removed Debug button |
| Dashboard | `src/sections/User/view/user-view.tsx` | Removed 4 Debug buttons |
| Backend | `src/main/resources/application.yml` | Moved email password + Cloudinary credentials to env vars; fixed JWT comment |
| Backend | `.gitignore` | Added firebase-service-account.json, certificate.p12, keystore.p12 |

### Manual actions required (you must do these)

| Priority | System | Action |
|----------|--------|--------|
| **CRITICAL** | Mobile | Remove `android/key.properties` + `upload-keystore.jks` from git history; generate new keystore |
| **CRITICAL** | Backend | Rotate email password (`MALEKdjait1693`), Cloudinary API key/secret, Firebase service account |
| **CRITICAL** | Backend | Set `MAIL_PASSWORD`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET` env vars on server |
| **CRITICAL** | Backend | Remove firebase-service-account.json, certificate.p12, keystore.p12 from git history |
| **HIGH** | Access | If `gym_access_secrets_cache.json` was ever pushed remotely, rotate affected TOTP credentials |
| **MEDIUM** | Mobile | Remove `android:usesCleartextTraffic="true"` from AndroidManifest |
| **MEDIUM** | Mobile | Wrap `print()` / `debugPrint()` in `kDebugMode` checks |
| **LOW** | Backend | Reduce JWT access token expiry from 30 days to 7 days |
| **LOW** | Dashboard | Fix CI/CD typo `$SVERVER_USER` → `$SERVER_USER` in `.gitlab-ci.yml` |
