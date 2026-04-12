# Dashboard Feedback Design Spec
**Date**: 2026-04-12
**Status**: Approved for implementation

---

## Goal

Add playful success feedback for Access operators:
- play a sound when data is pushed successfully to a ZKTeco device
- play a different sound when a sync run completes successfully
- show a compact dashboard animation to the right of the `Hard Reset` button
- keep sound playback working while the main window is hidden to tray
- let any operator disable each sound and each animation from the normal settings page
- let any operator choose a custom sound per event or fall back to the bundled default
- let operators choose whether device-push feedback fires once per successful device or once per sync run

---

## Default Asset Names

Bundled defaults live in the Tauri public asset folders:

- `tauri-ui/public/sounds/device-push-success.mp3`
- `tauri-ui/public/sounds/sync-complete-success.mp3`
- `tauri-ui/public/animations/device-push-celebration.json`
- `tauri-ui/public/animations/sync-complete-confetti.json`

These paths work in development and in the packaged desktop build.

---

## Product Rules

### Success events

- `device_push_success`
  - emitted when one device push batch finishes with `status=SUCCESS`
  - payload includes `syncRunId`, `batchId`, `deviceId`, `deviceName`

- `sync_completed_success`
  - emitted when a sync run finishes with `status=SUCCESS`
  - payload includes `syncRunId`, `runType`, `triggerSource`

### Device-push repetition

Operator setting:
- `per_device`: celebrate every successful device push
- `per_run`: celebrate only the first successful device push seen for a sync run

### Failure handling

- missing default sound: fail silently
- missing animation JSON: render nothing, do not break layout
- unreadable custom sound: fall back to default when possible
- invalid custom upload: reject with a clear settings error

---

## Backend Design

### Config fields

Persist these Access config fields:

- `push_success_sound_enabled`
- `sync_success_sound_enabled`
- `push_success_animation_enabled`
- `sync_success_animation_enabled`
- `push_success_repeat_mode`
- `push_success_sound_source`
- `sync_success_sound_source`
- `push_success_custom_sound_path`
- `sync_success_custom_sound_path`

Normalization rules:
- repeat mode: `per_device` or `per_run`
- sound source: `default` or `custom`
- custom paths are stored as normalized strings or empty string

### Custom sound storage

Custom audio files are copied into the Access writable data area:

- `<access_data_dir>/feedback/device-push-success.<ext>`
- `<access_data_dir>/feedback/sync-complete-success.<ext>`

The config stores the copied path, not the original desktop source path.

### Local API routes

Add:

- `GET /api/v2/feedback/events`
- `GET /api/v2/feedback/sounds/device-push`
- `POST /api/v2/feedback/sounds/device-push`
- `DELETE /api/v2/feedback/sounds/device-push`
- `GET /api/v2/feedback/sounds/sync-complete`
- `POST /api/v2/feedback/sounds/sync-complete`
- `DELETE /api/v2/feedback/sounds/sync-complete`

Upload body uses JSON:

```json
{
  "fileName": "celebration.mp3",
  "contentBase64": "..."
}
```

### Feedback event stream

`MainApp` owns an in-memory feedback event buffer and sequence counter.

- device sync code emits `device_push_success`
- sync finalization emits `sync_completed_success`
- SSE subscribers receive new events by sequence
- idle subscribers receive `ping`

This avoids inferring success from general status polling and keeps the event source alive while the app is hidden to tray.

---

## Frontend Design

### Global runtime

Mount a global feedback orchestrator near the app root.

Responsibilities:
- open `/feedback/events` once
- play sounds with HTML5 `Audio`
- keep working while the app is hidden to tray
- expose the latest dashboard beacon event

### Dashboard animation

Render a compact success beacon in the dashboard action row, immediately to the right of `Hard Reset`.

Event personalities:
- device push: small badge-like celebration
- sync complete: slightly bigger confetti pulse

### Settings page

Add an always-visible `Feedback` card outside the locked advanced section.

Controls:
- toggle `Device push sound`
- toggle `Sync completed sound`
- toggle `Device push animation`
- toggle `Sync completed animation`
- select `Device push repetition`
- select sound source per event: `Default` or `Custom`
- choose custom sound file per event
- replace or reset custom sound per event
- show active file name per event

Because the current page only shows the main save button inside advanced settings, these feedback controls should patch config immediately when changed.

---

## Verification

Backend:
- config serialization covers new feedback fields
- feedback routes are registered
- feedback SSE emits queued events
- custom sound upload and reset work
- successful device push emits `device_push_success`
- successful sync emits `sync_completed_success`

Frontend:
- TypeScript build passes
- dashboard renders beacon without breaking the action row
- settings card can toggle, upload, replace, and reset sounds
- sound playback still works with the app hidden to tray
