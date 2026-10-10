import assert from "node:assert/strict";
import test from "node:test";

import {
  chipVariant,
  hexCode,
  lastCheckText,
  needsConfirm,
  switchDisabled,
  watchdogChip,
  watchdogTexts,
  type WatchdogStatus,
} from "./watchdogStatus.ts";

function status(over: Partial<WatchdogStatus> = {}): WatchdogStatus {
  return {
    taskName: "MonClub Access Watchdog",
    registered: true,
    enabled: true,
    state: "Ready",
    lastRunAt: "2026-10-10T08:00:00Z",
    lastResult: "ok",
    lastResultCode: 0,
    nextRunAt: "2026-10-10T08:02:00Z",
    intervalMinutes: 2,
    restartsLastHour: 0,
    stoodDown: false,
    stoodDownReason: null,
    scriptPath: "C:\\x\\watchdog\\monclub_access_watchdog.ps1",
    lastLogEntry: null,
    lastError: null,
    available: true,
    installRoot: "C:\\x",
    checkedAt: "2026-10-10T08:01:00Z",
    ...over,
  };
}

test("chip: on / off / not installed / error / stood down", () => {
  assert.equal(watchdogChip(status(), null), "on");
  assert.equal(watchdogChip(status({ enabled: false, state: "Disabled" }), null), "off");
  assert.equal(watchdogChip(status({ registered: false, enabled: false }), null), "notInstalled");
  assert.equal(watchdogChip(status({ registered: null, enabled: null, lastError: "timed out" }), null), "error");
  assert.equal(watchdogChip(status({ stoodDown: true, restartsLastHour: 5 }), null), "stoodDown");
  assert.equal(watchdogChip(status({ lastResult: "failed", lastResultCode: 267014 }), null), "error");
});

test("chip: an OFF watchdog is Off even after crashes (it is not restarting anything)", () => {
  assert.equal(watchdogChip(status({ enabled: false, stoodDown: true }), null), "off");
});

test("chip: nothing read yet", () => {
  assert.equal(watchdogChip(null, null), "loading");
  assert.equal(watchdogChip(null, "Failed to fetch"), "error");
});

test("chip colours", () => {
  assert.equal(chipVariant("on"), "success");
  assert.equal(chipVariant("stoodDown"), "warning");
  assert.equal(chipVariant("error"), "destructive");
});

test("only turning it off asks first", () => {
  assert.equal(needsConfirm(false), true);
  assert.equal(needsConfirm(true), false);
});

test("the switch is locked outside an installed build, while saving, and when the task cannot be read", () => {
  assert.equal(switchDisabled(status(), false), false);
  assert.equal(switchDisabled(status({ available: false }), false), true);
  assert.equal(switchDisabled(status(), true), true);
  assert.equal(switchDisabled(status({ registered: null }), false), true);
  assert.equal(switchDisabled(null, false), true);
  // A missing task can be turned on (the server registers it).
  assert.equal(switchDisabled(status({ registered: false, enabled: false }), false), false);
});

test("the confirm warning says what is lost, in both languages", () => {
  assert.equal(
    watchdogTexts("en").confirmBody,
    "Access will not restart by itself after a crash or an interrupted update.",
  );
  assert.match(watchdogTexts("fr").confirmBody, /plantage/);
  assert.match(watchdogTexts("fr").confirmBody, /mise à jour interrompue/);
});

test("both languages have every chip", () => {
  for (const lang of ["fr", "en"] as const) {
    for (const chip of ["loading", "on", "off", "notInstalled", "error", "stoodDown"] as const) {
      assert.ok(watchdogTexts(lang).chip[chip], `${lang} ${chip}`);
    }
  }
  assert.equal(watchdogTexts("en").chip.stoodDown, "Stood down after repeated crashes");
  assert.equal(watchdogTexts("en").chip.notInstalled, "Not installed");
});

test("last check: OK, the log line of that check, a failure code, never", () => {
  assert.match(lastCheckText(status(), "en"), /^Last check: .+ — OK$/);
  const logged = status({
    lastLogEntry: { at: "2026-10-10T08:00:01Z", rawAt: "x", level: "INFO", message: "restart issued", fromLastCheck: true },
  });
  assert.match(lastCheckText(logged, "en"), /— restart issued$/);
  const older = status({
    lastLogEntry: { at: "2026-10-09T08:00:01Z", rawAt: "x", level: "INFO", message: "restart issued", fromLastCheck: false },
  });
  assert.match(lastCheckText(older, "en"), /— OK$/);
  assert.match(lastCheckText(status({ lastResult: "failed", lastResultCode: 267014 }), "fr"), /échec \(code 0x41306\)$/);
  assert.equal(lastCheckText(status({ lastRunAt: null, lastResult: "not_run_yet" }), "en"), "Last check: never");
  assert.equal(lastCheckText(status({ lastRunAt: null }), "fr"), "Dernière vérification : jamais");
});

test("result codes are shown as Task Scheduler writes them", () => {
  assert.equal(hexCode(267011), "0x41303");
  assert.equal(hexCode(2147942402), "0x80070002");
  assert.equal(hexCode(null), "?");
});
