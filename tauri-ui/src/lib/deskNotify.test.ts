import assert from "node:assert/strict";
import test from "node:test";
import { deskAccepts, deskActionPath, deskDuration, deskAdvance, deskDaysLeft, DESK_DEFAULTS, DeskTestInbox, deskScrollOffset } from "./deskNotify.ts";
import type { PopupEvent } from "../api/types.ts";

const now = new Date(2026, 10, 9, 10);
const event = (patch: Partial<PopupEvent> = {}) => ({ allowed: true, ...patch }) as PopupEvent;
test("modes distinguish ordinary entries, alerts, refusals, and orange re-entry", () => {
  const settings = { ...DESK_DEFAULTS, enabled: true };
  assert.equal(deskAccepts(event(), settings, now), false);
  assert.equal(deskAccepts(event({ allowed: false }), settings, now), true);
  assert.equal(deskAccepts(event({ reason: "DENY_ANTI_FRAUD_CARD", allowed: false }), { ...settings, mode: "REFUSALS_ONLY" }, now), false);
  for (const patch of [{ userBirthday: "1990-11-09" }, { userValidTo: "2026-11-16" }, { repeatCount: 3 },
    { fees: [{ name: "Assurance", dueDate: "2026-11-10", paid: true, required: false }] }]) {
    assert.equal(deskAccepts(event(patch), settings, now), true);
    assert.equal(deskAccepts(event(patch), { ...settings, mode: "REFUSALS_ONLY" }, now), false);
  }
  assert.equal(deskAccepts(event({ userValidTo: "2026-11-17" }), settings, now), false);
  assert.equal(deskAccepts(event({ deskTest: true }), settings, now), true);
  assert.equal(deskAccepts(event({ deskTest: true }), DESK_DEFAULTS, now), false);
  assert.equal(deskAccepts(event(), { ...settings, mode: "ALL" }, now), true);
});
test("expiry includes the seventh calendar day regardless of DST or clock time", () => {
  assert.equal(deskDaysLeft("2026-11-16", now), 7);
  assert.equal(deskDaysLeft("broken", now), null);
});
test("timers double refusals, stay indefinitely for zero, and pause without losing time", () => {
  assert.equal(deskDuration(event({ allowed: false }), 8), 16000);
  assert.equal(deskDuration(event(), 8), 8000);
  assert.equal(deskDuration(event({ allowed: false }), 0), 0);
  assert.equal(deskAdvance(1000, 500, true), 1000);
  assert.equal(deskAdvance(1000, 500, false), 500);
  assert.equal(deskAdvance(1000, 1500, false), 0);
});
test("actions use the existing membership id space and encode card numbers", () => {
  assert.equal(deskActionPath({ action: "open", activeMembershipId: 42 }), "/users?member=42");
  assert.equal(deskActionPath({ action: "renew", activeMembershipId: 42 }), "/users?member=42&action=renew");
  assert.equal(deskActionPath({ action: "payRest", activeMembershipId: 42 }), "/users?member=42&action=payRest");
  assert.equal(deskActionPath({ action: "assignCard", cardNo: "00123" }), "/users?assignCard=00123");
  assert.equal(deskActionPath({ action: "open" }), "/users");
});
test("a test received before the enable heartbeat is visible locally waits for fresh settings", () => {
  const inbox = new DeskTestInbox();
  assert.equal(deskAccepts(event({ deskTest: true }), DESK_DEFAULTS, now), false);
  const pending = event({ deskTest: true, eventId: "enable-and-test" });
  assert.equal(inbox.receive(pending), true);
  assert.equal(inbox.receive(pending), true); // duplicate delivery
  assert.equal(inbox.receive(event()), false);
  assert.deepEqual(inbox.drain({ ...DESK_DEFAULTS, enabled: true }), [pending]);
  assert.deepEqual(inbox.drain({ ...DESK_DEFAULTS, enabled: true }), []);
});
test("bottom stacks keep the newest tile in view on a short monitor", () => {
  assert.equal(deskScrollOffset(860, 660, "BOTTOM_RIGHT"), 200);
  assert.equal(deskScrollOffset(860, 660, "TOP_LEFT"), 0);
  assert.equal(deskScrollOffset(300, 660, "BOTTOM_CENTER"), 0);
});
