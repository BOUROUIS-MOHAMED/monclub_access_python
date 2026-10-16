import assert from "node:assert/strict";
import test from "node:test";

import { tokenWindow } from "./sessionWindow.ts";

const ISSUED = "2026-10-01T00:00:00+00:00";
const EXPIRES = "2026-10-31T00:00:00+00:00";
const at = (iso: string) => Date.parse(iso);

test("days left are floored and the bar is the share still ahead", () => {
  assert.deepEqual(tokenWindow(ISSUED, EXPIRES, at("2026-10-08T12:00:00Z")), { daysLeft: 22, pctLeft: 75 });
});

test("a fresh token is a full bar, an expired one is empty", () => {
  assert.deepEqual(tokenWindow(ISSUED, EXPIRES, at(ISSUED)), { daysLeft: 30, pctLeft: 100 });
  assert.deepEqual(tokenWindow(ISSUED, EXPIRES, at("2026-11-02T00:00:00Z")), { daysLeft: 0, pctLeft: 0 });
});

test("a PC clock before the issue time never shows more than a full bar", () => {
  assert.deepEqual(tokenWindow(ISSUED, EXPIRES, at("2026-09-25T00:00:00Z")), { daysLeft: 36, pctLeft: 100 });
});

test("a missing, unreadable or empty window is null", () => {
  assert.equal(tokenWindow(null, EXPIRES), null);
  assert.equal(tokenWindow(ISSUED, undefined), null);
  assert.equal(tokenWindow("soon", EXPIRES), null);
  assert.equal(tokenWindow(EXPIRES, ISSUED), null);
  assert.equal(tokenWindow(ISSUED, ISSUED), null);
});
