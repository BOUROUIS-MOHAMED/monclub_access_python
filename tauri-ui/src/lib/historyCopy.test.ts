import assert from "node:assert/strict";
import test from "node:test";

import { relativeTimeFr } from "./historyCopy.ts";

const NOW = Date.parse("2026-10-16T18:42:30Z");

test("relative time in French minutes, hours and days", () => {
  assert.equal(relativeTimeFr("2026-10-16T18:42:00Z", NOW), "à l'instant");
  assert.equal(relativeTimeFr("2026-10-16T18:40:00Z", NOW), "il y a 2 min");
  assert.equal(relativeTimeFr("2026-10-16T18:40:00+00:00", NOW), "il y a 2 min");
  assert.equal(relativeTimeFr("2026-10-16T15:40:00Z", NOW), "il y a 3 h");
  assert.equal(relativeTimeFr("2026-10-13T18:40:00Z", NOW), "il y a 3 j");
});

test("missing, unreadable or future timestamps give null (the caller shows the clock time)", () => {
  assert.equal(relativeTimeFr(null, NOW), null);
  assert.equal(relativeTimeFr("", NOW), null);
  assert.equal(relativeTimeFr("pas une date", NOW), null);
  assert.equal(relativeTimeFr("2026-10-16T18:45:00Z", NOW), null);
});

test("a naive local now_iso() value is read as local time", () => {
  const now = new Date(2026, 9, 16, 18, 45, 10); // local wall clock
  assert.equal(relativeTimeFr("2026-10-16 18:40:00", now), "il y a 5 min");
});
