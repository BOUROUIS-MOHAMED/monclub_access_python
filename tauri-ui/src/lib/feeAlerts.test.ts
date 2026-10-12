import assert from "node:assert/strict";
import test from "node:test";

import {
  dayNumber,
  feeDueSoonDays,
  feeLines,
  feeLinesView,
  feeStatus,
  localDayNumber,
  parseFees,
  type PopupFee,
} from "./feeAlerts.ts";

// 2026-10-11 10:00 on the PC's own clock.
const TODAY = new Date(2026, 9, 11, 10, 0, 0);

function fee(over: Partial<PopupFee> = {}): PopupFee {
  return { name: "Casier", dueDate: "2026-10-20", required: false, paid: true, ...over };
}

test("a fee never paid is unpaid, whatever its due date", () => {
  assert.equal(feeStatus(fee({ paid: false, dueDate: "2026-12-31" }), TODAY, 7), "unpaid");
  assert.equal(feeStatus(fee({ paid: false, dueDate: null }), TODAY, 7), "unpaid");
});

test("a paid fee past its due date is unpaid (overdue)", () => {
  assert.equal(feeStatus(fee({ dueDate: "2026-10-10" }), TODAY, 7), "unpaid");
});

test("a paid fee is due soon from today to today + N, both included", () => {
  assert.equal(feeStatus(fee({ dueDate: "2026-10-11" }), TODAY, 7), "dueSoon");
  assert.equal(feeStatus(fee({ dueDate: "2026-10-18" }), TODAY, 7), "dueSoon");
  assert.equal(feeStatus(fee({ dueDate: "2026-10-19" }), TODAY, 7), null);
  assert.equal(feeStatus(fee({ dueDate: "2026-10-19" }), TODAY, 8), "dueSoon");
});

test("a paid fee with no due date needs no line", () => {
  assert.equal(feeStatus(fee({ dueDate: null }), TODAY, 7), null);
});

test("today is the PC's local day, late in the evening and just after midnight", () => {
  const lateEvening = new Date(2026, 9, 11, 23, 59, 0);
  assert.equal(localDayNumber(lateEvening), dayNumber("2026-10-11"));
  assert.equal(feeStatus(fee({ dueDate: "2026-10-11" }), lateEvening, 7), "dueSoon");
  const justAfterMidnight = new Date(2026, 9, 12, 0, 1, 0);
  assert.equal(feeStatus(fee({ dueDate: "2026-10-11" }), justAfterMidnight, 7), "unpaid");
});

test("the French copy of the approved artboard", () => {
  const [unpaid] = feeLines([fee({ name: "Carte badge", paid: false })], TODAY, 7);
  assert.equal(unpaid.title, "Frais « Carte badge » impayé");
  assert.equal(unpaid.action, "Passez à l'accueil pour le régler.");
  const [soon] = feeLines([fee({ dueDate: "2026-10-14" })], TODAY, 7);
  assert.equal(soon.title, "Frais « Casier » : expire dans 3 jours");
  assert.equal(soon.action, "Passez à l'accueil pour le renouveler.");
  assert.equal(soon.daysLeft, 3);
  assert.equal(feeLines([fee({ dueDate: "2026-10-12" })], TODAY, 7)[0].title, "Frais « Casier » : expire dans 1 jour");
  assert.equal(feeLines([fee({ dueDate: "2026-10-11" })], TODAY, 7)[0].title, "Frais « Casier » : expire aujourd'hui");
});

test("order: unpaid required, unpaid optional, then due soon, soonest first", () => {
  const lines = feeLines([
    fee({ name: "Soon late", dueDate: "2026-10-17" }),
    fee({ name: "Optional", paid: false, required: false, dueDate: "2026-10-01" }),
    fee({ name: "Soon early", dueDate: "2026-10-12" }),
    fee({ name: "Required", paid: false, required: true, dueDate: "2026-10-30" }),
  ], TODAY, 7);
  assert.deepEqual(lines.map((l) => l.name), ["Required", "Optional", "Soon early", "Soon late"]);
});

test("inside a group the older due date comes first (no date last), then the name", () => {
  const lines = feeLines([
    fee({ name: "B", paid: false, dueDate: null }),
    fee({ name: "C", paid: false, dueDate: "2026-09-01" }),
    fee({ name: "A", paid: false, dueDate: null }),
  ], TODAY, 7);
  assert.deepEqual(lines.map((l) => l.name), ["C", "A", "B"]);
});

test("at most two lines, then « +N autre(s) »", () => {
  const three = [fee({ name: "A", paid: false }), fee({ name: "B", paid: false }), fee({ name: "C", dueDate: "2026-10-12" })];
  const v = feeLinesView(three, TODAY, 7);
  assert.deepEqual(v.shown.map((l) => l.name), ["A", "B"]);
  assert.equal(v.more, 1);
  assert.equal(v.moreText, "+1 autre");
  const four = [...three, fee({ name: "D", dueDate: "2026-10-13" })];
  assert.equal(feeLinesView(four, TODAY, 7).moreText, "+2 autres");
  assert.equal(feeLinesView(three.slice(0, 2), TODAY, 7).moreText, null);
});

test("the tile mark is the most serious line", () => {
  assert.equal(feeLinesView([fee({ dueDate: "2026-10-12" }), fee({ name: "X", paid: false })], TODAY, 7).mark, "unpaid");
  assert.equal(feeLinesView([fee({ dueDate: "2026-10-12" })], TODAY, 7).mark, "dueSoon");
  assert.equal(feeLinesView([fee({ dueDate: "2026-11-30" })], TODAY, 7).mark, null);
  assert.equal(feeLinesView([], TODAY, 7).mark, null);
});

test("parseFees keeps clean items and drops junk", () => {
  assert.deepEqual(parseFees(undefined), []);
  assert.deepEqual(parseFees("[]"), []);
  assert.deepEqual(parseFees([
    null, 3, { name: "  " },
    { name: "Casier", dueDate: "2026-13-40", required: "true", paid: 1 },
    { name: " Badge ", dueDate: "2026-10-12T00:00:00", required: true, paid: true },
  ]), [
    { name: "Casier", dueDate: null, required: false, paid: false },
    { name: "Badge", dueDate: "2026-10-12", required: true, paid: true },
  ]);
});

test("feeDueSoonDays: 1-30, 7 when absent or unreadable", () => {
  assert.equal(feeDueSoonDays(undefined), 7);
  assert.equal(feeDueSoonDays(null), 7);
  assert.equal(feeDueSoonDays("abc"), 7);
  assert.equal(feeDueSoonDays(14), 14);
  assert.equal(feeDueSoonDays("10"), 10);
  assert.equal(feeDueSoonDays(0), 1);
  assert.equal(feeDueSoonDays(99), 30);
});
