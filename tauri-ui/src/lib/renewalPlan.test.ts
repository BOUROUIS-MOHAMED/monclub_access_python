import assert from "node:assert/strict";
import test from "node:test";
import { renewalPlanChoice } from "./renewalPlan.ts";

const plans = [{ id: 1, title: "Ancienne", price: "90", successor_plan_id: 2 },
  { id: "2", title: "Actuelle", price: "100" }, { id: 3, title: "Autre" }];

test("renewal starts on the synced successor and names both plans", () => {
  const result = renewalPlanChoice(plans, "1");
  assert.equal(result.plan, plans[1]);
  assert.equal(result.note, "Ancienne formule « Ancienne » rangée : renouvellement sur « Actuelle ».");
});

test("plans without a successor keep the member's current plan", () => {
  assert.deepEqual(renewalPlanChoice(plans, 2), { plan: plans[1], note: null });
  assert.deepEqual(renewalPlanChoice([{ id: 1, successor_plan_id: null }], 1),
    { plan: { id: 1, successor_plan_id: null }, note: null });
});

test("missing member plan or missing successor keeps the first-plan fallback", () => {
  assert.deepEqual(renewalPlanChoice(plans, 99), { plan: plans[0], note: null });
  const unavailable = [{ id: 3 }, { id: 1, successor_plan_id: 9 }];
  assert.deepEqual(renewalPlanChoice(unavailable, 1), { plan: unavailable[0], note: null });
  assert.deepEqual(renewalPlanChoice([], 1), { plan: undefined, note: null });
});
