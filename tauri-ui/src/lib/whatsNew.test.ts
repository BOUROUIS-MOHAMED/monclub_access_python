import assert from "node:assert/strict";
import test from "node:test";

import { shouldShowWhatsNew } from "./whatsNew.ts";

const items = [
  { category: "acc" as const, fr: "Le portique se reconnecte plus vite", en: "The turnstile reconnects faster" },
];
const changelog = [
  { version: "1.4.39", items },
  { version: "1.4.38", items: [] },
];

test("a version with items is shown on the first start", () => {
  assert.deepEqual(shouldShowWhatsNew("1.4.39", null, changelog), items);
});

test("the version already dismissed stays hidden", () => {
  assert.equal(shouldShowWhatsNew("1.4.39", "1.4.39", changelog), null);
});

test("a different last shown version allows the current version's items", () => {
  assert.deepEqual(shouldShowWhatsNew("1.4.39", "1.4.37", changelog), items);
});

test("an empty seed or an unlisted version stays hidden", () => {
  assert.equal(shouldShowWhatsNew("1.4.39", null, []), null);
  assert.equal(shouldShowWhatsNew("1.4.40", null, changelog), null);
});

test("a version with no items stays hidden even when another version has items", () => {
  assert.equal(shouldShowWhatsNew("1.4.38", null, changelog), null);
});
