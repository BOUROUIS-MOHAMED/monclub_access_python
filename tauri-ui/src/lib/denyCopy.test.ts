import assert from "node:assert/strict";
import test from "node:test";

import { aDenyCopy, denyShort, A_DENY_FALLBACK } from "./denyCopy.ts";

test("known engine codes map to their short French text", () => {
  assert.equal(denyShort("DENY_NO_CARD_MATCH"), "Carte non reconnue");
  assert.equal(denyShort("DENY_EXPIRED"), "Code QR expiré");
  assert.equal(denyShort("DENY_ANTI_FRAUD_CARD"), "Passage déjà enregistré");
  assert.equal(denyShort("DENY_NOT_IN_LOCAL_ROSTER"), "Abonnement non trouvé");
});

test("codes are matched case-insensitively after trimming", () => {
  assert.equal(denyShort("  deny_no_match "), "Badge non reconnu");
});

test("ULTRA device refusals and empty reasons fall back to 'Accès refusé'", () => {
  assert.equal(denyShort("DEVICE_DENIED"), "Accès refusé");
  assert.equal(denyShort(""), "Accès refusé");
  assert.equal(denyShort(null), "Accès refusé");
  assert.equal(denyShort(undefined), "Accès refusé");
  assert.equal(aDenyCopy("UNKNOWN_CODE"), A_DENY_FALLBACK);
});

test("a human sentence from the engine is shown as is", () => {
  assert.equal(denyShort("Carte bloquée par le club"), "Carte bloquée par le club");
});
