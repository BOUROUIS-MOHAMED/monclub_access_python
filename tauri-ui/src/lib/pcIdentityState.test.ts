import assert from "node:assert/strict";
import test from "node:test";

import { shouldShowPcSetup, setupFailureFromError } from "./pcIdentityState.ts";

test("ACCESS_PC_CAP_REACHED switches new-PC setup to takeover", () => {
  const next = setupFailureFromError({
    code: "ACCESS_PC_CAP_REACHED",
    message: "cap reached",
    details: { cap: 2, activeCount: 2 },
    takeoverRequired: true,
  });

  assert.deepEqual(next, {
    mode: "takeover",
    message: "La limite de 2 PC actifs est atteinte. Choisissez le poste que ce PC remplace.",
    cap: 2,
    activeCount: 2,
  });
});

test("other registration errors keep the new-PC form available", () => {
  const next = setupFailureFromError({ message: "Serveur indisponible" });

  assert.deepEqual(next, {
    mode: "new",
    message: "Serveur indisponible",
    cap: null,
    activeCount: null,
  });
});

test("identity setup never gates the app when status is unavailable or bypassed", () => {
  assert.equal(shouldShowPcSetup(null, false), false);
  assert.equal(shouldShowPcSetup({ state: "first_run" }, false), true);
  assert.equal(shouldShowPcSetup({ state: "revoked" }, false), true);
  assert.equal(shouldShowPcSetup({ state: "invalid_token" }, true), false);
  assert.equal(shouldShowPcSetup({ state: "active" }, false), false);
});
