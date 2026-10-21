import { test } from "node:test";
import assert from "node:assert/strict";
import { equal, oneOf, verifyChecks, assertChecks } from "../checks.js";

test("the asserted check definitions are the exact expected/actual evidence, even on failure", async () => {
  const attachments: { name: string; body: string }[] = [];
  const report = {
    attach: async (name: string, options: any) => {
      attachments.push({ name, body: options.body });
    },
  };
  await assert.rejects(
    verifyChecks(report, "Payment checks", { amount: equal(6000, 3000) }),
    /Payment checks: amount/,
  );
  assert.equal(attachments[0].name, "Payment checks");
  assert.deepEqual(JSON.parse(attachments[0].body), {
    amount: { expected: 6000, actual: 3000 },
  });
});

test("allowed states use the same contract and a missing observation cannot pass as null", () => {
  assert.doesNotThrow(() =>
    assertChecks({ status: oneOf(["succeeded", "processing"], "processing") }),
  );
  assert.throws(() =>
    assertChecks({ status: oneOf(["succeeded", "processing"], "failed") }),
  );
  assert.throws(() => assertChecks({ value: equal(null, undefined) }));
  assert.throws(() => assertChecks({}), /must contain checks/);
  assert.throws(
    () => equal(undefined as any, undefined),
    /explicit expected value/,
  );
  assert.throws(() => oneOf([] as any, undefined), /explicit expected values/);
});

test("raw response objects cannot be used as verification report values", () => {
  assert.throws(
    () => equal(true, { api_key: "SENTINEL_PRIVATE_VALUE" }),
    (error) => {
      assert.match(String(error), /scalar observations/);
      assert.doesNotMatch(String(error), /SENTINEL_PRIVATE_VALUE|api_key/);
      return true;
    },
  );
});
