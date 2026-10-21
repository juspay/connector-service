import { test } from "node:test";
import assert from "node:assert/strict";
import { stripeAdapter } from "../support/processors/stripe.js";
import { verifyChecks } from "../support/checks.js";

test("processor adapters return observations; the shared verifier asserts and records mismatches", async (t) => {
  t.mock.method(
    globalThis,
    "fetch",
    async (_url: string | URL | Request, init?: RequestInit) => {
      assert.equal(init?.method ?? "GET", "GET");
      return new Response(
        JSON.stringify({
          livemode: false,
          status: "requires_action",
          amount_received: 6000,
          currency: "usd",
        }),
        { status: 200 },
      );
    },
  );
  const checks = await stripeAdapter.verify({
    auth: { connector_account_details: { api_key: "sk_test_fixture" } },
    payment: { amount: 6000, currency: "USD" },
    reference: "pi_synthetic",
    outcome: "succeeded",
  });
  assert.deepEqual(checks.status, {
    expected: "succeeded",
    actual: "requires_action",
  });
  const attachments: unknown[] = [];
  await assert.rejects(
    verifyChecks(
      {
        attach: async (_name, options) => {
          attachments.push(JSON.parse(String(options?.body)));
        },
      },
      "Stripe checks",
      checks,
    ),
    /Stripe checks: status/,
  );
  assert.equal(attachments.length, 1);
});
