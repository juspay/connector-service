import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { stripeConnectedAccount } from "../support/stripe.js";

function clearAccountEnv(t: TestContext) {
  const original = process.env.STRIPE_CONNECTED_ACCOUNT_ID;
  delete process.env.STRIPE_CONNECTED_ACCOUNT_ID;
  t.after(() => {
    if (original === undefined) delete process.env.STRIPE_CONNECTED_ACCOUNT_ID;
    else process.env.STRIPE_CONNECTED_ACCOUNT_ID = original;
  });
}

const auth = { connector_account_details: { api_key: "sk_test_fixture" } };

test("Connect fixture lookup refuses non-sandbox keys before contacting Stripe", async (t) => {
  const fetch = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("Unexpected request");
  });
  await assert.rejects(
    stripeConnectedAccount({
      connector_account_details: { api_key: "sk_live_fixture" },
    }),
    /sandbox API key/,
  );
  assert.equal(fetch.mock.callCount(), 0);
});

test("Connect fixture lookup selects an existing charge-enabled card account", async (t) => {
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        JSON.stringify({
          data: [
            {
              id: "acct_disabled",
              charges_enabled: false,
              capabilities: { card_payments: "active" },
            },
            {
              id: "acct_synthetic",
              charges_enabled: true,
              capabilities: { card_payments: "active" },
            },
          ],
        }),
        { status: 200 },
      ),
  );
  assert.equal(await stripeConnectedAccount(auth), "acct_synthetic");
});

test("Connect fixture response failures cannot expose raw response data", async (t) => {
  t.mock.method(
    globalThis,
    "fetch",
    async () => new Response("SENTINEL_PRIVATE_VALUE", { status: 200 }),
  );
  await assert.rejects(stripeConnectedAccount(auth), (error) => {
    assert.match(String(error), /Invalid Stripe sandbox fixture response/);
    assert.doesNotMatch(String(error), /SENTINEL_PRIVATE_VALUE/);
    return true;
  });
});
