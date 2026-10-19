import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertOtp,
  credentials,
  merge,
  resolveOverrides,
  readPrivateJson,
} from "../support/config.js";
import { connectors, paymentCases } from "../support/cases.js";
import { variants as stripeVariants } from "../otp/stripe/card-no3ds/variants.js";

test("merchant patches retain nested connector defaults, replace arrays, and do not mutate shared input", () => {
  const defaults = {
    metadata: { retained: true, replaced: 1 },
    methods: ["card"],
  };
  const result = merge(defaults, {
    metadata: { replaced: 2 },
    methods: ["wallet"],
  });
  assert.deepEqual(result, {
    metadata: { retained: true, replaced: 2 },
    methods: ["wallet"],
  });
  assert.equal(defaults.metadata.replaced, 1);
  assert.deepEqual(defaults.methods, ["card"]);
  assert.deepEqual(merge({ metadata: {} }, { metadata: null }), {
    metadata: null,
  });
});

test("HS credential layouts support direct entries, the first account, and explicit account selection", () => {
  const auth = {
    connector_account_details: {
      auth_type: "HeaderKey",
      api_key: "sandbox-placeholder",
    },
  };
  const document = {
    stripe: auth,
    adyen: {
      note: "ignored",
      connector_1: auth,
      connector_2: { ...auth, metadata: { alternate: true } },
    },
  };
  assert.deepEqual(credentials(document, "stripe"), auth);
  assert.deepEqual(credentials(document, "adyen"), auth);
  assert.equal(
    credentials(document, "adyen", "connector_2").metadata.alternate,
    true,
  );
  assert.throws(
    () => credentials(document, "adyen", "missing"),
    /Missing HS sandbox credentials/,
  );
  assert.throws(
    () => credentials(document, "missing"),
    /Missing HS sandbox credentials/,
  );
});

test("OTP overrides cannot accidentally switch the suite to mandate, wallet, or 3DS flows", () => {
  const base = {
    amount: 100,
    authentication_type: "no_three_ds",
    payment_method: "card",
    payment_method_data: { card: {} },
  };
  assert.doesNotThrow(() => assertOtp(base));
  for (const patch of [
    { authentication_type: "three_ds" },
    { payment_method: "wallet" },
    { amount: 0 },
    { amount: NaN },
    { amount: 1.5 },
    { off_session: true },
    { setup_future_usage: "off_session" },
    { mandate_data: {} },
    { mandate_id: "saved" },
    { customer_acceptance: {} },
    { recurring_details: {} },
  ])
    assert.throws(() => assertOtp(merge(base, patch)), /OTP requires/);
});

test("baseline discovers one automatic Stripe payment and rejects invalid selections", () => {
  assert.deepEqual(connectors, ["stripe"]);
  assert.equal(paymentCases(stripeVariants).length, 1);
  assert.deepEqual(paymentCases(stripeVariants)[0].scenarios, ["automatic"]);
  assert.throws(() => paymentCases([], "missing"), /Unknown request variant/);
  assert.throws(
    () => paymentCases([{ id: "baseline", scenarios: ["automatic"] }]),
    /unique synthetic/,
  );
  assert.throws(
    () => paymentCases([{ id: "empty", scenarios: [] }]),
    /Invalid lifecycle/,
  );
});

test("request variants merge configuration without selecting a different credential account", () => {
  const document = {
    connectors: {
      stripe: {
        credential: "our_sandbox_account",
        payment: { metadata: { common: "fixture" } },
        connectorMetadata: { account_name: "sandbox-placeholder" },
      },
    },
    variants: {
      "stripe/metadata": { payment: { metadata: { specific: "fixture" } } },
    },
  };
  const merged = resolveOverrides(document, "stripe", {
    id: "metadata",
    payment: { metadata: { fixture_case: "order" } },
    scenarios: ["automatic"],
  });
  assert.deepEqual(merged.payment, {
    metadata: { common: "fixture", fixture_case: "order", specific: "fixture" },
  });
  assert.deepEqual(merged.connectorMetadata, {
    account_name: "sandbox-placeholder",
  });
  assert.equal("credential" in merged, false);
  assert.throws(
    () =>
      resolveOverrides(
        { variants: { "stripe/baseline": { credential: "other-account" } } },
        "stripe",
        { id: "baseline", scenarios: ["automatic"] },
      ),
    /credential belongs/,
  );
  assert.throws(
    () =>
      resolveOverrides({ merchants: {} }, "stripe", {
        id: "baseline",
        scenarios: ["automatic"],
      }),
    /legacy merchant/,
  );
});

test("override merge rejects prototype keys from JSON input", () => {
  assert.throws(
    () => merge({}, JSON.parse('{"__proto__":{"polluted":true}}')),
    /Invalid override key/,
  );
  assert.equal(({} as any).polluted, undefined);
});

test("malformed private configuration cannot leak its contents into reports", () => {
  const folder = mkdtempSync(join(tmpdir(), "ucs-e2e-private-json-"));
  const path = join(folder, "credentials.json");
  try {
    writeFileSync(path, '{"api_key":"SENTINEL_PRIVATE_VALUE" broken');
    assert.throws(
      () => readPrivateJson(path, "sandbox credentials"),
      (error) => {
        assert.match(String(error), /Cannot read sandbox credentials/);
        assert.doesNotMatch(
          String(error),
          /SENTINEL_PRIVATE_VALUE|api_key|credentials.json/,
        );
        return true;
      },
    );
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});
