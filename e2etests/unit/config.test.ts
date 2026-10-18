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
import {
  connectors,
  paymentCases,
  refundVerification,
} from "../support/cases.js";
import { variants as adyenVariants } from "../otp/adyen/card-no3ds/variants.js";
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

test("baseline exercises four lifecycles once per connector, with focused request variants", () => {
  let count = 0;
  for (const connector of connectors) {
    const variants =
      connector === "adyen"
        ? adyenVariants
        : connector === "stripe"
          ? stripeVariants
          : [];
    const cases = paymentCases(variants);
    assert.equal(cases.filter((c) => c.id === "baseline").length, 1);
    assert.equal(cases[0].scenarios.length, 4);
    count += cases.reduce((sum, c) => sum + c.scenarios.length, 0);
  }
  assert.equal(count, 30);
  assert.equal(
    paymentCases(adyenVariants, "gbp-metadata")[0].scenarios.length,
    1,
  );
  assert.throws(
    () => paymentCases(adyenVariants, "missing"),
    /Unknown request variant/,
  );
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
      adyen: {
        credential: "our_sandbox_account",
        payment: { metadata: { common: "fixture" } },
        connectorMetadata: { account_name: "sandbox-placeholder" },
      },
    },
    variants: {
      "adyen/gbp-metadata": { payment: { metadata: { specific: "fixture" } } },
    },
  };
  const merged = resolveOverrides(document, "adyen", adyenVariants[0]);
  assert.deepEqual(merged.payment, {
    currency: "GBP",
    metadata: { common: "fixture", fixture_case: "order", specific: "fixture" },
  });
  assert.deepEqual(merged.connectorMetadata, {
    account_name: "sandbox-placeholder",
  });
  assert.equal("credential" in merged, false);
  assert.throws(
    () =>
      resolveOverrides(
        { variants: { "adyen/baseline": { credential: "other-account" } } },
        "adyen",
        { id: "baseline", scenarios: ["automatic"] },
      ),
    /credential belongs/,
  );
  assert.throws(
    () => resolveOverrides({ merchants: {} }, "adyen", adyenVariants[0]),
    /legacy merchant/,
  );
});

test("Adyen refund acceptance is distinct from terminal refund sync verification", () => {
  assert.equal(refundVerification("adyen"), "accepted");
  for (const connector of connectors.filter((c) => c !== "adyen"))
    assert.equal(refundVerification(connector), "synced");
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
