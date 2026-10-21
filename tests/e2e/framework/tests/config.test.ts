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
} from "../config.js";
import { type OtpScenario } from "../scenario.js";
import { otpSupersetCases } from "../scenario.js";
import {
  basicCardPayment,
  checkoutPayment,
} from "../../otp/superset/card-no3ds/requests.js";
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
  assert.doesNotThrow(() =>
    assertOtp({
      ...base,
      customer_acceptance: {
        acceptance_type: "online",
        online: { ip_address: "192.0.2.1", user_agent: "Test browser" },
      },
    }),
  );
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
    { recurring_details: {} },
  ])
    assert.throws(() => assertOtp(merge(base, patch)), /OTP requires/);
});

test("one superset case expands across connectors and preserves terminal versus submission expectations", () => {
  const definition: OtpScenario = {
    id: "manual-capture",
    description: "Authorize and capture",
    verifies: "Terminal capture succeeds",
    sequence: ["Authorize", "Capture", "Verify terminal capture"],

    request: basicCardPayment(),
    scenarios: ["manual-capture"],
  };
  const cases = otpSupersetCases(definition);
  assert.equal(cases.length, 5);
  const stripe = cases.find((c) => c.connector === "stripe")!.scenario;
  const adyen = cases.find((c) => c.connector === "adyen")!.scenario;
  assert.deepEqual(stripe.scenarios, ["manual-capture"]);
  assert.deepEqual(adyen.scenarios, ["capture-submission"]);
  assert.match(adyen.verifies, /Terminal completion is not asserted/);
  assert.equal(
    adyen.payment!.payment_method_data.card.card_number,
    "4111111111111111",
  );
  assert.deepEqual(definition.scenarios, ["manual-capture"]);
});

test("complete connector request overrides retain absent fields and do not inherit common payment defaults", () => {
  const cases = otpSupersetCases({
    id: "direct-charge",
    description: "Direct charge",
    verifies: "Payment succeeds",
    sequence: ["Confirm"],

    request: checkoutPayment(),
    scenarios: ["automatic"],
  });
  assert.equal(cases.length, 1);
  const selected = cases[0].scenario;

  assert.equal("setup_future_usage" in selected.request, false);
  assert.equal("authentication_type" in selected.request, false);
  assert.equal("phone" in selected.request.customer, false);
  assert.deepEqual(selected.request.billing_descriptor, {});
  assert.equal(Object.keys(selected.request.metadata).length, 15);
  assert.equal(
    selected.request.split_payments.stripe_split_payment.charge_type,
    "direct",
  );
});

test("request variants merge configuration without selecting a different credential account", () => {
  const document = {
    connectors: {
      stripe: {
        credential: "sandbox_account",
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
    /only connectors and variants/,
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
