import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "inline-customer",
  description:
    "Confirm inline with synthetic customer and order-reference details.",
  verifies:
    "The payment succeeds through UCS with matching amount and currency.",
  coverage: "regression",
  sequence: [
    "Create and confirm payment",
    "Verify terminal payment and processor reference",
  ],
  request: {
    ...basicCardPayment(),
    confirm: true,
    customer: {
      name: "Test Buyer",
      email: "ucs-e2e@example.com",
      phone: "2025550100",
      phone_country_code: "+1",
    },
    metadata: { fixture_case: "customer" },
    merchant_order_reference_id: "synthetic-order",
  },
  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
