import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "inline-customer",
  description: "Confirm inline with customer and order-reference details.",
  verifies:
    "The payment succeeds through UCS with matching amount and currency.",

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
    merchant_order_reference_id: "test-order",
  },
  scenarios: ["automatic"],
};

for (const { connector, scenario: selected, skipReason } of otpSupersetCases(
  scenario,
)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      test.skip(!!skipReason, skipReason);
      await runOtpScenario(connector, selected, info);
    });
  });
}
