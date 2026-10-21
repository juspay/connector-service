import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { checkoutPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "billing-profile",
  description:
    "Enable billing-profile forwarding and confirm an inline card payment with a distinct billing address.",
  verifies:
    "The payment succeeds with the billing-profile option enabled, matching amount and currency, UCS routing, and a recorded processor reference.",

  sequence: [
    "Apply billing profile option",
    "Create and confirm payment",
    "Retrieve terminal payment",
    "Verify payment fields and UCS routing",
  ],
  request: {
    ...checkoutPayment(),
    billing: {
      ...checkoutPayment().billing,
      address: {
        ...checkoutPayment().billing.address,
        line1: "2 Billing Example Street",
      },
    },
  },
  profile: { use_billing_as_payment_method_billing: true },
  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
