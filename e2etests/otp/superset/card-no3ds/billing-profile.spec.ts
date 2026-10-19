import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { checkoutPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "billing-profile",
  description:
    "Enable billing-profile forwarding and confirm an inline card payment with a distinct billing address.",
  verifies:
    "The payment succeeds and processor payment method billing address matches the supplied synthetic billing address.",
  coverage: "regression",
  sequence: [
    "Apply billing profile option",
    "Create and confirm payment",
    "Retrieve terminal payment",
    "Verify processor payment method billing",
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
