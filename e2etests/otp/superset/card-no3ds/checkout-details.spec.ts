import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { checkoutPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "checkout-details",
  description:
    "Confirm inline with synthetic customer, billing, shipping, description, descriptor, and metadata.",
  verifies:
    "HS and the processor succeed; processor preserves the supplied description, descriptor, metadata, and shipping address.",
  coverage: "regression",
  sequence: [
    "Create and confirm payment",
    "Retrieve terminal payment",
    "Verify UCS routing and processor field forwarding",
  ],
  request: checkoutPayment(),

  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
