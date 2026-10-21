import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { checkoutPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "checkout-details",
  description:
    "Confirm inline with customer, billing, shipping, description, descriptor, and metadata.",
  verifies:
    "The payment succeeds with checkout details supplied, matching amount and currency, UCS routing, and a recorded processor reference.",

  sequence: [
    "Create and confirm payment",
    "Retrieve terminal payment",
    "Verify payment fields and UCS routing",
  ],
  request: checkoutPayment(),

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
