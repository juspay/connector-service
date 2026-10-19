import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "baseline",
  description:
    "Create a card payment, then confirm it separately using the server API key.",
  verifies:
    "Creation requires confirmation; the payment and processor payment reach succeeded with matching amount and currency.",
  coverage: "regression",
  sequence: [
    "Create payment with card",
    "Confirm with server API key",
    "Retrieve terminal payment",
    "Verify UCS routing and processor payment",
  ],
  request: basicCardPayment(),

  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
