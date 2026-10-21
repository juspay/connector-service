import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "inline-currency",
  description:
    "Confirm an inline card payment in the currency selected by the connector override.",
  verifies:
    "The payment succeeds and preserves the requested amount and currency.",

  sequence: [
    "Create and confirm payment",
    "Verify amount, currency and terminal state",
  ],
  request: {
    ...basicCardPayment(),
    confirm: true,
    metadata: { fixture_case: "currency" },
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
