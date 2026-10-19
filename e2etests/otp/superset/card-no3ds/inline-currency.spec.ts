import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "inline-currency",
  description:
    "Confirm an inline card payment in the currency selected by the connector override.",
  verifies:
    "The payment succeeds and preserves the requested amount and currency.",
  coverage: "regression",
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
