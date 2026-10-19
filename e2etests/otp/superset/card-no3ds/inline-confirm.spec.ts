import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "inline-confirm",
  description: "Create and confirm a card payment in one server request.",
  verifies:
    "The create response completes without customer action; HS and the processor report succeeded with matching amount and currency.",
  coverage: "regression",
  sequence: [
    "Create and confirm payment",
    "Retrieve terminal payment",
    "Verify UCS routing and processor payment",
  ],
  request: { ...basicCardPayment(), confirm: true },

  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
