import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "refund-partial",
  description:
    "Complete an automatic card payment, then refund half of its amount.",
  verifies:
    "Payment and refund succeed; the processor records half refunded and does not mark the charge fully refunded.",
  coverage: "regression",
  sequence: [
    "Create payment",
    "Confirm automatic payment",
    "Verify succeeded",
    "Refund half the amount",
    "Retrieve refund until succeeded",
    "Verify processor partial refund",
  ],
  request: basicCardPayment(),

  scenarios: ["refund-partial"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
