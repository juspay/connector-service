import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "refund-full",
  description:
    "Complete an automatic card payment, then refund its entire amount.",
  verifies:
    "Payment succeeds; refund reaches succeeded; the processor records the full refunded amount and a full-refund flag.",
  coverage: "regression",
  sequence: [
    "Create payment",
    "Confirm automatic payment",
    "Verify succeeded",
    "Refund full amount",
    "Retrieve refund until succeeded",
    "Verify processor refund amount and flag",
  ],
  request: basicCardPayment(),

  scenarios: ["refund-full"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
