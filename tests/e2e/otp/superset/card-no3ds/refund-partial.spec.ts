import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "refund-partial",
  description:
    "Complete an automatic card payment, then refund half of its amount.",
  verifies:
    "Payment succeeds; the HS refund reaches succeeded for half the payment amount with a recorded processor refund reference.",

  sequence: [
    "Create payment",
    "Confirm automatic payment",
    "Verify succeeded",
    "Refund half the amount",
    "Retrieve refund until succeeded",
    "Verify refund amount and recorded processor reference",
  ],
  request: basicCardPayment(),

  scenarios: ["refund-partial"],
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
