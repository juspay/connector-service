import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { clientPayment, clientConfirmation } from "./requests.js";

const scenario: OtpScenario = {
  id: "client-confirm",
  description:
    "Create without card details, then confirm with a publishable key, payment client secret, and card details.",
  verifies:
    "Creation returns requires_payment_method; client confirmation succeeds through UCS with matching amount and currency and a recorded processor reference.",

  sequence: [
    "Create without card",
    "Confirm with publishable key and client secret",
    "Retrieve terminal payment with server key",
    "Verify UCS routing and recorded processor reference",
  ],
  request: clientPayment(),
  clientConfirmation: true,
  confirmRequest: clientConfirmation(),
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
