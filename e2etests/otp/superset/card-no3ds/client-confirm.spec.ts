import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { clientPayment, clientConfirmation } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "client-confirm",
  description:
    "Create without card details, then confirm with a publishable key, payment client secret, and card details.",
  verifies:
    "Creation returns requires_payment_method; client confirmation succeeds through UCS and the processor records the expected amount and currency.",
  coverage: "regression",
  sequence: [
    "Create without card",
    "Confirm with publishable key and client secret",
    "Retrieve terminal payment with server key",
    "Verify UCS routing and processor payment",
  ],
  request: clientPayment(),
  clientConfirmation: true,
  confirmRequest: clientConfirmation(),
  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
