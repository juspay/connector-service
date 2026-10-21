import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "client-capture",
  description:
    "Create without card details, authorize through client confirmation, then capture the full amount.",
  verifies:
    "Creation requires a payment method; authorization requires capture; capture reaches succeeded with the expected amount.",

  sequence: [
    "Create without card",
    "Client confirm manual authorization",
    "Verify requires_capture",
    "Capture full amount",
    "Verify succeeded",
  ],
  request: basicCardPayment(),
  clientConfirmation: true,
  scenarios: ["manual-capture"],
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
