import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "client-void",
  description:
    "Create without card details, authorize through client confirmation, then cancel.",
  verifies:
    "Creation requires a payment method; authorization requires capture; cancellation reaches cancelled.",

  sequence: [
    "Create without card",
    "Client confirm manual authorization",
    "Verify requires_capture",
    "Cancel authorization",
    "Verify cancelled",
  ],
  request: basicCardPayment(),
  clientConfirmation: true,
  scenarios: ["manual-void"],
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
