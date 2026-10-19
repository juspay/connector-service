import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "client-void",
  description:
    "Create without card details, authorize through client confirmation, then cancel.",
  verifies:
    "Creation requires a payment method; authorization requires capture; cancellation reaches cancelled.",
  coverage: "regression",
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

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
