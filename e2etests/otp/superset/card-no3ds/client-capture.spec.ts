import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "client-capture",
  description:
    "Create without card details, authorize through client confirmation, then capture the full amount.",
  verifies:
    "Creation requires a payment method; authorization requires capture; capture reaches succeeded with the expected amount.",
  coverage: "regression",
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

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
