import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "manual-void",
  description:
    "Authorize a card payment without capture, then cancel the authorization.",
  verifies:
    "Authorization reaches requires_capture; cancellation reaches cancelled in HS and canceled at the processor, with zero received amount.",
  coverage: "regression",
  sequence: [
    "Create payment",
    "Confirm manual authorization",
    "Verify requires_capture",
    "Cancel authorization",
    "Verify cancelled and zero received amount",
  ],
  request: { ...basicCardPayment(), capture_method: "manual" },

  scenarios: ["manual-void"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
