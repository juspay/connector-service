import { test } from "@playwright/test";
import type { OtpScenario } from "../../../support/cases.js";
import { runOtpScenario } from "../../../support/otp-scenarios.js";
import { otpSupersetCases } from "../../../support/otp-superset.js";
import { basicCardPayment } from "./fixtures.js";

const scenario: OtpScenario = {
  id: "manual-capture",
  description:
    "Authorize a card payment without capture, then explicitly capture its full amount.",
  verifies:
    "Authorization reaches requires_capture with the full capturable amount; capture reaches succeeded and the processor receives the full amount.",
  coverage: "regression",
  sequence: [
    "Create payment",
    "Confirm manual authorization",
    "Verify requires_capture",
    "Capture full amount",
    "Verify succeeded in HS and the processor",
  ],
  request: { ...basicCardPayment(), capture_method: "manual" },

  scenarios: ["manual-capture"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
