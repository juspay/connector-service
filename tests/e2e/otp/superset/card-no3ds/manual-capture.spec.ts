import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "manual-capture",
  description:
    "Authorize a card payment without capture, then explicitly capture its full amount.",
  verifies:
    "Authorization reaches requires_capture with the full capturable amount; capture reaches succeeded in HS with the expected amount and currency.",

  sequence: [
    "Create payment",
    "Confirm manual authorization",
    "Verify requires_capture",
    "Capture full amount",
    "Verify payment succeeded in HS",
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
