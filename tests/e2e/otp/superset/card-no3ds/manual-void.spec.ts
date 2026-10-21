import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "manual-void",
  description:
    "Authorize a card payment without capture, then cancel the authorization.",
  verifies:
    "Authorization reaches requires_capture; cancellation reaches cancelled in HS with the expected payment identity and amount.",

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
