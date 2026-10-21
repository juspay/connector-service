import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "inline-confirm",
  description: "Create and confirm a card payment in one server request.",
  verifies:
    "The create response completes without customer action; HS reports succeeded with matching amount and currency, UCS routing, and a recorded processor reference.",

  sequence: [
    "Create and confirm payment",
    "Retrieve terminal payment",
    "Verify UCS routing and recorded processor reference",
  ],
  request: { ...basicCardPayment(), confirm: true },

  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
