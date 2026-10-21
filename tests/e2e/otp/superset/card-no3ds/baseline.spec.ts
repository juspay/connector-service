import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { basicCardPayment } from "./requests.js";

const scenario: OtpScenario = {
  id: "baseline",
  description:
    "Create a card payment, then confirm it separately using the server API key.",
  verifies:
    "Creation requires confirmation; the HS payment reaches succeeded with matching amount and currency, UCS routing, and a recorded processor reference.",

  sequence: [
    "Create payment with card",
    "Confirm with server API key",
    "Retrieve terminal payment",
    "Verify UCS routing and recorded processor reference",
  ],
  request: basicCardPayment(),

  scenarios: ["automatic"],
};

for (const { connector, scenario: selected } of otpSupersetCases(scenario)) {
  test.describe(`${connector}/${selected.id}`, () => {
    test(`${selected.scenarios[0]} @otp @no3ds @${connector}`, async ({}, info) => {
      await runOtpScenario(connector, selected, info);
    });
  });
}
