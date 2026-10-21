import { test } from "@playwright/test";
import type { OtpScenario } from "../../../framework/scenario.js";
import { runOtpScenario } from "../../../framework/runner.js";
import { otpSupersetCases } from "../../../framework/scenario.js";
import { connectDirectPayment } from "./requests.js";

const scenario: OtpScenario = {
  requires: "stripe-connect",
  id: "direct-charge-no-shipping",
  description:
    "Confirm a platform direct charge with shipping explicitly null.",
  verifies:
    "The HS payment succeeds with the expected amount and currency, UCS routing, and a recorded processor reference.",

  sequence: [
    "Read configured sandbox connected account",
    "Create direct charge without shipping",
    "Retrieve terminal payment",
    "Verify UCS routing and recorded processor reference",
  ],
  request: { ...connectDirectPayment(), shipping: null },
  scenarios: ["automatic"],
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
